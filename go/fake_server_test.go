package infisical_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	infisical "github.com/grow-codes-packages/infisical/go"
)

const (
	fakeProject = "proj-fake"
	fakeToken   = "fake-TOKEN-1234"
)

type fakeSecret struct {
	ID      string
	Key     string
	Value   string
	Comment string
	Version int
	Tags    []string
	Created time.Time
	Updated time.Time
}

// fakeInfisical is a small stateful Infisical (v4 secrets, v2 folders, v1
// tags) used to run the provider and the conformance scenarios in unit tests.
type fakeInfisical struct {
	*httptest.Server
	mu      sync.Mutex
	folders map[string]bool                   // env + ":" + path
	secrets map[string]map[string]*fakeSecret // env + ":" + path → key → secret
	tags    map[string]string                 // slug → id
	nextID  int
	calls   []string
	// failNext answers the next request matching "METHOD path" with this status.
	failNext map[string]int
}

func newFake(t *testing.T) *fakeInfisical {
	t.Helper()
	f := &fakeInfisical{
		folders:  map[string]bool{"dev:/": true, "staging:/": true},
		secrets:  map[string]map[string]*fakeSecret{},
		tags:     map[string]string{},
		failNext: map[string]int{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeInfisical) client(t *testing.T, mutate func(*infisical.Config)) *infisical.Client {
	t.Helper()
	cfg := infisical.Config{
		CommonConfig: infisical.CommonConfig{URL: f.URL, Retry: &infisical.RetryPolicy{MaxRetries: 0}},
		Token:        infisical.NewSecret(fakeToken), ProjectID: fakeProject, Environment: "dev",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := infisical.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (f *fakeInfisical) callCount(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, name, msg string) {
	writeJSON(w, status, map[string]any{"reqId": "req-fake", "statusCode": status, "error": name, "message": msg})
}

func normPath(p string) string {
	c := path.Clean("/" + p)
	return c
}

func (f *fakeInfisical) secretJSON(env, p string, s *fakeSecret, view bool) map[string]any {
	tags := []map[string]any{}
	for _, id := range s.Tags {
		for slug, tid := range f.tags {
			if tid == id {
				tags = append(tags, map[string]any{"id": id, "slug": slug, "name": slug, "color": "#000000"})
			}
		}
	}
	v := s.Value
	if !view {
		v = "<hidden-by-infisical>"
	}
	return map[string]any{
		"id": s.ID, "workspace": fakeProject, "environment": env, "version": s.Version, "type": "shared",
		"secretKey": s.Key, "secretValue": v, "secretComment": s.Comment, "secretValueHidden": !view,
		"secretPath": p, "createdAt": s.Created.Format(time.RFC3339Nano), "updatedAt": s.Updated.Format(time.RFC3339Nano),
		"tags": tags, "secretMetadata": []any{},
	}
}

func (f *fakeInfisical) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if st, ok := f.failNext[r.Method+" "+r.URL.Path]; ok {
		delete(f.failNext, r.Method+" "+r.URL.Path)
		fail(w, st, "Injected", "injected failure")
		return
	}
	if r.URL.Path == "/api/status" {
		writeJSON(w, 200, map[string]any{"message": "Ok", "redisConfigured": true})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		fail(w, 401, "UnauthorizedError", "Token missing")
		return
	}
	var body map[string]any
	if data, _ := io.ReadAll(r.Body); len(data) > 0 {
		_ = json.Unmarshal(data, &body)
	}
	q := r.URL.Query()
	get := func(k string) string {
		if v, ok := body[k].(string); ok {
			return v
		}
		return q.Get(k)
	}
	env := get("environment")
	switch {
	case r.URL.Path == "/api/v1/identities/details":
		writeJSON(w, 200, map[string]any{"identityDetails": map[string]any{}})
	case r.URL.Path == "/api/v4/secrets" && r.Method == http.MethodGet:
		p := normPath(get("secretPath"))
		if !f.folders[env+":"+p] {
			fail(w, 404, "SecretPathNotFound", "Folder with path '"+p+"' in environment with slug '"+env+"' not found")
			return
		}
		view := q.Get("viewSecretValue") != "false"
		out := []map[string]any{}
		keys := make([]string, 0)
		for k := range f.secrets[env+":"+p] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, f.secretJSON(env, p, f.secrets[env+":"+p][k], view))
		}
		writeJSON(w, 200, map[string]any{"secrets": out, "imports": []any{}})
	case strings.HasPrefix(r.URL.Path, "/api/v4/secrets/"):
		f.secretRoute(w, r, env, normPath(get("secretPath")), strings.TrimPrefix(r.URL.Path, "/api/v4/secrets/"), body, q)
	case r.URL.Path == "/api/v2/folders" && r.Method == http.MethodPost:
		parent, name := normPath(get("path")), get("name")
		if !f.folders[env+":"+parent] {
			fail(w, 404, "NotFound", "Folder with path '"+parent+"' not found")
			return
		}
		full := normPath(parent + "/" + name)
		if f.folders[env+":"+full] {
			fail(w, 400, "BadRequest", "Folder with name '"+name+"' already exists in path '"+parent+"'")
			return
		}
		f.folders[env+":"+full] = true
		f.nextID++
		writeJSON(w, 200, map[string]any{"folder": map[string]any{"id": fmt.Sprint("folder-", f.nextID), "name": name, "path": full, "version": 1}})
	case r.URL.Path == "/api/v1/projects/"+fakeProject+"/tags" && r.Method == http.MethodGet:
		tags := []map[string]any{}
		for slug, id := range f.tags {
			tags = append(tags, map[string]any{"id": id, "slug": slug, "color": "#000000"})
		}
		writeJSON(w, 200, map[string]any{"tags": tags})
	case r.URL.Path == "/api/v1/projects/"+fakeProject+"/tags" && r.Method == http.MethodPost:
		slug := get("slug")
		f.nextID++
		f.tags[slug] = fmt.Sprint("tag-", f.nextID)
		writeJSON(w, 200, map[string]any{"tag": map[string]any{"id": f.tags[slug], "slug": slug, "color": get("color")}})
	default:
		fail(w, 404, "Not Found", "Route "+r.Method+":"+r.URL.RequestURI()+" not found")
	}
}

func (f *fakeInfisical) secretRoute(w http.ResponseWriter, r *http.Request, env, p, rawName string, body map[string]any, q url.Values) {
	name, _ := url.PathUnescape(rawName)
	folder := f.secrets[env+":"+p]
	now := time.Now().UTC()
	tagIDs := func() []string {
		raw, ok := body["tagIds"].([]any)
		if !ok {
			return nil
		}
		out := []string{}
		for _, v := range raw {
			out = append(out, fmt.Sprint(v))
		}
		return out
	}
	switch r.Method {
	case http.MethodGet:
		s, ok := folder[name]
		if !ok || !f.folders[env+":"+p] {
			fail(w, 404, "NotFound", "Secret with name '"+name+"' not found")
			return
		}
		writeJSON(w, 200, map[string]any{"secret": f.secretJSON(env, p, s, q.Get("viewSecretValue") != "false")})
	case http.MethodPost:
		if !f.folders[env+":"+p] {
			fail(w, 404, "NotFound", "Folder with path '"+p+"' in environment with slug '"+env+"' not found")
			return
		}
		if _, ok := folder[name]; ok {
			fail(w, 400, "BadRequest", "Secret '"+name+"' already exists in path '"+p+"' of environment '"+env+"'")
			return
		}
		if folder == nil {
			folder = map[string]*fakeSecret{}
			f.secrets[env+":"+p] = folder
		}
		f.nextID++
		comment, _ := body["secretComment"].(string)
		value, _ := body["secretValue"].(string)
		s := &fakeSecret{ID: fmt.Sprint("sec-", f.nextID), Key: name, Value: strings.TrimSpace(value), Comment: comment,
			Version: 1, Tags: tagIDs(), Created: now, Updated: now}
		folder[name] = s
		writeJSON(w, 200, map[string]any{"secret": f.secretJSON(env, p, s, true)})
	case http.MethodPatch:
		s, ok := folder[name]
		if !ok {
			fail(w, 404, "NotFound", "Secret with name "+name+" not found")
			return
		}
		if v, ok := body["secretValue"].(string); ok {
			s.Value = strings.TrimSpace(v)
		}
		if v, ok := body["secretComment"].(string); ok {
			s.Comment = v
		}
		if ids := tagIDs(); ids != nil {
			s.Tags = ids
		}
		s.Version++
		s.Updated = now
		writeJSON(w, 200, map[string]any{"secret": f.secretJSON(env, p, s, true)})
	case http.MethodDelete:
		s, ok := folder[name]
		if !ok {
			fail(w, 404, "NotFound", "Secret not found")
			return
		}
		delete(folder, name)
		writeJSON(w, 200, map[string]any{"secret": f.secretJSON(env, p, s, true)})
	}
}
