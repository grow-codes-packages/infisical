package infisical

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestListSecrets(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v4/secrets", "listSecrets.withImports")
	c := newMockClient(t, m, nil)
	list, err := c.ListSecrets(bg(), &ListSecretsOptions{SecretPath: "app/", Recursive: true, TagSlugs: []string{"a", "b"},
		ExpandReferences: Bool(false), IncludeImports: Bool(true), ViewSecretValue: Bool(true), IncludePersonalOverrides: true})
	if err != nil {
		t.Fatal(err)
	}
	q := m.last(t, http.MethodGet, "/api/v4/secrets").Query
	for k, v := range map[string]string{
		"projectId": testProject, "environment": "dev", "secretPath": "/app", "recursive": "true", "expandSecretReferences": "false",
		"includeImports": "true", "tagSlugs": "a,b", "viewSecretValue": "true", "includePersonalOverrides": "true",
	} {
		if q.Get(k) != v {
			t.Fatalf("query %s=%q, want %q", k, q.Get(k), v)
		}
	}
	if len(list.Secrets) != 0 || len(list.Imports) != 1 || list.Imports[0].Environment != "staging" || list.Imports[0].Secrets[0].Value.Reveal() != "common-value-1" {
		t.Fatalf("imports: %+v", list)
	}
	if c.APIVersion("secrets") != "v4" {
		t.Fatal("v4 pinned after a successful call")
	}

	m.fixture(t, http.MethodGet, "/api/v4/secrets", "listSecrets.ok")
	list, err = c.ListSecrets(bg(), nil)
	if err != nil || len(list.Secrets) == 0 {
		t.Fatalf("list ok: %v", err)
	}
	q = m.last(t, http.MethodGet, "/api/v4/secrets").Query
	if q.Get("expandSecretReferences") != "true" || q.Get("includeImports") != "true" || q.Get("recursive") != "false" || q.Get("secretPath") != "/" || q.Has("tagSlugs") {
		t.Fatalf("defaults: %v", q)
	}
	m.fixture(t, http.MethodGet, "/api/v4/secrets", "listSecrets.hiddenValues")
	list, err = c.ListSecrets(bg(), &ListSecretsOptions{ViewSecretValue: Bool(false)})
	if err != nil || !list.Secrets[0].ValueHidden || list.Secrets[0].Value.Reveal() != "" {
		t.Fatalf("hidden: %v %+v", err, list.Secrets)
	}
	m.fixture(t, http.MethodGet, "/api/v4/secrets", "listSecrets.envMissing404")
	_, err = c.ListSecrets(bg(), nil)
	wantCode(t, err, ErrorCodeNotFound)
	m.fixture(t, http.MethodGet, "/api/v4/secrets", "listSecrets.tagSlugs")
	list, err = c.ListSecrets(bg(), nil)
	if err != nil || len(list.Secrets) == 0 || len(list.Secrets[0].Tags) == 0 || list.Secrets[0].Tags[0].Slug == "" {
		t.Fatalf("tags: %v", err)
	}
}

func TestSecretListMerged(t *testing.T) {
	l := &SecretList{
		Secrets: []SecretEntry{
			{Key: "A", Value: NewSecret("deep"), SecretPath: "/x/y"},
			{Key: "A", Value: NewSecret("root"), SecretPath: "/"},
			{Key: "B", Value: NewSecret("b"), SecretPath: "/x"},
		},
		Imports: []ImportedSecrets{{Secrets: []SecretEntry{{Key: "B", Value: NewSecret("imported")}, {Key: "C", Value: NewSecret("c")}}}},
	}
	m := l.Merged()
	if m["A"].Value.Reveal() != "root" || m["B"].Value.Reveal() != "b" || m["C"].Value.Reveal() != "c" || len(m) != 3 {
		t.Fatalf("merged: %v", m)
	}
}

func TestGetSecret(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v4/secrets/SDK_49LJ3988_ONE", "getSecret.ok")
	c := newMockClient(t, m, nil)
	s, err := c.GetSecret(bg(), "SDK_49LJ3988_ONE", &GetSecretOptions{Version: 1, Type: SecretTypeShared, SecretPath: "/",
		ExpandReferences: Bool(false), IncludeImports: Bool(false), ViewSecretValue: Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	if s.Key != "SDK_49LJ3988_ONE" || s.Value.Reveal() != "v1-49lj3988" || s.Version != 1 || s.Comment != "c1" || s.Type != SecretTypeShared ||
		s.ProjectID != testProject || s.Environment != "dev" || s.SecretPath != "/" || s.CreatedAt.IsZero() || s.ID == "" {
		t.Fatalf("entry: %+v", s)
	}
	if fmt.Sprint(s) == "" || strings.Contains(fmt.Sprintf("%+v", *s), "v1-49lj3988") {
		t.Fatal("value printed")
	}
	q := m.last(t, http.MethodGet, "/api/v4/secrets/SDK_49LJ3988_ONE").Query
	if q.Get("version") != "1" || q.Get("type") != "shared" || q.Get("expandSecretReferences") != "false" || q.Get("includeImports") != "false" {
		t.Fatalf("query: %v", q)
	}
	_, err = c.GetSecret(bg(), "", nil)
	wantCode(t, err, ErrorCodeValidation)
	_, err = c.GetSecret(bg(), "X", &GetSecretOptions{Version: -1})
	wantCode(t, err, ErrorCodeValidation)
	m.fixture(t, http.MethodGet, "/api/v4/secrets/X", "getSecret.version404")
	_, err = c.GetSecret(bg(), "X", &GetSecretOptions{Version: 9})
	wantCode(t, err, ErrorCodeNotFound)
	_, err = c.GetSecret(bg(), "X", &GetSecretOptions{ProjectID: "p", Environment: ""})
	wantCode(t, err, ErrorCodeNotFound)
	// Names are path-escaped.
	m.fixture(t, http.MethodGet, "/api/v4/secrets/lower.case-Name", "getSecret.ok")
	if _, err := c.GetSecret(bg(), "lower.case-Name", nil); err != nil {
		t.Fatal(err)
	}
	m.json(http.MethodGet, "/api/v4/secrets/meta", 200, map[string]any{"secret": map[string]any{
		"secretKey": "meta", "secretValue": "v", "version": 2, "secretMetadata": []map[string]string{{"key": "owner", "value": "team"}},
	}})
	if s, err := c.GetSecret(bg(), "meta", nil); err != nil || s.Metadata["owner"] != "team" {
		t.Fatalf("metadata: %v", err)
	}
	m.json(http.MethodGet, "/api/v4/secrets/broken", 200, "{not json")
	_, err = c.GetSecret(bg(), "broken", nil)
	wantCode(t, err, ErrorCodeUnavailable)
}

func TestCreateUpdateDeleteSecret(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v1/projects/"+testProject+"/tags", "listTags.ok")
	m.fixture(t, http.MethodPost, "/api/v4/secrets/SDK_49LJ3988_ONE", "createSecret.ok")
	m.fixture(t, http.MethodPatch, "/api/v4/secrets/SDK_49LJ3988_ONE", "updateSecret.renameCommentTags")
	m.fixture(t, http.MethodDelete, "/api/v4/secrets/SDK_49LJ3988_ONE", "deleteSecret.ok")
	c := newMockClient(t, m, nil)

	s, err := c.CreateSecret(bg(), "SDK_49LJ3988_ONE", "v1", &CreateSecretOptions{Comment: "c1", TagSlugs: []string{"t-49lj3988"},
		TagIDs: []string{"extra"}, Type: SecretTypeShared, SkipMultilineEncoding: true, Metadata: map[string]string{"b": "2", "a": "1"}})
	if err != nil || s.Version != 1 {
		t.Fatalf("create: %v", err)
	}
	b := m.last(t, http.MethodPost, "/api/v4/secrets/SDK_49LJ3988_ONE").Body
	if str(b["projectId"]) != testProject || str(b["environment"]) != "dev" || str(b["secretPath"]) != "/" || str(b["secretValue"]) != "v1" ||
		str(b["secretComment"]) != "c1" || str(b["type"]) != "shared" || b["skipMultilineEncoding"] != true {
		t.Fatalf("create body: %v", b)
	}
	if tags := b["tagIds"].([]any); len(tags) != 2 || tags[0] != "extra" || tags[1] != "8ec93966-db51-4801-a143-26296a09c05c" {
		t.Fatalf("tag ids: %v", tags)
	}
	if md := b["secretMetadata"].([]any); len(md) != 2 || md[0].(map[string]any)["key"] != "a" {
		t.Fatalf("metadata: %v", md)
	}

	s, err = c.UpdateSecret(bg(), "SDK_49LJ3988_ONE", &UpdateSecretOptions{Value: String("v2"), NewName: "SDK_49LJ3988_RENAMED",
		Comment: String("c2"), TagIDs: []string{}, Type: SecretTypeShared, SkipMultilineEncoding: Bool(false), Metadata: map[string]string{}})
	if err != nil || s.Key != "SDK_49LJ3988_RENAMED" || s.Version != 3 {
		t.Fatalf("update: %v %+v", err, s)
	}
	b = m.last(t, http.MethodPatch, "/api/v4/secrets/SDK_49LJ3988_ONE").Body
	if str(b["secretValue"]) != "v2" || str(b["newSecretName"]) != "SDK_49LJ3988_RENAMED" || str(b["secretComment"]) != "c2" ||
		len(b["tagIds"].([]any)) != 0 || b["skipMultilineEncoding"] != false || str(b["type"]) != "shared" {
		t.Fatalf("update body: %v", b)
	}
	// Nothing set: only the scope is sent.
	if _, err := c.UpdateSecret(bg(), "SDK_49LJ3988_ONE", nil); err != nil {
		t.Fatal(err)
	}
	b = m.last(t, http.MethodPatch, "/api/v4/secrets/SDK_49LJ3988_ONE").Body
	if _, ok := b["tagIds"]; ok || len(b) != 3 {
		t.Fatalf("minimal update body: %v", b)
	}

	if _, err := c.DeleteSecret(bg(), "SDK_49LJ3988_ONE", &DeleteSecretOptions{Type: SecretTypePersonal, SecretPath: "/"}); err != nil {
		t.Fatal(err)
	}
	if b = m.last(t, http.MethodDelete, "/api/v4/secrets/SDK_49LJ3988_ONE").Body; str(b["type"]) != "personal" {
		t.Fatalf("delete body: %v", b)
	}

	// Errors.
	for _, fn := range []func() error{
		func() error { _, err := c.CreateSecret(bg(), "", "v", nil); return err },
		func() error { _, err := c.UpdateSecret(bg(), "", nil); return err },
		func() error { _, err := c.DeleteSecret(bg(), "", nil); return err },
	} {
		wantCode(t, fn(), ErrorCodeValidation)
	}
	_, err = c.CreateSecret(bg(), "X", "v", &CreateSecretOptions{TagSlugs: []string{"nope"}})
	wantCode(t, err, ErrorCodeNotFound)
	_, err = c.UpdateSecret(bg(), "X", &UpdateSecretOptions{TagSlugs: []string{"nope"}})
	wantCode(t, err, ErrorCodeNotFound)
	m.fixture(t, http.MethodPost, "/api/v4/secrets/DUP", "createSecret.duplicate400")
	_, err = c.CreateSecret(bg(), "DUP", "v", nil)
	wantCode(t, err, ErrorCodeConflict)
	m.fixture(t, http.MethodPost, "/api/v4/secrets/P", "createSecret.personalAsIdentity400")
	_, err = c.CreateSecret(bg(), "P", "v", &CreateSecretOptions{Type: SecretTypePersonal})
	wantCode(t, err, ErrorCodeValidation)
	m.fixture(t, http.MethodPost, "/api/v4/secrets/F", "createSecret.folderMissing404")
	_, err = c.CreateSecret(bg(), "F", "v", &CreateSecretOptions{SecretPath: "/missing"})
	wantCode(t, err, ErrorCodeNotFound)
	m.fixture(t, http.MethodDelete, "/api/v4/secrets/GONE", "deleteSecret.404")
	_, err = c.DeleteSecret(bg(), "GONE", nil)
	wantCode(t, err, ErrorCodeNotFound)
	m.fixture(t, http.MethodPatch, "/api/v4/secrets/GONE", "getSecret.404")
	_, err = c.UpdateSecret(bg(), "GONE", &UpdateSecretOptions{Value: String("x")})
	wantCode(t, err, ErrorCodeNotFound)
	m.json(http.MethodGet, "/api/v1/projects/"+testProject+"/tags", 500, errBody(500, "Internal", "x"))
	_, err = c.CreateSecret(bg(), "X", "v", &CreateSecretOptions{TagSlugs: []string{"t"}})
	wantCode(t, err, ErrorCodeUnavailable)

	nc := newMockClient(t, m, func(cfg *Config) { cfg.Environment = "" })
	for _, fn := range []func() error{
		func() error { _, err := nc.GetSecret(bg(), "X", nil); return err },
		func() error { _, err := nc.CreateSecret(bg(), "X", "v", nil); return err },
		func() error { _, err := nc.UpdateSecret(bg(), "X", nil); return err },
		func() error { _, err := nc.DeleteSecret(bg(), "X", nil); return err },
		func() error { _, err := nc.CreateSecrets(bg(), []SecretInput{{Key: "A"}}, nil); return err },
		func() error { _, err := nc.UpdateSecrets(bg(), []SecretUpdate{{Key: "A"}}, nil); return err },
		func() error { _, err := nc.DeleteSecrets(bg(), []string{"A"}, nil); return err },
	} {
		wantCode(t, fn(), ErrorCodeConfig)
	}
}

func TestBatchSecrets(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodPost, "/api/v4/secrets/batch", "createSecrets.ok")
	m.fixture(t, http.MethodPatch, "/api/v4/secrets/batch", "updateSecrets.upsert")
	m.fixture(t, http.MethodDelete, "/api/v4/secrets/batch", "deleteSecrets.ok")
	c := newMockClient(t, m, nil)

	out, err := c.CreateSecrets(bg(), []SecretInput{
		{Key: "B1", Value: "b1"},
		{Key: "B2", Value: "b2", Comment: "c", TagIDs: []string{"t"}, SkipMultilineEncoding: true, Metadata: map[string]string{"k": "v"}},
	}, &BatchScope{SecretPath: "/"})
	if err != nil || len(out) != 2 {
		t.Fatalf("create batch: %v", err)
	}
	b := m.last(t, http.MethodPost, "/api/v4/secrets/batch").Body
	items := b["secrets"].([]any)
	if len(items) != 2 || str(items[1].(map[string]any)["secretComment"]) != "c" || str(b["secretPath"]) != "/" {
		t.Fatalf("create batch body: %v", b)
	}
	out, err = c.UpdateSecrets(bg(), []SecretUpdate{
		{Key: "UP", Value: String("u"), NewName: "UP2", Comment: String("c"), TagIDs: []string{}, SkipMultilineEncoding: Bool(true)},
	}, &UpdateSecretsOptions{Mode: BatchModeUpsert})
	if err != nil || len(out) != 1 {
		t.Fatalf("update batch: %v", err)
	}
	b = m.last(t, http.MethodPatch, "/api/v4/secrets/batch").Body
	item := b["secrets"].([]any)[0].(map[string]any)
	if str(b["mode"]) != "upsert" || str(item["secretValue"]) != "u" || str(item["newSecretName"]) != "UP2" || item["skipMultilineEncoding"] != true {
		t.Fatalf("update batch body: %v", b)
	}
	if _, err := c.UpdateSecrets(bg(), []SecretUpdate{{Key: "UP"}}, nil); err != nil {
		t.Fatal(err)
	}
	if b = m.last(t, http.MethodPatch, "/api/v4/secrets/batch").Body; b["mode"] != nil {
		t.Fatal("mode must be omitted by default")
	}
	out, err = c.DeleteSecrets(bg(), []string{"B1", "B2"}, &DeleteSecretsOptions{Type: SecretTypeShared})
	if err != nil || len(out) == 0 {
		t.Fatalf("delete batch: %v", err)
	}
	if item = m.last(t, http.MethodDelete, "/api/v4/secrets/batch").Body["secrets"].([]any)[0].(map[string]any); str(item["type"]) != "shared" {
		t.Fatalf("delete batch item: %v", item)
	}

	for _, fn := range []func() error{
		func() error { _, err := c.CreateSecrets(bg(), nil, nil); return err },
		func() error { _, err := c.UpdateSecrets(bg(), nil, nil); return err },
		func() error { _, err := c.DeleteSecrets(bg(), nil, nil); return err },
		func() error { _, err := c.CreateSecrets(bg(), []SecretInput{{Key: " "}}, nil); return err },
		func() error { _, err := c.UpdateSecrets(bg(), []SecretUpdate{{}}, nil); return err },
		func() error { _, err := c.DeleteSecrets(bg(), []string{""}, nil); return err },
	} {
		wantCode(t, fn(), ErrorCodeValidation)
	}
	m.fixture(t, http.MethodPost, "/api/v4/secrets/batch", "createSecrets.duplicate400")
	_, err = c.CreateSecrets(bg(), []SecretInput{{Key: "A", Value: "1"}}, nil)
	wantCode(t, err, ErrorCodeConflict)
	m.fixture(t, http.MethodPatch, "/api/v4/secrets/batch", "updateSecrets.404")
	_, err = c.UpdateSecrets(bg(), []SecretUpdate{{Key: "A"}}, nil)
	wantCode(t, err, ErrorCodeNotFound)
	m.fixture(t, http.MethodDelete, "/api/v4/secrets/batch", "deleteSecrets.404")
	_, err = c.DeleteSecrets(bg(), []string{"A"}, nil)
	wantCode(t, err, ErrorCodeNotFound)
}

// TestV3Fallback: a server without the v4 routes answers 404 "Route … not
// found"; the client switches to /api/v3/secrets/raw for good.
func TestV3Fallback(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v3/secrets/raw", "listSecrets.v3raw-ok")
	m.fixture(t, http.MethodGet, "/api/v3/secrets/raw/V3_49LJ3988", "getSecret.v3raw-ok")
	m.fixture(t, http.MethodPost, "/api/v3/secrets/raw/V3_49LJ3988", "createSecret.v3raw-ok")
	m.fixture(t, http.MethodPatch, "/api/v3/secrets/raw/V3_49LJ3988", "updateSecret.v3raw-ok")
	m.fixture(t, http.MethodDelete, "/api/v3/secrets/raw/V3_49LJ3988", "deleteSecret.v3raw-ok")
	m.fixture(t, http.MethodPost, "/api/v3/secrets/batch/raw", "createSecrets.v3raw-ok")
	m.fixture(t, http.MethodPatch, "/api/v3/secrets/batch/raw", "updateSecrets.v3raw-ok")
	m.fixture(t, http.MethodDelete, "/api/v3/secrets/batch/raw", "deleteSecrets.v3raw-ok")
	c := newMockClient(t, m, nil)

	list, err := c.ListSecrets(bg(), &ListSecretsOptions{TagSlugs: []string{"x"}, IncludePersonalOverrides: true})
	if err != nil || len(list.Secrets) == 0 || c.APIVersion("secrets") != "v3" {
		t.Fatalf("fallback list: %v %s", err, c.APIVersion("secrets"))
	}
	if n := len(m.requests(http.MethodGet, "/api/v4/secrets")); n != 1 {
		t.Fatalf("one v4 probe expected, got %d", n)
	}
	q := m.last(t, http.MethodGet, "/api/v3/secrets/raw").Query
	if q.Get("workspaceId") != testProject || q.Get("include_imports") != "true" || q.Get("expandSecretReferences") != "true" || q.Has("projectId") || q.Has("viewSecretValue") {
		t.Fatalf("v3 query: %v", q)
	}
	if s, err := c.GetSecret(bg(), "V3_49LJ3988", &GetSecretOptions{Version: 1}); err != nil || s.Value.Reveal() != "r1" {
		t.Fatalf("v3 get: %v", err)
	}
	if _, err := c.CreateSecret(bg(), "V3_49LJ3988", "r1", nil); err != nil {
		t.Fatal(err)
	}
	if b := m.last(t, http.MethodPost, "/api/v3/secrets/raw/V3_49LJ3988").Body; str(b["workspaceId"]) != testProject || b["projectId"] != nil {
		t.Fatalf("v3 body: %v", b)
	}
	if _, err := c.UpdateSecret(bg(), "V3_49LJ3988", &UpdateSecretOptions{Value: String("r2")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteSecret(bg(), "V3_49LJ3988", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateSecrets(bg(), []SecretInput{{Key: "V3B", Value: "x"}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateSecrets(bg(), []SecretUpdate{{Key: "V3B", Value: String("y")}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteSecrets(bg(), []string{"V3B"}, nil); err != nil {
		t.Fatal(err)
	}
	if n := len(m.requests(http.MethodGet, "/api/v4/secrets")); n != 1 {
		t.Fatal("v4 must not be probed again")
	}

	// Forced v3 never touches v4.
	m2 := newMock(t)
	m2.fixture(t, http.MethodGet, "/api/v3/secrets/raw/V3_49LJ3988", "getSecret.v3raw-ok")
	f := newMockClient(t, m2, func(cfg *Config) { cfg.APIVersion = "v3" })
	if _, err := f.GetSecret(bg(), "V3_49LJ3988", nil); err != nil || m2.count() != 1 || f.APIVersion("secrets") != "v3" {
		t.Fatalf("forced v3: %v", err)
	}
	// Forced v4 on a server without v4 is UNSUPPORTED (no fallback).
	v4 := newMockClient(t, m2, func(cfg *Config) { cfg.APIVersion = "v4" })
	_, err = v4.GetSecret(bg(), "V3_49LJ3988", nil)
	if e := wantErr(t, err, ErrorCodeUnsupported); !errors.Is(e, errRouteMissing) {
		t.Fatal("route missing marker")
	}
}

func TestVersionDetectionKeepsV4(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v4/secrets/X", "getSecret.404")
	c := newMockClient(t, m, nil)
	_, err := c.GetSecret(bg(), "X", nil)
	wantCode(t, err, ErrorCodeNotFound)
	if c.APIVersion("secrets") != "v4" {
		t.Fatal("a domain 404 pins v4")
	}
	// A network failure leaves the version undetected.
	u := newMockClient(t, m, func(cfg *Config) { cfg.URL = "http://127.0.0.1:1"; cfg.Retry = fastRetry(0) })
	_, err = u.GetSecret(bg(), "X", nil)
	wantCode(t, err, ErrorCodeUnavailable)
	if u.APIVersion("secrets") != "" {
		t.Fatal("undetected after a network error")
	}
}
