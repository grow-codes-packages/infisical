package infisical_test

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	infisical "github.com/grow-codes-packages/infisical/go"
	"github.com/grow-codes-packages/infisical/go/testkit"
)

// TestConformanceAgainstFake runs the shared conformance scenarios against
// the in-memory fake Infisical (the Docker suite runs them against the real one).
func TestConformanceAgainstFake(t *testing.T) {
	f := newFake(t)
	testkit.Run(t, "../conformance/scenarios", testkit.Options{
		Categories: []string{"core", "secrets"},
		Factories: testkit.Factories{
			"core": testkit.CoreFactory(func(context.Context) (testkit.CoreTarget, error) {
				return f.client(t, nil), nil
			}),
			"secrets": testkit.SecretsFactory(func(context.Context) (infisical.SecretsProvider, error) {
				return f.client(t, nil).Secrets(), nil
			}),
		},
		Capabilities: []string{"write", "delete", "versions"},
		ServiceName:  "grow-conformance-go-unit",
	})
}

func TestProviderModel(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := f.client(t, nil)
	p := c.Secrets()

	v, err := p.Set(ctx, "app/db/PASSWORD", "pw-1", &infisical.SetOptions{Description: "db", Tags: map[string]string{"team-a": "#ff0000", "plain": "x"}})
	if err != nil || v != "1" {
		t.Fatalf("set creates folders: %v %q", err, v)
	}
	if f.callCount("POST /api/v2/folders") != 2 {
		t.Fatalf("app and app/db folders expected, got %d", f.callCount("POST /api/v2/folders"))
	}
	v, err = p.Set(ctx, "app/db/PASSWORD", "pw-2", &infisical.SetOptions{Description: "db2"})
	if err != nil || v != "2" {
		t.Fatalf("set updates: %v %q", err, v)
	}
	sv, err := p.Get(ctx, "app/db/PASSWORD", nil)
	if err != nil || sv.Version() != "2" {
		t.Fatalf("get: %v", err)
	}
	if s, _ := sv.Reveal(); s != "pw-2" {
		t.Fatalf("value %q", s)
	}
	md, err := p.Metadata(ctx, "app/db/PASSWORD", nil)
	if err != nil || md.Path != "/app/db" || md.Version != "2" || md.Extra["comment"] != "db2" || md.Tags["team-a"] != "team-a" || md.Extra["id"] == "" {
		t.Fatalf("metadata: %v %+v", err, md)
	}
	// Path option replaces the base path.
	if sv, err := p.Get(ctx, "PASSWORD", &infisical.GetOptions{Path: "/app/db"}); err != nil || sv == nil {
		t.Fatalf("path option: %v", err)
	}
	// Versions are integers.
	if _, err := p.Get(ctx, "app/db/PASSWORD", &infisical.GetOptions{Version: "abc"}); !errors.Is(err, infisical.ErrValidation) {
		t.Fatalf("bad version: %v", err)
	}
	if _, err := p.Metadata(ctx, "app/db/PASSWORD", &infisical.GetOptions{Version: "0"}); !errors.Is(err, infisical.ErrValidation) {
		t.Fatalf("bad version: %v", err)
	}
	if sv, err := p.Get(ctx, "app/db/PASSWORD", &infisical.GetOptions{Version: "2"}); err != nil || sv == nil {
		t.Fatalf("version get: %v", err)
	}

	// List: folder, folder with trailing slash, key-prefix fallback, missing folder.
	_, _ = p.Set(ctx, "app/db/USER", "u", nil)
	_, _ = p.Set(ctx, "app/db/HOST", "h", nil)
	for _, arg := range []string{"app/db", "app/db/", "/app/db/"} {
		mds, err := p.List(ctx, arg)
		if err != nil || len(mds) != 3 || mds[0].Name != "app/db/HOST" {
			t.Fatalf("list %q: %v %+v", arg, err, mds)
		}
	}
	if mds, err := p.List(ctx, "app/db/US"); err != nil || len(mds) != 1 || mds[0].Name != "app/db/USER" {
		t.Fatalf("prefix list: %v %+v", err, mds)
	}
	for _, arg := range []string{"nope/", "nope/deeper/X"} {
		if mds, err := p.List(ctx, arg); err != nil || len(mds) != 0 {
			t.Fatalf("missing %q: %v %+v", arg, err, mds)
		}
	}
	all, err := p.GetAll(ctx, "app/db/")
	if err != nil || len(all) != 3 {
		t.Fatalf("getAll: %v %d", err, len(all))
	}
	if s, _ := all["app/db/USER"].Reveal(); s != "u" {
		t.Fatalf("getAll names: %v", all)
	}
	if all, err := p.GetAll(ctx, "missing"); err != nil || len(all) != 0 {
		t.Fatalf("getAll missing: %v", err)
	}
	if mds, err := p.List(ctx, ""); err != nil || len(mds) != 0 {
		t.Fatalf("root list: %v", err)
	}

	// loadEnv over a folder uses the key as the variable name.
	t.Setenv("GROWUNIT_USER", "")
	_ = os.Unsetenv("GROWUNIT_USER")
	names, err := p.LoadEnv(ctx, "app/db", &infisical.LoadEnvOptions{Prefix: "GROWUNIT_", Override: true})
	if err != nil || len(names) != 3 || os.Getenv("GROWUNIT_USER") != "u" {
		t.Fatalf("loadEnv: %v %v", err, names)
	}
	for k := range names {
		_ = os.Unsetenv(k)
	}

	// Unsupported and invalid writes.
	cas := 1
	if _, err := p.Set(ctx, "X", "v", &infisical.SetOptions{CAS: &cas}); !errors.Is(err, infisical.ErrUnsupported) {
		t.Fatalf("cas: %v", err)
	}
	if _, err := p.Set(ctx, "X", []byte{0xff, 0xfe}, nil); !errors.Is(err, infisical.ErrValidation) {
		t.Fatalf("binary: %v", err)
	}
	if _, err := p.Set(ctx, "dir/", "v", nil); !errors.Is(err, infisical.ErrValidation) {
		t.Fatalf("no key: %v", err)
	}
	if err := p.Delete(ctx, "app/db/USER", &infisical.DeleteOptions{Versions: []string{"1"}}); !errors.Is(err, infisical.ErrUnsupported) {
		t.Fatalf("versions: %v", err)
	}
	if err := p.Delete(ctx, "app/db/USER", &infisical.DeleteOptions{Permanent: true}); !errors.Is(err, infisical.ErrUnsupported) {
		t.Fatalf("permanent: %v", err)
	}
	if err := p.Delete(ctx, "dir/", nil); !errors.Is(err, infisical.ErrValidation) {
		t.Fatalf("delete no key: %v", err)
	}
	if _, err := p.Metadata(ctx, "dir/", nil); !errors.Is(err, infisical.ErrValidation) {
		t.Fatalf("metadata no key: %v", err)
	}
	if err := p.Delete(ctx, "app/db/USER", nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, "app/db/USER", nil); !errors.Is(err, infisical.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if md, err := p.Metadata(ctx, "app/db/USER", nil); err != nil || md != nil {
		t.Fatalf("metadata missing: %v", err)
	}
	// Existing tags are reused.
	if _, err := p.Set(ctx, "T", "v", &infisical.SetOptions{Tags: map[string]string{"team-a": ""}}); err != nil {
		t.Fatal(err)
	}
	if p.Options().BasePath != "/" {
		t.Fatal("base path")
	}
}

func TestProviderWithOptions(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := f.client(t, nil)
	p := c.SecretsWith(infisical.SecretsProviderOptions{Environment: "staging", BasePath: "/svc", ExpandReferences: infisical.Bool(false), IncludeImports: infisical.Bool(false)})
	if _, err := p.Set(ctx, "A", "1", nil); err != nil {
		t.Fatal(err)
	}
	if sv, err := c.GetSecret(ctx, "A", &infisical.GetSecretOptions{Environment: "staging", SecretPath: "/svc"}); err != nil || sv.Value.Reveal() != "1" {
		t.Fatalf("staging/svc: %v", err)
	}
	if v, ok, err := p.GetString(ctx, "A", nil); err != nil || !ok || v != "1" {
		t.Fatalf("getString: %v", err)
	}
}

func TestProviderErrors(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := f.client(t, nil)
	p := c.Secrets()
	f.mu.Lock()
	f.failNext["GET /api/v4/secrets/X"] = 500
	f.mu.Unlock()
	if _, err := p.Get(ctx, "X", nil); !errors.Is(err, infisical.ErrUnavailable) {
		t.Fatalf("get 500: %v", err)
	}
	f.mu.Lock()
	f.failNext["GET /api/v4/secrets/X"] = 403
	f.mu.Unlock()
	if _, err := p.Metadata(ctx, "X", nil); !errors.Is(err, infisical.ErrPermissionDenied) {
		t.Fatalf("metadata 403: %v", err)
	}
	f.mu.Lock()
	f.failNext["GET /api/v4/secrets"] = 403
	f.mu.Unlock()
	if _, err := p.List(ctx, "a"); !errors.Is(err, infisical.ErrPermissionDenied) {
		t.Fatalf("list 403: %v", err)
	}
	f.mu.Lock()
	f.failNext["GET /api/v4/secrets"] = 403
	f.mu.Unlock()
	if _, err := p.GetAll(ctx, ""); !errors.Is(err, infisical.ErrPermissionDenied) {
		t.Fatalf("getAll 403: %v", err)
	}
	f.mu.Lock()
	f.failNext["POST /api/v2/folders"] = 403
	f.mu.Unlock()
	if _, err := p.Set(ctx, "deep/K", "v", nil); !errors.Is(err, infisical.ErrPermissionDenied) {
		t.Fatalf("folder 403: %v", err)
	}
	f.mu.Lock()
	f.failNext["GET /api/v1/projects/"+fakeProject+"/tags"] = 500
	f.mu.Unlock()
	if _, err := p.Set(ctx, "K", "v", &infisical.SetOptions{Tags: map[string]string{"t": ""}}); !errors.Is(err, infisical.ErrUnavailable) {
		t.Fatalf("tags 500: %v", err)
	}
	f.mu.Lock()
	f.failNext["POST /api/v1/projects/"+fakeProject+"/tags"] = 403
	f.mu.Unlock()
	if _, err := p.Set(ctx, "K", "v", &infisical.SetOptions{Tags: map[string]string{"t": ""}}); !errors.Is(err, infisical.ErrPermissionDenied) {
		t.Fatalf("create tag 403: %v", err)
	}
	f.mu.Lock()
	f.failNext["POST /api/v4/secrets/K"] = 403
	f.mu.Unlock()
	if _, err := p.Set(ctx, "K", "v", nil); !errors.Is(err, infisical.ErrPermissionDenied) {
		t.Fatalf("create 403: %v", err)
	}
}

func TestProviderWatchAndCache(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := f.client(t, nil)
	p := c.Secrets()
	if _, err := p.Set(ctx, "W", "one", nil); err != nil {
		t.Fatal(err)
	}
	changes := make(chan string, 4)
	h := p.Watch(ctx, "W", 10*time.Millisecond, func(n, _ *infisical.SecretValue) {
		if n == nil {
			changes <- "<deleted>"
			return
		}
		s, _ := n.Reveal()
		changes <- s
	}, nil)
	defer h.Stop()
	time.Sleep(30 * time.Millisecond)
	if _, err := p.Set(ctx, "W", "two", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-changes:
		if got != "two" {
			t.Fatalf("watch: %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no change seen")
	}
	cache := infisical.NewSecretCache(p, &infisical.CacheOptions{TTL: time.Minute})
	for i := 0; i < 3; i++ {
		if v, ok, err := cache.GetString(ctx, "W", nil); err != nil || !ok || v != "two" {
			t.Fatalf("cache: %v", err)
		}
	}
	if st := cache.Stats(); st.Hits != 2 {
		t.Fatalf("cache stats %+v", st)
	}
}

func TestClientLoadEnvAndDotenv(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	c := f.client(t, nil)
	for k, v := range map[string]string{"GROWLE_A": "a\"q\\x", "GROWLE_B": "multi\nline", "GROWLE_C": "c"} {
		if _, err := c.CreateSecret(ctx, k, v, nil); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GROWLE_C", "keep")
	names, err := c.LoadEnv(ctx, &infisical.EnvOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("GROWLE_A"); _ = os.Unsetenv("GROWLE_B") })
	sort.Strings(names)
	if strings.Join(names, ",") != "GROWLE_A,GROWLE_B" || os.Getenv("GROWLE_C") != "keep" || os.Getenv("GROWLE_B") != "multi\nline" {
		t.Fatalf("loadEnv: %v", names)
	}
	names, err = c.LoadEnv(ctx, &infisical.EnvOptions{Override: true})
	if err != nil || len(names) != 3 || os.Getenv("GROWLE_C") != "c" {
		t.Fatalf("override: %v %v", err, names)
	}
	doc, err := c.ExportDotenv(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "GROWLE_A=\"a\\\"q\\\\x\"\nGROWLE_B=\"multi\\nline\"\nGROWLE_C=\"c\"\n"
	if doc != want {
		t.Fatalf("dotenv:\n%q\nwant\n%q", doc, want)
	}
	if _, err := c.LoadEnv(ctx, &infisical.EnvOptions{SecretPath: "/missing"}); !errors.Is(err, infisical.ErrNotFound) {
		t.Fatalf("missing path: %v", err)
	}
	if _, err := c.ExportDotenv(ctx, &infisical.EnvOptions{SecretPath: "/missing"}); !errors.Is(err, infisical.ErrNotFound) {
		t.Fatalf("missing path: %v", err)
	}
	if _, err := c.LoadEnv(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := infisical.FormatDotenv(map[string]string{"K": "a\rb"}); got != "K=\"a\\rb\"\n" {
		t.Fatalf("cr: %q", got)
	}
	// A variable name the OS rejects.
	if _, err := c.CreateSecret(ctx, "BAD=NAME", "x", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoadEnv(ctx, &infisical.EnvOptions{Override: true}); !errors.Is(err, infisical.ErrValidation) {
		t.Fatalf("bad env name: %v", err)
	}
}
