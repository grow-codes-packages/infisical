package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	infisical "github.com/grow-codes-packages/infisical/go"
)

// Integration tests: every public function of the package is called against
// the real Infisical from docker/compose.yml with a round-trip assertion.

type fixture struct {
	t       *testing.T
	ctx     context.Context
	run     string // lower-case unique id
	key     string // upper-case key prefix
	project string
	env     string
	c       *infisical.Client
}

func setup(t *testing.T) *fixture {
	t.Helper()
	bootstrap := os.Getenv("GROW_BOOTSTRAP_ENV")
	if bootstrap == "" {
		bootstrap = "/bootstrap/env"
	}
	loadBootstrapEnv(t, bootstrap)
	if os.Getenv("GROW_INFISICAL_URL") == "" {
		t.Skip("GROW_INFISICAL_URL is not set; run through docker/compose.yml")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	run := hex.EncodeToString(b)
	c, err := infisical.NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	return &fixture{t: t, ctx: ctx, run: run, key: "SDKGO_" + strings.ToUpper(run) + "_", project: mustEnv(t, "INFISICAL_PROJECT_ID"), env: mustEnv(t, "INFISICAL_ENVIRONMENT"), c: c}
}

func mustEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s missing from the bootstrap environment", name)
	}
	return v
}

// clientWith builds a client for the same server with a different auth.
func (f *fixture) clientWith(mutate func(*infisical.Config)) *infisical.Client {
	f.t.Helper()
	cfg, err := infisical.ConfigFromEnv()
	if err != nil {
		f.t.Fatal(err)
	}
	cfg.ClientID, cfg.ClientSecret = "", infisical.Secret{}
	mutate(&cfg)
	c, err := infisical.NewClient(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = c.Close() })
	return c
}

func code(t *testing.T, err error, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("want %v, got %v", want, err)
	}
}

func reveal(t *testing.T, s *infisical.SecretEntry) string {
	t.Helper()
	if s == nil {
		t.Fatal("nil secret")
	}
	return s.Value.Reveal()
}

func TestCoreClient(t *testing.T) {
	f := setup(t)
	hs, err := f.c.Health(f.ctx)
	if err != nil || !hs.Healthy || hs.Status != "ok" {
		t.Fatalf("health: %+v %v", hs, err)
	}
	if d, err := f.c.Ping(f.ctx); err != nil || d <= 0 {
		t.Fatalf("ping: %v", err)
	}
	_, err = f.c.ServerVersion(f.ctx)
	code(t, err, infisical.ErrUnsupported)
	if f.c.Config().ProjectID != f.project || f.c.Config().Environment != f.env {
		t.Fatalf("config from env: %s", f.c.Config())
	}
	if strings.Contains(f.c.Config().String(), os.Getenv("INFISICAL_CLIENT_SECRET")) {
		t.Fatal("config prints the client secret")
	}
	if _, err := f.c.GetSecret(f.ctx, mustEnv(t, "INFISICAL_SEED_SECRET_NAME"), nil); err != nil {
		t.Fatal(err)
	}
	if v := f.c.APIVersion("secrets"); v != "v4" {
		t.Fatalf("detected secrets API %q, want v4 on the pinned server", v)
	}
	if err := f.c.Close(); err != nil || f.c.Close() != nil {
		t.Fatal("close must be idempotent")
	}
}

func TestAuthMethods(t *testing.T) {
	f := setup(t)
	seed, seedValue := mustEnv(t, "INFISICAL_SEED_SECRET_NAME"), mustEnv(t, "INFISICAL_SEED_SECRET_VALUE")

	t.Run("universal auth login renew revoke", func(t *testing.T) {
		a := f.c.Auth()
		if _, ok := a.Method().(*infisical.UniversalAuth); !ok {
			t.Fatalf("fromEnv must select UniversalAuth, got %T", a.Method())
		}
		tok, err := a.Login(f.ctx)
		if err != nil || tok.Token.IsZero() || tok.ExpiresIn <= 0 || tok.MaxTTL < tok.ExpiresIn {
			t.Fatalf("login: %v %+v", err, tok)
		}
		renewed, err := a.Renew(f.ctx)
		if err != nil || renewed.Token.IsZero() || a.Token().Token.Reveal() != renewed.Token.Reveal() {
			t.Fatalf("renew: %v", err)
		}
		old := a.Token().Token
		if err := a.Revoke(f.ctx); err != nil || a.Token() != nil {
			t.Fatalf("revoke: %v", err)
		}
		// The revoked token is rejected; the client logs in again on its own.
		static := f.clientWith(func(cfg *infisical.Config) { cfg.Token = old })
		_, err = static.Ping(f.ctx)
		code(t, err, infisical.ErrAuthentication)
		if s, err := f.c.GetSecret(f.ctx, seed, nil); err != nil || reveal(t, s) != seedValue {
			t.Fatalf("auto re-login: %v", err)
		}
		// Token replaced behind the client's back → one re-login on 401.
		a.SetToken(old)
		if _, err := f.c.Ping(f.ctx); err != nil {
			t.Fatalf("SetToken + 401 relogin: %v", err)
		}
	})

	t.Run("universal auth methods", func(t *testing.T) {
		ua := infisical.NewUniversalAuth(mustEnv(t, "INFISICAL_CLIENT_ID"), mustEnv(t, "INFISICAL_CLIENT_SECRET"))
		tok, err := ua.Login(f.ctx, f.c)
		if err != nil {
			t.Fatal(err)
		}
		tok2, err := ua.Renew(f.ctx, f.c, tok.Token)
		if err != nil || tok2.ExpiresIn <= 0 {
			t.Fatalf("renew: %v", err)
		}
		if err := ua.Revoke(f.ctx, f.c, tok2.Token); err != nil {
			t.Fatal(err)
		}
		_, err = ua.Renew(f.ctx, f.c, tok2.Token)
		code(t, err, infisical.ErrAuthentication)
		// One wrong secret (lockout is disabled for the test identity).
		bad := f.clientWith(func(cfg *infisical.Config) {
			cfg.Auth = infisical.NewUniversalAuth(mustEnv(t, "INFISICAL_CLIENT_ID"), "wrong-secret-"+f.run)
		})
		_, err = bad.Ping(f.ctx)
		code(t, err, infisical.ErrAuthentication)
	})

	t.Run("token auth kinds", func(t *testing.T) {
		for _, name := range []string{"INFISICAL_VIEWER_TOKEN", "INFISICAL_SERVICE_TOKEN", "INFISICAL_USER_TOKEN"} {
			c := f.clientWith(func(cfg *infisical.Config) { cfg.Auth = infisical.NewTokenAuth(mustEnv(t, name)) })
			if _, err := c.Ping(f.ctx); err != nil {
				t.Fatalf("%s ping: %v", name, err)
			}
			if s, err := c.GetSecret(f.ctx, seed, nil); err != nil || reveal(t, s) != seedValue {
				t.Fatalf("%s get: %v", name, err)
			}
		}
		malformed := f.clientWith(func(cfg *infisical.Config) { cfg.Token = infisical.NewSecret("not-a-token-" + f.run) })
		_, err := malformed.Ping(f.ctx)
		code(t, err, infisical.ErrAuthentication)
		noAccess := f.clientWith(func(cfg *infisical.Config) { cfg.Token = infisical.NewSecret(mustEnv(t, "INFISICAL_NOACCESS_TOKEN")) })
		_, err = noAccess.ListSecrets(f.ctx, nil)
		code(t, err, infisical.ErrPermissionDenied)
	})

	t.Run("kubernetes and aws request shapes", func(t *testing.T) {
		id := mustEnv(t, "INFISICAL_NOACCESS_IDENTITY_ID")
		_, err := (&infisical.KubernetesAuth{IdentityID: id, JWT: infisical.NewSecret("eyJhbGciOiJSUzI1NiJ9.e30.sig")}).Login(f.ctx, f.c)
		if !errors.Is(err, infisical.ErrNotFound) || !strings.Contains(err.Error(), "Kubernetes auth method not found") {
			t.Fatalf("kubernetes: %v", err)
		}
		aws := &infisical.AwsIamAuth{IdentityID: id, Region: "us-east-1", AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: infisical.NewSecret("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")}
		if req, err := aws.LoginRequest(); err != nil || req.IamRequestHeaders == "" {
			t.Fatalf("aws request: %v", err)
		}
		_, err = aws.Login(f.ctx, f.c)
		if !errors.Is(err, infisical.ErrNotFound) || !strings.Contains(err.Error(), "AWS auth method not found") {
			t.Fatalf("aws: %v", err)
		}
	})
}

func TestSecretsCRUD(t *testing.T) {
	f := setup(t)
	k := f.key + "ONE"
	tag, err := f.c.CreateTag(f.ctx, "go-"+f.run, "#00aa00", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = f.c.DeleteTag(f.ctx, tag.ID, nil) }()

	created, err := f.c.CreateSecret(f.ctx, k, "v1-"+f.run, &infisical.CreateSecretOptions{Comment: "c1", TagSlugs: []string{tag.Slug}})
	if err != nil || created.Version != 1 {
		t.Fatalf("create: %v", err)
	}
	got, err := f.c.GetSecret(f.ctx, k, nil)
	if err != nil || reveal(t, got) != "v1-"+f.run || got.Comment != "c1" || len(got.Tags) != 1 || got.Tags[0].Slug != tag.Slug {
		t.Fatalf("get: %v %+v", err, got)
	}
	_, err = f.c.CreateSecret(f.ctx, k, "dup", nil)
	code(t, err, infisical.ErrConflict)

	if _, err := f.c.UpdateSecret(f.ctx, k, &infisical.UpdateSecretOptions{Value: infisical.String("v2-" + f.run)}); err != nil {
		t.Fatal(err)
	}
	if got, err = f.c.GetSecret(f.ctx, k, nil); err != nil || reveal(t, got) != "v2-"+f.run || got.Version != 2 {
		t.Fatalf("updated value: %v", err)
	}
	if old, err := f.c.GetSecret(f.ctx, k, &infisical.GetSecretOptions{Version: 1}); err != nil || reveal(t, old) != "v1-"+f.run {
		t.Fatalf("version 1: %v", err)
	}
	renamed := f.key + "RENAMED"
	if _, err := f.c.UpdateSecret(f.ctx, k, &infisical.UpdateSecretOptions{NewName: renamed, Comment: infisical.String("c2"), TagIDs: []string{}}); err != nil {
		t.Fatal(err)
	}
	if got, err = f.c.GetSecret(f.ctx, renamed, nil); err != nil || got.Comment != "c2" || len(got.Tags) != 0 || reveal(t, got) != "v2-"+f.run {
		t.Fatalf("renamed: %v %+v", err, got)
	}
	_, err = f.c.GetSecret(f.ctx, k, nil)
	code(t, err, infisical.ErrNotFound)

	list, err := f.c.ListSecrets(f.ctx, nil)
	if err != nil || !slices.ContainsFunc(list.Secrets, func(s infisical.SecretEntry) bool { return s.Key == renamed }) {
		t.Fatalf("list: %v", err)
	}
	if _, err := f.c.UpdateSecret(f.ctx, renamed, &infisical.UpdateSecretOptions{TagSlugs: []string{tag.Slug}}); err != nil {
		t.Fatal(err)
	}
	tagged, err := f.c.ListSecrets(f.ctx, &infisical.ListSecretsOptions{TagSlugs: []string{tag.Slug}})
	if err != nil || len(tagged.Secrets) != 1 || tagged.Secrets[0].Key != renamed {
		t.Fatalf("tag filter: %v %+v", err, tagged)
	}
	hidden, err := f.c.GetSecret(f.ctx, renamed, &infisical.GetSecretOptions{ViewSecretValue: infisical.Bool(false)})
	if err != nil || !hidden.ValueHidden {
		t.Fatalf("hidden: %v", err)
	}

	// References: expanded by default, raw on request.
	host, dsn := f.key+"HOST", f.key+"DSN"
	if _, err := f.c.CreateSecret(f.ctx, host, "db.local", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.CreateSecret(f.ctx, dsn, "pg://${"+host+"}/x", nil); err != nil {
		t.Fatal(err)
	}
	if s, err := f.c.GetSecret(f.ctx, dsn, nil); err != nil || reveal(t, s) != "pg://db.local/x" {
		t.Fatalf("expanded: %v %q", err, reveal(t, s))
	}
	if s, err := f.c.GetSecret(f.ctx, dsn, &infisical.GetSecretOptions{ExpandReferences: infisical.Bool(false)}); err != nil || reveal(t, s) != "pg://${"+host+"}/x" {
		t.Fatalf("raw: %v", err)
	}

	for _, name := range []string{renamed, host, dsn} {
		if _, err := f.c.DeleteSecret(f.ctx, name, nil); err != nil {
			t.Fatal(err)
		}
	}
	_, err = f.c.GetSecret(f.ctx, renamed, nil)
	code(t, err, infisical.ErrNotFound)
	_, err = f.c.DeleteSecret(f.ctx, renamed, nil)
	code(t, err, infisical.ErrNotFound)
}

func TestSecretsBatch(t *testing.T) {
	f := setup(t)
	a, b, up := f.key+"BA", f.key+"BB", f.key+"UP"
	out, err := f.c.CreateSecrets(f.ctx, []infisical.SecretInput{{Key: a, Value: "a1"}, {Key: b, Value: "b1", Comment: "cb"}}, nil)
	if err != nil || len(out) != 2 {
		t.Fatalf("create batch: %v", err)
	}
	if s, err := f.c.GetSecret(f.ctx, b, nil); err != nil || reveal(t, s) != "b1" || s.Comment != "cb" {
		t.Fatalf("read back: %v", err)
	}
	_, err = f.c.CreateSecrets(f.ctx, []infisical.SecretInput{{Key: a, Value: "dup"}}, nil)
	code(t, err, infisical.ErrConflict)
	if _, err := f.c.UpdateSecrets(f.ctx, []infisical.SecretUpdate{{Key: a, Value: infisical.String("a2")}}, nil); err != nil {
		t.Fatal(err)
	}
	if s, err := f.c.GetSecret(f.ctx, a, nil); err != nil || reveal(t, s) != "a2" {
		t.Fatalf("updated: %v", err)
	}
	_, err = f.c.UpdateSecrets(f.ctx, []infisical.SecretUpdate{{Key: up, Value: infisical.String("u")}}, nil)
	code(t, err, infisical.ErrNotFound)
	if _, err := f.c.UpdateSecrets(f.ctx, []infisical.SecretUpdate{{Key: up, Value: infisical.String("u")}}, &infisical.UpdateSecretsOptions{Mode: infisical.BatchModeUpsert}); err != nil {
		t.Fatal(err)
	}
	if s, err := f.c.GetSecret(f.ctx, up, nil); err != nil || reveal(t, s) != "u" {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := f.c.DeleteSecrets(f.ctx, []string{a, b, up}, nil); err != nil {
		t.Fatal(err)
	}
	list, err := f.c.ListSecrets(f.ctx, nil)
	if err != nil || slices.ContainsFunc(list.Secrets, func(s infisical.SecretEntry) bool { return strings.HasPrefix(s.Key, f.key) }) {
		t.Fatalf("batch delete: %v", err)
	}
	_, err = f.c.DeleteSecrets(f.ctx, []string{a}, nil)
	code(t, err, infisical.ErrNotFound)
}

func TestSecretsV3Forced(t *testing.T) {
	f := setup(t)
	v3 := f.clientWith(func(cfg *infisical.Config) {
		cfg.APIVersion = infisical.APIVersionV3
		cfg.ClientID, cfg.ClientSecret = mustEnv(t, "INFISICAL_CLIENT_ID"), infisical.NewSecret(mustEnv(t, "INFISICAL_CLIENT_SECRET"))
	})
	k := f.key + "V3"
	if _, err := v3.CreateSecret(f.ctx, k, "r1", nil); err != nil {
		t.Fatal(err)
	}
	if s, err := v3.GetSecret(f.ctx, k, nil); err != nil || reveal(t, s) != "r1" {
		t.Fatalf("v3 get: %v", err)
	}
	if _, err := v3.UpdateSecret(f.ctx, k, &infisical.UpdateSecretOptions{Value: infisical.String("r2")}); err != nil {
		t.Fatal(err)
	}
	list, err := v3.ListSecrets(f.ctx, nil)
	if err != nil || !slices.ContainsFunc(list.Secrets, func(s infisical.SecretEntry) bool { return s.Key == k && s.Value.Reveal() == "r2" }) {
		t.Fatalf("v3 list: %v", err)
	}
	if _, err := v3.DeleteSecret(f.ctx, k, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := v3.CreateSecrets(f.ctx, []infisical.SecretInput{{Key: k + "B", Value: "x"}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := v3.UpdateSecrets(f.ctx, []infisical.SecretUpdate{{Key: k + "B", Value: infisical.String("y")}}, nil); err != nil {
		t.Fatal(err)
	}
	if s, err := f.c.GetSecret(f.ctx, k+"B", nil); err != nil || reveal(t, s) != "y" {
		t.Fatalf("v3 batch read back via v4: %v", err)
	}
	if _, err := v3.DeleteSecrets(f.ctx, []string{k + "B"}, nil); err != nil {
		t.Fatal(err)
	}
	if v3.APIVersion("secrets") != "v3" {
		t.Fatal("forced v3")
	}
}

func TestPersonalSecretsAndVersions(t *testing.T) {
	f := setup(t)
	user := f.clientWith(func(cfg *infisical.Config) { cfg.Token = infisical.NewSecret(mustEnv(t, "INFISICAL_USER_TOKEN")) })
	k := f.key + "PERS"
	shared, err := f.c.CreateSecret(f.ctx, k, "shared-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.UpdateSecret(f.ctx, k, &infisical.UpdateSecretOptions{Value: infisical.String("shared-2")}); err != nil {
		t.Fatal(err)
	}
	vs, err := user.ListSecretVersions(f.ctx, shared.ID, &infisical.ListSecretVersionsOptions{Limit: 10})
	if err != nil || len(vs) != 2 || vs[0].Version != 2 || vs[0].Value.Reveal() != "shared-2" || vs[1].Value.Reveal() != "shared-1" {
		t.Fatalf("versions: %v %+v", err, vs)
	}
	_, err = f.c.ListSecretVersions(f.ctx, shared.ID, nil)
	code(t, err, infisical.ErrPermissionDenied)

	if _, err := user.CreateSecret(f.ctx, k, "mine", &infisical.CreateSecretOptions{Type: infisical.SecretTypePersonal}); err != nil {
		t.Fatal(err)
	}
	if s, err := user.GetSecret(f.ctx, k, &infisical.GetSecretOptions{Type: infisical.SecretTypePersonal}); err != nil || reveal(t, s) != "mine" || s.Type != infisical.SecretTypePersonal {
		t.Fatalf("personal: %v", err)
	}
	ov, err := user.ListSecrets(f.ctx, &infisical.ListSecretsOptions{IncludePersonalOverrides: true})
	if err != nil || !slices.ContainsFunc(ov.Secrets, func(s infisical.SecretEntry) bool { return s.Key == k && s.Value.Reveal() == "mine" }) {
		t.Fatalf("personal overrides: %v", err)
	}
	if _, err := user.DeleteSecret(f.ctx, k, &infisical.DeleteSecretOptions{Type: infisical.SecretTypePersonal}); err != nil {
		t.Fatal(err)
	}
	if s, err := f.c.GetSecret(f.ctx, k, nil); err != nil || reveal(t, s) != "shared-2" {
		t.Fatalf("shared survives: %v", err)
	}
	_, err = f.c.CreateSecret(f.ctx, k+"X", "x", &infisical.CreateSecretOptions{Type: infisical.SecretTypePersonal})
	code(t, err, infisical.ErrValidation)
	if _, err := f.c.DeleteSecret(f.ctx, k, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFolders(t *testing.T) {
	f := setup(t)
	name := "go-" + f.run
	folder, err := f.c.CreateFolder(f.ctx, name, &infisical.CreateFolderOptions{Path: "/", Description: "d"})
	if err != nil || folder.Path != "/"+name {
		t.Fatalf("create: %v %+v", err, folder)
	}
	if _, err := f.c.CreateFolder(f.ctx, "child", &infisical.CreateFolderOptions{Path: "/" + name}); err != nil {
		t.Fatal(err)
	}
	fs, err := f.c.ListFolders(f.ctx, &infisical.ListFoldersOptions{Path: "/" + name, Recursive: true})
	if err != nil || len(fs) != 1 || fs[0].Name != "child" {
		t.Fatalf("list: %v %+v", err, fs)
	}
	_, err = f.c.CreateFolder(f.ctx, name, nil)
	code(t, err, infisical.ErrConflict)
	_, err = f.c.CreateFolder(f.ctx, "bad name!", nil)
	code(t, err, infisical.ErrValidation)
	if _, err := f.c.UpdateFolder(f.ctx, folder.ID, &infisical.UpdateFolderOptions{Path: "/", Name: name + "-r"}); err != nil {
		t.Fatal(err)
	}
	root, err := f.c.ListFolders(f.ctx, nil)
	if err != nil || !slices.ContainsFunc(root, func(x infisical.Folder) bool { return x.Name == name+"-r" }) {
		t.Fatalf("renamed: %v", err)
	}
	if _, err := f.c.DeleteFolder(f.ctx, folder.ID, &infisical.DeleteFolderOptions{Path: "/", Force: true}); err != nil {
		t.Fatal(err)
	}
	root, _ = f.c.ListFolders(f.ctx, nil)
	if slices.ContainsFunc(root, func(x infisical.Folder) bool { return x.ID == folder.ID }) {
		t.Fatal("folder still listed")
	}
	_, err = f.c.DeleteFolder(f.ctx, folder.ID, nil)
	code(t, err, infisical.ErrNotFound)
}

func TestProjectsEnvironmentsTags(t *testing.T) {
	f := setup(t)
	page, err := f.c.ListProjects(f.ctx, &infisical.ListProjectsOptions{Limit: 100})
	if err != nil || !slices.ContainsFunc(page.Projects, func(p infisical.Project) bool { return p.ID == f.project }) || page.TotalCount < 1 {
		t.Fatalf("list projects: %v", err)
	}
	p, err := f.c.GetProject(f.ctx, "")
	if err != nil || p.ID != f.project || p.Slug != mustEnv(t, "INFISICAL_PROJECT_SLUG") {
		t.Fatalf("get project: %v", err)
	}
	if bySlug, err := f.c.GetProjectBySlug(f.ctx, p.Slug); err != nil || bySlug.ID != p.ID {
		t.Fatalf("by slug: %v", err)
	}
	slug := "go-" + f.run
	created, err := f.c.CreateEnvironment(f.ctx, "Go "+f.run, slug, nil)
	if err != nil || created.Slug != slug {
		t.Fatalf("create env: %v", err)
	}
	envs, err := f.c.ListEnvironments(f.ctx, nil)
	if err != nil || !slices.ContainsFunc(envs, func(e infisical.Environment) bool { return e.Slug == slug }) ||
		!slices.ContainsFunc(envs, func(e infisical.Environment) bool { return e.Slug == mustEnv(t, "INFISICAL_ENVIRONMENT_STAGING") }) {
		t.Fatalf("list envs: %v %+v", err, envs)
	}
	_, err = f.c.CreateEnvironment(f.ctx, "Dup", slug, nil)
	code(t, err, infisical.ErrConflict)
	viewer := f.clientWith(func(cfg *infisical.Config) { cfg.Token = infisical.NewSecret(mustEnv(t, "INFISICAL_VIEWER_TOKEN")) })
	_, err = viewer.CreateEnvironment(f.ctx, "No", "no-"+f.run, nil)
	code(t, err, infisical.ErrPermissionDenied)

	tag, err := f.c.CreateTag(f.ctx, "tag-"+f.run, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	tags, err := f.c.ListTags(f.ctx, nil)
	if err != nil || !slices.ContainsFunc(tags, func(x infisical.Tag) bool { return x.ID == tag.ID && x.Slug == "tag-"+f.run }) {
		t.Fatalf("list tags: %v", err)
	}
	_, err = f.c.CreateTag(f.ctx, "tag-"+f.run, "", nil)
	code(t, err, infisical.ErrConflict)
	if _, err := f.c.DeleteTag(f.ctx, tag.ID, nil); err != nil {
		t.Fatal(err)
	}
	tags, _ = f.c.ListTags(f.ctx, nil)
	if slices.ContainsFunc(tags, func(x infisical.Tag) bool { return x.ID == tag.ID }) {
		t.Fatal("tag still listed")
	}
}

func TestImportsLoadEnvDotenv(t *testing.T) {
	f := setup(t)
	folder := "/imp-" + f.run
	if _, err := f.c.CreateFolder(f.ctx, "imp-"+f.run, nil); err != nil {
		t.Fatal(err)
	}
	k1, k2 := f.key+"E1", f.key+"E2"
	if _, err := f.c.CreateSecrets(f.ctx, []infisical.SecretInput{{Key: k1, Value: "one"}, {Key: k2, Value: "two\nlines"}}, &infisical.BatchScope{SecretPath: folder}); err != nil {
		t.Fatal(err)
	}
	staging := mustEnv(t, "INFISICAL_ENVIRONMENT_STAGING")
	imp, err := f.c.CreateSecretImport(f.ctx, &infisical.CreateSecretImportOptions{Path: folder, ImportEnvironment: staging, ImportPath: "/common"})
	if err != nil {
		t.Fatal(err)
	}
	imps, err := f.c.ListSecretImports(f.ctx, &infisical.SecretImportOptions{Path: folder})
	if err != nil || len(imps) != 1 || imps[0].ID != imp.ID || imps[0].ImportEnvironment.Slug != staging || imps[0].ImportPath != "/common" {
		t.Fatalf("list imports: %v %+v", err, imps)
	}
	list, err := f.c.ListSecrets(f.ctx, &infisical.ListSecretsOptions{SecretPath: folder})
	if err != nil || len(list.Imports) != 1 || list.Merged()["SDK_COMMON"].Value.Reveal() != "common-value-1" {
		t.Fatalf("imported secrets: %v %+v", err, list)
	}

	_ = os.Unsetenv(k1)
	t.Setenv(k2, "keep")
	names, err := f.c.LoadEnv(f.ctx, &infisical.EnvOptions{SecretPath: folder})
	if err != nil || !slices.Contains(names, k1) || slices.Contains(names, k2) || os.Getenv(k1) != "one" || os.Getenv(k2) != "keep" || os.Getenv("SDK_COMMON") != "common-value-1" {
		t.Fatalf("loadEnv: %v %v", err, names)
	}
	t.Cleanup(func() { _ = os.Unsetenv(k1); _ = os.Unsetenv("SDK_COMMON") })
	doc, err := f.c.ExportDotenv(f.ctx, &infisical.EnvOptions{SecretPath: folder, IncludeImports: infisical.Bool(false)})
	want := k1 + "=\"one\"\n" + k2 + "=\"two\\nlines\"\n"
	if err != nil || doc != want {
		t.Fatalf("dotenv: %v\n%q\nwant %q", err, doc, want)
	}

	if _, err := f.c.DeleteSecretImport(f.ctx, imp.ID, &infisical.SecretImportOptions{Path: folder}); err != nil {
		t.Fatal(err)
	}
	if imps, _ := f.c.ListSecretImports(f.ctx, &infisical.SecretImportOptions{Path: folder}); len(imps) != 0 {
		t.Fatal("import still listed")
	}
	_, err = f.c.DeleteSecretImport(f.ctx, imp.ID, &infisical.SecretImportOptions{Path: folder})
	code(t, err, infisical.ErrNotFound)
	if _, err := f.c.DeleteFolder(f.ctx, "imp-"+f.run, &infisical.DeleteFolderOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
}

func TestSecretsProvider(t *testing.T) {
	f := setup(t)
	p := f.c.SecretsWith(infisical.SecretsProviderOptions{BasePath: "/prov-" + f.run})
	v, err := p.Set(f.ctx, "db/PASSWORD", "pw-1", &infisical.SetOptions{Description: "db password", Tags: map[string]string{"prov-" + f.run: "#123456"}})
	if err != nil || v != "1" {
		t.Fatalf("set (creates folders): %v %q", err, v)
	}
	if v, err = p.Set(f.ctx, "db/PASSWORD", map[string]any{"k": "v"}, nil); err != nil || v != "2" {
		t.Fatalf("set (update): %v %q", err, v)
	}
	var obj map[string]string
	if ok, err := p.GetJSON(f.ctx, "db/PASSWORD", &obj, nil); err != nil || !ok || obj["k"] != "v" {
		t.Fatalf("getJSON: %v", err)
	}
	if sv, err := p.Get(f.ctx, "db/PASSWORD", &infisical.GetOptions{Version: "1"}); err != nil || sv == nil {
		t.Fatalf("version 1: %v", err)
	} else if s, _ := sv.Reveal(); s != "pw-1" {
		t.Fatalf("version 1 value %q", s)
	}
	md, err := p.Metadata(f.ctx, "db/PASSWORD", nil)
	if err != nil || md.Path != "/prov-"+f.run+"/db" || md.Version != "2" || md.Tags["prov-"+f.run] == "" || md.Extra["comment"] != "db password" {
		t.Fatalf("metadata: %v %+v", err, md)
	}
	mds, err := p.List(f.ctx, "db/")
	if err != nil || len(mds) != 1 || mds[0].Name != "db/PASSWORD" {
		t.Fatalf("list: %v %+v", err, mds)
	}
	cache := infisical.NewSecretCache(p, nil)
	if ok, err := cache.Exists(f.ctx, "db/PASSWORD", nil); err != nil || !ok {
		t.Fatalf("cache: %v", err)
	}
	changed := make(chan struct{}, 1)
	h := p.Watch(f.ctx, "db/PASSWORD", 200*time.Millisecond, func(n, _ *infisical.SecretValue) {
		if n == nil {
			select {
			case changed <- struct{}{}:
			default:
			}
		}
	}, nil)
	time.Sleep(500 * time.Millisecond)
	if err := p.Delete(f.ctx, "db/PASSWORD", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(10 * time.Second):
		t.Fatal("watch did not see the deletion")
	}
	h.Stop()
	if err := p.Delete(f.ctx, "db/PASSWORD", nil); !errors.Is(err, infisical.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	_, err = p.Set(f.ctx, "BIN", []byte{0xff}, nil)
	code(t, err, infisical.ErrValidation)
	tags, _ := f.c.ListTags(f.ctx, nil)
	for _, tg := range tags {
		if tg.Slug == "prov-"+f.run {
			_, _ = f.c.DeleteTag(f.ctx, tg.ID, nil)
		}
	}
}
