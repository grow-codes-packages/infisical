package infisical

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClientConfig(t *testing.T) {
	t.Run("core.config.env-precedence", func(t *testing.T) {
		env := map[string]string{
			EnvPrefix + "URL": "http://grow:1", "INFISICAL_API_URL": "http://vendor:2/api",
			"INFISICAL_TOKEN": "vendor-token", "INFISICAL_PROJECT_ID": "p-vendor", "INFISICAL_ENVIRONMENT": "staging",
		}
		cfg, err := ConfigFromEnvWith(Config{}, env)
		if err != nil || cfg.URL != "http://grow:1" || cfg.Token.Reveal() != "vendor-token" || cfg.ProjectID != "p-vendor" || cfg.Environment != "staging" {
			t.Fatalf("env: %v %s", err, cfg)
		}
		delete(env, EnvPrefix+"URL")
		env[EnvPrefix+"TOKEN"] = "grow-token"
		env[EnvPrefix+"PROJECT_ID"] = "p-grow"
		cfg, _ = ConfigFromEnvWith(Config{}, env)
		if cfg.URL != "http://vendor:2" || cfg.Token.Reveal() != "grow-token" || cfg.ProjectID != "p-grow" {
			t.Fatalf("vendor url must lose /api and GROW_* must win: %s", cfg)
		}
		cfg, _ = ConfigFromEnvWith(Config{CommonConfig: CommonConfig{URL: "https://explicit/"}, Token: NewSecret("explicit"), ProjectID: "p-x"}, env)
		if cfg.URL != "https://explicit" || cfg.Token.Reveal() != "explicit" || cfg.ProjectID != "p-x" {
			t.Fatal("explicit must win")
		}
		cfg, _ = ConfigFromEnvWith(Config{}, map[string]string{})
		if cfg.URL != DefaultURL || cfg.RequestTimeout != DefaultRequestTimeout || cfg.SecretPath != "/" || cfg.Environment != "" {
			t.Fatalf("defaults: %s", cfg)
		}
		_, err = ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "TOTAL_TIMEOUT": "forever-xyz"})
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), EnvPrefix+"TOTAL_TIMEOUT") || strings.Contains(err.Error(), "forever-xyz") {
			t.Fatalf("invalid value: %v", err)
		}
		_, err = ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "REVOKE_ON_CLOSE": "maybe"})
		wantCode(t, err, ErrorCodeConfig)
		t.Setenv(EnvPrefix+"URL", "http://process-env:9")
		if cfg, err := ConfigFromEnv(); err != nil || cfg.URL != "http://process-env:9" {
			t.Fatalf("process env: %v %s", err, cfg)
		}
	})

	t.Run("universal auth env and CLI aliases", func(t *testing.T) {
		env := map[string]string{
			"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "cid", "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "csecret-1234",
			EnvPrefix + "SECRET_PATH": "app/", EnvPrefix + "API_VERSION": "V3", EnvPrefix + "REVOKE_ON_CLOSE": "yes",
		}
		cfg, err := ConfigFromEnvWith(Config{}, env)
		if err != nil || cfg.ClientID != "cid" || cfg.ClientSecret.Reveal() != "csecret-1234" || cfg.SecretPath != "/app" ||
			cfg.APIVersion != "v3" || !cfg.RevokeOnClose {
			t.Fatalf("aliases: %v %s", err, cfg)
		}
		if _, ok := cfg.authMethod().(*UniversalAuth); !ok {
			t.Fatalf("want UniversalAuth, got %T", cfg.authMethod())
		}
		env["INFISICAL_CLIENT_ID"] = "cid2"
		cfg, _ = ConfigFromEnvWith(Config{}, env)
		if cfg.ClientID != "cid2" {
			t.Fatal("INFISICAL_CLIENT_ID must beat the CLI alias")
		}
		cfg.Token = NewSecret("static")
		if _, ok := cfg.authMethod().(*TokenAuth); !ok {
			t.Fatal("a static token must beat universal auth")
		}
		cfg.Auth = &KubernetesAuth{IdentityID: "i"}
		if _, ok := cfg.authMethod().(*KubernetesAuth); !ok {
			t.Fatal("an explicit Auth must win")
		}
		if (Config{}).authMethod() != nil {
			t.Fatal("no auth expected")
		}
	})

	t.Run("core.redaction.config", func(t *testing.T) {
		cfg := Config{Token: NewSecret("tok-SECRET-1234"), ClientID: "cid", ClientSecret: NewSecret("cs-SECRET-5678")}
		for _, s := range []string{cfg.String(), fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), cfg.GoString()} {
			if strings.Contains(s, "SECRET") {
				t.Fatalf("config leaks a credential: %s", s)
			}
		}
		if !strings.Contains(cfg.String(), "Auth:TokenAuth") {
			t.Fatalf("auth kind missing: %s", cfg)
		}
		for _, a := range []fmt.Stringer{
			&UniversalAuth{ClientSecret: NewSecret("cs-SECRET")}, &TokenAuth{Token: NewSecret("t-SECRET")},
			&KubernetesAuth{JWT: NewSecret("j-SECRET")}, &AwsIamAuth{SecretAccessKey: NewSecret("a-SECRET")},
		} {
			if strings.Contains(a.String(), "SECRET") {
				t.Fatalf("auth leaks: %s", a)
			}
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		bad := []Config{
			{CommonConfig: CommonConfig{URL: "ftp://x"}},
			{APIVersion: "v9"},
			{ClientID: "only-id"},
			{ClientSecret: NewSecret("only-secret")},
			{Environment: "has space"},
		}
		for i, cfg := range bad {
			if _, err := NewClient(cfg); !errors.Is(err, ErrConfig) {
				t.Fatalf("case %d: want CONFIG, got %v", i, err)
			}
		}
		if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "API_VERSION": "v1"}); !errors.Is(err, ErrConfig) {
			t.Fatalf("api version: %v", err)
		}
		if cfg, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "API_VERSION": "Auto"}); err != nil || cfg.APIVersion != APIVersionAuto {
			t.Fatalf("api version auto: %v %q", err, cfg.APIVersion)
		}
		if _, err := NewClient(Config{CommonConfig: CommonConfig{TLS: TLSConfig{CACertPEM: "not pem"}}}); !errors.Is(err, ErrConfig) {
			t.Fatalf("tls: %v", err)
		}
	})

	t.Run("from env", func(t *testing.T) {
		t.Setenv(EnvPrefix+"URL", "http://127.0.0.1:1/api/")
		c, err := NewClientFromEnv()
		if err != nil || c.Config().URL != "http://127.0.0.1:1" {
			t.Fatalf("NewClientFromEnv: %v", err)
		}
		_ = c.Close()
		t.Setenv(EnvPrefix+"URL", "nope")
		if _, err := NewClientFromEnv(); !errors.Is(err, ErrConfig) {
			t.Fatalf("want CONFIG, got %v", err)
		}
	})
}

func TestHealthPingVersion(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/status", "health.ok")
	m.fixture(t, http.MethodGet, "/api/v1/identities/details", "ping.identity")
	m.fixture(t, http.MethodGet, "/api/v2/users/me", "ping.user")
	m.fixture(t, http.MethodGet, "/api/v2/service-token", "ping.serviceToken")

	c := newMockClient(t, m, nil)
	hs, err := c.Health(bg())
	if err != nil || !hs.Healthy || hs.Status != "ok" || hs.Details["redisConfigured"] != "true" || hs.Details["message"] != "Ok" {
		t.Fatalf("health: %+v %v", hs, err)
	}
	if h := m.last(t, http.MethodGet, "/api/status").Header; h.Get("Authorization") != "" {
		t.Fatal("health must be unauthenticated")
	}

	for _, tc := range []struct {
		token, path string
	}{
		{"st.abc.def", "/api/v2/service-token"},
		{jwt(`{"authTokenType":"accessToken","userId":"u"}`), "/api/v2/users/me"},
		{jwt(`{"userId":"u"}`), "/api/v2/users/me"},
		{jwt(`{"authTokenType":"identityAccessToken","identityId":"i"}`), "/api/v1/identities/details"},
		{"a.%%%.c", "/api/v1/identities/details"},
		{"a." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c", "/api/v1/identities/details"},
		{testToken, "/api/v1/identities/details"},
	} {
		cc := newMockClient(t, m, func(cfg *Config) { cfg.Token = NewSecret(tc.token) })
		before := len(m.requests(http.MethodGet, tc.path))
		if d, err := cc.Ping(bg()); err != nil || d <= 0 {
			t.Fatalf("ping %s: %v", tc.path, err)
		}
		if got := m.requests(http.MethodGet, tc.path); len(got) != before+1 || got[len(got)-1].Header.Get("Authorization") != "Bearer "+tc.token {
			t.Fatalf("ping must use %s with the bearer", tc.path)
		}
	}

	_, err = c.ServerVersion(bg())
	wantCode(t, err, ErrorCodeUnsupported)
	if c.APIVersion("folders") != "v2" || c.APIVersion("tags") != "v1" || c.APIVersion("nope") != "" || c.APIVersion("secrets") != "" {
		t.Fatal("APIVersion")
	}
}

func jwt(payload string) string {
	return "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

func TestPingErrors(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v1/identities/details", "auth.malformedToken")
	c := newMockClient(t, m, nil)
	_, err := c.Ping(bg())
	e := wantErr(t, err, ErrorCodeAuthentication)
	if e.HTTPStatus != 403 || e.RequestID != "req-Pzo5lTCTSGutpn" || !contains(e.Message, "malformed") {
		t.Fatalf("token error mapping: %+v", e)
	}
	m.fixture(t, http.MethodGet, "/api/v1/identities/details", "auth.noToken")
	_, err = c.Ping(bg())
	wantCode(t, err, ErrorCodeAuthentication)

	// No auth at all: the request goes out without a bearer.
	nc := newMockClient(t, m, func(cfg *Config) { cfg.Token = Secret{} })
	_, err = nc.Ping(bg())
	wantCode(t, err, ErrorCodeAuthentication)
	if m.last(t, http.MethodGet, "/api/v1/identities/details").Header.Get("Authorization") != "" {
		t.Fatal("no bearer expected")
	}
	// A failing login surfaces from Ping.
	m.fixture(t, http.MethodPost, "/api/v1/auth/universal-auth/login", "universalAuth.login.401")
	uc := newMockClient(t, m, func(cfg *Config) {
		cfg.Token = Secret{}
		cfg.ClientID = "cid"
		cfg.ClientSecret = NewSecret("bad-secret")
	})
	_, err = uc.Ping(bg())
	wantCode(t, err, ErrorCodeAuthentication)
}

func TestHealthStates(t *testing.T) {
	t.Run("core.health.unreachable", func(t *testing.T) {
		c, err := NewClient(Config{CommonConfig: CommonConfig{URL: "http://127.0.0.1:1", Retry: fastRetry(0), ConnectTimeout: time.Second}})
		if err != nil {
			t.Fatal(err)
		}
		hs, err := c.Health(bg())
		if err != nil || hs.Healthy || hs.Status != "unreachable" {
			t.Fatalf("unreachable: %+v %v", hs, err)
		}
		ctx, cancel := context.WithCancel(bg())
		cancel()
		if _, err := c.Health(ctx); !errors.Is(err, ErrCancelled) {
			t.Fatalf("cancelled: %v", err)
		}
	})
	t.Run("unhealthy", func(t *testing.T) {
		m := newMock(t)
		m.json(http.MethodGet, "/api/status", 503, errBody(503, "ServiceUnavailable", "db down"))
		hs, err := newMockClient(t, m, nil).Health(bg())
		if err != nil || hs.Healthy || hs.Status != "unhealthy" || hs.Details["httpStatus"] != "503" {
			t.Fatalf("unhealthy: %+v %v", hs, err)
		}
	})
}

func TestErrorMapping(t *testing.T) {
	m := newMock(t)
	c := newMockClient(t, m, nil)
	get := func() error { _, err := c.GetSecret(bg(), "K", nil); return err }

	m.fixture(t, http.MethodGet, "/api/v4/secrets/K", "createSecret.duplicate400")
	e := wantErr(t, get(), ErrorCodeConflict)
	if e.HTTPStatus != 400 || !contains(e.Message, "already exists") || e.RequestID != "req-gUedbtx3O8pTHI" {
		t.Fatalf("conflict: %+v", e)
	}
	m.fixture(t, http.MethodGet, "/api/v4/secrets/K", "getSecret.missingProjectId422")
	wantCode(t, get(), ErrorCodeValidation)
	m.fixture(t, http.MethodGet, "/api/v4/secrets/K", "createFolder.422")
	e = wantErr(t, get(), ErrorCodeValidation)
	if !contains(e.Message, "name: Invalid folder name") {
		t.Fatalf("zod issues: %s", e.Message)
	}
	m.fixture(t, http.MethodGet, "/api/v4/secrets/K", "listSecrets.serviceTokenRefDenied")
	wantCode(t, get(), ErrorCodePermissionDenied)
	m.fixture(t, http.MethodGet, "/api/v4/secrets/K", "listSecretVersions.identity403")
	wantCode(t, get(), ErrorCodePermissionDenied)
	m.fixture(t, http.MethodGet, "/api/v4/secrets/K", "getSecret.404")
	wantCode(t, get(), ErrorCodeNotFound)

	// 429 without Retry-After: the wait comes from the message (retries exhausted).
	m.json(http.MethodGet, "/api/v4/secrets/K", 429, errBody(429, "RateLimitExceeded", "Rate limit exceeded. Please try again in 0 seconds"))
	wantCode(t, get(), ErrorCodeRateLimited)
	m.on(http.MethodGet, "/api/v4/secrets/K", func(*recorded) reply {
		return reply{status: 429, body: errBody(429, "RateLimitExceeded", "Rate limit exceeded. Please try again in 90 seconds")}
	})
	e = wantErr(t, get(), ErrorCodeRateLimited)
	if e.RetryAfter != 90*time.Second || !e.Retryable {
		t.Fatalf("retry after: %+v", e)
	}
	// Retry-After header wins and stops retries when above maxRetryAfter.
	m.on(http.MethodGet, "/api/v4/secrets/K", func(*recorded) reply {
		return reply{status: 429, header: map[string]string{"Retry-After": "120"}, body: errBody(429, "RateLimitExceeded", "slow down")}
	})
	if e = wantErr(t, get(), ErrorCodeRateLimited); e.RetryAfter != 120*time.Second {
		t.Fatalf("retry-after header: %v", e.RetryAfter)
	}

	// 5xx is retried for GET and then UNAVAILABLE; 504 is TIMEOUT.
	n := 0
	m.on(http.MethodGet, "/api/v4/secrets/K", func(*recorded) reply {
		n++
		return reply{status: 502, body: errBody(502, "BadGateway", "upstream")}
	})
	wantCode(t, get(), ErrorCodeUnavailable)
	if n != 3 {
		t.Fatalf("want 3 attempts, got %d", n)
	}
	m.json(http.MethodGet, "/api/v4/secrets/K", 504, errBody(504, "GatewayTimeoutError", "slow"))
	wantCode(t, get(), ErrorCodeTimeout)

	// A non-Infisical error body keeps the transport mapping.
	m.json(http.MethodGet, "/api/v4/secrets/K", 418, "not json at all")
	wantCode(t, get(), ErrorCodeValidation)
	m.json(http.MethodGet, "/api/v4/secrets/K", 400, map[string]any{"message": 42, "error": "Odd"})
	e = wantErr(t, get(), ErrorCodeValidation)
	if !contains(e.Message, "42") {
		t.Fatalf("raw message: %s", e.Message)
	}

	// Secrets known to the client never appear in messages.
	m.json(http.MethodGet, "/api/v4/secrets/K", 400, errBody(400, "BadRequest", "token "+testToken+" rejected"))
	if e = wantErr(t, get(), ErrorCodeValidation); contains(e.Message, testToken) {
		t.Fatalf("message leaks the token: %s", e.Message)
	}
}

func TestCaptureTransportEdges(t *testing.T) {
	if messageText(nil) != "" {
		t.Fatal("empty message")
	}
	if got := messageText([]byte(`[{"message":"m","path":[0,"x"]},{"code":"c"}]`)); got != "0.x: m" {
		t.Fatalf("issues: %q", got)
	}
	ct := &captureTransport{next: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("boom") })}
	ct.CloseIdleConnections() // next has no CloseIdleConnections: no panic
	req, _ := http.NewRequestWithContext(bg(), http.MethodGet, "http://x", nil)
	if _, err := ct.RoundTrip(req); err == nil {
		t.Fatal("error expected")
	}
	ct = &captureTransport{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Header: http.Header{}, Body: errReader{}}, nil
	})}
	resp, err := ct.RoundTrip(req)
	if err != nil || resp.StatusCode != 500 {
		t.Fatalf("read error: %v", err)
	}
	_ = resp.Body.Close()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (errReader) Close() error             { return nil }

func TestClose(t *testing.T) {
	t.Run("core.close.idempotent", func(t *testing.T) {
		m := newMock(t)
		c := newMockClient(t, m, nil)
		p := c.Secrets()
		h := p.Watch(bg(), "X", time.Hour, func(_, _ *SecretValue) {}, nil)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-h.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("watcher not stopped by Close")
		}
		_, err := c.GetSecret(bg(), "X", nil)
		wantCode(t, err, ErrorCodeCancelled)
		// SecretsWith after Close stops immediately.
		_ = c.SecretsWith(SecretsProviderOptions{Environment: "prod"}).Close()
	})
	t.Run("revoke on close", func(t *testing.T) {
		m := newMock(t)
		m.json(http.MethodPost, "/api/v1/auth/universal-auth/login", 200, map[string]any{"accessToken": "at-LOGIN-1", "expiresIn": 300, "accessTokenMaxTTL": 3600})
		m.json(http.MethodPost, "/api/v1/auth/token/revoke", 200, map[string]any{"message": "ok"})
		m.fixture(t, http.MethodGet, "/api/v1/identities/details", "ping.identity")
		c := newMockClient(t, m, func(cfg *Config) {
			cfg.Token = Secret{}
			cfg.ClientID, cfg.ClientSecret, cfg.RevokeOnClose = "cid", NewSecret("csecret"), true
		})
		if _, err := c.Ping(bg()); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		r := m.last(t, http.MethodPost, "/api/v1/auth/token/revoke")
		if str(r.Body["accessToken"]) != "at-LOGIN-1" || r.Header.Get("Authorization") != "" {
			t.Fatalf("revoke body: %+v", r.Body)
		}
		// Static tokens are never revoked on close.
		s := newMockClient(t, m, func(cfg *Config) { cfg.RevokeOnClose = true })
		if _, err := s.Ping(bg()); err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
		if len(m.requests(http.MethodPost, "/api/v1/auth/token/revoke")) != 1 {
			t.Fatal("static token revoked")
		}
	})
}

func TestScopeErrors(t *testing.T) {
	m := newMock(t)
	c := newMockClient(t, m, func(cfg *Config) { cfg.ProjectID, cfg.Environment = "", "" })
	_, err := c.ListSecrets(bg(), nil)
	if e := wantErr(t, err, ErrorCodeConfig); !contains(e.Message, "projectId") {
		t.Fatal(e.Message)
	}
	_, err = c.ListSecrets(bg(), &ListSecretsOptions{ProjectID: "p"})
	if e := wantErr(t, err, ErrorCodeConfig); !contains(e.Message, "environment") {
		t.Fatal(e.Message)
	}
	if m.count() != 0 {
		t.Fatal("no request expected")
	}
}
