package infisical

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeClock) add(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

// uaServer serves login (at-1, at-2, …), renew (rn-1, …) and identity details.
type uaServer struct {
	*mockServer
	mu      sync.Mutex
	logins  int
	renews  int
	valid   map[string]bool
	renewOK bool
}

func newUAServer(t *testing.T) *uaServer {
	s := &uaServer{mockServer: newMock(t), valid: map[string]bool{}, renewOK: true}
	s.on(http.MethodPost, "/api/v1/auth/universal-auth/login", func(r *recorded) reply {
		if r.Header.Get("Authorization") != "" {
			return reply{status: 403, body: errBody(403, "TokenError", "malformed")}
		}
		if str(r.Body["clientSecret"]) != "csecret-OK" {
			return reply{status: 401, body: errBody(401, "UnauthorizedError", "Invalid credentials")}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.logins++
		tok := "at-" + string(rune('0'+s.logins))
		s.valid[tok] = true
		return reply{status: 200, body: map[string]any{"accessToken": tok, "expiresIn": 100, "accessTokenMaxTTL": 1000, "tokenType": "Bearer"}}
	})
	s.on(http.MethodPost, "/api/v1/auth/token/renew", func(r *recorded) reply {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.renewOK {
			return reply{status: 401, body: errBody(401, "UnauthorizedError", "Cannot renew: token has been revoked")}
		}
		s.renews++
		tok := "rn-" + string(rune('0'+s.renews))
		s.valid[tok] = true
		return reply{status: 200, body: map[string]any{"accessToken": tok, "expiresIn": 100, "accessTokenMaxTTL": 1000, "tokenType": "Bearer"}}
	})
	s.on(http.MethodPost, "/api/v1/auth/token/revoke", func(r *recorded) reply {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.valid, str(r.Body["accessToken"]))
		return reply{status: 200, body: map[string]any{"message": "Successfully revoked access token"}}
	})
	s.on(http.MethodGet, "/api/v1/identities/details", func(r *recorded) reply {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
			return reply{status: 401, body: errBody(401, "UnauthorizedError", "Failed to authorize: token has been revoked")}
		}
		return reply{status: 200, body: map[string]any{"identityDetails": map[string]any{}}}
	})
	return s
}

func (s *uaServer) bearer(t *testing.T) string {
	t.Helper()
	return strings.TrimPrefix(s.last(t, http.MethodGet, "/api/v1/identities/details").Header.Get("Authorization"), "Bearer ")
}

func uaClient(t *testing.T, s *uaServer, clock *fakeClock) *Client {
	c := newMockClient(t, s.mockServer, func(cfg *Config) {
		cfg.Token = Secret{}
		cfg.Auth = NewUniversalAuth("cid", "csecret-OK")
	})
	if clock != nil {
		c.now = clock.now
	}
	return c
}

func TestUniversalAuthRefresh(t *testing.T) {
	s := newUAServer(t)
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	c := uaClient(t, s, clock)

	if _, err := c.Ping(bg()); err != nil || s.bearer(t) != "at-1" {
		t.Fatalf("first call logs in: %v", err)
	}
	r := s.last(t, http.MethodPost, "/api/v1/auth/universal-auth/login")
	if str(r.Body["clientId"]) != "cid" || r.Header.Get("Authorization") != "" {
		t.Fatalf("login request: %+v", r.Body)
	}
	tok := c.Auth().Token()
	if tok.Token.Reveal() != "at-1" || tok.ExpiresIn != 100*time.Second || tok.MaxTTL != 1000*time.Second || !tok.ExpiresAt().Equal(clock.now().Add(100*time.Second)) {
		t.Fatalf("token: %+v", tok)
	}
	clock.add(79 * time.Second)
	_, _ = c.Ping(bg())
	if s.bearer(t) != "at-1" || s.renews != 0 {
		t.Fatal("no renew before 80 %")
	}
	clock.add(2 * time.Second)
	_, _ = c.Ping(bg())
	if s.bearer(t) != "rn-1" || s.renews != 1 {
		t.Fatalf("renew at 80 %%: %s", s.bearer(t))
	}
	if r := s.last(t, http.MethodPost, "/api/v1/auth/token/renew"); str(r.Body["accessToken"]) != "at-1" || r.Header.Get("Authorization") != "" {
		t.Fatal("renew request")
	}
	// Renewal failure → re-login.
	s.renewOK = false
	clock.add(90 * time.Second)
	_, _ = c.Ping(bg())
	if s.bearer(t) != "at-2" || s.logins != 2 {
		t.Fatalf("relogin after failed renew: %s", s.bearer(t))
	}
	// Near MaxTTL → login instead of renew.
	s.renewOK = true
	clock.add(950 * time.Second)
	_, _ = c.Ping(bg())
	if s.bearer(t) != "at-3" || s.renews != 1 {
		t.Fatalf("max ttl relogin: %s renews=%d", s.bearer(t), s.renews)
	}
	// A revoked token (401) → one re-login and retry.
	s.mu.Lock()
	delete(s.valid, "at-3")
	s.mu.Unlock()
	if _, err := c.Ping(bg()); err != nil || s.bearer(t) != "at-4" {
		t.Fatalf("401 relogin: %v %s", err, s.bearer(t))
	}
}

func TestAuthModule(t *testing.T) {
	s := newUAServer(t)
	c := uaClient(t, s, nil)
	a := c.Auth()
	if a.Token() != nil {
		t.Fatal("no token before login")
	}
	if _, err := a.Renew(bg()); !errors.Is(err, ErrValidation) {
		t.Fatalf("renew without token: %v", err)
	}
	if err := a.Revoke(bg()); err != nil {
		t.Fatalf("revoke without token is a no-op: %v", err)
	}
	if _, ok := a.Method().(*UniversalAuth); !ok {
		t.Fatal("method")
	}
	tok, err := a.Login(bg())
	if err != nil || tok.Token.Reveal() != "at-1" {
		t.Fatalf("login: %v", err)
	}
	tok, err = a.Renew(bg())
	if err != nil || tok.Token.Reveal() != "rn-1" {
		t.Fatalf("renew: %v", err)
	}
	if err := a.Revoke(bg()); err != nil || a.Token() != nil {
		t.Fatalf("revoke: %v", err)
	}
	s.renewOK = false
	if _, err := a.Login(bg()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Renew(bg()); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("renew failure: %v", err)
	}
	// SetToken switches to a static token until the next login.
	a.SetToken(NewSecret("at-1"))
	if _, err := c.Ping(bg()); err != nil || s.bearer(t) != "at-1" {
		t.Fatalf("set token: %v", err)
	}
	a.SetToken(Secret{})
	if a.Token() != nil {
		t.Fatal("cleared")
	}
	// Revoke failure surfaces.
	s.json(http.MethodPost, "/api/v1/auth/token/revoke", 500, errBody(500, "Internal", "x"))
	_, _ = a.Login(bg())
	if err := a.Revoke(bg()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoke failure: %v", err)
	}

	// UniversalAuth methods directly.
	ua := NewUniversalAuth("cid", "csecret-OK")
	ua.OrganizationSlug = "sub-org"
	tok, err = ua.Login(bg(), c)
	if err != nil || str(s.last(t, http.MethodPost, "/api/v1/auth/universal-auth/login").Body["organizationSlug"]) != "sub-org" {
		t.Fatalf("org slug: %v", err)
	}
	s.renewOK = true
	if _, err := ua.Renew(bg(), c, tok.Token); err != nil {
		t.Fatal(err)
	}
	s.json(http.MethodPost, "/api/v1/auth/token/revoke", 200, map[string]any{"message": "ok"})
	if err := ua.Revoke(bg(), c, tok.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := ua.Renew(bg(), c, Secret{}); !errors.Is(err, ErrValidation) {
		t.Fatal("renew empty")
	}
	if err := ua.Revoke(bg(), c, Secret{}); !errors.Is(err, ErrValidation) {
		t.Fatal("revoke empty")
	}
	if _, err := (&UniversalAuth{}).Login(bg(), c); !errors.Is(err, ErrConfig) {
		t.Fatal("empty UA")
	}
}

func TestAuthErrors(t *testing.T) {
	s := newUAServer(t)
	// Wrong secret: login fails with AUTHENTICATION and is never retried.
	c := newMockClient(t, s.mockServer, func(cfg *Config) {
		cfg.Token = Secret{}
		cfg.ClientID, cfg.ClientSecret = "cid", NewSecret("wrong-secret")
	})
	_, err := c.Ping(bg())
	wantCode(t, err, ErrorCodeAuthentication)
	if n := len(s.requests(http.MethodPost, "/api/v1/auth/universal-auth/login")); n != 1 {
		t.Fatalf("login must not be retried (lockout), got %d", n)
	}
	// Login responses without a token are UNAVAILABLE.
	s.json(http.MethodPost, "/api/v1/auth/universal-auth/login", 200, map[string]any{})
	_, err = c.Auth().Login(bg())
	wantCode(t, err, ErrorCodeUnavailable)
	// No method configured.
	n := newMockClient(t, s.mockServer, func(cfg *Config) { cfg.Token = Secret{} })
	_, err = n.Auth().Login(bg())
	wantCode(t, err, ErrorCodeConfig)
	// Cancelled renew is not followed by a login.
	clock := &fakeClock{t: time.Unix(0, 0)}
	s2 := newUAServer(t)
	u := uaClient(t, s2, clock)
	if _, err := u.Ping(bg()); err != nil {
		t.Fatal(err)
	}
	clock.add(90 * time.Second)
	ctx, cancel := context.WithCancel(bg())
	cancel()
	if _, err := u.Ping(ctx); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancelled: %v", err)
	}
	// Re-login failure keeps the original AUTHENTICATION error.
	s2.mu.Lock()
	s2.valid = map[string]bool{}
	s2.mu.Unlock()
	s2.json(http.MethodPost, "/api/v1/auth/universal-auth/login", 401, errBody(401, "UnauthorizedError", "This identity auth method is temporarily locked"))
	s2.json(http.MethodPost, "/api/v1/auth/token/renew", 401, errBody(401, "UnauthorizedError", "revoked"))
	clock.add(time.Hour)
	_, err = u.Ping(bg())
	wantCode(t, err, ErrorCodeAuthentication)
}

func TestReloginRace(t *testing.T) {
	s := newUAServer(t)
	c := uaClient(t, s, nil)
	if _, err := c.Auth().Login(bg()); err != nil {
		t.Fatal(err)
	}
	// Another caller already replaced the stale token: no new login.
	tok, err := c.auth.relogin(bg(), "stale")
	if err != nil || tok != "at-1" || s.logins != 1 {
		t.Fatalf("relogin race: %v %s", err, tok)
	}
	c.auth.tok = nil
	if _, err := c.auth.relogin(bg(), "at-1"); err != nil || s.logins != 2 {
		t.Fatal("relogin with no token logs in")
	}
	s.json(http.MethodPost, "/api/v1/auth/universal-auth/login", 401, errBody(401, "UnauthorizedError", "Invalid credentials"))
	if _, err := c.auth.relogin(bg(), "at-2"); err == nil {
		t.Fatal("relogin error expected")
	}
}

func TestTokenAuth(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v4/secrets/SDK_SEED", "tokenAuth.getSecret")
	c := newMockClient(t, m, func(cfg *Config) { cfg.Token = Secret{}; cfg.Auth = NewTokenAuth("viewer-TOKEN-1") })
	s, err := c.GetSecret(bg(), "SDK_SEED", nil)
	if err != nil || s.Value.Reveal() != "seed-value-1" {
		t.Fatalf("token auth get: %v", err)
	}
	if m.last(t, http.MethodGet, "/api/v4/secrets/SDK_SEED").Header.Get("Authorization") != "Bearer viewer-TOKEN-1" {
		t.Fatal("bearer")
	}
	if c.auth.managed() {
		t.Fatal("token auth is static")
	}
	// A static token is not re-logged in on 401.
	m.fixture(t, http.MethodGet, "/api/v4/secrets/SDK_SEED", "auth.revokedToken")
	_, err = c.GetSecret(bg(), "SDK_SEED", nil)
	wantCode(t, err, ErrorCodeAuthentication)
	if _, err := (&TokenAuth{}).Login(bg(), c); !errors.Is(err, ErrConfig) {
		t.Fatal("empty token")
	}
}

func TestKubernetesAuth(t *testing.T) {
	m := newMock(t)
	m.json(http.MethodPost, "/api/v1/auth/kubernetes-auth/login", 200, map[string]any{"accessToken": "k8s-AT-1", "expiresIn": 300, "accessTokenMaxTTL": 3600, "tokenType": "Bearer"})
	c := newMockClient(t, m, nil)
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("sa-JWT-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := &KubernetesAuth{IdentityID: "id-1", TokenPath: path, OrganizationSlug: "org"}
	tok, err := k.Login(bg(), c)
	if err != nil || tok.Token.Reveal() != "k8s-AT-1" {
		t.Fatalf("login: %v", err)
	}
	r := m.last(t, http.MethodPost, "/api/v1/auth/kubernetes-auth/login")
	if str(r.Body["jwt"]) != "sa-JWT-123" || str(r.Body["identityId"]) != "id-1" || str(r.Body["organizationSlug"]) != "org" || r.Header.Get("Authorization") != "" {
		t.Fatalf("request: %+v", r.Body)
	}
	if _, err := (&KubernetesAuth{IdentityID: "id-1", JWT: NewSecret("inline-JWT")}).Login(bg(), c); err != nil {
		t.Fatal(err)
	}
	if str(m.last(t, http.MethodPost, "/api/v1/auth/kubernetes-auth/login").Body["jwt"]) != "inline-JWT" {
		t.Fatal("inline jwt")
	}
	if _, err := (&KubernetesAuth{}).Login(bg(), c); !errors.Is(err, ErrConfig) {
		t.Fatal("identity required")
	}
	if _, err := (&KubernetesAuth{IdentityID: "x", TokenPath: filepath.Join(t.TempDir(), "missing")}).Login(bg(), c); !errors.Is(err, ErrConfig) {
		t.Fatal("missing token file")
	}
	if _, err := (&KubernetesAuth{IdentityID: "x"}).Login(bg(), c); !errors.Is(err, ErrConfig) {
		t.Fatal("default path does not exist on the test host")
	}
	m.fixture(t, http.MethodPost, "/api/v1/auth/kubernetes-auth/login", "kubernetesAuth.login.notConfigured")
	_, err = k.Login(bg(), c)
	wantCode(t, err, ErrorCodeNotFound)
}

// TestSigV4Vector checks the signer against the AWS SigV4 test suite case "get-vanilla".
func TestSigV4Vector(t *testing.T) {
	h := SignV4(SigV4Request{
		Method: "GET", Host: "example.amazonaws.com", Path: "/", Region: "us-east-1", Service: "service",
		AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Time: time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC),
	})
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if h["Authorization"] != want {
		t.Fatalf("signature:\n got %s\nwant %s", h["Authorization"], want)
	}
	// get-vanilla-query-order-key-case: sorted query parameters.
	h = SignV4(SigV4Request{
		Method: "GET", Host: "example.amazonaws.com", Query: "Param2=value2&Param1=value1", Region: "us-east-1", Service: "service",
		AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Time: time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC), Headers: map[string]string{"host": "example.amazonaws.com"},
	})
	if !strings.HasSuffix(h["Authorization"], "Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500") {
		t.Fatalf("query order: %s", h["Authorization"])
	}
}

func TestAwsIamAuth(t *testing.T) {
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		t.Setenv(k, "")
	}
	fixed := func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) }
	a := &AwsIamAuth{IdentityID: "id-1", Region: "eu-central-1", AccessKeyID: "AKIDEXAMPLE",
		SecretAccessKey: NewSecret("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"), SessionToken: NewSecret("sess-TOKEN"), now: fixed}
	req, err := a.LoginRequest()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(req.IamRequestBody)
	if string(body) != "Action=GetCallerIdentity&Version=2011-06-15" || req.IamHTTPRequestMethod != "POST" {
		t.Fatalf("body: %s", body)
	}
	raw, _ := base64.StdEncoding.DecodeString(req.IamRequestHeaders)
	var hdr map[string]string
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["Host"] != "sts.eu-central-1.amazonaws.com" || hdr["X-Amz-Date"] != "20261118T120000Z" || hdr["X-Amz-Security-Token"] != "sess-TOKEN" ||
		hdr["Content-Length"] != "43" || !strings.HasPrefix(hdr["Content-Type"], "application/x-www-form-urlencoded") {
		t.Fatalf("headers: %v", hdr)
	}
	wantAuth := SignV4(SigV4Request{Method: "POST", Host: hdr["Host"], Path: "/", Body: body, Region: "eu-central-1", Service: "sts",
		AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", Time: fixed(),
		Headers: map[string]string{"Host": hdr["Host"], "Content-Type": hdr["Content-Type"], "X-Amz-Security-Token": "sess-TOKEN"}})["Authorization"]
	if hdr["Authorization"] != wantAuth || !strings.Contains(wantAuth, "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token") ||
		!strings.Contains(wantAuth, "/20261118/eu-central-1/sts/aws4_request") {
		t.Fatalf("authorization: %s", hdr["Authorization"])
	}

	m := newMock(t)
	m.json(http.MethodPost, "/api/v1/auth/aws-auth/login", 200, map[string]any{"accessToken": "aws-AT-1", "expiresIn": 300, "accessTokenMaxTTL": 3600})
	c := newMockClient(t, m, func(cfg *Config) { cfg.Token = Secret{}; cfg.Auth = a })
	if _, err := c.Ping(bg()); err == nil {
		t.Fatal("details route not mocked: error expected")
	}
	r := m.last(t, http.MethodPost, "/api/v1/auth/aws-auth/login")
	if str(r.Body["identityId"]) != "id-1" || str(r.Body["iamRequestHeaders"]) == "" || r.Header.Get("Authorization") != "" {
		t.Fatalf("login body: %+v", r.Body)
	}
	if tok := c.Auth().Token(); tok == nil || tok.Token.Reveal() != "aws-AT-1" {
		t.Fatal("token stored")
	}

	// Credentials and region from the environment.
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
	t.Setenv("AWS_SESSION_TOKEN", "env-session")
	env := &AwsIamAuth{IdentityID: "id-2"}
	region, key, secret, session := env.credentials()
	if region != "us-west-2" || key != "AKIAENV" || secret != "env-secret" || session != "env-session" {
		t.Fatalf("env credentials: %s %s", region, key)
	}
	if _, err := env.LoginRequest(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_DEFAULT_REGION", "")
	if region, _, _, _ := env.credentials(); region != "us-east-1" {
		t.Fatalf("default region %s", region)
	}
	if _, err := (&AwsIamAuth{}).LoginRequest(); !errors.Is(err, ErrConfig) {
		t.Fatal("identity required")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	if _, err := (&AwsIamAuth{IdentityID: "x"}).Login(bg(), c); !errors.Is(err, ErrConfig) {
		t.Fatal("credentials required")
	}
	m.fixture(t, http.MethodPost, "/api/v1/auth/aws-auth/login", "awsIamAuth.login.notConfigured")
	_, err = a.Login(bg(), c)
	wantCode(t, err, ErrorCodeNotFound)
}

func TestAccessTokenExpiresAt(t *testing.T) {
	var nilTok *AccessToken
	if !nilTok.ExpiresAt().IsZero() || !(&AccessToken{}).ExpiresAt().IsZero() {
		t.Fatal("zero expiry")
	}
}
