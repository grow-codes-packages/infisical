package infisical

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is the Infisical client. It is safe for concurrent use.
//
// Service functions are methods of the client: secrets (ListSecrets,
// GetSecret, CreateSecret, UpdateSecret, DeleteSecret and the batch variants),
// folders, projects and environments, tags, secret imports, secret versions,
// LoadEnv and ExportDotenv. Auth returns the token manager, Secrets the
// SecretsProvider (SPEC §3). Close stops watchers and releases connections.
type Client struct {
	cfg       Config
	transport *httpTransport
	auth      *Auth
	now       func() time.Time
	closeOnce sync.Once

	apiMu      sync.Mutex
	secretsAPI string

	bgMu    sync.Mutex
	closers []func()
	closed  bool

	provOnce sync.Once
	provider *ProjectSecretsProvider
}

// NewClient validates cfg and returns a client. It does not contact the
// server: a login (Universal, Kubernetes or AWS auth) happens on the first
// authenticated call or on Auth().Login.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.normalized()
	t, err := newHTTPTransport(cfg.CommonConfig)
	if err != nil {
		return nil, err
	}
	t.client.Transport = &captureTransport{next: t.client.Transport}
	c := &Client{cfg: cfg, transport: t, now: time.Now}
	if cfg.APIVersion != APIVersionAuto {
		c.secretsAPI = cfg.APIVersion
	}
	c.rememberSecret(cfg.Token.Reveal(), cfg.ClientSecret.Reveal())
	c.auth = newAuth(c, cfg.authMethod())
	return c, nil
}

// NewClientFromEnv builds a client from the environment (see ConfigFromEnv).
func NewClientFromEnv() (*Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewClient(cfg)
}

// Config returns the effective configuration.
func (c *Client) Config() Config { return c.cfg }

// Auth returns the token manager (Login, Renew, Revoke, Token, SetToken).
func (c *Client) Auth() *Auth { return c.auth }

// Secrets returns the SecretsProvider (SPEC §3) over Config.ProjectID,
// Config.Environment and Config.SecretPath. Close of the client stops its watchers.
func (c *Client) Secrets() *ProjectSecretsProvider {
	c.provOnce.Do(func() {
		c.provider = newProjectSecretsProvider(c, SecretsProviderOptions{})
		c.onClose(func() { _ = c.provider.Close() })
	})
	return c.provider
}

// SecretsWith returns a new SecretsProvider with its own project, environment,
// base path or read flags. Close of the client stops its watchers.
func (c *Client) SecretsWith(opts SecretsProviderOptions) *ProjectSecretsProvider {
	p := newProjectSecretsProvider(c, opts)
	c.onClose(func() { _ = p.Close() })
	return p
}

// APIVersion reports the API version the client uses for a resource:
// "secrets" ("v4" or "v3"; "" until detected by the first secrets call),
// "folders" and "secret-imports" ("v2"), "projects", "environments", "tags",
// "secret-versions" and "auth" ("v1"). Unknown resources give "".
func (c *Client) APIVersion(resource string) string {
	switch resource {
	case "secrets":
		c.apiMu.Lock()
		defer c.apiMu.Unlock()
		return c.secretsAPI
	case "folders", "secret-imports":
		return "v2"
	case "projects", "environments", "tags", "secret-versions", "auth":
		return "v1"
	}
	return ""
}

// rememberSecret registers values that must never appear in errors or logs.
func (c *Client) rememberSecret(values ...string) {
	for _, v := range values {
		if len(v) >= 4 {
			c.transport.addSecret(v)
		}
	}
}

// onClose registers fn to run on Close (immediately when already closed).
func (c *Client) onClose(fn func()) {
	c.bgMu.Lock()
	if c.closed {
		c.bgMu.Unlock()
		fn()
		return
	}
	c.closers = append(c.closers, fn)
	c.bgMu.Unlock()
}

// Health checks the server without credentials (GET /api/status). Healthy is
// true with Status "ok" when the server answers 200; Details carries the
// status flags (redisConfigured, emailConfigured, …). It never fails for an
// unhealthy or unreachable server (Status "unhealthy" / "unreachable"); it
// fails only for CANCELLED and CONFIG.
func (c *Client) Health(ctx context.Context) (HealthStatus, error) {
	return c.transport.checkHealth(ctx, "health", &request{Method: http.MethodGet, Path: "/api/status", Operation: "health"})
}

// Ping makes an authenticated round trip and returns its latency. The route
// depends on the token kind: machine identity tokens use
// GET /api/v1/identities/details, user JWTs GET /api/v2/users/me and legacy
// service tokens GET /api/v2/service-token. A missing, invalid or revoked
// token gives an AUTHENTICATION error.
func (c *Client) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	path := "/api/v1/identities/details"
	tok, err := c.auth.bearer(ctx)
	if err != nil {
		return 0, err
	}
	switch tokenKind(tok) {
	case tokenKindService:
		path = "/api/v2/service-token"
	case tokenKindUser:
		path = "/api/v2/users/me"
	}
	if _, err := c.send(ctx, call{method: http.MethodGet, path: path, op: "ping"}); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// ServerVersion always fails with UNSUPPORTED: no Infisical endpoint reports
// the running server version (GET /api/status has none, and the admin config
// only reports the latest available release).
func (c *Client) ServerVersion(context.Context) (string, error) {
	return "", UnsupportedError("serverVersion", "Infisical exposes no server version over HTTP")
}

// Close stops every secrets watcher, revokes a token obtained by login when
// Config.RevokeOnClose is set (best effort, 5 s) and releases connections.
// It is idempotent.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.bgMu.Lock()
		c.closed = true
		fns := c.closers
		c.closers = nil
		c.bgMu.Unlock()
		for i := len(fns) - 1; i >= 0; i-- {
			fns[i]()
		}
		if c.cfg.RevokeOnClose {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			c.auth.revokeManaged(ctx)
			cancel()
		}
		c.transport.close()
	})
	return nil
}

// --- token kinds ---------------------------------------------------------------

type tokenKindValue int

const (
	tokenKindIdentity tokenKindValue = iota
	tokenKindUser
	tokenKindService
)

// tokenKind classifies a bearer token: legacy service tokens start with
// "st."; user JWTs carry authTokenType "accessToken"; everything else is
// treated as a machine identity access token.
func tokenKind(token string) tokenKindValue {
	if strings.HasPrefix(token, "st.") {
		return tokenKindService
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenKindIdentity
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return tokenKindIdentity
	}
	var claims struct {
		AuthTokenType string `json:"authTokenType"`
		UserID        string `json:"userId"`
		IdentityID    string `json:"identityId"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return tokenKindIdentity
	}
	if claims.AuthTokenType == "accessToken" || (claims.UserID != "" && claims.IdentityID == "") {
		return tokenKindUser
	}
	return tokenKindIdentity
}

// --- request plumbing --------------------------------------------------------

// call is one Infisical API call; path is absolute ("/api/v4/secrets").
type call struct {
	method string
	path   string
	query  url.Values
	body   any
	op     string
	// noAuth sends no Authorization header (login, renew, revoke: any bearer
	// there makes Infisical answer 403 TokenError).
	noAuth bool
	// token overrides the managed token for this call.
	token string
}

// send executes r with the managed token; an AUTHENTICATION error with a
// token obtained by login triggers one re-login and one retry.
func (c *Client) send(ctx context.Context, r call) (*response, error) {
	token := r.token
	if token == "" && !r.noAuth {
		var err error
		if token, err = c.auth.bearer(ctx); err != nil {
			return nil, err
		}
	}
	res, err := c.raw(ctx, r, token)
	if err == nil || r.noAuth || r.token != "" || CodeOf(err) != ErrorCodeAuthentication || !c.auth.managed() {
		return res, err
	}
	fresh, lerr := c.auth.relogin(ctx, token)
	if lerr != nil {
		return nil, err
	}
	return c.raw(ctx, r, fresh)
}

// raw executes r once (with transport retries) and maps Infisical errors.
func (c *Client) raw(ctx context.Context, r call, token string) (*response, error) {
	h := http.Header{}
	if token != "" && !r.noAuth {
		h.Set("Authorization", "Bearer "+token)
	}
	ctx, capture := withCapture(ctx)
	req := &request{Method: r.method, Path: r.path, Query: r.query, Header: h, Operation: r.op}
	if r.body != nil {
		req.JSON = r.body
	}
	res, err := c.transport.do(ctx, req)
	if err != nil {
		return nil, c.mapError(r.op, err, capture)
	}
	return res, nil
}

// callJSON executes r and decodes the JSON response into out (nil: ignore).
func (c *Client) callJSON(ctx context.Context, r call, out any) error {
	res, err := c.send(ctx, r)
	if err != nil {
		return err
	}
	if out == nil || len(strings.TrimSpace(string(res.Body))) == 0 {
		return nil
	}
	return res.decodeJSON(r.op, out)
}

// projectID resolves an explicit project id or Config.ProjectID.
func (c *Client) projectID(op, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if c.cfg.ProjectID != "" {
		return c.cfg.ProjectID, nil
	}
	return "", ConfigError(op + ": projectId is required (set Config.ProjectID, GROW_INFISICAL_PROJECT_ID or INFISICAL_PROJECT_ID)")
}

// environment resolves an explicit environment slug or Config.Environment.
func (c *Client) environment(op, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if c.cfg.Environment != "" {
		return c.cfg.Environment, nil
	}
	return "", ConfigError(op + ": environment is required (set Config.Environment, GROW_INFISICAL_ENVIRONMENT or INFISICAL_ENVIRONMENT)")
}

// secretPath resolves an explicit path or Config.SecretPath (normalized).
func (c *Client) secretPath(explicit string) string {
	if explicit != "" {
		return normalizePath(explicit)
	}
	return normalizePath(c.cfg.SecretPath)
}

// scope resolves project, environment and path together.
type scope struct {
	projectID   string
	environment string
	path        string
}

func (c *Client) scope(op, projectID, environment, path string) (scope, error) {
	p, err := c.projectID(op, projectID)
	if err != nil {
		return scope{}, err
	}
	e, err := c.environment(op, environment)
	if err != nil {
		return scope{}, err
	}
	return scope{projectID: p, environment: e, path: c.secretPath(path)}, nil
}

// isNotFound reports a NOT_FOUND error.
func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
