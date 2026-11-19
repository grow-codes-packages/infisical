package infisical

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultKubernetesTokenPath is where KubernetesAuth reads the service
// account token when KubernetesAuth.JWT is empty.
const DefaultKubernetesTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- a file path, not a credential

// refreshFactor is the share of a token's lifetime after which it is renewed.
const refreshFactor = 0.8

// AccessToken is an Infisical access token with its lifetime. Token never
// prints (it is a Secret).
type AccessToken struct {
	// Token is the bearer token.
	Token Secret
	// ExpiresIn is the lifetime from IssuedAt (0: the token does not expire
	// or its lifetime is unknown, as for static tokens).
	ExpiresIn time.Duration
	// MaxTTL is the maximum lifetime reachable by renewals (0: unknown).
	MaxTTL time.Duration
	// TokenType is the token type reported by the server ("Bearer").
	TokenType string
	// IssuedAt is when the client received the token.
	IssuedAt time.Time
}

// ExpiresAt returns IssuedAt + ExpiresIn (zero when the token does not expire).
func (t *AccessToken) ExpiresAt() time.Time {
	if t == nil || t.ExpiresIn <= 0 {
		return time.Time{}
	}
	return t.IssuedAt.Add(t.ExpiresIn)
}

// Authenticator obtains an access token. UniversalAuth, TokenAuth,
// KubernetesAuth and AwsIamAuth implement it; a custom implementation gets
// automatic re-login on AUTHENTICATION errors.
type Authenticator interface {
	// Login obtains a new access token through c (without an Authorization header).
	Login(ctx context.Context, c *Client) (*AccessToken, error)
}

// tokenJSON is the login / renew response body.
type tokenJSON struct {
	AccessToken       string `json:"accessToken"`
	ExpiresIn         int64  `json:"expiresIn"`
	AccessTokenMaxTTL int64  `json:"accessTokenMaxTTL"`
	TokenType         string `json:"tokenType"`
}

// tokenCall posts body to an auth endpoint without a bearer and decodes the token.
func (c *Client) tokenCall(ctx context.Context, op, path string, body any) (*AccessToken, error) {
	var out tokenJSON
	if err := c.callJSON(ctx, call{method: http.MethodPost, path: path, body: body, op: op, noAuth: true}, &out); err != nil {
		return nil, err
	}
	if out.AccessToken == "" {
		return nil, &Error{Code: ErrorCodeUnavailable, Message: op + ": the response carries no access token", Retryable: true}
	}
	c.rememberSecret(out.AccessToken)
	return &AccessToken{
		Token:     NewSecret(out.AccessToken),
		ExpiresIn: time.Duration(out.ExpiresIn) * time.Second,
		MaxTTL:    time.Duration(out.AccessTokenMaxTTL) * time.Second,
		TokenType: out.TokenType,
		IssuedAt:  c.now(),
	}, nil
}

// renewToken extends a machine identity access token (POST /api/v1/auth/token/renew).
// The returned token may be byte-identical to the old one.
func (c *Client) renewToken(ctx context.Context, token Secret) (*AccessToken, error) {
	if token.IsZero() {
		return nil, ValidationError("auth.renew", "access token is required")
	}
	return c.tokenCall(ctx, "auth.renew", "/api/v1/auth/token/renew", map[string]string{"accessToken": token.Reveal()})
}

// revokeToken revokes an access token (POST /api/v1/auth/token/revoke);
// revoking twice succeeds.
func (c *Client) revokeToken(ctx context.Context, token Secret) error {
	if token.IsZero() {
		return ValidationError("auth.revoke", "access token is required")
	}
	return c.callJSON(ctx, call{
		method: http.MethodPost, path: "/api/v1/auth/token/revoke", op: "auth.revoke", noAuth: true,
		body: map[string]string{"accessToken": token.Reveal()},
	}, nil)
}

// --- UniversalAuth ------------------------------------------------------------

// UniversalAuth logs a machine identity in with a client id and secret
// (POST /api/v1/auth/universal-auth/login). Tokens are renewed automatically
// at 80 % of their lifetime and re-obtained when renewal is no longer possible.
//
// Infisical locks a Universal Auth identity after repeated failed logins
// (default 3 failures → 300 s, during which even the right secret fails); the
// client never retries a rejected login.
type UniversalAuth struct {
	// ClientID is the Universal Auth client id.
	ClientID string
	// ClientSecret is the Universal Auth client secret.
	ClientSecret Secret
	// OrganizationSlug optionally selects a sub-organization.
	OrganizationSlug string
}

// NewUniversalAuth returns a UniversalAuth for clientID and clientSecret.
func NewUniversalAuth(clientID, clientSecret string) *UniversalAuth {
	return &UniversalAuth{ClientID: clientID, ClientSecret: NewSecret(clientSecret)}
}

// Login implements Authenticator.
func (u *UniversalAuth) Login(ctx context.Context, c *Client) (*AccessToken, error) {
	if u.ClientID == "" || u.ClientSecret.IsZero() {
		return nil, ConfigError("auth.universalAuth: clientId and clientSecret are required")
	}
	c.rememberSecret(u.ClientSecret.Reveal())
	body := map[string]string{"clientId": u.ClientID, "clientSecret": u.ClientSecret.Reveal()}
	if u.OrganizationSlug != "" {
		body["organizationSlug"] = u.OrganizationSlug
	}
	return c.tokenCall(ctx, "auth.universalAuth.login", "/api/v1/auth/universal-auth/login", body)
}

// Renew extends token on the server (POST /api/v1/auth/token/renew). Always
// keep the returned token; it cannot outlive its MaxTTL.
func (u *UniversalAuth) Renew(ctx context.Context, c *Client, token Secret) (*AccessToken, error) {
	return c.renewToken(ctx, token)
}

// Revoke revokes token (POST /api/v1/auth/token/revoke).
func (u *UniversalAuth) Revoke(ctx context.Context, c *Client, token Secret) error {
	return c.revokeToken(ctx, token)
}

// String renders the method with the secret redacted.
func (u *UniversalAuth) String() string {
	return "UniversalAuth{ClientID:" + u.ClientID + " ClientSecret:" + Redacted + "}"
}

// --- TokenAuth ----------------------------------------------------------------

// TokenAuth uses a static access token: a token-auth machine identity token,
// a user JWT or a legacy service token ("st.…"). It is never refreshed.
type TokenAuth struct {
	// Token is the static bearer token.
	Token Secret
}

// NewTokenAuth returns a TokenAuth for token.
func NewTokenAuth(token string) *TokenAuth { return &TokenAuth{Token: NewSecret(token)} }

// Login implements Authenticator; it returns the static token without a request.
func (t *TokenAuth) Login(_ context.Context, c *Client) (*AccessToken, error) {
	if t.Token.IsZero() {
		return nil, ConfigError("auth.tokenAuth: token is required")
	}
	c.rememberSecret(t.Token.Reveal())
	return &AccessToken{Token: t.Token, TokenType: "Bearer", IssuedAt: c.now()}, nil
}

// String renders the method with the token redacted.
func (t *TokenAuth) String() string { return "TokenAuth{Token:" + Redacted + "}" }

// --- KubernetesAuth -----------------------------------------------------------

// KubernetesAuth logs a machine identity in with a Kubernetes service
// account token (POST /api/v1/auth/kubernetes-auth/login). The server
// validates the token through the Kubernetes TokenReview API.
type KubernetesAuth struct {
	// IdentityID is the machine identity id.
	IdentityID string
	// JWT is the service account token; empty reads TokenPath.
	JWT Secret
	// TokenPath is the token file (default DefaultKubernetesTokenPath).
	TokenPath string
	// OrganizationSlug optionally selects a sub-organization.
	OrganizationSlug string
}

// Login implements Authenticator.
func (k *KubernetesAuth) Login(ctx context.Context, c *Client) (*AccessToken, error) {
	const op = "auth.kubernetesAuth.login"
	if k.IdentityID == "" {
		return nil, ConfigError(op + ": identityId is required")
	}
	jwt := k.JWT.Reveal()
	if jwt == "" {
		path := k.TokenPath
		if path == "" {
			path = DefaultKubernetesTokenPath
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, ConfigError(op + ": the service account token file cannot be read")
		}
		jwt = strings.TrimSpace(string(data))
	}
	c.rememberSecret(jwt)
	body := map[string]string{"identityId": k.IdentityID, "jwt": jwt}
	if k.OrganizationSlug != "" {
		body["organizationSlug"] = k.OrganizationSlug
	}
	return c.tokenCall(ctx, op, "/api/v1/auth/kubernetes-auth/login", body)
}

// String renders the method with the token redacted.
func (k *KubernetesAuth) String() string {
	return "KubernetesAuth{IdentityID:" + k.IdentityID + " JWT:" + Redacted + "}"
}

// --- token manager ------------------------------------------------------------

// Auth manages the client's access token: it logs in on first use, renews
// the token at 80 % of its lifetime (re-login when renewal fails or MaxTTL is
// reached) and re-logs in once when a call fails with AUTHENTICATION.
// Static tokens (Config.Token, TokenAuth) are used as they are.
type Auth struct {
	c      *Client
	method Authenticator

	mu      sync.Mutex
	tok     *AccessToken
	loginAt time.Time
	static  bool
}

func newAuth(c *Client, method Authenticator) *Auth {
	_, static := method.(*TokenAuth)
	return &Auth{c: c, method: method, static: static}
}

// Method returns the configured Authenticator (nil when none).
func (a *Auth) Method() Authenticator { return a.method }

// managed reports whether tokens come from a login that can be repeated.
func (a *Auth) managed() bool { return a.method != nil && !a.static }

// Login obtains a new token with the configured method and stores it.
func (a *Auth) Login(ctx context.Context) (*AccessToken, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.loginLocked(ctx)
}

func (a *Auth) loginLocked(ctx context.Context) (*AccessToken, error) {
	if a.method == nil {
		return nil, ConfigError("auth.login: no authentication method configured (set Config.Auth, Token or ClientID/ClientSecret)")
	}
	t, err := a.method.Login(ctx, a.c)
	if err != nil {
		return nil, err
	}
	a.tok, a.loginAt = t, t.IssuedAt
	cp := *t
	return &cp, nil
}

// Renew extends the current token on the server and stores the result.
func (a *Auth) Renew(ctx context.Context) (*AccessToken, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok == nil {
		return nil, ValidationError("auth.renew", "no access token to renew; log in first")
	}
	t, err := a.c.renewToken(ctx, a.tok.Token)
	if err != nil {
		return nil, err
	}
	a.tok = t
	cp := *t
	return &cp, nil
}

// Revoke revokes the current token on the server and forgets it; the next
// call logs in again (static tokens are revoked too and then fail).
func (a *Auth) Revoke(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok == nil {
		return nil
	}
	if err := a.c.revokeToken(ctx, a.tok.Token); err != nil {
		return err
	}
	a.tok = nil
	return nil
}

// revokeManaged revokes a token obtained by login (best effort, used by Close).
func (a *Auth) revokeManaged(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok == nil || !a.managed() {
		return
	}
	_ = a.c.revokeToken(ctx, a.tok.Token)
	a.tok = nil
}

// Token returns the current access token (nil before the first login).
func (a *Auth) Token() *AccessToken {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok == nil {
		return nil
	}
	cp := *a.tok
	return &cp
}

// SetToken replaces the current token with a static one (no refresh until
// the next Login).
func (a *Auth) SetToken(token Secret) {
	a.c.rememberSecret(token.Reveal())
	a.mu.Lock()
	defer a.mu.Unlock()
	if token.IsZero() {
		a.tok = nil
		return
	}
	a.tok = &AccessToken{Token: token, TokenType: "Bearer", IssuedAt: a.c.now()}
}

// bearer returns a valid token for the next call ("" when no auth is configured).
func (a *Auth) bearer(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok == nil {
		if a.method == nil {
			return "", nil
		}
		if _, err := a.loginLocked(ctx); err != nil {
			return "", err
		}
		return a.tok.Token.Reveal(), nil
	}
	t := a.tok
	if t.ExpiresIn <= 0 || !a.managed() {
		return t.Token.Reveal(), nil
	}
	now := a.c.now()
	refreshAt := t.IssuedAt.Add(time.Duration(float64(t.ExpiresIn) * refreshFactor))
	if now.Before(refreshAt) {
		return t.Token.Reveal(), nil
	}
	maxReached := t.MaxTTL > 0 && !now.Add(t.ExpiresIn).Before(a.loginAt.Add(t.MaxTTL))
	if !maxReached {
		if nt, err := a.c.renewToken(ctx, t.Token); err == nil {
			a.tok = nt
			return nt.Token.Reveal(), nil
		} else if c := CodeOf(err); c == ErrorCodeCancelled {
			return "", err
		}
	}
	if _, err := a.loginLocked(ctx); err != nil {
		return "", err
	}
	return a.tok.Token.Reveal(), nil
}

// relogin logs in again unless another call already replaced stale.
func (a *Auth) relogin(ctx context.Context, stale string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok != nil && a.tok.Token.Reveal() != stale {
		return a.tok.Token.Reveal(), nil
	}
	if _, err := a.loginLocked(ctx); err != nil {
		return "", err
	}
	return a.tok.Token.Reveal(), nil
}
