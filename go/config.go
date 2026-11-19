package infisical

import (
	"fmt"
	"strings"
)

// DefaultURL is the default endpoint of Infisical (self-hosted standalone image port).
const DefaultURL = "http://127.0.0.1:8080"

// DefaultSecretPath is the secret path used when none is configured.
const DefaultSecretPath = "/"

// Secrets API versions accepted by Config.APIVersion.
const (
	// APIVersionAuto detects the highest secrets API version at run time (v4,
	// falling back to v3). "auto" is accepted as an alias.
	APIVersionAuto = ""
	// APIVersionV4 forces the v4 secrets API (/api/v4/secrets).
	APIVersionV4 = "v4"
	// APIVersionV3 forces the deprecated v3 "raw" secrets API (/api/v3/secrets/raw).
	APIVersionV3 = "v3"
)

// vendorEnv lists the vendor variables consulted after GROW_INFISICAL_*.
var vendorEnv = VendorEnv{URL: []string{"INFISICAL_API_URL"}}

// Vendor variables per field, in precedence order (after GROW_INFISICAL_<NAME>).
var (
	vendorTokenEnv        = []string{"INFISICAL_TOKEN"}
	vendorClientIDEnv     = []string{"INFISICAL_CLIENT_ID", "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"}
	vendorClientSecretEnv = []string{"INFISICAL_CLIENT_SECRET", "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"}
	vendorProjectIDEnv    = []string{"INFISICAL_PROJECT_ID"}
	vendorEnvironmentEnv  = []string{"INFISICAL_ENVIRONMENT"}
)

// Config configures a Client. Build it with a struct literal or ConfigFromEnv;
// zero values mean "use the default". Call Validate to check it.
//
// Environment variables read by ConfigFromEnv (explicit value > GROW_INFISICAL_* >
// vendor variables > default):
//
//	URL            GROW_INFISICAL_URL, INFISICAL_API_URL (a trailing "/api" is removed)
//	Token          GROW_INFISICAL_TOKEN, INFISICAL_TOKEN
//	ClientID       GROW_INFISICAL_CLIENT_ID, INFISICAL_CLIENT_ID, INFISICAL_UNIVERSAL_AUTH_CLIENT_ID
//	ClientSecret   GROW_INFISICAL_CLIENT_SECRET, INFISICAL_CLIENT_SECRET, INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET
//	ProjectID      GROW_INFISICAL_PROJECT_ID, INFISICAL_PROJECT_ID
//	Environment    GROW_INFISICAL_ENVIRONMENT, INFISICAL_ENVIRONMENT
//	SecretPath     GROW_INFISICAL_SECRET_PATH (default "/")
//	APIVersion     GROW_INFISICAL_API_VERSION ("auto" or "", "v4" or "v3")
//	RevokeOnClose  GROW_INFISICAL_REVOKE_ON_CLOSE
//
// plus the common GROW_INFISICAL_CONNECT_TIMEOUT, REQUEST_TIMEOUT, TOTAL_TIMEOUT,
// MAX_RETRIES, CA_CERT, CLIENT_CERT, CLIENT_KEY, INSECURE_SKIP_VERIFY and PROXY.
//
// Authentication is chosen in this order: Auth (an explicit Authenticator) >
// Token (a static access token, see TokenAuth) > ClientID + ClientSecret
// (UniversalAuth with automatic token refresh) > none (only Health works).
type Config struct {
	CommonConfig

	// Auth is an explicit authentication method (UniversalAuth, TokenAuth,
	// KubernetesAuth, AwsIamAuth or your own Authenticator). It wins over
	// Token and ClientID/ClientSecret.
	Auth Authenticator
	// Token is a static access token: a machine identity access token, a user
	// JWT or a legacy service token ("st.…"). It is never refreshed.
	Token Secret
	// ClientID is the Universal Auth client id of a machine identity.
	ClientID string
	// ClientSecret is the Universal Auth client secret of a machine identity.
	ClientSecret Secret
	// ProjectID is the default project for every project-scoped call.
	ProjectID string
	// Environment is the default environment slug (for example "dev"). It is
	// required by secret, folder and import calls (CONFIG error when missing
	// at call time), not at construction.
	Environment string
	// SecretPath is the default secret path (default "/").
	SecretPath string
	// APIVersion forces the secrets API version ("v4" or "v3"); empty or "auto"
	// detects it at run time (v4 first, v3 only when the server lacks the v4 route).
	APIVersion string
	// RevokeOnClose revokes a token the client obtained by logging in
	// (Universal, Kubernetes or AWS auth) when Close is called. Static tokens
	// are never revoked.
	RevokeOnClose bool
}

// ConfigFromEnv reads the configuration from the process environment.
func ConfigFromEnv() (Config, error) { return ConfigFromEnvWith(Config{}, nil) }

// ConfigFromEnvWith resolves explicit values > GROW_INFISICAL_* > vendor
// variables > defaults. env replaces the process environment when non-nil.
func ConfigFromEnvWith(explicit Config, env map[string]string) (Config, error) {
	r := NewEnvReader(EnvPrefix, env)
	c := explicit
	if err := c.applyEnv(r, vendorEnv); err != nil {
		return Config{}, err
	}
	if c.Token.IsZero() {
		if v, ok := r.String("TOKEN", vendorTokenEnv...); ok {
			c.Token = NewSecret(v)
		}
	}
	if c.ClientID == "" {
		c.ClientID, _ = r.String("CLIENT_ID", vendorClientIDEnv...)
	}
	if c.ClientSecret.IsZero() {
		if v, ok := r.String("CLIENT_SECRET", vendorClientSecretEnv...); ok {
			c.ClientSecret = NewSecret(v)
		}
	}
	if c.ProjectID == "" {
		c.ProjectID, _ = r.String("PROJECT_ID", vendorProjectIDEnv...)
	}
	if c.Environment == "" {
		c.Environment, _ = r.String("ENVIRONMENT", vendorEnvironmentEnv...)
	}
	if c.SecretPath == "" {
		c.SecretPath, _ = r.String("SECRET_PATH")
	}
	if c.APIVersion == "" {
		c.APIVersion, _ = r.String("API_VERSION")
	}
	if !c.RevokeOnClose {
		v, ok, err := r.Bool("REVOKE_ON_CLOSE")
		if err != nil {
			return Config{}, err
		}
		c.RevokeOnClose = ok && v
	}
	c = c.normalized()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// normalized applies the defaults and canonical forms (URL without a
// trailing "/api", absolute secret path, lower-case API version).
func (c Config) normalized() Config {
	c.CommonConfig = c.withDefaults(DefaultURL)
	u := strings.TrimRight(c.URL, "/")
	u = strings.TrimSuffix(u, "/api")
	c.URL = u
	c.SecretPath = normalizePath(c.SecretPath)
	c.APIVersion = normalizeAPIVersion(c.APIVersion)
	return c
}

// Validate checks the configuration and returns a CONFIG error.
func (c Config) Validate() error {
	if err := c.withDefaults(DefaultURL).validate(); err != nil {
		return err
	}
	switch normalizeAPIVersion(c.APIVersion) {
	case APIVersionAuto, APIVersionV4, APIVersionV3:
	default:
		return ConfigError(`apiVersion must be "auto" (or ""), "v4" or "v3"`)
	}
	if c.Auth == nil && c.Token.IsZero() && (c.ClientID == "") != c.ClientSecret.IsZero() {
		return ConfigError("clientId and clientSecret must be given together")
	}
	if strings.ContainsAny(c.Environment, " /\t\r\n") {
		return ConfigError("environment must be an environment slug")
	}
	return nil
}

// normalizeAPIVersion lower-cases the version and maps "auto" to APIVersionAuto ("").
func normalizeAPIVersion(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "auto" {
		return APIVersionAuto
	}
	return v
}

// authMethod returns the Authenticator the configuration selects (nil: none).
func (c Config) authMethod() Authenticator {
	switch {
	case c.Auth != nil:
		return c.Auth
	case !c.Token.IsZero():
		return &TokenAuth{Token: c.Token}
	case c.ClientID != "" && !c.ClientSecret.IsZero():
		return &UniversalAuth{ClientID: c.ClientID, ClientSecret: c.ClientSecret}
	}
	return nil
}

// String renders the configuration with every credential redacted.
func (c Config) String() string {
	auth := "none"
	if m := c.authMethod(); m != nil {
		auth = fmt.Sprintf("%T", m)
		auth = strings.TrimPrefix(auth, "*infisical.")
	}
	return fmt.Sprintf("Config{%s Auth:%s Token:%s ClientID:%s ClientSecret:%s ProjectID:%s Environment:%s SecretPath:%s APIVersion:%s RevokeOnClose:%t}",
		c.describe(), auth, c.Token, c.ClientID, c.ClientSecret, c.ProjectID, c.Environment,
		normalizePath(c.SecretPath), c.APIVersion, c.RevokeOnClose)
}

// GoString renders the configuration with every credential redacted.
func (c Config) GoString() string { return c.String() }
