// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! `InfisicalConfig`: common settings (SPEC §2.2) plus the Infisical credentials and the
//! default project, environment and secret path.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::api::normalize_path;
use crate::auth::{AuthMethod, TokenAuth, UniversalAuth};
use crate::core::clock::{Clock, SystemClock};
use crate::core::{
    CommonConfig, CommonConfigBuilder, EnvReader, Error, Hooks, Result, RetryPolicy, Secret,
    TlsConfig,
};

/// Endpoint used when neither the builder nor the environment sets one (self-hosted
/// standalone image port).
pub const DEFAULT_URL: &str = "http://127.0.0.1:8080";
/// Secret path used when none is configured.
pub const DEFAULT_SECRET_PATH: &str = "/";

/// Vendor variables checked (in order) after `GROW_INFISICAL_URL`.
const VENDOR_URL_VARS: &[&str] = &["INFISICAL_API_URL"];
/// Vendor variables checked (in order) after `GROW_INFISICAL_TOKEN`.
const VENDOR_TOKEN_VARS: &[&str] = &["INFISICAL_TOKEN"];
/// Vendor variables checked (in order) after `GROW_INFISICAL_CLIENT_ID`.
const VENDOR_CLIENT_ID_VARS: &[&str] =
    &["INFISICAL_CLIENT_ID", "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"];
/// Vendor variables checked (in order) after `GROW_INFISICAL_CLIENT_SECRET`.
const VENDOR_CLIENT_SECRET_VARS: &[&str] = &[
    "INFISICAL_CLIENT_SECRET",
    "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET",
];
/// Vendor variables checked (in order) after `GROW_INFISICAL_PROJECT_ID`.
const VENDOR_PROJECT_ID_VARS: &[&str] = &["INFISICAL_PROJECT_ID"];
/// Vendor variables checked (in order) after `GROW_INFISICAL_ENVIRONMENT`.
const VENDOR_ENVIRONMENT_VARS: &[&str] = &["INFISICAL_ENVIRONMENT"];

/// Secrets API version used by the client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ApiVersion {
    /// Detect at run time: v4 first, v3 only when the server lacks the v4 route.
    #[default]
    Auto,
    /// The v4 secrets API (`/api/v4/secrets`).
    V4,
    /// The deprecated v3 "raw" secrets API (`/api/v3/secrets/raw`).
    V3,
}

impl ApiVersion {
    /// `""` (auto), `"v4"` or `"v3"`.
    pub fn as_str(self) -> &'static str {
        match self {
            ApiVersion::Auto => "",
            ApiVersion::V4 => "v4",
            ApiVersion::V3 => "v3",
        }
    }
}

impl FromStr for ApiVersion {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(ApiVersion::Auto),
            "v4" => Ok(ApiVersion::V4),
            "v3" => Ok(ApiVersion::V3),
            _ => Err(Error::config(r#"apiVersion must be "", "v4" or "v3""#)),
        }
    }
}

/// Immutable client configuration; build it with [`InfisicalConfig::builder`] or
/// [`InfisicalConfig::from_env`]. `Debug` output redacts every credential.
///
/// Environment variables read by [`InfisicalConfig::from_env`] (explicit value >
/// `GROW_INFISICAL_*` > vendor variables > default):
///
/// | Field | Variables |
/// | - | - |
/// | url | `GROW_INFISICAL_URL`, `INFISICAL_API_URL` (a trailing `/api` is removed) |
/// | token | `GROW_INFISICAL_TOKEN`, `INFISICAL_TOKEN` |
/// | client id | `GROW_INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` |
/// | client secret | `GROW_INFISICAL_CLIENT_SECRET`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` |
/// | project id | `GROW_INFISICAL_PROJECT_ID`, `INFISICAL_PROJECT_ID` |
/// | environment | `GROW_INFISICAL_ENVIRONMENT`, `INFISICAL_ENVIRONMENT` |
/// | secret path | `GROW_INFISICAL_SECRET_PATH` (default `/`) |
/// | API version | `GROW_INFISICAL_API_VERSION` (`""`, `v4` or `v3`) |
/// | revoke on close | `GROW_INFISICAL_REVOKE_ON_CLOSE` |
///
/// plus the common `GROW_INFISICAL_CONNECT_TIMEOUT`, `REQUEST_TIMEOUT`, `TOTAL_TIMEOUT`,
/// `MAX_RETRIES`, `CA_CERT`, `CLIENT_CERT`, `CLIENT_KEY`, `INSECURE_SKIP_VERIFY` and `PROXY`.
///
/// Authentication is chosen in this order: an explicit [`AuthMethod`]
/// ([`InfisicalConfigBuilder::auth`]) > a static token ([`TokenAuth`]) > client id + client
/// secret ([`UniversalAuth`] with automatic token refresh) > none (only `health` works).
/// The environment is required by secret, folder and import calls (`CONFIG` error at call
/// time when missing), not at construction.
#[derive(Clone)]
pub struct InfisicalConfig {
    common: CommonConfig,
    auth: Option<Arc<dyn AuthMethod>>,
    token: Option<Secret>,
    client_id: Option<String>,
    client_secret: Option<Secret>,
    project_id: Option<String>,
    environment: Option<String>,
    secret_path: String,
    api_version: ApiVersion,
    revoke_on_close: bool,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for InfisicalConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InfisicalConfig")
            .field("common", &self.common)
            .field("auth", &self.auth_method())
            .field("token", &self.token)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .field("project_id", &self.project_id)
            .field("environment", &self.environment)
            .field("secret_path", &self.secret_path)
            .field("api_version", &self.api_version)
            .field("revoke_on_close", &self.revoke_on_close)
            .finish()
    }
}

impl InfisicalConfig {
    /// A builder with nothing set.
    pub fn builder() -> InfisicalConfigBuilder {
        InfisicalConfigBuilder::default()
    }

    /// Configuration from the process environment
    /// (explicit > `GROW_INFISICAL_*` > vendor variables > defaults).
    pub fn from_env() -> Result<Self> {
        Self::builder().build_from_env()
    }

    /// Settings shared by every Grow Codes SDK.
    pub fn common(&self) -> &CommonConfig {
        &self.common
    }

    /// Endpoint base URL (without a trailing `/api`).
    pub fn url(&self) -> &url::Url {
        self.common.url()
    }

    /// Static access token (machine identity token, user JWT or legacy `st.` service token).
    pub fn token(&self) -> Option<&Secret> {
        self.token.as_ref()
    }

    /// Universal Auth client id.
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// Universal Auth client secret.
    pub fn client_secret(&self) -> Option<&Secret> {
        self.client_secret.as_ref()
    }

    /// Default project id of project-scoped calls.
    pub fn project_id(&self) -> Option<&str> {
        self.project_id.as_deref()
    }

    /// Default environment slug.
    pub fn environment(&self) -> Option<&str> {
        self.environment.as_deref()
    }

    /// Default secret path (normalized, default `/`).
    pub fn secret_path(&self) -> &str {
        &self.secret_path
    }

    /// Forced secrets API version ([`ApiVersion::Auto`] detects it).
    pub fn api_version(&self) -> ApiVersion {
        self.api_version
    }

    /// Whether `close` revokes a token obtained by logging in.
    pub fn revoke_on_close(&self) -> bool {
        self.revoke_on_close
    }

    /// The clock used for token refresh decisions.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The authentication method this configuration selects (`None`: no credentials).
    pub fn auth_method(&self) -> Option<Arc<dyn AuthMethod>> {
        if let Some(a) = &self.auth {
            return Some(a.clone());
        }
        if let Some(t) = self.token.as_ref().filter(|t| !t.is_empty()) {
            return Some(Arc::new(TokenAuth::new(t.clone())));
        }
        match (&self.client_id, &self.client_secret) {
            (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => {
                Some(Arc::new(UniversalAuth::new(id.clone(), secret.clone())))
            }
            _ => None,
        }
    }

    /// Checks the service rules (common rules are checked when building).
    pub fn validate(&self) -> Result<()> {
        let has_id = self.client_id.as_deref().is_some_and(|s| !s.is_empty());
        let has_secret = self.client_secret.as_ref().is_some_and(|s| !s.is_empty());
        let has_token = self.token.as_ref().is_some_and(|s| !s.is_empty());
        if self.auth.is_none() && !has_token && has_id != has_secret {
            return Err(Error::config(
                "clientId and clientSecret must be given together",
            ));
        }
        if self
            .environment
            .as_deref()
            .is_some_and(|e| e.contains([' ', '/', '\t', '\r', '\n']))
        {
            return Err(Error::config("environment must be an environment slug"));
        }
        Ok(())
    }
}

/// Builder for [`InfisicalConfig`]. Values set here win over the environment.
#[derive(Clone, Default)]
pub struct InfisicalConfigBuilder {
    common: CommonConfigBuilder,
    auth: Option<Arc<dyn AuthMethod>>,
    token: Option<Secret>,
    client_id: Option<String>,
    client_secret: Option<Secret>,
    project_id: Option<String>,
    environment: Option<String>,
    secret_path: Option<String>,
    api_version: Option<ApiVersion>,
    revoke_on_close: Option<bool>,
    clock: Option<Arc<dyn Clock>>,
}

impl fmt::Debug for InfisicalConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InfisicalConfigBuilder")
            .field("common", &self.common)
            .field("auth", &self.auth)
            .field("token", &self.token)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .field("project_id", &self.project_id)
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

impl InfisicalConfigBuilder {
    /// Endpoint base URL (default [`DEFAULT_URL`]; a trailing `/api` is removed).
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.common = self.common.url(url);
        self
    }
    /// Static access token: a machine identity access token, a user JWT or a legacy service
    /// token (`st.…`). It is never refreshed.
    pub fn token(mut self, token: impl Into<Secret>) -> Self {
        self.token = Some(token.into());
        self
    }
    /// Explicit authentication method ([`UniversalAuth`], [`TokenAuth`],
    /// [`KubernetesAuth`](crate::KubernetesAuth), [`AwsIamAuth`](crate::AwsIamAuth) or your
    /// own); wins over the token and the client id/secret.
    pub fn auth(mut self, auth: impl AuthMethod + 'static) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }
    /// Explicit authentication method (shared).
    pub fn auth_arc(mut self, auth: Arc<dyn AuthMethod>) -> Self {
        self.auth = Some(auth);
        self
    }
    /// Universal Auth client id.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }
    /// Universal Auth client secret.
    pub fn client_secret(mut self, client_secret: impl Into<Secret>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }
    /// Default project id.
    pub fn project_id(mut self, project_id: impl Into<String>) -> Self {
        self.project_id = Some(project_id.into());
        self
    }
    /// Default environment slug (for example `dev`).
    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }
    /// Default secret path (default `/`).
    pub fn secret_path(mut self, secret_path: impl Into<String>) -> Self {
        self.secret_path = Some(secret_path.into());
        self
    }
    /// Forces the secrets API version.
    pub fn api_version(mut self, version: ApiVersion) -> Self {
        self.api_version = Some(version);
        self
    }
    /// Revokes a token obtained by logging in (Universal, Kubernetes or AWS auth) on
    /// `close`. Static tokens are never revoked.
    pub fn revoke_on_close(mut self, revoke: bool) -> Self {
        self.revoke_on_close = Some(revoke);
        self
    }
    /// Clock for token refresh decisions (tests use
    /// [`ManualClock`](crate::core::clock::ManualClock)).
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }
    /// Connect timeout (default 10 s).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.connect_timeout(timeout);
        self
    }
    /// Per-attempt timeout (default 30 s).
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.request_timeout(timeout);
        self
    }
    /// Whole-call timeout including retries (default 120 s).
    pub fn total_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.total_timeout(timeout);
        self
    }
    /// Retry policy.
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.common = self.common.retry(retry);
        self
    }
    /// Maximum retries (default 3).
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.common = self.common.max_retries(max_retries);
        self
    }
    /// TLS settings.
    pub fn tls(mut self, tls: TlsConfig) -> Self {
        self.common = self.common.tls(tls);
        self
    }
    /// Extra trusted CA certificates (PEM file).
    pub fn ca_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.common = self.common.ca_cert_path(path);
        self
    }
    /// Disables TLS verification (tests only).
    pub fn insecure_skip_verify(mut self, skip: bool) -> Self {
        self.common = self.common.insecure_skip_verify(skip);
        self
    }
    /// Proxy URL (environment proxies are ignored).
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.common = self.common.proxy(proxy);
        self
    }
    /// Extra request header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.common = self.common.header(name, value);
        self
    }
    /// Text appended to the User-Agent.
    pub fn user_agent_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.common = self.common.user_agent_suffix(suffix);
        self
    }
    /// Request hooks.
    pub fn hooks(mut self, hooks: Arc<dyn Hooks>) -> Self {
        self.common = self.common.hooks(hooks);
        self
    }
    /// Edits any other common setting.
    pub fn common(mut self, f: impl FnOnce(CommonConfigBuilder) -> CommonConfigBuilder) -> Self {
        self.common = f(self.common);
        self
    }

    /// Builds without reading the environment.
    pub fn build(self) -> Result<InfisicalConfig> {
        let mut common = self.common.clone().build(DEFAULT_URL)?;
        let path = common.url().path().trim_end_matches('/').to_owned();
        if let Some(stripped) = path.strip_suffix("/api") {
            let mut url = common.url().clone();
            url.set_path(if stripped.is_empty() { "/" } else { stripped });
            common = self.common.url(url.to_string()).build(DEFAULT_URL)?;
        }
        let blank = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
        let config = InfisicalConfig {
            common,
            auth: self.auth,
            token: self.token,
            client_id: blank(self.client_id),
            client_secret: self.client_secret,
            project_id: blank(self.project_id),
            environment: blank(self.environment).map(|e| e.trim().to_owned()),
            secret_path: normalize_path(self.secret_path.as_deref().unwrap_or(DEFAULT_SECRET_PATH)),
            api_version: self.api_version.unwrap_or_default(),
            revoke_on_close: self.revoke_on_close.unwrap_or(false),
            clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
        };
        config.validate()?;
        Ok(config)
    }

    /// Fills unset values from the process environment, then builds.
    pub fn build_from_env(self) -> Result<InfisicalConfig> {
        self.build_with_env(&EnvReader::new())
    }

    /// Fills unset values from `env`, then builds.
    pub fn build_with_env(mut self, env: &EnvReader) -> Result<InfisicalConfig> {
        self.common = self.common.apply_env(env, VENDOR_URL_VARS)?;
        if self.token.is_none() {
            self.token = env.secret("TOKEN", VENDOR_TOKEN_VARS);
        }
        if self.client_id.is_none() {
            self.client_id = env.string("CLIENT_ID", VENDOR_CLIENT_ID_VARS);
        }
        if self.client_secret.is_none() {
            self.client_secret = env.secret("CLIENT_SECRET", VENDOR_CLIENT_SECRET_VARS);
        }
        if self.project_id.is_none() {
            self.project_id = env.string("PROJECT_ID", VENDOR_PROJECT_ID_VARS);
        }
        if self.environment.is_none() {
            self.environment = env.string("ENVIRONMENT", VENDOR_ENVIRONMENT_VARS);
        }
        if self.secret_path.is_none() {
            self.secret_path = env.string("SECRET_PATH", &[]);
        }
        if self.api_version.is_none() {
            if let Some(v) = env.string("API_VERSION", &[]) {
                self.api_version = Some(v.parse().map_err(|_| {
                    Error::config(format!(
                        r#"environment variable {}API_VERSION must be "", "v4" or "v3""#,
                        env.prefix()
                    ))
                })?);
            }
        }
        if self.revoke_on_close.is_none() {
            self.revoke_on_close = env.bool("REVOKE_ON_CLOSE", &[])?;
        }
        self.build()
    }
}
