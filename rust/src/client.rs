// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! `InfisicalClient`: entry point of the SDK (SPEC §2.4) and the request plumbing of the
//! service modules.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use futures::future::BoxFuture;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::api::{self, Call, BODY_MAPPED_STATUSES};
use crate::auth::{Auth, AuthMethod, TokenState};
use crate::config::{ApiVersion, InfisicalConfig};
use crate::core::hooks::guarded;
use crate::core::lifecycle::CloseGroup;
use crate::core::redact::redact_url;
use crate::core::{Error, ErrorCode, ErrorInfo, HealthStatus, HttpTransport, Result, Secret};
use crate::provider::{ProjectSecretsProvider, SecretsProviderOptions};

/// How long `close` waits for the token revocation of `revoke_on_close`.
const REVOKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Async client for Infisical. Cheap to clone (clones share one connection pool, the token
/// and the background tasks).
///
/// Service functions are methods of the client: secrets
/// ([`list_secrets`](Self::list_secrets), [`get_secret`](Self::get_secret),
/// [`create_secret`](Self::create_secret), [`update_secret`](Self::update_secret),
/// [`delete_secret`](Self::delete_secret) and the batch variants), folders, projects and
/// environments, tags, secret imports, secret versions, [`load_env`](Self::load_env) and
/// [`export_dotenv`](Self::export_dotenv). [`auth`](Self::auth) returns the token manager,
/// [`secrets`](Self::secrets) the `SecretsProvider` (SPEC §3). [`close`](Self::close) stops
/// watchers and releases connections.
#[derive(Debug, Clone)]
pub struct InfisicalClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: InfisicalConfig,
    transport: HttpTransport,
    on_close: CloseGroup,
    method: Option<Arc<dyn AuthMethod>>,
    tokens: tokio::sync::Mutex<TokenState>,
    secrets_api: Mutex<ApiVersion>,
    background: CancellationToken,
}

/// Kind of a bearer token (selects the `ping` route).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Identity,
    User,
    Service,
}

/// Classifies a bearer token: legacy service tokens start with `st.`; user JWTs carry
/// `authTokenType: accessToken` (or a user id without an identity id); everything else is
/// treated as a machine identity token.
fn token_kind(token: &str) -> TokenKind {
    if token.starts_with("st.") {
        return TokenKind::Service;
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return TokenKind::Identity;
    }
    let Ok(payload) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1].trim_end_matches('='))
    else {
        return TokenKind::Identity;
    };
    let Ok(claims) = serde_json::from_slice::<Value>(&payload) else {
        return TokenKind::Identity;
    };
    let user = api::s(&claims, "userId");
    let identity = api::s(&claims, "identityId");
    if api::s(&claims, "authTokenType") == "accessToken"
        || (!user.is_empty() && identity.is_empty())
    {
        TokenKind::User
    } else {
        TokenKind::Identity
    }
}

/// Project, environment and path of a scoped call.
#[derive(Debug, Clone)]
pub(crate) struct Scope {
    pub project_id: String,
    pub environment: String,
    pub path: String,
}

impl InfisicalClient {
    /// Creates a client from a configuration. It does not contact the server: a login
    /// (Universal, Kubernetes or AWS auth) happens on the first authenticated call or on
    /// [`Auth::login`].
    pub fn new(config: InfisicalConfig) -> Result<Self> {
        config.validate()?;
        let transport = HttpTransport::new(config.common())?;
        for s in [config.token(), config.client_secret()]
            .into_iter()
            .flatten()
        {
            transport.add_known_secret(s);
        }
        let method = config.auth_method();
        let api_version = config.api_version();
        Ok(InfisicalClient {
            inner: Arc::new(Inner {
                config,
                transport,
                on_close: CloseGroup::new(),
                method,
                tokens: tokio::sync::Mutex::new(TokenState::default()),
                secrets_api: Mutex::new(api_version),
                background: CancellationToken::new(),
            }),
        })
    }

    /// Creates a client from the process environment (see [`InfisicalConfig::from_env`]).
    pub fn from_env() -> Result<Self> {
        Self::new(InfisicalConfig::from_env()?)
    }

    /// The configuration in use.
    pub fn config(&self) -> &InfisicalConfig {
        &self.inner.config
    }

    /// The HTTP transport (for custom calls).
    pub fn transport(&self) -> &HttpTransport {
        &self.inner.transport
    }

    /// The token manager (`login`, `renew`, `revoke`, `token`, `set_token`).
    pub fn auth(&self) -> Auth {
        Auth::new(self.clone())
    }

    /// The `SecretsProvider` (SPEC §3) over the configured project, environment and secret
    /// path. `close` stops its watchers.
    pub fn secrets(&self) -> ProjectSecretsProvider {
        ProjectSecretsProvider::new(self.clone(), SecretsProviderOptions::default())
    }

    /// A `SecretsProvider` with its own project, environment, base path or read flags.
    pub fn secrets_with(&self, opts: SecretsProviderOptions) -> ProjectSecretsProvider {
        ProjectSecretsProvider::new(self.clone(), opts)
    }

    /// The API version the client uses for a resource: `secrets` (`v4` or `v3`; `""` until
    /// the first secrets call detected it), `folders` and `secret-imports` (`v2`),
    /// `projects`, `environments`, `tags`, `secret-versions` and `auth` (`v1`). Unknown
    /// resources give `""`.
    pub fn api_version(&self, resource: &str) -> &'static str {
        match resource {
            "secrets" => self.secrets_version().as_str(),
            "folders" | "secret-imports" => "v2",
            "projects" | "environments" | "tags" | "secret-versions" | "auth" => "v1",
            _ => "",
        }
    }

    /// Registers work that [`InfisicalClient::close`] runs (flush, stop watchers, …).
    pub fn on_close<F>(&self, f: F)
    where
        F: FnOnce() -> BoxFuture<'static, ()> + Send + 'static,
    {
        self.inner.on_close.register(f);
    }

    /// Checks the server without credentials (`GET /api/status`). `healthy` is true with
    /// status `ok` when the server answers 200; `details` carries the status flags
    /// (`redisConfigured`, `emailConfigured`, …). It never fails for an unhealthy or
    /// unreachable server (status `unhealthy` / `unreachable`); only `CANCELLED` and
    /// `CONFIG` are returned as errors.
    pub async fn health(&self) -> Result<HealthStatus> {
        let mut req = self.transport().get("/api/status").operation("health");
        for status in [500, 502, 503, 504] {
            req = req.ok_status(status);
        }
        let resp = match req.send().await {
            Ok(resp) => resp,
            Err(err) => return HealthStatus::from_error(err),
        };
        if resp.status() != 200 {
            return Ok(HealthStatus::unhealthy("unhealthy")
                .with_detail("httpStatus", resp.status().to_string()));
        }
        let body: Value = resp.json().unwrap_or(Value::Null);
        let mut status = HealthStatus::healthy("ok");
        if let Value::Object(map) = &body {
            for (k, v) in map {
                if let Value::Bool(b) = v {
                    status = status.with_detail(k.clone(), b.to_string());
                }
            }
        }
        Ok(status)
    }

    /// Authenticated round trip; returns the latency. The route depends on the token kind:
    /// machine identity tokens use `GET /api/v1/identities/details`, user JWTs
    /// `GET /api/v2/users/me` and legacy service tokens `GET /api/v2/service-token`. A
    /// missing, invalid or revoked token gives `AUTHENTICATION`.
    pub async fn ping(&self) -> Result<Duration> {
        let started = Instant::now();
        let token = self.auth().bearer().await?;
        let path = match token.as_ref().map(|t| token_kind(t.expose_secret())) {
            Some(TokenKind::Service) => "/api/v2/service-token",
            Some(TokenKind::User) => "/api/v2/users/me",
            _ => "/api/v1/identities/details",
        };
        self.send(Call::get(path, "ping")).await?;
        Ok(started.elapsed())
    }

    /// Always `UNSUPPORTED`: no Infisical endpoint reports the running server version
    /// (`GET /api/status` has none and the admin config only reports the latest release).
    pub async fn server_version(&self) -> Result<String> {
        Err(Error::unsupported(
            "serverVersion: Infisical exposes no server version over HTTP",
        ))
    }

    /// Stops every secrets watcher, runs the registered close callbacks, revokes a token
    /// obtained by login when `revoke_on_close` is set (best effort, 5 s) and closes the
    /// transport. Idempotent.
    pub async fn close(&self) {
        self.inner.background.cancel();
        self.inner.on_close.close().await;
        if self.config().revoke_on_close() && !self.is_closed() {
            let _ = tokio::time::timeout(REVOKE_TIMEOUT, self.auth().revoke_managed()).await;
        }
        self.inner.transport.close();
    }

    /// Whether [`InfisicalClient::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.inner.transport.is_closed()
    }

    // --- crate plumbing -----------------------------------------------------------

    pub(crate) fn auth_method(&self) -> Option<&Arc<dyn AuthMethod>> {
        self.inner.method.as_ref()
    }

    pub(crate) fn token_state(&self) -> &tokio::sync::Mutex<TokenState> {
        &self.inner.tokens
    }

    pub(crate) fn now(&self) -> Instant {
        self.config().clock().now()
    }

    /// Registers a value that must never appear in errors or logs.
    pub(crate) fn remember(&self, value: &str) {
        self.inner.transport.add_known_secret(&Secret::new(value));
    }

    /// A token cancelled by [`InfisicalClient::close`] (parent of every background task).
    pub(crate) fn background(&self) -> CancellationToken {
        self.inner.background.child_token()
    }

    /// Executes `call` with the managed token; an `AUTHENTICATION` error with a token
    /// obtained by login triggers one re-login and one retry.
    pub(crate) async fn send(&self, call: Call) -> Result<Vec<u8>> {
        let token = match (&call.token, call.no_auth) {
            (Some(t), _) => Some(t.clone()),
            (None, true) => None,
            (None, false) => self.auth().bearer().await?,
        };
        let res = self.raw(&call, token.as_ref()).await;
        let auth = self.auth();
        match (res, token) {
            (Err(e), Some(stale))
                if e.code() == ErrorCode::Authentication
                    && !call.no_auth
                    && call.token.is_none()
                    && auth.managed() =>
            {
                match auth.relogin(&stale).await {
                    Ok(fresh) => self.raw(&call, Some(&fresh)).await,
                    Err(_) => Err(e),
                }
            }
            (res, _) => res,
        }
    }

    /// Executes `call` once (with transport retries) and maps Infisical error bodies.
    async fn raw(&self, call: &Call, token: Option<&Secret>) -> Result<Vec<u8>> {
        let mut b = self
            .inner
            .transport
            .request(call.method.clone(), &call.path)
            .operation(call.op.clone());
        if let Some(t) = token.filter(|t| !t.is_empty() && !call.no_auth) {
            b = b.bearer(t);
        }
        for (k, v) in &call.query {
            b = b.query(k.clone(), v.clone());
        }
        if let Some(body) = &call.body {
            b = b.json(body);
        }
        for status in BODY_MAPPED_STATUSES {
            b = b.ok_status(status);
        }
        let resp = b.send().await.map_err(api::rate_limit_hint)?;
        if resp.status() < 400 {
            return Ok(resp.bytes().to_vec());
        }
        let err = api::map_error_body(&call.op, resp.status(), resp.bytes(), |t| {
            self.inner.transport.redact(t)
        });
        if let Some(h) = self.config().common().hooks() {
            let info = ErrorInfo {
                method: call.method.to_string(),
                url: self.display_url(call),
                error: err.clone(),
                attempt: 1,
                will_retry: false,
                retry_delay: None,
            };
            guarded(|| h.on_error(&info));
        }
        Err(err)
    }

    /// The redacted URL of `call` (for hooks).
    fn display_url(&self, call: &Call) -> String {
        let mut url = self.config().url().clone();
        let base = url.path().trim_end_matches('/').to_owned();
        url.set_path(&format!("{base}/{}", call.path.trim_start_matches('/')));
        if !call.query.is_empty() {
            url.query_pairs_mut().extend_pairs(&call.query);
        }
        self.inner.transport.redact(&redact_url(url.as_str()))
    }

    /// Executes `call` and decodes the JSON response (`Null` for an empty body).
    pub(crate) async fn call_json(&self, call: Call) -> Result<Value> {
        let op = call.op.clone();
        let body = self.send(call).await?;
        decode_json(&op, &body)
    }

    /// Executes an unauthenticated `call` (login, renew, revoke) without touching the token
    /// manager and decodes the JSON response.
    pub(crate) async fn call_json_no_auth(&self, call: Call) -> Result<Value> {
        let body = self.raw(&call, None).await?;
        decode_json(&call.op, &body)
    }

    pub(crate) fn secrets_version(&self) -> ApiVersion {
        *self
            .inner
            .secrets_api
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn set_secrets_version(&self, v: ApiVersion) {
        *self
            .inner
            .secrets_api
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = v;
    }

    /// Runs a secrets request built for v4 (`false`) or v3 (`true`). With automatic
    /// detection the first call tries v4 and falls back to v3 only when the server answers
    /// 404 `Route … not found` (a definitive answer, so replaying a write is safe); any other
    /// HTTP answer pins v4.
    pub(crate) async fn secrets_call(&self, build: impl Fn(bool) -> Call) -> Result<Value> {
        let v = self.secrets_version();
        let res = self.call_json(build(v == ApiVersion::V3)).await;
        if v != ApiVersion::Auto {
            return res;
        }
        match &res {
            Err(e) if api::is_route_missing(e) => {
                self.set_secrets_version(ApiVersion::V3);
                return self.call_json(build(true)).await;
            }
            Ok(_) => self.set_secrets_version(ApiVersion::V4),
            Err(e) if e.http_status().is_some() => self.set_secrets_version(ApiVersion::V4),
            Err(_) => {}
        }
        res
    }

    /// An explicit project id or the configured one.
    pub(crate) fn project_id(&self, op: &str, explicit: Option<&str>) -> Result<String> {
        api::non_empty(explicit)
            .or(self.config().project_id())
            .map(str::to_owned)
            .ok_or_else(|| {
                Error::config(format!(
                    "{op}: projectId is required (set project_id, GROW_INFISICAL_PROJECT_ID or INFISICAL_PROJECT_ID)"
                ))
            })
    }

    /// An explicit environment slug or the configured one.
    pub(crate) fn environment(&self, op: &str, explicit: Option<&str>) -> Result<String> {
        api::non_empty(explicit)
            .or(self.config().environment())
            .map(str::to_owned)
            .ok_or_else(|| {
                Error::config(format!(
                    "{op}: environment is required (set environment, GROW_INFISICAL_ENVIRONMENT or INFISICAL_ENVIRONMENT)"
                ))
            })
    }

    /// An explicit path or the configured secret path (normalized).
    pub(crate) fn secret_path(&self, explicit: Option<&str>) -> String {
        api::normalize_path(api::non_empty(explicit).unwrap_or(self.config().secret_path()))
    }

    /// Project, environment and path together.
    pub(crate) fn scope(
        &self,
        op: &str,
        project_id: Option<&str>,
        environment: Option<&str>,
        path: Option<&str>,
    ) -> Result<Scope> {
        Ok(Scope {
            project_id: self.project_id(op, project_id)?,
            environment: self.environment(op, environment)?,
            path: self.secret_path(path),
        })
    }
}

/// Decodes a JSON response body (`Null` for an empty body).
fn decode_json(op: &str, body: &[u8]) -> Result<Value> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(body)
        .map_err(|_| Error::unavailable(format!("{op}: response is not valid JSON")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(claims: &str) -> String {
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!("eyJhbGciOiJIUzI1NiJ9.{}.sig", enc.encode(claims))
    }

    #[test]
    fn token_kinds() {
        assert_eq!(token_kind("st.abc.def"), TokenKind::Service);
        assert_eq!(token_kind("opaque"), TokenKind::Identity);
        assert_eq!(token_kind("a.!!!.c"), TokenKind::Identity);
        assert_eq!(token_kind(&jwt("not json")), TokenKind::Identity);
        assert_eq!(
            token_kind(&jwt(r#"{"authTokenType":"accessToken"}"#)),
            TokenKind::User
        );
        assert_eq!(token_kind(&jwt(r#"{"userId":"u"}"#)), TokenKind::User);
        assert_eq!(
            token_kind(&jwt(
                r#"{"identityId":"i","authTokenType":"identityAccessToken"}"#
            )),
            TokenKind::Identity
        );
    }
}
