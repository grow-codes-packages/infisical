//! Authentication: Universal Auth, static tokens, Kubernetes and AWS IAM logins, AWS
//! Signature Version 4 and the client's token manager ([`Auth`]).

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::api::{self, Call};
use crate::client::InfisicalClient;
use crate::core::{Error, ErrorCode, Result, Secret};

/// Where [`KubernetesAuth`] reads the service account token by default.
pub const DEFAULT_KUBERNETES_TOKEN_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Share of a token's lifetime after which it is renewed.
const REFRESH_FACTOR: f64 = 0.8;

/// The signed STS call Infisical replays to identify an AWS caller.
const STS_REQUEST_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";
const STS_CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// An Infisical access token with its lifetime. `token` never prints.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessToken {
    /// The bearer token.
    pub token: Secret,
    /// Lifetime from `issued_at` (`ZERO`: the token does not expire or its lifetime is
    /// unknown, as for static tokens).
    pub expires_in: Duration,
    /// Maximum lifetime reachable by renewals (`ZERO`: unknown).
    pub max_ttl: Duration,
    /// Token type reported by the server (`Bearer`).
    pub token_type: String,
    /// When the client received the token (client clock).
    pub issued_at: Instant,
}

impl AccessToken {
    /// A token without a known lifetime (static tokens).
    pub fn new_static(token: Secret, issued_at: Instant) -> Self {
        AccessToken {
            token,
            expires_in: Duration::ZERO,
            max_ttl: Duration::ZERO,
            token_type: "Bearer".to_owned(),
            issued_at,
        }
    }

    /// `issued_at + expires_in` (`None` when the token does not expire).
    pub fn expires_at(&self) -> Option<Instant> {
        (!self.expires_in.is_zero()).then(|| self.issued_at + self.expires_in)
    }
}

/// Obtains an access token. [`UniversalAuth`], [`TokenAuth`], [`KubernetesAuth`] and
/// [`AwsIamAuth`] implement it; a custom implementation gets automatic re-login on
/// `AUTHENTICATION` errors.
#[async_trait]
pub trait AuthMethod: Send + Sync + fmt::Debug {
    /// Obtains a new access token through `client` (login calls send no `Authorization`
    /// header).
    async fn login(&self, client: &InfisicalClient) -> Result<AccessToken>;

    /// Whether the token is static (never refreshed, no re-login). Default `false`.
    fn is_static(&self) -> bool {
        false
    }
}

// --- token endpoints ------------------------------------------------------------

impl InfisicalClient {
    /// Posts `body` to an auth endpoint without a bearer and decodes the token.
    pub(crate) async fn token_call(
        &self,
        op: &str,
        path: &str,
        body: Value,
    ) -> Result<AccessToken> {
        let out = self
            .call_json_no_auth(Call::post(path, op).json(body).no_auth())
            .await?;
        let token = api::s(&out, "accessToken");
        if token.is_empty() {
            return Err(Error::unavailable(format!(
                "{op}: the response carries no access token"
            )));
        }
        self.remember(&token);
        Ok(AccessToken {
            token: Secret::new(token),
            expires_in: Duration::from_secs(api::u(&out, "expiresIn")),
            max_ttl: Duration::from_secs(api::u(&out, "accessTokenMaxTTL")),
            token_type: api::s(&out, "tokenType"),
            issued_at: self.now(),
        })
    }

    /// Extends a machine identity access token (`POST /api/v1/auth/token/renew`). The
    /// returned token may be byte-identical to the old one.
    pub(crate) async fn renew_token(&self, token: &Secret) -> Result<AccessToken> {
        if token.is_empty() {
            return Err(api::invalid("auth.renew", "access token is required"));
        }
        self.token_call(
            "auth.renew",
            "/api/v1/auth/token/renew",
            json!({"accessToken": token.expose_secret()}),
        )
        .await
    }

    /// Revokes an access token (`POST /api/v1/auth/token/revoke`); revoking twice succeeds.
    pub(crate) async fn revoke_token(&self, token: &Secret) -> Result<()> {
        if token.is_empty() {
            return Err(api::invalid("auth.revoke", "access token is required"));
        }
        self.call_json_no_auth(
            Call::post("/api/v1/auth/token/revoke", "auth.revoke")
                .json(json!({"accessToken": token.expose_secret()}))
                .no_auth(),
        )
        .await?;
        Ok(())
    }
}

// --- UniversalAuth -----------------------------------------------------------------

/// Logs a machine identity in with a client id and secret
/// (`POST /api/v1/auth/universal-auth/login`). Tokens are renewed automatically at 80 % of
/// their lifetime and re-obtained when renewal is no longer possible.
///
/// Infisical locks a Universal Auth identity after repeated failed logins (default 3
/// failures → 300 s, during which even the right secret fails); the client never retries a
/// rejected login.
#[derive(Clone)]
pub struct UniversalAuth {
    client_id: String,
    client_secret: Secret,
    organization_slug: Option<String>,
}

impl fmt::Debug for UniversalAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UniversalAuth")
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .field("organization_slug", &self.organization_slug)
            .finish()
    }
}

impl UniversalAuth {
    /// Universal Auth for `client_id` and `client_secret`.
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<Secret>) -> Self {
        UniversalAuth {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            organization_slug: None,
        }
    }

    /// Selects a sub-organization.
    pub fn organization_slug(mut self, slug: impl Into<String>) -> Self {
        self.organization_slug = Some(slug.into());
        self
    }

    /// The client id.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Logs in (`POST /api/v1/auth/universal-auth/login`).
    pub async fn login(&self, client: &InfisicalClient) -> Result<AccessToken> {
        if self.client_id.is_empty() || self.client_secret.is_empty() {
            return Err(Error::config(
                "auth.universalAuth: clientId and clientSecret are required",
            ));
        }
        client.remember(self.client_secret.expose_secret());
        let mut body = json!({
            "clientId": self.client_id,
            "clientSecret": self.client_secret.expose_secret(),
        });
        if let Some(slug) = &self.organization_slug {
            body["organizationSlug"] = json!(slug);
        }
        client
            .token_call(
                "auth.universalAuth.login",
                "/api/v1/auth/universal-auth/login",
                body,
            )
            .await
    }

    /// Extends `token` on the server (`POST /api/v1/auth/token/renew`). Always keep the
    /// returned token; it cannot outlive its `max_ttl`.
    pub async fn renew(&self, client: &InfisicalClient, token: &Secret) -> Result<AccessToken> {
        client.renew_token(token).await
    }

    /// Revokes `token` (`POST /api/v1/auth/token/revoke`).
    pub async fn revoke(&self, client: &InfisicalClient, token: &Secret) -> Result<()> {
        client.revoke_token(token).await
    }
}

#[async_trait]
impl AuthMethod for UniversalAuth {
    async fn login(&self, client: &InfisicalClient) -> Result<AccessToken> {
        UniversalAuth::login(self, client).await
    }
}

// --- TokenAuth -------------------------------------------------------------------------

/// A static access token: a token-auth machine identity token, a user JWT or a legacy
/// service token (`st.…`). It is never refreshed.
#[derive(Debug, Clone)]
pub struct TokenAuth {
    token: Secret,
}

impl TokenAuth {
    /// Token auth for `token`.
    pub fn new(token: impl Into<Secret>) -> Self {
        TokenAuth {
            token: token.into(),
        }
    }
}

#[async_trait]
impl AuthMethod for TokenAuth {
    async fn login(&self, client: &InfisicalClient) -> Result<AccessToken> {
        if self.token.is_empty() {
            return Err(Error::config("auth.tokenAuth: token is required"));
        }
        client.remember(self.token.expose_secret());
        Ok(AccessToken::new_static(self.token.clone(), client.now()))
    }

    fn is_static(&self) -> bool {
        true
    }
}

// --- KubernetesAuth -------------------------------------------------------------------

/// Logs a machine identity in with a Kubernetes service account token
/// (`POST /api/v1/auth/kubernetes-auth/login`). The server validates the token through the
/// Kubernetes TokenReview API.
#[derive(Debug, Clone)]
pub struct KubernetesAuth {
    identity_id: String,
    jwt: Option<Secret>,
    token_path: Option<PathBuf>,
    organization_slug: Option<String>,
}

impl KubernetesAuth {
    /// Kubernetes auth for the machine identity `identity_id`; the token is read from
    /// [`DEFAULT_KUBERNETES_TOKEN_PATH`] unless [`jwt`](Self::jwt) or
    /// [`token_path`](Self::token_path) is set.
    pub fn new(identity_id: impl Into<String>) -> Self {
        KubernetesAuth {
            identity_id: identity_id.into(),
            jwt: None,
            token_path: None,
            organization_slug: None,
        }
    }

    /// The service account token itself.
    pub fn jwt(mut self, jwt: impl Into<Secret>) -> Self {
        self.jwt = Some(jwt.into());
        self
    }

    /// The service account token file.
    pub fn token_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.token_path = Some(path.into());
        self
    }

    /// Selects a sub-organization.
    pub fn organization_slug(mut self, slug: impl Into<String>) -> Self {
        self.organization_slug = Some(slug.into());
        self
    }
}

#[async_trait]
impl AuthMethod for KubernetesAuth {
    async fn login(&self, client: &InfisicalClient) -> Result<AccessToken> {
        const OP: &str = "auth.kubernetesAuth.login";
        if self.identity_id.is_empty() {
            return Err(Error::config(format!("{OP}: identityId is required")));
        }
        let jwt = match self.jwt.as_ref().filter(|j| !j.is_empty()) {
            Some(j) => j.expose_secret().to_owned(),
            None => {
                let path = self
                    .token_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_KUBERNETES_TOKEN_PATH));
                std::fs::read_to_string(path)
                    .map_err(|_| {
                        Error::config(format!(
                            "{OP}: the service account token file cannot be read"
                        ))
                    })?
                    .trim()
                    .to_owned()
            }
        };
        client.remember(&jwt);
        let mut body = json!({"identityId": self.identity_id, "jwt": jwt});
        if let Some(slug) = &self.organization_slug {
            body["organizationSlug"] = json!(slug);
        }
        client
            .token_call(OP, "/api/v1/auth/kubernetes-auth/login", body)
            .await
    }
}

// --- AwsIamAuth --------------------------------------------------------------------------

/// The login body [`AwsIamAuth`] sends (exposed for tests and debugging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsLoginRequest {
    /// Machine identity id.
    pub identity_id: String,
    /// Always `POST`.
    pub iam_http_request_method: String,
    /// base64(`Action=GetCallerIdentity&Version=2011-06-15`).
    pub iam_request_body: String,
    /// base64 of the JSON object of the signed headers.
    pub iam_request_headers: String,
    /// Optional sub-organization.
    pub organization_slug: Option<String>,
}

impl AwsLoginRequest {
    /// The JSON body of the login call.
    pub fn to_json(&self) -> Value {
        let mut body = json!({
            "identityId": self.identity_id,
            "iamHttpRequestMethod": self.iam_http_request_method,
            "iamRequestBody": self.iam_request_body,
            "iamRequestHeaders": self.iam_request_headers,
        });
        if let Some(slug) = &self.organization_slug {
            body["organizationSlug"] = json!(slug);
        }
        body
    }
}

/// Logs a machine identity in with AWS IAM credentials (`POST /api/v1/auth/aws-auth/login`).
/// The client signs an STS `GetCallerIdentity` request with AWS Signature Version 4 and
/// sends it to Infisical, which forwards it to AWS STS to verify the caller. Credentials
/// left unset are read from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
/// `AWS_SESSION_TOKEN` and `AWS_REGION` / `AWS_DEFAULT_REGION` (region default `us-east-1`).
#[derive(Clone)]
pub struct AwsIamAuth {
    identity_id: String,
    region: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<Secret>,
    session_token: Option<Secret>,
    organization_slug: Option<String>,
    signing_time: Option<SystemTime>,
}

impl fmt::Debug for AwsIamAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsIamAuth")
            .field("identity_id", &self.identity_id)
            .field("region", &self.region)
            .field("secret_access_key", &self.secret_access_key)
            .finish_non_exhaustive()
    }
}

/// Resolved AWS credentials: `(region, key id, secret, session token)`.
type AwsCredentials = (String, String, String, String);

impl AwsIamAuth {
    /// AWS IAM auth for the machine identity `identity_id`.
    pub fn new(identity_id: impl Into<String>) -> Self {
        AwsIamAuth {
            identity_id: identity_id.into(),
            region: None,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            organization_slug: None,
            signing_time: None,
        }
    }

    /// STS region (default `AWS_REGION`, `AWS_DEFAULT_REGION`, then `us-east-1`).
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Explicit AWS credentials.
    pub fn credentials(
        mut self,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<Secret>,
    ) -> Self {
        self.access_key_id = Some(access_key_id.into());
        self.secret_access_key = Some(secret_access_key.into());
        self
    }

    /// AWS session token (temporary credentials).
    pub fn session_token(mut self, token: impl Into<Secret>) -> Self {
        self.session_token = Some(token.into());
        self
    }

    /// Selects a sub-organization.
    pub fn organization_slug(mut self, slug: impl Into<String>) -> Self {
        self.organization_slug = Some(slug.into());
        self
    }

    /// Fixed signing time (tests); default: now.
    pub fn signing_time(mut self, time: SystemTime) -> Self {
        self.signing_time = Some(time);
        self
    }

    fn resolve(&self, lookup: impl Fn(&str) -> Option<String>) -> AwsCredentials {
        let first = |names: &[&str]| {
            names
                .iter()
                .find_map(|n| lookup(n).filter(|v| !v.is_empty()))
                .unwrap_or_default()
        };
        let set = |v: &Option<String>| v.clone().filter(|s| !s.is_empty());
        let region = set(&self.region)
            .or_else(|| {
                Some(first(&["AWS_REGION", "AWS_DEFAULT_REGION"])).filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "us-east-1".to_owned());
        let explicit_key = set(&self.access_key_id);
        let key_id = explicit_key
            .clone()
            .unwrap_or_else(|| first(&["AWS_ACCESS_KEY_ID"]));
        let secret = self
            .secret_access_key
            .as_ref()
            .map(|s| s.expose_secret().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| first(&["AWS_SECRET_ACCESS_KEY"]));
        let session = match &self.session_token {
            Some(t) => t.expose_secret().to_owned(),
            None if explicit_key.is_none() => first(&["AWS_SESSION_TOKEN"]),
            None => String::new(),
        };
        (region, key_id, secret, session)
    }

    /// Builds the signed login body (no network call).
    pub fn login_request(&self) -> Result<AwsLoginRequest> {
        self.login_request_with(|n| std::env::var(n).ok())
    }

    fn login_request_with(
        &self,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<AwsLoginRequest> {
        const OP: &str = "auth.awsIamAuth.login";
        if self.identity_id.is_empty() {
            return Err(Error::config(format!("{OP}: identityId is required")));
        }
        let (region, key_id, secret, session) = self.resolve(lookup);
        if key_id.is_empty() || secret.is_empty() {
            return Err(Error::config(format!(
                "{OP}: AWS credentials are required (access key id and secret access key or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"
            )));
        }
        let host = format!("sts.{region}.amazonaws.com");
        let mut headers = BTreeMap::from([
            ("Host".to_owned(), host.clone()),
            ("Content-Type".to_owned(), STS_CONTENT_TYPE.to_owned()),
        ]);
        if !session.is_empty() {
            headers.insert("X-Amz-Security-Token".to_owned(), session);
        }
        let mut signed = sign_v4(&SigV4Request {
            method: "POST".to_owned(),
            host,
            path: "/".to_owned(),
            query: String::new(),
            headers,
            body: STS_REQUEST_BODY.as_bytes().to_vec(),
            region,
            service: "sts".to_owned(),
            access_key_id: key_id,
            secret_access_key: Secret::new(secret),
            time: self.signing_time.unwrap_or_else(SystemTime::now),
        });
        signed.insert(
            "Content-Length".to_owned(),
            STS_REQUEST_BODY.len().to_string(),
        );
        let b64 = base64::engine::general_purpose::STANDARD;
        Ok(AwsLoginRequest {
            identity_id: self.identity_id.clone(),
            iam_http_request_method: "POST".to_owned(),
            iam_request_body: b64.encode(STS_REQUEST_BODY),
            iam_request_headers: b64.encode(serde_json::to_vec(&signed)?),
            organization_slug: self.organization_slug.clone(),
        })
    }
}

#[async_trait]
impl AuthMethod for AwsIamAuth {
    async fn login(&self, client: &InfisicalClient) -> Result<AccessToken> {
        let body = self.login_request()?;
        let (_, key_id, secret, session) = self.resolve(|n| std::env::var(n).ok());
        for v in [key_id, secret, session] {
            client.remember(&v);
        }
        client
            .token_call(
                "auth.awsIamAuth.login",
                "/api/v1/auth/aws-auth/login",
                body.to_json(),
            )
            .await
    }
}

// --- AWS Signature Version 4 -----------------------------------------------------------

/// A request to sign with AWS Signature Version 4.
#[derive(Debug, Clone)]
pub struct SigV4Request {
    /// HTTP method.
    pub method: String,
    /// Host header value.
    pub host: String,
    /// URI path (`/` when empty); it must already be URI-encoded.
    pub path: String,
    /// Raw query string (already encoded, may be empty).
    pub query: String,
    /// Headers signed in addition to `Host` and `X-Amz-Date`.
    pub headers: BTreeMap<String, String>,
    /// Request body.
    pub body: Vec<u8>,
    /// AWS region.
    pub region: String,
    /// AWS service (`sts`).
    pub service: String,
    /// Access key id.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: Secret,
    /// Signing time.
    pub time: SystemTime,
}

/// Signs `req` and returns every header to send: the given headers plus `Host`,
/// `X-Amz-Date` and `Authorization`.
pub fn sign_v4(req: &SigV4Request) -> BTreeMap<String, String> {
    let iso = crate::secrets::rfc3339(req.time);
    let date: String = [&iso[0..4], &iso[5..7], &iso[8..10]].concat();
    let amz_date = format!("{date}T{}{}{}Z", &iso[11..13], &iso[14..16], &iso[17..19]);
    let mut out = req.headers.clone();
    if !out.keys().any(|k| k.eq_ignore_ascii_case("host")) {
        out.insert("Host".to_owned(), req.host.clone());
    }
    out.insert("X-Amz-Date".to_owned(), amz_date.clone());

    let canon: BTreeMap<String, String> = out
        .iter()
        .map(|(k, v)| {
            (
                k.to_ascii_lowercase(),
                v.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    let canon_headers: String = canon.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = canon.keys().cloned().collect::<Vec<_>>().join(";");
    let path = if req.path.is_empty() { "/" } else { &req.path };
    let mut query: Vec<&str> = req.query.split('&').filter(|p| !p.is_empty()).collect();
    query.sort_unstable();
    let canonical = [
        req.method.as_str(),
        path,
        &query.join("&"),
        &canon_headers,
        &signed_headers,
        &hex(&Sha256::digest(&req.body)),
    ]
    .join("\n");
    let scope = format!("{date}/{}/{}/aws4_request", req.region, req.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac_sha256(
        format!("AWS4{}", req.secret_access_key.expose_secret()).as_bytes(),
        date.as_bytes(),
    );
    for part in [req.region.as_str(), req.service.as_str(), "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
    out.insert(
        "Authorization".to_owned(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            req.access_key_id
        ),
    );
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);
    let mut inner = Sha256::new();
    inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<_>>());
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<_>>());
    outer.update(inner.finalize());
    outer.finalize().to_vec()
}

// --- token manager ----------------------------------------------------------------

/// Token state kept by the client.
#[derive(Debug, Default)]
pub(crate) struct TokenState {
    token: Option<AccessToken>,
    login_at: Option<Instant>,
}

/// The client's token manager: it logs in on first use, renews the token at 80 % of its
/// lifetime (re-login when renewal fails or the max TTL is reached) and re-logs in once
/// when a call fails with `AUTHENTICATION`. Static tokens are used as they are.
#[derive(Debug, Clone)]
pub struct Auth {
    client: InfisicalClient,
}

impl Auth {
    pub(crate) fn new(client: InfisicalClient) -> Self {
        Auth { client }
    }

    /// The configured authentication method (`None` when none).
    pub fn method(&self) -> Option<Arc<dyn AuthMethod>> {
        self.client.auth_method().cloned()
    }

    /// Whether tokens come from a login that can be repeated.
    pub(crate) fn managed(&self) -> bool {
        self.client.auth_method().is_some_and(|m| !m.is_static())
    }

    /// Obtains a new token with the configured method and stores it.
    pub async fn login(&self) -> Result<AccessToken> {
        let mut st = self.client.token_state().lock().await;
        self.login_locked(&mut st).await
    }

    async fn login_locked(&self, st: &mut TokenState) -> Result<AccessToken> {
        let Some(method) = self.client.auth_method().cloned() else {
            return Err(Error::config(
                "auth.login: no authentication method configured (set auth, token or clientId/clientSecret)",
            ));
        };
        let t = method.login(&self.client).await?;
        st.login_at = Some(t.issued_at);
        st.token = Some(t.clone());
        Ok(t)
    }

    /// Extends the current token on the server and stores the result.
    pub async fn renew(&self) -> Result<AccessToken> {
        let mut st = self.client.token_state().lock().await;
        let Some(cur) = st.token.as_ref() else {
            return Err(api::invalid(
                "auth.renew",
                "no access token to renew; log in first",
            ));
        };
        let t = self.client.renew_token(&cur.token).await?;
        st.token = Some(t.clone());
        Ok(t)
    }

    /// Revokes the current token on the server and forgets it; the next call logs in again
    /// (a static token is revoked too and then fails).
    pub async fn revoke(&self) -> Result<()> {
        let mut st = self.client.token_state().lock().await;
        let Some(cur) = st.token.as_ref() else {
            return Ok(());
        };
        self.client.revoke_token(&cur.token).await?;
        st.token = None;
        Ok(())
    }

    /// Revokes a token obtained by login (best effort, used by `close`).
    pub(crate) async fn revoke_managed(&self) {
        if !self.managed() {
            return;
        }
        let mut st = self.client.token_state().lock().await;
        if let Some(cur) = st.token.take() {
            let _ = self.client.revoke_token(&cur.token).await;
        }
    }

    /// The current access token (`None` before the first login).
    pub async fn token(&self) -> Option<AccessToken> {
        self.client.token_state().lock().await.token.clone()
    }

    /// Replaces the current token with a static one (no refresh until the next login); an
    /// empty token clears it.
    pub async fn set_token(&self, token: impl Into<Secret>) {
        let token = token.into();
        self.client.remember(token.expose_secret());
        let mut st = self.client.token_state().lock().await;
        st.token = (!token.is_empty()).then(|| AccessToken::new_static(token, self.client.now()));
    }

    /// A valid token for the next call (`None` when no auth is configured).
    pub(crate) async fn bearer(&self) -> Result<Option<Secret>> {
        let mut st = self.client.token_state().lock().await;
        let Some(t) = st.token.clone() else {
            if self.client.auth_method().is_none() {
                return Ok(None);
            }
            return Ok(Some(self.login_locked(&mut st).await?.token));
        };
        if t.expires_in.is_zero() || !self.managed() {
            return Ok(Some(t.token));
        }
        let now = self.client.now();
        let refresh_at = t.issued_at + t.expires_in.mul_f64(REFRESH_FACTOR);
        if now < refresh_at {
            return Ok(Some(t.token));
        }
        let login_at = st.login_at.unwrap_or(t.issued_at);
        let max_reached = !t.max_ttl.is_zero() && now + t.expires_in >= login_at + t.max_ttl;
        if !max_reached {
            match self.client.renew_token(&t.token).await {
                Ok(nt) => {
                    st.token = Some(nt.clone());
                    return Ok(Some(nt.token));
                }
                Err(e) if e.code() == ErrorCode::Cancelled => return Err(e),
                Err(_) => {}
            }
        }
        Ok(Some(self.login_locked(&mut st).await?.token))
    }

    /// Logs in again unless another call already replaced `stale`.
    pub(crate) async fn relogin(&self, stale: &Secret) -> Result<Secret> {
        let mut st = self.client.token_state().lock().await;
        if let Some(t) = st.token.as_ref().filter(|t| &t.token != stale) {
            return Ok(t.token.clone());
        }
        Ok(self.login_locked(&mut st).await?.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::UNIX_EPOCH;

    #[test]
    fn hmac_matches_rfc4231() {
        // RFC 4231 test case 2 and a key longer than the block size (case 6).
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn aws_credentials_from_lookup() {
        let env: HashMap<&str, &str> = HashMap::from([
            ("AWS_DEFAULT_REGION", "eu-west-1"),
            ("AWS_ACCESS_KEY_ID", "AKIDENV"),
            ("AWS_SECRET_ACCESS_KEY", "env-secret"),
            ("AWS_SESSION_TOKEN", "env-session"),
        ]);
        let lookup = |n: &str| env.get(n).map(|v| (*v).to_owned());
        let a = AwsIamAuth::new("id");
        assert_eq!(
            a.resolve(lookup),
            (
                "eu-west-1".to_owned(),
                "AKIDENV".to_owned(),
                "env-secret".to_owned(),
                "env-session".to_owned()
            )
        );
        // explicit credentials never pick up the environment session token
        let a = AwsIamAuth::new("id")
            .credentials("AKID", "s")
            .region("us-west-2");
        assert_eq!(a.resolve(lookup).3, "");
        assert_eq!(a.resolve(lookup).0, "us-west-2");
        let a = a.session_token("tok");
        assert_eq!(a.resolve(lookup).3, "tok");
        assert_eq!(AwsIamAuth::new("id").resolve(|_| None).0, "us-east-1");
        let req = AwsIamAuth::new("id")
            .signing_time(UNIX_EPOCH)
            .login_request_with(lookup)
            .unwrap();
        let hdrs = base64::engine::general_purpose::STANDARD
            .decode(&req.iam_request_headers)
            .unwrap();
        let hdrs: BTreeMap<String, String> = serde_json::from_slice(&hdrs).unwrap();
        assert_eq!(hdrs["X-Amz-Security-Token"], "env-session");
        assert_eq!(hdrs["Host"], "sts.eu-west-1.amazonaws.com");
        assert!(AwsIamAuth::new("id").login_request_with(|_| None).is_err());
    }
}
