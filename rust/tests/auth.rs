//! Auth: Universal Auth, static tokens, Kubernetes and AWS IAM logins, SigV4 and the token
//! manager (refresh, re-login, revoke on close).

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use grow_infisical as sdk;
use sdk::core::clock::ManualClock;
use sdk::core::ErrorCode;
use sdk::{
    sign_v4, AccessToken, AuthMethod, AwsIamAuth, InfisicalClient as Client,
    InfisicalConfig as Config, KubernetesAuth, RetryPolicy, Secret, SigV4Request, TokenAuth,
    UniversalAuth,
};
use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LOGIN: &str = "/api/v1/auth/universal-auth/login";
const RENEW: &str = "/api/v1/auth/token/renew";
const REVOKE: &str = "/api/v1/auth/token/revoke";
const DETAILS: &str = "/api/v1/identities/details";

fn token_body(token: &str) -> Value {
    json!({"accessToken": token, "expiresIn": 300, "accessTokenMaxTTL": 3600, "tokenType": "Bearer"})
}

fn ua_client(server: &MockServer, clock: Option<ManualClock>) -> Client {
    let mut b = Config::builder()
        .url(server.uri())
        .client_id("cid-1")
        .client_secret("client-secret-1")
        .project_id(PROJECT)
        .environment(ENV)
        .retry(RetryPolicy::none());
    if let Some(c) = clock {
        b = b.clock(Arc::new(c));
    }
    Client::new(b.build().unwrap()).unwrap()
}

async fn ok_with_bearer(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path(DETAILS))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(reply("ping.identity"))
        .mount(server)
        .await;
}

#[tokio::test]
async fn universal_auth_login_on_first_call_and_refresh() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .and(body_partial_json(
            json!({"clientId": "cid-1", "clientSecret": "client-secret-1"}),
        ))
        .respond_with(json(200, token_body("tok-1")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(json(200, token_body("tok-3")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(RENEW))
        .and(body_partial_json(json!({"accessToken": "tok-1"})))
        .respond_with(json(200, token_body("tok-2")))
        .mount(&server)
        .await;
    on(&server, "POST", RENEW, "universalAuth.renew.revoked").await;
    for t in ["tok-1", "tok-2", "tok-3"] {
        ok_with_bearer(&server, t).await;
    }
    let clock = ManualClock::new();
    let c = ua_client(&server, Some(clock.clone()));
    assert!(c.auth().token().await.is_none());
    assert!(format!("{:?}", c.auth().method().unwrap()).contains("cid-1"));
    c.ping().await.unwrap();
    let login = &requests(&server, LOGIN).await[0];
    assert!(login.headers.get("authorization").is_none());
    let t = c.auth().token().await.unwrap();
    assert_eq!(t.token.reveal(), "tok-1");
    assert_eq!(t.expires_in, Duration::from_secs(300));
    assert_eq!(t.max_ttl, Duration::from_secs(3600));
    assert_eq!(t.token_type, "Bearer");
    assert!(t.expires_at().is_some());
    // before 80 % of the lifetime: no renewal
    clock.advance(Duration::from_secs(200));
    c.ping().await.unwrap();
    assert!(requests(&server, RENEW).await.is_empty());
    // after 80 %: renewed
    clock.advance(Duration::from_secs(50));
    c.ping().await.unwrap();
    assert_eq!(c.auth().token().await.unwrap().token.reveal(), "tok-2");
    // renewal of tok-2 fails (revoked) → login again
    clock.advance(Duration::from_secs(250));
    c.ping().await.unwrap();
    assert_eq!(c.auth().token().await.unwrap().token.reveal(), "tok-3");
    // past the max TTL: login without trying to renew
    let renews = requests(&server, RENEW).await.len();
    clock.advance(Duration::from_secs(3600));
    c.ping().await.unwrap();
    assert_eq!(requests(&server, RENEW).await.len(), renews);
    assert_eq!(requests(&server, LOGIN).await.len(), 3);
}

#[tokio::test]
async fn relogin_once_on_authentication_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(json(200, token_body("tok-1")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .respond_with(json(200, token_body("tok-2")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(DETAILS))
        .and(header("authorization", "Bearer tok-1"))
        .respond_with(reply("auth.revokedToken"))
        .mount(&server)
        .await;
    ok_with_bearer(&server, "tok-2").await;
    let c = ua_client(&server, None);
    c.ping().await.unwrap();
    assert_eq!(requests(&server, LOGIN).await.len(), 2);
    // a static token is never re-obtained
    let st = client_with(&server, |b| b.token("tok-1"));
    assert_eq!(
        st.ping().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
    assert_eq!(requests(&server, LOGIN).await.len(), 2);
}

#[tokio::test]
async fn relogin_failure_returns_the_original_error() {
    let server = MockServer::start().await;
    once(&server, "POST", LOGIN, "universalAuth.login.ok").await;
    on(&server, "POST", LOGIN, "universalAuth.login.lockedOut401").await;
    on(&server, "GET", DETAILS, "auth.revokedToken").await;
    let c = ua_client(&server, None);
    let e = c.ping().await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Authentication);
    assert!(e.message().contains("revoked"), "{}", e.message());
}

#[tokio::test]
async fn login_failures_are_not_retried() {
    let server = MockServer::start().await;
    on(&server, "POST", LOGIN, "universalAuth.login.lockedOut401").await;
    let c = ua_client(&server, None);
    let e = c.auth().login().await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Authentication);
    assert!(e.message().contains("temporarily locked"));
    assert!(!e.message().contains("client-secret-1"));
    assert_eq!(requests(&server, LOGIN).await.len(), 1);
    let server = MockServer::start().await;
    on(&server, "POST", LOGIN, "universalAuth.login.withBearer403").await;
    let e = ua_client(&server, None).auth().login().await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Authentication);
    // a 200 without a token
    let server = MockServer::start().await;
    on_reply(&server, "POST", LOGIN, json(200, json!({}))).await;
    let e = ua_client(&server, None).auth().login().await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unavailable);
}

#[tokio::test]
async fn auth_manager_operations() {
    let server = MockServer::start().await;
    on_reply(&server, "POST", LOGIN, json(200, token_body("tok-1"))).await;
    on_reply(&server, "POST", RENEW, json(200, token_body("tok-1"))).await;
    on(&server, "POST", REVOKE, "universalAuth.revoke.ok").await;
    ok_with_bearer(&server, "tok-1").await;
    ok_with_bearer(&server, "manual-token").await;
    let c = ua_client(&server, None);
    let a = c.auth();
    assert_eq!(a.renew().await.unwrap_err().code(), ErrorCode::Validation);
    a.revoke().await.unwrap(); // nothing to revoke
    assert!(requests(&server, REVOKE).await.is_empty());
    let t = a.login().await.unwrap();
    assert_eq!(t.token.reveal(), "tok-1");
    let r = a.renew().await.unwrap();
    assert_eq!(r.token, t.token);
    a.revoke().await.unwrap();
    assert!(a.token().await.is_none());
    let sent = sent(&server, REVOKE).await;
    assert_eq!(sent[0], json!({"accessToken": "tok-1"}));
    a.set_token("manual-token").await;
    let t = a.token().await.unwrap();
    assert!(t.expires_at().is_none());
    c.ping().await.unwrap();
    a.set_token("").await;
    assert!(a.token().await.is_none());
    // no method at all
    let none = Client::new(Config::builder().url(server.uri()).build().unwrap()).unwrap();
    assert_eq!(
        none.auth().login().await.unwrap_err().code(),
        ErrorCode::Config
    );
    assert!(none.auth().method().is_none());
}

#[tokio::test]
async fn revoke_on_close() {
    let server = MockServer::start().await;
    on_reply(&server, "POST", LOGIN, json(200, token_body("tok-1"))).await;
    on(&server, "POST", REVOKE, "universalAuth.revoke.ok").await;
    ok_with_bearer(&server, "tok-1").await;
    let c = Client::new(
        Config::builder()
            .url(server.uri())
            .client_id("cid-1")
            .client_secret("client-secret-1")
            .revoke_on_close(true)
            .retry(RetryPolicy::none())
            .build()
            .unwrap(),
    )
    .unwrap();
    c.ping().await.unwrap();
    c.close().await;
    c.close().await;
    assert_eq!(requests(&server, REVOKE).await.len(), 1);
    // static tokens are never revoked
    let st = client_with(&server, |b| b.token("tok-1").revoke_on_close(true));
    st.ping().await.unwrap();
    st.close().await;
    assert_eq!(requests(&server, REVOKE).await.len(), 1);
}

#[tokio::test]
async fn universal_auth_methods() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN))
        .and(body_partial_json(json!({"organizationSlug": "sub-org"})))
        .respond_with(json(200, token_body("tok-1")))
        .mount(&server)
        .await;
    on(&server, "POST", RENEW, "universalAuth.renew.revoked").await;
    on(
        &server,
        "POST",
        REVOKE,
        "universalAuth.revoke.alreadyRevoked",
    )
    .await;
    let c = client(&server);
    let ua = UniversalAuth::new("cid", "sec-12345").organization_slug("sub-org");
    assert_eq!(ua.client_id(), "cid");
    assert!(!format!("{ua:?}").contains("sec-12345"));
    let t = ua.login(&c).await.unwrap();
    assert_eq!(
        ua.renew(&c, &t.token).await.unwrap_err().code(),
        ErrorCode::Authentication
    );
    ua.revoke(&c, &t.token).await.unwrap();
    assert_eq!(
        ua.renew(&c, &Secret::default()).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        ua.revoke(&c, &Secret::default()).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let empty = UniversalAuth::new("", "x");
    assert_eq!(empty.login(&c).await.unwrap_err().code(), ErrorCode::Config);
    // the login never carries the static bearer of the client
    let login = &requests(&server, LOGIN).await[0];
    assert!(login.headers.get("authorization").is_none());
}

#[tokio::test]
async fn token_auth() {
    let server = MockServer::start().await;
    ok_with_bearer(&server, "static-1").await;
    let c = client_with(&server, |b| b.auth(TokenAuth::new("static-1")));
    c.ping().await.unwrap();
    assert!(c.auth().method().unwrap().is_static());
    let t = TokenAuth::new("");
    assert_eq!(t.login(&c).await.unwrap_err().code(), ErrorCode::Config);
}

#[tokio::test]
async fn kubernetes_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/kubernetes-auth/login"))
        .and(body_partial_json(
            json!({"identityId": "id-1", "jwt": "k8s-jwt-1", "organizationSlug": "o"}),
        ))
        .respond_with(json(200, token_body("tok-k8s")))
        .mount(&server)
        .await;
    on(
        &server,
        "POST",
        "/api/v1/auth/kubernetes-auth/login",
        "kubernetesAuth.login.notConfigured",
    )
    .await;
    let c = client(&server);
    let k = KubernetesAuth::new("id-1")
        .jwt("k8s-jwt-1")
        .organization_slug("o");
    assert_eq!(k.login(&c).await.unwrap().token.reveal(), "tok-k8s");
    let dir = std::env::temp_dir().join(format!("grow-infisical-k8s-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("token");
    std::fs::write(&file, "file-jwt-1\n").unwrap();
    let e = KubernetesAuth::new("id-2")
        .token_path(&file)
        .login(&c)
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
    assert!(e.message().contains("Kubernetes auth method not found"));
    let sent = sent(&server, "/api/v1/auth/kubernetes-auth/login").await;
    assert_eq!(sent[1]["jwt"], "file-jwt-1");
    std::fs::remove_dir_all(&dir).unwrap();
    let e = KubernetesAuth::new("id-2")
        .token_path(dir.join("missing"))
        .login(&c)
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Config);
    let e = KubernetesAuth::new("").login(&c).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Config);
}

fn vanilla(query: &str, headers: BTreeMap<String, String>) -> SigV4Request {
    SigV4Request {
        method: "GET".into(),
        host: "example.amazonaws.com".into(),
        path: "/".into(),
        query: query.into(),
        headers,
        body: Vec::new(),
        region: "us-east-1".into(),
        service: "service".into(),
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
        time: UNIX_EPOCH + Duration::from_secs(1_440_938_160), // 2015-08-30T12:36:00Z
    }
}

#[test]
fn sigv4_test_suite_vectors() {
    // AWS SigV4 test suite "get-vanilla"
    let h = sign_v4(&vanilla("", BTreeMap::new()));
    assert_eq!(
        h["Authorization"],
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
    assert_eq!(h["X-Amz-Date"], "20150830T123600Z");
    assert_eq!(h["Host"], "example.amazonaws.com");
    // "get-vanilla-query-order-key-case": sorted query, caller-provided host header
    let mut req = vanilla(
        "Param2=value2&Param1=value1",
        BTreeMap::from([("host".to_owned(), "example.amazonaws.com".to_owned())]),
    );
    req.path = String::new();
    let h = sign_v4(&req);
    assert!(h["Authorization"]
        .ends_with("Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"));
    assert!(!h.contains_key("Host"));
}

#[tokio::test]
async fn aws_iam_auth() {
    let fixed = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
    let a = AwsIamAuth::new("id-1")
        .region("eu-central-1")
        .credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
        .session_token("session-1")
        .organization_slug("o")
        .signing_time(fixed);
    assert!(!format!("{a:?}").contains("EXAMPLEKEY"));
    let req = a.login_request().unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    assert_eq!(
        b64.decode(&req.iam_request_body).unwrap(),
        b"Action=GetCallerIdentity&Version=2011-06-15"
    );
    let hdr: BTreeMap<String, String> =
        serde_json::from_slice(&b64.decode(&req.iam_request_headers).unwrap()).unwrap();
    assert_eq!(hdr["Host"], "sts.eu-central-1.amazonaws.com");
    assert_eq!(hdr["Content-Length"], "43");
    assert_eq!(hdr["X-Amz-Security-Token"], "session-1");
    let want = sign_v4(&SigV4Request {
        method: "POST".into(),
        host: hdr["Host"].clone(),
        path: "/".into(),
        query: String::new(),
        headers: BTreeMap::from([
            ("Host".to_owned(), hdr["Host"].clone()),
            ("Content-Type".to_owned(), hdr["Content-Type"].clone()),
            ("X-Amz-Security-Token".to_owned(), "session-1".to_owned()),
        ]),
        body: b"Action=GetCallerIdentity&Version=2011-06-15".to_vec(),
        region: "eu-central-1".into(),
        service: "sts".into(),
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
        time: fixed,
    });
    assert_eq!(hdr["Authorization"], want["Authorization"]);
    let body = req.to_json();
    assert_eq!(body["iamHttpRequestMethod"], "POST");
    assert_eq!(body["organizationSlug"], "o");
    assert_eq!(req.organization_slug.as_deref(), Some("o"));

    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/api/v1/auth/aws-auth/login",
        "awsIamAuth.login.notConfigured",
    )
    .await;
    let c = client(&server);
    let e = a.login(&c).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
    assert!(e.message().contains("AWS auth method not found"));
    let sent = &sent(&server, "/api/v1/auth/aws-auth/login").await[0];
    assert_eq!(sent["identityId"], "id-1");
    assert!(sent["iamRequestHeaders"].as_str().unwrap().len() > 100);
    let e = AwsIamAuth::new("").login(&c).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Config);
    let without_org = AwsIamAuth::new("i")
        .credentials("AKID", "s")
        .login_request()
        .unwrap();
    assert!(without_org.to_json().get("organizationSlug").is_none());
}

#[derive(Debug)]
struct Custom;

#[async_trait]
impl AuthMethod for Custom {
    async fn login(&self, client: &Client) -> sdk::Result<AccessToken> {
        Ok(AccessToken {
            token: Secret::new("custom-tok"),
            expires_in: Duration::from_secs(60),
            max_ttl: Duration::ZERO,
            token_type: "Bearer".into(),
            issued_at: client.config().clock().now(),
        })
    }
}

#[tokio::test]
async fn custom_auth_method_is_managed() {
    let server = MockServer::start().await;
    ok_with_bearer(&server, "custom-tok").await;
    let c = client_with(&server, |b| b.auth(Custom));
    c.ping().await.unwrap();
    assert!(!c.auth().method().unwrap().is_static());
    let t = AccessToken::new_static(Secret::new("x"), std::time::Instant::now());
    assert_eq!(t.expires_at(), None);
    let _ = SystemTime::now();
    // the response of the identities route is ignored apart from its status
    let _ = ResponseTemplate::new(200);
}
