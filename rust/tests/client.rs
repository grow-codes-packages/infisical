// Taken over from sdk-kit 0.1.0 (header removed): the skeleton tests targeted the demo
// service; these test the Infisical client surface against recorded Infisical responses.
//! `InfisicalClient`: config, health, ping, server version, close, error mapping, hooks,
//! API version detection.

mod common;
mod support;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{closed_port, fast_retry};
use grow_infisical as sdk;
use sdk::core::{EnvReader, ErrorCode, ErrorInfo, Hooks};
use sdk::{ApiVersion, InfisicalClient as Client, InfisicalConfig as Config, RetryPolicy, Secret};
use serde_json::json;
use support::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn env(pairs: &[(&str, &str)]) -> EnvReader {
    EnvReader::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    )
}

#[test]
fn config_from_env_precedence_and_aliases() {
    let c = Config::builder()
        .build_with_env(&env(&[
            ("INFISICAL_API_URL", "https://vault.example/api"),
            ("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "cid"),
            ("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "csecret-1"),
            ("INFISICAL_PROJECT_ID", "p-vendor"),
            ("GROW_INFISICAL_PROJECT_ID", "p-grow"),
            ("INFISICAL_ENVIRONMENT", "dev"),
            ("GROW_INFISICAL_SECRET_PATH", "app//db/"),
            ("GROW_INFISICAL_API_VERSION", "V3"),
            ("GROW_INFISICAL_REVOKE_ON_CLOSE", "true"),
        ]))
        .unwrap();
    assert_eq!(c.url().as_str(), "https://vault.example/");
    assert_eq!(c.client_id(), Some("cid"));
    assert_eq!(c.client_secret().unwrap().reveal(), "csecret-1");
    assert_eq!(c.project_id(), Some("p-grow"));
    assert_eq!(c.environment(), Some("dev"));
    assert_eq!(c.secret_path(), "/app/db");
    assert_eq!(c.api_version(), ApiVersion::V3);
    assert!(c.revoke_on_close());
    assert!(c.token().is_none());
    let dbg = format!("{c:?}");
    assert!(!dbg.contains("csecret-1"), "{dbg}");
    assert!(dbg.contains("UniversalAuth"));
    // explicit wins; the CLI values win over aliases
    let c = Config::builder()
        .project_id("explicit")
        .environment(" staging ")
        .build_with_env(&env(&[
            ("INFISICAL_CLIENT_ID", "a"),
            ("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "b"),
            ("INFISICAL_CLIENT_SECRET", "s-1234"),
            ("INFISICAL_TOKEN", "tok-1234"),
            ("GROW_INFISICAL_URL", "http://h:1/base/api/"),
        ]))
        .unwrap();
    assert_eq!(c.project_id(), Some("explicit"));
    assert_eq!(c.environment(), Some("staging"));
    assert_eq!(c.client_id(), Some("a"));
    assert_eq!(c.url().as_str(), "http://h:1/base");
    assert_eq!(c.secret_path(), "/");
    assert!(format!("{:?}", c.auth_method().unwrap()).contains("TokenAuth"));
    assert_eq!(c.api_version(), ApiVersion::Auto);
    assert!(!c.revoke_on_close());
    let root = Config::builder().url("http://h:1/api").build().unwrap();
    assert_eq!(root.url().as_str(), "http://h:1/");
    // errors
    for (k, v) in [
        ("GROW_INFISICAL_API_VERSION", "v9"),
        ("GROW_INFISICAL_REVOKE_ON_CLOSE", "maybe"),
    ] {
        let err = Config::builder()
            .build_with_env(&env(&[(k, v)]))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Config, "{k}");
        assert!(!err.message().contains(v) || k.ends_with("VERSION"));
    }
    assert_eq!(
        Config::builder().client_id("x").build().unwrap_err().code(),
        ErrorCode::Config
    );
    assert_eq!(
        Config::builder()
            .client_secret("x")
            .build()
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
    assert!(Config::builder().client_id("x").token("t").build().is_ok());
    assert!(Config::builder()
        .client_id("x")
        .auth(sdk::TokenAuth::new("t"))
        .build()
        .is_ok());
    assert_eq!(
        Config::builder()
            .environment("a b")
            .build()
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
    assert_eq!("".parse::<ApiVersion>().unwrap(), ApiVersion::Auto);
    assert_eq!("auto".parse::<ApiVersion>().unwrap(), ApiVersion::Auto);
    assert_eq!("v4".parse::<ApiVersion>().unwrap(), ApiVersion::V4);
    assert_eq!(ApiVersion::V4.as_str(), "v4");
    assert_eq!(ApiVersion::Auto.as_str(), "");
    assert!(Config::builder().build().unwrap().auth_method().is_none());
    let b = Config::builder()
        .client_id("id")
        .client_secret("builder-secret-1")
        .auth_arc(Arc::new(sdk::TokenAuth::new("t")))
        .secret_path("/x")
        .api_version(ApiVersion::V4)
        .revoke_on_close(true)
        .connect_timeout(Duration::from_secs(1))
        .request_timeout(Duration::from_secs(1))
        .total_timeout(Duration::from_secs(2))
        .max_retries(1)
        .tls(Default::default())
        .insecure_skip_verify(false)
        .proxy("http://proxy:3128")
        .header("x-a", "b")
        .user_agent_suffix("test")
        .clock(Arc::new(sdk::core::clock::SystemClock))
        .common(|c| c);
    assert!(!format!("{b:?}").contains("builder-secret-1"));
    let c = b.build().unwrap();
    assert_eq!(c.api_version(), ApiVersion::V4);
    assert!(c.common().proxy().is_some());
    let _ = c.clock().now();
}

#[tokio::test]
async fn health_ping_version_close() {
    let server = MockServer::start().await;
    on(&server, "GET", "/api/status", "health.ok").await;
    Mock::given(path("/api/v1/identities/details"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(reply("ping.identity"))
        .mount(&server)
        .await;
    let c = client(&server);
    let h = c.health().await.unwrap();
    assert!(h.healthy);
    assert_eq!(h.status, "ok");
    assert_eq!(h.details["redisConfigured"], "true");
    assert!(c.ping().await.unwrap() > Duration::ZERO);
    let err = c.server_version().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert_eq!(c.api_version("secrets"), "");
    assert_eq!(c.api_version("folders"), "v2");
    assert_eq!(c.api_version("secret-imports"), "v2");
    assert_eq!(c.api_version("tags"), "v1");
    assert_eq!(c.api_version("nope"), "");
    assert!(c
        .transport()
        .user_agent()
        .starts_with("grow-codes-infisical/"));
    assert_eq!(c.config().project_id(), Some(PROJECT));
    let ran = Arc::new(AtomicU32::new(0));
    let r = ran.clone();
    c.on_close(move || {
        Box::pin(async move {
            r.fetch_add(1, Ordering::SeqCst);
        })
    });
    assert!(!c.is_closed());
    c.close().await;
    c.close().await;
    assert!(c.is_closed());
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert_eq!(c.ping().await.unwrap_err().code(), ErrorCode::Cancelled);
    assert_eq!(c.health().await.unwrap_err().code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn health_unhealthy_and_unreachable() {
    let server = MockServer::start().await;
    on_reply(&server, "GET", "/api/status", ResponseTemplate::new(503)).await;
    let h = client(&server).health().await.unwrap();
    assert!(!h.healthy);
    assert_eq!(h.details["httpStatus"], "503");
    let server2 = MockServer::start().await;
    on_reply(&server2, "GET", "/api/status", ResponseTemplate::new(418)).await;
    let h = client(&server2).health().await.unwrap();
    assert_eq!(h.status, "unhealthy");
    let c = Client::new(
        Config::builder()
            .url(format!("http://127.0.0.1:{}", closed_port()))
            .retry(RetryPolicy::none())
            .build()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(c.health().await.unwrap().status, "unreachable");
}

#[tokio::test]
async fn ping_routes_by_token_kind() {
    let server = MockServer::start().await;
    on(&server, "GET", "/api/v2/service-token", "ping.serviceToken").await;
    on(&server, "GET", "/api/v2/users/me", "ping.user").await;
    let st = client_with(&server, |b| b.token("st.abc.def"));
    st.ping().await.unwrap();
    // a user JWT: payload {"authTokenType":"accessToken"}
    let user = client_with(&server, |b| {
        b.token("eyJhbGciOiJIUzI1NiJ9.eyJhdXRoVG9rZW5UeXBlIjoiYWNjZXNzVG9rZW4ifQ.sig")
    });
    user.ping().await.unwrap();
    assert_eq!(requests(&server, "/api/v2/users/me").await.len(), 1);
    // no credentials: identity route without a bearer
    let none = Client::new(Config::builder().url(server.uri()).build().unwrap()).unwrap();
    assert_eq!(none.ping().await.unwrap_err().code(), ErrorCode::NotFound);
}

#[tokio::test]
async fn error_mapping_from_bodies() {
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v1/identities/details",
        "auth.malformedToken",
    )
    .await;
    on(
        &server,
        "GET",
        "/api/v4/secrets",
        "listSecrets.403noMembership",
    )
    .await;
    on(
        &server,
        "GET",
        "/api/v4/secrets/SDK_SEED",
        "auth.revokedToken",
    )
    .await;
    on(
        &server,
        "POST",
        "/api/v4/secrets/bad:name",
        "createSecret.invalidName422",
    )
    .await;
    on(
        &server,
        "POST",
        "/api/v4/secrets/DUP",
        "createSecret.duplicate400",
    )
    .await;
    on(&server, "GET", "/api/v4/secrets/MISSING", "getSecret.404").await;
    let c = client(&server);
    let e = c.ping().await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Authentication);
    assert_eq!(e.http_status(), Some(403));
    assert!(e.request_id().unwrap().starts_with("req-"));
    assert!(!e.is_retryable());
    let e = c.list_secrets(None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::PermissionDenied);
    assert!(e
        .message()
        .starts_with("secrets.list /: permission denied: You are not a member"));
    let e = c.get_secret("SDK_SEED", None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Authentication);
    let e = c.create_secret("bad:name", "x", None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Validation);
    assert!(e
        .message()
        .contains("secretName: Secret name cannot contain colon"));
    let e = c.create_secret("DUP", "x", None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Conflict);
    let e = c.get_secret("MISSING", None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
    assert!(!e.message().contains(TOKEN));
}

#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl Hooks for Recorder {
    fn on_error(&self, info: &ErrorInfo) {
        self.0.lock().unwrap().push(format!(
            "{} {} {}",
            info.method,
            info.url,
            info.error.code()
        ));
    }
}

#[tokio::test]
async fn hooks_see_mapped_errors_and_secrets_are_redacted() {
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/api/v4/secrets/LEAK",
        json(
            404,
            json!({"reqId": "req-1", "message": format!("token {TOKEN} not found"), "error": "NotFound"}),
        ),
    )
    .await;
    let rec = Arc::new(Recorder::default());
    let c = client_with(&server, |b| b.hooks(rec.clone()));
    let e = c.get_secret("LEAK", None).await.unwrap_err();
    assert!(!e.message().contains(TOKEN), "{}", e.message());
    assert!(e.message().contains("[REDACTED]"));
    let seen = rec.0.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("GET http://"));
    assert!(seen[0].contains("/api/v4/secrets/LEAK?projectId=proj-1"));
    assert!(seen[0].ends_with("NOT_FOUND"));
}

#[tokio::test]
async fn transport_errors_rate_limit_and_retries() {
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v4/secrets",
        "listSecrets.429-synthetic",
    )
    .await;
    let c = client(&server);
    let e = c.list_secrets(None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::RateLimited);
    assert_eq!(e.retry_after(), Some(Duration::from_secs(7)));
    // 503 then 200: retried by the transport
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/secrets"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on(&server, "GET", "/api/v4/secrets", "listSecrets.ok").await;
    let c = client_with(&server, |b| b.retry(fast_retry(0.0)));
    assert!(!c.list_secrets(None).await.unwrap().secrets.is_empty());
    // invalid JSON in a success body
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/api/v4/secrets",
        ResponseTemplate::new(200).set_body_string("not json"),
    )
    .await;
    let e = client(&server).list_secrets(None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unavailable);
    // empty success body parses as an empty list
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/api/v4/secrets",
        ResponseTemplate::new(200),
    )
    .await;
    assert!(client(&server)
        .list_secrets(None)
        .await
        .unwrap()
        .secrets
        .is_empty());
}

#[tokio::test]
async fn api_version_detection_and_fallback() {
    // v4 answers: pinned to v4
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v4/secrets/SDK_49LJ3988_ONE",
        "getSecret.ok",
    )
    .await;
    let c = client(&server);
    c.get_secret("SDK_49LJ3988_ONE", None).await.unwrap();
    assert_eq!(c.api_version("secrets"), "v4");
    // v4 route missing → v3 raw (and the decision is cached)
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v4/secrets/SDK_49LJ3988_ONE",
        "routeMissing.404",
    )
    .await;
    on(
        &server,
        "GET",
        "/api/v3/secrets/raw/SDK_49LJ3988_ONE",
        "getSecret.v3raw-ok",
    )
    .await;
    let c = client(&server);
    let s = c.get_secret("SDK_49LJ3988_ONE", None).await.unwrap();
    assert!(!s.value.is_empty());
    assert_eq!(c.api_version("secrets"), "v3");
    c.get_secret("SDK_49LJ3988_ONE", None).await.unwrap();
    assert_eq!(
        requests(&server, "/api/v4/secrets/SDK_49LJ3988_ONE")
            .await
            .len(),
        1
    );
    let v3 = requests(&server, "/api/v3/secrets/raw/SDK_49LJ3988_ONE").await;
    assert_eq!(query(&v3[0], "workspaceId").as_deref(), Some(PROJECT));
    assert_eq!(query(&v3[0], "include_imports").as_deref(), Some("true"));
    assert_eq!(
        query(&v3[0], "expandSecretReferences").as_deref(),
        Some("true")
    );
    assert!(query(&v3[0], "viewSecretValue").is_none());
    // a domain error pins v4; a network error leaves it undetected
    let server = MockServer::start().await;
    on(&server, "GET", "/api/v4/secrets/MISSING", "getSecret.404").await;
    let c = client(&server);
    assert!(c.get_secret("MISSING", None).await.is_err());
    assert_eq!(c.api_version("secrets"), "v4");
    let dead = Client::new(
        Config::builder()
            .url(format!("http://127.0.0.1:{}", closed_port()))
            .token(TOKEN)
            .project_id(PROJECT)
            .environment(ENV)
            .retry(RetryPolicy::none())
            .build()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        dead.get_secret("X", None).await.unwrap_err().code(),
        ErrorCode::Unavailable
    );
    assert_eq!(dead.api_version("secrets"), "");
    // forced v4 never falls back
    let server = MockServer::start().await;
    on(&server, "GET", "/api/v4/secrets/X", "routeMissing.404").await;
    let c = client_with(&server, |b| b.api_version(ApiVersion::V4));
    assert_eq!(
        c.get_secret("X", None).await.unwrap_err().code(),
        ErrorCode::Unsupported
    );
    assert!(requests(&server, "/api/v3/secrets/raw/X").await.is_empty());
}

#[tokio::test]
async fn scope_requires_project_and_environment() {
    let server = MockServer::start().await;
    let c = Client::new(
        Config::builder()
            .url(server.uri())
            .token(Secret::new(TOKEN))
            .build()
            .unwrap(),
    )
    .unwrap();
    let e = c.list_secrets(None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Config);
    assert!(e.message().contains("projectId is required"));
    let c = Client::new(
        Config::builder()
            .url(server.uri())
            .token(TOKEN)
            .project_id("p")
            .build()
            .unwrap(),
    )
    .unwrap();
    let e = c.list_secrets(None).await.unwrap_err();
    assert!(e.message().contains("environment is required"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn from_env_entry_points() {
    let _ = Client::from_env();
    let _ = Config::from_env();
    let bad = Config::builder()
        .ca_cert_path("/nonexistent")
        .build()
        .unwrap();
    assert_eq!(Client::new(bad).unwrap_err().code(), ErrorCode::Config);
}
