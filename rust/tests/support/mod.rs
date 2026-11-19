//! Helpers for the Infisical service tests: recorded fixtures and a client on a mock server.
#![allow(dead_code)]

use std::path::PathBuf;

use grow_infisical::{InfisicalClient, InfisicalConfig, InfisicalConfigBuilder, RetryPolicy};
use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Static token used by [`client`] (an opaque machine identity token).
pub const TOKEN: &str = "test-identity-token-1234";
/// Project id used by [`client`].
pub const PROJECT: &str = "proj-1";
/// Environment used by [`client`].
pub const ENV: &str = "dev";

/// A recorded fixture (`tests/fixtures/infisical/<name>.json`): `{request, status, body}`.
pub fn fixture(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/infisical")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("fixture {name}"));
    serde_json::from_str(&text).expect("fixture json")
}

/// The fixture's recorded response body.
pub fn body(name: &str) -> Value {
    fixture(name)["body"].clone()
}

/// The fixture's response as a mock reply.
pub fn reply(name: &str) -> ResponseTemplate {
    let f = fixture(name);
    let status = f["status"].as_u64().expect("status") as u16;
    match &f["body"] {
        Value::Null => ResponseTemplate::new(status),
        Value::String(s) => ResponseTemplate::new(status).set_body_string(s.clone()),
        other => ResponseTemplate::new(status).set_body_json(other.clone()),
    }
}

/// A JSON reply.
pub fn json(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

/// Mounts `method path → fixture` (matched any number of times).
pub async fn on(server: &MockServer, verb: &str, p: &str, name: &str) {
    Mock::given(method(verb))
        .and(path(p))
        .respond_with(reply(name))
        .mount(server)
        .await;
}

/// Mounts `method path → fixture` for exactly one call (then falls through).
pub async fn once(server: &MockServer, verb: &str, p: &str, name: &str) {
    Mock::given(method(verb))
        .and(path(p))
        .respond_with(reply(name))
        .up_to_n_times(1)
        .mount(server)
        .await;
}

/// Mounts a raw reply.
pub async fn on_reply(server: &MockServer, verb: &str, p: &str, r: ResponseTemplate) {
    Mock::given(method(verb))
        .and(path(p))
        .respond_with(r)
        .mount(server)
        .await;
}

/// A config builder pointing at `server` with the test token, project, environment and no
/// retries.
pub fn builder(server: &MockServer) -> InfisicalConfigBuilder {
    InfisicalConfig::builder()
        .url(server.uri())
        .token(TOKEN)
        .project_id(PROJECT)
        .environment(ENV)
        .retry(RetryPolicy::none())
}

/// A client on `server` (see [`builder`]).
pub fn client(server: &MockServer) -> InfisicalClient {
    InfisicalClient::new(builder(server).build().expect("config")).expect("client")
}

/// A client on `server` with the given builder edits.
pub fn client_with(
    server: &MockServer,
    f: impl FnOnce(InfisicalConfigBuilder) -> InfisicalConfigBuilder,
) -> InfisicalClient {
    InfisicalClient::new(f(builder(server)).build().expect("config")).expect("client")
}

/// The JSON bodies of the requests the mock server received for `p`.
pub async fn sent(server: &MockServer, p: &str) -> Vec<Value> {
    requests(server, p)
        .await
        .iter()
        .filter(|r| !r.body.is_empty())
        .map(|r| serde_json::from_slice(&r.body).unwrap_or(Value::Null))
        .collect()
}

/// The requests the mock server received for `p`.
pub async fn requests(server: &MockServer, p: &str) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == p)
        .collect()
}

/// A query parameter of a request.
pub fn query(r: &wiremock::Request, name: &str) -> Option<String> {
    r.url
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}
