//! Service-owned: `load_config()` through the Infisical connector (GRO-1410 regression).

mod support;

use std::collections::HashMap;

use grow_infisical as sdk;
use sdk::secrets::{load_config, LoadOptions};
use serde_json::json;
use support::*;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer};

fn secret(key: &str, value: &str) -> serde_json::Value {
    json!({
        "id": format!("id-{key}"), "secretKey": key, "secretValue": value,
        "secretPath": "/services/orders", "version": 1, "type": "shared", "environment": ENV,
        "secretComment": "", "createdAt": "2026-11-18T20:28:13.931Z",
        "updatedAt": "2026-11-18T20:28:13.931Z", "tags": []
    })
}

#[tokio::test]
async fn load_config_reads_through_the_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/secrets"))
        .and(query_param("secretPath", "/services/orders"))
        .and(query_param("projectId", PROJECT))
        .and(query_param("environment", ENV))
        .respond_with(json(
            200,
            json!({
                "secrets": [secret("DATABASE_URL", "postgres://db"), secret("LOG_LEVEL", "debug")],
                "imports": []
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;
    // The connector reads the package variables from the map load_config was given (not the
    // process environment) and GROW_SECRETS_ADDR wins over GROW_INFISICAL_URL.
    let env: HashMap<String, String> = [
        ("GROW_SECRETS_PROVIDER", "infisical"),
        ("GROW_SECRETS_ADDR", server.uri().as_str()),
        ("GROW_SECRETS_PATH", "services/orders"),
        ("GROW_INFISICAL_URL", "http://127.0.0.1:1"),
        ("GROW_INFISICAL_TOKEN", TOKEN),
        ("GROW_INFISICAL_PROJECT_ID", PROJECT),
        ("GROW_INFISICAL_ENVIRONMENT", ENV),
        ("GROW_INFISICAL_MAX_RETRIES", "0"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let values = load_config(LoadOptions {
        env: Some(env),
        required: vec!["DATABASE_URL".to_string()],
        into_env: false,
        ..LoadOptions::default()
    })
    .await
    .expect("load_config");
    assert_eq!(values.len(), 2);
    assert_eq!(values["DATABASE_URL"], "postgres://db");
    assert_eq!(values["LOG_LEVEL"], "debug");
}
