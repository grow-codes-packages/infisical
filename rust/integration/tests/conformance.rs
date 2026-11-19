// Created by sdk-kit 0.1.0; owned by this repository.
//! Conformance scenarios for `core` and `secrets` against the real service (Docker), plus
//! the core client round trips. The per-function integration tests live in `infisical.rs`.

use std::sync::Arc;

use grow_infisical as sdk;
use grow_infisical_integration as support;
use sdk::testing::{ConformanceRunner, CoreHandler, SecretsHandler};
use sdk::ErrorCode;
use support::{conformance_dir, load_bootstrap_env};

use sdk::blocking::InfisicalClient as BlockingClient;

use sdk::InfisicalClient as Client;
use sdk::InfisicalConfig as Config;

fn client() -> Client {
    load_bootstrap_env();
    Client::new(Config::from_env().expect("config from env")).expect("client")
}

#[tokio::test]
async fn client_round_trip() {
    let c = client();
    let health = c.health().await.expect("health");
    assert!(health.healthy, "service not healthy: {health:?}");
    c.ping().await.expect("authenticated ping");
    let e = c.server_version().await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unsupported, "{e}");
    c.close().await;
    c.close().await;
}

#[test]
fn blocking_round_trip() {
    load_bootstrap_env();
    let c = BlockingClient::from_env().expect("client");
    assert!(c.health().expect("health").healthy);
    c.ping().expect("ping");
    assert_eq!(
        c.server_version().unwrap_err().code(),
        ErrorCode::Unsupported
    );
    let seed = std::env::var("INFISICAL_SEED_SECRET_NAME").expect("seed name");
    let s = c
        .block_on(c.async_client().get_secret(&seed, None))
        .expect("blocking get_secret");
    assert_eq!(
        s.value.reveal(),
        std::env::var("INFISICAL_SEED_SECRET_VALUE").unwrap()
    );
    c.close();
}

#[tokio::test]
async fn conformance() {
    load_bootstrap_env();
    // "version" is left out on purpose: Infisical exposes no server version
    // (server_version is UNSUPPORTED, docs/compatibility.md).
    let provider: Arc<dyn sdk::secrets::SecretsProvider> = Arc::new(client().secrets());
    let report = ConformanceRunner::new(conformance_dir())
        .capabilities(["write", "delete", "versions"])
        .handler(CoreHandler::new(Client::from_env))
        .handler(SecretsHandler::new(move || provider.clone()))
        .run()
        .await
        .expect("scenarios load");
    println!("{report}");
    report.assert_success();
}
