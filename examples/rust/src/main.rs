// Created by sdk-kit 0.1.0; owned by this repository.
//! The Infisical Rust SDK against a real server: configuration from the environment
//! (Universal Auth), health, a secret round trip, folders, the `SecretsProvider` and dotenv
//! export.
//!
//! ```sh
//! GROW_INFISICAL_URL=http://127.0.0.1:8080 \
//! INFISICAL_CLIENT_ID=... INFISICAL_CLIENT_SECRET=... \
//! INFISICAL_PROJECT_ID=... INFISICAL_ENVIRONMENT=dev cargo run
//! ```

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use grow_infisical as sdk;
use sdk::core::{ErrorInfo, Hooks};
use sdk::secrets::SecretsProvider;
use sdk::{
    CreateSecretOptions, DeleteFolderOptions, EnvOptions, ErrorCode, GetSecretOptions,
    UpdateSecretOptions,
};

use sdk::InfisicalClient as Client;
use sdk::InfisicalConfig as Config;

/// Prints every retry.
struct RetryLogger;

impl Hooks for RetryLogger {
    fn on_error(&self, info: &ErrorInfo) {
        if info.will_retry {
            eprintln!(
                "retrying {} {} (attempt {})",
                info.method, info.url, info.attempt
            );
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error [{}]: {err}", err.code());
        std::process::exit(1);
    }
}

async fn run() -> sdk::Result<()> {
    // explicit > GROW_INFISICAL_* > INFISICAL_* > defaults; invalid values name the
    // variable, never its value.
    let config = Config::builder()
        .hooks(Arc::new(RetryLogger))
        .build_from_env()?;
    println!("config: {config:?}"); // credentials print as [REDACTED]

    let client = Client::new(config)?;
    let health = client.health().await?; // never fails for an unreachable service
    println!("health: {} ({})", health.healthy, health.status);

    match client.ping().await {
        Ok(latency) => println!("ping: {} ms", latency.as_millis()),
        Err(e) if e.code() == ErrorCode::Authentication => {
            println!("ping: check INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET ({e})");
            return Err(e);
        }
        Err(e) => return Err(e),
    }

    // A secret round trip in a folder of its own.
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let folder = format!("example-{stamp}");
    let created = client.create_folder(&folder, None).await?;
    let path = format!("/{folder}");
    client
        .create_secret(
            "DATABASE_URL",
            "postgres://db:5432/app",
            Some(&CreateSecretOptions {
                secret_path: Some(path.clone()),
                comment: Some("created by the Rust example".into()),
                ..Default::default()
            }),
        )
        .await?;
    client
        .update_secret(
            "DATABASE_URL",
            Some(&UpdateSecretOptions {
                secret_path: Some(path.clone()),
                value: Some("postgres://db:5432/app2".into()),
                ..Default::default()
            }),
        )
        .await?;
    let secret = client
        .get_secret(
            "DATABASE_URL",
            Some(&GetSecretOptions {
                secret_path: Some(path.clone()),
                ..Default::default()
            }),
        )
        .await?;
    // the value prints as [REDACTED]; use `secret.value.reveal()` to read it
    println!(
        "secret {} version {}: {}",
        secret.key, secret.version, secret.value
    );

    // The SecretsProvider: names are "<folder>/<KEY>", set creates folders.
    let secrets = client.secrets();
    secrets
        .set(&format!("{folder}/feature/ENABLED"), "yes".into(), None)
        .await?;
    let enabled = secrets
        .get_bool(&format!("{folder}/feature/ENABLED"), None)
        .await?;
    println!("feature enabled: {enabled:?}");

    let dotenv = client
        .export_dotenv(Some(&EnvOptions {
            secret_path: Some(path),
            ..Default::default()
        }))
        .await?;
    println!("dotenv export: {} bytes", dotenv.len());

    // Clean up.
    client
        .delete_folder(
            &created.id,
            Some(&DeleteFolderOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await?;
    println!(
        "done; secrets API version: {}",
        client.api_version("secrets")
    );
    client.close().await;
    Ok(())
}
