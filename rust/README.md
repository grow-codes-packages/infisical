# grow-infisical (Rust)

Rust SDK for Infisical by [Grow Codes](https://grow.codes). Async on tokio, with an optional
blocking client.

```toml
[dependencies]
grow-infisical = "0.1.0"
# blocking client:   features = ["blocking"]
# test fakes/runner: features = ["testing"] (dev-dependency)
```

```rust,no_run
use grow_infisical::secrets::SecretsProvider;
use grow_infisical::{InfisicalClient, InfisicalConfig};

#[tokio::main]
async fn main() -> grow_infisical::Result<()> {
    // explicit > GROW_INFISICAL_* > INFISICAL_* > defaults
    // (INFISICAL_CLIENT_ID/SECRET → Universal Auth with automatic token refresh)
    let client = InfisicalClient::new(InfisicalConfig::from_env()?)?;
    println!("{:?}", client.health().await?);
    client.create_secret("DB_PASSWORD", "s3cr3t", None).await?;
    let secret = client.get_secret("DB_PASSWORD", None).await?;
    println!("{} v{}", secret.key, secret.version); // the value prints as [REDACTED]
    let value = client.secrets().get_string("DB_PASSWORD", None).await?;
    assert_eq!(value.as_deref(), Some("s3cr3t"));
    client.close().await;
    Ok(())
}
```

- Auth: `UniversalAuth` (login/renew/revoke, refresh at 80 % of the TTL, one re-login on
  401), `TokenAuth` (identity token, user JWT, `st.` service token), `KubernetesAuth`,
  `AwsIamAuth` (SigV4-signed STS request).
- Secrets v4 (v3 `raw` fallback detected at run time), batch create/update/delete, versions,
  reference expansion, personal overrides; folders, projects, environments, tags, secret
  imports; `load_env` / `export_dotenv`; the Grow `SecretsProvider` (`client.secrets()`).
- Errors: one `Error` enum with `code()`, `http_status()`, `request_id()`, `is_retryable()`,
  `retry_after()`; messages never contain credentials.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation (drop the future or pass a `CancellationToken`), request hooks, `tracing` debug
  events.
- MSRV 1.88. Licence Apache-2.0. Documentation: https://grow-codes-packages.github.io/infisical/

Development: `make deps build lint test coverage license pack docs` (see `Makefile`).
