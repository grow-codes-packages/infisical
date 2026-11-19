// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! # grow-infisical
//!
//! Rust SDK for [Infisical](https://grow-codes-packages.github.io/infisical/) by Grow Codes:
//! one async client (tokio) for Universal / token / Kubernetes / AWS IAM auth with automatic
//! token refresh, secrets (v4 with a v3 fallback detected at run time, batch operations,
//! versions, reference expansion), folders, projects and environments, tags, secret imports,
//! environment injection and the Grow [`SecretsProvider`](secrets::SecretsProvider).
//!
//! ```no_run
//! # async fn demo() -> grow_infisical::Result<()> {
//! use grow_infisical::secrets::SecretsProvider;
//! use grow_infisical::{InfisicalClient, InfisicalConfig, UpdateSecretOptions};
//!
//! // explicit > GROW_INFISICAL_* > INFISICAL_* > defaults
//! let client = InfisicalClient::new(InfisicalConfig::from_env()?)?;
//! println!("healthy: {}", client.health().await?.healthy);
//!
//! // secrets in the configured project / environment / path
//! client.create_secret("DB_PASSWORD", "s3cr3t", None).await?;
//! let secret = client.get_secret("DB_PASSWORD", None).await?;
//! assert_eq!(secret.value.reveal(), "s3cr3t");
//! let update = UpdateSecretOptions { value: Some("rotated".into()), ..Default::default() };
//! client.update_secret("DB_PASSWORD", Some(&update)).await?;
//!
//! // the Grow SecretsProvider (folders are created on demand)
//! let secrets = client.secrets();
//! secrets.set("app/API_KEY", "abc123".into(), None).await?;
//! assert_eq!(secrets.get_string("app/API_KEY", None).await?.as_deref(), Some("abc123"));
//!
//! client.close().await;
//! # Ok(())
//! # }
//! ```
//!
//! Features: `blocking` (a blocking client), `testing` (in-memory fakes and the conformance
//! runner).
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod core;

mod api;
mod auth;
mod client;
mod config;
mod envload;
mod models;
mod provider;
mod resources;
mod secrets_api;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

pub mod secrets;

pub use crate::core::{Error, ErrorCode, HealthStatus, Result, RetryPolicy, Secret};

pub use crate::config::{ApiVersion, DEFAULT_SECRET_PATH, DEFAULT_URL};

pub use crate::client::InfisicalClient;

pub use crate::config::InfisicalConfig;

pub use crate::config::InfisicalConfigBuilder;

pub use crate::api::normalize_path;
pub use crate::auth::{
    sign_v4, AccessToken, Auth, AuthMethod, AwsIamAuth, AwsLoginRequest, KubernetesAuth,
    SigV4Request, TokenAuth, UniversalAuth, DEFAULT_KUBERNETES_TOKEN_PATH,
};
pub use crate::envload::{format_dotenv, EnvOptions};
pub use crate::models::{
    Actor, BatchUpdateMode, Environment, Folder, ImportedSecrets, Project, ProjectPage,
    SecretEntry, SecretImport, SecretList, SecretType, SecretVersion, Tag,
};
pub use crate::provider::{ProjectSecretsProvider, SecretsProviderOptions};
pub use crate::resources::{
    CreateEnvironmentOptions, CreateFolderOptions, CreateSecretImportOptions, DeleteFolderOptions,
    ListFoldersOptions, ListProjectsOptions, SecretImportOptions, UpdateFolderOptions,
    DEFAULT_TAG_COLOR,
};
pub use crate::secrets_api::{
    BatchScope, CreateSecretOptions, DeleteSecretOptions, DeleteSecretsOptions, GetSecretOptions,
    ListSecretVersionsOptions, ListSecretsOptions, SecretInput, SecretUpdate, UpdateSecretOptions,
    UpdateSecretsOptions,
};

/// Service-prefixed alias of [`Error`].
pub type InfisicalError = Error;
