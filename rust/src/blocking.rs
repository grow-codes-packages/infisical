// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! Blocking wrapper (feature `blocking`). Each client owns a current-thread tokio runtime.
//!
//! Do not use it from inside an async runtime (calls would panic); use the async client there.
//!
//! The core calls (`health`, `ping`, `server_version`, `close`) have blocking methods. Every
//! service function is reached through [`InfisicalClient::block_on`] with the async API, so
//! the blocking client always offers exactly the async surface:
//!
//! ```no_run
//! # fn demo() -> grow_infisical::Result<()> {
//! use grow_infisical::blocking::InfisicalClient;
//! use grow_infisical::secrets::SecretsProvider;
//!
//! let client = InfisicalClient::from_env()?;
//! let inf = client.async_client();
//! let secret = client.block_on(inf.get_secret("DB_PASSWORD", None))?;
//! let value = client.block_on(inf.secrets().get_string("app/API_KEY", None))?;
//! # let _ = (secret, value);
//! client.close();
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::time::Duration;

use crate::core::{Error, HealthStatus, Result};
use crate::{InfisicalClient as AsyncClient, InfisicalConfig};

/// Blocking client for Infisical with the same methods as the async client.
#[derive(Debug)]
pub struct InfisicalClient {
    inner: AsyncClient,
    runtime: tokio::runtime::Runtime,
}

impl InfisicalClient {
    /// Creates a client from a configuration.
    pub fn new(config: InfisicalConfig) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::config("cannot start the tokio runtime").with_source(e))?;
        let inner = {
            let _guard = runtime.enter();
            AsyncClient::new(config)?
        };
        Ok(InfisicalClient { inner, runtime })
    }

    /// Creates a client from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::new(InfisicalConfig::from_env()?)
    }

    /// The wrapped async client.
    pub fn async_client(&self) -> &AsyncClient {
        &self.inner
    }

    /// Runs a future of the async API to completion on this client's runtime.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    /// See [`AsyncClient::health`].
    pub fn health(&self) -> Result<HealthStatus> {
        self.block_on(self.inner.health())
    }

    /// See [`AsyncClient::ping`].
    pub fn ping(&self) -> Result<Duration> {
        self.block_on(self.inner.ping())
    }

    /// See [`AsyncClient::server_version`].
    pub fn server_version(&self) -> Result<String> {
        self.block_on(self.inner.server_version())
    }

    /// See [`AsyncClient::close`]. Idempotent.
    pub fn close(&self) {
        self.block_on(self.inner.close());
    }
}

impl Drop for InfisicalClient {
    fn drop(&mut self) {
        self.inner.transport().close();
    }
}
