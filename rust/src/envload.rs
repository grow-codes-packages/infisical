//! Environment injection: `load_env` (like `infisical run`) and `export_dotenv`.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::client::InfisicalClient;
use crate::core::Result;
use crate::secrets::EnvSink;
use crate::secrets_api::ListSecretsOptions;

/// Options of [`InfisicalClient::load_env`] and [`InfisicalClient::export_dotenv`]. Unset
/// project, environment and path fall back to the client configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Secret path.
    pub secret_path: Option<String>,
    /// Include every sub-folder (shallower paths win on duplicate keys).
    pub recursive: bool,
    /// Include secrets of secret imports (default `true`; direct secrets win).
    pub include_imports: Option<bool>,
    /// Expand references (default `true`).
    pub expand_references: Option<bool>,
    /// Replace variables that are already set (`load_env` only).
    pub override_existing: bool,
}

/// Renders `key → value` pairs as a dotenv document: one `KEY="value"` line per secret,
/// sorted by key, with `\`, `"`, newline and carriage return escaped.
pub fn format_dotenv<'a, I>(values: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let sorted: BTreeMap<&str, &str> = values.into_iter().collect();
    let mut out = String::new();
    for (k, v) in sorted {
        out.push_str(k);
        out.push_str("=\"");
        for c in v.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                other => out.push(other),
            }
        }
        out.push_str("\"\n");
    }
    out
}

impl InfisicalClient {
    /// The effective `key → value` map of a scope (direct secrets win over imports).
    async fn env_secrets(&self, o: &EnvOptions) -> Result<BTreeMap<String, Zeroizing<String>>> {
        let list = self
            .list_secrets(Some(&ListSecretsOptions {
                project_id: o.project_id.clone(),
                environment: o.environment.clone(),
                secret_path: o.secret_path.clone(),
                recursive: o.recursive,
                include_imports: Some(o.include_imports.unwrap_or(true)),
                expand_references: Some(o.expand_references.unwrap_or(true)),
                ..ListSecretsOptions::default()
            }))
            .await?;
        Ok(list
            .merged()
            .into_iter()
            .map(|(k, e)| (k, Zeroizing::new(e.value.expose_secret().to_owned())))
            .collect())
    }

    /// Sets one process environment variable per secret of a path (like `infisical run`):
    /// the variable name is the secret key unchanged. Existing variables are kept unless
    /// `override_existing` is set. Returns the names of the variables it set, sorted (never
    /// values).
    pub async fn load_env(&self, opts: Option<&EnvOptions>) -> Result<Vec<String>> {
        self.load_env_into(opts, &mut crate::secrets::ProcessEnv)
            .await
    }

    /// Like [`load_env`](Self::load_env) but writes into any [`EnvSink`] (for example a
    /// `HashMap<String, String>`).
    pub async fn load_env_into(
        &self,
        opts: Option<&EnvOptions>,
        sink: &mut dyn EnvSink,
    ) -> Result<Vec<String>> {
        let o = opts.cloned().unwrap_or_default();
        let values = self.env_secrets(&o).await?;
        let mut set = Vec::with_capacity(values.len());
        for (k, v) in &values {
            if sink.get(k).is_some() && !o.override_existing {
                continue;
            }
            sink.set(k, v);
            set.push(k.clone());
        }
        Ok(set)
    }

    /// Renders the secrets of a path as a dotenv document (see [`format_dotenv`]). The
    /// result contains secret values: handle it like a secret.
    pub async fn export_dotenv(&self, opts: Option<&EnvOptions>) -> Result<String> {
        let o = opts.cloned().unwrap_or_default();
        let values = self.env_secrets(&o).await?;
        Ok(format_dotenv(
            values.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        ))
    }
}
