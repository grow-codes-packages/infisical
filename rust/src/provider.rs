//! `SecretsProvider` (SPEC §3) over one Infisical project and environment.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::api::{self, join_path, normalize_path, path_segments};
use crate::client::InfisicalClient;
use crate::core::{Error, ErrorCode, Result};
use crate::models::{SecretEntry, SecretType};
use crate::resources::CreateFolderOptions;
use crate::secrets::{
    watch, DeleteOptions, GetOptions, SecretData, SecretMap, SecretMetadata, SecretValue,
    SecretsProvider, SetOptions, WatchHandle, WatchOptions,
};
use crate::secrets_api::{
    CreateSecretOptions, DeleteSecretOptions, GetSecretOptions, ListSecretsOptions,
    UpdateSecretOptions,
};

/// Options of [`InfisicalClient::secrets_with`]. Unset fields fall back to the client
/// configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretsProviderOptions {
    /// Project id (default: configured).
    pub project_id: Option<String>,
    /// Environment slug (default: configured).
    pub environment: Option<String>,
    /// Folder names are relative to (default: the configured secret path).
    pub base_path: Option<String>,
    /// Expand references on reads (default `true`).
    pub expand_references: Option<bool>,
    /// Find keys through secret imports on `get` and `get_all` (default `true`).
    pub include_imports: Option<bool>,
}

/// The [`SecretsProvider`] over one Infisical project and environment.
///
/// Model: a name may contain `/`: the last segment is the secret key, the rest is the folder
/// below the base path (`app/db/PASSWORD` → path `<base>/app/db`, key `PASSWORD`).
/// `GetOptions::path` / `SetOptions::path` / `DeleteOptions::path` replace the base path.
/// `set` creates missing folders, updates an existing secret and returns the new version;
/// values are UTF-8 text (other bytes are a `VALIDATION` error) and Infisical trims
/// surrounding whitespace. Versions are the Infisical version numbers as strings. Delete is
/// always permanent and removes every version (`DeleteOptions::versions` / `permanent` are
/// `UNSUPPORTED`, as is `SetOptions::cas`). `SetOptions::tags` keys are tag slugs (created
/// when missing, with the value as the color when it starts with `#`);
/// `SecretMetadata::tags` maps slug → name (or slug).
#[derive(Debug, Clone)]
pub struct ProjectSecretsProvider {
    client: InfisicalClient,
    opts: SecretsProviderOptions,
    base: String,
}

fn metadata_of(name: &str, s: &SecretEntry) -> SecretMetadata {
    let mut md = SecretMetadata::new(name);
    md.path = Some(s.secret_path.clone());
    md.version = Some(s.version.to_string());
    md.created_at = s.created_at;
    md.updated_at = s.updated_at;
    md.versions = Some(s.version);
    for t in &s.tags {
        let v = if t.name.is_empty() { &t.slug } else { &t.name };
        md.tags.insert(t.slug.clone(), v.clone());
    }
    md.extra = BTreeMap::from([
        ("id".to_owned(), s.id.clone()),
        ("type".to_owned(), s.secret_type.as_str().to_owned()),
        ("environment".to_owned(), s.environment.clone()),
    ]);
    if !s.comment.is_empty() {
        md.extra.insert("comment".to_owned(), s.comment.clone());
    }
    md
}

fn check_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(Error::validation("secret name must not be empty"));
    }
    Ok(())
}

impl ProjectSecretsProvider {
    pub(crate) fn new(client: InfisicalClient, opts: SecretsProviderOptions) -> Self {
        let base = normalize_path(
            api::non_empty(opts.base_path.as_deref()).unwrap_or(client.config().secret_path()),
        );
        ProjectSecretsProvider { client, opts, base }
    }

    /// The options in use.
    pub fn options(&self) -> &SecretsProviderOptions {
        &self.opts
    }

    /// The base path names are relative to.
    pub fn base_path(&self) -> &str {
        &self.base
    }

    /// Polls `name` every `interval` and calls `on_change(new, old)` on a version change or
    /// deletion (see [`watch`]). The watch stops on [`WatchHandle::stop`] or when the client
    /// is closed.
    pub fn watch<F>(
        &self,
        name: impl Into<String>,
        interval: Duration,
        on_change: F,
        opts: WatchOptions,
    ) -> WatchHandle
    where
        F: Fn(Option<&SecretValue>, Option<&SecretValue>) + Send + Sync + 'static,
    {
        let handle = watch(Arc::new(self.clone()), name, interval, on_change, opts);
        let stop = handle.clone();
        let closed = self.client.background();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = closed.cancelled() => {
                        stop.stop();
                        return;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if stop.is_stopped() {
                            return;
                        }
                    }
                }
            }
        });
        handle
    }

    /// Splits `name` into its folder path and key.
    fn locate(&self, op: &str, name: &str, path: Option<&str>) -> Result<(String, String)> {
        let base = api::non_empty(path)
            .map(normalize_path)
            .unwrap_or_else(|| self.base.clone());
        let (dir, key) = match name.rfind('/') {
            Some(i) => (&name[..i], &name[i + 1..]),
            None => ("", name),
        };
        if key.trim().is_empty() {
            return Err(api::invalid(op, "secret name must end with a key"));
        }
        Ok((join_path(&[&base, dir]), key.to_owned()))
    }

    fn get_options(&self, path: String, opts: &GetOptions, view: bool) -> Result<GetSecretOptions> {
        let version = match opts.version.as_deref().filter(|v| !v.is_empty()) {
            None => None,
            Some(v) => match v.parse::<u64>() {
                Ok(n) if n > 0 => Some(n),
                _ => {
                    return Err(api::invalid(
                        "secrets.get",
                        "version must be a positive integer",
                    ))
                }
            },
        };
        Ok(GetSecretOptions {
            project_id: self.opts.project_id.clone(),
            environment: self.opts.environment.clone(),
            secret_path: Some(path),
            version,
            expand_references: Some(self.opts.expand_references.unwrap_or(true)),
            include_imports: Some(self.opts.include_imports.unwrap_or(true)),
            view_secret_value: Some(view),
            ..GetSecretOptions::default()
        })
    }

    async fn read(
        &self,
        op: &str,
        name: &str,
        opts: &GetOptions,
        view: bool,
    ) -> Result<Option<SecretEntry>> {
        let (path, key) = self.locate(op, name, opts.path.as_deref())?;
        let g = self.get_options(path, opts, view)?;
        match self.client.get_secret(&key, Some(&g)).await {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn list_folder(&self, rel: &str, key_prefix: &str) -> Result<Vec<SecretMetadata>> {
        let list = self
            .client
            .list_secrets(Some(&ListSecretsOptions {
                project_id: self.opts.project_id.clone(),
                environment: self.opts.environment.clone(),
                secret_path: Some(join_path(&[&self.base, rel])),
                expand_references: Some(false),
                include_imports: Some(false),
                view_secret_value: Some(false),
                ..ListSecretsOptions::default()
            }))
            .await?;
        let mut out: Vec<SecretMetadata> = list
            .secrets
            .iter()
            .filter(|s| s.key.starts_with(key_prefix) && s.secret_type != SecretType::Personal)
            .map(|s| {
                let name = if rel.is_empty() {
                    s.key.clone()
                } else {
                    format!("{rel}/{}", s.key)
                };
                metadata_of(&name, s)
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Creates every folder of `path` that does not exist yet.
    async fn ensure_folders(&self, path: &str) -> Result<()> {
        let mut parent = "/".to_owned();
        for seg in path_segments(path) {
            let res = self
                .client
                .create_folder(
                    &seg,
                    Some(&CreateFolderOptions {
                        project_id: self.opts.project_id.clone(),
                        environment: self.opts.environment.clone(),
                        path: Some(parent.clone()),
                        description: None,
                    }),
                )
                .await;
            match res {
                Ok(_) => {}
                Err(e) if e.code() == ErrorCode::Conflict => {}
                Err(e) => return Err(e),
            }
            parent = join_path(&[&parent, &seg]);
        }
        Ok(())
    }

    /// Resolves tag slugs to ids, creating missing tags.
    async fn ensure_tags(&self, tags: &BTreeMap<String, String>) -> Result<Vec<String>> {
        let project = self.opts.project_id.as_deref();
        let existing = self.client.list_tags(project).await?;
        let mut ids = Vec::with_capacity(tags.len());
        for (slug, value) in tags {
            if let Some(t) = existing.iter().find(|t| &t.slug == slug) {
                ids.push(t.id.clone());
                continue;
            }
            let color = if value.starts_with('#') { value } else { "" };
            ids.push(self.client.create_tag(slug, color, project).await?.id);
        }
        Ok(ids)
    }
}

#[async_trait]
impl SecretsProvider for ProjectSecretsProvider {
    async fn get(&self, name: &str, opts: Option<&GetOptions>) -> Result<Option<SecretValue>> {
        check_name(name)?;
        let opts = opts.cloned().unwrap_or_default();
        Ok(self.read("secrets.get", name, &opts, true).await?.map(|s| {
            SecretValue::new(s.value.expose_secret().as_bytes().to_vec())
                .with_version(s.version.to_string())
        }))
    }

    /// Every secret directly under `path` with one listing (plus imported keys when
    /// `include_imports` is on; direct secrets win), sorted by name.
    async fn get_all(&self, path: Option<&str>) -> Result<SecretMap> {
        let rel = path.unwrap_or("").trim_matches('/').to_owned();
        let res = self
            .client
            .list_secrets(Some(&ListSecretsOptions {
                project_id: self.opts.project_id.clone(),
                environment: self.opts.environment.clone(),
                secret_path: Some(join_path(&[&self.base, &rel])),
                expand_references: Some(self.opts.expand_references.unwrap_or(true)),
                include_imports: Some(self.opts.include_imports.unwrap_or(true)),
                ..ListSecretsOptions::default()
            }))
            .await;
        let list = match res {
            Ok(l) => l,
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(SecretMap::new()),
            Err(e) => return Err(e),
        };
        Ok(list
            .merged()
            .into_iter()
            .map(|(key, s)| {
                let name = if rel.is_empty() {
                    key
                } else {
                    format!("{rel}/{key}")
                };
                let value = SecretValue::new(s.value.expose_secret().as_bytes().to_vec())
                    .with_version(s.version.to_string());
                (name, value)
            })
            .collect())
    }

    /// Metadata of the secrets in a folder below the base path (`app/` or `app`); when no
    /// such folder exists the last segment is a key prefix inside its parent folder
    /// (`app/DB_` lists keys starting with `DB_` in `app`). Names resolve with `get`.
    async fn list(&self, prefix_or_path: Option<&str>) -> Result<Vec<SecretMetadata>> {
        let raw = prefix_or_path.unwrap_or("");
        let rel = raw.trim_matches('/');
        match self.list_folder(rel, "").await {
            Err(e) if e.code() == ErrorCode::NotFound && !rel.is_empty() && !raw.ends_with('/') => {
            }
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(Vec::new()),
            other => return other,
        }
        let (dir, prefix) = match rel.rfind('/') {
            Some(i) => (&rel[..i], &rel[i + 1..]),
            None => ("", rel),
        };
        match self.list_folder(dir, prefix).await {
            Err(e) if e.code() == ErrorCode::NotFound => Ok(Vec::new()),
            other => other,
        }
    }

    /// Creates the secret, or updates it when the key exists; missing folders are created.
    async fn set(
        &self,
        name: &str,
        value: SecretData,
        opts: Option<&SetOptions>,
    ) -> Result<String> {
        const OP: &str = "secrets.set";
        check_name(name)?;
        let opts = opts.cloned().unwrap_or_default();
        if opts.cas.is_some() {
            return Err(Error::unsupported(format!(
                "{OP}: Infisical has no check-and-set"
            )));
        }
        let text = String::from_utf8(value.into_bytes()?).map_err(|_| {
            api::invalid(
                OP,
                "Infisical stores text only; the value is not valid UTF-8",
            )
        })?;
        let text = zeroize::Zeroizing::new(text);
        let (path, key) = self.locate(OP, name, opts.path.as_deref())?;
        let tag_ids = if opts.tags.is_empty() {
            None
        } else {
            Some(self.ensure_tags(&opts.tags).await?)
        };
        let create = CreateSecretOptions {
            project_id: self.opts.project_id.clone(),
            environment: self.opts.environment.clone(),
            secret_path: Some(path.clone()),
            comment: opts.description.clone(),
            tag_ids: tag_ids.clone(),
            ..CreateSecretOptions::default()
        };
        let mut res = self.client.create_secret(&key, &text, Some(&create)).await;
        if let Err(e) = &res {
            if e.code() == ErrorCode::NotFound
                && e.message().to_ascii_lowercase().contains("folder")
            {
                self.ensure_folders(&path).await?;
                res = self.client.create_secret(&key, &text, Some(&create)).await;
            }
        }
        if let Err(e) = &res {
            if e.code() == ErrorCode::Conflict {
                let upd = UpdateSecretOptions {
                    project_id: self.opts.project_id.clone(),
                    environment: self.opts.environment.clone(),
                    secret_path: Some(path.clone()),
                    value: Some(text.to_string()),
                    comment: opts.description.clone().filter(|d| !d.is_empty()),
                    tag_ids,
                    ..UpdateSecretOptions::default()
                };
                res = self.client.update_secret(&key, Some(&upd)).await;
            }
        }
        Ok(res?.version.to_string())
    }

    async fn delete(&self, name: &str, opts: Option<&DeleteOptions>) -> Result<()> {
        const OP: &str = "secrets.delete";
        check_name(name)?;
        let opts = opts.cloned().unwrap_or_default();
        if !opts.versions.is_empty() || opts.permanent {
            return Err(Error::unsupported(format!(
                "{OP}: Infisical always deletes a secret permanently with all its versions"
            )));
        }
        let (path, key) = self.locate(OP, name, opts.path.as_deref())?;
        self.client
            .delete_secret(
                &key,
                Some(&DeleteSecretOptions {
                    project_id: self.opts.project_id.clone(),
                    environment: self.opts.environment.clone(),
                    secret_path: Some(path),
                    secret_type: None,
                }),
            )
            .await?;
        Ok(())
    }

    /// Metadata without transferring the value.
    async fn metadata(
        &self,
        name: &str,
        opts: Option<&GetOptions>,
    ) -> Result<Option<SecretMetadata>> {
        check_name(name)?;
        let opts = opts.cloned().unwrap_or_default();
        Ok(self
            .read("secrets.metadata", name, &opts, false)
            .await?
            .map(|s| metadata_of(name, &s)))
    }
}
