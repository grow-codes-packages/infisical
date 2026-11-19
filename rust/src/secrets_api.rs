//! Secrets: list, get, create, update, delete, batch operations and versions (v4 with a v3
//! fallback detected at run time; versions are v1).

use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Map, Value};

use crate::api::{self, encode_segment, Call};
use crate::client::{InfisicalClient, Scope};
use crate::core::{Error, Method, Result};
use crate::models::{BatchUpdateMode, SecretEntry, SecretList, SecretType, SecretVersion};

/// Options of [`InfisicalClient::list_secrets`]. Unset project, environment and path fall
/// back to the client configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListSecretsOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Secret path.
    pub secret_path: Option<String>,
    /// Also list every sub-folder.
    pub recursive: bool,
    /// Expand `${KEY}` / `${env.path.KEY}` references (default `true`).
    pub expand_references: Option<bool>,
    /// Add the secrets of secret imports (default `true`).
    pub include_imports: Option<bool>,
    /// Keep only secrets carrying one of these tag slugs.
    pub tag_slugs: Vec<String>,
    /// Return values (default `true`); `false` returns metadata only.
    pub view_secret_value: Option<bool>,
    /// Return the caller's personal values instead of the shared ones (user JWTs).
    pub include_personal_overrides: bool,
}

/// Options of [`InfisicalClient::get_secret`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GetSecretOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Secret path.
    pub secret_path: Option<String>,
    /// Reads an older version (`None`: the current one).
    pub version: Option<u64>,
    /// Shared secret (default) or the caller's personal override.
    pub secret_type: Option<SecretType>,
    /// Expand references (default `true`).
    pub expand_references: Option<bool>,
    /// Also find the key through secret imports (default `true`).
    pub include_imports: Option<bool>,
    /// Return the value (default `true`); `false` returns metadata only.
    pub view_secret_value: Option<bool>,
}

/// Options of [`InfisicalClient::create_secret`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateSecretOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Secret path (the folder must exist).
    pub secret_path: Option<String>,
    /// Comment.
    pub comment: Option<String>,
    /// Tags by id.
    pub tag_ids: Option<Vec<String>>,
    /// Tags by slug (resolved with `list_tags`; an unknown slug is `NOT_FOUND`).
    pub tag_slugs: Option<Vec<String>>,
    /// Create a personal override (user JWTs only) instead of a shared secret.
    pub secret_type: Option<SecretType>,
    /// Store multi-line values without encoding.
    pub skip_multiline_encoding: bool,
    /// Secret metadata (key/value pairs).
    pub metadata: BTreeMap<String, String>,
}

/// Options of [`InfisicalClient::update_secret`]; unset fields stay unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateSecretOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Secret path.
    pub secret_path: Option<String>,
    /// New value.
    pub value: Option<String>,
    /// Renames the secret.
    pub new_name: Option<String>,
    /// Replaces the comment.
    pub comment: Option<String>,
    /// Replaces the tag set by id (`Some(vec![])` removes every tag).
    pub tag_ids: Option<Vec<String>>,
    /// Replaces the tag set by slug (merged with `tag_ids`).
    pub tag_slugs: Option<Vec<String>>,
    /// Update the caller's personal override instead of the shared secret.
    pub secret_type: Option<SecretType>,
    /// Changes the multi-line encoding flag.
    pub skip_multiline_encoding: Option<bool>,
    /// Replaces the secret metadata.
    pub metadata: Option<BTreeMap<String, String>>,
}

/// Options of [`InfisicalClient::delete_secret`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteSecretOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Secret path.
    pub secret_path: Option<String>,
    /// Delete the caller's personal override instead of the shared secret.
    pub secret_type: Option<SecretType>,
}

/// One secret of [`InfisicalClient::create_secrets`]. `value` never prints in `Debug`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretInput {
    /// Secret name.
    pub key: String,
    /// Value.
    pub value: String,
    /// Comment.
    pub comment: Option<String>,
    /// Tags by id.
    pub tag_ids: Option<Vec<String>>,
    /// Store multi-line values without encoding.
    pub skip_multiline_encoding: bool,
    /// Secret metadata.
    pub metadata: BTreeMap<String, String>,
}

impl SecretInput {
    /// A secret with a key and a value.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        SecretInput {
            key: key.into(),
            value: value.into(),
            ..SecretInput::default()
        }
    }
}

impl std::fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretInput")
            .field("key", &self.key)
            .field("value", &crate::core::REDACTED)
            .field("comment", &self.comment)
            .finish_non_exhaustive()
    }
}

/// One secret of [`InfisicalClient::update_secrets`]; unset fields stay unchanged. `value`
/// never prints in `Debug`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretUpdate {
    /// Secret name.
    pub key: String,
    /// New value.
    pub value: Option<String>,
    /// Renames the secret.
    pub new_name: Option<String>,
    /// Replaces the comment.
    pub comment: Option<String>,
    /// Replaces the tag set (`Some(vec![])` removes every tag).
    pub tag_ids: Option<Vec<String>>,
    /// Changes the multi-line encoding flag.
    pub skip_multiline_encoding: Option<bool>,
}

impl SecretUpdate {
    /// An update of `key` with a new value.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        SecretUpdate {
            key: key.into(),
            value: Some(value.into()),
            ..SecretUpdate::default()
        }
    }
}

impl std::fmt::Debug for SecretUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretUpdate")
            .field("key", &self.key)
            .field("value", &self.value.as_ref().map(|_| crate::core::REDACTED))
            .field("new_name", &self.new_name)
            .finish_non_exhaustive()
    }
}

/// Where a batch create runs; unset fields fall back to the client configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchScope {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Secret path.
    pub secret_path: Option<String>,
}

/// Options of [`InfisicalClient::update_secrets`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateSecretsOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Secret path.
    pub secret_path: Option<String>,
    /// `FailOnNotFound` (server default), `Upsert` or `Ignore`.
    pub mode: Option<BatchUpdateMode>,
}

/// Options of [`InfisicalClient::delete_secrets`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteSecretsOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Secret path.
    pub secret_path: Option<String>,
    /// Delete personal overrides instead of shared secrets.
    pub secret_type: Option<SecretType>,
}

/// Paging of [`InfisicalClient::list_secret_versions`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListSecretVersionsOptions {
    /// Versions to skip (newest first).
    pub offset: u32,
    /// Page size (default 20, max 1000).
    pub limit: Option<u32>,
}

/// The route for v4 or v3 (`/api/v4/secrets` + suffix).
fn secrets_path(v3: bool, suffix: &str) -> String {
    if v3 {
        if suffix.starts_with("/batch") {
            return "/api/v3/secrets/batch/raw".to_owned();
        }
        return format!("/api/v3/secrets/raw{suffix}");
    }
    format!("/api/v4/secrets{suffix}")
}

/// `projectId` on v4, `workspaceId` on v3.
fn project_field(v3: bool) -> &'static str {
    if v3 {
        "workspaceId"
    } else {
        "projectId"
    }
}

/// `includeImports` on v4, `include_imports` on v3.
fn imports_field(v3: bool) -> &'static str {
    if v3 {
        "include_imports"
    } else {
        "includeImports"
    }
}

fn name_path(name: &str) -> String {
    format!("/{}", encode_segment(name))
}

fn scope_body(v3: bool, s: &Scope) -> Map<String, Value> {
    let mut b = Map::new();
    b.insert(project_field(v3).to_owned(), json!(s.project_id));
    b.insert("environment".to_owned(), json!(s.environment));
    b.insert("secretPath".to_owned(), json!(s.path));
    b
}

fn flag(v: bool) -> String {
    v.to_string()
}

impl InfisicalClient {
    /// Lists the secrets of a path (`GET /api/v4/secrets`, v3 fallback
    /// `GET /api/v3/secrets/raw`). A missing environment or path is `NOT_FOUND`.
    pub async fn list_secrets(&self, opts: Option<&ListSecretsOptions>) -> Result<SecretList> {
        const OP: &str = "secrets.list";
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.secret_path.as_deref(),
        )?;
        let body = self
            .secrets_call(|v3| {
                let mut c = Call::get(secrets_path(v3, ""), format!("{OP} {}", s.path))
                    .query(project_field(v3), s.project_id.clone())
                    .query("environment", s.environment.clone())
                    .query("secretPath", s.path.clone())
                    .query("recursive", flag(o.recursive))
                    .query(
                        "expandSecretReferences",
                        flag(o.expand_references.unwrap_or(true)),
                    )
                    .query(imports_field(v3), flag(o.include_imports.unwrap_or(true)));
                if !o.tag_slugs.is_empty() {
                    c = c.query("tagSlugs", o.tag_slugs.join(","));
                }
                if !v3 {
                    c = c.query("viewSecretValue", flag(o.view_secret_value.unwrap_or(true)));
                    if o.include_personal_overrides {
                        c = c.query("includePersonalOverrides", "true");
                    }
                }
                c
            })
            .await?;
        Ok(SecretList::from_json(&body))
    }

    /// Reads one secret (`GET /api/v4/secrets/{name}`, v3 fallback
    /// `GET /api/v3/secrets/raw/{name}`). A missing secret or version is `NOT_FOUND`.
    pub async fn get_secret(
        &self,
        name: &str,
        opts: Option<&GetSecretOptions>,
    ) -> Result<SecretEntry> {
        const OP: &str = "secrets.get";
        api::require_arg(OP, "name", name)?;
        let o = opts.cloned().unwrap_or_default();
        if o.version == Some(0) {
            return Err(api::invalid(OP, "version must be positive"));
        }
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.secret_path.as_deref(),
        )?;
        let body = self
            .secrets_call(|v3| {
                let mut c = Call::get(secrets_path(v3, &name_path(name)), format!("{OP} {name}"))
                    .query(project_field(v3), s.project_id.clone())
                    .query("environment", s.environment.clone())
                    .query("secretPath", s.path.clone());
                if let Some(v) = o.version {
                    c = c.query("version", v.to_string());
                }
                if let Some(t) = o.secret_type {
                    c = c.query("type", t.as_str());
                }
                c = c
                    .query(
                        "expandSecretReferences",
                        flag(o.expand_references.unwrap_or(true)),
                    )
                    .query(imports_field(v3), flag(o.include_imports.unwrap_or(true)));
                if !v3 {
                    c = c.query("viewSecretValue", flag(o.view_secret_value.unwrap_or(true)));
                }
                c
            })
            .await?;
        Ok(self.entry(&body))
    }

    fn entry(&self, body: &Value) -> SecretEntry {
        SecretEntry::from_json(body.get("secret").unwrap_or(&Value::Null))
    }

    /// Creates a secret (`POST /api/v4/secrets/{name}`). The folder must exist (`NOT_FOUND`
    /// otherwise); a duplicate is `CONFLICT`. Infisical trims surrounding whitespace of the
    /// value.
    pub async fn create_secret(
        &self,
        name: &str,
        value: &str,
        opts: Option<&CreateSecretOptions>,
    ) -> Result<SecretEntry> {
        const OP: &str = "secrets.create";
        api::require_arg(OP, "name", name)?;
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.secret_path.as_deref(),
        )?;
        let tag_ids = self
            .resolve_tag_ids(
                OP,
                &s.project_id,
                o.tag_ids.as_deref(),
                o.tag_slugs.as_deref(),
            )
            .await?;
        let body = self
            .secrets_call(|v3| {
                let mut b = scope_body(v3, &s);
                b.insert("secretValue".to_owned(), json!(value));
                if let Some(c) = &o.comment {
                    b.insert("secretComment".to_owned(), json!(c));
                }
                if let Some(ids) = &tag_ids {
                    b.insert("tagIds".to_owned(), json!(ids));
                }
                if let Some(t) = o.secret_type {
                    b.insert("type".to_owned(), json!(t.as_str()));
                }
                if o.skip_multiline_encoding {
                    b.insert("skipMultilineEncoding".to_owned(), json!(true));
                }
                if !o.metadata.is_empty() {
                    b.insert("secretMetadata".to_owned(), api::metadata_list(&o.metadata));
                }
                Call::post(secrets_path(v3, &name_path(name)), format!("{OP} {name}"))
                    .json(Value::Object(b))
            })
            .await?;
        Ok(self.entry(&body))
    }

    /// Changes a secret (`PATCH /api/v4/secrets/{name}`): value, name, comment, tags. Every
    /// update bumps the version. When no new value is sent the returned value is empty (the
    /// server does not echo it).
    pub async fn update_secret(
        &self,
        name: &str,
        opts: Option<&UpdateSecretOptions>,
    ) -> Result<SecretEntry> {
        const OP: &str = "secrets.update";
        api::require_arg(OP, "name", name)?;
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.secret_path.as_deref(),
        )?;
        let tag_ids = self
            .resolve_tag_ids(
                OP,
                &s.project_id,
                o.tag_ids.as_deref(),
                o.tag_slugs.as_deref(),
            )
            .await?;
        let body = self
            .secrets_call(|v3| {
                let mut b = scope_body(v3, &s);
                if let Some(v) = &o.value {
                    b.insert("secretValue".to_owned(), json!(v));
                }
                if let Some(n) = o.new_name.as_deref().filter(|n| !n.is_empty()) {
                    b.insert("newSecretName".to_owned(), json!(n));
                }
                if let Some(c) = &o.comment {
                    b.insert("secretComment".to_owned(), json!(c));
                }
                if let Some(ids) = &tag_ids {
                    b.insert("tagIds".to_owned(), json!(ids));
                }
                if let Some(t) = o.secret_type {
                    b.insert("type".to_owned(), json!(t.as_str()));
                }
                if let Some(skip) = o.skip_multiline_encoding {
                    b.insert("skipMultilineEncoding".to_owned(), json!(skip));
                }
                if let Some(md) = &o.metadata {
                    b.insert("secretMetadata".to_owned(), api::metadata_list(md));
                }
                Call::patch(secrets_path(v3, &name_path(name)), format!("{OP} {name}"))
                    .json(Value::Object(b))
            })
            .await?;
        Ok(self.entry(&body))
    }

    /// Deletes a secret with all its versions (`DELETE /api/v4/secrets/{name}`); a missing
    /// secret is `NOT_FOUND`.
    pub async fn delete_secret(
        &self,
        name: &str,
        opts: Option<&DeleteSecretOptions>,
    ) -> Result<SecretEntry> {
        const OP: &str = "secrets.delete";
        api::require_arg(OP, "name", name)?;
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.secret_path.as_deref(),
        )?;
        let body = self
            .secrets_call(|v3| {
                let mut b = scope_body(v3, &s);
                if let Some(t) = o.secret_type {
                    b.insert("type".to_owned(), json!(t.as_str()));
                }
                Call::delete(secrets_path(v3, &name_path(name)), format!("{OP} {name}"))
                    .json(Value::Object(b))
            })
            .await?;
        Ok(self.entry(&body))
    }

    async fn batch(
        &self,
        op: &str,
        method: Method,
        s: &Scope,
        extra: Option<(&str, Value)>,
        items: Vec<Value>,
    ) -> Result<Vec<SecretEntry>> {
        let body = self
            .secrets_call(|v3| {
                let mut b = scope_body(v3, s);
                b.insert("secrets".to_owned(), Value::Array(items.clone()));
                if let Some((k, v)) = &extra {
                    b.insert((*k).to_owned(), v.clone());
                }
                Call::new(
                    method.clone(),
                    secrets_path(v3, "/batch"),
                    format!("{op} {}", s.path),
                )
                .json(Value::Object(b))
            })
            .await?;
        Ok(SecretEntry::list(&body, "secrets"))
    }

    /// Creates several secrets atomically (`POST /api/v4/secrets/batch`): one duplicate
    /// fails the batch with `CONFLICT` and nothing is created. The result order is not
    /// guaranteed.
    pub async fn create_secrets(
        &self,
        secrets: &[SecretInput],
        opts: Option<&BatchScope>,
    ) -> Result<Vec<SecretEntry>> {
        const OP: &str = "secrets.createBatch";
        if secrets.is_empty() {
            return Err(api::invalid(OP, "at least one secret is required"));
        }
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.secret_path.as_deref(),
        )?;
        let mut items = Vec::with_capacity(secrets.len());
        for i in secrets {
            api::require_arg(OP, "key", &i.key)?;
            let mut m = json!({"secretKey": i.key, "secretValue": i.value});
            if let Some(c) = &i.comment {
                m["secretComment"] = json!(c);
            }
            if let Some(ids) = &i.tag_ids {
                m["tagIds"] = json!(ids);
            }
            if i.skip_multiline_encoding {
                m["skipMultilineEncoding"] = json!(true);
            }
            if !i.metadata.is_empty() {
                m["secretMetadata"] = api::metadata_list(&i.metadata);
            }
            items.push(m);
        }
        self.batch(OP, Method::POST, &s, None, items).await
    }

    /// Updates several secrets atomically (`PATCH /api/v4/secrets/batch`). With the default
    /// mode a missing key fails the batch with `NOT_FOUND`.
    pub async fn update_secrets(
        &self,
        secrets: &[SecretUpdate],
        opts: Option<&UpdateSecretsOptions>,
    ) -> Result<Vec<SecretEntry>> {
        const OP: &str = "secrets.updateBatch";
        if secrets.is_empty() {
            return Err(api::invalid(OP, "at least one secret is required"));
        }
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.secret_path.as_deref(),
        )?;
        let mut items = Vec::with_capacity(secrets.len());
        for i in secrets {
            api::require_arg(OP, "key", &i.key)?;
            let mut m = json!({"secretKey": i.key});
            if let Some(v) = &i.value {
                m["secretValue"] = json!(v);
            }
            if let Some(n) = i.new_name.as_deref().filter(|n| !n.is_empty()) {
                m["newSecretName"] = json!(n);
            }
            if let Some(c) = &i.comment {
                m["secretComment"] = json!(c);
            }
            if let Some(ids) = &i.tag_ids {
                m["tagIds"] = json!(ids);
            }
            if let Some(skip) = i.skip_multiline_encoding {
                m["skipMultilineEncoding"] = json!(skip);
            }
            items.push(m);
        }
        let extra = o.mode.map(|m| ("mode", json!(m.as_str())));
        self.batch(OP, Method::PATCH, &s, extra, items).await
    }

    /// Deletes several secrets atomically (`DELETE /api/v4/secrets/batch`): one missing key
    /// fails the batch with `NOT_FOUND` and nothing is deleted.
    pub async fn delete_secrets(
        &self,
        keys: &[&str],
        opts: Option<&DeleteSecretsOptions>,
    ) -> Result<Vec<SecretEntry>> {
        const OP: &str = "secrets.deleteBatch";
        if keys.is_empty() {
            return Err(api::invalid(OP, "at least one key is required"));
        }
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.secret_path.as_deref(),
        )?;
        let mut items = Vec::with_capacity(keys.len());
        for k in keys {
            api::require_arg(OP, "key", k)?;
            let mut m = json!({"secretKey": k});
            if let Some(t) = o.secret_type {
                m["type"] = json!(t.as_str());
            }
            items.push(m);
        }
        self.batch(OP, Method::DELETE, &s, None, items).await
    }

    /// Lists the versions of a secret by id, newest first
    /// (`GET /api/v1/secret/{secretId}/secret-versions`). Infisical serves this route to
    /// user JWTs only: machine identities get `PERMISSION_DENIED`.
    pub async fn list_secret_versions(
        &self,
        secret_id: &str,
        opts: Option<&ListSecretVersionsOptions>,
    ) -> Result<Vec<SecretVersion>> {
        const OP: &str = "secretVersions.list";
        api::require_arg(OP, "secretId", secret_id)?;
        let o = opts.cloned().unwrap_or_default();
        let limit = o.limit.unwrap_or(20);
        if !(1..=1000).contains(&limit) {
            return Err(api::invalid(OP, "limit must be 1–1000 and offset >= 0"));
        }
        let body = self
            .call_json(
                Call::get(
                    format!(
                        "/api/v1/secret/{}/secret-versions",
                        encode_segment(secret_id)
                    ),
                    format!("{OP} {secret_id}"),
                )
                .query("offset", o.offset.to_string())
                .query("limit", limit.to_string()),
            )
            .await?;
        Ok(api::arr(&body, "secretVersions")
            .iter()
            .map(SecretVersion::from_json)
            .collect())
    }

    /// Merges tag ids with the ids of tag slugs (`None` when both are `None`).
    pub(crate) async fn resolve_tag_ids(
        &self,
        op: &str,
        project_id: &str,
        ids: Option<&[String]>,
        slugs: Option<&[String]>,
    ) -> Result<Option<Vec<String>>> {
        if ids.is_none() && slugs.is_none() {
            return Ok(None);
        }
        let mut out: Vec<String> = ids.map(<[String]>::to_vec).unwrap_or_default();
        let slugs = slugs.unwrap_or_default();
        if slugs.is_empty() {
            return Ok(Some(out));
        }
        let tags = self.list_tags(Some(project_id)).await?;
        let by_slug: HashMap<&str, &str> = tags
            .iter()
            .map(|t| (t.slug.as_str(), t.id.as_str()))
            .collect();
        for slug in slugs {
            match by_slug.get(slug.as_str()) {
                Some(id) => out.push((*id).to_owned()),
                None => return Err(Error::not_found(format!("{op}: tag {slug} does not exist"))),
            }
        }
        Ok(Some(out))
    }
}
