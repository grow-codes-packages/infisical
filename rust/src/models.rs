//! Data types returned by the Infisical API calls.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use serde_json::Value;

use crate::api::{self, arr, b, s, time, u};
use crate::core::{Error, Result, Secret};

/// Type of a secret: shared (the default) or a user's personal override (user JWTs only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SecretType {
    /// The secret every member sees.
    #[default]
    Shared,
    /// The caller's personal override of a shared secret.
    Personal,
}

impl SecretType {
    /// Wire value (`shared` / `personal`).
    pub fn as_str(self) -> &'static str {
        match self {
            SecretType::Shared => "shared",
            SecretType::Personal => "personal",
        }
    }

    fn parse(text: &str) -> SecretType {
        if text == "personal" {
            SecretType::Personal
        } else {
            SecretType::Shared
        }
    }
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SecretType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "shared" => Ok(SecretType::Shared),
            "personal" => Ok(SecretType::Personal),
            _ => Err(Error::validation(format!(
                "secret type must be shared or personal, got {s:?}"
            ))),
        }
    }
}

/// How [`update_secrets`](crate::InfisicalClient::update_secrets) treats keys that do not
/// exist.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum BatchUpdateMode {
    /// Fail the whole batch when a key is missing (server default).
    #[default]
    FailOnNotFound,
    /// Create missing keys.
    Upsert,
    /// Skip missing keys.
    Ignore,
}

impl BatchUpdateMode {
    /// Wire value (`failOnNotFound`, `upsert`, `ignore`).
    pub fn as_str(self) -> &'static str {
        match self {
            BatchUpdateMode::FailOnNotFound => "failOnNotFound",
            BatchUpdateMode::Upsert => "upsert",
            BatchUpdateMode::Ignore => "ignore",
        }
    }
}

/// A project tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tag {
    /// Tag id.
    pub id: String,
    /// Slug (lower-case letters, digits and `-`).
    pub slug: String,
    /// Display name (often empty; Infisical keys tags by slug).
    pub name: String,
    /// Color (`#rrggbb`).
    pub color: String,
    /// Owning project.
    pub project_id: String,
    /// Creation time.
    pub created_at: Option<SystemTime>,
    /// Last update.
    pub updated_at: Option<SystemTime>,
}

impl Tag {
    pub(crate) fn from_json(v: &Value) -> Tag {
        Tag {
            id: s(v, "id"),
            slug: s(v, "slug"),
            name: s(v, "name"),
            color: s(v, "color"),
            project_id: s(v, "projectId"),
            created_at: time(v, "createdAt"),
            updated_at: time(v, "updatedAt"),
        }
    }
}

/// A secret as Infisical returns it. `value` never prints.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SecretEntry {
    /// Secret id (stable across versions and renames).
    pub id: String,
    /// Secret name.
    pub key: String,
    /// Value (reference-expanded unless disabled); empty when `value_hidden` or when the
    /// server did not echo it (an update without a new value).
    pub value: Secret,
    /// The server hid the value (`view_secret_value = false` or missing permission).
    pub value_hidden: bool,
    /// Comment.
    pub comment: String,
    /// Version (bumped by every update, also of comment, tags or name).
    pub version: u64,
    /// Shared or personal.
    pub secret_type: SecretType,
    /// Project id.
    pub project_id: String,
    /// Environment slug.
    pub environment: String,
    /// Folder of the secret.
    pub secret_path: String,
    /// Tags.
    pub tags: Vec<Tag>,
    /// Secret metadata (key/value pairs).
    pub metadata: BTreeMap<String, String>,
    /// Multi-line values stored without encoding.
    pub skip_multiline_encoding: bool,
    /// Creation time.
    pub created_at: Option<SystemTime>,
    /// Last update.
    pub updated_at: Option<SystemTime>,
}

impl SecretEntry {
    pub(crate) fn from_json(v: &Value) -> SecretEntry {
        let hidden = b(v, "secretValueHidden");
        SecretEntry {
            id: s(v, "id"),
            key: s(v, "secretKey"),
            value: if hidden {
                Secret::default()
            } else {
                Secret::new(s(v, "secretValue"))
            },
            value_hidden: hidden,
            comment: s(v, "secretComment"),
            version: u(v, "version"),
            secret_type: SecretType::parse(&s(v, "type")),
            project_id: s(v, "workspace"),
            environment: s(v, "environment"),
            secret_path: s(v, "secretPath"),
            tags: arr(v, "tags").iter().map(Tag::from_json).collect(),
            metadata: api::metadata_map(v, "secretMetadata"),
            skip_multiline_encoding: b(v, "skipMultilineEncoding"),
            created_at: time(v, "createdAt"),
            updated_at: time(v, "updatedAt"),
        }
    }

    pub(crate) fn list(v: &Value, key: &str) -> Vec<SecretEntry> {
        arr(v, key).iter().map(SecretEntry::from_json).collect()
    }
}

/// The secrets one secret import contributes to a listing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImportedSecrets {
    /// Source path.
    pub secret_path: String,
    /// Source environment slug.
    pub environment: String,
    /// Source folder id.
    pub folder_id: String,
    /// The imported secrets.
    pub secrets: Vec<SecretEntry>,
}

/// Result of [`list_secrets`](crate::InfisicalClient::list_secrets).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SecretList {
    /// Secrets of the path (and of sub-folders when recursive).
    pub secrets: Vec<SecretEntry>,
    /// Secrets contributed by secret imports (`include_imports`).
    pub imports: Vec<ImportedSecrets>,
}

impl SecretList {
    pub(crate) fn from_json(v: &Value) -> SecretList {
        SecretList {
            secrets: SecretEntry::list(v, "secrets"),
            imports: arr(v, "imports")
                .iter()
                .map(|i| ImportedSecrets {
                    secret_path: s(i, "secretPath"),
                    environment: s(i, "environment"),
                    folder_id: s(i, "folderId"),
                    secrets: SecretEntry::list(i, "secrets"),
                })
                .collect(),
        }
    }

    /// The effective `key → secret` map: direct secrets win over imported ones; with a
    /// recursive listing, shallower paths win.
    pub fn merged(&self) -> BTreeMap<String, SecretEntry> {
        let mut direct: Vec<&SecretEntry> = self.secrets.iter().collect();
        direct.sort_by_key(|e| api::path_segments(&e.secret_path).len());
        let mut out = BTreeMap::new();
        for e in direct
            .into_iter()
            .chain(self.imports.iter().flat_map(|i| i.secrets.iter()))
        {
            out.entry(e.key.clone()).or_insert_with(|| e.clone());
        }
        out
    }
}

/// A secret folder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Folder {
    /// Folder id.
    pub id: String,
    /// Folder name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Absolute path of the folder (create/update/delete responses).
    pub path: String,
    /// Path below the listed path (recursive listings).
    pub relative_path: String,
    /// Version.
    pub version: u64,
    /// Environment id.
    pub environment_id: String,
    /// Parent folder id.
    pub parent_id: String,
    /// Creation time.
    pub created_at: Option<SystemTime>,
    /// Last update.
    pub updated_at: Option<SystemTime>,
}

impl Folder {
    pub(crate) fn from_json(v: &Value) -> Folder {
        Folder {
            id: s(v, "id"),
            name: s(v, "name"),
            description: s(v, "description"),
            path: s(v, "path"),
            relative_path: s(v, "relativePath"),
            version: u(v, "version"),
            environment_id: s(v, "envId"),
            parent_id: s(v, "parentId"),
            created_at: time(v, "createdAt"),
            updated_at: time(v, "updatedAt"),
        }
    }
}

/// A project environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// Environment id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Slug (`dev`, `staging`, …).
    pub slug: String,
    /// Order inside the project.
    pub position: u64,
    /// Owning project.
    pub project_id: String,
    /// Creation time.
    pub created_at: Option<SystemTime>,
    /// Last update.
    pub updated_at: Option<SystemTime>,
}

impl Environment {
    pub(crate) fn from_json(v: &Value) -> Environment {
        Environment {
            id: s(v, "id"),
            name: s(v, "name"),
            slug: s(v, "slug"),
            position: u(v, "position"),
            project_id: s(v, "projectId"),
            created_at: time(v, "createdAt"),
            updated_at: time(v, "updatedAt"),
        }
    }
}

/// An Infisical project.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Project {
    /// Project id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Slug.
    pub slug: String,
    /// Description.
    pub description: String,
    /// Product type (`secret-manager`, …).
    pub project_type: String,
    /// Organization id.
    pub org_id: String,
    /// Environments ordered by position.
    pub environments: Vec<Environment>,
    /// Creation time.
    pub created_at: Option<SystemTime>,
    /// Last update.
    pub updated_at: Option<SystemTime>,
}

impl Project {
    pub(crate) fn from_json(v: &Value) -> Project {
        Project {
            id: s(v, "id"),
            name: s(v, "name"),
            slug: s(v, "slug"),
            description: s(v, "description"),
            project_type: s(v, "type"),
            org_id: s(v, "orgId"),
            environments: arr(v, "environments")
                .iter()
                .map(Environment::from_json)
                .collect(),
            created_at: time(v, "createdAt"),
            updated_at: time(v, "updatedAt"),
        }
    }
}

/// One page of [`list_projects`](crate::InfisicalClient::list_projects).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectPage {
    /// Projects of the page.
    pub projects: Vec<Project>,
    /// Number of projects visible to the caller.
    pub total_count: u64,
}

/// A secret import: makes the secrets of another environment/path visible in a path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretImport {
    /// Import id.
    pub id: String,
    /// Source path.
    pub import_path: String,
    /// Source environment.
    pub import_environment: Environment,
    /// Order (lower first).
    pub position: u64,
    /// Copies the secrets instead of referencing them.
    pub is_replication: bool,
    /// Importing folder id.
    pub folder_id: String,
    /// Source project name (cross-project imports).
    pub source_project_name: String,
    /// Creation time.
    pub created_at: Option<SystemTime>,
    /// Last update.
    pub updated_at: Option<SystemTime>,
}

impl SecretImport {
    pub(crate) fn from_json(v: &Value) -> SecretImport {
        SecretImport {
            id: s(v, "id"),
            import_path: s(v, "importPath"),
            import_environment: v
                .get("importEnv")
                .map(Environment::from_json)
                .unwrap_or_default(),
            position: u(v, "position"),
            is_replication: b(v, "isReplication"),
            folder_id: s(v, "folderId"),
            source_project_name: s(v, "sourceProjectName"),
            created_at: time(v, "createdAt"),
            updated_at: time(v, "updatedAt"),
        }
    }
}

/// Who wrote a secret version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Actor {
    /// Actor id.
    pub id: String,
    /// Actor type (`user`, `identity`, …).
    pub actor_type: String,
    /// Display name.
    pub name: String,
}

/// One stored version of a secret. `value` never prints.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SecretVersion {
    /// Version row id.
    pub id: String,
    /// Version number.
    pub version: u64,
    /// Secret name at this version.
    pub key: String,
    /// Value at this version.
    pub value: Secret,
    /// The server hid the value.
    pub value_hidden: bool,
    /// Comment at this version.
    pub comment: String,
    /// Shared or personal.
    pub secret_type: SecretType,
    /// Environment slug.
    pub environment: String,
    /// Who wrote the version.
    pub actor: Option<Actor>,
    /// When the version was written.
    pub created_at: Option<SystemTime>,
}

impl SecretVersion {
    pub(crate) fn from_json(v: &Value) -> SecretVersion {
        let e = SecretEntry::from_json(v);
        SecretVersion {
            id: e.id,
            version: e.version,
            key: e.key,
            value: e.value,
            value_hidden: e.value_hidden,
            comment: e.comment,
            secret_type: e.secret_type,
            environment: e.environment,
            actor: v.get("actor").filter(|a| a.is_object()).map(|a| Actor {
                id: s(a, "actorId"),
                actor_type: s(a, "actorType"),
                name: s(a, "name"),
            }),
            created_at: e.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enums() {
        assert_eq!(SecretType::Personal.to_string(), "personal");
        assert_eq!("shared".parse::<SecretType>().unwrap(), SecretType::Shared);
        assert_eq!(
            "personal".parse::<SecretType>().unwrap(),
            SecretType::Personal
        );
        assert!("x".parse::<SecretType>().is_err());
        assert_eq!(BatchUpdateMode::default().as_str(), "failOnNotFound");
        assert_eq!(BatchUpdateMode::Upsert.as_str(), "upsert");
        assert_eq!(BatchUpdateMode::Ignore.as_str(), "ignore");
    }

    #[test]
    fn merged_prefers_direct_and_shallow() {
        let v = json!({
            "secrets": [
                {"secretKey": "A", "secretValue": "deep", "secretPath": "/x/y"},
                {"secretKey": "A", "secretValue": "top", "secretPath": "/"},
                {"secretKey": "H", "secretValueHidden": true, "secretValue": "<hidden>"}
            ],
            "imports": [{"secretPath": "/c", "environment": "staging", "secrets": [
                {"secretKey": "A", "secretValue": "imported"},
                {"secretKey": "B", "secretValue": "imported-b"}
            ]}]
        });
        let list = SecretList::from_json(&v);
        let m = list.merged();
        assert_eq!(m["A"].value.reveal(), "top");
        assert_eq!(m["B"].value.reveal(), "imported-b");
        assert!(m["H"].value_hidden && m["H"].value.is_empty());
        assert_eq!(list.imports[0].environment, "staging");
        let version = SecretVersion::from_json(&json!({"version": 2, "actor": null}));
        assert!(version.actor.is_none());
        let imp = SecretImport::from_json(&json!({"id": "i"}));
        assert_eq!(imp.import_environment, Environment::default());
    }
}
