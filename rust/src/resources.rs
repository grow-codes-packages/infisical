//! Folders (v2), projects and environments (v1), tags (v1) and secret imports (v2).

use serde_json::{json, Value};

use crate::api::{self, arr, encode_segment, Call};
use crate::client::InfisicalClient;
use crate::core::Result;
use crate::models::{Environment, Folder, Project, ProjectPage, SecretImport, Tag};

/// Color [`InfisicalClient::create_tag`] uses when none is given.
pub const DEFAULT_TAG_COLOR: &str = "#bec2c8";

/// Options of [`InfisicalClient::list_folders`]. Unset fields fall back to the client
/// configuration (`path` to the configured secret path).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListFoldersOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Parent path.
    pub path: Option<String>,
    /// List every descendant (each with `relative_path`).
    pub recursive: bool,
}

/// Options of [`InfisicalClient::create_folder`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateFolderOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Parent path.
    pub path: Option<String>,
    /// Description.
    pub description: Option<String>,
}

/// Options of [`InfisicalClient::update_folder`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateFolderOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Parent path of the folder.
    pub path: Option<String>,
    /// The (new) folder name; required by the server.
    pub name: String,
    /// New description.
    pub description: Option<String>,
}

/// Options of [`InfisicalClient::delete_folder`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteFolderOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Parent path of the folder.
    pub path: Option<String>,
    /// Delete a folder that still holds secrets or folders.
    pub force: bool,
}

/// Options of [`InfisicalClient::list_projects`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListProjectsOptions {
    /// Product type filter (default `secret-manager`).
    pub project_type: Option<String>,
    /// Page size (1–100; `None` uses the server default).
    pub limit: Option<u32>,
    /// Projects to skip.
    pub offset: u32,
}

/// Options of [`InfisicalClient::create_environment`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateEnvironmentOptions {
    /// Project id (default: configured).
    pub project_id: Option<String>,
    /// Order of the environment (`None`: appended last).
    pub position: Option<u32>,
}

/// The importing path of a secret-import call (unset fields fall back to the config).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretImportOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Importing path.
    pub path: Option<String>,
}

/// Options of [`InfisicalClient::create_secret_import`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateSecretImportOptions {
    /// Project id.
    pub project_id: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
    /// Importing path.
    pub path: Option<String>,
    /// Source environment slug (required).
    pub import_environment: String,
    /// Source path (default `/`).
    pub import_path: Option<String>,
    /// Import from another project.
    pub source_project_id: Option<String>,
    /// Copy the secrets instead of referencing them.
    pub is_replication: bool,
}

fn project_route(project_id: &str, suffix: &str) -> String {
    format!("/api/v1/projects/{}{suffix}", encode_segment(project_id))
}

impl InfisicalClient {
    // --- folders --------------------------------------------------------------------

    /// Lists the folders under a path (`GET /api/v2/folders`).
    pub async fn list_folders(&self, opts: Option<&ListFoldersOptions>) -> Result<Vec<Folder>> {
        const OP: &str = "folders.list";
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.path.as_deref(),
        )?;
        let mut c = Call::get("/api/v2/folders", format!("{OP} {}", s.path))
            .query("projectId", s.project_id)
            .query("environment", s.environment)
            .query("path", s.path);
        if o.recursive {
            c = c.query("recursive", "true");
        }
        let body = self.call_json(c).await?;
        Ok(arr(&body, "folders")
            .iter()
            .map(Folder::from_json)
            .collect())
    }

    /// Creates a folder under a path (`POST /api/v2/folders`). Names allow letters, digits,
    /// `-` and `_` (`VALIDATION` otherwise); a duplicate is `CONFLICT`.
    pub async fn create_folder(
        &self,
        name: &str,
        opts: Option<&CreateFolderOptions>,
    ) -> Result<Folder> {
        const OP: &str = "folders.create";
        api::require_arg(OP, "name", name)?;
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.path.as_deref(),
        )?;
        let mut b = json!({"projectId": s.project_id, "environment": s.environment, "name": name, "path": s.path});
        if let Some(d) = o.description.as_deref().filter(|d| !d.is_empty()) {
            b["description"] = json!(d);
        }
        let body = self
            .call_json(Call::post("/api/v2/folders", format!("{OP} {name}")).json(b))
            .await?;
        Ok(Folder::from_json(
            body.get("folder").unwrap_or(&Value::Null),
        ))
    }

    /// Renames a folder or changes its description (`PATCH /api/v2/folders/{id}`); an
    /// unknown id is `NOT_FOUND`.
    pub async fn update_folder(
        &self,
        folder_id: &str,
        opts: &UpdateFolderOptions,
    ) -> Result<Folder> {
        const OP: &str = "folders.update";
        api::require_arg(OP, "folderId", folder_id)?;
        api::require_arg(OP, "name", &opts.name)?;
        let s = self.scope(
            OP,
            opts.project_id.as_deref(),
            opts.environment.as_deref(),
            opts.path.as_deref(),
        )?;
        let mut b = json!({"projectId": s.project_id, "environment": s.environment, "name": opts.name, "path": s.path});
        if let Some(d) = &opts.description {
            b["description"] = json!(d);
        }
        let body = self
            .call_json(
                Call::patch(
                    format!("/api/v2/folders/{}", encode_segment(folder_id)),
                    format!("{OP} {folder_id}"),
                )
                .json(b),
            )
            .await?;
        Ok(Folder::from_json(
            body.get("folder").unwrap_or(&Value::Null),
        ))
    }

    /// Deletes a folder by id or name (`DELETE /api/v2/folders/{idOrName}`); a missing
    /// folder is `NOT_FOUND`.
    pub async fn delete_folder(
        &self,
        folder_id_or_name: &str,
        opts: Option<&DeleteFolderOptions>,
    ) -> Result<Folder> {
        const OP: &str = "folders.delete";
        api::require_arg(OP, "folderIdOrName", folder_id_or_name)?;
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.path.as_deref(),
        )?;
        let mut b =
            json!({"projectId": s.project_id, "environment": s.environment, "path": s.path});
        if o.force {
            b["forceDelete"] = json!(true);
        }
        let body = self
            .call_json(
                Call::delete(
                    format!("/api/v2/folders/{}", encode_segment(folder_id_or_name)),
                    format!("{OP} {folder_id_or_name}"),
                )
                .json(b),
            )
            .await?;
        Ok(Folder::from_json(
            body.get("folder").unwrap_or(&Value::Null),
        ))
    }

    // --- projects + environments ----------------------------------------------------

    /// Lists the projects the caller is a member of (`GET /api/v1/projects`).
    pub async fn list_projects(&self, opts: Option<&ListProjectsOptions>) -> Result<ProjectPage> {
        const OP: &str = "projects.list";
        let o = opts.cloned().unwrap_or_default();
        if o.limit.is_some_and(|l| !(1..=100).contains(&l)) {
            return Err(api::invalid(OP, "limit must be 1–100 and offset >= 0"));
        }
        let mut c = Call::get("/api/v1/projects", OP).query(
            "type",
            o.project_type
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| "secret-manager".to_owned()),
        );
        if let Some(l) = o.limit {
            c = c.query("limit", l.to_string());
        }
        if o.offset > 0 {
            c = c.query("offset", o.offset.to_string());
        }
        let body = self.call_json(c).await?;
        Ok(ProjectPage {
            projects: arr(&body, "projects")
                .iter()
                .map(Project::from_json)
                .collect(),
            total_count: api::u(&body, "totalCount"),
        })
    }

    /// Reads a project by id (`GET /api/v1/projects/{id}`); `None` reads the configured
    /// project. An unknown id is `NOT_FOUND`.
    pub async fn get_project(&self, project_id: Option<&str>) -> Result<Project> {
        const OP: &str = "projects.get";
        let id = self.project_id(OP, project_id)?;
        let body = self
            .call_json(Call::get(project_route(&id, ""), format!("{OP} {id}")))
            .await?;
        Ok(Project::from_json(
            body.get("project").unwrap_or(&Value::Null),
        ))
    }

    /// Reads a project by slug (`GET /api/v1/projects/slug/{slug}`).
    pub async fn get_project_by_slug(&self, slug: &str) -> Result<Project> {
        const OP: &str = "projects.getBySlug";
        api::require_arg(OP, "slug", slug)?;
        let body = self
            .call_json(Call::get(
                format!("/api/v1/projects/slug/{}", encode_segment(slug)),
                format!("{OP} {slug}"),
            ))
            .await?;
        Ok(Project::from_json(&body))
    }

    /// The environments of a project ordered by position (from `GET /api/v1/projects/{id}`;
    /// Infisical has no list route). `None` uses the configured project.
    pub async fn list_environments(&self, project_id: Option<&str>) -> Result<Vec<Environment>> {
        Ok(self.get_project(project_id).await?.environments)
    }

    /// Creates a project environment (`POST /api/v1/projects/{id}/environments`; project
    /// admin). Slugs allow lower-case letters, digits and `-`; a duplicate slug is
    /// `CONFLICT`.
    pub async fn create_environment(
        &self,
        name: &str,
        slug: &str,
        opts: Option<&CreateEnvironmentOptions>,
    ) -> Result<Environment> {
        const OP: &str = "environments.create";
        api::require_arg(OP, "name", name)?;
        api::require_arg(OP, "slug", slug)?;
        let o = opts.cloned().unwrap_or_default();
        let id = self.project_id(OP, o.project_id.as_deref())?;
        let mut b = json!({"name": name, "slug": slug});
        if let Some(p) = o.position.filter(|p| *p > 0) {
            b["position"] = json!(p);
        }
        let body = self
            .call_json(
                Call::post(project_route(&id, "/environments"), format!("{OP} {slug}")).json(b),
            )
            .await?;
        Ok(Environment::from_json(
            body.get("environment").unwrap_or(&Value::Null),
        ))
    }

    // --- tags -------------------------------------------------------------------------

    /// Lists the tags of a project (`GET /api/v1/projects/{id}/tags`); `None` uses the
    /// configured project.
    pub async fn list_tags(&self, project_id: Option<&str>) -> Result<Vec<Tag>> {
        const OP: &str = "tags.list";
        let id = self.project_id(OP, project_id)?;
        let body = self
            .call_json(Call::get(project_route(&id, "/tags"), OP))
            .await?;
        Ok(arr(&body, "tags").iter().map(Tag::from_json).collect())
    }

    /// Creates a project tag (`POST /api/v1/projects/{id}/tags`). Slugs allow lower-case
    /// letters, digits and `-`; an empty `color` uses [`DEFAULT_TAG_COLOR`]; a duplicate
    /// slug is `CONFLICT`.
    pub async fn create_tag(
        &self,
        slug: &str,
        color: &str,
        project_id: Option<&str>,
    ) -> Result<Tag> {
        const OP: &str = "tags.create";
        api::require_arg(OP, "slug", slug)?;
        let id = self.project_id(OP, project_id)?;
        let color = if color.is_empty() {
            DEFAULT_TAG_COLOR
        } else {
            color
        };
        let body = self
            .call_json(
                Call::post(project_route(&id, "/tags"), format!("{OP} {slug}"))
                    .json(json!({"slug": slug, "color": color})),
            )
            .await?;
        Ok(Tag::from_json(body.get("tag").unwrap_or(&Value::Null)))
    }

    /// Deletes a tag by id (`DELETE /api/v1/projects/{id}/tags/{tagId}`); the tag disappears
    /// from every secret. An unknown id is `NOT_FOUND`.
    pub async fn delete_tag(&self, tag_id: &str, project_id: Option<&str>) -> Result<Tag> {
        const OP: &str = "tags.delete";
        api::require_arg(OP, "tagId", tag_id)?;
        let id = self.project_id(OP, project_id)?;
        let body = self
            .call_json(Call::delete(
                project_route(&id, &format!("/tags/{}", encode_segment(tag_id))),
                format!("{OP} {tag_id}"),
            ))
            .await?;
        Ok(Tag::from_json(body.get("tag").unwrap_or(&Value::Null)))
    }

    // --- secret imports ---------------------------------------------------------------

    /// Lists the imports of a path (`GET /api/v2/secret-imports`).
    pub async fn list_secret_imports(
        &self,
        opts: Option<&SecretImportOptions>,
    ) -> Result<Vec<SecretImport>> {
        const OP: &str = "secretImports.list";
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.path.as_deref(),
        )?;
        let body = self
            .call_json(
                Call::get("/api/v2/secret-imports", format!("{OP} {}", s.path))
                    .query("projectId", s.project_id)
                    .query("environment", s.environment)
                    .query("path", s.path),
            )
            .await?;
        Ok(arr(&body, "secretImports")
            .iter()
            .map(SecretImport::from_json)
            .collect())
    }

    /// Imports the secrets of `import_environment`/`import_path` into a path
    /// (`POST /api/v2/secret-imports`). Infisical accepts duplicates and source paths that do
    /// not exist.
    pub async fn create_secret_import(
        &self,
        opts: &CreateSecretImportOptions,
    ) -> Result<SecretImport> {
        const OP: &str = "secretImports.create";
        api::require_arg(OP, "importEnvironment", &opts.import_environment)?;
        let s = self.scope(
            OP,
            opts.project_id.as_deref(),
            opts.environment.as_deref(),
            opts.path.as_deref(),
        )?;
        let mut imp = json!({
            "environment": opts.import_environment,
            "path": api::normalize_path(opts.import_path.as_deref().unwrap_or("/")),
        });
        if let Some(p) = opts.source_project_id.as_deref().filter(|p| !p.is_empty()) {
            imp["sourceProjectId"] = json!(p);
        }
        let mut b = json!({"projectId": s.project_id, "environment": s.environment, "path": s.path, "import": imp});
        if opts.is_replication {
            b["isReplication"] = json!(true);
        }
        let body = self
            .call_json(Call::post("/api/v2/secret-imports", format!("{OP} {}", s.path)).json(b))
            .await?;
        Ok(SecretImport::from_json(
            body.get("secretImport").unwrap_or(&Value::Null),
        ))
    }

    /// Deletes an import by id (`DELETE /api/v2/secret-imports/{id}`); an unknown id is
    /// `NOT_FOUND`.
    pub async fn delete_secret_import(
        &self,
        import_id: &str,
        opts: Option<&SecretImportOptions>,
    ) -> Result<SecretImport> {
        const OP: &str = "secretImports.delete";
        api::require_arg(OP, "importId", import_id)?;
        let o = opts.cloned().unwrap_or_default();
        let s = self.scope(
            OP,
            o.project_id.as_deref(),
            o.environment.as_deref(),
            o.path.as_deref(),
        )?;
        let body = self
            .call_json(
                Call::delete(
                    format!("/api/v2/secret-imports/{}", encode_segment(import_id)),
                    format!("{OP} {import_id}"),
                )
                .json(json!({"projectId": s.project_id, "environment": s.environment, "path": s.path})),
            )
            .await?;
        Ok(SecretImport::from_json(
            body.get("secretImport").unwrap_or(&Value::Null),
        ))
    }
}
