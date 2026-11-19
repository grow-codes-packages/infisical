//! Folders, projects, environments, tags, secret imports, `load_env` and `export_dotenv`.

mod support;

use std::collections::HashMap;

use grow_infisical as sdk;
use sdk::core::ErrorCode;
use sdk::{
    format_dotenv, CreateEnvironmentOptions, CreateFolderOptions, CreateSecretImportOptions,
    DeleteFolderOptions, EnvOptions, ListFoldersOptions, ListProjectsOptions, SecretImportOptions,
    UpdateFolderOptions, DEFAULT_TAG_COLOR,
};
use serde_json::json;
use support::*;
use wiremock::MockServer;

const FOLDER_ID: &str = "e182ee25-3082-409f-937f-236cf3065f01";

#[tokio::test]
async fn folders() {
    let server = MockServer::start().await;
    on(&server, "GET", "/api/v2/folders", "listFolders.recursive").await;
    on(&server, "POST", "/api/v2/folders", "createFolder.ok").await;
    on(
        &server,
        "PATCH",
        &format!("/api/v2/folders/{FOLDER_ID}"),
        "updateFolder.ok",
    )
    .await;
    on(
        &server,
        "DELETE",
        &format!("/api/v2/folders/{FOLDER_ID}"),
        "deleteFolder.ok",
    )
    .await;
    let c = client(&server);
    let fs = c
        .list_folders(Some(&ListFoldersOptions {
            path: Some("/".into()),
            recursive: true,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(fs[0].name, "app");
    assert!(!fs[0].environment_id.is_empty() && !fs[0].parent_id.is_empty());
    assert!(fs.iter().any(|f| !f.relative_path.is_empty()));
    let r = &requests(&server, "/api/v2/folders").await[0];
    assert_eq!(query(r, "recursive").as_deref(), Some("true"));
    assert_eq!(query(r, "path").as_deref(), Some("/"));
    c.list_folders(None).await.unwrap();
    assert!(query(&requests(&server, "/api/v2/folders").await[1], "recursive").is_none());

    let f = c
        .create_folder(
            "f-49lj3988",
            Some(&CreateFolderOptions {
                path: Some("/".into()),
                description: Some("d".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(f.id, FOLDER_ID);
    assert_eq!(f.version, 1);
    assert_eq!(
        sent(&server, "/api/v2/folders").await[0],
        json!({"projectId": "proj-1", "environment": "dev", "name": "f-49lj3988", "path": "/", "description": "d"})
    );
    c.create_folder("x", None).await.unwrap();
    assert!(sent(&server, "/api/v2/folders").await[1]
        .get("description")
        .is_none());
    assert!(c.create_folder("", None).await.is_err());

    let f = c
        .update_folder(
            FOLDER_ID,
            &UpdateFolderOptions {
                name: "g-49lj3988".into(),
                description: Some("nd".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(f.name, "g-49lj3988");
    assert_eq!(f.version, 2);
    let body = &sent(&server, &format!("/api/v2/folders/{FOLDER_ID}")).await[0];
    assert_eq!(body["name"], "g-49lj3988");
    assert_eq!(body["description"], "nd");
    let e = c
        .update_folder(FOLDER_ID, &UpdateFolderOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Validation);
    assert!(c
        .update_folder(
            "",
            &UpdateFolderOptions {
                name: "n".into(),
                ..Default::default()
            }
        )
        .await
        .is_err());

    c.delete_folder(
        FOLDER_ID,
        Some(&DeleteFolderOptions {
            force: true,
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let bodies = sent(&server, &format!("/api/v2/folders/{FOLDER_ID}")).await;
    assert_eq!(bodies[1]["forceDelete"], true);
    c.delete_folder(FOLDER_ID, None).await.unwrap();
    assert!(c.delete_folder("", None).await.is_err());

    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/api/v2/folders",
        "createFolder.duplicate400",
    )
    .await;
    on(&server, "PATCH", "/api/v2/folders/nope", "updateFolder.404").await;
    on(
        &server,
        "DELETE",
        "/api/v2/folders/nope",
        "deleteFolder.404",
    )
    .await;
    let c = client(&server);
    assert_eq!(
        c.create_folder("app", None).await.unwrap_err().code(),
        ErrorCode::Conflict
    );
    let e = c
        .update_folder(
            "nope",
            &UpdateFolderOptions {
                name: "n".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
    assert_eq!(
        c.delete_folder("nope", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let server = MockServer::start().await;
    on(&server, "POST", "/api/v2/folders", "createFolder.422").await;
    assert_eq!(
        client(&server)
            .create_folder("bad name!", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn projects_and_environments() {
    let server = MockServer::start().await;
    on(&server, "GET", "/api/v1/projects", "listProjects.ok").await;
    on(&server, "GET", "/api/v1/projects/proj-1", "getProject.ok").await;
    on(&server, "GET", "/api/v1/projects/missing", "getProject.404").await;
    on(
        &server,
        "GET",
        "/api/v1/projects/slug/sdk-test",
        "getProjectBySlug.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/api/v1/projects/proj-1/environments",
        "createEnvironment.ok",
    )
    .await;
    let c = client(&server);
    let page = c
        .list_projects(Some(&ListProjectsOptions {
            limit: Some(100),
            offset: 5,
            project_type: Some("kms".into()),
        }))
        .await
        .unwrap();
    assert!(page.total_count >= 1);
    let p = &page.projects[0];
    assert_eq!(p.slug, "sdk-test");
    assert_eq!(p.project_type, "secret-manager");
    assert!(!p.org_id.is_empty() && !p.environments.is_empty());
    let r = &requests(&server, "/api/v1/projects").await[0];
    assert_eq!(query(r, "type").as_deref(), Some("kms"));
    assert_eq!(query(r, "limit").as_deref(), Some("100"));
    assert_eq!(query(r, "offset").as_deref(), Some("5"));
    c.list_projects(None).await.unwrap();
    let r = &requests(&server, "/api/v1/projects").await[1];
    assert_eq!(query(r, "type").as_deref(), Some("secret-manager"));
    assert!(query(r, "limit").is_none() && query(r, "offset").is_none());
    for limit in [0, 101] {
        let o = ListProjectsOptions {
            limit: Some(limit),
            ..Default::default()
        };
        assert_eq!(
            c.list_projects(Some(&o)).await.unwrap_err().code(),
            ErrorCode::Validation
        );
    }

    let p = c.get_project(None).await.unwrap();
    assert_eq!(p.name, "SDK Test");
    assert!(!p.description.is_empty());
    assert_eq!(
        c.get_project(Some("missing")).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let by_slug = c.get_project_by_slug("sdk-test").await.unwrap();
    assert_eq!(by_slug.id, p.id);
    assert!(c.get_project_by_slug("").await.is_err());
    let envs = c.list_environments(None).await.unwrap();
    assert!(envs.iter().any(|e| e.slug == "staging"));

    let e = c
        .create_environment(
            "E 49lj3988",
            "e-49lj3988",
            Some(&CreateEnvironmentOptions {
                position: Some(5),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(e.slug, "e-49lj3988");
    assert_eq!(e.position, 5);
    assert!(e.created_at.is_some());
    assert_eq!(
        sent(&server, "/api/v1/projects/proj-1/environments").await[0],
        json!({"name": "E 49lj3988", "slug": "e-49lj3988", "position": 5})
    );
    c.create_environment("n", "s", None).await.unwrap();
    assert!(c.create_environment("", "s", None).await.is_err());
    assert!(c.create_environment("n", "", None).await.is_err());

    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/api/v1/projects/proj-1/environments",
        "createEnvironment.duplicate400",
    )
    .await;
    assert_eq!(
        client(&server)
            .create_environment("n", "dev", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Conflict
    );
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/api/v1/projects/proj-1/environments",
        "createEnvironment.403viewer",
    )
    .await;
    assert_eq!(
        client(&server)
            .create_environment("n", "x", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    let server = MockServer::start().await;
    on(&server, "GET", "/api/v1/projects", "listProjects.empty").await;
    assert!(client(&server)
        .list_projects(None)
        .await
        .unwrap()
        .projects
        .is_empty());
}

#[tokio::test]
async fn tags() {
    let server = MockServer::start().await;
    let tags = "/api/v1/projects/proj-1/tags";
    let tag_id = "8ec93966-db51-4801-a143-26296a09c05c";
    on(&server, "GET", tags, "listTags.ok").await;
    on(&server, "POST", tags, "createTag.ok").await;
    on(
        &server,
        "DELETE",
        &format!("{tags}/{tag_id}"),
        "deleteTag.ok",
    )
    .await;
    let c = client(&server);
    let list = c.list_tags(None).await.unwrap();
    assert_eq!(list[0].slug, "t-49lj3988");
    assert_eq!(list[0].color, "#00aa00");
    let t = c.create_tag("t-49lj3988", "#00aa00", None).await.unwrap();
    assert_eq!(t.id, tag_id);
    assert!(!t.project_id.is_empty());
    c.create_tag("t2", "", Some("proj-1")).await.unwrap();
    assert_eq!(sent(&server, tags).await[1]["color"], DEFAULT_TAG_COLOR);
    assert!(c.create_tag("", "", None).await.is_err());
    let d = c.delete_tag(tag_id, None).await.unwrap();
    assert_eq!(d.id, tag_id);
    assert!(c.delete_tag("", None).await.is_err());

    let server = MockServer::start().await;
    on(&server, "POST", tags, "createTag.duplicate400").await;
    on(&server, "DELETE", &format!("{tags}/nope"), "deleteTag.404").await;
    let c = client(&server);
    assert_eq!(
        c.create_tag("dup", "", None).await.unwrap_err().code(),
        ErrorCode::Conflict
    );
    assert_eq!(
        c.delete_tag("nope", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let server = MockServer::start().await;
    on(&server, "POST", tags, "createTag.422").await;
    assert_eq!(
        client(&server)
            .create_tag("Bad Slug", "", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn secret_imports() {
    let server = MockServer::start().await;
    let id = "643ebf45-dad3-4470-8943-f53f5d883d16";
    on(
        &server,
        "GET",
        "/api/v2/secret-imports",
        "listSecretImports.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/api/v2/secret-imports",
        "createSecretImport.ok",
    )
    .await;
    on(
        &server,
        "DELETE",
        &format!("/api/v2/secret-imports/{id}"),
        "deleteSecretImport.ok",
    )
    .await;
    let c = client(&server);
    let at_app = SecretImportOptions {
        path: Some("/app".into()),
        ..Default::default()
    };
    let list = c.list_secret_imports(Some(&at_app)).await.unwrap();
    assert_eq!(list[0].id, id);
    assert_eq!(list[0].import_path, "/common");
    assert_eq!(list[0].import_environment.slug, "staging");
    assert_eq!(list[0].position, 1);
    assert!(!list[0].is_replication);
    assert!(!list[0].folder_id.is_empty());
    assert_eq!(
        query(
            &requests(&server, "/api/v2/secret-imports").await[0],
            "path"
        )
        .as_deref(),
        Some("/app")
    );
    let imp = c
        .create_secret_import(&CreateSecretImportOptions {
            path: Some("/app".into()),
            import_environment: "staging".into(),
            import_path: Some("common/".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(imp.id, id);
    assert_eq!(
        sent(&server, "/api/v2/secret-imports").await[0],
        json!({"projectId": "proj-1", "environment": "dev", "path": "/app", "import": {"environment": "staging", "path": "/common"}})
    );
    c.create_secret_import(&CreateSecretImportOptions {
        import_environment: "staging".into(),
        source_project_id: Some("other".into()),
        is_replication: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let body = &sent(&server, "/api/v2/secret-imports").await[1];
    assert_eq!(body["import"]["sourceProjectId"], "other");
    assert_eq!(body["import"]["path"], "/");
    assert_eq!(body["isReplication"], true);
    let e = c
        .create_secret_import(&CreateSecretImportOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Validation);
    let d = c.delete_secret_import(id, Some(&at_app)).await.unwrap();
    assert_eq!(d.import_environment.slug, "staging");
    assert!(c.delete_secret_import("", None).await.is_err());
    c.list_secret_imports(None).await.unwrap();
    let server = MockServer::start().await;
    on(
        &server,
        "DELETE",
        "/api/v2/secret-imports/nope",
        "deleteSecretImport.404",
    )
    .await;
    assert_eq!(
        client(&server)
            .delete_secret_import("nope", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
}

fn env_listing() -> serde_json::Value {
    json!({
        "secrets": [
            {"secretKey": "A", "secretValue": "one", "secretPath": "/app"},
            {"secretKey": "B", "secretValue": "two\nlines \"q\" \\ \r", "secretPath": "/app"},
            {"secretKey": "A", "secretValue": "deep", "secretPath": "/app/nested"},
            {"secretKey": "KEEP", "secretValue": "new", "secretPath": "/app"}
        ],
        "imports": [{"secretPath": "/common", "environment": "staging", "secrets": [
            {"secretKey": "A", "secretValue": "imported"},
            {"secretKey": "C", "secretValue": "three"}
        ]}]
    })
}

#[tokio::test]
async fn load_env_and_export_dotenv() {
    let server = MockServer::start().await;
    on_reply(&server, "GET", "/api/v4/secrets", json(200, env_listing())).await;
    let c = client(&server);
    let mut sink: HashMap<String, String> = HashMap::from([("KEEP".to_owned(), "old".to_owned())]);
    let opts = EnvOptions {
        secret_path: Some("/app".into()),
        recursive: true,
        ..Default::default()
    };
    let names = c.load_env_into(Some(&opts), &mut sink).await.unwrap();
    assert_eq!(
        names.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["A", "B", "C"]
    );
    assert_eq!(names["A"], "A");
    assert_eq!(sink["A"], "one");
    assert_eq!(sink["C"], "three");
    assert_eq!(sink["KEEP"], "old");
    let r = &requests(&server, "/api/v4/secrets").await[0];
    assert_eq!(query(r, "recursive").as_deref(), Some("true"));
    assert_eq!(query(r, "includeImports").as_deref(), Some("true"));
    let over = EnvOptions {
        override_existing: true,
        include_imports: Some(false),
        expand_references: Some(false),
        ..Default::default()
    };
    let names = c.load_env_into(Some(&over), &mut sink).await.unwrap();
    assert!(names.contains_key("KEEP"));
    assert_eq!(sink["KEEP"], "new");
    let r = &requests(&server, "/api/v4/secrets").await[1];
    assert_eq!(query(r, "includeImports").as_deref(), Some("false"));
    assert_eq!(query(r, "expandSecretReferences").as_deref(), Some("false"));

    let doc = c.export_dotenv(None).await.unwrap();
    assert_eq!(
        doc,
        "A=\"one\"\nB=\"two\\nlines \\\"q\\\" \\\\ \\r\"\nC=\"three\"\nKEEP=\"new\"\n"
    );
    assert_eq!(
        format_dotenv([("Z", "1"), ("Y", "2")]),
        "Y=\"2\"\nZ=\"1\"\n"
    );

    // the process environment
    let var = format!("GROW_INFISICAL_TEST_{}", std::process::id());
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/api/v4/secrets",
        json(
            200,
            json!({"secrets": [{"secretKey": var, "secretValue": "from-infisical"}]}),
        ),
    )
    .await;
    let names = client(&server).load_env(None).await.unwrap();
    assert_eq!(names.into_keys().collect::<Vec<_>>(), vec![var.clone()]);
    assert_eq!(std::env::var(&var).unwrap(), "from-infisical");
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v4/secrets",
        "listSecrets.envMissing404",
    )
    .await;
    let c = client(&server);
    assert!(c.load_env(None).await.is_err());
    assert!(c.export_dotenv(None).await.is_err());
}
