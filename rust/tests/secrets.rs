//! Secrets API: list, get, create, update, delete, batch, versions, v3 forced, tag slugs.

mod support;

use std::collections::BTreeMap;

use grow_infisical as sdk;
use sdk::core::ErrorCode;
use sdk::{
    ApiVersion, BatchScope, BatchUpdateMode, CreateSecretOptions, DeleteSecretOptions,
    DeleteSecretsOptions, GetSecretOptions, ListSecretVersionsOptions, ListSecretsOptions,
    SecretInput, SecretType, SecretUpdate, UpdateSecretOptions, UpdateSecretsOptions,
};
use serde_json::json;
use support::*;
use wiremock::MockServer;

const TAGS: &str = "/api/v1/projects/proj-1/tags";

#[tokio::test]
async fn list_secrets_queries_and_parsing() {
    let server = MockServer::start().await;
    on(&server, "GET", "/api/v4/secrets", "listSecrets.withImports").await;
    let c = client(&server);
    let list = c.list_secrets(None).await.unwrap();
    assert!(list.secrets.is_empty());
    assert_eq!(list.imports[0].secret_path, "/common");
    assert_eq!(list.imports[0].secrets[0].key, "SDK_COMMON");
    assert_eq!(list.merged()["SDK_COMMON"].value.reveal(), "common-value-1");
    let r = &requests(&server, "/api/v4/secrets").await[0];
    for (k, v) in [
        ("projectId", "proj-1"),
        ("environment", "dev"),
        ("secretPath", "/"),
        ("recursive", "false"),
        ("expandSecretReferences", "true"),
        ("includeImports", "true"),
        ("viewSecretValue", "true"),
    ] {
        assert_eq!(query(r, k).as_deref(), Some(v), "{k}");
    }
    assert!(query(r, "tagSlugs").is_none());
    assert!(query(r, "includePersonalOverrides").is_none());
    let opts = ListSecretsOptions {
        project_id: Some("p2".into()),
        environment: Some("staging".into()),
        secret_path: Some("app/".into()),
        recursive: true,
        expand_references: Some(false),
        include_imports: Some(false),
        tag_slugs: vec!["a".into(), "b".into()],
        view_secret_value: Some(false),
        include_personal_overrides: true,
    };
    c.list_secrets(Some(&opts)).await.unwrap();
    let r = &requests(&server, "/api/v4/secrets").await[1];
    for (k, v) in [
        ("projectId", "p2"),
        ("environment", "staging"),
        ("secretPath", "/app"),
        ("recursive", "true"),
        ("expandSecretReferences", "false"),
        ("includeImports", "false"),
        ("viewSecretValue", "false"),
        ("tagSlugs", "a,b"),
        ("includePersonalOverrides", "true"),
    ] {
        assert_eq!(query(r, k).as_deref(), Some(v), "{k}");
    }

    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v4/secrets",
        "listSecrets.hiddenValues",
    )
    .await;
    let list = client(&server).list_secrets(None).await.unwrap();
    assert!(list
        .secrets
        .iter()
        .all(|s| s.value_hidden && s.value.is_empty()));

    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v4/secrets",
        "listSecrets.envMissing404",
    )
    .await;
    let e = client(&server).list_secrets(None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
}

#[tokio::test]
async fn get_secret_variants() {
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v4/secrets/SDK_49LJ3988_ONE",
        "getSecret.ok",
    )
    .await;
    let c = client(&server);
    let s = c.get_secret("SDK_49LJ3988_ONE", None).await.unwrap();
    assert_eq!(s.key, "SDK_49LJ3988_ONE");
    assert_eq!(s.value.reveal(), "v1-49lj3988");
    assert!(!format!("{s:?}").contains("v1-49lj3988"));
    assert_eq!(s.comment, "c1");
    assert_eq!(s.version, 1);
    assert_eq!(s.secret_type, SecretType::Shared);
    assert_eq!(s.secret_path, "/");
    assert_eq!(s.environment, "dev");
    assert!(s.created_at.is_some() && s.updated_at.is_some());
    assert!(!s.project_id.is_empty());
    let opts = GetSecretOptions {
        secret_path: Some("/app".into()),
        version: Some(1),
        secret_type: Some(SecretType::Personal),
        expand_references: Some(false),
        include_imports: Some(false),
        view_secret_value: Some(false),
        ..Default::default()
    };
    c.get_secret("SDK_49LJ3988_ONE", Some(&opts)).await.unwrap();
    let r = &requests(&server, "/api/v4/secrets/SDK_49LJ3988_ONE").await[1];
    for (k, v) in [
        ("secretPath", "/app"),
        ("version", "1"),
        ("type", "personal"),
        ("expandSecretReferences", "false"),
        ("includeImports", "false"),
        ("viewSecretValue", "false"),
    ] {
        assert_eq!(query(r, k).as_deref(), Some(v), "{k}");
    }
    let bad = GetSecretOptions {
        version: Some(0),
        ..Default::default()
    };
    assert_eq!(
        c.get_secret("X", Some(&bad)).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        c.get_secret(" ", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    on(&server, "GET", "/api/v4/secrets/V", "getSecret.version404").await;
    assert_eq!(
        c.get_secret("V", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    // names are percent-encoded in the path
    on(&server, "GET", "/api/v4/secrets/a%20b", "getSecret.ok").await;
    c.get_secret("a b", None).await.unwrap();
}

#[tokio::test]
async fn create_update_delete() {
    let server = MockServer::start().await;
    on(&server, "GET", TAGS, "listTags.ok").await;
    on(
        &server,
        "POST",
        "/api/v4/secrets/SDK_49LJ3988_ONE",
        "createSecret.ok",
    )
    .await;
    on(
        &server,
        "PATCH",
        "/api/v4/secrets/SDK_49LJ3988_ONE",
        "updateSecret.renameCommentTags",
    )
    .await;
    on(
        &server,
        "DELETE",
        "/api/v4/secrets/SDK_49LJ3988_ONE",
        "deleteSecret.ok",
    )
    .await;
    let c = client(&server);
    let created = c
        .create_secret(
            "SDK_49LJ3988_ONE",
            "v1-49lj3988",
            Some(&CreateSecretOptions {
                comment: Some("c1".into()),
                tag_ids: Some(vec!["id-0".into()]),
                tag_slugs: Some(vec!["t-49lj3988".into()]),
                secret_type: Some(SecretType::Shared),
                skip_multiline_encoding: true,
                metadata: BTreeMap::from([("owner".to_owned(), "team".to_owned())]),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(created.version, 1);
    let body = &sent(&server, "/api/v4/secrets/SDK_49LJ3988_ONE").await[0];
    assert_eq!(
        body,
        &json!({
            "projectId": "proj-1", "environment": "dev", "secretPath": "/",
            "secretValue": "v1-49lj3988", "secretComment": "c1",
            "tagIds": ["id-0", "8ec93966-db51-4801-a143-26296a09c05c"],
            "type": "shared", "skipMultilineEncoding": true,
            "secretMetadata": [{"key": "owner", "value": "team"}]
        })
    );
    // minimal create sends only the scope and the value
    c.create_secret("SDK_49LJ3988_ONE", "x", None)
        .await
        .unwrap();
    let body = &sent(&server, "/api/v4/secrets/SDK_49LJ3988_ONE").await[1];
    assert_eq!(
        body,
        &json!({"projectId": "proj-1", "environment": "dev", "secretPath": "/", "secretValue": "x"})
    );
    // unknown slug
    let e = c
        .create_secret(
            "X",
            "x",
            Some(&CreateSecretOptions {
                tag_slugs: Some(vec!["nope".into()]),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
    assert_eq!(
        c.create_secret("", "x", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );

    let upd = c
        .update_secret(
            "SDK_49LJ3988_ONE",
            Some(&UpdateSecretOptions {
                value: Some("v2".into()),
                new_name: Some("SDK_49LJ3988_RENAMED".into()),
                comment: Some("c2".into()),
                tag_ids: Some(vec![]),
                tag_slugs: Some(vec![]),
                secret_type: Some(SecretType::Shared),
                skip_multiline_encoding: Some(false),
                metadata: Some(BTreeMap::new()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(upd.key, "SDK_49LJ3988_RENAMED");
    assert_eq!(upd.version, 3);
    assert!(upd.value.is_empty());
    let body = &sent(&server, "/api/v4/secrets/SDK_49LJ3988_ONE").await[2];
    assert_eq!(
        body,
        &json!({
            "projectId": "proj-1", "environment": "dev", "secretPath": "/",
            "secretValue": "v2", "newSecretName": "SDK_49LJ3988_RENAMED", "secretComment": "c2",
            "tagIds": [], "type": "shared", "skipMultilineEncoding": false, "secretMetadata": []
        })
    );
    c.update_secret("SDK_49LJ3988_ONE", None).await.unwrap();
    let body = &sent(&server, "/api/v4/secrets/SDK_49LJ3988_ONE").await[3];
    assert_eq!(
        body,
        &json!({"projectId": "proj-1", "environment": "dev", "secretPath": "/"})
    );
    assert!(c.update_secret("", None).await.is_err());

    let del = c
        .delete_secret(
            "SDK_49LJ3988_ONE",
            Some(&DeleteSecretOptions {
                secret_type: Some(SecretType::Personal),
                secret_path: Some("/".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert!(!del.id.is_empty());
    let body = &sent(&server, "/api/v4/secrets/SDK_49LJ3988_ONE").await[4];
    assert_eq!(body["type"], "personal");
    assert!(c.delete_secret("", None).await.is_err());
    on(
        &server,
        "DELETE",
        "/api/v4/secrets/GONE",
        "deleteSecret.404",
    )
    .await;
    assert_eq!(
        c.delete_secret("GONE", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn batch_operations() {
    let server = MockServer::start().await;
    on(&server, "POST", "/api/v4/secrets/batch", "createSecrets.ok").await;
    on(
        &server,
        "PATCH",
        "/api/v4/secrets/batch",
        "updateSecrets.upsert",
    )
    .await;
    on(
        &server,
        "DELETE",
        "/api/v4/secrets/batch",
        "deleteSecrets.ok",
    )
    .await;
    let c = client(&server);
    let mut b2 = SecretInput::new("B2", "b2");
    b2.comment = Some("c".into());
    b2.tag_ids = Some(vec!["t".into()]);
    b2.skip_multiline_encoding = true;
    b2.metadata = BTreeMap::from([("k".to_owned(), "v".to_owned())]);
    assert!(!format!("{b2:?}").contains("b2\""));
    let out = c
        .create_secrets(
            &[SecretInput::new("B1", "b1"), b2],
            Some(&BatchScope {
                secret_path: Some("/app".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(out.len(), 2);
    let body = &sent(&server, "/api/v4/secrets/batch").await[0];
    assert_eq!(body["secretPath"], "/app");
    assert_eq!(
        body["secrets"],
        json!([
            {"secretKey": "B1", "secretValue": "b1"},
            {"secretKey": "B2", "secretValue": "b2", "secretComment": "c", "tagIds": ["t"],
             "skipMultilineEncoding": true, "secretMetadata": [{"key": "k", "value": "v"}]}
        ])
    );
    assert_eq!(
        c.create_secrets(&[], None).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert!(c
        .create_secrets(&[SecretInput::new("", "x")], None)
        .await
        .is_err());

    let mut u = SecretUpdate::new("UP", "u");
    u.new_name = Some("UP2".into());
    u.comment = Some("c".into());
    u.tag_ids = Some(vec![]);
    u.skip_multiline_encoding = Some(true);
    assert!(!format!("{u:?}").contains("\"u\""));
    let out = c
        .update_secrets(
            &[u, SecretUpdate::default()],
            Some(&UpdateSecretsOptions {
                mode: Some(BatchUpdateMode::Upsert),
                ..Default::default()
            }),
        )
        .await;
    assert_eq!(out.unwrap_err().code(), ErrorCode::Validation); // empty key
    let mut keep = SecretUpdate::new("UP", "u");
    keep.value = None;
    c.update_secrets(
        &[SecretUpdate::new("UP", "u"), keep],
        Some(&UpdateSecretsOptions {
            mode: Some(BatchUpdateMode::Upsert),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let body = &sent(&server, "/api/v4/secrets/batch").await[1];
    assert_eq!(body["mode"], "upsert");
    assert_eq!(
        body["secrets"],
        json!([{"secretKey": "UP", "secretValue": "u"}, {"secretKey": "UP"}])
    );
    let mut full = SecretUpdate::new("UP", "u");
    full.new_name = Some("UP2".into());
    full.comment = Some("c".into());
    full.tag_ids = Some(vec![]);
    full.skip_multiline_encoding = Some(true);
    c.update_secrets(&[full], None).await.unwrap();
    let body = &sent(&server, "/api/v4/secrets/batch").await[2];
    assert!(body.get("mode").is_none());
    assert_eq!(
        body["secrets"][0],
        json!({"secretKey": "UP", "secretValue": "u", "newSecretName": "UP2", "secretComment": "c", "tagIds": [], "skipMultilineEncoding": true})
    );
    assert!(c.update_secrets(&[], None).await.is_err());

    let out = c
        .delete_secrets(
            &["B1", "B2"],
            Some(&DeleteSecretsOptions {
                secret_type: Some(SecretType::Shared),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(out.len(), 3);
    let body = &sent(&server, "/api/v4/secrets/batch").await[3];
    assert_eq!(
        body["secrets"],
        json!([{"secretKey": "B1", "type": "shared"}, {"secretKey": "B2", "type": "shared"}])
    );
    assert!(c.delete_secrets(&[], None).await.is_err());
    assert!(c.delete_secrets(&[""], None).await.is_err());

    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/api/v4/secrets/batch",
        "createSecrets.duplicate400",
    )
    .await;
    on(
        &server,
        "PATCH",
        "/api/v4/secrets/batch",
        "updateSecrets.404",
    )
    .await;
    on(
        &server,
        "DELETE",
        "/api/v4/secrets/batch",
        "deleteSecrets.404",
    )
    .await;
    let c = client(&server);
    assert_eq!(
        c.create_secrets(&[SecretInput::new("A", "a")], None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Conflict
    );
    assert_eq!(
        c.update_secrets(&[SecretUpdate::new("A", "a")], None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        c.delete_secrets(&["A"], None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn forced_v3_routes() {
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v3/secrets/raw",
        "listSecrets.v3raw-imports",
    )
    .await;
    on(
        &server,
        "POST",
        "/api/v3/secrets/raw/K",
        "createSecret.v3raw-ok",
    )
    .await;
    on(
        &server,
        "PATCH",
        "/api/v3/secrets/raw/K",
        "updateSecret.v3raw-ok",
    )
    .await;
    on(
        &server,
        "DELETE",
        "/api/v3/secrets/raw/K",
        "deleteSecret.v3raw-ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/api/v3/secrets/batch/raw",
        "createSecrets.v3raw-ok",
    )
    .await;
    on(
        &server,
        "PATCH",
        "/api/v3/secrets/batch/raw",
        "updateSecrets.v3raw-ok",
    )
    .await;
    on(
        &server,
        "DELETE",
        "/api/v3/secrets/batch/raw",
        "deleteSecrets.v3raw-ok",
    )
    .await;
    let c = client_with(&server, |b| b.api_version(ApiVersion::V3));
    assert_eq!(c.api_version("secrets"), "v3");
    let list = c.list_secrets(None).await.unwrap();
    assert!(!list.secrets.is_empty() || !list.imports.is_empty());
    let r = &requests(&server, "/api/v3/secrets/raw").await[0];
    assert_eq!(query(r, "workspaceId").as_deref(), Some("proj-1"));
    assert_eq!(query(r, "include_imports").as_deref(), Some("true"));
    assert!(query(r, "viewSecretValue").is_none());
    c.create_secret("K", "v", None).await.unwrap();
    c.update_secret("K", None).await.unwrap();
    c.delete_secret("K", None).await.unwrap();
    assert_eq!(
        sent(&server, "/api/v3/secrets/raw/K").await[0]["workspaceId"],
        "proj-1"
    );
    c.create_secrets(&[SecretInput::new("K", "v")], None)
        .await
        .unwrap();
    c.update_secrets(&[SecretUpdate::new("K", "v")], None)
        .await
        .unwrap();
    c.delete_secrets(&["K"], None).await.unwrap();
    assert_eq!(sent(&server, "/api/v3/secrets/batch/raw").await.len(), 3);
    assert_eq!(c.api_version("secrets"), "v3");
}

#[tokio::test]
async fn secret_versions() {
    let server = MockServer::start().await;
    let id = "805cfac2-aef1-4b20-850a-5495bb4795d1";
    let p = format!("/api/v1/secret/{id}/secret-versions");
    on(&server, "GET", &p, "listSecretVersions.ok").await;
    let c = client(&server);
    let vs = c.list_secret_versions(id, None).await.unwrap();
    assert_eq!(vs[0].version, 3);
    assert_eq!(vs[0].value.reveal(), "v2-49lj3988");
    assert_eq!(vs[0].actor.as_ref().unwrap().actor_type, "identity");
    assert!(vs.windows(2).all(|w| w[0].version > w[1].version));
    let r = &requests(&server, &p).await[0];
    assert_eq!(query(r, "offset").as_deref(), Some("0"));
    assert_eq!(query(r, "limit").as_deref(), Some("20"));
    c.list_secret_versions(
        id,
        Some(&ListSecretVersionsOptions {
            offset: 1,
            limit: Some(1000),
        }),
    )
    .await
    .unwrap();
    let r = &requests(&server, &p).await[1];
    assert_eq!(query(r, "offset").as_deref(), Some("1"));
    assert_eq!(query(r, "limit").as_deref(), Some("1000"));
    for limit in [0, 1001] {
        let e = c
            .list_secret_versions(
                id,
                Some(&ListSecretVersionsOptions {
                    offset: 0,
                    limit: Some(limit),
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Validation);
    }
    assert!(c.list_secret_versions("", None).await.is_err());
    let server = MockServer::start().await;
    on(&server, "GET", &p, "listSecretVersions.identity403").await;
    let e = client(&server)
        .list_secret_versions(id, None)
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::PermissionDenied);
}
