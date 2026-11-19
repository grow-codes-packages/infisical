//! `ProjectSecretsProvider`: the SPEC §3 secrets provider over one project and environment.

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use grow_infisical as sdk;
use sdk::core::ErrorCode;
use sdk::secrets::{
    DeleteOptions, EnvSource, GetOptions, LoadEnvOptions, SecretCache, SecretsProvider, SetOptions,
    WatchOptions,
};
use sdk::SecretsProviderOptions;
use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer};

fn secret(key: &str, value: &str, path: &str, version: u64) -> Value {
    json!({
        "id": format!("id-{key}"), "secretKey": key, "secretValue": value, "secretPath": path,
        "version": version, "type": "shared", "environment": "dev", "secretComment": "note",
        "createdAt": "2026-11-18T20:28:13.931Z", "updatedAt": "2026-11-18T20:28:13.931Z",
        "tags": [{"id": "t1", "slug": "team", "name": ""}, {"id": "t2", "slug": "x", "name": "X"}]
    })
}

#[tokio::test]
async fn get_and_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/secrets/PASSWORD"))
        .and(query_param("secretPath", "/base/app/db"))
        .respond_with(json(
            200,
            json!({"secret": secret("PASSWORD", "pw", "/base/app/db", 3)}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/secrets/PASSWORD"))
        .and(query_param("secretPath", "/other"))
        .respond_with(json(
            200,
            json!({"secret": secret("PASSWORD", "pw-o", "/other", 1)}),
        ))
        .mount(&server)
        .await;
    on(&server, "GET", "/api/v4/secrets/MISSING", "getSecret.404").await;
    on(
        &server,
        "GET",
        "/api/v4/secrets/DENIED",
        "listSecrets.403noMembership",
    )
    .await;
    let c = client(&server);
    let p = c.secrets_with(SecretsProviderOptions {
        base_path: Some("base/".into()),
        ..Default::default()
    });
    assert_eq!(p.base_path(), "/base");
    assert_eq!(p.options().base_path.as_deref(), Some("base/"));
    let v = p.get("app/db/PASSWORD", None).await.unwrap().unwrap();
    assert_eq!(v.reveal().unwrap(), "pw");
    assert_eq!(v.version(), Some("3"));
    let r = &requests(&server, "/api/v4/secrets/PASSWORD").await[0];
    assert_eq!(query(r, "viewSecretValue").as_deref(), Some("true"));
    assert_eq!(query(r, "includeImports").as_deref(), Some("true"));
    let o = GetOptions {
        path: Some("other".into()),
        version: Some("1".into()),
    };
    assert_eq!(
        p.get_string("PASSWORD", Some(&o)).await.unwrap().unwrap(),
        "pw-o"
    );
    let r = &requests(&server, "/api/v4/secrets/PASSWORD").await[1];
    assert_eq!(query(r, "version").as_deref(), Some("1"));
    for bad in ["0", "x"] {
        let o = GetOptions {
            version: Some(bad.into()),
            path: None,
        };
        assert_eq!(
            p.get("A", Some(&o)).await.unwrap_err().code(),
            ErrorCode::Validation
        );
    }
    assert!(p.get("MISSING", None).await.unwrap().is_none());
    assert!(!p.exists("MISSING", None).await.unwrap());
    assert_eq!(
        p.require("MISSING", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        p.get("DENIED", None).await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        p.get(" ", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        p.get("dir/", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );

    let md = p.metadata("app/db/PASSWORD", None).await.unwrap().unwrap();
    assert_eq!(md.name, "app/db/PASSWORD");
    assert_eq!(md.path.as_deref(), Some("/base/app/db"));
    assert_eq!(md.version.as_deref(), Some("3"));
    assert_eq!(md.versions, Some(3));
    assert_eq!(md.tags["team"], "team");
    assert_eq!(md.tags["x"], "X");
    assert_eq!(md.extra["comment"], "note");
    assert_eq!(md.extra["id"], "id-PASSWORD");
    assert!(md.created_at.is_some());
    let r = &requests(&server, "/api/v4/secrets/PASSWORD").await[2];
    assert_eq!(query(r, "viewSecretValue").as_deref(), Some("false"));
    assert!(p.metadata("MISSING", None).await.unwrap().is_none());
    assert!(p.metadata("", None).await.is_err());
    // the default provider uses the configured path
    assert_eq!(c.secrets().base_path(), "/");
}

#[tokio::test]
async fn list_and_get_all() {
    let server = MockServer::start().await;
    let folder = json!({"secrets": [
        secret("B", "b", "/app", 1),
        secret("A", "a", "/app", 2),
        {"secretKey": "P", "type": "personal", "secretPath": "/app"}
    ]});
    Mock::given(method("GET"))
        .and(path("/api/v4/secrets"))
        .and(query_param("secretPath", "/app"))
        .respond_with(json(200, folder.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/secrets"))
        .and(query_param("secretPath", "/"))
        .respond_with(json(200, json!({"secrets": [secret("DB_X", "x", "/", 1), secret("OTHER", "o", "/", 1)],
            "imports": [{"secrets": [secret("IMPORTED", "i", "/c", 1), secret("DB_X", "shadowed", "/c", 1)]}]})))
        .mount(&server)
        .await;
    on(
        &server,
        "GET",
        "/api/v4/secrets",
        "listSecrets.envMissing404",
    )
    .await;
    let p = client(&server).secrets();
    let names: Vec<String> = p
        .list(Some("app/"))
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(names, vec!["app/A", "app/B"]);
    let r = &requests(&server, "/api/v4/secrets").await[0];
    assert_eq!(query(r, "viewSecretValue").as_deref(), Some("false"));
    assert_eq!(query(r, "includeImports").as_deref(), Some("false"));
    assert_eq!(query(r, "expandSecretReferences").as_deref(), Some("false"));
    // no folder "DB_": key prefix inside the parent
    let names: Vec<String> = p
        .list(Some("DB_"))
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(names, vec!["DB_X"]);
    // a missing folder with a trailing slash, or a missing parent: empty
    assert!(p.list(Some("nope/")).await.unwrap().is_empty());
    assert!(p.list(Some("nope/deeper/K")).await.unwrap().is_empty());
    assert_eq!(p.list(None).await.unwrap().len(), 2);

    let all = p.get_all(Some("app")).await.unwrap();
    assert_eq!(
        all.names().collect::<Vec<_>>(),
        vec!["app/A", "app/B", "app/P"]
    );
    assert_eq!(all.get("app/A").unwrap().version(), Some("2"));
    let root = p.get_all(None).await.unwrap();
    assert_eq!(
        root.names().collect::<Vec<_>>(),
        vec!["DB_X", "IMPORTED", "OTHER"]
    );
    assert_eq!(root.get("DB_X").unwrap().reveal().unwrap(), "x");
    assert!(p.get_all(Some("missing")).await.unwrap().is_empty());

    // load_env of the generic provider API uses get_all
    let mut sink = std::collections::HashMap::new();
    let set = sdk::secrets::load_env_into(
        &p,
        &EnvSource::Path("app".into()),
        &LoadEnvOptions {
            prefix: "X_".into(),
            ..Default::default()
        },
        &mut sink,
    )
    .await
    .unwrap();
    assert_eq!(set.len(), 3);

    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v4/secrets",
        "listSecrets.403noMembership",
    )
    .await;
    let p = client(&server).secrets();
    assert!(p.list(None).await.is_err());
    assert!(p.get_all(None).await.is_err());
}

#[tokio::test]
async fn set_creates_updates_and_makes_folders() {
    let server = MockServer::start().await;
    let created = json!({"secret": secret("KEY", "", "/a/b", 1)});
    let updated = json!({"secret": secret("KEY", "", "/a/b", 2)});
    Mock::given(method("POST"))
        .and(path("/api/v4/secrets/KEY"))
        .respond_with(reply("createSecret.folderMissing404"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/secrets/KEY"))
        .respond_with(json(200, created))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on(
        &server,
        "POST",
        "/api/v4/secrets/KEY",
        "createSecret.duplicate400",
    )
    .await;
    on_reply(&server, "PATCH", "/api/v4/secrets/KEY", json(200, updated)).await;
    Mock::given(method("POST"))
        .and(path("/api/v2/folders"))
        .respond_with(reply("createFolder.duplicate400"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on(&server, "POST", "/api/v2/folders", "createFolder.ok").await;
    on_reply(
        &server,
        "GET",
        "/api/v1/projects/proj-1/tags",
        json(200, json!({"tags": [{"id": "t-old", "slug": "old"}]})),
    )
    .await;
    on_reply(
        &server,
        "POST",
        "/api/v1/projects/proj-1/tags",
        json(200, json!({"tag": {"id": "t-new", "slug": "new"}})),
    )
    .await;
    let p = client(&server).secrets();
    let opts = SetOptions {
        description: Some("desc".into()),
        tags: BTreeMap::from([
            ("old".to_owned(), "x".to_owned()),
            ("new".to_owned(), "#123456".to_owned()),
        ]),
        ..Default::default()
    };
    assert_eq!(
        p.set("a/b/KEY", "v1".into(), Some(&opts)).await.unwrap(),
        "1"
    );
    let folders = sent(&server, "/api/v2/folders").await;
    assert_eq!(folders.len(), 2);
    assert_eq!(
        (folders[0]["name"].as_str(), folders[0]["path"].as_str()),
        (Some("a"), Some("/"))
    );
    assert_eq!(
        (folders[1]["name"].as_str(), folders[1]["path"].as_str()),
        (Some("b"), Some("/a"))
    );
    let tag_post = &sent(&server, "/api/v1/projects/proj-1/tags").await[0];
    assert_eq!(tag_post["color"], "#123456");
    let create = &sent(&server, "/api/v4/secrets/KEY").await[1];
    assert_eq!(create["secretPath"], "/a/b");
    assert_eq!(create["secretComment"], "desc");
    assert_eq!(create["tagIds"], json!(["t-new", "t-old"]));
    // exists → update
    assert_eq!(
        p.set("a/b/KEY", json!({"k": 1}).into(), Some(&opts))
            .await
            .unwrap(),
        "2"
    );
    let upd = &sent(&server, "/api/v4/secrets/KEY").await[3];
    assert_eq!(upd["secretValue"], "{\"k\":1}");
    assert_eq!(upd["secretComment"], "desc");
    p.set("a/b/KEY", "v3".into(), None).await.unwrap();
    let upd = &sent(&server, "/api/v4/secrets/KEY").await[5];
    assert!(upd.get("secretComment").is_none());

    let cas = SetOptions {
        cas: Some(1),
        ..Default::default()
    };
    assert_eq!(
        p.set("K", "v".into(), Some(&cas)).await.unwrap_err().code(),
        ErrorCode::Unsupported
    );
    assert_eq!(
        p.set("K", vec![0xff_u8].into(), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    assert!(p.set("", "v".into(), None).await.is_err());

    // a failing folder creation is reported
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/api/v4/secrets/KEY",
        "createSecret.folderMissing404",
    )
    .await;
    on(&server, "POST", "/api/v2/folders", "createFolder.422").await;
    let p = client(&server).secrets();
    assert_eq!(
        p.set("x/KEY", "v".into(), None).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    // tag listing errors are reported
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/api/v1/projects/proj-1/tags",
        "listSecrets.403noMembership",
    )
    .await;
    let p = client(&server).secrets();
    let tagged = SetOptions {
        tags: BTreeMap::from([("t".to_owned(), String::new())]),
        ..Default::default()
    };
    assert!(p.set("K", "v".into(), Some(&tagged)).await.is_err());
    // tag creation errors are reported
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/api/v1/projects/proj-1/tags",
        json(200, json!({"tags": []})),
    )
    .await;
    on(
        &server,
        "POST",
        "/api/v1/projects/proj-1/tags",
        "createTag.422",
    )
    .await;
    let p = client(&server).secrets();
    assert!(p.set("K", "v".into(), Some(&tagged)).await.is_err());
}

#[tokio::test]
async fn delete() {
    let server = MockServer::start().await;
    on(&server, "DELETE", "/api/v4/secrets/KEY", "deleteSecret.ok").await;
    on(
        &server,
        "DELETE",
        "/api/v4/secrets/GONE",
        "deleteSecret.404",
    )
    .await;
    let p = client(&server).secrets();
    p.delete("dir/KEY", None).await.unwrap();
    assert_eq!(
        sent(&server, "/api/v4/secrets/KEY").await[0]["secretPath"],
        "/dir"
    );
    p.delete(
        "KEY",
        Some(&DeleteOptions {
            path: Some("/elsewhere".into()),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        sent(&server, "/api/v4/secrets/KEY").await[1]["secretPath"],
        "/elsewhere"
    );
    assert_eq!(
        p.delete("GONE", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    for opts in [
        DeleteOptions {
            versions: vec!["1".into()],
            ..Default::default()
        },
        DeleteOptions {
            permanent: true,
            ..Default::default()
        },
    ] {
        assert_eq!(
            p.delete("KEY", Some(&opts)).await.unwrap_err().code(),
            ErrorCode::Unsupported
        );
    }
    assert!(p.delete("", None).await.is_err());
    assert!(p.delete("dir/", None).await.is_err());
}

#[tokio::test]
async fn watch_and_cache() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/secrets/W"))
        .respond_with(json(200, json!({"secret": secret("W", "w1", "/", 1)})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/secrets/W"))
        .respond_with(json(200, json!({"secret": secret("W", "w2", "/", 2)})))
        .mount(&server)
        .await;
    let c = client(&server);
    let p = c.secrets();
    let changes = Arc::new(AtomicU32::new(0));
    let seen = changes.clone();
    let h = p.watch(
        "W",
        Duration::from_millis(30),
        move |new, old| {
            if new.and_then(|v| v.version()) == Some("2") && old.is_some() {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        },
        WatchOptions::default(),
    );
    for _ in 0..100 {
        if changes.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(changes.load(Ordering::SeqCst) > 0);
    let cache = SecretCache::new(Arc::new(p.clone()));
    assert!(cache.exists("W", None).await.unwrap());
    // closing the client stops the watch
    c.close().await;
    for _ in 0..50 {
        if h.is_stopped() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(h.is_stopped());
    // a stopped handle ends its supervisor too
    let c = client(&server);
    let h = c.secrets().watch(
        "W",
        Duration::from_secs(60),
        |_, _| {},
        WatchOptions::default(),
    );
    h.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(h.is_stopped());
}
