//! Integration tests: every public function of the crate is called against the real
//! Infisical from docker/compose.yml with a round-trip assertion.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use grow_infisical as sdk;
use grow_infisical_integration::load_bootstrap_env;
use sdk::secrets::{GetOptions, SecretCache, SecretsProvider, SetOptions, WatchOptions};
use sdk::{
    ApiVersion, AwsIamAuth, BatchScope, BatchUpdateMode, CreateFolderOptions,
    CreateSecretImportOptions, CreateSecretOptions, DeleteFolderOptions, DeleteSecretOptions,
    EnvOptions, ErrorCode, GetSecretOptions, InfisicalClient as Client, InfisicalConfig as Config,
    InfisicalConfigBuilder, KubernetesAuth, ListFoldersOptions, ListProjectsOptions,
    ListSecretVersionsOptions, ListSecretsOptions, SecretImportOptions, SecretInput, SecretType,
    SecretUpdate, SecretsProviderOptions, TokenAuth, UniversalAuth, UpdateFolderOptions,
    UpdateSecretOptions, UpdateSecretsOptions,
};

struct Fx {
    run: String,
    key: String,
    project: String,
    env: String,
    c: Client,
}

fn must(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} missing from the bootstrap environment"))
}

fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{:08x}",
        (nanos as u64 ^ u64::from(std::process::id())) & 0xffff_ffff
    )
}

fn setup() -> Fx {
    load_bootstrap_env();
    let run = run_id();
    Fx {
        key: format!("SDKRS_{}_", run.to_uppercase()),
        run,
        project: must("INFISICAL_PROJECT_ID"),
        env: must("INFISICAL_ENVIRONMENT"),
        c: Client::from_env().expect("client from env"),
    }
}

/// A client for the same server with another auth (Universal Auth credentials removed).
fn client_with(f: impl FnOnce(InfisicalConfigBuilder) -> InfisicalConfigBuilder) -> Client {
    let b = Config::builder().client_id("").client_secret("");
    Client::new(f(b).build_from_env().expect("config")).expect("client")
}

fn code<T: std::fmt::Debug>(r: sdk::Result<T>, want: ErrorCode) {
    match r {
        Err(e) => assert_eq!(e.code(), want, "{e}"),
        Ok(v) => panic!("want {want:?}, got Ok({v:?})"),
    }
}

#[tokio::test]
async fn core_client() {
    let f = setup();
    let h = f.c.health().await.unwrap();
    assert!(h.healthy && h.status == "ok", "{h:?}");
    assert!(f.c.ping().await.unwrap() > Duration::ZERO);
    code(f.c.server_version().await, ErrorCode::Unsupported);
    assert_eq!(f.c.config().project_id(), Some(f.project.as_str()));
    assert_eq!(f.c.config().environment(), Some(f.env.as_str()));
    assert!(!format!("{:?}", f.c.config()).contains(&must("INFISICAL_CLIENT_SECRET")));
    f.c.get_secret(&must("INFISICAL_SEED_SECRET_NAME"), None)
        .await
        .unwrap();
    assert_eq!(f.c.api_version("secrets"), "v4");
    f.c.close().await;
    f.c.close().await;
    assert!(f.c.is_closed());
}

#[tokio::test]
async fn auth_methods() {
    let f = setup();
    let seed = must("INFISICAL_SEED_SECRET_NAME");
    let seed_value = must("INFISICAL_SEED_SECRET_VALUE");

    // universal auth through the token manager
    let a = f.c.auth();
    assert!(format!("{:?}", a.method().unwrap()).contains("UniversalAuth"));
    let tok = a.login().await.unwrap();
    assert!(
        !tok.token.is_empty() && tok.expires_in > Duration::ZERO && tok.max_ttl >= tok.expires_in
    );
    let renewed = a.renew().await.unwrap();
    assert_eq!(a.token().await.unwrap().token, renewed.token);
    let old = a.token().await.unwrap().token;
    a.revoke().await.unwrap();
    assert!(a.token().await.is_none());
    let stale = client_with(|b| b.token(old.clone()));
    code(stale.ping().await, ErrorCode::Authentication);
    let s = f.c.get_secret(&seed, None).await.unwrap();
    assert_eq!(s.value.reveal(), seed_value, "automatic re-login");
    a.set_token(old).await;
    f.c.ping().await.expect("SetToken + 401 re-login");

    // UniversalAuth methods
    let ua = UniversalAuth::new(must("INFISICAL_CLIENT_ID"), must("INFISICAL_CLIENT_SECRET"));
    let t = ua.login(&f.c).await.unwrap();
    let t2 = ua.renew(&f.c, &t.token).await.unwrap();
    assert!(t2.expires_in > Duration::ZERO);
    ua.revoke(&f.c, &t2.token).await.unwrap();
    code(ua.renew(&f.c, &t2.token).await, ErrorCode::Authentication);
    // one wrong secret (lockout is disabled for the test identity)
    let bad = client_with(|b| {
        b.auth(UniversalAuth::new(
            must("INFISICAL_CLIENT_ID"),
            format!("wrong-secret-{}", f.run),
        ))
    });
    code(bad.ping().await, ErrorCode::Authentication);

    // token auth kinds
    for name in [
        "INFISICAL_VIEWER_TOKEN",
        "INFISICAL_SERVICE_TOKEN",
        "INFISICAL_USER_TOKEN",
    ] {
        let c = client_with(|b| b.auth(TokenAuth::new(must(name))));
        c.ping()
            .await
            .unwrap_or_else(|e| panic!("{name} ping: {e}"));
        let s = c.get_secret(&seed, None).await.unwrap();
        assert_eq!(s.value.reveal(), seed_value, "{name}");
    }
    let malformed = client_with(|b| b.token(format!("not-a-token-{}", f.run)));
    code(malformed.ping().await, ErrorCode::Authentication);
    let no_access = client_with(|b| b.token(must("INFISICAL_NOACCESS_TOKEN")));
    code(
        no_access.list_secrets(None).await,
        ErrorCode::PermissionDenied,
    );

    // kubernetes and AWS request shapes (no Kubernetes API / STS in the fixture)
    let id = must("INFISICAL_NOACCESS_IDENTITY_ID");
    let e = sdk::AuthMethod::login(
        &KubernetesAuth::new(&id).jwt("eyJhbGciOiJSUzI1NiJ9.e30.sig"),
        &f.c,
    )
    .await
    .unwrap_err();
    assert!(
        e.code() == ErrorCode::NotFound && e.message().contains("Kubernetes auth method not found"),
        "{e}"
    );
    let aws = AwsIamAuth::new(&id)
        .region("us-east-1")
        .credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    assert!(!aws.login_request().unwrap().iam_request_headers.is_empty());
    let e = sdk::AuthMethod::login(&aws, &f.c).await.unwrap_err();
    assert!(
        e.code() == ErrorCode::NotFound && e.message().contains("AWS auth method not found"),
        "{e}"
    );

    // revoke on close
    let rc = Client::new(
        Config::builder()
            .revoke_on_close(true)
            .build_from_env()
            .unwrap(),
    )
    .unwrap();
    rc.ping().await.unwrap();
    let tok = rc.auth().token().await.unwrap().token;
    rc.close().await;
    code(
        client_with(|b| b.token(tok)).ping().await,
        ErrorCode::Authentication,
    );
}

#[tokio::test]
async fn secrets_crud() {
    let f = setup();
    let c = &f.c;
    let k = format!("{}ONE", f.key);
    let tag = c
        .create_tag(&format!("rs-{}", f.run), "#00aa00", None)
        .await
        .unwrap();

    let created = c
        .create_secret(
            &k,
            &format!("v1-{}", f.run),
            Some(&CreateSecretOptions {
                comment: Some("c1".into()),
                tag_slugs: Some(vec![tag.slug.clone()]),
                metadata: BTreeMap::from([("owner".to_owned(), "rust".to_owned())]),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(created.version, 1);
    let got = c.get_secret(&k, None).await.unwrap();
    assert_eq!(got.value.reveal(), format!("v1-{}", f.run));
    assert_eq!(got.comment, "c1");
    assert_eq!(got.tags.len(), 1);
    assert_eq!(got.tags[0].slug, tag.slug);
    code(c.create_secret(&k, "dup", None).await, ErrorCode::Conflict);

    c.update_secret(
        &k,
        Some(&UpdateSecretOptions {
            value: Some(format!("v2-{}", f.run)),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let got = c.get_secret(&k, None).await.unwrap();
    assert_eq!(
        (got.value.reveal(), got.version),
        (format!("v2-{}", f.run).as_str(), 2)
    );
    let old = c
        .get_secret(
            &k,
            Some(&GetSecretOptions {
                version: Some(1),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(old.value.reveal(), format!("v1-{}", f.run));
    let renamed = format!("{}RENAMED", f.key);
    c.update_secret(
        &k,
        Some(&UpdateSecretOptions {
            new_name: Some(renamed.clone()),
            comment: Some("c2".into()),
            tag_ids: Some(vec![]),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let got = c.get_secret(&renamed, None).await.unwrap();
    assert!(
        got.comment == "c2" && got.tags.is_empty() && got.value.reveal() == format!("v2-{}", f.run)
    );
    code(c.get_secret(&k, None).await, ErrorCode::NotFound);

    let list = c.list_secrets(None).await.unwrap();
    assert!(list.secrets.iter().any(|s| s.key == renamed));
    c.update_secret(
        &renamed,
        Some(&UpdateSecretOptions {
            tag_slugs: Some(vec![tag.slug.clone()]),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let tagged = c
        .list_secrets(Some(&ListSecretsOptions {
            tag_slugs: vec![tag.slug.clone()],
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(tagged.secrets.len(), 1);
    assert_eq!(tagged.secrets[0].key, renamed);
    let hidden = c
        .get_secret(
            &renamed,
            Some(&GetSecretOptions {
                view_secret_value: Some(false),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert!(hidden.value_hidden);

    // references: expanded by default, raw on request
    let (host, dsn) = (format!("{}HOST", f.key), format!("{}DSN", f.key));
    c.create_secret(&host, "db.local", None).await.unwrap();
    c.create_secret(&dsn, &format!("pg://${{{host}}}/x"), None)
        .await
        .unwrap();
    assert_eq!(
        c.get_secret(&dsn, None).await.unwrap().value.reveal(),
        "pg://db.local/x"
    );
    let raw = c
        .get_secret(
            &dsn,
            Some(&GetSecretOptions {
                expand_references: Some(false),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(raw.value.reveal(), format!("pg://${{{host}}}/x"));

    for name in [&renamed, &host, &dsn] {
        c.delete_secret(name, None).await.unwrap();
    }
    code(c.get_secret(&renamed, None).await, ErrorCode::NotFound);
    code(c.delete_secret(&renamed, None).await, ErrorCode::NotFound);
    c.delete_tag(&tag.id, None).await.unwrap();
}

#[tokio::test]
async fn secrets_batch() {
    let f = setup();
    let c = &f.c;
    let (a, b, up) = (
        format!("{}BA", f.key),
        format!("{}BB", f.key),
        format!("{}UP", f.key),
    );
    let mut bb = SecretInput::new(&b, "b1");
    bb.comment = Some("cb".into());
    let out = c
        .create_secrets(&[SecretInput::new(&a, "a1"), bb], None)
        .await
        .unwrap();
    assert_eq!(out.len(), 2);
    let s = c.get_secret(&b, None).await.unwrap();
    assert!(s.value.reveal() == "b1" && s.comment == "cb");
    code(
        c.create_secrets(&[SecretInput::new(&a, "dup")], None).await,
        ErrorCode::Conflict,
    );
    c.update_secrets(&[SecretUpdate::new(&a, "a2")], None)
        .await
        .unwrap();
    assert_eq!(c.get_secret(&a, None).await.unwrap().value.reveal(), "a2");
    code(
        c.update_secrets(&[SecretUpdate::new(&up, "u")], None).await,
        ErrorCode::NotFound,
    );
    c.update_secrets(
        &[SecretUpdate::new(&up, "u")],
        Some(&UpdateSecretsOptions {
            mode: Some(BatchUpdateMode::Upsert),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(c.get_secret(&up, None).await.unwrap().value.reveal(), "u");
    c.delete_secrets(&[&a, &b, &up], None).await.unwrap();
    let list = c.list_secrets(None).await.unwrap();
    assert!(!list.secrets.iter().any(|s| s.key.starts_with(&f.key)));
    code(c.delete_secrets(&[&a], None).await, ErrorCode::NotFound);
}

#[tokio::test]
async fn secrets_v3_forced() {
    let f = setup();
    let v3 = Client::new(
        Config::builder()
            .api_version(ApiVersion::V3)
            .build_from_env()
            .unwrap(),
    )
    .unwrap();
    let k = format!("{}V3", f.key);
    v3.create_secret(&k, "r1", None).await.unwrap();
    assert_eq!(v3.get_secret(&k, None).await.unwrap().value.reveal(), "r1");
    v3.update_secret(
        &k,
        Some(&UpdateSecretOptions {
            value: Some("r2".into()),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let list = v3.list_secrets(None).await.unwrap();
    assert!(list
        .secrets
        .iter()
        .any(|s| s.key == k && s.value.reveal() == "r2"));
    v3.delete_secret(&k, None).await.unwrap();
    let kb = format!("{k}B");
    v3.create_secrets(&[SecretInput::new(&kb, "x")], None)
        .await
        .unwrap();
    v3.update_secrets(&[SecretUpdate::new(&kb, "y")], None)
        .await
        .unwrap();
    assert_eq!(f.c.get_secret(&kb, None).await.unwrap().value.reveal(), "y");
    v3.delete_secrets(&[&kb], None).await.unwrap();
    assert_eq!(v3.api_version("secrets"), "v3");
}

#[tokio::test]
async fn personal_secrets_and_versions() {
    let f = setup();
    let user = client_with(|b| b.token(must("INFISICAL_USER_TOKEN")));
    let k = format!("{}PERS", f.key);
    let shared = f.c.create_secret(&k, "shared-1", None).await.unwrap();
    f.c.update_secret(
        &k,
        Some(&UpdateSecretOptions {
            value: Some("shared-2".into()),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let vs = user
        .list_secret_versions(
            &shared.id,
            Some(&ListSecretVersionsOptions {
                offset: 0,
                limit: Some(10),
            }),
        )
        .await
        .unwrap();
    assert_eq!(vs.len(), 2);
    assert_eq!(vs[0].version, 2);
    assert_eq!(vs[0].value.reveal(), "shared-2");
    assert_eq!(vs[1].value.reveal(), "shared-1");
    code(
        f.c.list_secret_versions(&shared.id, None).await,
        ErrorCode::PermissionDenied,
    );

    user.create_secret(
        &k,
        "mine",
        Some(&CreateSecretOptions {
            secret_type: Some(SecretType::Personal),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let s = user
        .get_secret(
            &k,
            Some(&GetSecretOptions {
                secret_type: Some(SecretType::Personal),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert!(s.value.reveal() == "mine" && s.secret_type == SecretType::Personal);
    let ov = user
        .list_secrets(Some(&ListSecretsOptions {
            include_personal_overrides: true,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(ov
        .secrets
        .iter()
        .any(|s| s.key == k && s.value.reveal() == "mine"));
    user.delete_secret(
        &k,
        Some(&DeleteSecretOptions {
            secret_type: Some(SecretType::Personal),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        f.c.get_secret(&k, None).await.unwrap().value.reveal(),
        "shared-2"
    );
    code(
        f.c.create_secret(
            &format!("{k}X"),
            "x",
            Some(&CreateSecretOptions {
                secret_type: Some(SecretType::Personal),
                ..Default::default()
            }),
        )
        .await,
        ErrorCode::Validation,
    );
    f.c.delete_secret(&k, None).await.unwrap();
}

#[tokio::test]
async fn folders() {
    let f = setup();
    let c = &f.c;
    let name = format!("rs-{}", f.run);
    let folder = c
        .create_folder(
            &name,
            Some(&CreateFolderOptions {
                path: Some("/".into()),
                description: Some("d".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(folder.path, format!("/{name}"));
    c.create_folder(
        "child",
        Some(&CreateFolderOptions {
            path: Some(format!("/{name}")),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let fs = c
        .list_folders(Some(&ListFoldersOptions {
            path: Some(format!("/{name}")),
            recursive: true,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(fs.len(), 1);
    assert_eq!(fs[0].name, "child");
    code(c.create_folder(&name, None).await, ErrorCode::Conflict);
    code(
        c.create_folder("bad name!", None).await,
        ErrorCode::Validation,
    );
    c.update_folder(
        &folder.id,
        &UpdateFolderOptions {
            path: Some("/".into()),
            name: format!("{name}-r"),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let root = c.list_folders(None).await.unwrap();
    assert!(root.iter().any(|x| x.name == format!("{name}-r")));
    c.delete_folder(
        &folder.id,
        Some(&DeleteFolderOptions {
            path: Some("/".into()),
            force: true,
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let root = c.list_folders(None).await.unwrap();
    assert!(!root.iter().any(|x| x.id == folder.id));
    code(c.delete_folder(&folder.id, None).await, ErrorCode::NotFound);
}

#[tokio::test]
async fn projects_environments_tags() {
    let f = setup();
    let c = &f.c;
    let page = c
        .list_projects(Some(&ListProjectsOptions {
            limit: Some(100),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(page.total_count >= 1 && page.projects.iter().any(|p| p.id == f.project));
    let p = c.get_project(None).await.unwrap();
    assert_eq!(p.id, f.project);
    assert_eq!(p.slug, must("INFISICAL_PROJECT_SLUG"));
    assert_eq!(c.get_project_by_slug(&p.slug).await.unwrap().id, p.id);
    let slug = format!("rs-{}", f.run);
    let created = c
        .create_environment(&format!("Rust {}", f.run), &slug, None)
        .await
        .unwrap();
    assert_eq!(created.slug, slug);
    let envs = c.list_environments(None).await.unwrap();
    assert!(envs.iter().any(|e| e.slug == slug));
    assert!(envs
        .iter()
        .any(|e| e.slug == must("INFISICAL_ENVIRONMENT_STAGING")));
    code(
        c.create_environment("Dup", &slug, None).await,
        ErrorCode::Conflict,
    );
    let viewer = client_with(|b| b.token(must("INFISICAL_VIEWER_TOKEN")));
    code(
        viewer
            .create_environment("No", &format!("no-{}", f.run), None)
            .await,
        ErrorCode::PermissionDenied,
    );

    let tag_slug = format!("tag-{}", f.run);
    let tag = c.create_tag(&tag_slug, "", None).await.unwrap();
    let tags = c.list_tags(None).await.unwrap();
    assert!(tags.iter().any(|t| t.id == tag.id && t.slug == tag_slug));
    code(c.create_tag(&tag_slug, "", None).await, ErrorCode::Conflict);
    c.delete_tag(&tag.id, None).await.unwrap();
    let tags = c.list_tags(None).await.unwrap();
    assert!(!tags.iter().any(|t| t.id == tag.id));
}

#[tokio::test]
async fn imports_load_env_dotenv() {
    let f = setup();
    let c = &f.c;
    let folder_name = format!("imp-{}", f.run);
    let folder = format!("/{folder_name}");
    c.create_folder(&folder_name, None).await.unwrap();
    let (k1, k2) = (format!("{}E1", f.key), format!("{}E2", f.key));
    c.create_secrets(
        &[
            SecretInput::new(&k1, "one"),
            SecretInput::new(&k2, "two\nlines"),
        ],
        Some(&BatchScope {
            secret_path: Some(folder.clone()),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let staging = must("INFISICAL_ENVIRONMENT_STAGING");
    let imp = c
        .create_secret_import(&CreateSecretImportOptions {
            path: Some(folder.clone()),
            import_environment: staging.clone(),
            import_path: Some("/common".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let at = SecretImportOptions {
        path: Some(folder.clone()),
        ..Default::default()
    };
    let imps = c.list_secret_imports(Some(&at)).await.unwrap();
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].id, imp.id);
    assert_eq!(imps[0].import_environment.slug, staging);
    assert_eq!(imps[0].import_path, "/common");
    let list = c
        .list_secrets(Some(&ListSecretsOptions {
            secret_path: Some(folder.clone()),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(list.imports.len(), 1);
    assert_eq!(list.merged()["SDK_COMMON"].value.reveal(), "common-value-1");

    std::env::remove_var(&k1);
    std::env::set_var(&k2, "keep");
    let names = c
        .load_env(Some(&EnvOptions {
            secret_path: Some(folder.clone()),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(names.get(&k1) == Some(&k1) && !names.contains_key(&k2));
    assert_eq!(std::env::var(&k1).unwrap(), "one");
    assert_eq!(std::env::var(&k2).unwrap(), "keep");
    assert_eq!(std::env::var("SDK_COMMON").unwrap(), "common-value-1");
    for v in [&k1, &k2] {
        std::env::remove_var(v);
    }
    std::env::remove_var("SDK_COMMON");
    let mut sink: HashMap<String, String> = HashMap::new();
    let names = c
        .load_env_into(
            Some(&EnvOptions {
                secret_path: Some(folder.clone()),
                include_imports: Some(false),
                ..Default::default()
            }),
            &mut sink,
        )
        .await
        .unwrap();
    assert_eq!(
        names.into_keys().collect::<Vec<_>>(),
        vec![k1.clone(), k2.clone()]
    );
    assert_eq!(sink[&k2], "two\nlines");
    let doc = c
        .export_dotenv(Some(&EnvOptions {
            secret_path: Some(folder.clone()),
            include_imports: Some(false),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(doc, format!("{k1}=\"one\"\n{k2}=\"two\\nlines\"\n"));

    c.delete_secret_import(&imp.id, Some(&at)).await.unwrap();
    assert!(c.list_secret_imports(Some(&at)).await.unwrap().is_empty());
    code(
        c.delete_secret_import(&imp.id, Some(&at)).await,
        ErrorCode::NotFound,
    );
    c.delete_folder(
        &folder_name,
        Some(&DeleteFolderOptions {
            force: true,
            ..Default::default()
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn secrets_provider() {
    let f = setup();
    let base = format!("/prov-{}", f.run);
    let p = f.c.secrets_with(SecretsProviderOptions {
        base_path: Some(base.clone()),
        ..Default::default()
    });
    let tag = format!("prov-{}", f.run);
    let v = p
        .set(
            "db/PASSWORD",
            "pw-1".into(),
            Some(&SetOptions {
                description: Some("db password".into()),
                tags: BTreeMap::from([(tag.clone(), "#123456".to_owned())]),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(v, "1", "set creates folders");
    let v = p
        .set("db/PASSWORD", serde_json::json!({"k": "v"}).into(), None)
        .await
        .unwrap();
    assert_eq!(v, "2", "set updates");
    let obj = p.get_json("db/PASSWORD", None).await.unwrap().unwrap();
    assert_eq!(obj["k"], "v");
    let old = p
        .get(
            "db/PASSWORD",
            Some(&GetOptions {
                version: Some("1".into()),
                path: None,
            }),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old.reveal().unwrap(), "pw-1");
    let md = p.metadata("db/PASSWORD", None).await.unwrap().unwrap();
    assert_eq!(md.path.as_deref(), Some(format!("{base}/db").as_str()));
    assert_eq!(md.version.as_deref(), Some("2"));
    assert!(md.tags.contains_key(&tag));
    assert_eq!(md.extra["comment"], "db password");
    let mds = p.list(Some("db/")).await.unwrap();
    assert_eq!(mds.len(), 1);
    assert_eq!(mds[0].name, "db/PASSWORD");
    let all = p.get_all(Some("db")).await.unwrap();
    assert_eq!(all.names().collect::<Vec<_>>(), vec!["db/PASSWORD"]);
    let cache = SecretCache::new(Arc::new(p.clone()));
    assert!(cache.exists("db/PASSWORD", None).await.unwrap());

    let deleted = Arc::new(AtomicBool::new(false));
    let seen = deleted.clone();
    let h = p.watch(
        "db/PASSWORD",
        Duration::from_millis(200),
        move |new, _| {
            if new.is_none() {
                seen.store(true, Ordering::SeqCst);
            }
        },
        WatchOptions::default(),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    p.delete("db/PASSWORD", None).await.unwrap();
    for _ in 0..100 {
        if deleted.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(deleted.load(Ordering::SeqCst), "watch saw the deletion");
    h.stop();
    code(p.delete("db/PASSWORD", None).await, ErrorCode::NotFound);
    code(
        p.set("BIN", vec![0xff_u8].into(), None).await,
        ErrorCode::Validation,
    );
    for t in f.c.list_tags(None).await.unwrap() {
        if t.slug == tag {
            f.c.delete_tag(&t.id, None).await.unwrap();
        }
    }
    let _ =
        f.c.delete_folder(
            base.trim_start_matches('/'),
            Some(&DeleteFolderOptions {
                path: Some("/".into()),
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

/// GRO-1410: `load_config()` with the default connector reads `GROW_SECRETS_PATH`. The address
/// comes from `GROW_SECRETS_ADDR` (it wins over `GROW_INFISICAL_URL`), credentials, project and
/// environment from the package variables of the same environment (Universal Auth).
#[tokio::test]
async fn load_config_through_the_connector() {
    use sdk::secrets::{load_config, LoadOptions};
    let f = setup();
    let base = format!("lc-{}", f.run);
    let p = f.c.secrets();
    p.set(
        &format!("{base}/svc/DATABASE_URL"),
        "postgres://db".into(),
        None,
    )
    .await
    .unwrap();
    p.set(&format!("{base}/svc/LOG_LEVEL"), "debug".into(), None)
        .await
        .unwrap();
    let mut env: HashMap<String, String> = std::env::vars().collect();
    env.insert("GROW_SECRETS_PROVIDER".into(), "infisical".into());
    env.insert("GROW_SECRETS_ADDR".into(), must("GROW_INFISICAL_URL"));
    env.insert("GROW_SECRETS_PATH".into(), format!("{base}/svc"));
    env.insert("GROW_INFISICAL_URL".into(), "http://127.0.0.1:1".into());
    let values = load_config(LoadOptions {
        env: Some(env),
        required: vec!["DATABASE_URL".into()],
        into_env: false,
        ..LoadOptions::default()
    })
    .await
    .expect("load_config");
    assert_eq!(values.len(), 2, "{:?}", values.keys().collect::<Vec<_>>());
    assert_eq!(values["DATABASE_URL"], "postgres://db");
    assert_eq!(values["LOG_LEVEL"], "debug");
    let _ =
        f.c.delete_folder(
            &base,
            Some(&DeleteFolderOptions {
                path: Some("/".into()),
                force: true,
                ..Default::default()
            }),
        )
        .await;
}
