# Secrets API

The raw Infisical secrets API: one call per endpoint, Infisical's own fields (`key`, `version`,
`comment`, `tags`, `metadata`, `type`, `secretPath`). For typed reads, caching and watching use the
[SecretsProvider](secrets-provider.md) instead.

The SDK uses the **v4** routes (`/api/v4/secrets`) and switches to the deprecated **v3 `raw`**
routes only when the server answers 404 `Route … not found` (servers older than v4). The detected
version is kept per client (`client.apiVersion("secrets")`); `apiVersion: "v3"` forces v3. On v3
every read flag is sent explicitly, because the v3 defaults differ (no reference expansion, no
imports).

| Function | Endpoint (v4) | Notes |
| - | - | - |
| `listSecrets({projectId, environment, secretPath, recursive, expandReferences, includeImports, tagSlugs, viewSecretValue, includePersonalOverrides})` | `GET /api/v4/secrets` | references expanded and imports included by default; `tagSlugs` filters; missing path or environment → `NOT_FOUND`; returns `secrets` + `imports` (`merged()` gives the effective key → secret map) |
| `getSecret(name, {version, type, secretPath, expandReferences, includeImports, viewSecretValue})` | `GET /api/v4/secrets/{name}` | `type: personal` reads the caller's override (user tokens); an unknown version → `NOT_FOUND` |
| `createSecret(name, value, {comment, tagIds, tagSlugs, type, skipMultilineEncoding, metadata})` | `POST /api/v4/secrets/{name}` | folders are not created (`NOT_FOUND`); existing key → `CONFLICT`; the server trims the value |
| `updateSecret(name, {value, newName, comment, tagIds, tagSlugs, type, skipMultilineEncoding, metadata})` | `PATCH /api/v4/secrets/{name}` | only given fields change; tags replace the set; every update bumps the version |
| `deleteSecret(name, {type})` | `DELETE /api/v4/secrets/{name}` | deletes every version; missing → `NOT_FOUND` |
| `createSecrets(secrets[], scope)` | `POST /api/v4/secrets/batch` | atomic; one existing key → `CONFLICT` for the whole batch |
| `updateSecrets(secrets[], {mode})` | `PATCH /api/v4/secrets/batch` | `mode`: `failOnNotFound` (default), `upsert`, `ignore` |
| `deleteSecrets(keys[], scope)` | `DELETE /api/v4/secrets/batch` | atomic; missing key → `NOT_FOUND` |
| `listSecretVersions(secretId, {offset, limit})` | `GET /api/v1/secret/{id}/secret-versions` | newest first; **user tokens only** — machine identities get `PERMISSION_DENIED` |

`tagSlugs` on create/update are resolved to ids with one `listTags` call (an unknown slug is
`NOT_FOUND`) and merged with `tagIds`. `metadata` is a key → value map in every language (sent as
Infisical's `secretMetadata` list). References use Infisical's syntax: `${KEY}` (same folder),
`${env.path.KEY}` (other environment or folder).

## Create, read, update, delete

=== "TypeScript"

    ```ts
    const created = await client.secrets.createSecret("DB_PASSWORD", "s3cret", {
      secretPath: "/app",
      comment: "primary database",
      tagSlugs: ["database"],
      metadata: { owner: "team-a" },
    });
    const secret = await client.secrets.getSecret("DB_PASSWORD", { secretPath: "/app" });
    console.log(secret.version, secret.value.reveal());
    await client.secrets.updateSecret("DB_PASSWORD", { secretPath: "/app", value: "rotated" });
    const old = await client.secrets.getSecret("DB_PASSWORD", { secretPath: "/app", version: 1 });
    const list = await client.secrets.listSecrets({ secretPath: "/app", recursive: true });
    await client.secrets.deleteSecret("DB_PASSWORD", { secretPath: "/app" });
    ```

=== "Rust"

    ```rust
    use std::collections::BTreeMap;
    use grow_infisical::{CreateSecretOptions, GetSecretOptions, ListSecretsOptions, UpdateSecretOptions};

    let created = client.create_secret("DB_PASSWORD", "s3cret", Some(&CreateSecretOptions {
        secret_path: Some("/app".into()),
        comment: Some("primary database".into()),
        tag_slugs: Some(vec!["database".into()]),
        metadata: BTreeMap::from([("owner".into(), "team-a".into())]),
        ..Default::default()
    })).await?;
    let at_app = GetSecretOptions { secret_path: Some("/app".into()), ..Default::default() };
    let secret = client.get_secret("DB_PASSWORD", Some(&at_app)).await?;
    println!("{} {}", secret.version, secret.value.reveal());
    client.update_secret("DB_PASSWORD", Some(&UpdateSecretOptions {
        secret_path: Some("/app".into()),
        value: Some("rotated".into()),
        ..Default::default()
    })).await?;
    let old = client.get_secret("DB_PASSWORD", Some(&GetSecretOptions { version: Some(1), ..at_app })).await?;
    let list = client.list_secrets(Some(&ListSecretsOptions {
        secret_path: Some("/app".into()), recursive: true, ..Default::default()
    })).await?;
    client.delete_secret("DB_PASSWORD", None).await?; // config secret_path
    ```

=== "Go"

    ```go
    created, err := client.CreateSecret(ctx, "DB_PASSWORD", "s3cret", &infisical.CreateSecretOptions{
        SecretPath: "/app",
        Comment:    "primary database",
        TagSlugs:   []string{"database"},
        Metadata:   map[string]string{"owner": "team-a"},
    })
    secret, err := client.GetSecret(ctx, "DB_PASSWORD", &infisical.GetSecretOptions{SecretPath: "/app"})
    fmt.Println(secret.Version, secret.Value.Reveal())
    _, err = client.UpdateSecret(ctx, "DB_PASSWORD", &infisical.UpdateSecretOptions{
        SecretPath: "/app", Value: infisical.String("rotated"),
    })
    old, err := client.GetSecret(ctx, "DB_PASSWORD", &infisical.GetSecretOptions{SecretPath: "/app", Version: 1})
    list, err := client.ListSecrets(ctx, &infisical.ListSecretsOptions{SecretPath: "/app", Recursive: true})
    _, err = client.DeleteSecret(ctx, "DB_PASSWORD", &infisical.DeleteSecretOptions{SecretPath: "/app"})
    ```

=== "Python"

    ```python
    created = client.secrets.create_secret(
        "DB_PASSWORD", "s3cret", secret_path="/app", comment="primary database",
        tag_slugs=["database"], metadata={"owner": "team-a"},
    )
    secret = client.secrets.get_secret("DB_PASSWORD", secret_path="/app")
    print(secret.version, secret.value.reveal())
    client.secrets.update_secret("DB_PASSWORD", secret_path="/app", value="rotated")
    old = client.secrets.get_secret("DB_PASSWORD", secret_path="/app", version=1)
    listed = client.secrets.list_secrets(secret_path="/app", recursive=True)
    client.secrets.delete_secret("DB_PASSWORD", secret_path="/app")
    ```

=== "Java"

    ```java
    SecretEntry created = client.createSecret("DB_PASSWORD", "s3cret",
        CreateSecretOptions.builder()
            .secretPath("/app")
            .comment("primary database")
            .tagSlugs(List.of("database"))
            .metadata(Map.of("owner", "team-a"))
            .build());
    SecretEntry secret = client.getSecret("DB_PASSWORD",
        GetSecretOptions.builder().secretPath("/app").build());
    System.out.println(secret.version() + " " + secret.value().reveal());
    client.updateSecret("DB_PASSWORD",
        UpdateSecretOptions.builder().secretPath("/app").value("rotated").build());
    SecretEntry old = client.getSecret("DB_PASSWORD",
        GetSecretOptions.builder().secretPath("/app").version(1).build());
    SecretList list = client.listSecrets(
        ListSecretsOptions.builder().secretPath("/app").recursive(true).build());
    client.deleteSecret("DB_PASSWORD",
        DeleteSecretOptions.builder().secretPath("/app").build());
    ```

## Batch calls and versions

=== "TypeScript"

    ```ts
    await client.secrets.createSecrets([
      { key: "A", value: "1" },
      { key: "B", value: "2", comment: "second" },
    ]);
    await client.secrets.updateSecrets([{ key: "A", value: "10" }], { mode: "upsert" });
    await client.secrets.deleteSecrets(["A", "B"]);
    // user tokens only
    const versions = await client.secrets.listSecretVersions(secret.id, { limit: 10 });
    ```

=== "Rust"

    ```rust
    use grow_infisical::{BatchUpdateMode, SecretInput, SecretUpdate, UpdateSecretsOptions};

    client.create_secrets(&[SecretInput::new("A", "1"), SecretInput::new("B", "2")], None).await?;
    client.update_secrets(&[SecretUpdate::new("A", "10")], Some(&UpdateSecretsOptions {
        mode: Some(BatchUpdateMode::Upsert), ..Default::default()
    })).await?;
    client.delete_secrets(&["A", "B"], None).await?;
    let versions = client.list_secret_versions(&secret.id, None).await?; // user tokens only
    ```

=== "Go"

    ```go
    _, err = client.CreateSecrets(ctx, []infisical.SecretInput{{Key: "A", Value: "1"}, {Key: "B", Value: "2"}}, nil)
    _, err = client.UpdateSecrets(ctx, []infisical.SecretUpdate{{Key: "A", Value: infisical.String("10")}},
        &infisical.UpdateSecretsOptions{Mode: infisical.BatchModeUpsert})
    _, err = client.DeleteSecrets(ctx, []string{"A", "B"}, nil)
    versions, err := client.ListSecretVersions(ctx, secret.ID, &infisical.ListSecretVersionsOptions{Limit: 10})
    ```

=== "Python"

    ```python
    client.secrets.create_secrets([sdk.BatchCreateSecret("A", "1"), sdk.BatchCreateSecret("B", "2")])
    client.secrets.update_secrets([sdk.BatchUpdateSecret("A", value="10")], mode="upsert")
    client.secrets.delete_secrets(["A", "B"])
    versions = client.secrets.list_secret_versions(secret.id, limit=10)  # user tokens only
    ```

=== "Java"

    ```java
    client.createSecrets(List.of(SecretInput.of("A", "1"), SecretInput.of("B", "2")), null);
    client.updateSecrets(List.of(SecretUpdate.of("A", "10")),
        UpdateSecretsOptions.builder().mode(BatchUpdateMode.UPSERT).build());
    client.deleteSecrets(List.of("A", "B"), null);
    List<SecretVersion> versions = client.listSecretVersions(secret.id(),
        ListSecretVersionsOptions.builder().limit(10).build()); // user tokens only
    ```

Every I/O call has an async form: TypeScript returns promises, Rust is `async` (or the `blocking`
feature), Python has `AsyncInfisicalClient` (`await client.secrets.get_secret(…)`) and Java has
`…Async` variants returning `CompletableFuture`.
