# Tags and secret imports

**Tags** label secrets inside a project (v1 API). **Secret imports** make the secrets of another
environment or folder visible in a folder (v2 API); `listSecrets` and `getSecret` include imported
secrets by default, and direct secrets win over imported ones.

| Function | Endpoint | Notes |
| - | - | - |
| `listTags({projectId})` | `GET /api/v1/projects/{id}/tags` | `id`, `slug`, `name`, `color` |
| `createTag(slug, color, {projectId})` | `POST /api/v1/projects/{id}/tags` | an existing slug → `CONFLICT`; empty color = server default |
| `deleteTag(tagId, {projectId})` | `DELETE /api/v1/projects/{id}/tags/{tagId}` | missing → `NOT_FOUND` |
| `listSecretImports({path})` | `GET /api/v2/secret-imports` | imports of a folder, in import order |
| `createSecretImport({path, importEnvironment, importPath, isReplication, sourceProjectId})` | `POST /api/v2/secret-imports` | the server accepts duplicates and missing source paths |
| `deleteSecretImport(importId, {path})` | `DELETE /api/v2/secret-imports/{id}` | missing → `NOT_FOUND` |

In Go, Rust and Java the tag calls take the project id as a plain argument (`ProjectOptions` in Go
and Java, `Option<&str>` in Rust); `nil`/`None`/`null` uses the config.

=== "TypeScript"

    ```ts
    const tag = await client.tags.createTag("database", "#00aa00");
    const tags = await client.tags.listTags();
    const imp = await client.imports.createSecretImport({
      path: "/app",
      importEnvironment: "staging",
      importPath: "/common",
    });
    const imports = await client.imports.listSecretImports({ path: "/app" });
    await client.imports.deleteSecretImport(imp.id, { path: "/app" });
    await client.tags.deleteTag(tag.id);
    ```

=== "Rust"

    ```rust
    use grow_infisical::{CreateSecretImportOptions, SecretImportOptions};

    let tag = client.create_tag("database", "#00aa00", None).await?;
    let tags = client.list_tags(None).await?;
    let imp = client.create_secret_import(&CreateSecretImportOptions {
        path: Some("/app".into()),
        import_environment: "staging".into(),
        import_path: Some("/common".into()),
        ..Default::default()
    }).await?;
    let at = SecretImportOptions { path: Some("/app".into()), ..Default::default() };
    let imports = client.list_secret_imports(Some(&at)).await?;
    client.delete_secret_import(&imp.id, Some(&at)).await?;
    client.delete_tag(&tag.id, None).await?;
    ```

=== "Go"

    ```go
    tag, err := client.CreateTag(ctx, "database", "#00aa00", nil)
    tags, err := client.ListTags(ctx, nil)
    imp, err := client.CreateSecretImport(ctx, &infisical.CreateSecretImportOptions{
        Path: "/app", ImportEnvironment: "staging", ImportPath: "/common",
    })
    at := &infisical.SecretImportOptions{Path: "/app"}
    imports, err := client.ListSecretImports(ctx, at)
    _, err = client.DeleteSecretImport(ctx, imp.ID, at)
    _, err = client.DeleteTag(ctx, tag.ID, nil)
    ```

=== "Python"

    ```python
    tag = client.tags.create_tag("database", "#00aa00")
    tags = client.tags.list_tags()
    imp = client.imports.create_secret_import(
        path="/app", import_environment="staging", import_path="/common"
    )
    imports = client.imports.list_secret_imports(path="/app")
    client.imports.delete_secret_import(imp.id, path="/app")
    client.tags.delete_tag(tag.id)
    ```

=== "Java"

    ```java
    Tag tag = client.createTag("database", "#00aa00", null);
    List<Tag> tags = client.listTags(null);
    SecretImport imp = client.createSecretImport(CreateSecretImportOptions.builder()
        .path("/app").importEnvironment("staging").importPath("/common").build());
    SecretImportOptions at = SecretImportOptions.builder().path("/app").build();
    List<SecretImport> imports = client.listSecretImports(at);
    client.deleteSecretImport(imp.id(), at);
    client.deleteTag(tag.id(), null);
    ```
