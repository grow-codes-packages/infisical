# Folders

Folders organise secrets inside an environment (`/`, `/app`, `/app/db`). The calls use the **v2**
folder API; `path` is the parent folder (default `secretPath` of the config, `/`).

| Function | Endpoint (v2) | Notes |
| - | - | - |
| `listFolders({path, recursive})` | `GET /api/v2/folders` | direct children, or the whole tree with `recursive` |
| `createFolder(name, {path, description})` | `POST /api/v2/folders` | names may contain letters, digits, `-` and `_` (`VALIDATION` otherwise); an existing name → `CONFLICT`; a missing parent → `NOT_FOUND` |
| `updateFolder(folderId, {name, path, description})` | `PATCH /api/v2/folders/{id}` | rename or change the description |
| `deleteFolder(folderIdOrName, {path, force})` | `DELETE /api/v2/folders/{idOrName}` | deletes the folder with its secrets; missing → `NOT_FOUND`. The force flag is `forceDelete` in TypeScript/Python and `force` in Go, Rust and Java |

The [SecretsProvider](secrets-provider.md) creates missing folders on `set`; the raw
`createSecret` does not.

=== "TypeScript"

    ```ts
    const folder = await client.folders.createFolder("app", { description: "application" });
    await client.folders.createFolder("db", { path: "/app" });
    const tree = await client.folders.listFolders({ recursive: true });
    await client.folders.updateFolder(folder.id, { name: "service" });
    await client.folders.deleteFolder(folder.id, { forceDelete: true });
    ```

=== "Rust"

    ```rust
    use grow_infisical::{CreateFolderOptions, DeleteFolderOptions, ListFoldersOptions, UpdateFolderOptions};

    let folder = client.create_folder("app", None).await?;
    client.create_folder("db", Some(&CreateFolderOptions {
        path: Some("/app".into()), ..Default::default()
    })).await?;
    let tree = client.list_folders(Some(&ListFoldersOptions { recursive: true, ..Default::default() })).await?;
    client.update_folder(&folder.id, &UpdateFolderOptions { name: "service".into(), ..Default::default() }).await?;
    client.delete_folder(&folder.id, Some(&DeleteFolderOptions { force: true, ..Default::default() })).await?;
    ```

=== "Go"

    ```go
    folder, err := client.CreateFolder(ctx, "app", &infisical.CreateFolderOptions{Description: "application"})
    _, err = client.CreateFolder(ctx, "db", &infisical.CreateFolderOptions{Path: "/app"})
    tree, err := client.ListFolders(ctx, &infisical.ListFoldersOptions{Recursive: true})
    _, err = client.UpdateFolder(ctx, folder.ID, &infisical.UpdateFolderOptions{Name: "service"})
    _, err = client.DeleteFolder(ctx, folder.ID, &infisical.DeleteFolderOptions{Force: true})
    ```

=== "Python"

    ```python
    folder = client.folders.create_folder("app", description="application")
    client.folders.create_folder("db", path="/app")
    tree = client.folders.list_folders(recursive=True)
    client.folders.update_folder(folder.id, name="service")
    client.folders.delete_folder(folder.id, force_delete=True)
    ```

=== "Java"

    ```java
    Folder folder = client.createFolder("app",
        CreateFolderOptions.builder().description("application").build());
    client.createFolder("db", CreateFolderOptions.builder().path("/app").build());
    List<Folder> tree = client.listFolders(ListFoldersOptions.builder().recursive(true).build());
    client.updateFolder(folder.id(), UpdateFolderOptions.builder().name("service").build());
    client.deleteFolder(folder.id(), DeleteFolderOptions.builder().force(true).build());
    ```
