# Secrets over Infisical (SecretsProvider)

The shared [Secrets](../secrets.md) interface — the same in every Grow Codes secrets SDK — on top of
the Infisical secrets API. Use it when code should not care which secrets service it talks to.

| Language | Default provider | Provider for another project, environment or base path |
| - | - | - |
| TypeScript | `client.provider` | `client.secretsProvider({ projectId, environment, basePath })` |
| Rust | `client.secrets()` | `client.secrets_with(SecretsProviderOptions { … })` |
| Go | `client.Secrets()` | `client.SecretsWith(infisical.SecretsProviderOptions{…})` |
| Python | `client.provider` | `client.secrets_provider(project_id=…, environment=…, base_path=…)` |
| Java | `client.secrets()` | `client.secretsWith(SecretsProviderOptions.builder()…build())` |

## Name model

A name may contain `/`: the last segment is the **secret key**, the rest is the **folder** below the
provider's base path (default `secretPath` of the config, `/`). `app/db/PASSWORD` is key
`PASSWORD` in folder `<base>/app/db`. `GetOptions.path`, `SetOptions.path` and `DeleteOptions.path`
replace the base path for one call.

| Function | Maps to | Infisical specifics |
| - | - | - |
| `get(name, {version})` | `getSecret` | `version` is Infisical's version number as a string; missing → `null` |
| `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany` | `get` | shared behaviour ([Secrets](../secrets.md)) |
| `getAll(path)` | one `listSecrets` (imports per config) | every secret directly under the folder; a missing folder → empty map |
| `list(prefixOrPath)` | `listSecrets` with values hidden | a folder (`app` or `app/`); when no such folder exists, the last segment is a key prefix in its parent (`app/DB_` lists keys starting with `DB_` in `app`); a missing folder → empty list; personal overrides are skipped |
| `set(name, value, {tags, description})` | `createSecret`, `updateSecret` on `CONFLICT` | creates missing folders; returns the new version; `tags` keys are tag slugs (created when missing, a value starting with `#` is the colour); values are UTF-8 text (other bytes → `VALIDATION`); the server trims surrounding whitespace; `cas` → `UNSUPPORTED` |
| `delete(name, {versions, permanent})` | `deleteSecret` | always deletes every version permanently; `versions` → `UNSUPPORTED`; `permanent: true` is accepted; an explicit `permanent: false` → `UNSUPPORTED` where the language can tell (TypeScript); missing → `NOT_FOUND` |
| `metadata(name)` | `getSecret` with the value hidden | `version`, `createdAt`, `updatedAt`, `tags` (slug → slug), `versions`, `extra` (`id`, `comment`, `type`) |
| `loadEnv(path \| mapping, {override, prefix})` | `getAll` / `get` | shared behaviour; returns env name → secret name |
| `watch(name, interval, onChange)` | polls `get` | compares the version; `close()` of the client stops every watcher |
| `SecretCache(provider, {ttl, …})` | — | TTL + LRU cache with refresh-ahead and stale-while-revalidate |

=== "TypeScript"

    ```ts
    const secrets = client.provider;
    await secrets.set("app/db/PASSWORD", "s3cret", { tags: { database: "#00aa00" } });
    const password = await secrets.require("app/db/PASSWORD");
    const port = await secrets.getNumber("app/db/PORT"); // null when missing
    const names = (await secrets.list("app/db")).map((m) => m.name);
    await secrets.loadEnv("app/db", { prefix: "DB_" });
    const watch = secrets.watch("app/db/PASSWORD", 30_000, (now) => console.log("rotated", now?.version));
    watch.stop();
    await secrets.delete("app/db/PASSWORD");
    ```

=== "Rust"

    ```rust
    use grow_infisical::secrets::{LoadEnvOptions, SecretsProvider, WatchOptions};

    let secrets = client.secrets();
    secrets.set("app/db/PASSWORD", "s3cret".into(), None).await?;
    let password = secrets.require("app/db/PASSWORD", None).await?;
    let port = secrets.get_number("app/db/PORT", None).await?; // None when missing
    let names: Vec<_> = secrets.list(Some("app/db")).await?.into_iter().map(|m| m.name).collect();
    secrets.load_env(&"app/db".into(), &LoadEnvOptions { prefix: "DB_".into(), ..Default::default() }).await?;
    let watch = secrets.watch("app/db/PASSWORD", Duration::from_secs(30), |now, _| {
        println!("rotated: {:?}", now.and_then(|v| v.version().map(str::to_owned)));
    }, WatchOptions::default());
    watch.stop();
    secrets.delete("app/db/PASSWORD", None).await?;
    ```

=== "Go"

    ```go
    secrets := client.Secrets()
    _, err := secrets.Set(ctx, "app/db/PASSWORD", "s3cret", &infisical.SetOptions{Tags: map[string]string{"database": "#00aa00"}})
    password, err := secrets.Require(ctx, "app/db/PASSWORD", nil)
    port, ok, err := secrets.GetNumber(ctx, "app/db/PORT", nil) // ok=false when missing
    metas, err := secrets.List(ctx, "app/db")
    _, err = secrets.LoadEnv(ctx, "app/db", &infisical.LoadEnvOptions{Prefix: "DB_"})
    watch := secrets.Watch(ctx, "app/db/PASSWORD", 30*time.Second, func(now, old *infisical.SecretValue) {
        fmt.Println("rotated")
    }, nil)
    watch.Stop()
    err = secrets.Delete(ctx, "app/db/PASSWORD", nil)
    ```

=== "Python"

    ```python
    secrets = client.provider
    secrets.set("app/db/PASSWORD", "s3cret", tags={"database": "#00aa00"})
    password = secrets.require("app/db/PASSWORD")
    port = secrets.get_number("app/db/PORT")  # None when missing
    names = [m.name for m in secrets.list("app/db")]
    secrets.load_env("app/db", prefix="DB_")
    watch = secrets.watch("app/db/PASSWORD", 30.0, lambda now, old: print("rotated"))
    watch.stop()
    secrets.delete("app/db/PASSWORD")
    ```

=== "Java"

    ```java
    ProjectSecretsProvider secrets = client.secrets();
    secrets.set("app/db/PASSWORD", "s3cret",
        SetOptions.builder().tags(Map.of("database", "#00aa00")).build());
    SecretValue password = secrets.require("app/db/PASSWORD");
    Optional<Double> port = secrets.getNumber("app/db/PORT");
    List<SecretMetadata> metas = secrets.list("app/db");
    secrets.loadEnv("app/db", LoadEnvOptions.builder().prefix("DB_").build()); // system properties
    WatchHandle watch = secrets.watch("app/db/PASSWORD", Duration.ofSeconds(30),
        (now, old) -> System.out.println("rotated"));
    watch.stop();
    secrets.delete("app/db/PASSWORD");
    ```

The conformance scenarios `secrets.roundtrip`, `secrets.bulk`, `secrets.missing` and
`secrets.redaction` run against the real server in every language.
