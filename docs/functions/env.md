# Env injection

`loadEnv` works like `infisical run`: it reads the effective secrets of a folder and sets one
environment variable per secret, named exactly like the secret key. `exportDotenv` renders the same
secrets as a dotenv document. Both use one `listSecrets` call (v4) with references expanded and
imports included by default; direct secrets win over imported ones and, with `recursive`, shallower
folders win over deeper ones.

| Function | Notes |
| - | - |
| `loadEnv({projectId, environment, secretPath, recursive, includeImports, expandReferences, override})` | existing variables are kept unless `override`; returns the variables it set as **env name → secret key** (never values) in every language |
| `exportDotenv({…same selection…})` | `KEY="value"` lines sorted by key; `\`, `"`, LF and CR are escaped (`\\`, `\"`, `\n`, `\r`). The result contains secret values — treat it like a secret |
| `formatDotenv(map)` | the renderer of `exportDotenv` for your own key → value map (TypeScript `formatDotenv`, Python `format_dotenv`, Go `FormatDotenv`, Rust `format_dotenv`, Java `InfisicalClient.formatDotenv`) |

Targets: TypeScript `process.env` (or `env`), Python `os.environ` (or `environ`), Go `os.Setenv`,
Rust `std::env::set_var` (or any `EnvSink` with `load_env_into`), Java **system properties** (the JVM
cannot change its environment) or any `EnvLoader.Target`.

The [SecretsProvider](secrets-provider.md) has the shared `loadEnv(path | mapping, {override,
prefix})` too; it upper-cases names and supports a prefix and a mapping, while this one keeps
Infisical's key names unchanged.

=== "TypeScript"

    ```ts
    const set = await client.secrets.loadEnv({ secretPath: "/app", recursive: true });
    console.log(Object.keys(set)); // ["DB_HOST", "DB_PASSWORD"]
    const dotenv = await client.secrets.exportDotenv({ secretPath: "/app" });
    ```

=== "Rust"

    ```rust
    use grow_infisical::EnvOptions;

    let opts = EnvOptions { secret_path: Some("/app".into()), recursive: true, ..Default::default() };
    let set = client.load_env(Some(&opts)).await?; // BTreeMap env name → key
    let dotenv = client.export_dotenv(Some(&opts)).await?;
    ```

=== "Go"

    ```go
    set, err := client.LoadEnv(ctx, &infisical.EnvOptions{SecretPath: "/app", Recursive: true})
    dotenv, err := client.ExportDotenv(ctx, &infisical.EnvOptions{SecretPath: "/app"})
    ```

=== "Python"

    ```python
    set_vars = client.secrets.load_env(secret_path="/app", recursive=True)
    dotenv = client.secrets.export_dotenv(secret_path="/app")
    ```

=== "Java"

    ```java
    Map<String, String> set = client.loadEnv(
        EnvOptions.builder().secretPath("/app").recursive(true).build()); // system properties
    String dotenv = client.exportDotenv(EnvOptions.builder().secretPath("/app").build());
    ```
