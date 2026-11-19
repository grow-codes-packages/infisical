# Functions

The Infisical API of this SDK. Every function exists in all five languages with the same
behaviour; the module pages show each one with an example per language. Names follow each
language's convention (`createSecret` in TypeScript and Java, `create_secret` in Rust and Python,
`CreateSecret` in Go with `ctx` first).

!!! info "Where the functions live"
    The function names are the same in every language. TypeScript and Python group them in
    modules on the client (`client.secrets`, `client.folders`, `client.projects`, `client.tags`,
    `client.imports`); Go, Rust and Java expose them directly on the client
    (`client.CreateSecret(ctx, …)`, `client.create_secret(…)`, `client.createSecret(…)`). The
    [SecretsProvider](secrets.md) is `client.provider` / `client.secretsProvider(…)` in TypeScript
    and Python and `client.Secrets()` / `client.SecretsWith(…)` in Go, Rust and Java.

| Module | Accessor (TypeScript · Go) | Functions | API version | Page |
| - | - | - | - | - |
| Client | `client` | `health`, `ping`, `serverVersion` (always `UNSUPPORTED`), `close`, `apiVersion(resource)` | `/api/status`; ping by token kind | [Client](client.md) |
| Auth | `client.auth` · `client.Auth()` | `UniversalAuth` (`login`, `renew`, `revoke`), `TokenAuth`, `KubernetesAuth`, `AwsIamAuth`; automatic refresh and one re-login on 401 | v1 | [Auth](functions/auth.md) |
| Secrets | `client.secrets` · `client` | `listSecrets`, `getSecret`, `createSecret`, `updateSecret`, `deleteSecret`, `createSecrets`, `updateSecrets`, `deleteSecrets`, `listSecretVersions` | v4, v3 `raw` fallback | [Secrets API](functions/secrets-api.md) |
| Folders | `client.folders` · `client` | `listFolders`, `createFolder`, `updateFolder`, `deleteFolder` | v2 | [Folders](functions/folders.md) |
| Projects + environments | `client.projects` · `client` | `listProjects`, `getProject`, `getProjectBySlug`, `listEnvironments`, `createEnvironment` | v1 | [Projects](functions/projects.md) |
| Tags + imports | `client.tags`, `client.imports` · `client` | `listTags`, `createTag`, `deleteTag`, `listSecretImports`, `createSecretImport`, `deleteSecretImport` | v1 / v2 | [Tags and imports](functions/tags-imports.md) |
| Env injection | `client.secrets` · `client` | `loadEnv`, `exportDotenv`, `formatDotenv` | v4 | [Env injection](functions/env.md) |
| SecretsProvider | `client.provider` · `client.Secrets()` | the shared [Secrets](secrets.md) interface: `get`, `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany`, `getAll`, `list`, `set`, `delete`, `metadata`, `loadEnv`, `watch`, `SecretCache` | v4 | [Secrets over Infisical](functions/secrets-provider.md) |

Every function is called against a real `infisical/infisical:v0.167.10` in the Docker suite of each
language, except the parts listed in [Compatibility](compatibility.md).

## Service configuration

| Setting | Default | Environment variables (precedence order) |
| - | - | - |
| `url` | `http://127.0.0.1:8080` | `GROW_INFISICAL_URL`, `INFISICAL_API_URL` (one trailing `/api` is removed) |
| `token` — static access token (identity token, user JWT or `st.` service token) | none | `GROW_INFISICAL_TOKEN`, `INFISICAL_TOKEN` |
| `clientId` — Universal Auth client id | none | `GROW_INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` |
| `clientSecret` — Universal Auth client secret | none | `GROW_INFISICAL_CLIENT_SECRET`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` |
| `auth` — explicit auth method (wins over `token` and `clientId`) | none | — |
| `projectId` — default project | none (`CONFIG` error at call time when needed) | `GROW_INFISICAL_PROJECT_ID`, `INFISICAL_PROJECT_ID` |
| `environment` — default environment slug | none (`CONFIG` error at call time when needed) | `GROW_INFISICAL_ENVIRONMENT`, `INFISICAL_ENVIRONMENT` |
| `secretPath` — default folder path | `/` | `GROW_INFISICAL_SECRET_PATH` |
| `apiVersion` — secrets API version | `auto` (also `""`): v4, v3 only when v4 is missing | `GROW_INFISICAL_API_VERSION` (`auto`, `v4`, `v3`) |
| `revokeOnClose` — revoke a login token in `close()` | `false` | `GROW_INFISICAL_REVOKE_ON_CLOSE` |

Authentication is chosen in this order: `auth` > `token` (never refreshed) > `clientId` +
`clientSecret` (Universal Auth with automatic refresh) > none (only `health` works). The common
settings (timeouts, retries, TLS, proxy, hooks, logger) are described in
[Configuration](configuration.md).

TypeScript and Python also accept the read defaults `expandSecretReferences` / `includeImports`
(both `true`) in the config; Go, Rust and Java take them per call (`ExpandReferences`,
`IncludeImports`, default `true`). The optional `organizationSlug` of identity logins
(sub-organizations) is a config field in TypeScript and Python and an option of each auth method
(`UniversalAuth`, `KubernetesAuth`, `AwsIamAuth`) in Go, Rust and Java.
