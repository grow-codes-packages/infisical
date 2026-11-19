---
name: infisical-sdk
description: Add and use the Grow Codes SDK for Infisical (`infisical`) in TypeScript, Rust, Go, Python or Java projects. Use when code must talk to Infisical - installing @grow-codes/infisical, the grow-infisical crate or PyPI package, the Go module github.com/grow-codes-packages/infisical/go or Maven codes.grow.packages:infisical, configuring it with GROW_INFISICAL_* variables, handling InfisicalError codes, testing with the bundled fakes, or running the Docker integration suite of this repository.
---

# Infisical SDK (Grow Codes)

One API for Infisical in five languages (categories: secrets). Pick the package for the
project's language, configure it from the environment, and handle errors by their canonical code.

## 1. Add the package

| Language | Command | Import |
| - | - | - |
| TypeScript | `npm install @grow-codes/infisical` | `import { InfisicalClient } from "@grow-codes/infisical"` |
| Rust | `cargo add grow-infisical` (add `tokio` with `macros,rt-multi-thread`) | `use grow_infisical::InfisicalClient;` |
| Go | `go get github.com/grow-codes-packages/infisical/go` | `infisical "github.com/grow-codes-packages/infisical/go"` |
| Python | `pip install grow-infisical` (or `uv add grow-infisical`) | `from grow_infisical import InfisicalClient` |
| Java | Maven `codes.grow.packages:infisical` (Gradle `implementation("codes.grow.packages:infisical:<version>")`) | `import codes.grow.packages.infisical.InfisicalClient;` |

Check the latest version in the README badges before pinning one.

## 2. Configure

Prefer environment configuration so no credential is written into code. A machine identity with
Universal Auth is the normal setup (the SDK logs in, refreshes the token and re-logs in on 401):

```sh
export GROW_INFISICAL_URL=https://infisical.example.internal   # or INFISICAL_API_URL=…/api
export INFISICAL_CLIENT_ID=...         # from your secret store, never committed
export INFISICAL_CLIENT_SECRET=...
export INFISICAL_PROJECT_ID=...
export INFISICAL_ENVIRONMENT=dev       # required by secret calls (CONFIG error at call time)
```

`INFISICAL_TOKEN` (an access token, user JWT or legacy `st.` service token) replaces the client id
and secret; it is used as it is and never refreshed. Precedence: explicit config value >
`GROW_INFISICAL_*` > vendor variables (`INFISICAL_API_URL`, `INFISICAL_TOKEN`,
`INFISICAL_CLIENT_ID` / `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` /
`INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENVIRONMENT`) > default.
Service-only variables: `GROW_INFISICAL_SECRET_PATH` (default `/`), `GROW_INFISICAL_API_VERSION`
(`auto`, `v4`, `v3`), `GROW_INFISICAL_REVOKE_ON_CLOSE`. Common ones: `…_CONNECT_TIMEOUT`,
`…_REQUEST_TIMEOUT`, `…_TOTAL_TIMEOUT` (`10s`, `1500`), `…_MAX_RETRIES`, `…_CA_CERT`,
`…_CLIENT_CERT`, `…_CLIENT_KEY`, `…_PROXY`. Environment proxies (`HTTPS_PROXY`) are ignored unless
`proxy` is set. Kubernetes and AWS IAM machine identities use `KubernetesAuth` / `AwsIamAuth` as
the config's `auth`.

## 3. Use

Create one client per process and close it on shutdown (TypeScript `await client.close()`, Rust
`client.close().await`, Go `defer client.Close()`, Python `with …`/`close()`, Java
try-with-resources).

- `health()` never throws for an unhealthy service; check `healthy`.
- `ping()` verifies credentials (`AUTHENTICATION` error when they are wrong).
- `serverVersion()` always raises `UNSUPPORTED` (Infisical does not report its version).
- All I/O is retried with jitter on 429/502/503/504 and connection errors; only idempotent calls
  are retried on 500.
- Errors carry `code` (`CONFIG`, `AUTHENTICATION`, `PERMISSION_DENIED`, `NOT_FOUND`, `CONFLICT`,
  `RATE_LIMITED`, `VALIDATION`, `UNAVAILABLE`, `TIMEOUT`, `UNSUPPORTED`, `CANCELLED`), `retryable`,
  `httpStatus` and `requestId`. Branch on the code, not on the message text. Go:
  `errors.Is(err, infisical.ErrNotFound)`. Infisical's 400 "already exists" is `CONFLICT`.

### Secrets (portable provider API)

Prefer the provider when the code only reads and writes secret values: it is the same in every
Grow Codes secrets SDK. Get it with TypeScript/Python `client.provider`, Go `client.Secrets()`, Rust
and Java `client.secrets()` (another project/environment/base path: `secretsProvider(…)` /
`SecretsWith(…)` / `secrets_with(…)` / `secretsWith(…)`). Names are `folder/KEY`
(`app/db/PASSWORD` = key `PASSWORD` in folder `/app/db`); `set` creates missing folders.

Read with `get`/`getString`/`getJson`/`require` (missing → `null`/`None`/`nil`, `require` →
`NOT_FOUND`), write with `set`, list with `list`, load into the environment with `loadEnv`, watch
with `watch`. Wrap the provider in `SecretCache` for hot paths. Values are `SecretValue` objects:
call `reveal()` only where the plain value is needed and never log it. Infisical trims values and
stores text only (bytes → `VALIDATION`); `delete` always removes every version.

```ts
const db = await client.provider.require("app/db/PASSWORD");          // TypeScript
```

```python
db = client.provider.require("app/db/PASSWORD")                        # Python
```

```go
db, err := client.Secrets().Require(ctx, "app/db/PASSWORD", nil)       // Go
```

```rust
let db = client.secrets().require("app/db/PASSWORD", None).await?;    // Rust (use grow_infisical::secrets::SecretsProvider)
```

```java
SecretValue db = client.secrets().require("app/db/PASSWORD");          // Java
```

### Infisical API (service functions)

Same names in every language. TypeScript and Python group them in modules; Go, Rust and Java call
them on the client:

| Need | TypeScript / Python | Go / Rust / Java |
| - | - | - |
| secret with version, tags, metadata | `client.secrets.getSecret(name, {secretPath})` / `get_secret(name, secret_path=…)` | `GetSecret(ctx, name, opts)` / `get_secret(name, opts)` / `getSecret(name, opts)` |
| list, create, update, delete, batches | `listSecrets`, `createSecret`, `updateSecret`, `deleteSecret`, `createSecrets`, `updateSecrets`, `deleteSecrets` on `client.secrets` | same names on the client |
| folders | `client.folders.listFolders/createFolder/updateFolder/deleteFolder` | same names on the client |
| projects, environments | `client.projects.listProjects/getProject/getProjectBySlug/listEnvironments/createEnvironment` | same names on the client |
| tags, secret imports | `client.tags.*`, `client.imports.*` | same names on the client |
| env injection like `infisical run` | `client.secrets.loadEnv({secretPath})`, `exportDotenv` | `LoadEnv`, `ExportDotenv` on the client |
| secret history (user tokens only) | `client.secrets.listSecretVersions(secretId)` | same name on the client |

The raw API does not create folders (`createSecret` into a missing folder → `NOT_FOUND`), uses v4
and falls back to v3 only on servers without v4. `loadEnv` returns `{envName: secretKey}` in every
language; Java sets system properties because it cannot change the environment. Full examples:
`docs/functions/*.md`.

<!-- service:skill-usage — the service adds its own functions and examples here. -->

## 4. Test code that uses the SDK

Use the in-memory fakes from the testing module instead of a real Infisical in unit tests:
TypeScript `@grow-codes/infisical/testing`, Rust feature `testing`, Go package `testkit`, Python
`grow_infisical.testing`, Java `codes.grow.packages.infisical.testing`.

## 5. Work on this repository

Read `AGENTS.md` first. Short version: the five languages keep the same API; files with the
`Generated by sdk-kit` header are changed in sdk-kit, not here; `make lint coverage` must pass
(≥ 90 % lines and branches); `make test-docker LANGS="<lang>"` runs the integration suite against
`infisical/infisical:v0.167.10`.
