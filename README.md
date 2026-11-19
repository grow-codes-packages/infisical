# Grow Codes SDK for Infisical

[![CI](https://github.com/grow-codes-packages/infisical/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/infisical/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/grow-codes-packages/infisical?sort=semver)](https://github.com/grow-codes-packages/infisical/releases)
[![Docs](https://img.shields.io/badge/docs-grow--codes--packages.github.io-blue)](https://grow-codes-packages.github.io/infisical/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [![npm](https://img.shields.io/npm/v/@grow-codes/infisical)](https://www.npmjs.com/package/@grow-codes/infisical) | [![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/infisical/badges/coverage-typescript.json)](https://github.com/grow-codes-packages/infisical/actions/workflows/ci.yml) |
| Rust | [![crates.io](https://img.shields.io/crates/v/grow-infisical)](https://crates.io/crates/grow-infisical) [![docs.rs](https://img.shields.io/docsrs/grow-infisical)](https://docs.rs/grow-infisical) | [![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/infisical/badges/coverage-rust.json)](https://github.com/grow-codes-packages/infisical/actions/workflows/ci.yml) |
| Go | [![Go Reference](https://pkg.go.dev/badge/github.com/grow-codes-packages/infisical/go.svg)](https://pkg.go.dev/github.com/grow-codes-packages/infisical/go) | [![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/infisical/badges/coverage-go.json)](https://github.com/grow-codes-packages/infisical/actions/workflows/ci.yml) |
| Python | [![PyPI](https://img.shields.io/pypi/v/grow-infisical)](https://pypi.org/project/grow-infisical/) | [![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/infisical/badges/coverage-python.json)](https://github.com/grow-codes-packages/infisical/actions/workflows/ci.yml) |
| Java | [![Maven Central](https://img.shields.io/maven-central/v/codes.grow.packages/infisical)](https://central.sonatype.com/artifact/codes.grow.packages/infisical) | [![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/infisical/badges/coverage-java.json)](https://github.com/grow-codes-packages/infisical/actions/workflows/ci.yml) |

Open-source client libraries for [Infisical](#trademarks-and-disclaimer) in **TypeScript, Rust, Go,
Python and Java** — one API, five idiomatic packages, tested against a real Infisical in Docker.

- **Typed client** with timeouts, retries with jitter, `Retry-After`, cancellation and one error
  model (`InfisicalError` with canonical codes) in every language.
- **Secrets stay secret**: credentials are redacted in `toString`, logs, hooks and error messages.
- **The Infisical API**: secrets (v4 with a v3 fallback, batches, references, imports, versions),
  folders, projects, environments, tags and secret imports, `loadEnv` and dotenv export.
- **Machine identity auth**: Universal Auth with automatic refresh, static tokens, Kubernetes and
  AWS IAM logins.
- **Secrets**: the shared provider API — typed getters, `loadEnv`, change watching and a TTL cache
  with refresh-ahead.

## Contents

- [Supported service version](#supported-service-version)
- [Install](#install)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Function overview](#function-overview)
- [Testing with Docker](#testing-with-docker)
- [Compatibility](#compatibility)
- [Contributing](#contributing)
- [Security](#security)
- [Licence](#licence)
- [Trademarks and disclaimer](#trademarks-and-disclaimer)
- [About Grow Codes](#about-grow-codes)

## Supported service version

Tested in CI against **`infisical/infisical:v0.167.10`** (the version pinned in the Grow Codes stack catalog). Other
versions with the same API usually work; see [Compatibility](#compatibility) and
[docs/compatibility.md](docs/compatibility.md).

## Install

| Language | Package | Install |
| - | - | - |
| TypeScript (Node.js ≥ 22.12) | `@grow-codes/infisical` | `npm install @grow-codes/infisical` |
| Rust (MSRV 1.88) | `grow-infisical` | `cargo add grow-infisical` |
| Go (1.26+) | `github.com/grow-codes-packages/infisical/go` | `go get github.com/grow-codes-packages/infisical/go` |
| Python (≥ 3.10) | `grow-infisical` | `pip install grow-infisical` |
| Java (17+) | `codes.grow.packages:infisical` | see below |

Maven:

```xml
<dependency>
  <groupId>codes.grow.packages</groupId>
  <artifactId>infisical</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
implementation("codes.grow.packages:infisical:0.1.0")
```

## Quickstart

Every package reads its configuration from the environment (see [Configuration](#configuration))
or from an explicit config object. The examples check the service health, log in with a Universal
Auth machine identity and read a secret.

```sh
export GROW_INFISICAL_URL=http://127.0.0.1:8080      # or INFISICAL_API_URL=https://…/api
export INFISICAL_CLIENT_ID=...                       # Universal Auth machine identity
export INFISICAL_CLIENT_SECRET=...                   # never commit real credentials
export INFISICAL_PROJECT_ID=...
export INFISICAL_ENVIRONMENT=dev
```

### TypeScript

```ts
import { InfisicalClient } from "@grow-codes/infisical";

const client = InfisicalClient.fromEnv();
try {
  const health = await client.health(); // never throws for an unreachable server
  console.log(health.healthy, health.status);
  console.log("latency ms:", await client.ping());
  const url = await client.provider.getString("DATABASE_URL"); // null when missing
  const secret = await client.secrets.getSecret("DATABASE_URL"); // raw API: version, tags, …
  console.log(secret.key, secret.version, url !== null);
} finally {
  await client.close();
}
```

### Rust

```rust
use grow_infisical::secrets::SecretsProvider;
use grow_infisical::InfisicalClient;

#[tokio::main]
async fn main() -> grow_infisical::Result<()> {
    let client = InfisicalClient::from_env()?;
    let health = client.health().await?;
    println!("{} {}", health.healthy, health.status);
    println!("latency: {:?}", client.ping().await?);
    let url = client.secrets().get_string("DATABASE_URL", None).await?; // None when missing
    let secret = client.get_secret("DATABASE_URL", None).await?;
    println!("{} v{} {}", secret.key, secret.version, url.is_some());
    client.close().await;
    Ok(())
}
```

### Go

```go
package main

import (
	"context"
	"fmt"
	"log"

	infisical "github.com/grow-codes-packages/infisical/go"
)

func main() {
	ctx := context.Background()
	client, err := infisical.NewClientFromEnv()
	if err != nil {
		log.Fatal(err) // CONFIG error naming the variable, never its value
	}
	defer client.Close()

	health, err := client.Health(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(health.Healthy, health.Status)
	url, ok, err := client.Secrets().GetString(ctx, "DATABASE_URL", nil)
	if err != nil {
		log.Fatal(err)
	}
	secret, err := client.GetSecret(ctx, "DATABASE_URL", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret.Key, secret.Version, ok, len(url) > 0)
}
```

### Python

```python
from grow_infisical import InfisicalClient

with InfisicalClient.from_env() as client:
    health = client.health()
    print(health.healthy, health.status)
    print("latency ms:", client.ping())
    url = client.provider.get_string("DATABASE_URL")  # None when missing
    secret = client.secrets.get_secret("DATABASE_URL")
    print(secret.key, secret.version, url is not None)
```

Async code uses `AsyncInfisicalClient` with the same methods (`async with`, `await client.health()`).

### Java

```java
import codes.grow.packages.infisical.InfisicalClient;
import codes.grow.packages.infisical.SecretEntry;
import java.util.Optional;

try (InfisicalClient client = InfisicalClient.fromEnv()) {
    var health = client.health();
    System.out.println(health.healthy() + " " + health.status());
    System.out.println("latency: " + client.ping());
    Optional<String> url = client.secrets().getString("DATABASE_URL");
    SecretEntry secret = client.getSecret("DATABASE_URL");
    System.out.println(secret.key() + " v" + secret.version() + " " + url.isPresent());
}
```

More complete programs live in [examples/](examples/) — one folder per language.

## Configuration

All settings can be passed in code or through environment variables. Precedence: **explicit value >
`GROW_INFISICAL_*` variable > vendor variable > default.** A present but invalid value raises a
`ConfigError` that names the variable (never its value).

| Setting | Environment variable | Default |
| - | - | - |
| `url` | `GROW_INFISICAL_URL`, `INFISICAL_API_URL` (one trailing `/api` is removed) | `http://127.0.0.1:8080` |
| `token` — static access token (identity token, user JWT, `st.` service token) | `GROW_INFISICAL_TOKEN`, `INFISICAL_TOKEN` | none |
| `clientId` — Universal Auth | `GROW_INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` | none |
| `clientSecret` — Universal Auth | `GROW_INFISICAL_CLIENT_SECRET`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` | none |
| `auth` — explicit method (`UniversalAuth`, `TokenAuth`, `KubernetesAuth`, `AwsIamAuth`) | — | from `token` / `clientId` |
| `projectId` | `GROW_INFISICAL_PROJECT_ID`, `INFISICAL_PROJECT_ID` | none (`ConfigError` at call time) |
| `environment` (slug, e.g. `dev`) | `GROW_INFISICAL_ENVIRONMENT`, `INFISICAL_ENVIRONMENT` | none (`ConfigError` at call time) |
| `secretPath` | `GROW_INFISICAL_SECRET_PATH` | `/` |
| `apiVersion` (secrets API) | `GROW_INFISICAL_API_VERSION` (`auto`, `v4`, `v3`) | `auto`: v4, v3 only when v4 is missing |
| `revokeOnClose` | `GROW_INFISICAL_REVOKE_ON_CLOSE` | `false` |
| `connectTimeout` | `GROW_INFISICAL_CONNECT_TIMEOUT` | 10 s |
| `requestTimeout` (per attempt) | `GROW_INFISICAL_REQUEST_TIMEOUT` | 30 s |
| `totalTimeout` (including retries) | `GROW_INFISICAL_TOTAL_TIMEOUT` | 120 s |
| `retry.maxRetries` | `GROW_INFISICAL_MAX_RETRIES` | 3 |
| `tls.caCertPath` | `GROW_INFISICAL_CA_CERT` | system roots |
| `tls.clientCertPath` / `tls.clientKeyPath` | `GROW_INFISICAL_CLIENT_CERT` / `GROW_INFISICAL_CLIENT_KEY` | none |
| `tls.insecureSkipVerify` (tests only) | `GROW_INFISICAL_INSECURE_SKIP_VERIFY` | `false` |
| `proxy` | `GROW_INFISICAL_PROXY` | none (environment proxies are ignored) |
| `headers`, `userAgentSuffix`, `hooks`, `logger` | — | none |

Authentication is chosen in this order: `auth` > `token` (used as it is, never refreshed) >
`clientId` + `clientSecret` (Universal Auth: login on first use, renewal at 80 % of the lifetime,
re-login near the max TTL and once after a 401) > none (only `health()` works). TypeScript and
Python also take `organizationSlug`, `expandSecretReferences` and `includeImports` in the config;
Go, Rust and Java take them on the auth method and per call.

Durations accept milliseconds (`1500`) or units (`500ms`, `10s`, `1m30s`); booleans accept
`true/false/1/0/yes/no/on/off`. Field names follow each language's convention
(`request_timeout` in Python and Rust, `RequestTimeout` in Go). The full reference is in the
[documentation](https://grow-codes-packages.github.io/infisical/).

## Function overview

<!-- service:function-overview — the service fills this section; keep the heading. -->

The same functions exist in every language, named per language convention (`createSecret` in
TypeScript and Java, `create_secret` in Python and Rust, `CreateSecret` in Go with `ctx` first).
TypeScript and Python group the service functions in modules (`client.secrets`, `client.folders`,
`client.projects`, `client.tags`, `client.imports`); Go, Rust and Java expose them on the client.
Each module links to its documentation page with full examples in all five languages.

| Area | Functions | Description |
| - | - | - |
| Client | `health`, `ping`, `serverVersion`, `close`, `apiVersion` | liveness via `/api/status` (never throws), authenticated round trip (route by token kind), `UNSUPPORTED` (Infisical reports no version), shutdown (stops watchers, optional token revoke), detected API version |
| [Auth](docs/functions/auth.md) | `UniversalAuth` (`login`, `renew`, `revoke`), `TokenAuth`, `KubernetesAuth`, `AwsIamAuth` | machine identity logins with automatic refresh and one re-login on 401; static tokens; Kubernetes and AWS IAM (SigV4) logins |
| [Secrets API](docs/functions/secrets-api.md) (`client.secrets`) | `listSecrets`, `getSecret`, `createSecret`, `updateSecret`, `deleteSecret`, `createSecrets`, `updateSecrets`, `deleteSecrets`, `listSecretVersions` | v4 with a v3 `raw` fallback detected at run time; reference expansion (`${env.path.KEY}`), imports, personal overrides, tags by id or slug, metadata map, atomic batches |
| [Folders](docs/functions/folders.md) (`client.folders`) | `listFolders`, `createFolder`, `updateFolder`, `deleteFolder` | v2 folder tree |
| [Projects + environments](docs/functions/projects.md) (`client.projects`) | `listProjects`, `getProject`, `getProjectBySlug`, `listEnvironments`, `createEnvironment` | read projects and environments; create an environment (admin) |
| [Tags + imports](docs/functions/tags-imports.md) (`client.tags`, `client.imports`) | `listTags`, `createTag`, `deleteTag`, `listSecretImports`, `createSecretImport`, `deleteSecretImport` | project tags; secrets imported from another environment or folder |
| [Env injection](docs/functions/env.md) (`client.secrets`) | `loadEnv`, `exportDotenv`, `formatDotenv` | like `infisical run`: one variable per secret key; dotenv export |
| [Secrets (SecretsProvider)](docs/functions/secrets-provider.md) (`client.provider` · Go/Rust/Java `client.secrets()`) | `get`, `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany`, `getAll`, `list`, `set`, `delete`, `metadata`, `loadEnv`, `watch`, `SecretCache` | the interface shared by every Grow Codes secrets SDK; names `app/db/KEY` map to folder `/app/db`, key `KEY`; `set` creates folders |

### Auth

`UniversalAuth`, `TokenAuth`, `KubernetesAuth`, `AwsIamAuth` — [documentation](docs/functions/auth.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const ua = new UniversalAuth(clientId, clientSecret);
const client = new InfisicalClient({ url, auth: ua, projectId, environment: "dev" });
await ua.login(); await ua.renew(); await ua.revoke();
```

**Rust**

```rust
let config = InfisicalConfig::builder().url(url).auth(UniversalAuth::new(client_id, client_secret)).build()?;
let client = InfisicalClient::new(config)?;
client.auth().login().await?; client.auth().renew().await?; client.auth().revoke().await?;
```

**Go**

```go
client, err := infisical.NewClient(infisical.Config{Auth: infisical.NewUniversalAuth(clientID, clientSecret)})
_, err = client.Auth().Login(ctx)
_, err = client.Auth().Renew(ctx)
err = client.Auth().Revoke(ctx)
```

**Python**

```python
ua = sdk.UniversalAuth(client_id, client_secret)
client = sdk.InfisicalClient(sdk.InfisicalConfig(url=url, auth=ua))
ua.login(); ua.renew(); ua.revoke()
```

**Java**

```java
InfisicalClient client = InfisicalClient.builder().url(url).auth(new UniversalAuth(clientId, clientSecret)).build();
client.auth().login(); client.auth().renew(); client.auth().revoke();
```

</details>

### Secrets API

`listSecrets`, `getSecret`, `createSecret`, `updateSecret`, `deleteSecret`, batch calls,
`listSecretVersions` — [documentation](docs/functions/secrets-api.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
await client.secrets.createSecret("DB_PASSWORD", "s3cret", { secretPath: "/app", tagSlugs: ["db"] });
await client.secrets.updateSecret("DB_PASSWORD", { secretPath: "/app", value: "rotated" });
const s = await client.secrets.getSecret("DB_PASSWORD", { secretPath: "/app" });
await client.secrets.createSecrets([{ key: "A", value: "1" }, { key: "B", value: "2" }]);
await client.secrets.deleteSecrets(["A", "B"]);
```

**Rust**

```rust
client.create_secret("DB_PASSWORD", "s3cret", Some(&CreateSecretOptions {
    secret_path: Some("/app".into()), tag_slugs: Some(vec!["db".into()]), ..Default::default()
})).await?;
let s = client.get_secret("DB_PASSWORD", Some(&GetSecretOptions {
    secret_path: Some("/app".into()), ..Default::default()
})).await?;
client.create_secrets(&[SecretInput::new("A", "1"), SecretInput::new("B", "2")], None).await?;
client.delete_secrets(&["A", "B"], None).await?;
```

**Go**

```go
_, err := client.CreateSecret(ctx, "DB_PASSWORD", "s3cret", &infisical.CreateSecretOptions{SecretPath: "/app", TagSlugs: []string{"db"}})
_, err = client.UpdateSecret(ctx, "DB_PASSWORD", &infisical.UpdateSecretOptions{SecretPath: "/app", Value: infisical.String("rotated")})
s, err := client.GetSecret(ctx, "DB_PASSWORD", &infisical.GetSecretOptions{SecretPath: "/app"})
_, err = client.CreateSecrets(ctx, []infisical.SecretInput{{Key: "A", Value: "1"}, {Key: "B", Value: "2"}}, nil)
_, err = client.DeleteSecrets(ctx, []string{"A", "B"}, nil)
```

**Python**

```python
client.secrets.create_secret("DB_PASSWORD", "s3cret", secret_path="/app", tag_slugs=["db"])
client.secrets.update_secret("DB_PASSWORD", secret_path="/app", value="rotated")
s = client.secrets.get_secret("DB_PASSWORD", secret_path="/app")
client.secrets.create_secrets([sdk.BatchCreateSecret("A", "1"), sdk.BatchCreateSecret("B", "2")])
client.secrets.delete_secrets(["A", "B"])
```

**Java**

```java
client.createSecret("DB_PASSWORD", "s3cret",
    CreateSecretOptions.builder().secretPath("/app").tagSlugs(List.of("db")).build());
client.updateSecret("DB_PASSWORD", UpdateSecretOptions.builder().secretPath("/app").value("rotated").build());
SecretEntry s = client.getSecret("DB_PASSWORD", GetSecretOptions.builder().secretPath("/app").build());
client.createSecrets(List.of(SecretInput.of("A", "1"), SecretInput.of("B", "2")), null);
client.deleteSecrets(List.of("A", "B"), null);
```

</details>

### Folders

`listFolders`, `createFolder`, `updateFolder`, `deleteFolder` — [documentation](docs/functions/folders.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const f = await client.folders.createFolder("app");
await client.folders.updateFolder(f.id, { name: "service" });
await client.folders.deleteFolder(f.id, { forceDelete: true });
```

**Rust**

```rust
let f = client.create_folder("app", None).await?;
client.update_folder(&f.id, &UpdateFolderOptions { name: "service".into(), ..Default::default() }).await?;
client.delete_folder(&f.id, Some(&DeleteFolderOptions { force: true, ..Default::default() })).await?;
```

**Go**

```go
f, err := client.CreateFolder(ctx, "app", nil)
_, err = client.UpdateFolder(ctx, f.ID, &infisical.UpdateFolderOptions{Name: "service"})
_, err = client.DeleteFolder(ctx, f.ID, &infisical.DeleteFolderOptions{Force: true})
```

**Python**

```python
f = client.folders.create_folder("app")
client.folders.update_folder(f.id, name="service")
client.folders.delete_folder(f.id, force_delete=True)
```

**Java**

```java
Folder f = client.createFolder("app", null);
client.updateFolder(f.id(), UpdateFolderOptions.builder().name("service").build());
client.deleteFolder(f.id(), DeleteFolderOptions.builder().force(true).build());
```

</details>

### Projects and environments

`listProjects`, `getProject`, `getProjectBySlug`, `listEnvironments`, `createEnvironment` —
[documentation](docs/functions/projects.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const project = await client.projects.getProject();
const envs = await client.projects.listEnvironments();
await client.projects.createEnvironment("QA", "qa");
```

**Rust**

```rust
let project = client.get_project(None).await?;
let envs = client.list_environments(None).await?;
client.create_environment("QA", "qa", None).await?;
```

**Go**

```go
project, err := client.GetProject(ctx, "")
envs, err := client.ListEnvironments(ctx, nil)
_, err = client.CreateEnvironment(ctx, "QA", "qa", nil)
```

**Python**

```python
project = client.projects.get_project()
envs = client.projects.list_environments()
client.projects.create_environment("QA", "qa")
```

**Java**

```java
Project project = client.getProject(null);
List<Environment> envs = client.listEnvironments(null);
client.createEnvironment("QA", "qa", null);
```

</details>

### Tags and secret imports

`listTags`, `createTag`, `deleteTag`, `listSecretImports`, `createSecretImport`,
`deleteSecretImport` — [documentation](docs/functions/tags-imports.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const tag = await client.tags.createTag("db", "#00aa00");
const imp = await client.imports.createSecretImport({ path: "/app", importEnvironment: "staging", importPath: "/common" });
await client.imports.deleteSecretImport(imp.id, { path: "/app" });
await client.tags.deleteTag(tag.id);
```

**Rust**

```rust
let tag = client.create_tag("db", "#00aa00", None).await?;
let imp = client.create_secret_import(&CreateSecretImportOptions {
    path: Some("/app".into()), import_environment: "staging".into(), import_path: Some("/common".into()), ..Default::default()
}).await?;
client.delete_secret_import(&imp.id, Some(&SecretImportOptions { path: Some("/app".into()), ..Default::default() })).await?;
client.delete_tag(&tag.id, None).await?;
```

**Go**

```go
tag, err := client.CreateTag(ctx, "db", "#00aa00", nil)
imp, err := client.CreateSecretImport(ctx, &infisical.CreateSecretImportOptions{Path: "/app", ImportEnvironment: "staging", ImportPath: "/common"})
_, err = client.DeleteSecretImport(ctx, imp.ID, &infisical.SecretImportOptions{Path: "/app"})
_, err = client.DeleteTag(ctx, tag.ID, nil)
```

**Python**

```python
tag = client.tags.create_tag("db", "#00aa00")
imp = client.imports.create_secret_import(path="/app", import_environment="staging", import_path="/common")
client.imports.delete_secret_import(imp.id, path="/app")
client.tags.delete_tag(tag.id)
```

**Java**

```java
Tag tag = client.createTag("db", "#00aa00", null);
SecretImport imp = client.createSecretImport(CreateSecretImportOptions.builder()
    .path("/app").importEnvironment("staging").importPath("/common").build());
client.deleteSecretImport(imp.id(), SecretImportOptions.builder().path("/app").build());
client.deleteTag(tag.id(), null);
```

</details>

### Env injection

`loadEnv`, `exportDotenv`, `formatDotenv` — [documentation](docs/functions/env.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const set = await client.secrets.loadEnv({ secretPath: "/app" }); // { DB_HOST: "DB_HOST", … }
const dotenv = await client.secrets.exportDotenv({ secretPath: "/app" });
```

**Rust**

```rust
let opts = EnvOptions { secret_path: Some("/app".into()), ..Default::default() };
let set = client.load_env(Some(&opts)).await?;
let dotenv = client.export_dotenv(Some(&opts)).await?;
```

**Go**

```go
set, err := client.LoadEnv(ctx, &infisical.EnvOptions{SecretPath: "/app"})
dotenv, err := client.ExportDotenv(ctx, &infisical.EnvOptions{SecretPath: "/app"})
```

**Python**

```python
set_vars = client.secrets.load_env(secret_path="/app")
dotenv = client.secrets.export_dotenv(secret_path="/app")
```

**Java**

```java
Map<String, String> set = client.loadEnv(EnvOptions.builder().secretPath("/app").build()); // system properties
String dotenv = client.exportDotenv(EnvOptions.builder().secretPath("/app").build());
```

</details>

### Secrets (SecretsProvider)

`get`, `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany`, `getAll`,
`list`, `set`, `delete`, `metadata`, `loadEnv`, `watch`, `SecretCache` —
[documentation](docs/functions/secrets-provider.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const p = client.provider;
await p.set("app/db/PASSWORD", "s3cret");
const pw = await p.require("app/db/PASSWORD");
const names = (await p.list("app/db")).map((m) => m.name);
```

**Rust**

```rust
let p = client.secrets();
p.set("app/db/PASSWORD", "s3cret".into(), None).await?;
let pw = p.require("app/db/PASSWORD", None).await?;
let names = p.list(Some("app/db")).await?;
```

**Go**

```go
p := client.Secrets()
_, err := p.Set(ctx, "app/db/PASSWORD", "s3cret", nil)
pw, err := p.Require(ctx, "app/db/PASSWORD", nil)
names, err := p.List(ctx, "app/db")
```

**Python**

```python
p = client.provider
p.set("app/db/PASSWORD", "s3cret")
pw = p.require("app/db/PASSWORD")
names = [m.name for m in p.list("app/db")]
```

**Java**

```java
ProjectSecretsProvider p = client.secrets();
p.set("app/db/PASSWORD", "s3cret");
SecretValue pw = p.require("app/db/PASSWORD");
List<SecretMetadata> names = p.list("app/db");
```

</details>

<!-- /service:function-overview -->

## Testing with Docker

The integration suite runs every public function against a real Infisical (`infisical/infisical:v0.167.10`) in Docker.
Each language package is packed and installed into a separate consumer project first, so the tests
use the package exactly as you would.

`docker/compose.yml` starts Infisical with PostgreSQL 18.1 and Valkey 9.1.3 (the stack catalog
tags) and a one-shot `bootstrap` that uses the same admin bootstrap as the Grow Codes stack template,
then creates the project `sdk-test` (environments `dev`, `staging`, `prod`, `test`), folders, seed
secrets, a Universal Auth machine identity, a Token Auth viewer, an identity without access, a
legacy service token and a user token, and writes the test credentials to `/bootstrap/env`. The
encryption key and auth secret in the compose file are test-only values.

```sh
make test-docker                     # all five languages
make test-docker LANGS="go python"   # a subset
```

No host ports are published and every run uses its own Compose project, so runs never collide; the
stack is always removed afterwards (`docker compose down -v`). Unit tests need no Docker:
`make test` or `make coverage`.

## Compatibility

| | TypeScript | Rust | Go | Python | Java |
| - | - | - | - | - | - |
| Runtime | Node.js ≥ 22.12, ESM + CJS | stable, MSRV 1.88 | 1.26, 1.27 | 3.10 – 3.14 | 17, 21, 25 |
| Async | `Promise` + `AbortSignal` | `async` (tokio), `blocking` feature | `context.Context` | sync + `asyncio` | sync + `CompletableFuture` |
| Infisical | `infisical/infisical:v0.167.10` | `infisical/infisical:v0.167.10` | `infisical/infisical:v0.167.10` | `infisical/infisical:v0.167.10` | `infisical/infisical:v0.167.10` |

API versions per resource: secrets **v4** (v3 `raw` fallback detected at run time), folders and
secret imports v2, projects, environments, tags, versions and auth v1. Functions that the
single-node fixture cannot serve (Kubernetes and AWS IAM login success, rate limiting, the automatic
v4 → v3 fallback) are unit-tested; they are listed with the reason in
[docs/compatibility.md](docs/compatibility.md), together with the error mapping and the parity
decisions shared by all five packages. Paid Infisical features (secret rotation, approvals, dynamic
secrets, audit log streaming) are out of scope.

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md) first. All five languages keep the same API; a change lands in all of them
together. Parts of this repository are generated by
[sdk-kit](https://github.com/grow-codes-packages/sdk-kit) and changed there.

## Security

Please report vulnerabilities privately to [opensource@grow.codes](mailto:opensource@grow.codes).
See [SECURITY.md](SECURITY.md).

## Licence

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attributions.

## Trademarks and disclaimer

This is an independent, community-maintained project. It is **not affiliated with, endorsed or
sponsored by its owner (Infisical, Inc.)**. Infisical is a trademark of Infisical, Inc.; it is used here only to name the
service this SDK connects to. The Infisical server is licensed separately by its owner
(MIT core + Infisical Enterprise licence for `ee/`).

The software is provided "AS IS", without warranties or conditions of any kind. Grow Codes is not
responsible for any damage, data loss, security incident, outage or cost that results from using it.
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## About Grow Codes

This SDK is built and maintained by [Grow Codes](https://grow.codes). Grow Codes publishes the
client libraries it builds as open source in the
[grow-codes-packages](https://github.com/grow-codes-packages) organisation, generated from one
shared kit so that every service and every language behaves the same way. Learn more at
[grow.codes](https://grow.codes).
