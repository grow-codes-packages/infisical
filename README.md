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
- **Secrets**: read, write, list and delete secrets, typed getters, `loadEnv`, change watching and a
  TTL cache with refresh-ahead.

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
| Rust (MSRV 1.85) | `grow-infisical` | `cargo add grow-infisical` |
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

Every package reads its configuration from the environment (`GROW_INFISICAL_URL`,
`GROW_INFISICAL_TOKEN`, …, see [Configuration](#configuration)) or from an explicit config
object. The examples check the service health and make one authenticated call.

### TypeScript

```ts
import { InfisicalClient } from "@grow-codes/infisical";

const client = InfisicalClient.fromEnv();
try {
  const health = await client.health();
  console.log(health.healthy, health.status);
  console.log("latency ms:", await client.ping());
} finally {
  await client.close();
}
```

### Rust

```rust
use grow_infisical::InfisicalClient;

#[tokio::main]
async fn main() -> Result<(), grow_infisical::Error> {
    let client = InfisicalClient::from_env()?;
    let health = client.health().await?;
    println!("{} {}", health.healthy, health.status);
    println!("latency: {:?}", client.ping().await?);
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
		log.Fatal(err)
	}
	defer client.Close()

	health, err := client.Health(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(health.Healthy, health.Status)
}
```

### Python

```python
from grow_infisical import InfisicalClient

with InfisicalClient.from_env() as client:
    health = client.health()
    print(health.healthy, health.status)
    print("latency ms:", client.ping())
```

Async code uses `AsyncInfisicalClient` with the same methods (`async with`, `await client.health()`).

### Java

```java
import codes.grow.packages.infisical.InfisicalClient;

try (InfisicalClient client = InfisicalClient.fromEnv()) {
    var health = client.health();
    System.out.println(health.healthy() + " " + health.status());
    System.out.println("latency ms: " + client.ping());
}
```

More complete programs live in [examples/](examples/) — one folder per language.

## Configuration

All settings can be passed in code or through environment variables. Precedence: **explicit value >
`GROW_INFISICAL_*` variable > vendor variable > default.** A present but invalid value raises a
`ConfigError` that names the variable (never its value).

| Setting | Environment variable | Default |
| - | - | - |
| `url` | `GROW_INFISICAL_URL` | service default |
| `token` | `GROW_INFISICAL_TOKEN` | none |
| `connectTimeout` | `GROW_INFISICAL_CONNECT_TIMEOUT` | 10 s |
| `requestTimeout` (per attempt) | `GROW_INFISICAL_REQUEST_TIMEOUT` | 30 s |
| `totalTimeout` (including retries) | `GROW_INFISICAL_TOTAL_TIMEOUT` | 120 s |
| `retry.maxRetries` | `GROW_INFISICAL_MAX_RETRIES` | 3 |
| `tls.caCertPath` | `GROW_INFISICAL_CA_CERT` | system roots |
| `tls.clientCertPath` / `tls.clientKeyPath` | `GROW_INFISICAL_CLIENT_CERT` / `GROW_INFISICAL_CLIENT_KEY` | none |
| `tls.insecureSkipVerify` (tests only) | `GROW_INFISICAL_INSECURE_SKIP_VERIFY` | `false` |
| `proxy` | `GROW_INFISICAL_PROXY` | none (environment proxies are ignored) |
| `headers`, `userAgentSuffix`, `hooks`, `logger` | — | none |

Vendor variables that are also read: `INFISICAL_API_URL`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_TOKEN`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENVIRONMENT`, `GROW_INFISICAL_*`.

Durations accept milliseconds (`1500`) or units (`500ms`, `10s`, `1m30s`); booleans accept
`true/false/1/0/yes/no/on/off`. Field names follow each language's convention
(`request_timeout` in Python and Rust, `RequestTimeout` in Go). The full reference is in the
[documentation](https://grow-codes-packages.github.io/infisical/).

## Function overview

<!-- service:function-overview — the service fills this section; keep the heading. -->

The same functions exist in every language, named per language convention (`getString` in
TypeScript and Java, `get_string` in Python and Rust, `GetString` in Go).

| Area | Functions | Description |
| - | - | - |
| Client | `health`, `ping`, `serverVersion`, `close` | liveness, authenticated round trip, server version, shutdown |
| Secrets | `get`, `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany`, `getAll`, `list`, `set`, `delete`, `metadata`, `loadEnv`, `watch` | secrets provider API, plus `SecretCache` |

<!-- /service:function-overview -->

## Testing with Docker

The integration suite runs every public function against a real Infisical (`infisical/infisical:v0.167.10`) in Docker.
Each language package is packed and installed into a separate consumer project first, so the tests
use the package exactly as you would.

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
| Runtime | Node.js ≥ 22.12, ESM + CJS | stable, MSRV 1.85 | 1.26, 1.27 | 3.10 – 3.14 | 17, 21, 25 |
| Async | `Promise` + `AbortSignal` | `async` (tokio), `blocking` feature | `context.Context` | sync + `asyncio` | sync + `CompletableFuture` |
| Infisical | `infisical/infisical:v0.167.10` | `infisical/infisical:v0.167.10` | `infisical/infisical:v0.167.10` | `infisical/infisical:v0.167.10` | `infisical/infisical:v0.167.10` |

Functions that Infisical (or its emulator) cannot serve are listed with the reason in
[docs/compatibility.md](docs/compatibility.md).

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
sponsored by Infisical, Inc.**. Infisical is a trademark of Infisical, Inc.; it is used here only to name the
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
