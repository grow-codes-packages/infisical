# Compatibility

## Runtimes

| Language | Supported | Tested in CI |
| - | - | - |
| TypeScript | Node.js ≥ 22.12, ESM and CommonJS | Node 22, 24 |
| Rust | MSRV 1.88, edition 2021, tokio | stable, 1.88 |
| Go | Go ≥ 1.26 | 1.26, 1.27 |
| Python | ≥ 3.10 | 3.10, 3.13, 3.14 |
| Java | ≥ 17 (Java 17 bytecode) | Temurin 17, 21, 25 |

## Infisical versions

The integration suite runs against `infisical/infisical:v0.167.10` (the tag of the Grow Codes stack
catalog) with PostgreSQL 18.1 and Valkey 9.1.3. A one-shot bootstrap creates the admin, an
organisation, the project `sdk-test` (environments `dev`, `staging`, `prod`, `test`), folders, seed
secrets, a Universal Auth project-admin identity, a Token Auth viewer, an identity without access,
a legacy service token and a user token.

API versions used per resource on that server:

| Resource | Version | Routes |
| - | - | - |
| Secrets (single, batch) | **v4**, v3 `raw` fallback | `/api/v4/secrets…` · `/api/v3/secrets/raw…` |
| Folders, secret imports | v2 | `/api/v2/folders`, `/api/v2/secret-imports` |
| Projects, environments, tags | v1 | `/api/v1/projects…` |
| Secret versions | v1 | `/api/v1/secret/{id}/secret-versions` |
| Auth (login, renew, revoke) | v1 | `/api/v1/auth/…` |
| Health | — | `/api/status` |

The v3 fallback is used only when the server answers 404 with `"error":"Not Found"` and a message
starting with `Route ` (servers that predate v4); v3 calls send `expandSecretReferences` and
`include_imports` explicitly. `apiVersion: "v3"` forces v3; the Docker suite runs the secrets calls
on forced v3 too.

## Functions the fixture cannot serve

Every public function is called against the real service in the Docker suite. These paths cannot
succeed against a self-hosted, single-node fixture; they are covered by unit tests against
recorded responses and mock servers.

| Function / path | Languages | Reason | What the Docker suite checks |
| - | - | - | - |
| `KubernetesAuth` login success | all | needs a Kubernetes TokenReview API | the request shape (server answers "Kubernetes auth method not found" → `NOT_FOUND`) |
| `AwsIamAuth` login success | all | needs real AWS STS | the request shape and SigV4 headers ("AWS auth method not found" → `NOT_FOUND`); the signature is unit-tested against the AWS SigV4 test vectors |
| 429 / `Retry-After` | all | self-hosted Infisical has no rate limiter | — (unit tests, including the "try again in N seconds" message form) |
| 5xx retries, timeouts | all | cannot be triggered on demand | — |
| v4 → v3 automatic fallback | all | the pinned server has v4 | v3 itself, by forcing `apiVersion: "v3"` |
| `serverVersion()` | all | no endpoint reports the running version | `UNSUPPORTED` is asserted |

Paid features (secret rotation, approvals, dynamic secrets, audit log streaming) are out of scope
for v1 and not implemented. No code from Infisical's `ee/` folders is used.

## Service behaviour the SDK normalises

| Infisical behaviour | What the SDK does (all languages) |
| - | - |
| 400 "… already exists" for secrets, batches, folders, tags and environments | `CONFLICT` |
| 403 `TokenError` (malformed or foreign token) | `AUTHENTICATION` |
| 401 (missing, revoked or expired token) | `AUTHENTICATION`; with a login method the client logs in again once and repeats the call |
| Request id only in the error body (`reqId`) | copied to `requestId` |
| 404 `Route … not found` | v3 fallback for secrets, `UNSUPPORTED` elsewhere |
| 422 validation errors (zod issue list) | `VALIDATION` with the issues in the message |
| `Authorization` header on login/renew/revoke → 403 | these calls never send one |
| Universal Auth lockout after repeated bad secrets | a rejected login is never retried |
| `PATCH` without a value answers `secretValue: ""` | documented; read the secret again for its value |
| Values are trimmed by the server | documented; leading/trailing whitespace does not round-trip |
| `getSecret(name, {version})` finds a version only under the key it had then | documented (after a rename, use `listSecretVersions`) |
| A list fails with 403 when one value references a secret the caller cannot read | surfaced as `PERMISSION_DENIED` |
| `listSecretVersions` is served for user tokens only | machine identities get `PERMISSION_DENIED` (no N+1 emulation) |
| `createSecretImport` accepts duplicates and missing source paths | passed through |

## Parity decisions (all five languages)

- **SecretsProvider names**: `a/b/KEY` → folder `/a/b` (below the base path), key `KEY`. `set`
  creates missing folders and updates an existing key. Binary values are not supported (`set` with
  non-UTF-8 bytes → `VALIDATION`). `cas` → `UNSUPPORTED`.
- **Provider `delete`**: Infisical always deletes every version permanently. `versions` →
  `UNSUPPORTED`; `permanent: true` is accepted. An explicit `permanent: false` → `UNSUPPORTED` where
  the language can tell it from "not set" (TypeScript); Rust, Go, Java and Python use a plain
  boolean whose default is `false`, so it is accepted there.
- **Provider `list`** on a missing folder returns an empty list; a name that is not a folder is a
  key prefix inside its parent folder.
- **`fromEnv()`**: `environment` (and `projectId`) are required at call time, not at construction
  (`CONFIG`). The Infisical CLI aliases `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` /
  `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` are read after `INFISICAL_CLIENT_ID` /
  `INFISICAL_CLIENT_SECRET`; a trailing `/api` of `INFISICAL_API_URL` is removed.
  `apiVersion` accepts `auto` and `""` for detection in every language.
- **Token kinds** (`ping()` route and the TypeScript/Python `TokenKind`): `identity`, `user`,
  `serviceToken`.
- **Tags** on `createSecret`/`updateSecret`: both `tagIds` and `tagSlugs` (slugs resolved with
  `listTags`, merged with the ids).
- **Secret metadata** is a key → value map.
- **Dotenv** escapes `\`, `"`, LF and CR.
- **`loadEnv`** (service and provider) returns env name → secret key/name.

## Language differences

The API is the same in every language; only the conventions differ (naming, durations, async
model). In addition:

| Topic | TypeScript, Python | Go, Rust, Java |
| - | - | - |
| Service functions | grouped in modules: `client.secrets`, `client.folders`, `client.projects`, `client.tags`, `client.imports` | methods on the client |
| SecretsProvider accessor | `client.provider`, `client.secretsProvider(…)` | `client.Secrets()` / `secrets()`, `SecretsWith(…)` / `secrets_with(…)` / `secretsWith(…)` |
| Universal Auth `login`/`renew`/`revoke` | on the auth method bound to the client | on the token manager `client.Auth()` / `auth()` (the methods also take the client) |
| Read defaults `expandSecretReferences`, `includeImports` | config fields (default `true`) | per call / per provider (default `true`) |
| `organizationSlug` | config field | option of each auth method |
| Batch item types | `BatchCreateSecret`, `BatchUpdateSecret` | `SecretInput`, `SecretUpdate` |
| `deleteFolder` force flag | `forceDelete` | `force` |

Java cannot change the process environment, so `loadEnv` sets **system properties** (or writes to
an `EnvLoader.Target`) and returns the names it set. Java `…Async` variants run the blocking call on
a shared executor; cancelling the future does not interrupt an in-flight request.

## Skipped conformance scenarios

| Scenario | Reason |
| - | - |
| `core.health` step `serverVersion` | no `version` capability (`serverVersion()` is `UNSUPPORTED`) |
