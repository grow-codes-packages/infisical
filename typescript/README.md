# @grow-codes/**KEY**

TypeScript SDK for [**DISPLAY**](https://grow-codes-packages.github.io/infisical/) by Grow Codes.
Node.js 22.12 or newer, ESM and CommonJS, full type definitions.

```sh
npm install @grow-codes/infisical
```

```ts
import { InfisicalClient } from "@grow-codes/infisical";

// Reads GROW_INFISICAL_URL, GROW_INFISICAL_TOKEN, timeouts, TLS and proxy settings.
const client = InfisicalClient.fromEnv();
try {
  console.log(await client.health()); // { healthy: true, status: "ok", details: {} }
  console.log(`ping: ${(await client.ping()).toFixed(1)} ms`);
} finally {
  await client.close();
}
```

Every error is a `InfisicalError` subclass with a canonical `code` (`NOT_FOUND`,
`AUTHENTICATION`, `RATE_LIMITED`, …), `httpStatus`, `requestId` and `retryable`. Credentials
never appear in messages, logs, hook data or `toString()` output.

Test helpers (in-memory fakes and the conformance runner) live in
`@grow-codes/infisical/testing`.

Documentation: https://grow-codes-packages.github.io/infisical/ · Licence: Apache-2.0.
**DISPLAY** is a trademark of **VENDOR**; this package is not affiliated with or endorsed by it.
