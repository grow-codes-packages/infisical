// Service-owned: generated once by sdk-kit, then maintained in this repository.
// Connector used by `loadConfig()` (secrets/load-config.ts): builds a client from the
// `GROW_SECRETS_*` bootstrap and the package's own environment variables and returns the
// SecretsProvider to read the config keys from.

import { InfisicalClient } from "./client.js";
import { InfisicalConfig } from "./config.js";
import type { SecretsBootstrap, SecretsConnection } from "./secrets/load-config.js";

/**
 * Connects to Infisical for `loadConfig()`. Builds the client from the package's own variables
 * (`GROW_INFISICAL_*` / `INFISICAL_*`, Universal Auth included) read from `env` (the environment
 * `loadConfig` reads the bootstrap from), with the address from `GROW_SECRETS_ADDR` when set, and
 * returns `client.provider` (the SecretsProvider for the configured project and environment).
 * `client.secrets` is the raw secrets API module, not the provider.
 */
export function connectSecrets(
  bootstrap: SecretsBootstrap,
  env: Readonly<Record<string, string | undefined>>,
): Promise<SecretsConnection> {
  const overrides = bootstrap.addr === undefined ? {} : { url: bootstrap.addr };
  // Inside then(): an invalid configuration rejects the promise instead of throwing.
  return Promise.resolve().then(() => {
    const client = new InfisicalClient(InfisicalConfig.fromEnv(overrides, env));
    return { provider: client.provider, close: () => client.close() };
  });
}
