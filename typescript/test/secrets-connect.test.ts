// Service-owned: generated once by sdk-kit, then maintained in this repository.

import { afterEach, describe, expect, it } from "vitest";
import { InfisicalSecretsProvider, loadConfig } from "../src/index.js";
import { connectSecrets } from "../src/secrets-connect.js";
import { PROJECT, cleanup, clientFor, fakeInfisical } from "./infisical/helpers.js";

afterEach(cleanup);

describe("connectSecrets", () => {
  it("returns the client's SecretsProvider (client.provider), not the secrets API module", async () => {
    const connection = await connectSecrets(
      { addr: "http://127.0.0.1:1", path: "", auth: "" },
      { GROW_INFISICAL_TOKEN: "t", GROW_INFISICAL_PROJECT_ID: PROJECT },
    );
    try {
      expect(connection.provider).toBeInstanceOf(InfisicalSecretsProvider);
      expect(typeof connection.provider.getAll).toBe("function");
    } finally {
      await connection.close();
    }
  });
});

describe("loadConfig through the Infisical connector (GRO-1410 regression)", () => {
  it("reads GROW_SECRETS_PATH from the server named by GROW_SECRETS_ADDR", async () => {
    const fake = await fakeInfisical();
    const seed = clientFor(fake.server).provider;
    await seed.set("services/orders/DATABASE_URL", "postgres://db");
    await seed.set("services/orders/LOG_LEVEL", "debug");
    await seed.set("OTHER", "ignored");

    const env: Record<string, string | undefined> = {
      GROW_SECRETS_PROVIDER: "infisical",
      GROW_SECRETS_ADDR: fake.server.url,
      GROW_SECRETS_PATH: "services/orders",
      GROW_INFISICAL_URL: "http://127.0.0.1:1",
      GROW_INFISICAL_TOKEN: "identity-token-value",
      GROW_INFISICAL_PROJECT_ID: PROJECT,
      GROW_INFISICAL_ENVIRONMENT: "dev",
      GROW_INFISICAL_MAX_RETRIES: "0",
    };
    const values = await loadConfig({ env, required: ["DATABASE_URL"] });
    expect(values).toEqual({ DATABASE_URL: "postgres://db", LOG_LEVEL: "debug" });
    expect(env["DATABASE_URL"]).toBe("postgres://db");
    expect(env["LOG_LEVEL"]).toBe("debug");
    expect(env["OTHER"]).toBeUndefined();
  });
});
