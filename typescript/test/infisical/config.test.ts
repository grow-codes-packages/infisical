import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import {
  ConfigError,
  InfisicalConfig,
  REDACTED,
  Secret,
  TokenAuth,
  VENDOR_ENV,
} from "../../src/index.js";

describe("InfisicalConfig", () => {
  it("defaults", () => {
    const c = new InfisicalConfig();
    expect(c.url).toBe("http://127.0.0.1:8080");
    expect(c.secretPath).toBe("/");
    expect(c.apiVersion).toBe("auto");
    expect(c.expandSecretReferences).toBe(true);
    expect(c.includeImports).toBe(true);
    expect(c.revokeOnClose).toBe(false);
    expect(c.environment).toBeUndefined();
    expect(c.projectId).toBeUndefined();
    expect(Object.isFrozen(c)).toBe(true);
    expect(InfisicalConfig.from(c)).toBe(c);
    expect(c.toJSON().auth).toBeNull();
  });

  it("keeps service settings", () => {
    const auth = new TokenAuth("tok-1234");
    const c = new InfisicalConfig({
      clientId: "cid",
      clientSecret: "client-secret-value",
      organizationSlug: "org",
      auth,
      projectId: "p",
      environment: "dev",
      secretPath: "/app",
      apiVersion: "v3",
      expandSecretReferences: false,
      includeImports: false,
      revokeOnClose: true,
      proxy: "http://p:1",
      userAgentSuffix: "s",
      hooks: {},
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    });
    expect(c.clientId).toBe("cid");
    expect(c.clientSecret?.reveal()).toBe("client-secret-value");
    expect(c.organizationSlug).toBe("org");
    expect(c.auth).toBe(auth);
    expect(c.toJSON()).toMatchObject({
      auth: "token",
      projectId: "p",
      environment: "dev",
      secretPath: "/app",
      apiVersion: "v3",
      clientSecret: REDACTED,
    });
    expect(c.knownSecrets()).toEqual(["client-secret-value"]);
    // empty strings count as unset
    const empty = new InfisicalConfig({
      clientId: "",
      organizationSlug: "",
      projectId: "",
      environment: "",
    });
    expect(empty.clientId).toBeUndefined();
    expect(empty.organizationSlug).toBeUndefined();
  });

  it("validate() raises ConfigError", () => {
    expect(() => new InfisicalConfig({ token: "  " })).toThrow(ConfigError);
    expect(() => new InfisicalConfig({ clientId: "x" })).toThrow(/given together/);
    expect(() => new InfisicalConfig({ clientSecret: "x" })).toThrow(/given together/);
    expect(() => new InfisicalConfig({ secretPath: "app" })).toThrow(/secretPath/);
    expect(() => new InfisicalConfig({ apiVersion: "v9" as unknown as "v4" })).toThrow(
      /apiVersion/,
    );
    expect(() => new InfisicalConfig({ url: "ftp://x" })).toThrow(ConfigError);
  });

  it("core.redaction.config: credentials never print", () => {
    const c = new InfisicalConfig({
      token: "super-secret-tok",
      clientId: "cid",
      clientSecret: new Secret("client-secret-xyz"),
    });
    for (const form of [String(c), JSON.stringify(c), inspect(c)]) {
      expect(form).not.toContain("super-secret-tok");
      expect(form).not.toContain("client-secret-xyz");
    }
    expect(String(c)).toMatch(/^InfisicalConfig\(/);
  });

  it("core.config.env-precedence: explicit > GROW_* > vendor > default", () => {
    const env = {
      GROW_INFISICAL_URL: "http://grow:1",
      INFISICAL_API_URL: "http://vendor:2/api",
      INFISICAL_TOKEN: "vendor-token",
      GROW_INFISICAL_PROJECT_ID: "grow-project",
      INFISICAL_PROJECT_ID: "vendor-project",
      INFISICAL_ENVIRONMENT: "staging",
      GROW_INFISICAL_SECRET_PATH: "/app",
      GROW_INFISICAL_REQUEST_TIMEOUT: "5s",
    };
    const c = InfisicalConfig.fromEnv({}, env);
    expect(c.url).toBe("http://grow:1");
    expect(c.token?.reveal()).toBe("vendor-token");
    expect(c.projectId).toBe("grow-project");
    expect(c.environment).toBe("staging");
    expect(c.secretPath).toBe("/app");
    expect(c.requestTimeoutMs).toBe(5000);

    const vendor = InfisicalConfig.fromEnv({}, { INFISICAL_API_URL: "http://vendor:2/api/" });
    expect(vendor.url).toBe("http://vendor:2");
    expect(InfisicalConfig.fromEnv({}, { INFISICAL_API_URL: "http://v:3" }).url).toBe("http://v:3");

    const explicit = InfisicalConfig.fromEnv({ projectId: "explicit", url: "http://e:4" }, env);
    expect(explicit.projectId).toBe("explicit");
    expect(explicit.url).toBe("http://e:4");

    expect(InfisicalConfig.fromEnv({}, {}).url).toBe(InfisicalConfig.DEFAULT_URL);
    expect(VENDOR_ENV.clientId).toContain("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID");
    expect(InfisicalConfig.fromEnv().url).toBeTypeOf("string");
  });

  it("reads API_VERSION and REVOKE_ON_CLOSE; '' means auto", () => {
    const c = InfisicalConfig.fromEnv(
      {},
      { GROW_INFISICAL_API_VERSION: "V3", GROW_INFISICAL_REVOKE_ON_CLOSE: "true" },
    );
    expect(c.apiVersion).toBe("v3");
    expect(c.revokeOnClose).toBe(true);
    expect(new InfisicalConfig({ apiVersion: "" }).apiVersion).toBe("auto");
    expect(() => InfisicalConfig.fromEnv({}, { GROW_INFISICAL_API_VERSION: "v9" })).toThrow(
      /apiVersion/,
    );
  });

  it("reads Universal Auth credentials incl. the CLI aliases", () => {
    const c = InfisicalConfig.fromEnv(
      {},
      {
        INFISICAL_UNIVERSAL_AUTH_CLIENT_ID: "cli-id",
        INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET: "cli-secret",
      },
    );
    expect(c.clientId).toBe("cli-id");
    expect(c.clientSecret?.reveal()).toBe("cli-secret");
    const g = InfisicalConfig.fromEnv(
      {},
      {
        GROW_INFISICAL_CLIENT_ID: "g-id",
        INFISICAL_CLIENT_ID: "v-id",
        GROW_INFISICAL_CLIENT_SECRET: "g-secret",
        INFISICAL_CLIENT_SECRET: "v-secret",
      },
    );
    expect(g.clientId).toBe("g-id");
    expect(g.clientSecret?.reveal()).toBe("g-secret");
  });

  it("an invalid env value names the variable, never the value", () => {
    let err: unknown;
    try {
      InfisicalConfig.fromEnv({}, { GROW_INFISICAL_TOTAL_TIMEOUT: "forever-and-secret" });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConfigError);
    expect((err as Error).message).toContain("GROW_INFISICAL_TOTAL_TIMEOUT");
    expect((err as Error).message).not.toContain("forever-and-secret");
  });
});
