import { afterEach, describe, expect, it } from "vitest";
import { ConfigError, ValidationError, dotenvQuote } from "../../src/index.js";
import { PROJECT, bodyOf, cleanup, clientFor, queryOf, reply, routed } from "./helpers.js";

afterEach(cleanup);

describe("secrets v4", () => {
  it("listSecrets sends every flag and parses secrets + imports", async () => {
    const s = await routed({
      "GET /api/v4/secrets": (req) =>
        queryOf(req).get("secretPath") === "/app"
          ? reply("listSecrets.withImports")
          : reply("listSecrets.ok"),
    });
    const c = clientFor(s);
    const list = await c.secrets.listSecrets();
    expect(list.secrets).toHaveLength(8);
    const renamed = list.secrets.find((x) => x.key === "SDK_49LJ3988_RENAMED")!;
    expect(renamed.version).toBe(3);
    expect(renamed.value.reveal()).toBe("v2-49lj3988");
    expect(renamed.value.version).toBe("3");
    expect(String(renamed.value)).toBe("SecretValue([REDACTED])");
    expect(renamed.tags[0]).toMatchObject({ slug: "t-49lj3988", color: "#00aa00" });
    expect(renamed.createdAt).toBeInstanceOf(Date);
    expect(renamed.comment).toBe("c2");
    expect(renamed.type).toBe("shared");
    const q = queryOf(s.requests[0]!);
    expect(Object.fromEntries(q)).toEqual({
      projectId: PROJECT,
      environment: "dev",
      secretPath: "/",
      recursive: "false",
      expandSecretReferences: "true",
      includeImports: "true",
    });
    expect(c.apiVersion()).toBe("v4");

    const app = await c.secrets.listSecrets({
      secretPath: "app/",
      recursive: true,
      expandReferences: false,
      includeImports: true,
      tagSlugs: ["a", "b"],
      viewSecretValue: false,
      includePersonalOverrides: true,
      environment: "staging",
      projectId: "other",
    });
    expect(app.imports[0]).toMatchObject({ environment: "staging", secretPath: "/common" });
    expect(app.imports[0]!.secrets[0]!.key).toBe("SDK_COMMON");
    expect(app.imports[0]!.folderId).toBeTypeOf("string");
    expect(Object.fromEntries(queryOf(s.requests[1]!))).toEqual({
      projectId: "other",
      environment: "staging",
      secretPath: "/app",
      recursive: "true",
      expandSecretReferences: "false",
      includeImports: "true",
      tagSlugs: "a,b",
      viewSecretValue: "false",
      includePersonalOverrides: "true",
    });
    await c.secrets.listSecrets({
      tagSlugs: [],
      viewSecretValue: true,
      includePersonalOverrides: false,
    });
    expect(queryOf(s.requests[2]!).get("tagSlugs")).toBeNull();
  });

  it("getSecret with version / type / flags", async () => {
    const s = await routed({ "GET /api/v4/secrets/SDK_49LJ3988_ONE": reply("getSecret.ok") });
    const c = clientFor(s, { expandSecretReferences: false, includeImports: false });
    const secret = await c.secrets.getSecret("SDK_49LJ3988_ONE", {
      version: 1,
      type: "personal",
      viewSecretValue: true,
    });
    expect(secret).toMatchObject({ key: "SDK_49LJ3988_ONE", version: 1, secretPath: "/" });
    expect(secret.value.reveal()).toBe("v1-49lj3988");
    expect(Object.fromEntries(queryOf(s.requests[0]!))).toEqual({
      projectId: PROJECT,
      environment: "dev",
      secretPath: "/",
      version: "1",
      type: "personal",
      expandSecretReferences: "false",
      includeImports: "false",
      viewSecretValue: "true",
    });
    await expect(c.secrets.getSecret("X", { version: 0 })).rejects.toBeInstanceOf(ValidationError);
    await expect(c.secrets.getSecret("")).rejects.toBeInstanceOf(ValidationError);
  });

  it("getSecret without secret in the body is UNAVAILABLE", async () => {
    const s = await routed({ "GET /api/v4/secrets/A": { status: 200, body: {} } });
    await expect(clientFor(s).secrets.getSecret("A")).rejects.toMatchObject({
      code: "UNAVAILABLE",
    });
  });

  it("missing environment / project → ConfigError at call time", async () => {
    const s = await routed({});
    const noEnv = clientFor(s, { environment: undefined });
    await expect(noEnv.secrets.listSecrets()).rejects.toBeInstanceOf(ConfigError);
    const noProject = clientFor(s, { projectId: undefined });
    await expect(noProject.secrets.getSecret("A")).rejects.toThrow(/projectId is required/);
    expect(s.requests).toHaveLength(0);
  });

  it("createSecret / updateSecret / deleteSecret send the documented bodies", async () => {
    const s = await routed({
      "POST /api/v4/secrets/SDK_49LJ3988_ONE": reply("createSecret.ok"),
      "PATCH /api/v4/secrets/SDK_49LJ3988_ONE": reply("updateSecret.renameCommentTags"),
      "DELETE /api/v4/secrets/SDK_49LJ3988_RENAMED": reply("deleteSecret.ok"),
    });
    const c = clientFor(s, { secretPath: "/" });
    const created = await c.secrets.createSecret("SDK_49LJ3988_ONE", "v1-49lj3988", {
      comment: "c1",
      tagIds: ["t1"],
      type: "shared",
      skipMultilineEncoding: true,
      metadata: [{ key: "k", value: "v" }],
    });
    expect(created.version).toBe(1);
    expect(bodyOf(s.requests[0]!)).toEqual({
      projectId: PROJECT,
      environment: "dev",
      secretPath: "/",
      secretValue: "v1-49lj3988",
      secretComment: "c1",
      tagIds: ["t1"],
      type: "shared",
      skipMultilineEncoding: true,
      secretMetadata: [{ key: "k", value: "v" }],
    });
    const updated = await c.secrets.updateSecret("SDK_49LJ3988_ONE", {
      newName: "SDK_49LJ3988_RENAMED",
      comment: "c2",
      tagIds: ["8ec93966-db51-4801-a143-26296a09c05c"],
    });
    expect(updated).toMatchObject({ key: "SDK_49LJ3988_RENAMED", version: 3, comment: "c2" });
    expect(bodyOf(s.requests[1]!)).toEqual({
      projectId: PROJECT,
      environment: "dev",
      secretPath: "/",
      newSecretName: "SDK_49LJ3988_RENAMED",
      secretComment: "c2",
      tagIds: ["8ec93966-db51-4801-a143-26296a09c05c"],
    });
    const deleted = await c.secrets.deleteSecret("SDK_49LJ3988_RENAMED", { type: "shared" });
    expect(deleted.key).toBeTypeOf("string");
    expect(bodyOf(s.requests[2]!)).toEqual({
      projectId: PROJECT,
      environment: "dev",
      secretPath: "/",
      type: "shared",
    });
    await expect(c.secrets.createSecret("A", 5 as unknown as string)).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(c.secrets.updateSecret("A", { newName: " " })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });

  it("batch create / update / delete", async () => {
    const s = await routed({
      "POST /api/v4/secrets/batch": reply("createSecrets.ok"),
      "PATCH /api/v4/secrets/batch": reply("updateSecrets.upsert"),
      "DELETE /api/v4/secrets/batch": reply("deleteSecrets.ok"),
    });
    const c = clientFor(s);
    const created = await c.secrets.createSecrets([
      { key: "B1_49LJ3988", value: "b1" },
      {
        key: "B2_49LJ3988",
        value: "b2",
        comment: "c",
        tagIds: ["t"],
        skipMultilineEncoding: false,
        metadata: [],
      },
    ]);
    expect(created.map((x) => x.key).sort()).toEqual(["B1_49LJ3988", "B2_49LJ3988"]);
    expect(bodyOf(s.requests[0]!).secrets[1]).toEqual({
      secretKey: "B2_49LJ3988",
      secretValue: "b2",
      secretComment: "c",
      tagIds: ["t"],
      skipMultilineEncoding: false,
      secretMetadata: [],
    });
    const updated = await c.secrets.updateSecrets(
      [
        {
          key: "UP_49LJ3988",
          value: "u",
          newName: "N",
          comment: "c",
          tagIds: [],
          secretPath: "x",
          skipMultilineEncoding: true,
          metadata: [],
        },
      ],
      { mode: "upsert" },
    );
    expect(updated[0]!.key).toBe("UP_49LJ3988");
    const ub = bodyOf(s.requests[1]!);
    expect(ub.mode).toBe("upsert");
    expect(ub.secrets[0]).toMatchObject({
      secretKey: "UP_49LJ3988",
      newSecretName: "N",
      secretPath: "/x",
    });
    const deleted = await c.secrets.deleteSecrets([
      "B1_49LJ3988",
      { key: "B2R_49LJ3988", type: "shared" },
      { key: "UP_49LJ3988" },
    ]);
    expect(deleted).toHaveLength(3);
    expect(bodyOf(s.requests[2]!).secrets).toEqual([
      { secretKey: "B1_49LJ3988" },
      { secretKey: "B2R_49LJ3988", type: "shared" },
      { secretKey: "UP_49LJ3988" },
    ]);
    expect(await c.secrets.createSecrets([])).toEqual([]);
    expect(await c.secrets.updateSecrets([])).toEqual([]);
    expect(await c.secrets.deleteSecrets([])).toEqual([]);
    expect(s.requests).toHaveLength(3);
    await expect(c.secrets.deleteSecrets([""])).rejects.toBeInstanceOf(ValidationError);
  });

  it("batch errors: duplicate → CONFLICT, missing → NOT_FOUND", async () => {
    const s = await routed({
      "POST /api/v4/secrets/batch": reply("createSecrets.duplicate400"),
      "PATCH /api/v4/secrets/batch": reply("updateSecrets.404"),
      "DELETE /api/v4/secrets/batch": reply("deleteSecrets.404"),
    });
    const c = clientFor(s);
    await expect(c.secrets.createSecrets([{ key: "A", value: "a" }])).rejects.toMatchObject({
      code: "CONFLICT",
    });
    await expect(c.secrets.updateSecrets([{ key: "A" }])).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await expect(c.secrets.deleteSecrets(["A"])).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("listSecretVersions (user token) and PERMISSION_DENIED for identities", async () => {
    const id = "805cfac2-aef1-4b20-850a-5495bb4795d1";
    const s = await routed({
      [`GET /api/v1/secret/${id}/secret-versions`]: (req) =>
        req.headers.authorization === "Bearer user"
          ? reply("listSecretVersions.ok")
          : reply("listSecretVersions.identity403"),
    });
    const user = clientFor(s, { token: "user" });
    const versions = await user.secrets.listSecretVersions(id, { offset: 0, limit: 50 });
    expect(versions.map((v) => v.version)).toEqual([3, 2, 1]);
    expect(versions[0]).toMatchObject({ key: "SDK_49LJ3988_RENAMED", comment: "c2" });
    expect(versions[0]!.actor).toMatchObject({ actorType: "identity", name: "sdk-universal-auth" });
    expect(versions[0]!.value.reveal()).toBe("v2-49lj3988");
    expect(versions[0]!.createdAt).toBeInstanceOf(Date);
    expect(Object.fromEntries(queryOf(s.requests[0]!))).toEqual({ offset: "0", limit: "50" });
    await user.secrets.listSecretVersions(id);
    expect(queryOf(s.requests[1]!).get("limit")).toBe("20");
    await expect(clientFor(s).secrets.listSecretVersions(id)).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });
    await expect(user.secrets.listSecretVersions(id, { limit: 1001 })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(user.secrets.listSecretVersions(id, { offset: -1 })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });

  it("loadEnv: direct secrets beat nested folders and imports; override flag", async () => {
    const secret = (key: string, value: string, path: string) => ({
      secretKey: key,
      secretValue: value,
      secretPath: path,
      version: 1,
    });
    const s = await routed({
      "GET /api/v4/secrets": {
        status: 200,
        body: {
          secrets: [
            secret("DEEP", "deep", "/app/nested"),
            secret("SHARED", "nested", "/app/nested"),
            secret("SHARED", "direct", "/app"),
            secret("", "ignored", "/app"),
          ],
          imports: [
            {
              environment: "staging",
              secretPath: "/common",
              secrets: [secret("SHARED", "imported", "/app"), secret("IMP", 'imp\n"q"\\', "/app")],
            },
          ],
        },
      },
    });
    const c = clientFor(s);
    const env: Record<string, string | undefined> = { DEEP: "keep" };
    const set = await c.secrets.loadEnv({ secretPath: "/app", recursive: true, env });
    expect(set).toEqual({ SHARED: "SHARED", IMP: "IMP" });
    expect(env).toMatchObject({ DEEP: "keep", SHARED: "direct", IMP: 'imp\n"q"\\' });
    expect(queryOf(s.requests[0]!).get("recursive")).toBe("true");
    const all = await c.secrets.loadEnv({ secretPath: "/app", env, override: true });
    expect(Object.keys(all).sort()).toEqual(["DEEP", "IMP", "SHARED"]);
    expect(env.DEEP).toBe("deep");
    const dotenv = await c.secrets.exportDotenv({ secretPath: "/app" });
    expect(dotenv).toBe('DEEP="deep"\nIMP="imp\\n\\"q\\"\\\\"\nSHARED="direct"\n');
    expect(queryOf(s.requests[2]!).get("recursive")).toBe("false");
  });

  it("loadEnv defaults to process.env", async () => {
    const s = await routed({
      "GET /api/v4/secrets": {
        status: 200,
        body: {
          secrets: [{ secretKey: "GROW_TS_UNIT_LOADENV", secretValue: "v", secretPath: "/" }],
        },
      },
    });
    try {
      await clientFor(s).secrets.loadEnv();
      expect(process.env.GROW_TS_UNIT_LOADENV).toBe("v");
    } finally {
      delete process.env.GROW_TS_UNIT_LOADENV;
    }
    expect(dotenvQuote("a\r\nb")).toBe('"a\\nb"');
  });
});

describe("secrets v3 fallback", () => {
  it("auto: route-missing on v4 switches to v3 for good", async () => {
    const s = await routed({
      "GET /api/v3/secrets/raw": reply("listSecrets.v3raw-ok"),
      "POST /api/v3/secrets/raw/V3_49LJ3988": reply("createSecret.v3raw-ok"),
    });
    const c = clientFor(s);
    const list = await c.secrets.listSecrets({ recursive: true });
    expect(list.secrets.length).toBeGreaterThan(0);
    expect(c.apiVersion()).toBe("v3");
    expect(s.requests.map((r) => r.url.split("?")[0])).toEqual([
      "/api/v4/secrets",
      "/api/v3/secrets/raw",
    ]);
    expect(Object.fromEntries(queryOf(s.requests[1]!))).toEqual({
      workspaceId: PROJECT,
      environment: "dev",
      secretPath: "/",
      recursive: "true",
      expandSecretReferences: "true",
      include_imports: "true",
    });
    await c.secrets.createSecret("V3_49LJ3988", "r1");
    expect(s.requests[2]!.url).toBe("/api/v3/secrets/raw/V3_49LJ3988");
    expect(bodyOf(s.requests[2]!)).toMatchObject({ workspaceId: PROJECT, secretValue: "r1" });
  });

  it("forced v3 uses the raw routes for every call", async () => {
    const s = await routed({
      "GET /api/v3/secrets/raw/V3_49LJ3988": reply("getSecret.v3raw-ok"),
      "PATCH /api/v3/secrets/raw/V3_49LJ3988": reply("updateSecret.v3raw-ok"),
      "DELETE /api/v3/secrets/raw/V3_49LJ3988": reply("deleteSecret.v3raw-ok"),
      "POST /api/v3/secrets/batch/raw": reply("createSecrets.v3raw-ok"),
      "PATCH /api/v3/secrets/batch/raw": reply("updateSecrets.v3raw-ok"),
      "DELETE /api/v3/secrets/batch/raw": reply("deleteSecrets.v3raw-ok"),
    });
    const c = clientFor(s, { apiVersion: "v3" });
    await c.secrets.getSecret("V3_49LJ3988");
    expect(queryOf(s.requests[0]!).get("include_imports")).toBe("true");
    await c.secrets.updateSecret("V3_49LJ3988", { value: "r2" });
    await c.secrets.deleteSecret("V3_49LJ3988");
    await c.secrets.createSecrets([{ key: "A", value: "a" }]);
    await c.secrets.updateSecrets([{ key: "A", value: "b" }]);
    await c.secrets.deleteSecrets(["A"]);
    expect(s.requests.every((r) => r.url.startsWith("/api/v3/"))).toBe(true);
    expect(bodyOf(s.requests[3]!).workspaceId).toBe(PROJECT);
  });

  it("a confirmed v4 never falls back; forced v4 reports route-missing as UNSUPPORTED", async () => {
    const s = await routed({ "GET /api/v4/secrets/A": reply("getSecret.404") });
    const c = clientFor(s);
    await expect(c.secrets.getSecret("A")).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(c.apiVersion()).toBe("v4");
    await expect(c.secrets.listSecrets()).rejects.toMatchObject({ code: "UNSUPPORTED" });
    const forced = clientFor(s, { apiVersion: "v4" });
    await expect(forced.secrets.listSecrets()).rejects.toMatchObject({ code: "UNSUPPORTED" });
    expect(s.requests.some((r) => r.url.startsWith("/api/v3"))).toBe(false);
  });

  it("network errors keep the version unknown", async () => {
    const s = await routed({ "GET /api/v4/secrets": { destroy: true } });
    const c = clientFor(s, { retry: { maxRetries: 0 } });
    await expect(c.secrets.listSecrets()).rejects.toMatchObject({ code: "UNAVAILABLE" });
    expect(c.apiVersion()).toBe("unknown");
  });
});
