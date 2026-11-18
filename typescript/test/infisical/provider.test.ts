import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { InfisicalClient, NotFoundError, SecretCache } from "../../src/index.js";
import { formatReport, runConformance } from "../../src/testing/index.js";
import { PROJECT, cleanup, clientFor, fakeInfisical, routed, track } from "./helpers.js";

afterEach(cleanup);

const scenariosDir = fileURLToPath(new URL("../../../conformance/scenarios/", import.meta.url));

describe("InfisicalSecretsProvider", () => {
  it("conformance scenarios pass against the fake server", async () => {
    const fake = await fakeInfisical();
    const report = await runConformance({
      scenariosDir,
      categories: ["secrets"],
      factories: { secrets: () => clientFor(fake.server).provider },
      capabilities: { secrets: ["write", "delete", "versions"] },
    });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.passed).toBeGreaterThan(0);
  });

  it("name model: a/b/KEY → folder /a/b, key KEY; base path and opts.path", async () => {
    const fake = await fakeInfisical();
    const c = clientFor(fake.server);
    const p = c.provider;
    expect(p.locate("KEY")).toEqual({ secretPath: "/", key: "KEY" });
    expect(p.locate("a/b/KEY")).toEqual({ secretPath: "/a/b", key: "KEY" });
    expect(p.locate("KEY", "x/")).toEqual({ secretPath: "/x", key: "KEY" });
    expect(() => p.locate("a/")).toThrow(/invalid secret name/);
    expect(() => p.locate("")).toThrow(/invalid secret name/);
    expect(p.nameOf("/a/b", "K")).toBe("a/b/K");

    const scoped = c.secretsProvider({ basePath: "/app", environment: "dev", projectId: PROJECT });
    expect(scoped.basePath).toBe("/app");
    expect(scoped.locate("K")).toEqual({ secretPath: "/app", key: "K" });
    expect(scoped.nameOf("/app/x", "K")).toBe("x/K");
    expect(scoped.nameOf("/other", "K")).toBe("other/K");

    // set creates the folders, version bumps on update
    expect(await scoped.set("x/y/K", "v1")).toBe("1");
    expect(fake.folders.has("/app/x/y")).toBe(true);
    expect(await scoped.set("x/y/K", "v2", { description: "d" })).toBe("2");
    expect(await scoped.getString("x/y/K")).toBe("v2");
    expect((await scoped.get("x/y/K", { version: "2" }))?.version).toBe("2");
    const meta = await scoped.metadata("x/y/K");
    expect(meta).toMatchObject({ name: "x/y/K", path: "/app/x/y", version: "2", versions: 2 });
    expect(meta?.extra).toMatchObject({ comment: "d", type: "shared" });
    expect(meta?.createdAt).toBeInstanceOf(Date);
    expect((await scoped.list("x/y")).map((m) => m.name)).toEqual(["x/y/K"]);
    expect(await scoped.list("missing")).toEqual([]);
    expect((await scoped.getAll("missing")).size).toBe(0);
    await expect(scoped.get("x/y/K", { version: "abc" })).rejects.toMatchObject({
      code: "VALIDATION",
    });
    await expect(scoped.metadata("x/y/K", { version: "0" })).rejects.toMatchObject({
      code: "VALIDATION",
    });
    expect(await scoped.metadata("x/y/K", { version: "1" })).not.toBeNull();
    await scoped.delete("x/y/K", { permanent: true });
    expect(await scoped.get("x/y/K")).toBeNull();
    await expect(scoped.delete("x/y/K")).rejects.toBeInstanceOf(NotFoundError);
  });

  it("tags: slugs resolve to ids, missing tags are created (value = color when hex)", async () => {
    const fake = await fakeInfisical();
    const p = clientFor(fake.server).provider;
    await p.set("TAGGED", "v", { tags: { red: "#ff0000", plain: "anything" } });
    const meta = await p.metadata("TAGGED");
    expect(meta?.tags).toEqual({ red: "red", plain: "plain" });
    await p.set("TAGGED", "v2", { tags: { red: "" } });
    expect((await p.metadata("TAGGED"))?.tags).toEqual({ red: "red" });
    await p.set("TAGGED", "v3", { tags: {} });
    expect((await p.metadata("TAGGED"))?.tags).toEqual({});
  });

  it("tag created concurrently: a ConflictError is resolved by listing again", async () => {
    let listed = 0;
    const s = await routed({
      [`GET /api/v1/projects/${PROJECT}/tags`]: () => ({
        status: 200,
        body: { tags: listed++ === 0 ? [] : [{ id: "tag-1", slug: "race" }] },
      }),
      [`POST /api/v1/projects/${PROJECT}/tags`]: {
        status: 400,
        body: { reqId: "r", statusCode: 400, message: "Tag already exists", error: "BadRequest" },
      },
      "POST /api/v4/secrets/K": { status: 200, body: { secret: { secretKey: "K", version: 1 } } },
    });
    expect(await clientFor(s).provider.set("K", "v", { tags: { race: "" } })).toBe("1");
    const s2 = await routed({
      [`GET /api/v1/projects/${PROJECT}/tags`]: { status: 200, body: { tags: [] } },
      [`POST /api/v1/projects/${PROJECT}/tags`]: {
        status: 400,
        body: { reqId: "r", statusCode: 400, message: "Tag already exists", error: "BadRequest" },
      },
    });
    await expect(
      clientFor(s2).provider.set("K", "v", { tags: { race: "" } }),
    ).rejects.toMatchObject({
      code: "CONFLICT",
    });
    const s3 = await routed({
      [`GET /api/v1/projects/${PROJECT}/tags`]: { status: 200, body: { tags: [] } },
      [`POST /api/v1/projects/${PROJECT}/tags`]: { status: 403, body: { message: "no" } },
    });
    await expect(clientFor(s3).provider.set("K", "v", { tags: { x: "" } })).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });
  });

  it("unsupported options and invalid values", async () => {
    const fake = await fakeInfisical();
    const p = clientFor(fake.server).provider;
    await expect(p.set("A", "v", { cas: 1 })).rejects.toMatchObject({ code: "UNSUPPORTED" });
    await expect(p.set("A", new Uint8Array([0xff, 0xfe]))).rejects.toMatchObject({
      code: "VALIDATION",
    });
    await expect(p.delete("A", { versions: ["1"] })).rejects.toMatchObject({ code: "UNSUPPORTED" });
    await expect(p.delete("A", { permanent: false })).rejects.toMatchObject({
      code: "UNSUPPORTED",
    });
    await p.delete("A", { versions: [] }).catch((e: unknown) => {
      expect(e).toBeInstanceOf(NotFoundError);
    });
  });

  it("errors other than NOT_FOUND propagate", async () => {
    const forbidden = {
      status: 403,
      body: { reqId: "r", statusCode: 403, message: "denied", error: "PermissionDenied" },
    };
    const s = await routed({
      "GET /api/v4/secrets/A": forbidden,
      "GET /api/v4/secrets": forbidden,
      "POST /api/v4/secrets/A": forbidden,
      "POST /api/v4/secrets/B": {
        status: 404,
        body: {
          reqId: "r",
          statusCode: 404,
          message: "Folder with path '/x' not found",
          error: "CreateSecret",
        },
      },
      "POST /api/v2/folders": forbidden,
      "POST /api/v4/secrets/C": {
        status: 404,
        body: { reqId: "r", statusCode: 404, message: "Project not found", error: "NotFound" },
      },
    });
    const p = clientFor(s).provider;
    await expect(p.get("A")).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(p.metadata("A")).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(p.list()).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(p.getAll()).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(p.set("A", "v")).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(p.set("x/B", "v")).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(p.set("C", "v")).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("getAll merges imports without overriding direct secrets", async () => {
    const s = await routed({
      "GET /api/v4/secrets": {
        status: 200,
        body: {
          secrets: [
            { secretKey: "B", secretValue: "direct", version: 2, secretPath: "/" },
            { secretKey: "A", secretValue: "a", version: 1, secretPath: "/" },
          ],
          imports: [
            {
              environment: "staging",
              secretPath: "/common",
              secrets: [
                { secretKey: "B", secretValue: "imported", version: 1 },
                { secretKey: "C", secretValue: "c", version: 1 },
              ],
            },
          ],
        },
      },
    });
    const all = await clientFor(s).provider.getAll();
    expect([...all.keys()]).toEqual(["A", "B", "C"]);
    expect(all.get("B")?.reveal()).toBe("direct");
    expect(all.get("B")?.version).toBe("2");
  });

  it("works with SecretCache and loadEnv(path)", async () => {
    const fake = await fakeInfisical();
    const c = clientFor(fake.server);
    await c.provider.set("env/DB_HOST", "db");
    const cache = new SecretCache(c.provider, { ttlMs: 60_000 });
    expect(await cache.getString("env/DB_HOST")).toBe("db");
    expect(await cache.getString("env/DB_HOST")).toBe("db");
    expect(cache.stats().hits).toBe(1);
    const target: Record<string, string | undefined> = {};
    expect(await c.provider.loadEnv("env", { env: target, prefix: "APP_" })).toEqual({
      APP_DB_HOST: "env/DB_HOST",
    });
    expect(target.APP_DB_HOST).toBe("db");
  });

  it("watch detects version changes and stops on close", async () => {
    const fake = await fakeInfisical();
    const c = track(
      new InfisicalClient({
        url: fake.server.url,
        token: "t",
        projectId: PROJECT,
        environment: "dev",
      }),
    );
    await c.provider.set("W", "1");
    const changes: (string | null)[] = [];
    const handle = c.provider.watch("W", 20, (n) => {
      changes.push(n?.reveal() ?? null);
    });
    await handle.ready;
    await c.provider.set("W", "2");
    await new Promise((r) => setTimeout(r, 120));
    expect(changes).toContain("2");
    await c.close();
    expect(handle.stopped).toBe(true);
  });
});
