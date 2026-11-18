// Integration tests against the real Infisical service (docker/compose.yml + bootstrap). Every
// public function is called at least once with a round-trip assertion (write → read back).
// Runs on Node >= 24 with type stripping: erasable TypeScript syntax only.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, describe, test } from "node:test";
import {
  AwsIamAuth,
  InfisicalClient,
  type InfisicalConfigOptions,
  InfisicalError,
  KubernetesAuth,
  TokenAuth,
  UniversalAuth,
} from "@grow-codes/infisical";
import { loadBootstrapEnv } from "./env.ts";

const RUN = randomBytes(4).toString("hex").toUpperCase();
const key = (name: string): string => `SDK_${RUN}_${name}`;
const clients: InfisicalClient[] = [];

function env(name: string): string {
  const v = process.env[name];
  assert.ok(v !== undefined && v !== "", `${name} must be set (bootstrap env)`);
  return v;
}

function client(overrides: InfisicalConfigOptions = {}): InfisicalClient {
  const c = InfisicalClient.fromEnv(overrides);
  clients.push(c);
  return c;
}

/** A client that authenticates with a static token only (no Universal Auth). */
function tokenClient(token: string, overrides: InfisicalConfigOptions = {}): InfisicalClient {
  return client({ auth: new TokenAuth(token), ...overrides });
}

async function rejectsWith(p: Promise<unknown>, code: string): Promise<InfisicalError> {
  let caught: unknown;
  try {
    await p;
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof InfisicalError, `expected ${code}, got ${String(caught)}`);
  assert.equal(caught.code, code, caught.message);
  return caught;
}

before(() => {
  loadBootstrapEnv();
  assert.ok(process.env.GROW_INFISICAL_URL, "GROW_INFISICAL_URL must be set");
});

after(async () => {
  await Promise.all(clients.map((c) => c.close()));
});

describe("core", () => {
  test("health reports a healthy service", async () => {
    const health = await client().health();
    assert.equal(health.healthy, true, JSON.stringify(health));
    assert.equal(health.status, "ok");
    assert.equal(health.details.redisConfigured, "true");
  });

  test("ping with Universal Auth, user token, service token and identity token", async () => {
    const ua = client();
    assert.ok(ua.auth instanceof UniversalAuth);
    assert.ok((await ua.ping()) >= 0);
    assert.ok((await tokenClient(env("INFISICAL_USER_TOKEN")).ping()) >= 0);
    assert.ok((await tokenClient(env("INFISICAL_SERVICE_TOKEN")).ping()) >= 0);
    assert.ok((await tokenClient(env("INFISICAL_VIEWER_TOKEN")).ping()) >= 0);
  });

  test("ping with a wrong token raises AUTHENTICATION and never leaks it", async () => {
    const wrong = "wrong-token-for-integration";
    const err = await rejectsWith(client({ token: wrong }).ping(), "AUTHENTICATION");
    assert.ok(!err.message.includes(wrong));
    assert.match(err.requestId ?? "", /^req-/);
  });

  test("serverVersion is UNSUPPORTED; close is idempotent", async () => {
    const c = InfisicalClient.fromEnv();
    await rejectsWith(c.serverVersion(), "UNSUPPORTED");
    await c.close();
    await c.close();
    await rejectsWith(c.ping(), "CONFIG");
  });
});

describe("auth", () => {
  test("UniversalAuth login → renew → revoke round trip", async () => {
    const ua = new UniversalAuth(env("INFISICAL_CLIENT_ID"), env("INFISICAL_CLIENT_SECRET"));
    const c = client({ auth: ua });
    const first = await ua.login();
    assert.ok(first.expiresInMs > 0);
    assert.equal(first.tokenType, "Bearer");
    const seed = await c.secrets.getSecret(env("INFISICAL_SEED_SECRET_NAME"));
    assert.equal(seed.value.reveal(), env("INFISICAL_SEED_SECRET_VALUE"));
    const renewed = await ua.renew();
    assert.ok(renewed.expiresInMs > 0);
    const revokedToken = renewed.accessToken.reveal();
    await ua.revoke();
    assert.equal(ua.accessToken, null);
    // the revoked token is rejected by the server
    await rejectsWith(tokenClient(revokedToken).ping(), "AUTHENTICATION");
    // the client logs in again on the next call
    assert.ok((await c.ping()) >= 0);
    assert.notEqual(ua.accessToken, null);
  });

  test("automatic re-login after the server revokes the token (401)", async () => {
    const ua = new UniversalAuth(env("INFISICAL_CLIENT_ID"), env("INFISICAL_CLIENT_SECRET"));
    const c = client({ auth: ua });
    const t = await ua.login();
    await c.transport.request({
      method: "POST",
      path: "/api/v1/auth/token/revoke",
      json: { accessToken: t.accessToken.reveal() },
    });
    const seed = await c.secrets.getSecret(env("INFISICAL_SEED_SECRET_NAME"));
    assert.equal(seed.value.reveal(), env("INFISICAL_SEED_SECRET_VALUE"));
    assert.notEqual(ua.accessToken?.accessToken.reveal(), t.accessToken.reveal());
  });

  test("unknown client id → AUTHENTICATION (does not touch the test identity's lockout)", async () => {
    const ua = new UniversalAuth("00000000-0000-4000-8000-000000000000", "not-the-secret");
    client({ auth: ua });
    const err = await rejectsWith(ua.login(), "AUTHENTICATION");
    assert.ok(!err.message.includes("not-the-secret"));
  });

  test("TokenAuth: identity token (viewer) reads but cannot write", async () => {
    const viewer = tokenClient(env("INFISICAL_VIEWER_TOKEN"));
    const seed = await viewer.secrets.getSecret(env("INFISICAL_SEED_SECRET_NAME"));
    assert.equal(seed.value.reveal(), env("INFISICAL_SEED_SECRET_VALUE"));
    await rejectsWith(viewer.secrets.createSecret(key("VIEWER"), "x"), "PERMISSION_DENIED");
    const service = tokenClient(env("INFISICAL_SERVICE_TOKEN"));
    const s2 = await service.secrets.getSecret(env("INFISICAL_SEED_SECRET_NAME"));
    assert.equal(s2.value.reveal(), env("INFISICAL_SEED_SECRET_VALUE"));
  });

  test("KubernetesAuth and AwsIamAuth send the documented login (method not configured → NOT_FOUND)", async () => {
    const identityId = env("INFISICAL_NOACCESS_IDENTITY_ID");
    const k8s = new KubernetesAuth({ identityId, jwt: "header.payload.signature" });
    client({ auth: k8s });
    const e1 = await rejectsWith(k8s.login(), "NOT_FOUND");
    assert.match(e1.message, /Kubernetes auth method not found/);
    const aws = new AwsIamAuth({
      identityId,
      region: "us-east-1",
      credentials: { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "integration-dummy-key" },
    });
    client({ auth: aws });
    const e2 = await rejectsWith(aws.login(), "NOT_FOUND");
    assert.match(e2.message, /AWS auth method not found/);
    assert.ok(!e2.message.includes("integration-dummy-key"));
  });
});

describe("secrets (v4)", () => {
  test("create → get → update (value, rename, comment, tags) → versions → delete", async () => {
    const c = client();
    const tag = await c.tags.createTag(`t-${RUN.toLowerCase()}`, "#00aa00");
    const name = key("ONE");
    const created = await c.secrets.createSecret(name, `v1-${RUN}`, { comment: "c1" });
    assert.equal(created.version, 1);
    assert.equal(c.apiVersion(), "v4");
    const got = await c.secrets.getSecret(name);
    assert.equal(got.value.reveal(), `v1-${RUN}`);
    assert.equal(got.comment, "c1");
    await rejectsWith(c.secrets.createSecret(name, "dup"), "CONFLICT");

    const updated = await c.secrets.updateSecret(name, { value: `v2-${RUN}` });
    assert.equal(updated.version, 2);
    // versions are looked up by the key they had: read v1 before the rename
    const v1 = await c.secrets.getSecret(name, { version: 1 });
    assert.equal(v1.value.reveal(), `v1-${RUN}`);
    const renamed = await c.secrets.updateSecret(name, {
      newName: key("RENAMED"),
      comment: "c2",
      tagIds: [tag.id],
    });
    assert.equal(renamed.key, key("RENAMED"));
    const after = await c.secrets.getSecret(key("RENAMED"));
    assert.equal(after.value.reveal(), `v2-${RUN}`);
    assert.equal(after.comment, "c2");
    assert.deepEqual(
      after.tags.map((t) => t.slug),
      [tag.slug],
    );
    const tagged = await c.secrets.listSecrets({ tagSlugs: [tag.slug] });
    assert.deepEqual(
      tagged.secrets.map((s) => s.key),
      [key("RENAMED")],
    );

    // versions: user tokens only; identities get PERMISSION_DENIED
    const user = tokenClient(env("INFISICAL_USER_TOKEN"));
    const versions = await user.secrets.listSecretVersions(after.id);
    assert.deepEqual(
      versions.map((v) => v.version),
      [3, 2, 1],
    );
    assert.equal(versions[2]?.value.reveal(), `v1-${RUN}`);
    await rejectsWith(c.secrets.listSecretVersions(after.id), "PERMISSION_DENIED");

    await c.secrets.deleteSecret(key("RENAMED"));
    await rejectsWith(c.secrets.getSecret(key("RENAMED")), "NOT_FOUND");
    await rejectsWith(c.secrets.deleteSecret(key("RENAMED")), "NOT_FOUND");
    await c.tags.deleteTag(tag.id);
  });

  test("batch create / update (upsert) / delete", async () => {
    const c = client();
    const created = await c.secrets.createSecrets([
      { key: key("B1"), value: "b1" },
      { key: key("B2"), value: "b2", comment: "c" },
    ]);
    assert.equal(created.length, 2);
    await rejectsWith(c.secrets.createSecrets([{ key: key("B1"), value: "x" }]), "CONFLICT");
    const updated = await c.secrets.updateSecrets(
      [
        { key: key("B1"), value: "b1b" },
        { key: key("UP"), value: "u" },
      ],
      { mode: "upsert" },
    );
    assert.equal(updated.length, 2);
    assert.equal((await c.secrets.getSecret(key("B1"))).value.reveal(), "b1b");
    assert.equal((await c.secrets.getSecret(key("UP"))).value.reveal(), "u");
    await rejectsWith(c.secrets.updateSecrets([{ key: key("NOPE"), value: "x" }]), "NOT_FOUND");
    const deleted = await c.secrets.deleteSecrets([key("B1"), { key: key("B2") }, key("UP")]);
    assert.equal(deleted.length, 3);
    const list = await c.secrets.listSecrets();
    assert.ok(!list.secrets.some((s) => s.key.startsWith(`SDK_${RUN}_B`)));
  });

  test("reference expansion on read (same env and cross env + folder)", async () => {
    const c = client();
    await c.secrets.createSecret(key("HOST"), `db-${RUN}`);
    await c.secrets.createSecret(
      key("DSN"),
      `pg://\${${key("HOST")}}/x|\${staging.common.SDK_COMMON}`,
    );
    const expanded = await c.secrets.getSecret(key("DSN"));
    assert.equal(expanded.value.reveal(), `pg://db-${RUN}/x|common-value-1`);
    const raw = await c.secrets.getSecret(key("DSN"), { expandReferences: false });
    assert.match(raw.value.reveal(), /\$\{/);
    const list = await c.secrets.listSecrets({ expandReferences: true });
    assert.equal(
      list.secrets.find((s) => s.key === key("DSN"))?.value.reveal(),
      `pg://db-${RUN}/x|common-value-1`,
    );
    await c.secrets.deleteSecrets([key("HOST"), key("DSN")]);
  });

  test("personal override (user token)", async () => {
    const user = tokenClient(env("INFISICAL_USER_TOKEN"), { expandSecretReferences: false });
    await user.secrets.createSecret(key("P"), "shared-value");
    await user.secrets.createSecret(key("P"), "personal-value", { type: "personal" });
    const personal = await user.secrets.getSecret(key("P"), { type: "personal" });
    assert.equal(personal.value.reveal(), "personal-value");
    assert.equal(personal.type, "personal");
    await user.secrets.deleteSecret(key("P"), { type: "personal" });
    const shared = await user.secrets.getSecret(key("P"));
    assert.equal(shared.value.reveal(), "shared-value");
    await user.secrets.deleteSecret(key("P"));
  });

  test("forced v3 (raw routes): every secrets call round-trips", async () => {
    const c = client({ apiVersion: "v3" });
    assert.equal(c.apiVersion(), "v3");
    await c.secrets.createSecret(key("V3"), "r1");
    assert.equal((await c.secrets.getSecret(key("V3"))).value.reveal(), "r1");
    await c.secrets.updateSecret(key("V3"), { value: "r2" });
    const list = await c.secrets.listSecrets();
    assert.equal(list.secrets.find((s) => s.key === key("V3"))?.value.reveal(), "r2");
    await c.secrets.createSecrets([{ key: key("V3B"), value: "b" }]);
    await c.secrets.updateSecrets([{ key: key("V3B"), value: "b2" }]);
    assert.equal((await c.secrets.getSecret(key("V3B"))).value.reveal(), "b2");
    await c.secrets.deleteSecrets([key("V3B")]);
    await c.secrets.deleteSecret(key("V3"));
    await rejectsWith(c.secrets.getSecret(key("V3")), "NOT_FOUND");
  });

  test("missing environment → CONFIG; missing folder → NOT_FOUND", async () => {
    const c = client({ environment: "" });
    await rejectsWith(c.secrets.listSecrets({ environment: undefined }), "CONFIG");
    const d = client();
    await rejectsWith(
      d.secrets.createSecret(key("X"), "x", { secretPath: `/missing-${RUN}` }),
      "NOT_FOUND",
    );
  });
});

describe("folders, projects, tags, imports", () => {
  test("folders: create → list → update → list recursive → delete", async () => {
    const c = client();
    const name = `f-${RUN.toLowerCase()}`;
    const created = await c.folders.createFolder(name, { description: "d" });
    assert.equal(created.path, `/${name}`);
    await rejectsWith(c.folders.createFolder(name), "CONFLICT");
    assert.ok((await c.folders.listFolders()).some((f) => f.name === name));
    await c.folders.createFolder("inner", { path: `/${name}` });
    const renamed = await c.folders.updateFolder(created.id, { name: `g-${RUN.toLowerCase()}` });
    assert.equal(renamed.name, `g-${RUN.toLowerCase()}`);
    const rec = await c.folders.listFolders({ recursive: true });
    assert.ok(rec.some((f) => f.relativePath === `/g-${RUN.toLowerCase()}/inner`));
    const deleted = await c.folders.deleteFolder(created.id, { forceDelete: true });
    assert.equal(deleted.id, created.id);
    assert.ok(!(await c.folders.listFolders()).some((f) => f.id === created.id));
  });

  test("projects + environments", async () => {
    const c = client();
    const page = await c.projects.listProjects();
    assert.ok(page.projects.some((p) => p.id === env("INFISICAL_PROJECT_ID")));
    assert.ok(page.totalCount >= 1);
    const project = await c.projects.getProject();
    assert.equal(project.slug, env("INFISICAL_PROJECT_SLUG"));
    const bySlug = await c.projects.getProjectBySlug(env("INFISICAL_PROJECT_SLUG"));
    assert.equal(bySlug.id, project.id);
    const slug = `e-${RUN.toLowerCase()}`;
    const created = await c.projects.createEnvironment(`E ${RUN}`, slug);
    assert.equal(created.slug, slug);
    const envs = await c.projects.listEnvironments();
    assert.ok(envs.some((e) => e.slug === "dev"));
    assert.ok(envs.some((e) => e.slug === slug));
    await rejectsWith(c.projects.createEnvironment(`E ${RUN}`, slug), "CONFLICT");
    const viewer = tokenClient(env("INFISICAL_VIEWER_TOKEN"));
    await rejectsWith(
      viewer.projects.createEnvironment("V", `v-${RUN.toLowerCase()}`),
      "PERMISSION_DENIED",
    );
  });

  test("tags: create → list → delete", async () => {
    const c = client();
    const slug = `tag-${RUN.toLowerCase()}`;
    const tag = await c.tags.createTag(slug, "#123456");
    assert.ok((await c.tags.listTags()).some((t) => t.id === tag.id && t.color === "#123456"));
    await rejectsWith(c.tags.createTag(slug, "#123456"), "CONFLICT");
    await c.tags.deleteTag(tag.id);
    assert.ok(!(await c.tags.listTags()).some((t) => t.id === tag.id));
  });

  test("imports: create → list → read through → delete", async () => {
    const c = client();
    const folder = `i-${RUN.toLowerCase()}`;
    await c.folders.createFolder(folder);
    const imp = await c.imports.createSecretImport({
      path: `/${folder}`,
      importEnvironment: "staging",
      importPath: "/common",
    });
    const list = await c.imports.listSecretImports({ path: `/${folder}` });
    assert.ok(list.some((i) => i.id === imp.id && i.importEnvironment.slug === "staging"));
    const secrets = await c.secrets.listSecrets({ secretPath: `/${folder}`, includeImports: true });
    assert.equal(
      secrets.imports
        .flatMap((i) => i.secrets)
        .find((s) => s.key === "SDK_COMMON")
        ?.value.reveal(),
      "common-value-1",
    );
    const viaImport = await c.secrets.getSecret("SDK_COMMON", { secretPath: `/${folder}` });
    assert.equal(viaImport.value.reveal(), "common-value-1");
    await c.imports.deleteSecretImport(imp.id, { path: `/${folder}` });
    assert.equal((await c.imports.listSecretImports({ path: `/${folder}` })).length, 0);
    await c.folders.deleteFolder(folder, { forceDelete: true });
  });
});

describe("env injection", () => {
  test("loadEnv and exportDotenv over a folder tree", async () => {
    const c = client();
    const folder = `e-${RUN.toLowerCase()}`;
    await c.folders.createFolder(folder);
    await c.folders.createFolder("nested", { path: `/${folder}` });
    await c.secrets.createSecret(key("TOP"), "top", { secretPath: `/${folder}` });
    await c.secrets.createSecret(key("DEEP"), "deep\nline", { secretPath: `/${folder}/nested` });
    const target: Record<string, string | undefined> = { [key("TOP")]: "keep" };
    const set = await c.secrets.loadEnv({ secretPath: `/${folder}`, recursive: true, env: target });
    assert.deepEqual(set, { [key("DEEP")]: key("DEEP") });
    assert.equal(target[key("TOP")], "keep");
    assert.equal(target[key("DEEP")], "deep\nline");
    await c.secrets.loadEnv({ secretPath: `/${folder}`, env: target, override: true });
    assert.equal(target[key("TOP")], "top");
    const dotenv = await c.secrets.exportDotenv({ secretPath: `/${folder}`, recursive: true });
    assert.equal(dotenv, `${key("DEEP")}="deep\\nline"\n${key("TOP")}="top"\n`);
    await c.folders.deleteFolder(folder, { forceDelete: true });
  });
});

describe("SecretsProvider", () => {
  test("set (creates folders, tags) → get → metadata → list → getAll → loadEnv → watch → delete", async () => {
    const c = client();
    const p = c.secretsProvider({ basePath: `/p-${RUN.toLowerCase()}` });
    assert.equal(
      await p.set("app/DB_HOST", "db", {
        description: "d",
        tags: { [`pt-${RUN.toLowerCase()}`]: "#ff0000" },
      }),
      "1",
    );
    assert.equal(await p.set("app/DB_HOST", "db2"), "2");
    assert.equal(await p.set("app/PORT", "5432"), "1");
    assert.equal(await p.getString("app/DB_HOST"), "db2");
    assert.equal(await p.getNumber("app/PORT"), 5432);
    assert.equal((await p.get("app/DB_HOST", { version: "1" }))?.reveal(), "db");
    const meta = await p.metadata("app/DB_HOST");
    assert.equal(meta?.version, "2");
    assert.equal(meta?.extra.comment, "d");
    assert.deepEqual(Object.keys(meta?.tags ?? {}), [`pt-${RUN.toLowerCase()}`]);
    assert.deepEqual(
      (await p.list("app")).map((m) => m.name),
      ["app/DB_HOST", "app/PORT"],
    );
    assert.equal((await p.getAll("app")).get("app/PORT")?.reveal(), "5432");
    assert.equal((await p.getMany(["app/PORT", "app/NOPE"])).size, 1);
    assert.equal(await p.exists("app/NOPE"), false);
    await rejectsWith(p.require("app/NOPE"), "NOT_FOUND");
    const target: Record<string, string | undefined> = {};
    assert.deepEqual(await p.loadEnv("app", { env: target, prefix: "X_" }), {
      X_DB_HOST: "app/DB_HOST",
      X_PORT: "app/PORT",
    });
    assert.equal(target.X_PORT, "5432");

    const seen: (string | null)[] = [];
    const handle = p.watch("app/PORT", 200, (n) => {
      seen.push(n?.reveal() ?? null);
    });
    await handle.ready;
    await p.set("app/PORT", "6543");
    for (let i = 0; i < 50 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 100));
    handle.stop();
    assert.deepEqual(seen, ["6543"]);

    await p.delete("app/DB_HOST");
    await p.delete("app/PORT");
    assert.equal(await p.get("app/DB_HOST"), null);
    await rejectsWith(p.delete("app/DB_HOST"), "NOT_FOUND");
  });
});
