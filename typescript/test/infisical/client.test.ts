import { afterEach, describe, expect, it } from "vitest";
import {
  InfisicalClient,
  InfisicalConfig,
  InfisicalError,
  PACKAGE_KEY,
  TokenAuth,
  UniversalAuth,
} from "../../src/index.js";
import { closedPort, startServer } from "../helpers/server.js";
import { cleanup, clientFor, jwt, reply, routed, track } from "./helpers.js";

afterEach(cleanup);

describe("InfisicalClient core", () => {
  it("health maps GET /api/status", async () => {
    const s = await routed({ "GET /api/status": reply("health.ok") });
    const c = clientFor(s);
    const h = await c.health();
    expect(h.healthy).toBe(true);
    expect(h.status).toBe("ok");
    expect(h.details.redisConfigured).toBe("true");
    expect(h.details.message).toBeUndefined();
    expect(s.requests[0]!.headers.authorization).toBeUndefined();
    expect(s.requests[0]!.headers["user-agent"]).toMatch(
      new RegExp(`^grow-codes-${PACKAGE_KEY}/\\S+ \\(typescript\\)$`),
    );
  });

  it("health: empty body, unhealthy status, unreachable, cancelled", async () => {
    const s = await routed({ "GET /api/status": { status: 200 } });
    expect(await clientFor(s).health()).toMatchObject({ healthy: true, status: "ok" });
    const down = await routed({ "GET /api/status": { status: 503 } });
    expect(await clientFor(down, { retry: { maxRetries: 0 } }).health()).toMatchObject({
      healthy: false,
      status: "unhealthy",
    });
    const port = await closedPort();
    const c = track(
      new InfisicalClient({ url: `http://127.0.0.1:${port}`, retry: { maxRetries: 0 } }),
    );
    expect(await c.health()).toMatchObject({ healthy: false, status: "unreachable" });
    await expect(clientFor(s).health({ signal: AbortSignal.abort() })).rejects.toMatchObject({
      code: "CANCELLED",
    });
  });

  it("ping picks the route by token kind", async () => {
    const s = await routed({
      "GET /api/v1/identities/details": reply("ping.identity"),
      "GET /api/v2/users/me": reply("ping.user"),
      "GET /api/v2/service-token": reply("ping.serviceToken"),
    });
    expect(await clientFor(s).ping()).toBeGreaterThanOrEqual(0);
    await clientFor(s, { token: jwt({ authTokenType: "accessToken" }) }).ping();
    await clientFor(s, { token: "st.abc.secret" }).ping();
    await clientFor(s, { token: undefined, auth: new TokenAuth("x", { kind: "user" }) }).ping();
    expect(s.requests.map((r) => r.url)).toEqual([
      "/api/v1/identities/details",
      "/api/v2/users/me",
      "/api/v2/service-token",
      "/api/v2/users/me",
    ]);
    expect(s.requests[0]!.headers.authorization).toBe("Bearer identity-token-value");
  });

  it("ping without credentials → AUTHENTICATION (401 Token missing)", async () => {
    const s = await routed({ "GET /api/v1/identities/details": reply("auth.noToken") });
    const c = clientFor(s, { token: undefined });
    expect(c.auth).toBeUndefined();
    const err = await c.ping().catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "AUTHENTICATION", httpStatus: 401 });
    expect((err as InfisicalError).requestId).toBe("req-lMFd5Tl7rpeWrk");
    expect(s.requests[0]!.headers.authorization).toBeUndefined();
  });

  it("a malformed token (403 TokenError) is AUTHENTICATION and never leaks", async () => {
    const s = await routed({ "GET /api/v1/identities/details": reply("auth.malformedToken") });
    const err = await clientFor(s, { token: "wrong-token-xyz" })
      .ping()
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(InfisicalError);
    expect(err).toMatchObject({ code: "AUTHENTICATION", httpStatus: 403 });
    expect((err as Error).message).toBe(
      "ping: The provided access token is malformed. Please use a valid token or generate a new one and try again. (HTTP 403)",
    );
    expect((err as Error).message).not.toContain("wrong-token-xyz");
  });

  it("serverVersion is UNSUPPORTED without a request", async () => {
    const s = await routed({});
    await expect(clientFor(s).serverVersion()).rejects.toMatchObject({ code: "UNSUPPORTED" });
    expect(s.requests).toHaveLength(0);
  });

  it("core.close.idempotent: close twice; calls after close are CONFIG", async () => {
    const s = await routed({ "GET /api/status": reply("health.ok") });
    const c = new InfisicalClient({ url: s.url });
    const w = c.provider.watch("X", 1000, () => undefined);
    await c.close();
    await c.close();
    expect(w.stopped).toBe(true);
    await expect(c.ping()).rejects.toMatchObject({ code: "CONFIG" });
  });

  it("uses Universal Auth from clientId/clientSecret; explicit auth and token win", async () => {
    const s = await routed({});
    const ua = clientFor(s, { token: undefined, clientId: "id", clientSecret: "secret" });
    expect(ua.auth).toBeInstanceOf(UniversalAuth);
    const tok = clientFor(s, { clientId: "id", clientSecret: "secret" });
    expect(tok.auth).toBeInstanceOf(TokenAuth);
    const explicit = new TokenAuth("t2");
    expect(clientFor(s, { auth: explicit }).auth).toBe(explicit);
    expect(tok.apiVersion()).toBe("unknown");
    expect(clientFor(s, { apiVersion: "v3" }).apiVersion("secrets")).toBe("v3");
  });

  it("fromEnv builds from GROW_* variables", async () => {
    const s = await routed({ "GET /api/v1/identities/details": reply("ping.identity") });
    process.env.GROW_INFISICAL_URL = s.url;
    try {
      const c = track(InfisicalClient.fromEnv({ token: "tok" }));
      expect(c.config.url).toBe(s.url);
      await c.ping();
    } finally {
      delete process.env.GROW_INFISICAL_URL;
    }
  });

  it("config instances are accepted as is", async () => {
    const s = await routed({});
    const cfg = new InfisicalConfig({ url: s.url });
    expect(track(new InfisicalClient(cfg)).config).toBe(cfg);
  });
});

describe("error mapping through the interceptor", () => {
  it("400 already exists → CONFLICT; 422 issues → VALIDATION; 404 → NOT_FOUND", async () => {
    const s = await routed({
      "POST /api/v4/secrets/DUP": reply("createSecret.duplicate400"),
      "POST /api/v4/secrets/bad%3Aname": reply("createSecret.invalidName422"),
      "GET /api/v4/secrets/NOPE": reply("getSecret.404"),
    });
    const c = clientFor(s);
    const dup = await c.secrets.createSecret("DUP", "x").catch((e: unknown) => e);
    expect(dup).toMatchObject({
      code: "CONFLICT",
      httpStatus: 400,
      requestId: "req-gUedbtx3O8pTHI",
    });
    const bad = await c.secrets.createSecret("bad:name", "x").catch((e: unknown) => e);
    expect(bad).toMatchObject({ code: "VALIDATION", httpStatus: 422 });
    expect((bad as Error).message).toContain("secretName: Secret name cannot contain colon");
    await expect(c.secrets.getSecret("NOPE")).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("429 without Retry-After uses the message hint; Retry-After header wins", async () => {
    const body = reply("listSecrets.429-synthetic").body;
    let calls = 0;
    const s = await routed({
      "GET /api/v4/secrets": () => {
        calls++;
        return { status: 429, body };
      },
    });
    const slept: number[] = [];
    const c = track(
      new InfisicalClient(
        {
          url: s.url,
          token: "t",
          projectId: "p",
          environment: "dev",
          retry: { maxRetries: 1, initialBackoffMs: 1 },
        },
        {
          sleep: (ms) => {
            slept.push(ms);
            return Promise.resolve();
          },
        },
      ),
    );
    const err = await c.secrets.listSecrets().catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "RATE_LIMITED", retryAfterMs: 7000 });
    expect(calls).toBe(2);
    expect(slept[0]).toBe(7000);

    const h = await routed({
      "GET /api/v4/secrets": { status: 429, headers: { "retry-after": "1" }, body },
    });
    const c2 = clientFor(h, { retry: { maxRetries: 0 } });
    await expect(c2.secrets.listSecrets()).rejects.toMatchObject({ retryAfterMs: 1000 });
  });

  it("passes non-JSON and large error bodies through", async () => {
    const big = "x".repeat(70 * 1024);
    const s = await routed({
      "GET /api/v4/secrets": { status: 502, body: "<html>bad gateway</html>" },
      "GET /api/v4/secrets/BIG": { status: 400, body: big },
    });
    const c = clientFor(s, { retry: { maxRetries: 0 } });
    await expect(c.secrets.listSecrets()).rejects.toMatchObject({ code: "UNAVAILABLE" });
    await expect(c.secrets.getSecret("BIG")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("keeps a server x-request-id header", async () => {
    const s = await startServer([
      {
        status: 404,
        headers: { "x-request-id": "hdr-id" },
        body: { reqId: "body-id", statusCode: 404, message: "nope", error: "NotFound" },
      },
    ]);
    const c = clientFor(s);
    await expect(c.secrets.getSecret("A")).rejects.toMatchObject({ requestId: "hdr-id" });
    await s.close();
  });

  it("hooks see the request id taken from the body", async () => {
    const seen: (string | undefined)[] = [];
    const s = await routed({ "GET /api/v4/secrets/NOPE": reply("getSecret.404") });
    const c = clientFor(s, { hooks: { onResponse: (i) => seen.push(i.requestId) } });
    await c.secrets.getSecret("NOPE").catch(() => undefined);
    expect(seen).toEqual(["req-r5Ov49jIwmHNBv"]);
  });
});
