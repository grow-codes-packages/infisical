import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AwsIamAuth,
  ConfigError,
  InfisicalClient,
  KUBERNETES_TOKEN_PATH,
  KubernetesAuth,
  REFRESH_FACTOR,
  STS_BODY,
  Secret,
  TokenAuth,
  UniversalAuth,
  ValidationError,
  detectTokenKind,
  signAwsRequest,
} from "../../src/index.js";
import { PROJECT, bodyOf, cleanup, jwt, reply, routed, track } from "./helpers.js";

afterEach(cleanup);

const LOGIN = "POST /api/v1/auth/universal-auth/login";
const RENEW = "POST /api/v1/auth/token/renew";
const REVOKE = "POST /api/v1/auth/token/revoke";
const SECRET = "GET /api/v4/secrets/SDK_SEED";

function tokenBody(token: string, expiresIn = 300, max = 3600) {
  return {
    status: 200,
    body: { accessToken: token, expiresIn, accessTokenMaxTTL: max, tokenType: "Bearer" },
  };
}

describe("detectTokenKind / TokenAuth", () => {
  it("detects service tokens, user JWTs and identity tokens", () => {
    expect(detectTokenKind("st.abc.def")).toBe("serviceToken");
    expect(detectTokenKind(jwt({ authTokenType: "accessToken" }))).toBe("user");
    expect(detectTokenKind(jwt({ authTokenType: "identityAccessToken" }))).toBe("identity");
    expect(detectTokenKind("a.%%%.c")).toBe("identity");
    expect(detectTokenKind("opaque")).toBe("identity");
  });

  it("TokenAuth is static and redacted", async () => {
    const t = new TokenAuth(new Secret("st.x.y"), {});
    expect(t.tokenKind).toBe("serviceToken");
    expect(new TokenAuth("opaque-token", { kind: "user" }).tokenKind).toBe("user");
    expect((await t.token()).reveal()).toBe("st.x.y");
    t.bind();
    t.invalidate();
    await t.close();
    expect(t.knownSecrets()).toEqual(["st.x.y"]);
    expect(String(t)).toBe("TokenAuth(serviceToken)");
    expect(t.refreshable).toBe(false);
    expect(() => new TokenAuth("  ")).toThrow(ConfigError);
    expect(() => new TokenAuth("")).toThrow(ConfigError);
  });
});

describe("UniversalAuth", () => {
  it("login (no Authorization header), renew, revoke", async () => {
    const s = await routed({
      [LOGIN]: tokenBody("access-1"),
      [RENEW]: tokenBody("access-2"),
      [REVOKE]: reply("universalAuth.revoke.ok"),
    });
    const ua = new UniversalAuth("client-id", "client-secret-value");
    expect(String(ua)).toBe("UniversalAuth([REDACTED])");
    await expect(ua.login()).rejects.toThrow(/pass this auth object/);
    track(new InfisicalClient({ url: s.url, auth: ua, organizationSlug: "org" }));
    expect(ua.accessToken).toBeNull();
    const t = await ua.login();
    expect(t.accessToken.reveal()).toBe("access-1");
    expect(t.expiresInMs).toBe(300_000);
    expect(t.maxTtlMs).toBe(3_600_000);
    expect(t.tokenType).toBe("Bearer");
    const loginReq = s.requests[0]!;
    expect(loginReq.headers.authorization).toBeUndefined();
    expect(bodyOf(loginReq)).toEqual({
      clientId: "client-id",
      clientSecret: "client-secret-value",
      organizationSlug: "org",
    });
    expect(ua.knownSecrets()).toEqual(["access-1", "client-secret-value"]);
    expect((await ua.renew()).accessToken.reveal()).toBe("access-2");
    expect(bodyOf(s.requests[1]!)).toEqual({ accessToken: "access-1" });
    expect(s.requests[1]!.headers.authorization).toBeUndefined();
    await ua.revoke();
    expect(bodyOf(s.requests[2]!)).toEqual({ accessToken: "access-2" });
    expect(ua.accessToken).toBeNull();
    await ua.revoke(); // no token: no request
    expect(s.requests).toHaveLength(3);
    await expect(ua.renew()).rejects.toMatchObject({ code: "AUTHENTICATION" });
  });

  it("login failures map to AUTHENTICATION and never leak the secret", async () => {
    const s = await routed({
      [LOGIN]: (_r, i) =>
        i === 0 ? reply("universalAuth.login.401") : reply("universalAuth.login.withBearer403"),
    });
    const ua = new UniversalAuth("client-id", "client-secret-value");
    track(new InfisicalClient({ url: s.url, auth: ua }));
    const e1 = await ua.login().catch((e: unknown) => e);
    expect(e1).toMatchObject({ code: "AUTHENTICATION", httpStatus: 401 });
    expect((e1 as Error).message).not.toContain("client-secret-value");
    expect((e1 as { requestId?: string }).requestId).toMatch(/^req-/);
    await expect(ua.login()).rejects.toMatchObject({ code: "AUTHENTICATION", httpStatus: 403 });
  });

  it("rejects bad input and double binding", async () => {
    expect(() => new UniversalAuth("", "x")).toThrow(ValidationError);
    expect(() => new UniversalAuth("id", "")).toThrow(ConfigError);
    const s = await routed({});
    const ua = new UniversalAuth("id", "secret");
    track(new InfisicalClient({ url: s.url, auth: ua }));
    expect(() => track(new InfisicalClient({ url: s.url, auth: ua }))).toThrow(/already bound/);
  });

  it("automatic refresh: login, renew at 80 %, re-login near max TTL and after renew failure", async () => {
    let now = 1_000_000;
    let tokens = 0;
    let renewFails = false;
    const s = await routed({
      [LOGIN]: () => tokenBody(`login-${++tokens}`, 100, 300),
      [RENEW]: () =>
        renewFails
          ? reply("universalAuth.renew.revoked")
          : tokenBody(`renew-${++tokens}`, 100, 300),
      [SECRET]: reply("getSecret.ok"),
    });
    const ua = new UniversalAuth("id", "secret");
    const client = track(
      new InfisicalClient(
        { url: s.url, auth: ua, projectId: PROJECT, environment: "dev" },
        { now: () => now },
      ),
    );
    const read = async () => {
      await client.secrets.getSecret("SDK_SEED");
      return s.requests.at(-1)!.headers.authorization;
    };
    expect(await read()).toBe("Bearer login-1");
    now += 79_000;
    expect(await read()).toBe("Bearer login-1");
    now += 2_000; // past 80 % of 100 s → renew
    expect(await read()).toBe("Bearer renew-2");
    now += 200_000; // the chain's max TTL (300 s) is near → login
    expect(await read()).toBe("Bearer login-3");
    renewFails = true;
    now += 85_000; // renew fails → login
    expect(await read()).toBe("Bearer login-4");
    expect(REFRESH_FACTOR).toBe(0.8);
  });

  it("concurrent calls share one login; 401 triggers one re-login", async () => {
    let logins = 0;
    const s = await routed({
      [LOGIN]: () => ({ ...tokenBody(`t-${++logins}`, 0, 0), delayMs: 20 }),
      [SECRET]: reply("getSecret.ok"),
    });
    const ua = new UniversalAuth("id", "secret");
    const client = track(
      new InfisicalClient({ url: s.url, auth: ua, projectId: PROJECT, environment: "dev" }),
    );
    await Promise.all([client.secrets.getSecret("SDK_SEED"), client.secrets.getSecret("SDK_SEED")]);
    expect(logins).toBe(1);
    // expiresIn 0 / max 0: a token without lifetime is replaced on the next call
    await client.secrets.getSecret("SDK_SEED");
    expect(logins).toBe(2);
  });

  it("re-logs in once on 401 and gives up after the second 401", async () => {
    let logins = 0;
    const s = await routed({
      [LOGIN]: () => tokenBody(`t-${++logins}`),
      [SECRET]: (req) =>
        req.headers.authorization === "Bearer t-1"
          ? reply("auth.revokedToken")
          : reply("getSecret.ok"),
      "GET /api/v4/secrets/ALWAYS": reply("auth.revokedToken"),
    });
    const ua = new UniversalAuth("id", "secret");
    const client = track(
      new InfisicalClient({ url: s.url, auth: ua, projectId: PROJECT, environment: "dev" }),
    );
    expect((await client.secrets.getSecret("SDK_SEED")).key).toBe("SDK_49LJ3988_ONE");
    expect(logins).toBe(2);
    await expect(client.secrets.getSecret("ALWAYS")).rejects.toMatchObject({
      code: "AUTHENTICATION",
    });
    expect(logins).toBe(3);
  });

  it("static tokens are not retried on 401", async () => {
    const s = await routed({ [SECRET]: reply("auth.revokedToken") });
    const client = track(
      new InfisicalClient({ url: s.url, token: "tok", projectId: PROJECT, environment: "dev" }),
    );
    await expect(client.secrets.getSecret("SDK_SEED")).rejects.toMatchObject({
      code: "AUTHENTICATION",
    });
    expect(s.requests).toHaveLength(1);
  });

  it("cancellation during renew is not swallowed", async () => {
    let now = 0;
    const s = await routed({
      [LOGIN]: tokenBody("a", 10, 1000),
      [RENEW]: { ...tokenBody("b", 10, 1000), delayMs: 200 },
    });
    const ua = new UniversalAuth("id", "secret");
    track(new InfisicalClient({ url: s.url, auth: ua }, { now: () => now }));
    await ua.token();
    now += 9_000;
    const ctrl = new AbortController();
    const p = ua.token({ signal: ctrl.signal });
    setTimeout(() => ctrl.abort(), 20);
    await expect(p).rejects.toMatchObject({ code: "CANCELLED" });
  });

  it("revokeOnClose revokes the login token; errors are ignored", async () => {
    const s = await routed({ [LOGIN]: tokenBody("tok-a"), [REVOKE]: { status: 500 } });
    const ua = new UniversalAuth("id", "secret");
    const client = new InfisicalClient({
      url: s.url,
      auth: ua,
      revokeOnClose: true,
      retry: { maxRetries: 0 },
    });
    await ua.login();
    await client.close();
    expect(s.requests.map((r) => r.url)).toEqual([
      "/api/v1/auth/universal-auth/login",
      "/api/v1/auth/token/revoke",
    ]);
    expect(ua.accessToken).toBeNull();
  });

  it("rejects responses without accessToken", async () => {
    const s = await routed({ [LOGIN]: { status: 200, body: { expiresIn: 1 } } });
    const ua = new UniversalAuth("id", "secret");
    track(new InfisicalClient({ url: s.url, auth: ua }));
    await expect(ua.login()).rejects.toMatchObject({ code: "UNAVAILABLE" });
    const s2 = await routed({ [LOGIN]: { status: 200, body: { accessToken: "x" } } });
    const ua2 = new UniversalAuth("id", "secret");
    track(new InfisicalClient({ url: s2.url, auth: ua2 }));
    const t = await ua2.login();
    expect(t.tokenType).toBe("Bearer");
    expect(t.expiresInMs).toBe(0);
  });
});

describe("KubernetesAuth", () => {
  it("logs in with an inline JWT or the token file", async () => {
    const s = await routed({
      "POST /api/v1/auth/kubernetes-auth/login": (req) =>
        bodyOf(req).identityId === "missing"
          ? reply("kubernetesAuth.login.notConfigured")
          : tokenBody("k8s-access"),
    });
    const inline = new KubernetesAuth({ identityId: "id-1", jwt: "sa-jwt-value" });
    expect(inline.jwtPath).toBe(KUBERNETES_TOKEN_PATH);
    track(new InfisicalClient({ url: s.url, auth: inline }));
    expect((await inline.login()).accessToken.reveal()).toBe("k8s-access");
    expect(bodyOf(s.requests[0]!)).toEqual({ identityId: "id-1", jwt: "sa-jwt-value" });
    expect(inline.knownSecrets()).toContain("sa-jwt-value");

    const dir = mkdtempSync(join(tmpdir(), "k8s-"));
    const file = join(dir, "token");
    writeFileSync(file, "file-jwt\n");
    const fromFile = new KubernetesAuth({ identityId: "id-2", jwtPath: file });
    track(new InfisicalClient({ url: s.url, auth: fromFile }));
    await fromFile.login();
    expect(bodyOf(s.requests[1]!)).toEqual({ identityId: "id-2", jwt: "file-jwt" });
    expect(fromFile.knownSecrets()).toEqual(["k8s-access"]);

    const missingFile = new KubernetesAuth({ identityId: "id-3", jwtPath: join(dir, "nope") });
    track(new InfisicalClient({ url: s.url, auth: missingFile }));
    await expect(missingFile.login()).rejects.toBeInstanceOf(ConfigError);

    const notConfigured = new KubernetesAuth({ identityId: "missing", jwt: "j" });
    track(new InfisicalClient({ url: s.url, auth: notConfigured }));
    await expect(notConfigured.login()).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(() => new KubernetesAuth({ identityId: "" })).toThrow(ValidationError);
  });
});

describe("AwsIamAuth / signAwsRequest", () => {
  const creds = {
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  };
  const date = new Date("2026-11-18T12:00:00Z");

  it("matches the botocore SigV4 signature (with and without session token)", () => {
    const base = {
      method: "POST",
      host: "sts.eu-central-1.amazonaws.com",
      path: "/",
      region: "eu-central-1",
      service: "sts",
      body: STS_BODY,
      date,
      ...creds,
    };
    const signed = signAwsRequest({
      ...base,
      headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
    });
    expect(signed.Host).toBe("sts.eu-central-1.amazonaws.com");
    expect(signed["X-Amz-Date"]).toBe("20261118T120000Z");
    expect(signed.Authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261118/eu-central-1/sts/aws4_request, " +
        "SignedHeaders=content-type;host;x-amz-date, " +
        "Signature=3c567ac0245fb355268d7e973a8550a595b77d0068f7003091d5f3be5275c726",
    );
    const withToken = signAwsRequest({
      ...base,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        host: "sts.eu-central-1.amazonaws.com",
        "X-Amz-Security-Token": "SESSIONTOKENEXAMPLE",
      },
    });
    expect(withToken.Authorization).toContain(
      "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, " +
        "Signature=e2d61764114ac5abbd9e0312197536c4b0c777f879b178617bccc808ee33552b",
    );
    expect(() => signAwsRequest({ ...base, headers: {}, accessKeyId: "" })).toThrow(
      ValidationError,
    );
  });

  it("canonicalises query strings", () => {
    const a = signAwsRequest({
      method: "GET",
      host: "h",
      path: "/",
      query: "b=2&a=1&a=0&&flag",
      region: "r",
      service: "s",
      headers: {},
      body: "",
      date,
      ...creds,
    });
    const b = signAwsRequest({
      method: "GET",
      host: "h",
      path: "/",
      query: "a=0&a=1&b=2&flag",
      region: "r",
      service: "s",
      headers: {},
      body: "",
      date,
      ...creds,
    });
    expect(a.Authorization).toBe(b.Authorization);
  });

  it("builds the login body from explicit, provider and env credentials", async () => {
    const explicit = new AwsIamAuth({
      identityId: "id-1",
      region: "eu-central-1",
      credentials: creds,
    });
    const req = await explicit.buildLoginRequest(date);
    expect(req.iamHttpRequestMethod).toBe("POST");
    expect(Buffer.from(req.iamRequestBody, "base64").toString()).toBe(STS_BODY);
    const headers = JSON.parse(Buffer.from(req.iamRequestHeaders, "base64").toString());
    expect(headers.Authorization).toContain("Signature=3c567ac0");
    expect(explicit.knownSecrets()).toEqual([creds.secretAccessKey]);

    const provider = new AwsIamAuth({
      identityId: "id-2",
      env: { AWS_DEFAULT_REGION: "us-west-2" },
      credentials: () => Promise.resolve({ ...creds, sessionToken: new Secret("sess-token") }),
    });
    expect(provider.region).toBe("us-west-2");
    const h2 = JSON.parse(
      Buffer.from((await provider.buildLoginRequest(date)).iamRequestHeaders, "base64").toString(),
    );
    expect(h2.Host).toBe("sts.us-west-2.amazonaws.com");
    expect(h2["X-Amz-Security-Token"]).toBe("sess-token");

    const fromEnv = new AwsIamAuth({
      identityId: "id-3",
      env: {
        AWS_REGION: "eu-west-1",
        AWS_ACCESS_KEY_ID: "AKID",
        AWS_SECRET_ACCESS_KEY: "secret-key",
        AWS_SESSION_TOKEN: "env-session",
      },
    });
    const h3 = JSON.parse(
      Buffer.from((await fromEnv.buildLoginRequest()).iamRequestHeaders, "base64").toString(),
    );
    expect(h3["X-Amz-Security-Token"]).toBe("env-session");
    const noSession = new AwsIamAuth({
      identityId: "id-3",
      env: {
        AWS_ACCESS_KEY_ID: "AKID",
        AWS_SECRET_ACCESS_KEY: "secret-key",
        AWS_SESSION_TOKEN: "",
      },
    });
    expect(noSession.region).toBe("us-east-1");
    await noSession.buildLoginRequest();

    const none = new AwsIamAuth({ identityId: "id-4", env: {} });
    await expect(none.buildLoginRequest()).rejects.toBeInstanceOf(ConfigError);
    expect(() => new AwsIamAuth({ identityId: " " })).toThrow(ValidationError);
    expect(new AwsIamAuth({ identityId: "x" }).region).toBeTypeOf("string");
  });

  it("posts the signed request to /api/v1/auth/aws-auth/login", async () => {
    const s = await routed({
      "POST /api/v1/auth/aws-auth/login": reply("awsIamAuth.login.notConfigured"),
    });
    const aws = new AwsIamAuth({ identityId: "id-1", region: "eu-central-1", credentials: creds });
    track(new InfisicalClient({ url: s.url, auth: aws }));
    await expect(aws.login()).rejects.toMatchObject({ code: "NOT_FOUND" });
    const body = bodyOf(s.requests[0]!);
    expect(body.identityId).toBe("id-1");
    expect(body.iamHttpRequestMethod).toBe("POST");
    expect(s.requests[0]!.body).not.toContain(creds.secretAccessKey);
  });
});
