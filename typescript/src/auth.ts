// Service-owned. Infisical auth methods (API.md §2): Universal Auth, static tokens, Kubernetes
// Auth and AWS IAM Auth, with automatic access-token renewal and re-login.

import { createHash, createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  AuthenticationError,
  ConfigError,
  type HttpTransport,
  Secret,
  ValidationError,
} from "./core/index.js";
import { compact, num, requireText, send, str, unexpected } from "./http.js";

/** What kind of principal a token belongs to (selects the `ping()` route). */
export type TokenKind = "identity" | "user" | "serviceToken";

/** Everything an auth method needs from its client. @internal */
export interface AuthContext {
  readonly transport: HttpTransport;
  readonly organizationSlug?: string | undefined;
  readonly now: () => number;
}

/** Per-call cancellation. */
export interface AuthCallOptions {
  signal?: AbortSignal;
}

/** An access token returned by a login or renewal. */
export interface AccessToken {
  /** The bearer token (redacting wrapper). */
  readonly accessToken: Secret;
  /** Lifetime of this token in ms (`expiresIn`). */
  readonly expiresInMs: number;
  /** Longest lifetime reachable by renewals in ms (`accessTokenMaxTTL`, 0 = unlimited). */
  readonly maxTtlMs: number;
  /** Token type (`Bearer`). */
  readonly tokenType: string;
  /** When the token was obtained or last renewed. */
  readonly obtainedAt: Date;
}

/**
 * An auth method. Pass one as `auth` in {@link InfisicalConfigOptions}; the client binds it and
 * asks it for a token before every authenticated call.
 */
export interface InfisicalAuth {
  /** Method name (`token`, `universal-auth`, `kubernetes-auth`, `aws-auth`). */
  readonly kind: string;
  /** Principal kind of the tokens this method produces. */
  readonly tokenKind: TokenKind;
  /** Whether a rejected token can be replaced by logging in again. */
  readonly refreshable: boolean;
  /** Binds the method to a client. @internal */
  bind(context: AuthContext): void;
  /** The current token, logging in or renewing when needed. */
  token(options?: AuthCallOptions): Promise<Secret>;
  /** Forgets the current token (the next call logs in again). */
  invalidate(): void;
  /** Credential values to redact from errors. */
  knownSecrets(): string[];
  /** Releases the method; revokes a login token when `revoke` is true. */
  close(revoke?: boolean): Promise<void>;
}

/**
 * Detects the token kind: `st.…` is a legacy service token; a JWT whose payload has
 * `authTokenType: "accessToken"` is a user token; everything else is a machine identity token.
 */
export function detectTokenKind(token: string): TokenKind {
  if (token.startsWith("st.")) return "serviceToken";
  const parts = token.split(".");
  if (parts.length === 3) {
    try {
      const payload = JSON.parse(Buffer.from(parts[1] ?? "", "base64url").toString("utf8")) as {
        authTokenType?: unknown;
      };
      if (payload.authTokenType === "accessToken") return "user";
    } catch {
      // not a JWT: identity token by default
    }
  }
  return "identity";
}

/** A static token: machine identity token (Token Auth), user JWT or legacy service token. */
export class TokenAuth implements InfisicalAuth {
  readonly kind = "token";
  readonly tokenKind: TokenKind;
  readonly refreshable = false;
  readonly #token: Secret;

  /**
   * @param token the bearer token.
   * @param options.kind overrides the detected {@link TokenKind}.
   */
  constructor(token: string | Secret, options: { kind?: TokenKind } = {}) {
    const secret = Secret.from(token);
    if (secret === undefined || secret.reveal().trim() === "") {
      throw new ConfigError("TokenAuth: token must not be empty");
    }
    this.#token = secret;
    this.tokenKind = options.kind ?? detectTokenKind(secret.reveal());
  }

  bind(): void {
    // static tokens need no client
  }

  token(): Promise<Secret> {
    return Promise.resolve(this.#token);
  }

  invalidate(): void {
    // a static token cannot be replaced
  }

  knownSecrets(): string[] {
    return [this.#token.reveal()];
  }

  close(): Promise<void> {
    return Promise.resolve();
  }

  toString(): string {
    return `TokenAuth(${this.tokenKind})`;
  }
}

interface StoredToken extends AccessToken {
  /** When the login that started this token chain happened (ms). */
  readonly loginAt: number;
}

/** Fraction of a token's lifetime after which it is renewed. */
export const REFRESH_FACTOR = 0.8;

/**
 * Base of the login-based machine identity methods: `login`, `renew`, `revoke` and automatic
 * refresh (renew at 80 % of the lifetime, re-login when the max TTL is reached or renewal fails).
 */
export abstract class IdentityLoginAuth implements InfisicalAuth {
  abstract readonly kind: string;
  readonly tokenKind: TokenKind = "identity";
  readonly refreshable = true;
  #context: AuthContext | undefined;
  #token: StoredToken | undefined;
  #pending: Promise<Secret> | undefined;

  /** Login path, e.g. `/api/v1/auth/universal-auth/login`. */
  protected abstract readonly loginPath: string;
  /** Builds the login body (without `organizationSlug`). */
  protected abstract loginBody(options: AuthCallOptions): Promise<Record<string, unknown>>;

  bind(context: AuthContext): void {
    if (this.#context !== undefined && this.#context.transport !== context.transport) {
      throw new ConfigError(`${this.kind}: this auth object is already bound to another client`);
    }
    this.#context = context;
  }

  /** The bound client context (`ConfigError` before the method is passed to a client). */
  protected get context(): AuthContext {
    if (this.#context === undefined) {
      throw new ConfigError(`${this.kind}: pass this auth object to an InfisicalClient first`);
    }
    return this.#context;
  }

  /** The current access token (`null` before the first login or after revoke). */
  get accessToken(): AccessToken | null {
    return this.#token ?? null;
  }

  /** Logs in and stores the new access token. */
  async login(options: AuthCallOptions = {}): Promise<AccessToken> {
    const ctx = this.context;
    const body = await this.loginBody(options);
    const data = await send<unknown>(ctx.transport, {
      method: "POST",
      path: this.loginPath,
      operation: `auth.${this.kind}.login`,
      json: compact({ ...body, organizationSlug: ctx.organizationSlug }),
      signal: options.signal,
      login: true,
    });
    const now = ctx.now();
    this.#token = { ...parseAccessToken(data, `auth.${this.kind}.login`, now), loginAt: now };
    return this.#token;
  }

  /** Renews the current token (`POST /api/v1/auth/token/renew`) and stores the returned one. */
  async renew(options: AuthCallOptions = {}): Promise<AccessToken> {
    const ctx = this.context;
    const current = this.#token;
    if (current === undefined) {
      throw new AuthenticationError(`auth.${this.kind}.renew: no access token (login first)`);
    }
    const data = await send<unknown>(ctx.transport, {
      method: "POST",
      path: "/api/v1/auth/token/renew",
      operation: `auth.${this.kind}.renew`,
      json: { accessToken: current.accessToken.reveal() },
      signal: options.signal,
      login: true,
    });
    const now = ctx.now();
    this.#token = {
      ...parseAccessToken(data, `auth.${this.kind}.renew`, now),
      loginAt: current.loginAt,
    };
    return this.#token;
  }

  /** Revokes the current token (`POST /api/v1/auth/token/revoke`). No-op without a token. */
  async revoke(options: AuthCallOptions = {}): Promise<void> {
    const ctx = this.context;
    const current = this.#token;
    if (current === undefined) return;
    await send<unknown>(ctx.transport, {
      method: "POST",
      path: "/api/v1/auth/token/revoke",
      operation: `auth.${this.kind}.revoke`,
      json: { accessToken: current.accessToken.reveal() },
      signal: options.signal,
      login: true,
    });
    if (this.#token === current) this.#token = undefined;
  }

  token(options: AuthCallOptions = {}): Promise<Secret> {
    const current = this.#token;
    if (current !== undefined && !this.#needsRefresh(current)) {
      return Promise.resolve(current.accessToken);
    }
    this.#pending ??= this.#refresh(current, options).finally(() => {
      this.#pending = undefined;
    });
    return this.#pending;
  }

  #expiry(t: StoredToken): number {
    const own = t.obtainedAt.getTime() + t.expiresInMs;
    return t.maxTtlMs > 0 ? Math.min(own, t.loginAt + t.maxTtlMs) : own;
  }

  #needsRefresh(t: StoredToken): boolean {
    const start = t.obtainedAt.getTime();
    return this.context.now() >= start + (this.#expiry(t) - start) * REFRESH_FACTOR;
  }

  async #refresh(current: StoredToken | undefined, options: AuthCallOptions): Promise<Secret> {
    if (current !== undefined) {
      const now = this.context.now();
      const maxLeft =
        current.maxTtlMs > 0 ? current.loginAt + current.maxTtlMs - now : Number.POSITIVE_INFINITY;
      if (maxLeft > current.expiresInMs * (1 - REFRESH_FACTOR) && now < this.#expiry(current)) {
        try {
          return (await this.renew(options)).accessToken;
        } catch (err) {
          if ((err as { code?: unknown }).code === "CANCELLED") throw err;
          // renewal failed (revoked, max TTL): log in again
        }
      }
    }
    return (await this.login(options)).accessToken;
  }

  invalidate(): void {
    this.#token = undefined;
  }

  knownSecrets(): string[] {
    return this.#token === undefined ? [] : [this.#token.accessToken.reveal()];
  }

  async close(revoke = false): Promise<void> {
    if (revoke && this.#token !== undefined && this.#context !== undefined) {
      await this.revoke().catch(() => undefined);
    }
    this.#token = undefined;
  }

  toString(): string {
    return `${this.constructor.name}([REDACTED])`;
  }
}

function parseAccessToken(data: unknown, operation: string, now: number): AccessToken {
  const d = (data ?? {}) as Record<string, unknown>;
  const token = d.accessToken;
  if (typeof token !== "string" || token === "") throw unexpected(operation, "no accessToken");
  return {
    accessToken: new Secret(token),
    expiresInMs: num(d.expiresIn) * 1000,
    maxTtlMs: num(d.accessTokenMaxTTL) * 1000,
    tokenType: str(d.tokenType) === "" ? "Bearer" : str(d.tokenType),
    obtainedAt: new Date(now),
  };
}

/** Universal Auth (client id + client secret) — `POST /api/v1/auth/universal-auth/login`. */
export class UniversalAuth extends IdentityLoginAuth {
  readonly kind = "universal-auth";
  protected readonly loginPath = "/api/v1/auth/universal-auth/login";
  /** The client id. */
  readonly clientId: string;
  readonly #clientSecret: Secret;

  constructor(clientId: string, clientSecret: string | Secret) {
    super();
    this.clientId = requireText(clientId, "clientId", "UniversalAuth");
    const secret = Secret.from(clientSecret);
    if (secret === undefined)
      throw new ConfigError("UniversalAuth: clientSecret must not be empty");
    this.#clientSecret = secret;
  }

  protected loginBody(): Promise<Record<string, unknown>> {
    return Promise.resolve({ clientId: this.clientId, clientSecret: this.#clientSecret.reveal() });
  }

  override knownSecrets(): string[] {
    return [...super.knownSecrets(), this.#clientSecret.reveal()];
  }
}

/** Default path of the Kubernetes service-account token. */
export const KUBERNETES_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/** Options of {@link KubernetesAuth}. */
export interface KubernetesAuthOptions {
  /** Machine identity id. */
  identityId: string;
  /** Service-account JWT; read from {@link jwtPath} at every login when absent. */
  jwt?: string | Secret;
  /** Path of the service-account token (default {@link KUBERNETES_TOKEN_PATH}). */
  jwtPath?: string;
}

/** Kubernetes Auth — `POST /api/v1/auth/kubernetes-auth/login` with a service-account JWT. */
export class KubernetesAuth extends IdentityLoginAuth {
  readonly kind = "kubernetes-auth";
  protected readonly loginPath = "/api/v1/auth/kubernetes-auth/login";
  /** The machine identity id. */
  readonly identityId: string;
  /** Path the JWT is read from when no `jwt` was given. */
  readonly jwtPath: string;
  readonly #jwt: Secret | undefined;

  constructor(options: KubernetesAuthOptions) {
    super();
    this.identityId = requireText(options.identityId, "identityId", "KubernetesAuth");
    this.#jwt = Secret.from(options.jwt);
    this.jwtPath = options.jwtPath ?? KUBERNETES_TOKEN_PATH;
  }

  protected async loginBody(): Promise<Record<string, unknown>> {
    let jwt = this.#jwt?.reveal();
    if (jwt === undefined) {
      try {
        jwt = (await readFile(this.jwtPath, "utf8")).trim();
      } catch {
        throw new ConfigError(`KubernetesAuth: cannot read the service-account token file`);
      }
    }
    return { identityId: this.identityId, jwt };
  }

  override knownSecrets(): string[] {
    return [...super.knownSecrets(), ...(this.#jwt === undefined ? [] : [this.#jwt.reveal()])];
  }
}

/** AWS credentials used to sign the STS request. */
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string | Secret;
  sessionToken?: string | Secret;
}

/** Options of {@link AwsIamAuth}. */
export interface AwsIamAuthOptions {
  /** Machine identity id. */
  identityId: string;
  /** AWS region of the STS endpoint (default `AWS_REGION`, `AWS_DEFAULT_REGION`, `us-east-1`). */
  region?: string;
  /**
   * Credentials or a provider (e.g. the AWS SDK credential chain). Default: `AWS_ACCESS_KEY_ID`,
   * `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`.
   */
  credentials?: AwsCredentials | (() => Promise<AwsCredentials>);
  /** Environment for the defaults (default `process.env`). */
  env?: Readonly<Record<string, string | undefined>>;
}

/** The fields of an AWS IAM login body. */
export interface AwsLoginRequest {
  identityId: string;
  iamHttpRequestMethod: "POST";
  /** base64 of `Action=GetCallerIdentity&Version=2011-06-15`. */
  iamRequestBody: string;
  /** base64 of the JSON of the SigV4-signed headers. */
  iamRequestHeaders: string;
}

/** Body of the signed STS request. */
export const STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15";

/** AWS IAM Auth — signs `sts:GetCallerIdentity` (SigV4) and posts it to `/api/v1/auth/aws-auth/login`. */
export class AwsIamAuth extends IdentityLoginAuth {
  readonly kind = "aws-auth";
  protected readonly loginPath = "/api/v1/auth/aws-auth/login";
  /** The machine identity id. */
  readonly identityId: string;
  /** STS region. */
  readonly region: string;
  readonly #credentials: AwsIamAuthOptions["credentials"];
  readonly #env: Readonly<Record<string, string | undefined>>;
  #lastSecrets: string[] = [];

  constructor(options: AwsIamAuthOptions) {
    super();
    this.identityId = requireText(options.identityId, "identityId", "AwsIamAuth");
    this.#env = options.env ?? process.env;
    this.region =
      options.region ?? this.#env.AWS_REGION ?? this.#env.AWS_DEFAULT_REGION ?? "us-east-1";
    this.#credentials = options.credentials;
  }

  async #resolveCredentials(): Promise<AwsCredentials> {
    const c = this.#credentials;
    if (typeof c === "function") return c();
    if (c !== undefined) return c;
    const accessKeyId = this.#env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = this.#env.AWS_SECRET_ACCESS_KEY;
    if (accessKeyId === undefined || accessKeyId === "" || secretAccessKey === undefined) {
      throw new ConfigError(
        "AwsIamAuth: no AWS credentials (pass credentials or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)",
      );
    }
    const sessionToken = this.#env.AWS_SESSION_TOKEN;
    return {
      accessKeyId,
      secretAccessKey,
      ...(sessionToken === undefined || sessionToken === "" ? {} : { sessionToken }),
    };
  }

  /** Builds the signed login body (exposed for tests and custom flows). */
  async buildLoginRequest(date: Date = new Date()): Promise<AwsLoginRequest> {
    const creds = await this.#resolveCredentials();
    const secretKey = Secret.from(creds.secretAccessKey)?.reveal() ?? "";
    const session = Secret.from(creds.sessionToken)?.reveal();
    this.#lastSecrets = [secretKey, ...(session === undefined ? [] : [session])];
    const host = `sts.${this.region}.amazonaws.com`;
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
      Host: host,
    };
    if (session !== undefined) headers["X-Amz-Security-Token"] = session;
    const signed = signAwsRequest({
      method: "POST",
      host,
      path: "/",
      region: this.region,
      service: "sts",
      headers,
      body: STS_BODY,
      accessKeyId: creds.accessKeyId,
      secretAccessKey: secretKey,
      date,
    });
    return {
      identityId: this.identityId,
      iamHttpRequestMethod: "POST",
      iamRequestBody: Buffer.from(STS_BODY, "utf8").toString("base64"),
      iamRequestHeaders: Buffer.from(JSON.stringify(signed), "utf8").toString("base64"),
    };
  }

  protected async loginBody(): Promise<Record<string, unknown>> {
    return { ...(await this.buildLoginRequest(new Date(this.context.now()))) };
  }

  override knownSecrets(): string[] {
    return [...super.knownSecrets(), ...this.#lastSecrets];
  }
}

/** Input of {@link signAwsRequest}. */
export interface AwsSignInput {
  method: string;
  host: string;
  /** Absolute path (already URI-encoded), e.g. `/`. */
  path: string;
  /** Raw query string without `?` (sorted by the signer), default empty. */
  query?: string;
  region: string;
  service: string;
  /** Headers to sign (`Host` is added when missing). */
  headers: Record<string, string>;
  body: string;
  accessKeyId: string;
  secretAccessKey: string;
  date: Date;
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function hmac(key: string | Buffer, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

function canonicalQuery(query: string): string {
  if (query === "") return "";
  return query
    .split("&")
    .filter((p) => p !== "")
    .map((p) => {
      const eq = p.indexOf("=");
      const k = eq < 0 ? p : p.slice(0, eq);
      const v = eq < 0 ? "" : p.slice(eq + 1);
      return [k, v] as const;
    })
    .sort(([a, av], [b, bv]) => (a === b ? (av < bv ? -1 : 1) : a < b ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
}

/**
 * Signs a request with AWS Signature Version 4 and returns the headers to send: the input
 * headers plus `X-Amz-Date` and `Authorization`.
 */
export function signAwsRequest(input: AwsSignInput): Record<string, string> {
  if (input.accessKeyId === "" || input.secretAccessKey === "") {
    throw new ValidationError("signAwsRequest: credentials must not be empty");
  }
  const amzDate = input.date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const day = amzDate.slice(0, 8);
  const headers: Record<string, string> = { ...input.headers };
  if (!Object.keys(headers).some((k) => k.toLowerCase() === "host")) headers.Host = input.host;
  headers["X-Amz-Date"] = amzDate;
  const canon = Object.entries(headers)
    .map(([k, v]) => [k.toLowerCase(), v.trim().replace(/\s+/g, " ")] as const)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const signedHeaders = canon.map(([k]) => k).join(";");
  const canonicalRequest = [
    input.method.toUpperCase(),
    input.path,
    canonicalQuery(input.query ?? ""),
    canon.map(([k, v]) => `${k}:${v}\n`).join(""),
    signedHeaders,
    sha256Hex(input.body),
  ].join("\n");
  const scope = `${day}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const kDate = hmac(`AWS4${input.secretAccessKey}`, day);
  const kRegion = hmac(kDate, input.region);
  const kService = hmac(kRegion, input.service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");
  headers.Authorization =
    `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return headers;
}
