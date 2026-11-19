// Service-owned: generated once by sdk-kit, then maintained in this repository.

import {
  type CommonConfig,
  type CommonConfigOptions,
  type CommonVendorEnv,
  ConfigError,
  type EnvMap,
  EnvReader,
  type Hooks,
  type ClientLogger,
  REDACTED,
  type RetryPolicy,
  Secret,
  type TlsOptions,
  describeCommonConfig,
  mergeOptions,
  readCommonEnv,
  resolveCommonConfig,
  secretValues,
  validateCommonConfig,
} from "./core/index.js";
import type { InfisicalAuth } from "./auth.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/** Port text from the stack catalog; the default URL uses its first number. */
const CATALOG_PORT = "8080";

/** Secrets API version: detected at run time (`auto`) or forced. */
export type ApiVersion = "auto" | "v4" | "v3";

/** Options accepted by {@link InfisicalConfig} (all optional). */
export interface InfisicalConfigOptions extends CommonConfigOptions {
  /**
   * Static access token (machine identity token, user JWT or legacy `st.` service token), sent as
   * `Authorization: Bearer <token>` (env `GROW_INFISICAL_TOKEN`, `INFISICAL_TOKEN`).
   */
  token?: string | Secret;
  /** Universal Auth client id (env `GROW_INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_ID`). */
  clientId?: string;
  /** Universal Auth client secret (env `GROW_INFISICAL_CLIENT_SECRET`, `INFISICAL_CLIENT_SECRET`). */
  clientSecret?: string | Secret;
  /** Organization slug sent with identity logins (optional, sub-organization logins). */
  organizationSlug?: string;
  /**
   * Explicit auth method ({@link UniversalAuth}, {@link TokenAuth}, {@link KubernetesAuth},
   * {@link AwsIamAuth}). Wins over `token` and `clientId`/`clientSecret`.
   */
  auth?: InfisicalAuth;
  /** Default project id (env `GROW_INFISICAL_PROJECT_ID`, `INFISICAL_PROJECT_ID`). */
  projectId?: string;
  /**
   * Default environment slug, e.g. `dev` (env `GROW_INFISICAL_ENVIRONMENT`,
   * `INFISICAL_ENVIRONMENT`). Required by secret operations (`ConfigError` at call time).
   */
  environment?: string;
  /** Default secret path (env `GROW_INFISICAL_SECRET_PATH`, default `/`). */
  secretPath?: string;
  /**
   * Secrets API version (env `GROW_INFISICAL_API_VERSION`; default `auto`: v4, falling back to v3
   * when v4 is missing; `""` means `auto`).
   */
  apiVersion?: ApiVersion | "";
  /** Expand `${…}` secret references on read (default `true`). */
  expandSecretReferences?: boolean;
  /** Include imported secrets on read (default `true`). */
  includeImports?: boolean;
  /**
   * Revoke an access token obtained by login when the client is closed (env
   * `GROW_INFISICAL_REVOKE_ON_CLOSE`, default `false`).
   */
  revokeOnClose?: boolean;
}

/** Vendor variables read after `GROW_INFISICAL_*`, in order (SPEC §2.2). */
export const VENDOR_ENV: CommonVendorEnv & {
  token: readonly string[];
  clientId: readonly string[];
  clientSecret: readonly string[];
  projectId: readonly string[];
  environment: readonly string[];
} = {
  url: ["INFISICAL_API_URL"],
  token: ["INFISICAL_TOKEN"],
  clientId: ["INFISICAL_CLIENT_ID", "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"],
  clientSecret: ["INFISICAL_CLIENT_SECRET", "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"],
  projectId: ["INFISICAL_PROJECT_ID"],
  environment: ["INFISICAL_ENVIRONMENT"],
};

const API_VERSIONS: ReadonlySet<string> = new Set(["auto", "v4", "v3"]);

/** Immutable configuration of {@link InfisicalClient}. */
export class InfisicalConfig implements CommonConfig {
  /** Default endpoint. */
  static readonly DEFAULT_URL = `http://127.0.0.1:${/\d+/.exec(CATALOG_PORT)?.[0] ?? "8080"}`;
  /** Prefix of every environment variable. */
  static readonly ENV_PREFIX = "GROW_INFISICAL_";

  readonly url: string;
  readonly connectTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly totalTimeoutMs: number;
  readonly retry: RetryPolicy;
  readonly tls: Readonly<TlsOptions>;
  readonly proxy?: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly userAgentSuffix?: string;
  readonly hooks?: Hooks;
  readonly logger?: ClientLogger;
  /** Static access token. */
  readonly token?: Secret;
  /** Universal Auth client id. */
  readonly clientId?: string;
  /** Universal Auth client secret. */
  readonly clientSecret?: Secret;
  /** Organization slug for identity logins. */
  readonly organizationSlug?: string;
  /** Explicit auth method. */
  readonly auth?: InfisicalAuth;
  /** Default project id. */
  readonly projectId?: string;
  /** Default environment slug. */
  readonly environment?: string;
  /** Default secret path (`/`). */
  readonly secretPath: string;
  /** Secrets API version (`auto`). */
  readonly apiVersion: ApiVersion;
  /** Expand secret references on read (`true`). */
  readonly expandSecretReferences: boolean;
  /** Include imported secrets on read (`true`). */
  readonly includeImports: boolean;
  /** Revoke a login token on close (`false`). */
  readonly revokeOnClose: boolean;

  /** Applies defaults, validates (throws {@link ConfigError}) and freezes. */
  constructor(options: InfisicalConfigOptions = {}) {
    const common = resolveCommonConfig(options, InfisicalConfig.DEFAULT_URL);
    this.url = common.url;
    this.connectTimeoutMs = common.connectTimeoutMs;
    this.requestTimeoutMs = common.requestTimeoutMs;
    this.totalTimeoutMs = common.totalTimeoutMs;
    this.retry = common.retry;
    this.tls = common.tls;
    this.headers = common.headers;
    if (common.proxy !== undefined) this.proxy = common.proxy;
    if (common.userAgentSuffix !== undefined) this.userAgentSuffix = common.userAgentSuffix;
    if (common.hooks !== undefined) this.hooks = common.hooks;
    if (common.logger !== undefined) this.logger = common.logger;
    const token = Secret.from(options.token);
    if (token !== undefined) this.token = token;
    if (options.clientId !== undefined && options.clientId !== "") this.clientId = options.clientId;
    const clientSecret = Secret.from(options.clientSecret);
    if (clientSecret !== undefined) this.clientSecret = clientSecret;
    if (options.organizationSlug !== undefined && options.organizationSlug !== "")
      this.organizationSlug = options.organizationSlug;
    if (options.auth !== undefined) this.auth = options.auth;
    if (options.projectId !== undefined && options.projectId !== "")
      this.projectId = options.projectId;
    if (options.environment !== undefined && options.environment !== "")
      this.environment = options.environment;
    this.secretPath = options.secretPath ?? "/";
    // "" is accepted as an alias of "auto" (the Go/Java spelling); case is ignored.
    const apiVersion = (options.apiVersion ?? "auto").trim().toLowerCase();
    this.apiVersion = (apiVersion === "" ? "auto" : apiVersion) as ApiVersion;
    this.expandSecretReferences = options.expandSecretReferences ?? true;
    this.includeImports = options.includeImports ?? true;
    this.revokeOnClose = options.revokeOnClose ?? false;
    this.validate();
    Object.freeze(this);
  }

  /** Returns `options` when it already is a config, otherwise builds one. */
  static from(options: InfisicalConfigOptions = {}): InfisicalConfig {
    if (options instanceof InfisicalConfig) return options;
    return new InfisicalConfig(options);
  }

  /**
   * Builds a config from the environment. Precedence: explicit `overrides` >
   * `GROW_INFISICAL_<NAME>` > vendor variables ({@link VENDOR_ENV}) > defaults. A URL taken from
   * `INFISICAL_API_URL` loses one trailing `/api` (the Infisical CLI form).
   */
  static fromEnv(overrides: InfisicalConfigOptions = {}, env: EnvMap = process.env) {
    const reader = new EnvReader(InfisicalConfig.ENV_PREFIX, env);
    const fromEnv: InfisicalConfigOptions = readCommonEnv(reader, VENDOR_ENV);
    const urlHit = reader.lookup("URL", VENDOR_ENV.url);
    if (urlHit !== undefined && urlHit.name !== `${InfisicalConfig.ENV_PREFIX}URL`) {
      fromEnv.url = urlHit.value.replace(/\/api\/?$/, "");
    }
    const token = reader.secret("TOKEN", VENDOR_ENV.token);
    if (token !== undefined) fromEnv.token = token;
    const clientId = reader.string("CLIENT_ID", VENDOR_ENV.clientId);
    if (clientId !== undefined) fromEnv.clientId = clientId;
    const clientSecret = reader.secret("CLIENT_SECRET", VENDOR_ENV.clientSecret);
    if (clientSecret !== undefined) fromEnv.clientSecret = clientSecret;
    const projectId = reader.string("PROJECT_ID", VENDOR_ENV.projectId);
    if (projectId !== undefined) fromEnv.projectId = projectId;
    const environment = reader.string("ENVIRONMENT", VENDOR_ENV.environment);
    if (environment !== undefined) fromEnv.environment = environment;
    const secretPath = reader.string("SECRET_PATH");
    if (secretPath !== undefined) fromEnv.secretPath = secretPath;
    const apiVersion = reader.string("API_VERSION");
    if (apiVersion !== undefined) fromEnv.apiVersion = apiVersion as ApiVersion;
    const revokeOnClose = reader.bool("REVOKE_ON_CLOSE");
    if (revokeOnClose !== undefined) fromEnv.revokeOnClose = revokeOnClose;
    const merged = mergeOptions<InfisicalConfigOptions>(fromEnv, overrides);
    return new InfisicalConfig(merged);
  }

  /** Throws {@link ConfigError} when a setting is invalid. */
  validate(): void {
    validateCommonConfig(this);
    const problems: string[] = [];
    if (this.token?.reveal().trim() === "") problems.push("token must not be blank");
    if ((this.clientId === undefined) !== (this.clientSecret === undefined)) {
      problems.push("clientId and clientSecret must be given together");
    }
    if (!this.secretPath.startsWith("/")) problems.push("secretPath must start with /");
    if (!API_VERSIONS.has(this.apiVersion)) problems.push("apiVersion must be auto, v4 or v3");
    if (problems.length > 0) {
      throw new ConfigError(`invalid configuration: ${problems.join("; ")}`);
    }
  }

  /** Credential values to redact from error messages and logs. */
  knownSecrets(): string[] {
    return secretValues(this.token, this.clientSecret);
  }

  /** Debug form with every credential redacted. */
  toJSON(): Record<string, unknown> {
    return {
      ...describeCommonConfig(this),
      token: this.token === undefined ? null : REDACTED,
      clientId: this.clientId ?? null,
      clientSecret: this.clientSecret === undefined ? null : REDACTED,
      organizationSlug: this.organizationSlug ?? null,
      auth: this.auth?.kind ?? null,
      projectId: this.projectId ?? null,
      environment: this.environment ?? null,
      secretPath: this.secretPath,
      apiVersion: this.apiVersion,
      expandSecretReferences: this.expandSecretReferences,
      includeImports: this.includeImports,
      revokeOnClose: this.revokeOnClose,
    };
  }

  toString(): string {
    return `InfisicalConfig(${JSON.stringify(this.toJSON())})`;
  }

  [INSPECT](): string {
    return this.toString();
  }
}
