// Service-owned: generated once by sdk-kit, then maintained in this repository.

import type { Dispatcher } from "undici";
import {
  type HealthStatus,
  HttpTransport,
  type TransportOptions,
  UnsupportedError,
  createDispatcher,
  healthStatus,
  probeHealth,
} from "./core/index.js";
import { InfisicalConfig, type InfisicalConfigOptions } from "./config.js";
import { type InfisicalAuth, TokenAuth, UniversalAuth } from "./auth.js";
import { Api, type ResolvedApiVersion } from "./api.js";
import { SecretsApi } from "./api-secrets.js";
import { FoldersApi, ImportsApi, ProjectsApi, TagsApi } from "./api-resources.js";
import { InfisicalSecretsProvider, type InfisicalSecretsProviderOptions } from "./provider.js";
import { errorBodyInterceptor, send } from "./http.js";

/** Per-call options. */
export interface CallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Test seams (undici `MockAgent`, fake sleep, clock). Not part of the stable API. */
export type ClientInternals = Pick<TransportOptions, "dispatcher" | "sleep" | "now">;

/** Routes used by `ping()` per token kind. */
const PING_PATHS = {
  identity: "/api/v1/identities/details",
  user: "/api/v2/users/me",
  serviceToken: "/api/v2/service-token",
} as const;

/** Client for Infisical. Service modules: `secrets`, `folders`, `projects`, `tags`, `imports`. */
export class InfisicalClient {
  /** The immutable configuration. */
  readonly config: InfisicalConfig;
  /** Secrets: list/get/create/update/delete, batch, versions, `loadEnv`, `exportDotenv`. */
  readonly secrets: SecretsApi;
  /** Folders: list/create/update/delete. */
  readonly folders: FoldersApi;
  /** Projects and environments. */
  readonly projects: ProjectsApi;
  /** Tags. */
  readonly tags: TagsApi;
  /** Secret imports. */
  readonly imports: ImportsApi;
  /** The SPEC §3 `SecretsProvider` for the configured project/environment/path. */
  readonly provider: InfisicalSecretsProvider;
  readonly #transport: HttpTransport;
  readonly #api: Api;
  readonly #dispatcher: Dispatcher | undefined;
  readonly #providers = new Set<InfisicalSecretsProvider>();
  #closed = false;

  /** Accepts a {@link InfisicalConfig} or plain options. */
  constructor(config: InfisicalConfigOptions = {}, internals: ClientInternals = {}) {
    const cfg = InfisicalConfig.from(config);
    this.config = cfg;
    const auth = resolveAuth(cfg);
    const base = internals.dispatcher ?? createDispatcher(cfg);
    this.#dispatcher = internals.dispatcher === undefined ? base : undefined;
    this.#transport = new HttpTransport({
      ...internals,
      dispatcher: base.compose(errorBodyInterceptor()),
      config: cfg,
      knownSecrets: () => [...cfg.knownSecrets(), ...(auth?.knownSecrets() ?? [])],
    });
    auth?.bind({
      transport: this.#transport,
      organizationSlug: cfg.organizationSlug,
      now: internals.now ?? Date.now,
    });
    this.#api = new Api(cfg, this.#transport, auth);
    this.secrets = new SecretsApi(this.#api);
    this.folders = new FoldersApi(this.#api);
    this.projects = new ProjectsApi(this.#api);
    this.tags = new TagsApi(this.#api);
    this.imports = new ImportsApi(this.#api);
    this.provider = this.secretsProvider();
  }

  /** Builds a client from `GROW_INFISICAL_*` (and `INFISICAL_*`) environment variables. */
  static fromEnv(overrides: InfisicalConfigOptions = {}): InfisicalClient {
    return new InfisicalClient(InfisicalConfig.fromEnv(overrides));
  }

  /** The shared HTTP transport (for service modules). @internal */
  get transport(): HttpTransport {
    return this.#transport;
  }

  /** The active auth method (`undefined` when no credentials are configured). */
  get auth(): InfisicalAuth | undefined {
    return this.#api.auth;
  }

  /**
   * A `SecretsProvider` for another project, environment or base path. It is stopped by
   * {@link close} like {@link provider}.
   */
  secretsProvider(options: InfisicalSecretsProviderOptions = {}): InfisicalSecretsProvider {
    const p = new InfisicalSecretsProvider(
      this.#api,
      { secrets: this.secrets, folders: this.folders, tags: this.tags },
      options,
    );
    this.#providers.add(p);
    return p;
  }

  /** The secrets API version in use: `v4`, `v3` or `unknown` before the first secrets call. */
  apiVersion(_resource: "secrets" = "secrets"): ResolvedApiVersion {
    return this.#api.secretsVersion();
  }

  /**
   * Unauthenticated liveness: `GET /api/status`. Never throws for an unhealthy or unreachable
   * service (only `CANCELLED` and `CONFIG`).
   */
  health(options: CallOptions = {}): Promise<HealthStatus> {
    return probeHealth(async () => {
      const data = await send<Record<string, unknown> | undefined>(this.#transport, {
        method: "GET",
        path: "/api/status",
        operation: "health",
        signal: options.signal,
      });
      const { message, ...details } = data ?? {};
      const word = typeof message === "string" ? message.toLowerCase() : "ok";
      return healthStatus(word, details);
    });
  }

  /**
   * Authenticated round trip; returns the latency in milliseconds. The route depends on the token
   * kind: identity `GET /api/v1/identities/details`, user `GET /api/v2/users/me`, service token
   * `GET /api/v2/service-token`. `AuthenticationError` on bad credentials.
   */
  async ping(options: CallOptions = {}): Promise<number> {
    const start = performance.now();
    const kind = this.#api.auth?.tokenKind ?? "identity";
    await this.#api.call({
      method: "GET",
      path: PING_PATHS[kind],
      operation: "ping",
      signal: options.signal,
    });
    return performance.now() - start;
  }

  /** Always `UnsupportedError`: Infisical exposes no running version over HTTP. */
  serverVersion(_options: CallOptions = {}): Promise<string> {
    return Promise.reject(
      new UnsupportedError("serverVersion: Infisical does not report its version"),
    );
  }

  /**
   * Stops watchers, revokes a login token when `revokeOnClose` is set and releases connections.
   * Idempotent.
   */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    for (const p of this.#providers) await p.close();
    await this.#api.auth?.close(this.config.revokeOnClose);
    await this.#transport.close();
    await this.#dispatcher?.close().catch(() => undefined);
  }
}

function resolveAuth(cfg: InfisicalConfig): InfisicalAuth | undefined {
  if (cfg.auth !== undefined) return cfg.auth;
  if (cfg.token !== undefined) return new TokenAuth(cfg.token);
  if (cfg.clientId !== undefined && cfg.clientSecret !== undefined) {
    return new UniversalAuth(cfg.clientId, cfg.clientSecret);
  }
  return undefined;
}
