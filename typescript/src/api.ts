// Service-owned. Shared state of one client used by every module: authenticated calls (with one
// re-login on 401), the secrets API version detection (v4 → v3, DECISIONS.md #6) and the
// project/environment defaults.

import { AuthenticationError, type HttpTransport } from "./core/index.js";
import type { InfisicalAuth } from "./auth.js";
import type { InfisicalConfig } from "./config.js";
import { type ApiCall, isRouteMissing, normalizePath, required, send } from "./http.js";

/** Version of the secrets API in use: `v4`, `v3` or `unknown` before the first call. */
export type ResolvedApiVersion = "v4" | "v3" | "unknown";

/** Project / environment / path scope accepted by most calls (defaults come from the config). */
export interface ScopeOptions {
  /** Project id (default `config.projectId`). */
  projectId?: string;
  /** Environment slug (default `config.environment`). */
  environment?: string;
  /** Cancels the call. */
  signal?: AbortSignal;
}

/** Internal per-client API context. @internal */
export class Api {
  readonly config: InfisicalConfig;
  readonly transport: HttpTransport;
  readonly auth: InfisicalAuth | undefined;
  #secretsVersion: "v4" | "v3" | undefined;

  constructor(config: InfisicalConfig, transport: HttpTransport, auth: InfisicalAuth | undefined) {
    this.config = config;
    this.transport = transport;
    this.auth = auth;
    if (config.apiVersion !== "auto") this.#secretsVersion = config.apiVersion;
  }

  /** Sends an authenticated call; a 401 with a refreshable auth method re-logs in once. */
  async call<T>(c: ApiCall): Promise<T> {
    const auth = this.auth;
    if (auth === undefined) return send<T>(this.transport, c);
    const signal = c.signal === undefined ? {} : { signal: c.signal };
    const token = await auth.token(signal);
    try {
      return await send<T>(this.transport, { ...c, token: token.reveal() });
    } catch (err) {
      if (!(auth.refreshable && err instanceof AuthenticationError && err.httpStatus === 401)) {
        throw err;
      }
      auth.invalidate();
      const fresh = await auth.token(signal);
      return send<T>(this.transport, { ...c, token: fresh.reveal() });
    }
  }

  /**
   * Sends a secrets call on the detected API version. While the version is unknown (`auto`), a
   * route-missing 404 on v4 switches to v3 and repeats the call once (the server did not run
   * it); any other HTTP answer confirms v4.
   */
  async secrets<T>(build: (version: "v4" | "v3") => ApiCall): Promise<T> {
    const known = this.#secretsVersion;
    const version = known ?? "v4";
    try {
      const out = await this.call<T>(build(version));
      this.#secretsVersion ??= version;
      return out;
    } catch (err) {
      if (known === undefined) {
        if (isRouteMissing(err)) {
          this.#secretsVersion = "v3";
          return this.call<T>(build("v3"));
        }
        if ((err as { httpStatus?: unknown }).httpStatus !== undefined) {
          this.#secretsVersion = "v4";
        }
      }
      throw err;
    }
  }

  /** The secrets API version in use. */
  secretsVersion(): ResolvedApiVersion {
    return this.#secretsVersion ?? "unknown";
  }

  /** Project id from the options or the config (`ConfigError` when missing). */
  projectId(options: ScopeOptions, operation: string): string {
    return required(options.projectId ?? this.config.projectId, "projectId", operation);
  }

  /** Environment slug from the options or the config (`ConfigError` when missing). */
  environment(options: ScopeOptions, operation: string): string {
    return required(options.environment ?? this.config.environment, "environment", operation);
  }

  /** Normalised path from the options or the config default. */
  path(path: string | undefined): string {
    return normalizePath(path ?? this.config.secretPath);
  }
}
