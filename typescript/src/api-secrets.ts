// Service-owned. Infisical secrets API (API.md §3): v4 `/api/v4/secrets` with the v3
// `/api/v3/secrets/raw` fallback, batch calls, versions, env injection and dotenv export.

import { ValidationError } from "./core/index.js";
import type { Api, ScopeOptions } from "./api.js";
import type { ApiCall } from "./http.js";
import { arr, compact, obj, positiveInt, requireText, seg, unexpected } from "./http.js";
import {
  type InfisicalSecret,
  type SecretList,
  type SecretMetadataEntry,
  type SecretType,
  type SecretVersion,
  parseSecret,
  parseSecretList,
  parseSecretVersion,
} from "./models.js";

/** Scope of a secret call: project, environment and folder path. */
export interface SecretScopeOptions extends ScopeOptions {
  /** Folder path (default `config.secretPath`, `/`). */
  secretPath?: string;
}

/** Options of {@link SecretsApi.listSecrets}. */
export interface ListSecretsOptions extends SecretScopeOptions {
  /** Include secrets of sub-folders (default `false`). */
  recursive?: boolean;
  /** Expand `${…}` references (default `config.expandSecretReferences`, `true`). */
  expandReferences?: boolean;
  /** Include imported secrets (default `config.includeImports`, `true`). */
  includeImports?: boolean;
  /** Only secrets with all of these tag slugs. */
  tagSlugs?: readonly string[];
  /** Return values (default `true`; `false` returns metadata only, v4). */
  viewSecretValue?: boolean;
  /** Replace shared values by the caller's personal overrides (user tokens, v4). */
  includePersonalOverrides?: boolean;
}

/** Options of {@link SecretsApi.getSecret}. */
export interface GetSecretOptions extends SecretScopeOptions {
  /** Read this version instead of the current one. */
  version?: number;
  /** `shared` (default) or `personal` (user tokens only). */
  type?: SecretType;
  /** Expand `${…}` references (default `config.expandSecretReferences`). */
  expandReferences?: boolean;
  /** Find the key through imports too (default `config.includeImports`). */
  includeImports?: boolean;
  /** Return the value (default `true`; `false` = metadata only, v4). */
  viewSecretValue?: boolean;
}

/** Options of {@link SecretsApi.createSecret}. */
export interface CreateSecretOptions extends SecretScopeOptions {
  comment?: string;
  /** Tag ids (see `client.tags.listTags`). */
  tagIds?: readonly string[];
  type?: SecretType;
  skipMultilineEncoding?: boolean;
  metadata?: readonly SecretMetadataEntry[];
}

/** Options of {@link SecretsApi.updateSecret}: only the given fields change. */
export interface UpdateSecretOptions extends SecretScopeOptions {
  /** New value. */
  value?: string;
  /** Renames the secret. */
  newName?: string;
  comment?: string;
  /** Replaces the tag set (tag ids). */
  tagIds?: readonly string[];
  type?: SecretType;
  skipMultilineEncoding?: boolean;
  metadata?: readonly SecretMetadataEntry[];
}

/** Options of {@link SecretsApi.deleteSecret}. */
export interface DeleteSecretOptions extends SecretScopeOptions {
  type?: SecretType;
}

/** One secret of {@link SecretsApi.createSecrets}. */
export interface BatchCreateSecret {
  key: string;
  value: string;
  comment?: string;
  tagIds?: readonly string[];
  skipMultilineEncoding?: boolean;
  metadata?: readonly SecretMetadataEntry[];
}

/** One secret of {@link SecretsApi.updateSecrets}. */
export interface BatchUpdateSecret {
  key: string;
  value?: string;
  newName?: string;
  comment?: string;
  tagIds?: readonly string[];
  /** Folder of this secret (default: the call's `secretPath`). */
  secretPath?: string;
  skipMultilineEncoding?: boolean;
  metadata?: readonly SecretMetadataEntry[];
}

/** Options of {@link SecretsApi.updateSecrets}. */
export interface UpdateSecretsOptions extends SecretScopeOptions {
  /** `failOnNotFound` (default), `upsert` (create missing) or `ignore` (skip missing). */
  mode?: "failOnNotFound" | "upsert" | "ignore";
}

/** One secret of {@link SecretsApi.deleteSecrets}: a key or `{ key, type }`. */
export type BatchDeleteSecret = string | { key: string; type?: SecretType };

/** Options of {@link SecretsApi.listSecretVersions}. */
export interface ListSecretVersionsOptions {
  /** Skip this many versions (default 0). */
  offset?: number;
  /** Page size, 1–1000 (default 20). */
  limit?: number;
  signal?: AbortSignal;
}

/** Options of {@link SecretsApi.loadEnv} and {@link SecretsApi.exportDotenv}. */
export interface EnvExportOptions extends SecretScopeOptions {
  /** Include sub-folders (default `false`). */
  recursive?: boolean;
  /** Include imported secrets (default `config.includeImports`). */
  includeImports?: boolean;
  /** Expand references (default `config.expandSecretReferences`). */
  expandReferences?: boolean;
}

/** Options of {@link SecretsApi.loadEnv}. */
export interface LoadEnvironmentOptions extends EnvExportOptions {
  /** Replace variables that already exist (default `false`). */
  override?: boolean;
  /** Target environment (default `process.env`). */
  env?: Record<string, string | undefined>;
}

function bool(value: boolean): string {
  return value ? "true" : "false";
}

function wireMetadata(m: readonly SecretMetadataEntry[] | undefined): unknown {
  return m?.map((e) => ({ key: e.key, value: e.value }));
}

/**
 * Quotes a value for a dotenv file: `"…"` with `\`, `"` and newlines escaped.
 */
export function dotenvQuote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r?\n/g, "\\n")}"`;
}

/** Secrets of one project environment (`client.secrets`). */
export class SecretsApi {
  readonly #api: Api;

  /** @internal */
  constructor(api: Api) {
    this.#api = api;
  }

  #scope(op: string, options: SecretScopeOptions) {
    return {
      projectId: this.#api.projectId(options, op),
      environment: this.#api.environment(options, op),
      secretPath: this.#api.path(options.secretPath),
    };
  }

  #projectKey(version: "v4" | "v3"): "projectId" | "workspaceId" {
    return version === "v4" ? "projectId" : "workspaceId";
  }

  #single(version: "v4" | "v3", name: string): string {
    return version === "v4" ? `/api/v4/secrets/${seg(name)}` : `/api/v3/secrets/raw/${seg(name)}`;
  }

  #batch(version: "v4" | "v3"): string {
    return version === "v4" ? "/api/v4/secrets/batch" : "/api/v3/secrets/batch/raw";
  }

  /**
   * Lists the secrets of a folder (`GET /api/v4/secrets`). References are expanded and imports
   * included by default; on v3 every flag is sent explicitly.
   */
  async listSecrets(options: ListSecretsOptions = {}): Promise<SecretList> {
    const op = "secrets.list";
    const scope = this.#scope(op, options);
    const cfg = this.#api.config;
    const expand = options.expandReferences ?? cfg.expandSecretReferences;
    const imports = options.includeImports ?? cfg.includeImports;
    const data = await this.#api.secrets<unknown>((v) => ({
      method: "GET",
      path: v === "v4" ? "/api/v4/secrets" : "/api/v3/secrets/raw",
      operation: `${op} ${scope.secretPath}`,
      query: {
        [this.#projectKey(v)]: scope.projectId,
        environment: scope.environment,
        secretPath: scope.secretPath,
        recursive: bool(options.recursive ?? false),
        expandSecretReferences: bool(expand),
        [v === "v4" ? "includeImports" : "include_imports"]: bool(imports),
        tagSlugs:
          options.tagSlugs === undefined || options.tagSlugs.length === 0
            ? undefined
            : options.tagSlugs.join(","),
        viewSecretValue:
          options.viewSecretValue === undefined ? undefined : bool(options.viewSecretValue),
        includePersonalOverrides:
          options.includePersonalOverrides === undefined
            ? undefined
            : bool(options.includePersonalOverrides),
      },
      signal: options.signal,
    }));
    return parseSecretList(data);
  }

  /** Reads one secret (`GET /api/v4/secrets/{name}`); `NotFoundError` when missing. */
  async getSecret(name: string, options: GetSecretOptions = {}): Promise<InfisicalSecret> {
    const op = `secrets.get ${name}`;
    requireText(name, "name", op);
    const scope = this.#scope(op, options);
    const cfg = this.#api.config;
    if (options.version !== undefined) positiveInt(options.version, "version", op);
    const expand = options.expandReferences ?? cfg.expandSecretReferences;
    const imports = options.includeImports ?? cfg.includeImports;
    const data = await this.#api.secrets<unknown>((v) => ({
      method: "GET",
      path: this.#single(v, name),
      operation: op,
      query: {
        [this.#projectKey(v)]: scope.projectId,
        environment: scope.environment,
        secretPath: scope.secretPath,
        version: options.version,
        type: options.type ?? "shared",
        expandSecretReferences: bool(expand),
        [v === "v4" ? "includeImports" : "include_imports"]: bool(imports),
        viewSecretValue:
          options.viewSecretValue === undefined ? undefined : bool(options.viewSecretValue),
      },
      signal: options.signal,
    }));
    return this.#secretOf(data, op);
  }

  #secretOf(data: unknown, op: string): InfisicalSecret {
    const secret = obj(data).secret;
    if (secret === undefined || secret === null) throw unexpected(op, "no secret");
    return parseSecret(secret);
  }

  #secretsOf(data: unknown): InfisicalSecret[] {
    return arr(obj(data).secrets).map(parseSecret);
  }

  /**
   * Creates a secret (`POST /api/v4/secrets/{name}`). Folders are not created automatically
   * (`NotFoundError`); an existing key raises `ConflictError`. The server trims the value.
   */
  async createSecret(
    name: string,
    value: string,
    options: CreateSecretOptions = {},
  ): Promise<InfisicalSecret> {
    const op = `secrets.create ${name}`;
    requireText(name, "name", op);
    if (typeof value !== "string") throw new ValidationError(`${op}: value must be a string`);
    const scope = this.#scope(op, options);
    const data = await this.#api.secrets<unknown>((v) => ({
      method: "POST",
      path: this.#single(v, name),
      operation: op,
      json: compact({
        [this.#projectKey(v)]: scope.projectId,
        environment: scope.environment,
        secretPath: scope.secretPath,
        secretValue: value,
        secretComment: options.comment,
        tagIds: options.tagIds,
        type: options.type,
        skipMultilineEncoding: options.skipMultilineEncoding,
        secretMetadata: wireMetadata(options.metadata),
      }),
      signal: options.signal,
    }));
    return this.#secretOf(data, op);
  }

  /**
   * Updates a secret (`PATCH /api/v4/secrets/{name}`): value, rename, comment, tags (replaces
   * the set). Every update bumps the version. When no value is sent the response value is empty.
   */
  async updateSecret(name: string, options: UpdateSecretOptions = {}): Promise<InfisicalSecret> {
    const op = `secrets.update ${name}`;
    requireText(name, "name", op);
    if (options.newName !== undefined) requireText(options.newName, "newName", op);
    const scope = this.#scope(op, options);
    const data = await this.#api.secrets<unknown>((v) => ({
      method: "PATCH",
      path: this.#single(v, name),
      operation: op,
      json: compact({
        [this.#projectKey(v)]: scope.projectId,
        environment: scope.environment,
        secretPath: scope.secretPath,
        secretValue: options.value,
        newSecretName: options.newName,
        secretComment: options.comment,
        tagIds: options.tagIds,
        type: options.type,
        skipMultilineEncoding: options.skipMultilineEncoding,
        secretMetadata: wireMetadata(options.metadata),
      }),
      signal: options.signal,
    }));
    return this.#secretOf(data, op);
  }

  /** Deletes a secret (all versions, `DELETE /api/v4/secrets/{name}`); `NotFoundError` when missing. */
  async deleteSecret(name: string, options: DeleteSecretOptions = {}): Promise<InfisicalSecret> {
    const op = `secrets.delete ${name}`;
    requireText(name, "name", op);
    const scope = this.#scope(op, options);
    const data = await this.#api.secrets<unknown>((v) => ({
      method: "DELETE",
      path: this.#single(v, name),
      operation: op,
      json: compact({
        [this.#projectKey(v)]: scope.projectId,
        environment: scope.environment,
        secretPath: scope.secretPath,
        type: options.type,
      }),
      signal: options.signal,
    }));
    return this.#secretOf(data, op);
  }

  #batchCall(
    method: "POST" | "PATCH" | "DELETE",
    op: string,
    options: SecretScopeOptions,
    extra: Record<string, unknown>,
  ): Promise<unknown> {
    const scope = this.#scope(op, options);
    return this.#api.secrets<unknown>((v): ApiCall => ({
      method,
      path: this.#batch(v),
      operation: op,
      json: compact({
        [this.#projectKey(v)]: scope.projectId,
        environment: scope.environment,
        secretPath: scope.secretPath,
        ...extra,
      }),
      signal: options.signal,
    }));
  }

  /** Creates several secrets atomically (`POST /api/v4/secrets/batch`); order not guaranteed. */
  async createSecrets(
    secrets: readonly BatchCreateSecret[],
    options: SecretScopeOptions = {},
  ): Promise<InfisicalSecret[]> {
    const op = "secrets.createMany";
    if (secrets.length === 0) return [];
    const items = secrets.map((s) =>
      compact({
        secretKey: requireText(s.key, "key", op),
        secretValue: s.value,
        secretComment: s.comment,
        tagIds: s.tagIds,
        skipMultilineEncoding: s.skipMultilineEncoding,
        secretMetadata: wireMetadata(s.metadata),
      }),
    );
    return this.#secretsOf(await this.#batchCall("POST", op, options, { secrets: items }));
  }

  /** Updates several secrets (`PATCH /api/v4/secrets/batch`, mode `failOnNotFound` by default). */
  async updateSecrets(
    secrets: readonly BatchUpdateSecret[],
    options: UpdateSecretsOptions = {},
  ): Promise<InfisicalSecret[]> {
    const op = "secrets.updateMany";
    if (secrets.length === 0) return [];
    const items = secrets.map((s) =>
      compact({
        secretKey: requireText(s.key, "key", op),
        secretValue: s.value,
        newSecretName: s.newName,
        secretComment: s.comment,
        tagIds: s.tagIds,
        secretPath: s.secretPath === undefined ? undefined : this.#api.path(s.secretPath),
        skipMultilineEncoding: s.skipMultilineEncoding,
        secretMetadata: wireMetadata(s.metadata),
      }),
    );
    return this.#secretsOf(
      await this.#batchCall("PATCH", op, options, { mode: options.mode, secrets: items }),
    );
  }

  /** Deletes several secrets atomically (`DELETE /api/v4/secrets/batch`). */
  async deleteSecrets(
    secrets: readonly BatchDeleteSecret[],
    options: SecretScopeOptions = {},
  ): Promise<InfisicalSecret[]> {
    const op = "secrets.deleteMany";
    if (secrets.length === 0) return [];
    const items = secrets.map((s) =>
      typeof s === "string"
        ? { secretKey: requireText(s, "key", op) }
        : compact({ secretKey: requireText(s.key, "key", op), type: s.type }),
    );
    return this.#secretsOf(await this.#batchCall("DELETE", op, options, { secrets: items }));
  }

  /**
   * Lists the versions of a secret, newest first (`GET /api/v1/secret/{id}/secret-versions`).
   * The route accepts **user tokens only**; machine identities get `PermissionDeniedError`.
   */
  async listSecretVersions(
    secretId: string,
    options: ListSecretVersionsOptions = {},
  ): Promise<SecretVersion[]> {
    const op = `secrets.versions ${secretId}`;
    requireText(secretId, "secretId", op);
    const offset = options.offset ?? 0;
    const limit = options.limit ?? 20;
    if (!Number.isInteger(offset) || offset < 0) {
      throw new ValidationError(`${op}: offset must be a non-negative integer`);
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
      throw new ValidationError(`${op}: limit must be an integer between 1 and 1000`);
    }
    const data = await this.#api.call<unknown>({
      method: "GET",
      path: `/api/v1/secret/${seg(secretId)}/secret-versions`,
      operation: op,
      query: { offset, limit },
      signal: options.signal,
    });
    return arr(obj(data).secretVersions).map(parseSecretVersion);
  }

  /**
   * Resolves `key → value` for a folder: direct secrets first, then sub-folders (recursive) and
   * imports, which never override a key that is already set.
   */
  async #values(options: EnvExportOptions): Promise<Map<string, string>> {
    const list = await this.listSecrets({
      ...options,
      recursive: options.recursive ?? false,
    });
    const base = this.#api.path(options.secretPath);
    const values = new Map<string, string>();
    const direct = list.secrets.filter((s) => s.secretPath === base);
    const nested = list.secrets.filter((s) => s.secretPath !== base);
    for (const s of [...direct, ...nested, ...list.imports.flatMap((i) => i.secrets)]) {
      if (s.key !== "" && !values.has(s.key)) values.set(s.key, s.value.reveal());
    }
    return values;
  }

  /**
   * Sets environment variables (default `process.env`) from the secrets of a folder; the key is
   * the variable name. Existing variables are kept unless `override`. Returns `{ name: key }` for
   * the variables that were set (never values).
   */
  async loadEnv(options: LoadEnvironmentOptions = {}): Promise<Record<string, string>> {
    const values = await this.#values(options);
    const env = options.env ?? process.env;
    const set: Record<string, string> = {};
    for (const [key, value] of values) {
      if (options.override !== true && env[key] !== undefined) continue;
      env[key] = value;
      set[key] = key;
    }
    return set;
  }

  /** Renders the secrets of a folder as a dotenv file (`KEY="value"` lines sorted by key). */
  async exportDotenv(options: EnvExportOptions = {}): Promise<string> {
    const values = await this.#values(options);
    const keys = [...values.keys()].sort();
    return keys.map((k) => `${k}=${dotenvQuote(values.get(k) as string)}\n`).join("");
  }
}
