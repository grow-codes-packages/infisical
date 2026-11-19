// Service-owned. SecretsProvider for Infisical (API.md "SecretsProvider mapping",
// DECISIONS.md #4): `a/b/KEY` → folder `/a/b` (below the provider's base path), key `KEY`.

import { ConflictError, NotFoundError, UnsupportedError, ValidationError } from "./core/index.js";
import {
  BaseSecretsProvider,
  type DeleteOptions,
  type GetOptions,
  type SecretMetadata,
  SecretValue,
  type SetOptions,
  type SignalOptions,
} from "./secrets/index.js";
import type { Api } from "./api.js";
import type { SecretsApi } from "./api-secrets.js";
import { DEFAULT_TAG_COLOR, type FoldersApi, type TagsApi } from "./api-resources.js";
import { joinPath, normalizePath } from "./http.js";
import type { InfisicalSecret } from "./models.js";

/** Options of {@link InfisicalSecretsProvider}. */
export interface InfisicalSecretsProviderOptions {
  /** Project id (default `config.projectId`). */
  projectId?: string;
  /** Environment slug (default `config.environment`). */
  environment?: string;
  /** Base path every name is relative to (default `config.secretPath`, `/`). */
  basePath?: string;
}

/** Where a provider name lives. */
export interface SecretLocation {
  secretPath: string;
  key: string;
}

const HEX_COLOR = /^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i;

/**
 * The SPEC §3 secrets interface on top of Infisical (`client.provider`). Names may contain `/`:
 * the last segment is the key, the rest is the folder below the base path. `set` creates missing
 * folders, resolves tag slugs (creating missing tags) and returns the new version.
 */
export class InfisicalSecretsProvider extends BaseSecretsProvider {
  readonly #secrets: SecretsApi;
  readonly #folders: FoldersApi;
  readonly #tags: TagsApi;
  readonly #scope: { projectId?: string; environment?: string };
  /** Base path of every name. */
  readonly basePath: string;

  /** @internal */
  constructor(
    api: Api,
    modules: { secrets: SecretsApi; folders: FoldersApi; tags: TagsApi },
    options: InfisicalSecretsProviderOptions = {},
  ) {
    super();
    this.#secrets = modules.secrets;
    this.#folders = modules.folders;
    this.#tags = modules.tags;
    this.#scope = {};
    if (options.projectId !== undefined) this.#scope.projectId = options.projectId;
    if (options.environment !== undefined) this.#scope.environment = options.environment;
    this.basePath = normalizePath(options.basePath ?? api.config.secretPath);
  }

  /** Splits a provider name into folder path and key. */
  locate(name: string, path?: string): SecretLocation {
    const base = path === undefined ? this.basePath : joinPath(this.basePath, path);
    const full = joinPath(base, name);
    const cut = full.lastIndexOf("/");
    const key = full.slice(cut + 1);
    if (key === "" || name.endsWith("/")) {
      throw new ValidationError(`secrets: invalid secret name "${name}"`);
    }
    return { secretPath: cut === 0 ? "/" : full.slice(0, cut), key };
  }

  /** Provider name of a secret at `secretPath`/`key` (relative to the base path). */
  nameOf(secretPath: string, key: string): string {
    const base = this.basePath === "/" ? "" : this.basePath;
    const rel = secretPath.startsWith(base) ? secretPath.slice(base.length) : secretPath;
    const dir = rel.replace(/^\/+/, "");
    return dir === "" ? key : `${dir}/${key}`;
  }

  #opts(loc: SecretLocation, signal: AbortSignal | undefined) {
    return {
      ...this.#scope,
      secretPath: loc.secretPath,
      ...(signal === undefined ? {} : { signal }),
    };
  }

  #version(version: string | undefined): number | undefined {
    if (version === undefined) return undefined;
    const n = Number(version);
    if (!Number.isInteger(n) || n < 1) {
      throw new ValidationError(`secrets: version "${version}" is not a positive integer`);
    }
    return n;
  }

  #metadata(name: string, s: InfisicalSecret): SecretMetadata {
    const tags: Record<string, string> = {};
    for (const t of s.tags) tags[t.slug] = t.slug;
    const meta: SecretMetadata = {
      name,
      path: s.secretPath,
      version: String(s.version),
      tags,
      versions: s.version,
      extra: { id: s.id, comment: s.comment, type: s.type },
    };
    if (s.createdAt !== undefined) meta.createdAt = s.createdAt;
    if (s.updatedAt !== undefined) meta.updatedAt = s.updatedAt;
    return meta;
  }

  protected async fetchSecret(name: string, options: GetOptions): Promise<SecretValue | null> {
    const loc = this.locate(name, options.path);
    try {
      const version = this.#version(options.version);
      const s = await this.#secrets.getSecret(loc.key, {
        ...this.#opts(loc, options.signal),
        ...(version === undefined ? {} : { version }),
      });
      return new SecretValue(s.value.reveal(), String(s.version));
    } catch (err) {
      if (err instanceof NotFoundError) return null;
      throw err;
    }
  }

  protected async fetchMetadata(name: string, options: GetOptions): Promise<SecretMetadata | null> {
    const loc = this.locate(name, options.path);
    try {
      const version = this.#version(options.version);
      const s = await this.#secrets.getSecret(loc.key, {
        ...this.#opts(loc, options.signal),
        viewSecretValue: false,
        ...(version === undefined ? {} : { version }),
      });
      return this.#metadata(this.nameOf(s.secretPath, s.key), s);
    } catch (err) {
      if (err instanceof NotFoundError) return null;
      throw err;
    }
  }

  #folderPath(prefixOrPath: string | undefined): string {
    return prefixOrPath === undefined ? this.basePath : joinPath(this.basePath, prefixOrPath);
  }

  /**
   * Lists the secrets directly under a folder. `prefixOrPath` is a folder below the base path
   * (`app/` or `app`); when no such folder exists it is a key prefix inside its parent folder
   * (`app/DB_` lists keys starting with `DB_` in `app`). A missing folder lists nothing.
   */
  protected async listSecrets(
    prefixOrPath: string | undefined,
    options: SignalOptions,
  ): Promise<SecretMetadata[]> {
    const raw = prefixOrPath ?? "";
    const rel = raw.replace(/^\/+|\/+$/g, "");
    try {
      return await this.#listFolder(rel, "", options.signal);
    } catch (err) {
      if (!(err instanceof NotFoundError)) throw err;
      if (rel === "" || raw.endsWith("/")) return [];
    }
    const cut = rel.lastIndexOf("/");
    try {
      return await this.#listFolder(
        cut < 0 ? "" : rel.slice(0, cut),
        rel.slice(cut + 1),
        options.signal,
      );
    } catch (err) {
      if (err instanceof NotFoundError) return [];
      throw err;
    }
  }

  async #listFolder(
    rel: string,
    keyPrefix: string,
    signal: AbortSignal | undefined,
  ): Promise<SecretMetadata[]> {
    const secretPath = this.#folderPath(rel === "" ? undefined : rel);
    const list = await this.#secrets.listSecrets({
      ...this.#opts({ secretPath, key: "" }, signal),
      recursive: false,
      includeImports: false,
      viewSecretValue: false,
    });
    return list.secrets
      .filter((s) => s.key.startsWith(keyPrefix) && s.type !== "personal")
      .map((s) => this.#metadata(this.nameOf(s.secretPath, s.key), s));
  }

  /** Every secret directly under `path` with one list call (imports per config). */
  override async getAll(
    path?: string,
    options: SignalOptions = {},
  ): Promise<Map<string, SecretValue>> {
    const secretPath = this.#folderPath(path);
    let list;
    try {
      list = await this.#secrets.listSecrets({
        ...this.#opts({ secretPath, key: "" }, options.signal),
        recursive: false,
      });
    } catch (err) {
      if (err instanceof NotFoundError) return new Map();
      throw err;
    }
    const entries: [string, SecretValue][] = [];
    const seen = new Set<string>();
    for (const s of [...list.secrets, ...list.imports.flatMap((i) => i.secrets)]) {
      if (seen.has(s.key)) continue;
      seen.add(s.key);
      entries.push([
        this.nameOf(secretPath, s.key),
        new SecretValue(s.value.reveal(), String(s.version)),
      ]);
    }
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return new Map(entries);
  }

  async #tagIds(tags: Record<string, string>, signal: AbortSignal | undefined): Promise<string[]> {
    const slugs = Object.keys(tags);
    if (slugs.length === 0) return [];
    const scope = { ...this.#scope, ...(signal === undefined ? {} : { signal }) };
    const existing = new Map((await this.#tags.listTags(scope)).map((t) => [t.slug, t.id]));
    const ids: string[] = [];
    for (const slug of slugs) {
      let id = existing.get(slug);
      if (id === undefined) {
        const wanted = tags[slug] ?? "";
        const color = HEX_COLOR.test(wanted) ? wanted : DEFAULT_TAG_COLOR;
        try {
          id = (await this.#tags.createTag(slug, color, scope)).id;
        } catch (err) {
          if (!(err instanceof ConflictError)) throw err;
          const again = (await this.#tags.listTags(scope)).find((t) => t.slug === slug);
          if (again === undefined) throw err;
          id = again.id;
        }
      }
      ids.push(id);
    }
    return ids;
  }

  async #ensureFolders(secretPath: string, signal: AbortSignal | undefined): Promise<void> {
    let parent = "/";
    for (const name of secretPath.split("/").filter((s) => s !== "")) {
      try {
        await this.#folders.createFolder(name, {
          ...this.#scope,
          path: parent,
          ...(signal === undefined ? {} : { signal }),
        });
      } catch (err) {
        if (!(err instanceof ConflictError)) throw err;
      }
      parent = joinPath(parent, name);
    }
  }

  protected async putSecret(name: string, value: Uint8Array, options: SetOptions): Promise<string> {
    if (options.cas !== undefined) {
      throw new UnsupportedError(`secrets.set ${name}: Infisical has no compare-and-set`);
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(value);
    } catch {
      throw new ValidationError(`secrets.set ${name}: Infisical stores UTF-8 text only`);
    }
    const loc = this.locate(name, options.path);
    const opts = this.#opts(loc, options.signal);
    const tagIds =
      options.tags === undefined ? undefined : await this.#tagIds(options.tags, options.signal);
    const extra = {
      ...(options.description === undefined ? {} : { comment: options.description }),
      ...(tagIds === undefined ? {} : { tagIds }),
    };
    const create = () => this.#secrets.createSecret(loc.key, text, { ...opts, ...extra });
    try {
      let created: InfisicalSecret;
      try {
        created = await create();
      } catch (err) {
        if (!(err instanceof NotFoundError) || !/folder/i.test(err.message)) throw err;
        await this.#ensureFolders(loc.secretPath, options.signal);
        created = await create();
      }
      return String(created.version);
    } catch (err) {
      if (!(err instanceof ConflictError)) throw err;
      const updated = await this.#secrets.updateSecret(loc.key, { ...opts, ...extra, value: text });
      return String(updated.version);
    }
  }

  protected async removeSecret(name: string, options: DeleteOptions): Promise<void> {
    if (
      (options.versions !== undefined && options.versions.length > 0) ||
      options.permanent === false
    ) {
      throw new UnsupportedError(
        `secrets.delete ${name}: Infisical always deletes every version permanently`,
      );
    }
    const loc = this.locate(name, options.path);
    await this.#secrets.deleteSecret(loc.key, this.#opts(loc, options.signal));
  }
}
