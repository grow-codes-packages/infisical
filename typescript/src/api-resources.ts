// Service-owned. Infisical folders (v2), projects + environments (v1), tags (v1) and secret
// imports (v2) — API.md §5–§7.

import { ValidationError } from "./core/index.js";
import type { Api, ScopeOptions } from "./api.js";
import { arr, compact, normalizePath, num, obj, requireText, seg, unexpected } from "./http.js";
import {
  type Environment,
  type Folder,
  type Project,
  type ProjectList,
  type SecretImport,
  type Tag,
  parseEnvironment,
  parseFolder,
  parseProject,
  parseSecretImport,
  parseTag,
} from "./models.js";

/** Scope of a folder-level call: project, environment and parent path. */
export interface FolderScopeOptions extends ScopeOptions {
  /** Parent folder path (default `/`). */
  path?: string;
}

/** Options of {@link FoldersApi.listFolders}. */
export interface ListFoldersOptions extends FolderScopeOptions {
  /** Include nested folders (each with `relativePath`). */
  recursive?: boolean;
}

/** Options of {@link FoldersApi.createFolder}. */
export interface CreateFolderOptions extends FolderScopeOptions {
  description?: string;
}

/** Options of {@link FoldersApi.updateFolder}. */
export interface UpdateFolderOptions extends FolderScopeOptions {
  /** New name (required by the API). */
  name: string;
  description?: string;
}

/** Options of {@link FoldersApi.deleteFolder}. */
export interface DeleteFolderOptions extends FolderScopeOptions {
  /** Delete even when the folder is not empty / referenced. */
  forceDelete?: boolean;
}

const FOLDER_NAME = /^[A-Za-z0-9_-]+$/;

function folderName(name: string, op: string): string {
  requireText(name, "name", op);
  if (!FOLDER_NAME.test(name)) {
    throw new ValidationError(`${op}: folder names may contain only letters, digits, - and _`);
  }
  return name;
}

/** Folders of a project environment (`client.folders`). */
export class FoldersApi {
  readonly #api: Api;

  /** @internal */
  constructor(api: Api) {
    this.#api = api;
  }

  #scope(op: string, options: FolderScopeOptions) {
    return {
      projectId: this.#api.projectId(options, op),
      environment: this.#api.environment(options, op),
      path: normalizePath(options.path),
    };
  }

  #folder(data: unknown, op: string): Folder {
    const folder = obj(data).folder;
    if (folder === undefined || folder === null) throw unexpected(op, "no folder");
    return parseFolder(folder);
  }

  /** Lists the folders under `path` (`GET /api/v2/folders`). */
  async listFolders(options: ListFoldersOptions = {}): Promise<Folder[]> {
    const op = "folders.list";
    const s = this.#scope(op, options);
    const data = await this.#api.call<unknown>({
      method: "GET",
      path: "/api/v2/folders",
      operation: `${op} ${s.path}`,
      query: {
        projectId: s.projectId,
        environment: s.environment,
        path: s.path,
        recursive: options.recursive === true ? "true" : undefined,
      },
      signal: options.signal,
    });
    return arr(obj(data).folders).map(parseFolder);
  }

  /** Creates a folder under `path` (`POST /api/v2/folders`); `ConflictError` when it exists. */
  async createFolder(name: string, options: CreateFolderOptions = {}): Promise<Folder> {
    const op = `folders.create ${name}`;
    folderName(name, op);
    const s = this.#scope(op, options);
    const data = await this.#api.call<unknown>({
      method: "POST",
      path: "/api/v2/folders",
      operation: op,
      json: compact({ ...s, name, description: options.description }),
      signal: options.signal,
    });
    return this.#folder(data, op);
  }

  /** Renames a folder / changes its description (`PATCH /api/v2/folders/{id}`). */
  async updateFolder(folderId: string, options: UpdateFolderOptions): Promise<Folder> {
    const op = `folders.update ${folderId}`;
    requireText(folderId, "folderId", op);
    folderName(options.name, op);
    const s = this.#scope(op, options);
    const data = await this.#api.call<unknown>({
      method: "PATCH",
      path: `/api/v2/folders/${seg(folderId)}`,
      operation: op,
      json: compact({ ...s, name: options.name, description: options.description }),
      signal: options.signal,
    });
    return this.#folder(data, op);
  }

  /** Deletes a folder by id or name under `path` (`DELETE /api/v2/folders/{idOrName}`). */
  async deleteFolder(folderIdOrName: string, options: DeleteFolderOptions = {}): Promise<Folder> {
    const op = `folders.delete ${folderIdOrName}`;
    requireText(folderIdOrName, "folderIdOrName", op);
    const s = this.#scope(op, options);
    const data = await this.#api.call<unknown>({
      method: "DELETE",
      path: `/api/v2/folders/${seg(folderIdOrName)}`,
      operation: op,
      json: compact({ ...s, forceDelete: options.forceDelete }),
      signal: options.signal,
    });
    return this.#folder(data, op);
  }
}

/** Options of {@link ProjectsApi.listProjects}. */
export interface ListProjectsOptions {
  /** Project type (default `secret-manager`). */
  type?: string;
  /** Page size 1–100 (default 100). */
  limit?: number;
  /** Offset (default 0). */
  offset?: number;
  signal?: AbortSignal;
}

/** Options of project-scoped reads. */
export interface ProjectOptions {
  /** Project id (default `config.projectId`). */
  projectId?: string;
  signal?: AbortSignal;
}

/** Options of {@link ProjectsApi.createEnvironment}. */
export interface CreateEnvironmentOptions extends ProjectOptions {
  /** Position in the environment list. */
  position?: number;
}

/** Projects and environments (`client.projects`). */
export class ProjectsApi {
  readonly #api: Api;

  /** @internal */
  constructor(api: Api) {
    this.#api = api;
  }

  /** Lists the projects the caller is a member of (`GET /api/v1/projects`). */
  async listProjects(options: ListProjectsOptions = {}): Promise<ProjectList> {
    const limit = options.limit ?? 100;
    const offset = options.offset ?? 0;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new ValidationError("projects.list: limit must be an integer between 1 and 100");
    }
    if (!Number.isInteger(offset) || offset < 0) {
      throw new ValidationError("projects.list: offset must be a non-negative integer");
    }
    const data = await this.#api.call<unknown>({
      method: "GET",
      path: "/api/v1/projects",
      operation: "projects.list",
      query: { type: options.type ?? "secret-manager", limit, offset },
      signal: options.signal,
    });
    const d = obj(data);
    const projects = arr(d.projects).map(parseProject);
    return { projects, totalCount: num(d.totalCount, projects.length) };
  }

  /** Reads a project by id (`GET /api/v1/projects/{id}`, default `config.projectId`). */
  async getProject(options: ProjectOptions = {}): Promise<Project> {
    const op = "projects.get";
    const projectId = this.#api.projectId(options, op);
    const data = await this.#api.call<unknown>({
      method: "GET",
      path: `/api/v1/projects/${seg(projectId)}`,
      operation: `${op} ${projectId}`,
      signal: options.signal,
    });
    const project = obj(data).project;
    if (project === undefined || project === null) throw unexpected(op, "no project");
    return parseProject(project);
  }

  /** Reads a project by slug (`GET /api/v1/projects/slug/{slug}`). */
  async getProjectBySlug(slug: string, options: { signal?: AbortSignal } = {}): Promise<Project> {
    const op = `projects.getBySlug ${slug}`;
    requireText(slug, "slug", op);
    const data = await this.#api.call<unknown>({
      method: "GET",
      path: `/api/v1/projects/slug/${seg(slug)}`,
      operation: op,
      signal: options.signal,
    });
    return parseProject(data);
  }

  /** The environments of a project, in display order. */
  async listEnvironments(options: ProjectOptions = {}): Promise<Environment[]> {
    return (await this.getProject(options)).environments;
  }

  /** Creates an environment (project admin; `POST /api/v1/projects/{id}/environments`). */
  async createEnvironment(
    name: string,
    slug: string,
    options: CreateEnvironmentOptions = {},
  ): Promise<Environment> {
    const op = `projects.createEnvironment ${slug}`;
    requireText(name, "name", op);
    requireText(slug, "slug", op);
    const projectId = this.#api.projectId(options, op);
    const data = await this.#api.call<unknown>({
      method: "POST",
      path: `/api/v1/projects/${seg(projectId)}/environments`,
      operation: op,
      json: compact({ name, slug, position: options.position }),
      signal: options.signal,
    });
    const env = obj(data).environment;
    if (env === undefined || env === null) throw unexpected(op, "no environment");
    return parseEnvironment(env);
  }
}

/** Default color of tags created by the SDK. */
export const DEFAULT_TAG_COLOR = "#888888";

/** Tags of a project (`client.tags`). */
export class TagsApi {
  readonly #api: Api;

  /** @internal */
  constructor(api: Api) {
    this.#api = api;
  }

  /** Lists the tags of a project (`GET /api/v1/projects/{id}/tags`). */
  async listTags(options: ProjectOptions = {}): Promise<Tag[]> {
    const op = "tags.list";
    const projectId = this.#api.projectId(options, op);
    const data = await this.#api.call<unknown>({
      method: "GET",
      path: `/api/v1/projects/${seg(projectId)}/tags`,
      operation: op,
      signal: options.signal,
    });
    return arr(obj(data).tags).map(parseTag);
  }

  /** Creates a tag (`POST /api/v1/projects/{id}/tags`); `ConflictError` when the slug exists. */
  async createTag(slug: string, color: string, options: ProjectOptions = {}): Promise<Tag> {
    const op = `tags.create ${slug}`;
    requireText(slug, "slug", op);
    requireText(color, "color", op);
    const projectId = this.#api.projectId(options, op);
    const data = await this.#api.call<unknown>({
      method: "POST",
      path: `/api/v1/projects/${seg(projectId)}/tags`,
      operation: op,
      json: { slug, color },
      signal: options.signal,
    });
    const tag = obj(data).tag;
    if (tag === undefined || tag === null) throw unexpected(op, "no tag");
    return parseTag(tag);
  }

  /** Deletes a tag by id (`DELETE /api/v1/projects/{id}/tags/{tagId}`). */
  async deleteTag(tagId: string, options: ProjectOptions = {}): Promise<Tag> {
    const op = `tags.delete ${tagId}`;
    requireText(tagId, "tagId", op);
    const projectId = this.#api.projectId(options, op);
    const data = await this.#api.call<unknown>({
      method: "DELETE",
      path: `/api/v1/projects/${seg(projectId)}/tags/${seg(tagId)}`,
      operation: op,
      signal: options.signal,
    });
    const tag = obj(data).tag;
    if (tag === undefined || tag === null) throw unexpected(op, "no tag");
    return parseTag(tag);
  }
}

/** Options of {@link ImportsApi.createSecretImport}. */
export interface CreateSecretImportOptions extends FolderScopeOptions {
  /** Source environment slug. */
  importEnvironment: string;
  /** Source path (default `/`). */
  importPath?: string;
  /** Replicate the secrets instead of referencing them. */
  isReplication?: boolean;
  /** Source project (cross-project imports). */
  sourceProjectId?: string;
}

/** Secret imports of a folder (`client.imports`). */
export class ImportsApi {
  readonly #api: Api;

  /** @internal */
  constructor(api: Api) {
    this.#api = api;
  }

  #scope(op: string, options: FolderScopeOptions) {
    return {
      projectId: this.#api.projectId(options, op),
      environment: this.#api.environment(options, op),
      path: normalizePath(options.path),
    };
  }

  #import(data: unknown, op: string): SecretImport {
    const imp = obj(data).secretImport;
    if (imp === undefined || imp === null) throw unexpected(op, "no secretImport");
    return parseSecretImport(imp);
  }

  /** Lists the imports of a folder (`GET /api/v2/secret-imports`). */
  async listSecretImports(options: FolderScopeOptions = {}): Promise<SecretImport[]> {
    const op = "imports.list";
    const s = this.#scope(op, options);
    const data = await this.#api.call<unknown>({
      method: "GET",
      path: "/api/v2/secret-imports",
      operation: `${op} ${s.path}`,
      query: s,
      signal: options.signal,
    });
    return arr(obj(data).secretImports).map(parseSecretImport);
  }

  /**
   * Imports the secrets of another environment/path into a folder (`POST /api/v2/secret-imports`).
   * The server accepts duplicates and missing source paths.
   */
  async createSecretImport(options: CreateSecretImportOptions): Promise<SecretImport> {
    const op = "imports.create";
    requireText(options.importEnvironment, "importEnvironment", op);
    const s = this.#scope(op, options);
    const data = await this.#api.call<unknown>({
      method: "POST",
      path: "/api/v2/secret-imports",
      operation: op,
      json: compact({
        ...s,
        import: compact({
          environment: options.importEnvironment,
          path: normalizePath(options.importPath),
          sourceProjectId: options.sourceProjectId,
        }),
        isReplication: options.isReplication,
      }),
      signal: options.signal,
    });
    return this.#import(data, op);
  }

  /** Deletes an import by id (`DELETE /api/v2/secret-imports/{id}`). */
  async deleteSecretImport(
    importId: string,
    options: FolderScopeOptions = {},
  ): Promise<SecretImport> {
    const op = `imports.delete ${importId}`;
    requireText(importId, "importId", op);
    const s = this.#scope(op, options);
    const data = await this.#api.call<unknown>({
      method: "DELETE",
      path: `/api/v2/secret-imports/${seg(importId)}`,
      operation: op,
      json: s,
      signal: options.signal,
    });
    return this.#import(data, op);
  }
}
