// Service-owned. Typed Infisical models and wire (JSON) parsers.

import { SecretValue } from "./secrets/index.js";
import { arr, num, obj, optString, parseDate, str } from "./http.js";

/** Secret type: shared (default) or the caller's personal override (user tokens only). */
export type SecretType = "shared" | "personal";

/** A tag attached to a secret or defined in a project. */
export interface Tag {
  id: string;
  slug: string;
  /** Display name (secrets only; usually the slug). */
  name?: string;
  color?: string;
  projectId?: string;
  createdAt?: Date;
  updatedAt?: Date;
}

/** One secret as returned by the secrets API. */
export interface InfisicalSecret {
  id: string;
  /** Secret key (name). */
  key: string;
  /** Value (redacting wrapper); empty when hidden or when an update did not send a value. */
  value: SecretValue;
  /** True when the server hid the value (`viewSecretValue=false` or missing permission). */
  valueHidden: boolean;
  version: number;
  type: SecretType;
  environment: string;
  secretPath: string;
  comment: string;
  tags: Tag[];
  /** Secret metadata (key → value). */
  metadata: Record<string, string>;
  skipMultilineEncoding: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}

/** Secrets reached through one secret import. */
export interface ImportedSecrets {
  environment: string;
  secretPath: string;
  folderId?: string;
  secrets: InfisicalSecret[];
}

/** Result of `listSecrets`. */
export interface SecretList {
  secrets: InfisicalSecret[];
  /** Imported secrets, in import priority order (empty unless imports were included). */
  imports: ImportedSecrets[];
}

/** One historical version of a secret. */
export interface SecretVersion {
  /** Version row id. */
  id: string;
  version: number;
  key: string;
  value: SecretValue;
  valueHidden: boolean;
  comment: string;
  type: SecretType;
  environment: string;
  createdAt?: Date;
  actor?: { actorId?: string; actorType?: string; name?: string };
}

/** A folder. */
export interface Folder {
  id: string;
  name: string;
  version: number;
  description?: string;
  parentId?: string;
  envId?: string;
  /** Full path of the folder (create/update responses). */
  path?: string;
  /** Path relative to the listed path (recursive lists). */
  relativePath?: string;
  createdAt?: Date;
  updatedAt?: Date;
}

/** An environment of a project. */
export interface Environment {
  id: string;
  name: string;
  slug: string;
  position?: number;
  projectId?: string;
}

/** A project. */
export interface Project {
  id: string;
  name: string;
  slug: string;
  type: string;
  orgId: string;
  description?: string;
  environments: Environment[];
  createdAt?: Date;
  updatedAt?: Date;
}

/** A page of projects. */
export interface ProjectList {
  projects: Project[];
  totalCount: number;
}

/** A secret import (secrets of another environment/path visible in this folder). */
export interface SecretImport {
  id: string;
  /** Source path. */
  importPath: string;
  /** Source environment. */
  importEnvironment: Environment;
  position: number;
  isReplication: boolean;
  sourceProjectName?: string;
  createdAt?: Date;
  updatedAt?: Date;
}

function withDates<T extends object>(out: T, raw: Record<string, unknown>): T {
  const createdAt = parseDate(raw.createdAt);
  const updatedAt = parseDate(raw.updatedAt);
  if (createdAt !== undefined) Object.assign(out, { createdAt });
  if (updatedAt !== undefined) Object.assign(out, { updatedAt });
  return out;
}

function setOpt(out: object, key: string, value: unknown): void {
  if (value !== undefined && value !== null) Object.assign(out, { [key]: value });
}

/** Parses a tag. */
export function parseTag(raw: unknown): Tag {
  const r = obj(raw);
  const tag: Tag = { id: str(r.id), slug: str(r.slug) };
  setOpt(tag, "name", optString(r.name));
  setOpt(tag, "color", optString(r.color));
  setOpt(tag, "projectId", optString(r.projectId));
  return withDates(tag, r);
}

function secretType(value: unknown): SecretType {
  return value === "personal" ? "personal" : "shared";
}

/** Parses a secret. */
export function parseSecret(raw: unknown): InfisicalSecret {
  const r = obj(raw);
  const version = num(r.version, 1);
  const s: InfisicalSecret = {
    id: str(r.id),
    key: str(r.secretKey),
    value: new SecretValue(str(r.secretValue), String(version)),
    valueHidden: r.secretValueHidden === true,
    version,
    type: secretType(r.type),
    environment: str(r.environment),
    secretPath: str(r.secretPath) === "" ? "/" : str(r.secretPath),
    comment: str(r.secretComment),
    tags: arr(r.tags).map(parseTag),
    metadata: Object.fromEntries(
      arr(r.secretMetadata).map((m) => {
        const e = obj(m);
        return [str(e.key), str(e.value)];
      }),
    ),
    skipMultilineEncoding: r.skipMultilineEncoding === true,
  };
  return withDates(s, r);
}

/** Parses a `{secrets, imports}` list response. */
export function parseSecretList(raw: unknown): SecretList {
  const r = obj(raw);
  return {
    secrets: arr(r.secrets).map(parseSecret),
    imports: arr(r.imports).map((i) => {
      const imp = obj(i);
      const out: ImportedSecrets = {
        environment: str(imp.environment),
        secretPath: str(imp.secretPath),
        secrets: arr(imp.secrets).map(parseSecret),
      };
      setOpt(out, "folderId", optString(imp.folderId));
      return out;
    }),
  };
}

/** Parses a secret version. */
export function parseSecretVersion(raw: unknown): SecretVersion {
  const r = obj(raw);
  const version = num(r.version, 1);
  const v: SecretVersion = {
    id: str(r.id),
    version,
    key: str(r.secretKey),
    value: new SecretValue(str(r.secretValue), String(version)),
    valueHidden: r.secretValueHidden === true,
    comment: str(r.secretComment),
    type: secretType(r.type),
    environment: str(r.environment),
  };
  const createdAt = parseDate(r.createdAt);
  if (createdAt !== undefined) v.createdAt = createdAt;
  if (r.actor !== null && typeof r.actor === "object") {
    const a = obj(r.actor);
    const actor: NonNullable<SecretVersion["actor"]> = {};
    setOpt(actor, "actorId", optString(a.actorId));
    setOpt(actor, "actorType", optString(a.actorType));
    setOpt(actor, "name", optString(a.name));
    v.actor = actor;
  }
  return v;
}

/** Parses a folder. */
export function parseFolder(raw: unknown): Folder {
  const r = obj(raw);
  const f: Folder = { id: str(r.id), name: str(r.name), version: num(r.version, 1) };
  setOpt(f, "description", optString(r.description));
  setOpt(f, "parentId", optString(r.parentId));
  setOpt(f, "envId", optString(r.envId));
  setOpt(f, "path", optString(r.path));
  setOpt(f, "relativePath", optString(r.relativePath));
  return withDates(f, r);
}

/** Parses an environment. */
export function parseEnvironment(raw: unknown): Environment {
  const r = obj(raw);
  const e: Environment = { id: str(r.id), name: str(r.name), slug: str(r.slug) };
  if (typeof r.position === "number") e.position = r.position;
  setOpt(e, "projectId", optString(r.projectId));
  return e;
}

/** Parses a project. */
export function parseProject(raw: unknown): Project {
  const r = obj(raw);
  const p: Project = {
    id: str(r.id),
    name: str(r.name),
    slug: str(r.slug),
    type: str(r.type),
    orgId: str(r.orgId),
    environments: arr(r.environments).map(parseEnvironment),
  };
  setOpt(p, "description", optString(r.description));
  return withDates(p, r);
}

/** Parses a secret import. */
export function parseSecretImport(raw: unknown): SecretImport {
  const r = obj(raw);
  const i: SecretImport = {
    id: str(r.id),
    importPath: str(r.importPath),
    importEnvironment: parseEnvironment(r.importEnv),
    position: num(r.position),
    isReplication: r.isReplication === true,
  };
  setOpt(i, "sourceProjectName", optString(r.sourceProjectName));
  return withDates(i, r);
}
