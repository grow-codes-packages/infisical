/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument -- loosely typed JSON in test fakes */
// Test helpers for the Infisical service code: recorded fixtures, a fixture router and a small
// stateful fake of the Infisical v4 secrets / v2 folders / v1 tags API.

import { readFileSync } from "node:fs";
import { InfisicalClient, type InfisicalConfigOptions } from "../../src/index.js";
import {
  type MockHandler,
  type MockResponse,
  type MockServer,
  type RecordedRequest,
  startServer,
} from "../helpers/server.js";

export const PROJECT = "d4ac094e-aa12-4d7f-96ab-1ebb84162b30";

/** A recorded response from `test/fixtures/<name>.json`. */
export interface Fixture {
  request: { method: string; path: string; body?: unknown };
  status: number;
  headers?: Record<string, string>;
  body: unknown;
}

export function fixture(name: string): Fixture {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/${name}.json`, import.meta.url), "utf8"),
  ) as Fixture;
}

/** The fixture as a mock response. */
export function reply(name: string, patch: (body: any) => unknown = (b) => b): MockResponse {
  const f = fixture(name);
  return {
    status: f.status,
    ...(f.headers === undefined ? {} : { headers: f.headers }),
    body: patch(structuredClone(f.body)) as object,
  };
}

/** A JWT-shaped token (unsigned) with the given payload. */
export function jwt(payload: Record<string, unknown>): string {
  const b = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b({ alg: "HS256" })}.${b(payload)}.sig`;
}

/** Route table: `"METHOD /path"` (path without query) → response or handler. */
export type Routes = Record<string, MockResponse | MockHandler>;

export function pathOf(req: RecordedRequest): string {
  return req.url.split("?")[0] ?? "";
}

export function queryOf(req: RecordedRequest): URLSearchParams {
  return new URL(req.url, "http://x").searchParams;
}

export function bodyOf(req: RecordedRequest): any {
  return req.body === "" ? undefined : JSON.parse(req.body);
}

const servers: MockServer[] = [];
const clients: InfisicalClient[] = [];

/** Closes every server and client started by the helpers. */
export async function cleanup(): Promise<void> {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await Promise.all(servers.splice(0).map((s) => s.close()));
}

/** Starts a server answering from the route table (404 route-missing for unknown routes). */
export async function routed(routes: Routes): Promise<MockServer> {
  const s = await startServer((req, i) => {
    const r = routes[`${req.method} ${pathOf(req)}`];
    if (r === undefined) {
      return {
        status: 404,
        body: {
          reqId: "req-missing",
          statusCode: 404,
          message: `Route ${req.method}:${req.url} not found`,
          error: "Not Found",
        },
      };
    }
    return typeof r === "function" ? r(req, i) : r;
  });
  servers.push(s);
  return s;
}

/** A client for a server with fast retries and a static identity token. */
export function clientFor(s: MockServer, options: InfisicalConfigOptions = {}): InfisicalClient {
  const c = new InfisicalClient({
    url: s.url,
    token: "identity-token-value",
    projectId: PROJECT,
    environment: "dev",
    retry: { maxRetries: 1, initialBackoffMs: 1 },
    ...options,
  });
  clients.push(c);
  return c;
}

/** Registers a client for cleanup. */
export function track(c: InfisicalClient): InfisicalClient {
  clients.push(c);
  return c;
}

interface FakeSecret {
  id: string;
  key: string;
  value: string;
  comment: string;
  version: number;
  path: string;
  tagIds: string[];
  createdAt: string;
  updatedAt: string;
}

function err(status: number, error: string, message: string): MockResponse {
  return { status, body: { reqId: `req-${status}`, statusCode: status, message, error } };
}

/**
 * A stateful fake of the Infisical v4 secrets, v2 folders and v1 tags API (one project, one
 * environment), enough to run the conformance scenarios in unit tests.
 */
export async function fakeInfisical(): Promise<{
  server: MockServer;
  secrets: Map<string, FakeSecret>;
  folders: Set<string>;
}> {
  const secrets = new Map<string, FakeSecret>();
  const folders = new Set<string>(["/"]);
  const tags = new Map<string, { id: string; slug: string; color: string }>();
  let n = 0;
  const id = () => `id-${++n}`;
  const wire = (s: FakeSecret, hide = false) => ({
    id: s.id,
    environment: "dev",
    version: s.version,
    type: "shared",
    secretKey: s.key,
    secretValue: hide ? "<hidden-by-infisical>" : s.value,
    secretValueHidden: hide,
    secretComment: s.comment,
    secretPath: s.path,
    tags: s.tagIds.map((t) => {
      const tag = [...tags.values()].find((x) => x.id === t);
      return { id: t, slug: tag?.slug, name: tag?.slug, color: tag?.color };
    }),
    secretMetadata: [],
    createdAt: s.createdAt,
    updatedAt: s.updatedAt,
  });
  const norm = (p: string | null | undefined) =>
    "/" +
    (p ?? "/")
      .split("/")
      .filter((x) => x !== "")
      .join("/");
  const server = await startServer((req) => {
    const path = pathOf(req);
    const q = queryOf(req);
    const body = bodyOf(req) ?? {};
    if (req.method === "GET" && path === "/api/v4/secrets") {
      const sp = norm(q.get("secretPath"));
      if (!folders.has(sp))
        return err(404, "SecretPathNotFound", `Folder with path '${sp}' not found`);
      const hide = q.get("viewSecretValue") === "false";
      const list = [...secrets.values()].filter((s) => s.path === sp).map((s) => wire(s, hide));
      return { body: { secrets: list, imports: [] } };
    }
    const single = /^\/api\/v4\/secrets\/([^/]+)$/.exec(path);
    if (single !== null) {
      const key = decodeURIComponent(single[1] ?? "");
      const sp = norm(req.method === "GET" ? q.get("secretPath") : body.secretPath);
      const k = `${sp}|${key}`;
      const cur = secrets.get(k);
      const now = new Date().toISOString();
      if (req.method === "GET") {
        if (cur === undefined) return err(404, "NotFound", `Secret with name '${key}' not found`);
        return { body: { secret: wire(cur, q.get("viewSecretValue") === "false") } };
      }
      if (req.method === "POST") {
        if (!folders.has(sp))
          return err(
            404,
            "CreateSecret",
            `Folder with path '${sp}' in environment with slug 'dev' not found`,
          );
        if (cur !== undefined)
          return err(
            400,
            "BadRequest",
            `Secret '${key}' already exists in path '${sp}' of environment 'dev'`,
          );
        const s: FakeSecret = {
          id: id(),
          key,
          value: String(body.secretValue).trim(),
          comment: body.secretComment ?? "",
          version: 1,
          path: sp,
          tagIds: body.tagIds ?? [],
          createdAt: now,
          updatedAt: now,
        };
        secrets.set(k, s);
        return { body: { secret: wire(s) } };
      }
      if (cur === undefined) return err(404, "NotFound", `Secret with name ${key} not found`);
      if (req.method === "PATCH") {
        if (body.secretValue !== undefined) cur.value = String(body.secretValue).trim();
        if (body.secretComment !== undefined) cur.comment = body.secretComment;
        if (body.tagIds !== undefined) cur.tagIds = body.tagIds;
        cur.version++;
        cur.updatedAt = now;
        return { body: { secret: wire(cur) } };
      }
      secrets.delete(k);
      return { body: { secret: wire(cur) } };
    }
    if (req.method === "POST" && path === "/api/v2/folders") {
      const full = norm(`${body.path}/${body.name}`);
      if (folders.has(full))
        return err(
          400,
          "BadRequest",
          `Folder with name '${body.name}' already exists in path '${body.path}'`,
        );
      folders.add(full);
      return { body: { folder: { id: id(), name: body.name, version: 1, path: full } } };
    }
    const tagsPath = `/api/v1/projects/${PROJECT}/tags`;
    if (path === tagsPath && req.method === "GET") return { body: { tags: [...tags.values()] } };
    if (path === tagsPath && req.method === "POST") {
      if (tags.has(body.slug)) return err(400, "BadRequest", "Tag already exists");
      const t = { id: id(), slug: body.slug, color: body.color };
      tags.set(body.slug, t);
      return { body: { tag: t } };
    }
    return err(404, "Not Found", `Route ${req.method}:${req.url} not found`);
  });
  servers.push(server);
  return { server, secrets, folders };
}
