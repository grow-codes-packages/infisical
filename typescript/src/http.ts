// Service-owned. Internal Infisical HTTP layer on top of the shared core transport: an undici
// interceptor that normalises Infisical error bodies (request id from the body field `reqId`,
// error name, zod issue lists, rate-limit hints), the Infisical-specific error mapping
// (API.md §0, DECISIONS.md #1, #6) and small wire helpers.

import type { Dispatcher } from "undici";
import {
  ConfigError,
  ErrorCode,
  type HttpTransport,
  InfisicalError,
  type QueryValue,
  UnavailableError,
  UnsupportedError,
  ValidationError,
  errorForCode,
} from "./core/index.js";

/** Request header names that carry the Infisical request id (set by the interceptor). */
export const REQUEST_ID_HEADER = "x-request-id";

/** Largest error body the interceptor buffers (bigger bodies pass through untouched). */
const MAX_ERROR_BODY = 64 * 1024;

const TAG = /^\[([A-Za-z][A-Za-z0-9 _-]{0,60})\] /;
const TRY_AGAIN = /try again in (\d+(?:\.\d+)?) seconds?/i;

/**
 * Rewrites an Infisical error body (`{"reqId","statusCode","message","error","details"?}`) into
 * `{"message":"[<error>] <text>"}` and returns the request id. `text` joins zod issue lists
 * (`path: message; …`) and appends `details[]`. Non-JSON bodies return `undefined`.
 */
export function normaliseErrorBody(
  raw: string,
): { body: string; requestId?: string; retryAfterSeconds?: number } | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const obj = parsed as Record<string, unknown>;
  let text = messageText(obj.message);
  const details = Array.isArray(obj.details)
    ? obj.details.filter((d): d is string => typeof d === "string")
    : [];
  if (details.length > 0)
    text = text === "" ? details.join("; ") : `${text}: ${details.join("; ")}`;
  const name = typeof obj.error === "string" && obj.error !== "" ? obj.error : undefined;
  const tagged = name !== undefined && TAG.test(`[${name}] `) ? `[${name}] ${text}` : text;
  const out: { body: string; requestId?: string; retryAfterSeconds?: number } = {
    body: JSON.stringify({ message: tagged }),
  };
  if (typeof obj.reqId === "string" && obj.reqId !== "") out.requestId = obj.reqId;
  const wait = TRY_AGAIN.exec(text);
  if (wait !== null) out.retryAfterSeconds = Math.ceil(Number(wait[1]));
  return out;
}

function messageText(message: unknown): string {
  if (typeof message === "string") return message;
  if (!Array.isArray(message)) return "";
  return message
    .map((issue: unknown) => {
      if (typeof issue === "string") return issue;
      if (issue === null || typeof issue !== "object") return "";
      const i = issue as { message?: unknown; path?: unknown };
      const msg = typeof i.message === "string" ? i.message : "";
      const path = Array.isArray(i.path) ? i.path.map(String).join(".") : "";
      return path === "" ? msg : `${path}: ${msg}`;
    })
    .filter((s) => s !== "")
    .join("; ");
}

type Handler = Dispatcher.DispatchHandler;
type Controller = Dispatcher.DispatchController;
type Headers = Record<string, string | string[] | undefined>;

/** Buffers error responses (status >= 400) and rewrites their body (see {@link normaliseErrorBody}). */
class ErrorBodyHandler implements Handler {
  readonly #inner: Handler;
  #status = 0;
  #headers: Headers = {};
  #statusMessage: string | undefined;
  #chunks: Buffer[] | undefined;
  #size = 0;

  constructor(inner: Handler) {
    this.#inner = inner;
  }

  onRequestStart(controller: Controller, context: unknown): void {
    this.#inner.onRequestStart?.(controller, context);
  }

  onRequestUpgrade(
    controller: Controller,
    statusCode: number,
    headers: Headers,
    socket: Parameters<NonNullable<Handler["onRequestUpgrade"]>>[3],
  ): void {
    this.#inner.onRequestUpgrade?.(controller, statusCode, headers, socket);
  }

  onResponseStart(
    controller: Controller,
    statusCode: number,
    headers: Headers,
    statusMessage?: string,
  ): void {
    const length = Number(headers["content-length"] ?? 0);
    if (statusCode < 400 || length > MAX_ERROR_BODY) {
      this.#inner.onResponseStart?.(controller, statusCode, headers, statusMessage);
      return;
    }
    this.#status = statusCode;
    this.#headers = { ...headers };
    this.#statusMessage = statusMessage;
    this.#chunks = [];
  }

  onResponseData(controller: Controller, chunk: Buffer): void {
    if (this.#chunks === undefined) {
      this.#inner.onResponseData?.(controller, chunk);
      return;
    }
    this.#size += chunk.length;
    this.#chunks.push(chunk);
  }

  onResponseEnd(controller: Controller, trailers: Headers): void {
    const chunks = this.#chunks;
    if (chunks !== undefined) {
      this.#chunks = undefined;
      let body = Buffer.concat(chunks, this.#size);
      const headers = this.#headers;
      const normalised =
        body.length <= MAX_ERROR_BODY ? normaliseErrorBody(body.toString("utf8")) : undefined;
      if (normalised !== undefined) {
        body = Buffer.from(normalised.body, "utf8");
        headers["content-length"] = String(body.length);
        delete headers["content-encoding"];
        if (normalised.requestId !== undefined && headers[REQUEST_ID_HEADER] === undefined) {
          headers[REQUEST_ID_HEADER] = normalised.requestId;
        }
        if (
          this.#status === 429 &&
          headers["retry-after"] === undefined &&
          normalised.retryAfterSeconds !== undefined
        ) {
          headers["retry-after"] = String(normalised.retryAfterSeconds);
        }
      }
      this.#inner.onResponseStart?.(controller, this.#status, headers, this.#statusMessage);
      if (body.length > 0) this.#inner.onResponseData?.(controller, body);
    }
    this.#inner.onResponseEnd?.(controller, trailers);
  }

  onResponseError(controller: Controller, error: Error): void {
    this.#inner.onResponseError?.(controller, error);
  }
}

/** undici interceptor that installs {@link ErrorBodyHandler} on every request. */
export function errorBodyInterceptor(): Dispatcher.DispatcherComposeInterceptor {
  return (dispatch) => (opts, handler) => dispatch(opts, new ErrorBodyHandler(handler));
}

/**
 * Internal marker for "the route does not exist on this server" (404 with `"error":"Not Found"`
 * and a message starting with `Route `): the signal for the v4 → v3 fallback (DECISIONS.md #6).
 */
export class RouteMissingError extends UnsupportedError {
  constructor(message: string, requestId?: string) {
    super(message, { httpStatus: 404, ...(requestId === undefined ? {} : { requestId }) });
    this.name = "UnsupportedError";
  }
}

/** True for the route-missing signal. */
export function isRouteMissing(err: unknown): err is RouteMissingError {
  return err instanceof RouteMissingError;
}

/**
 * Applies the Infisical status mapping on top of the SPEC defaults (API.md "Error mapping"):
 * - 400 whose message contains `already exists` → `CONFLICT` (other 400 → `VALIDATION`);
 * - 403 `TokenError` (malformed/foreign token) → `AUTHENTICATION`;
 * - 404 `Not Found` + `Route …` → {@link RouteMissingError} (`UNSUPPORTED`);
 * - login endpoints: 400/403 → `AUTHENTICATION`.
 * The `[<error>] ` tag added by the interceptor is removed from the message.
 */
export function mapInfisicalError(err: InfisicalError, login = false): InfisicalError {
  const status = err.httpStatus;
  let message = err.message;
  let tag: string | undefined;
  const sep = message.indexOf(": ");
  if (sep >= 0) {
    const rest = message.slice(sep + 2);
    const m = TAG.exec(rest);
    if (m !== null) {
      tag = m[1];
      message = message.slice(0, sep + 2) + rest.slice(m[0].length);
    }
  }
  if (status === undefined) return err;
  const details = {
    httpStatus: status,
    ...(err.requestId === undefined ? {} : { requestId: err.requestId }),
    ...(err.retryAfterMs === undefined ? {} : { retryAfterMs: err.retryAfterMs }),
    ...(err.cause === undefined ? {} : { cause: err.cause }),
  };
  if (status === 404 && tag === "Not Found" && message.slice(sep + 2).startsWith("Route ")) {
    return new RouteMissingError(message, err.requestId);
  }
  let code: ErrorCode = err.code;
  if (status === 400 && /already exists/i.test(message)) code = ErrorCode.Conflict;
  else if (status === 403 && tag === "TokenError") code = ErrorCode.Authentication;
  else if (login && (status === 400 || status === 403)) code = ErrorCode.Authentication;
  if (code === err.code && message === err.message) return err;
  return errorForCode(code, message, details);
}

/** One Infisical API call. */
export interface ApiCall {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  /** Absolute API path, e.g. `/api/v4/secrets`. */
  path: string;
  /** Operation name for error messages, e.g. `secrets.get API_KEY`. */
  operation: string;
  query?: Readonly<Record<string, QueryValue>>;
  json?: unknown;
  signal?: AbortSignal | undefined;
  /** Bearer token, or `undefined` for unauthenticated calls (login, health). */
  token?: string | undefined;
  /** Login endpoint: 400/403 map to `AuthenticationError`. */
  login?: boolean;
  idempotent?: boolean;
}

/** Sends one call through the transport and applies {@link mapInfisicalError}. */
export async function send<T>(transport: HttpTransport, call: ApiCall): Promise<T> {
  try {
    const res = await transport.request<T>({
      method: call.method,
      path: call.path,
      operation: call.operation,
      headers: call.token === undefined ? {} : { authorization: `Bearer ${call.token}` },
      ...(call.query === undefined ? {} : { query: call.query }),
      ...(call.json === undefined ? {} : { json: call.json }),
      ...(call.signal === undefined ? {} : { signal: call.signal }),
      ...(call.idempotent === undefined ? {} : { idempotent: call.idempotent }),
    });
    return res.data;
  } catch (err) {
    throw err instanceof InfisicalError ? mapInfisicalError(err, call.login === true) : err;
  }
}

/** Error for a response that does not have the documented shape. */
export function unexpected(operation: string, reason: string): UnavailableError {
  return new UnavailableError(`${operation}: unexpected response (${reason})`, {
    retryable: false,
  });
}

/** Rejects empty names client side (`ValidationError`). */
export function requireText(value: unknown, what: string, operation: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new ValidationError(`${operation}: ${what} must not be empty`);
  }
  return value;
}

/** Throws `ConfigError` naming the missing setting. */
export function required<T>(value: T | undefined, what: string, operation: string): T {
  if (value === undefined || value === "") {
    throw new ConfigError(
      `${operation}: ${what} is required (set it in the config / environment or pass it)`,
    );
  }
  return value;
}

/**
 * Normalises a secret/folder path: leading `/`, no duplicate or trailing slashes (`""` → `/`,
 * `"a//b/"` → `/a/b`).
 */
export function normalizePath(path: string | undefined): string {
  if (path === undefined) return "/";
  const parts = path.split("/").filter((s) => s !== "");
  return "/" + parts.join("/");
}

/** Joins two paths (`/a` + `b/c` → `/a/b/c`). */
export function joinPath(base: string, child: string): string {
  return normalizePath(`${base}/${child}`);
}

/** Percent-encodes one path segment. */
export function seg(value: string): string {
  return encodeURIComponent(value);
}

/** Parses an ISO timestamp (`undefined` when absent or invalid). */
export function parseDate(value: unknown): Date | undefined {
  if (typeof value !== "string" || value === "") return undefined;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

/** String or `undefined`. */
export function optString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** String or `""`. */
export function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** Finite number or `fallback`. */
export function num(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

/** Object or `{}`. */
export function obj(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/** Array or `[]`. */
export function arr(value: unknown): unknown[] {
  return Array.isArray(value) ? (value as unknown[]) : [];
}

/** Copies a body, dropping `undefined` values. */
export function compact(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) if (v !== undefined) out[k] = v;
  return out;
}

/** `ValidationError` unless `value` is a positive integer. */
export function positiveInt(value: number, what: string, operation: string): number {
  if (!Number.isInteger(value) || value < 1) {
    throw new ValidationError(`${operation}: ${what} must be a positive integer`);
  }
  return value;
}
