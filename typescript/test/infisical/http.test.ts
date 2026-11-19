import { describe, expect, it } from "vitest";
import {
  AuthenticationError,
  ConfigError,
  NotFoundError,
  PermissionDeniedError,
  UnavailableError,
  ValidationError,
  errorForStatus,
} from "../../src/index.js";
import {
  arr,
  compact,
  isRouteMissing,
  joinPath,
  mapInfisicalError,
  normaliseErrorBody,
  normalizePath,
  num,
  obj,
  optString,
  parseDate,
  positiveInt,
  required,
  requireText,
  seg,
  str,
  unexpected,
} from "../../src/http.js";
import { fixture } from "./helpers.js";

function normalised(name: string) {
  return normaliseErrorBody(JSON.stringify(fixture(name).body));
}

describe("normaliseErrorBody", () => {
  it("tags the error name and keeps reqId", () => {
    const out = normalised("auth.malformedToken");
    expect(out?.requestId).toBe("req-Pzo5lTCTSGutpn");
    expect(JSON.parse(out!.body).message).toMatch(/^\[TokenError\] The provided access token/);
  });

  it("joins zod issues with their path", () => {
    const out = normalised("createSecret.invalidName422");
    expect(JSON.parse(out!.body).message).toBe(
      "[ValidationFailure] secretName: Secret name cannot contain colon or forward slash.",
    );
  });

  it("appends details[]", () => {
    const out = normalised("listSecrets.serviceTokenRefDenied");
    const msg = JSON.parse(out!.body).message as string;
    expect(msg).toContain("Failed to expand one or more secret references: You do not have");
  });

  it("parses the retry hint of rate limits", () => {
    expect(normalised("listSecrets.429-synthetic")?.retryAfterSeconds).toBe(7);
  });

  it("handles odd bodies", () => {
    expect(normaliseErrorBody("<html>")).toBeUndefined();
    expect(normaliseErrorBody("[1]")).toBeUndefined();
    expect(normaliseErrorBody("null")).toBeUndefined();
    const plain = normaliseErrorBody(
      JSON.stringify({ message: ["a", 3, { path: "x", message: "m" }, { message: "only" }] }),
    );
    expect(JSON.parse(plain!.body).message).toBe("a; m; only");
    expect(plain?.requestId).toBeUndefined();
    const detailsOnly = normaliseErrorBody(JSON.stringify({ details: ["d1", 2, "d2"], error: "" }));
    expect(JSON.parse(detailsOnly!.body).message).toBe("d1; d2");
    const weird = normaliseErrorBody(JSON.stringify({ message: 5, error: "bad name!!" }));
    expect(JSON.parse(weird!.body).message).toBe("");
  });
});

describe("mapInfisicalError", () => {
  const make = (status: number, reason: string, requestId = "req-1") =>
    errorForStatus("op", status, { reason, requestId, retryAfterMs: 5, cause: new Error("c") });

  it("400 already exists → CONFLICT, other 400 → VALIDATION", () => {
    const e = mapInfisicalError(make(400, "[BadRequest] Secret 'X' already exists"));
    expect(e.code).toBe("CONFLICT");
    expect(e.message).toBe("op: Secret 'X' already exists (HTTP 400)");
    expect(e.requestId).toBe("req-1");
    expect(e.retryAfterMs).toBe(5);
    expect(mapInfisicalError(make(400, "[BadRequest] Missing project id")).code).toBe("VALIDATION");
  });

  it("403 TokenError → AUTHENTICATION, other 403 stays", () => {
    expect(mapInfisicalError(make(403, "[TokenError] malformed"))).toBeInstanceOf(
      AuthenticationError,
    );
    expect(mapInfisicalError(make(403, "[PermissionDenied] no"))).toBeInstanceOf(
      PermissionDeniedError,
    );
  });

  it("route missing is detected; domain 404 stays NOT_FOUND", () => {
    const e = mapInfisicalError(make(404, "[Not Found] Route GET:/api/v5/secrets not found"));
    expect(isRouteMissing(e)).toBe(true);
    expect(e.code).toBe("UNSUPPORTED");
    expect(e.name).toBe("UnsupportedError");
    expect(mapInfisicalError(make(404, "[Not Found] something else"))).toBeInstanceOf(
      NotFoundError,
    );
    expect(mapInfisicalError(make(404, "[NotFound] Route x"))).toBeInstanceOf(NotFoundError);
    expect(isRouteMissing(new Error("x"))).toBe(false);
  });

  it("login endpoints map 400/403 to AUTHENTICATION", () => {
    expect(mapInfisicalError(make(400, "bad"), true).code).toBe("AUTHENTICATION");
    expect(mapInfisicalError(make(403, "bad"), true).code).toBe("AUTHENTICATION");
    expect(mapInfisicalError(make(401, "bad"), true).code).toBe("AUTHENTICATION");
  });

  it("returns the same error when nothing changes", () => {
    const e = make(500, "boom");
    expect(mapInfisicalError(e)).toBe(e);
    const noStatus = new UnavailableError("op: [X] network");
    expect(mapInfisicalError(noStatus)).toBe(noStatus);
    const bare = errorForStatus("op", 422, {});
    expect(mapInfisicalError(bare)).toBe(bare);
  });
});

describe("helpers", () => {
  it("paths", () => {
    expect(normalizePath(undefined)).toBe("/");
    expect(normalizePath("")).toBe("/");
    expect(normalizePath("a//b/")).toBe("/a/b");
    expect(joinPath("/a", "b/c/")).toBe("/a/b/c");
    expect(seg("a b/c")).toBe("a%20b%2Fc");
  });

  it("wire values", () => {
    expect(parseDate("2026-11-18T20:28:13.931Z")?.toISOString()).toBe("2026-11-18T20:28:13.931Z");
    expect(parseDate("nope")).toBeUndefined();
    expect(parseDate(3)).toBeUndefined();
    expect(optString(1)).toBeUndefined();
    expect(str(1)).toBe("");
    expect(num("1", 7)).toBe(7);
    expect(num(Number.NaN)).toBe(0);
    expect(obj([1])).toEqual({});
    expect(arr({})).toEqual([]);
    expect(compact({ a: 1, b: undefined })).toEqual({ a: 1 });
  });

  it("validation helpers", () => {
    expect(() => requireText(" ", "name", "op")).toThrow(ValidationError);
    expect(() => required(undefined, "projectId", "op")).toThrow(ConfigError);
    expect(() => required("", "projectId", "op")).toThrow(/projectId is required/);
    expect(required("x", "p", "op")).toBe("x");
    expect(() => positiveInt(0, "version", "op")).toThrow(ValidationError);
    expect(positiveInt(2, "version", "op")).toBe(2);
    expect(unexpected("op", "why").message).toBe("op: unexpected response (why)");
  });
});
