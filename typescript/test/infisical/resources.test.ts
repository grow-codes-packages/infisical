import { afterEach, describe, expect, it } from "vitest";
import { ValidationError } from "../../src/index.js";
import { PROJECT, bodyOf, cleanup, clientFor, queryOf, reply, routed } from "./helpers.js";

afterEach(cleanup);

const FOLDER = "e182ee25-3082-409f-937f-236cf3065f01";

describe("folders", () => {
  it("list / create / update / delete", async () => {
    const s = await routed({
      "GET /api/v2/folders": (req) =>
        queryOf(req).get("recursive") === "true"
          ? reply("listFolders.recursive")
          : reply("listFolders.ok"),
      "POST /api/v2/folders": reply("createFolder.ok"),
      [`PATCH /api/v2/folders/${FOLDER}`]: reply("updateFolder.ok"),
      [`DELETE /api/v2/folders/${FOLDER}`]: reply("deleteFolder.ok"),
    });
    const c = clientFor(s);
    const folders = await c.folders.listFolders();
    expect(folders.map((f) => f.name)).toEqual(["app", "f-49lj3988"]);
    expect(folders[0]!.createdAt).toBeInstanceOf(Date);
    expect(Object.fromEntries(queryOf(s.requests[0]!))).toEqual({
      projectId: PROJECT,
      environment: "dev",
      path: "/",
    });
    const rec = await c.folders.listFolders({ recursive: true, path: "/" });
    expect(rec.map((f) => f.relativePath)).toContain("/app/nested");
    const created = await c.folders.createFolder("f-49lj3988", { description: "d" });
    expect(created).toMatchObject({ name: "f-49lj3988", path: "/f-49lj3988", version: 1 });
    expect(bodyOf(s.requests[2]!)).toEqual({
      projectId: PROJECT,
      environment: "dev",
      path: "/",
      name: "f-49lj3988",
      description: "d",
    });
    const updated = await c.folders.updateFolder(FOLDER, { name: "g-49lj3988" });
    expect(updated).toMatchObject({ name: "g-49lj3988", version: 2 });
    expect(bodyOf(s.requests[3]!)).toEqual({
      projectId: PROJECT,
      environment: "dev",
      path: "/",
      name: "g-49lj3988",
    });
    const deleted = await c.folders.deleteFolder(FOLDER, { forceDelete: true });
    expect(deleted.id).toBe(FOLDER);
    expect(bodyOf(s.requests[4]!).forceDelete).toBe(true);
  });

  it("errors and validation", async () => {
    const s = await routed({
      "POST /api/v2/folders": reply("createFolder.duplicate400"),
      [`PATCH /api/v2/folders/${FOLDER}`]: reply("updateFolder.404"),
      "DELETE /api/v2/folders/nope": reply("deleteFolder.404"),
      [`DELETE /api/v2/folders/${FOLDER}`]: { status: 200, body: {} },
    });
    const c = clientFor(s);
    await expect(c.folders.createFolder("app")).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(c.folders.updateFolder(FOLDER, { name: "x" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await expect(c.folders.deleteFolder("nope")).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(c.folders.deleteFolder(FOLDER)).rejects.toMatchObject({ code: "UNAVAILABLE" });
    await expect(c.folders.createFolder("bad name")).rejects.toBeInstanceOf(ValidationError);
    await expect(c.folders.updateFolder("", { name: "x" })).rejects.toBeInstanceOf(ValidationError);
    await expect(c.folders.deleteFolder("")).rejects.toBeInstanceOf(ValidationError);
  });
});

describe("projects + environments", () => {
  it("listProjects / getProject / getProjectBySlug / listEnvironments / createEnvironment", async () => {
    const s = await routed({
      "GET /api/v1/projects": reply("listProjects.ok"),
      [`GET /api/v1/projects/${PROJECT}`]: reply("getProject.ok"),
      "GET /api/v1/projects/slug/sdk-test": reply("getProjectBySlug.ok"),
      [`POST /api/v1/projects/${PROJECT}/environments`]: reply("createEnvironment.ok"),
    });
    const c = clientFor(s);
    const page = await c.projects.listProjects();
    expect(page.totalCount).toBe(1);
    expect(page.projects[0]).toMatchObject({
      id: PROJECT,
      slug: "sdk-test",
      type: "secret-manager",
    });
    expect(Object.fromEntries(queryOf(s.requests[0]!))).toEqual({
      type: "secret-manager",
      limit: "100",
      offset: "0",
    });
    await c.projects.listProjects({ type: "kms", limit: 1, offset: 2 });
    expect(queryOf(s.requests[1]!).get("type")).toBe("kms");
    const p = await c.projects.getProject();
    expect(p.environments.map((e) => e.slug)).toContain("dev");
    expect(p.createdAt).toBeInstanceOf(Date);
    const bySlug = await c.projects.getProjectBySlug("sdk-test");
    expect(bySlug.id).toBe(PROJECT);
    const envs = await c.projects.listEnvironments({ projectId: PROJECT });
    expect(envs[0]).toMatchObject({ slug: "dev", name: "Development" });
    const env = await c.projects.createEnvironment("E 49lj3988", "e-49lj3988", { position: 5 });
    expect(env).toMatchObject({ slug: "e-49lj3988", position: 5, projectId: PROJECT });
    expect(bodyOf(s.requests.at(-1)!)).toEqual({
      name: "E 49lj3988",
      slug: "e-49lj3988",
      position: 5,
    });
  });

  it("errors and validation", async () => {
    const s = await routed({
      "GET /api/v1/projects/nope": reply("getProject.404"),
      [`GET /api/v1/projects/${PROJECT}`]: { status: 200, body: {} },
      [`POST /api/v1/projects/${PROJECT}/environments`]: (_r, i) =>
        i === 1 ? reply("createEnvironment.duplicate400") : { status: 200, body: {} },
      "GET /api/v1/projects": { status: 200, body: { projects: [{ id: "x" }] } },
    });
    const c = clientFor(s);
    await expect(c.projects.getProject({ projectId: "nope" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await expect(c.projects.createEnvironment("E", "e")).rejects.toMatchObject({
      code: "CONFLICT",
    });
    await expect(c.projects.createEnvironment("E", "e")).rejects.toMatchObject({
      code: "UNAVAILABLE",
    });
    await expect(c.projects.getProject()).rejects.toMatchObject({ code: "UNAVAILABLE" });
    expect((await c.projects.listProjects()).totalCount).toBe(1);
    await expect(c.projects.listProjects({ limit: 101 })).rejects.toBeInstanceOf(ValidationError);
    await expect(c.projects.listProjects({ offset: -1 })).rejects.toBeInstanceOf(ValidationError);
    await expect(c.projects.getProjectBySlug("")).rejects.toBeInstanceOf(ValidationError);
    await expect(c.projects.createEnvironment("", "e")).rejects.toBeInstanceOf(ValidationError);
  });

  it("viewer gets PERMISSION_DENIED on createEnvironment", async () => {
    const s = await routed({
      [`POST /api/v1/projects/${PROJECT}/environments`]: reply("createEnvironment.403viewer"),
    });
    await expect(clientFor(s).projects.createEnvironment("E", "e")).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });
  });
});

describe("tags", () => {
  const TAG = "8ec93966-db51-4801-a143-26296a09c05c";
  it("list / create / delete", async () => {
    const s = await routed({
      [`GET /api/v1/projects/${PROJECT}/tags`]: reply("listTags.ok"),
      [`POST /api/v1/projects/${PROJECT}/tags`]: (req) =>
        bodyOf(req).slug === "dup" ? reply("createTag.duplicate400") : reply("createTag.ok"),
      [`DELETE /api/v1/projects/${PROJECT}/tags/${TAG}`]: reply("deleteTag.ok"),
      [`DELETE /api/v1/projects/${PROJECT}/tags/nope`]: reply("deleteTag.404"),
    });
    const c = clientFor(s);
    const tags = await c.tags.listTags();
    expect(tags[0]).toMatchObject({
      id: TAG,
      slug: "t-49lj3988",
      color: "#00aa00",
      projectId: PROJECT,
    });
    const tag = await c.tags.createTag("t-49lj3988", "#00aa00");
    expect(tag.slug).toBe("t-49lj3988");
    expect(bodyOf(s.requests[1]!)).toEqual({ slug: "t-49lj3988", color: "#00aa00" });
    expect((await c.tags.deleteTag(TAG)).id).toBe(TAG);
    await expect(c.tags.createTag("dup", "#000000")).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(c.tags.deleteTag("nope")).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(c.tags.createTag("x", "")).rejects.toBeInstanceOf(ValidationError);
    await expect(c.tags.deleteTag("")).rejects.toBeInstanceOf(ValidationError);
  });

  it("unexpected bodies", async () => {
    const s = await routed({
      [`POST /api/v1/projects/${PROJECT}/tags`]: { status: 200, body: {} },
      [`DELETE /api/v1/projects/${PROJECT}/tags/x`]: { status: 200, body: {} },
    });
    const c = clientFor(s);
    await expect(c.tags.createTag("x", "#000")).rejects.toMatchObject({ code: "UNAVAILABLE" });
    await expect(c.tags.deleteTag("x")).rejects.toMatchObject({ code: "UNAVAILABLE" });
  });
});

describe("secret imports", () => {
  const IMP = "643ebf45-dad3-4470-8943-f53f5d883d16";
  it("list / create / delete", async () => {
    const s = await routed({
      "GET /api/v2/secret-imports": reply("listSecretImports.ok"),
      "POST /api/v2/secret-imports": reply("createSecretImport.ok"),
      [`DELETE /api/v2/secret-imports/${IMP}`]: reply("deleteSecretImport.ok"),
      "DELETE /api/v2/secret-imports/nope": reply("deleteSecretImport.404"),
    });
    const c = clientFor(s);
    const list = await c.imports.listSecretImports({ path: "/app" });
    expect(list[0]).toMatchObject({
      id: IMP,
      importPath: "/common",
      position: 1,
      isReplication: false,
      sourceProjectName: "SDK Test",
    });
    expect(list[0]!.importEnvironment.slug).toBe("staging");
    expect(Object.fromEntries(queryOf(s.requests[0]!))).toEqual({
      projectId: PROJECT,
      environment: "dev",
      path: "/app",
    });
    const created = await c.imports.createSecretImport({
      path: "/app",
      importEnvironment: "staging",
      importPath: "/common",
      isReplication: false,
      sourceProjectId: PROJECT,
    });
    expect(created.id).toBe(IMP);
    expect(bodyOf(s.requests[1]!)).toEqual({
      projectId: PROJECT,
      environment: "dev",
      path: "/app",
      import: { environment: "staging", path: "/common", sourceProjectId: PROJECT },
      isReplication: false,
    });
    expect((await c.imports.deleteSecretImport(IMP, { path: "/app" })).id).toBe(IMP);
    expect(bodyOf(s.requests[2]!)).toEqual({
      projectId: PROJECT,
      environment: "dev",
      path: "/app",
    });
    await expect(c.imports.deleteSecretImport("nope")).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(c.imports.createSecretImport({ importEnvironment: "" })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(c.imports.deleteSecretImport("")).rejects.toBeInstanceOf(ValidationError);
  });

  it("unexpected body", async () => {
    const s = await routed({ "POST /api/v2/secret-imports": { status: 200, body: {} } });
    await expect(
      clientFor(s).imports.createSecretImport({ importEnvironment: "staging" }),
    ).rejects.toMatchObject({ code: "UNAVAILABLE" });
  });
});
