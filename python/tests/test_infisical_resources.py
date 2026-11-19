"""Folders, projects + environments, tags and secret imports."""

from __future__ import annotations

import pytest

import grow_infisical as sdk
from infisical_support import PROJECT, Router, aclient, client, fixture

FOLDERS = "/api/v2/folders"
IMPORTS = "/api/v2/secret-imports"
TAGS = f"/api/v1/projects/{PROJECT}/tags"


def test_folders() -> None:
    router = (
        Router()
        .add("GET", FOLDERS, "listFolders.ok", "listFolders.recursive")
        .add("POST", FOLDERS, "createFolder.ok", "createFolder.duplicate400")
        .add("PATCH", f"{FOLDERS}/f-1", "updateFolder.ok", "updateFolder.404")
        .add("DELETE", f"{FOLDERS}/f-1", "deleteFolder.ok", "deleteFolder.404")
    )
    with client(router) as c:
        assert c.folders.list_folders(path="app")
        assert router.last("GET", FOLDERS).params == {
            "projectId": PROJECT,
            "environment": "dev",
            "path": "/app",
        }
        nested = c.folders.list_folders(recursive=True)
        assert router.last("GET", FOLDERS).params["recursive"] == "true"
        assert any(f.relative_path for f in nested)
        made = c.folders.create_folder("app", description="d")
        assert made.id and made.path
        assert router.last("POST", FOLDERS).json == {
            "projectId": PROJECT,
            "environment": "dev",
            "path": "/",
            "name": "app",
            "description": "d",
        }
        with pytest.raises(sdk.ConflictError):
            c.folders.create_folder("app")
        with pytest.raises(sdk.ValidationError):
            c.folders.create_folder("bad/name")
        updated = c.folders.update_folder("f-1", name="renamed", path="/")
        assert updated.version >= 1
        with pytest.raises(sdk.NotFoundError):
            c.folders.update_folder("f-1", name="x")
        assert c.folders.delete_folder("f-1", force_delete=True).id
        assert router.last("DELETE", f"{FOLDERS}/f-1").json["forceDelete"] is True
        with pytest.raises(sdk.NotFoundError):
            c.folders.delete_folder("f-1")


def test_projects_and_environments() -> None:
    router = (
        Router()
        .add("GET", "/api/v1/projects", "listProjects.ok")
        .add("GET", f"/api/v1/projects/{PROJECT}", "getProject.ok")
        .add("GET", "/api/v1/projects/missing", "getProject.404")
        .add("GET", "/api/v1/projects/slug/sdk-test", "getProjectBySlug.ok")
        .add(
            "POST",
            f"/api/v1/projects/{PROJECT}/environments",
            "createEnvironment.ok",
            "createEnvironment.duplicate400",
            "createEnvironment.403viewer",
        )
    )
    with client(router) as c:
        page = c.projects.list_projects(limit=10, offset=0)
        assert page.total_count == fixture("listProjects.ok")["body"]["totalCount"]
        assert page.projects[0].environments
        assert router.last("GET", "/api/v1/projects").params == {
            "type": "secret-manager",
            "limit": "10",
            "offset": "0",
        }
        with pytest.raises(sdk.ValidationError):
            c.projects.list_projects(limit=101)
        project = c.projects.get_project()
        assert project.slug == "sdk-test"
        with pytest.raises(sdk.NotFoundError):
            c.projects.get_project("missing")
        assert c.projects.get_project_by_slug("sdk-test").id == project.id
        envs = c.projects.list_environments()
        assert [e.slug for e in envs][:1] == ["dev"]
        env = c.projects.create_environment("QA", "qa", position=5)
        assert env.slug and env.id
        assert router.last("POST", f"/api/v1/projects/{PROJECT}/environments").json == {
            "name": "QA",
            "slug": "qa",
            "position": 5,
        }
        with pytest.raises(sdk.ConflictError):
            c.projects.create_environment("QA", "qa")
        with pytest.raises(sdk.PermissionDeniedError):
            c.projects.create_environment("QA", "qa")


def test_tags() -> None:
    router = (
        Router()
        .add("GET", TAGS, "listTags.ok")
        .add("POST", TAGS, "createTag.ok", "createTag.duplicate400", "createTag.422")
        .add("DELETE", f"{TAGS}/t-1", "deleteTag.ok", "deleteTag.404")
    )
    with client(router) as c:
        assert c.tags.list_tags()[0].slug
        tag = c.tags.create_tag("team-a", "#ff0000")
        assert tag.id
        assert router.last("POST", TAGS).json == {"slug": "team-a", "color": "#ff0000"}
        with pytest.raises(sdk.ConflictError):
            c.tags.create_tag("team-a")
        with pytest.raises(sdk.ValidationError):
            c.tags.create_tag("Bad Slug")
        assert router.last("POST", TAGS).json["color"] == sdk.DEFAULT_TAG_COLOR
        assert c.tags.delete_tag("t-1").id
        with pytest.raises(sdk.NotFoundError):
            c.tags.delete_tag("t-1")


def test_imports() -> None:
    router = (
        Router()
        .add("GET", IMPORTS, "listSecretImports.ok")
        .add("POST", IMPORTS, "createSecretImport.ok")
        .add("DELETE", f"{IMPORTS}/i-1", "deleteSecretImport.ok", "deleteSecretImport.404")
    )
    with client(router) as c:
        listed = c.imports.list_secret_imports(path="/app")
        assert listed[0].import_environment.slug
        made = c.imports.create_secret_import(
            import_environment="staging",
            import_path="common",
            path="/app",
            is_replication=False,
            source_project_id="p2",
        )
        assert made.import_path == "/common" and made.position == 1
        assert router.last("POST", IMPORTS).json == {
            "projectId": PROJECT,
            "environment": "dev",
            "path": "/app",
            "import": {"environment": "staging", "path": "/common", "sourceProjectId": "p2"},
            "isReplication": False,
        }
        assert c.imports.delete_secret_import("i-1", path="/app").id
        with pytest.raises(sdk.NotFoundError):
            c.imports.delete_secret_import("i-1")
        with pytest.raises(sdk.ValidationError):
            c.imports.create_secret_import(import_environment="")


async def test_async_resources() -> None:
    router = (
        Router()
        .add("GET", FOLDERS, "listFolders.ok")
        .add("POST", FOLDERS, "createFolder.ok")
        .add("PATCH", f"{FOLDERS}/f", "updateFolder.ok")
        .add("DELETE", f"{FOLDERS}/f", "deleteFolder.ok")
        .add("GET", "/api/v1/projects", "listProjects.ok")
        .add("GET", f"/api/v1/projects/{PROJECT}", "getProject.ok")
        .add("GET", "/api/v1/projects/slug/s", "getProjectBySlug.ok")
        .add("POST", f"/api/v1/projects/{PROJECT}/environments", "createEnvironment.ok")
        .add("GET", TAGS, "listTags.ok")
        .add("POST", TAGS, "createTag.ok")
        .add("DELETE", f"{TAGS}/t", "deleteTag.ok")
        .add("GET", IMPORTS, "listSecretImports.ok")
        .add("POST", IMPORTS, "createSecretImport.ok")
        .add("DELETE", f"{IMPORTS}/i", "deleteSecretImport.ok")
    )
    async with aclient(router) as c:
        assert await c.folders.list_folders()
        await c.folders.create_folder("a")
        await c.folders.update_folder("f", name="b")
        await c.folders.delete_folder("f")
        assert (await c.projects.list_projects()).projects
        await c.projects.get_project()
        await c.projects.get_project_by_slug("s")
        assert await c.projects.list_environments()
        await c.projects.create_environment("Q", "q")
        assert await c.tags.list_tags()
        await c.tags.create_tag("x")
        await c.tags.delete_tag("t")
        assert await c.imports.list_secret_imports()
        await c.imports.create_secret_import(import_environment="staging")
        await c.imports.delete_secret_import("i")
