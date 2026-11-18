"""InfisicalSecretsProvider: name model, set (folders, tags, upsert), delete, metadata, get_all,
conformance scenarios against a stateful fake Infisical (sync + async)."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import unquote

import httpx
import pytest

import grow_infisical as sdk
from grow_infisical.testing import ConformanceRunner, assert_scenario, pytest_params
from infisical_support import PROJECT, Router, client, error_body, reply, secret_body

V4 = "/api/v4/secrets"
TAGS = f"/api/v1/projects/{PROJECT}/tags"


class FakeInfisical:
    """A tiny stateful Infisical: v4 secrets, v2 folder creation and tags (one environment)."""

    def __init__(self) -> None:
        self.folders: set[str] = {"/"}
        self.secrets: dict[tuple[str, str], dict[str, Any]] = {}
        self.tags: list[dict[str, str]] = []
        self.requests: list[tuple[str, str]] = []

    @staticmethod
    def _err(status: int, message: str, name: str) -> httpx.Response:
        body = {"reqId": "req-fake", "statusCode": status, "message": message, "error": name}
        return httpx.Response(status, json=body)

    def _public(self, path: str, key: str, item: dict[str, Any], hide: bool) -> dict[str, Any]:
        tags = [t for t in self.tags if t["id"] in item["tagIds"]]
        return {
            "id": item["id"],
            "secretKey": key,
            "secretValue": "<hidden-by-infisical>" if hide else item["value"],
            "secretValueHidden": hide,
            "version": item["version"],
            "type": "shared",
            "environment": "dev",
            "secretPath": path,
            "secretComment": item["comment"],
            "tags": tags,
            "createdAt": "2026-11-18T20:28:13.931Z",
            "updatedAt": "2026-11-18T20:28:13.931Z",
        }

    def __call__(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        self.requests.append((method, path))
        params = request.url.params
        body = json.loads(request.content) if request.content else {}
        if path == TAGS and method == "GET":
            return httpx.Response(200, json={"tags": self.tags})
        if path == TAGS and method == "POST":
            if any(t["slug"] == body["slug"] for t in self.tags):
                return self._err(400, "Tag already exists", "BadRequest")
            tag = {"id": f"tag-{len(self.tags)}", "slug": body["slug"], "color": body["color"]}
            self.tags.append(tag)
            return httpx.Response(200, json={"tag": tag})
        if path == "/api/v2/folders" and method == "POST":
            full = (body["path"].rstrip("/") + "/" + body["name"]).replace("//", "/")
            if body["path"] not in self.folders:
                return self._err(404, "Parent folder not found", "NotFound")
            if full in self.folders:
                return self._err(
                    400, f"Folder with name '{body['name']}' already exists", "BadRequest"
                )
            self.folders.add(full)
            return httpx.Response(
                200, json={"folder": {"id": full, "name": body["name"], "path": full}}
            )
        if path == V4 and method == "GET":
            folder = params.get("secretPath", "/")
            if folder not in self.folders:
                return self._err(
                    404, f"Folder with path '{folder}' not found", "SecretPathNotFound"
                )
            hide = params.get("viewSecretValue") == "false"
            items = [
                self._public(p, k, v, hide) for (p, k), v in self.secrets.items() if p == folder
            ]
            return httpx.Response(200, json={"secrets": items, "imports": []})
        if path.startswith(V4 + "/"):
            key = unquote(path[len(V4) + 1 :])
            folder = (
                params.get("secretPath") if method == "GET" else body.get("secretPath")
            ) or "/"
            item = self.secrets.get((folder, key))
            if method == "GET":
                if item is None:
                    return self._err(404, f"Secret with name '{key}' not found", "NotFound")
                hide = params.get("viewSecretValue") == "false"
                return httpx.Response(200, json={"secret": self._public(folder, key, item, hide)})
            if method == "POST":
                if folder not in self.folders:
                    return self._err(404, f"Folder with path '{folder}' not found", "CreateSecret")
                if item is not None:
                    return self._err(400, f"Secret '{key}' already exists", "BadRequest")
                item = {
                    "id": f"id-{len(self.secrets)}",
                    "value": body["secretValue"].strip(),
                    "version": 1,
                    "comment": body.get("secretComment", ""),
                    "tagIds": body.get("tagIds", []),
                }
                self.secrets[(folder, key)] = item
                return httpx.Response(200, json={"secret": self._public(folder, key, item, False)})
            if item is None:
                return self._err(404, f"Secret with name {key} not found", "NotFound")
            if method == "PATCH":
                if "secretValue" in body:
                    item["value"] = body["secretValue"].strip()
                if "secretComment" in body:
                    item["comment"] = body["secretComment"]
                if "tagIds" in body:
                    item["tagIds"] = body["tagIds"]
                item["version"] += 1
                return httpx.Response(200, json={"secret": self._public(folder, key, item, False)})
            del self.secrets[(folder, key)]
            return httpx.Response(200, json={"secret": self._public(folder, key, item, False)})
        return self._err(404, f"Route {method}:{path} not found", "Not Found")


def fake_client(fake: FakeInfisical, **kw: Any) -> sdk.InfisicalClient:
    return sdk.InfisicalClient(
        sdk.InfisicalConfig(
            url="http://infisical.test", token="t-fake", project_id=PROJECT, environment="dev", **kw
        ),
        http_transport=httpx.MockTransport(fake),
    )


def fake_aclient(fake: FakeInfisical) -> sdk.AsyncInfisicalClient:
    return sdk.AsyncInfisicalClient(
        sdk.InfisicalConfig(
            url="http://infisical.test", token="t-fake", project_id=PROJECT, environment="dev"
        ),
        http_transport=httpx.MockTransport(fake),
    )


CAPABILITIES = {"write", "delete", "versions"}


@pytest.mark.parametrize("scenario", pytest_params(categories=["secrets"]))
def test_conformance_sync(scenario: dict[str, Any]) -> None:
    with fake_client(FakeInfisical()) as c:
        runner = ConformanceRunner({"secrets": lambda ctx: c.provider}, capabilities=CAPABILITIES)
        assert_scenario(runner, scenario)


@pytest.mark.parametrize("scenario", pytest_params(categories=["secrets"]))
def test_conformance_async(scenario: dict[str, Any]) -> None:
    fake = FakeInfisical()
    runner = ConformanceRunner(
        {"secrets": lambda ctx: fake_aclient(fake).provider}, capabilities=CAPABILITIES
    )
    assert_scenario(runner, scenario)


def test_name_model_and_set_creates_folders_and_tags() -> None:
    fake = FakeInfisical()
    with fake_client(fake, secret_path="/base") as c:
        p = c.provider
        assert p.base_path == "/base"
        assert p.locate("a/b/KEY") == sdk.SecretLocation("/base/a/b", "KEY")
        assert p.locate("KEY", path="x") == sdk.SecretLocation("/base/x", "KEY")
        for bad in ("", "/", "dir/"):
            with pytest.raises(sdk.ValidationError):
                p.locate(bad)
        version = p.set("a/b/KEY", "v1", tags={"team": "#ff0000", "plain": "x"}, description="d")
        assert version == "1"
        assert {"/base", "/base/a", "/base/a/b"} <= fake.folders
        assert [t["color"] for t in fake.tags] == ["#ff0000", sdk.DEFAULT_TAG_COLOR]
        assert p.set("a/b/KEY", "v2", tags={"team": "x"}) == "2"  # existing tag reused
        assert len(fake.tags) == 2
        meta = p.metadata("a/b/KEY")
        assert meta is not None
        assert meta.name == "a/b/KEY" and meta.path == "/base/a/b" and meta.version == "2"
        assert meta.tags == {"team": "team"} and meta.extra["type"] == "shared"
        assert p.get("a/b/KEY", version="2") is not None
        with pytest.raises(sdk.ValidationError):
            p.get("a/b/KEY", version="first")
        assert [m.name for m in p.list("a/b")] == ["a/b/KEY"]
        assert p.list("missing") == []
        assert p.get_all("missing") == {}
        assert p.get_string("KEY", path="a/b") == "v2"
        with pytest.raises(sdk.UnsupportedError):
            p.set("a/b/KEY", "v", cas=1)
        with pytest.raises(sdk.ValidationError):
            p.set("a/b/KEY", b"\xff\xfe")
        with pytest.raises(sdk.UnsupportedError):
            p.delete("a/b/KEY", versions=["1"])
        p.delete("a/b/KEY")
        with pytest.raises(sdk.NotFoundError):
            p.delete("a/b/KEY")
        other = c.secrets_provider(environment="dev", base_path="/", project_id=PROJECT)
        assert other.base_path == "/"
        other.set("ROOT", "r")
        assert other.get_string("ROOT") == "r"


def test_set_tag_race_and_non_folder_404() -> None:
    router = (
        Router()
        .add(
            "GET", TAGS, reply(200, {"tags": []}), reply(200, {"tags": [{"id": "t9", "slug": "x"}]})
        )
        .add("POST", TAGS, error_body(400, "Tag already exists", "BadRequest"))
        .add("POST", f"{V4}/K", reply(200, {"secret": secret_body("K")}))
    )
    with client(router) as c:
        assert c.provider.set("K", "v", tags={"x": ""}) == "1"
    assert router.last("POST", f"{V4}/K").json["tagIds"] == ["t9"]
    router2 = (
        Router()
        .add("GET", TAGS, reply(200, {"tags": []}))
        .add("POST", TAGS, error_body(400, "Tag already exists", "BadRequest"))
    )
    with client(router2) as c, pytest.raises(sdk.ConflictError):
        c.provider.set("K", "v", tags={"x": ""})
    router3 = Router().add("POST", f"{V4}/K", error_body(404, "Project not found", "NotFound"))
    with client(router3) as c, pytest.raises(sdk.NotFoundError):
        c.provider.set("K", "v")
    router4 = Router().add("GET", f"{V4}/K", error_body(403, "denied", "PermissionDenied"))
    with client(router4) as c, pytest.raises(sdk.PermissionDeniedError):
        c.provider.get("K")


def test_get_all_includes_imports_without_overriding() -> None:
    body = {
        "secrets": [secret_body("A", "direct")],
        "imports": [
            {
                "environment": "staging",
                "secretPath": "/",
                "secrets": [secret_body("A", "imported"), secret_body("B", "imported-b")],
            }
        ],
    }
    router = Router().add("GET", V4, reply(200, body))
    with client(router) as c:
        values = c.provider.get_all()
    assert {k: v.reveal() for k, v in values.items()} == {"A": "direct", "B": "imported-b"}
    assert list(values) == ["A", "B"]


def test_watch_stopped_by_client_close() -> None:
    fake = FakeInfisical()
    c = fake_client(fake)
    c.provider.set("W", "1")
    changes: list[str | None] = []
    c.provider.watch("W", 0.02, lambda new, old: changes.append(new.reveal() if new else None))
    time.sleep(0.05)
    c.provider.set("W", "2")
    deadline = time.monotonic() + 2
    while "2" not in changes and time.monotonic() < deadline:
        time.sleep(0.01)
    c.close()
    assert "2" in changes


async def test_async_provider() -> None:
    fake = FakeInfisical()
    async with fake_aclient(fake) as c:
        p = c.provider
        assert p.base_path == "/"
        assert p.locate("x/Y").key == "Y"
        assert await p.set("dir/K", "v") == "1"
        assert (await p.require("dir/K")).reveal() == "v"
        meta = await p.metadata("dir/K")
        assert meta is not None and meta.version == "1"
        assert [m.name for m in await p.list("dir")] == ["dir/K"]
        assert (await p.get_all("dir"))["dir/K"].reveal() == "v"
        other = c.secrets_provider(base_path="/dir")
        assert await other.get_string("K") == "v"
        handle = p.watch("dir/K", 0.05, lambda new, old: None)
        await asyncio.sleep(0)
        handle.stop()
        await p.delete("dir/K")
        assert await p.get("dir/K") is None
