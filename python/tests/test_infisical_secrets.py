"""Secrets API: v4 calls, v3 fallback, batch, versions, load_env / export_dotenv, errors."""

from __future__ import annotations

import pytest

import grow_infisical as sdk
from infisical_support import (
    PROJECT,
    Router,
    aclient,
    client,
    error_body,
    fixture,
    reply,
    secret_body,
)

V4 = "/api/v4/secrets"
V3 = "/api/v3/secrets/raw"
TAGS = f"/api/v1/projects/{PROJECT}/tags"


def test_list_secrets_v4_params_and_parse() -> None:
    router = Router().add("GET", V4, "listSecrets.ok")
    with client(router) as c:
        listed = c.secrets.list_secrets(
            secret_path="app/", tag_slugs=["a", "b"], view_secret_value=True
        )
        assert c.api_version() == "v4"
    seen = router.last("GET", V4)
    assert seen.params == {
        "projectId": PROJECT,
        "environment": "dev",
        "secretPath": "/app",
        "recursive": "false",
        "expandSecretReferences": "true",
        "includeImports": "true",
        "tagSlugs": "a,b",
        "viewSecretValue": "true",
    }
    expected = fixture("listSecrets.ok")["body"]["secrets"]
    assert [s.key for s in listed.secrets] == [s["secretKey"] for s in expected]
    first = listed.secrets[0]
    assert first.value.reveal() == expected[0]["secretValue"]
    assert expected[0]["secretValue"] not in repr(first)
    assert first.created_at is not None and first.created_at.tzinfo is not None


def test_list_with_imports_hidden_and_overrides() -> None:
    router = Router().add("GET", V4, "listSecrets.withImports", "listSecrets.hiddenValues")
    with client(router, expand_secret_references=False, include_imports=False) as c:
        listed = c.secrets.list_secrets(include_imports=True, include_personal_overrides=False)
        assert listed.imports[0].environment == "staging"
        assert listed.imports[0].secrets[0].key == "SDK_COMMON"
        assert listed.imports[0].folder_id
        hidden = c.secrets.list_secrets(view_secret_value=False)
        assert all(s.value_hidden for s in hidden.secrets)
    params = router.calls("GET", V4)[0].params
    assert params["expandSecretReferences"] == "false"
    assert params["includeImports"] == "true"
    assert params["includePersonalOverrides"] == "false"


def test_get_secret_variants() -> None:
    router = Router().add(
        "GET", f"{V4}/API_KEY", "getSecret.ok", "getSecret.version1", "getSecret.404"
    )
    with client(router) as c:
        s = c.secrets.get_secret("API_KEY")
        assert s.version == 1 and s.secret_path == "/" and s.comment == "c1"
        old = c.secrets.get_secret("API_KEY", version=1, type="personal", secret_path="/x")
        assert old.version >= 1
        with pytest.raises(sdk.NotFoundError) as info:
            c.secrets.get_secret("API_KEY")
        assert info.value.request_id
        with pytest.raises(sdk.ValidationError):
            c.secrets.get_secret("API_KEY", version=0)
        with pytest.raises(sdk.ValidationError):
            c.secrets.get_secret(" ")
    second = router.calls("GET", f"{V4}/API_KEY")[1]
    assert second.params["version"] == "1" and second.params["type"] == "personal"
    assert second.params["secretPath"] == "/x"


def test_scope_required_at_call_time() -> None:
    router = Router()
    c = sdk.InfisicalClient(
        sdk.InfisicalConfig(url="http://infisical.test", token="t-1"),
        http_transport=router.transport,
    )
    with pytest.raises(sdk.ConfigError, match="project_id"):
        c.secrets.list_secrets()
    with pytest.raises(sdk.ConfigError, match="environment"):
        c.secrets.list_secrets(project_id="p")
    assert router.seen == []


def test_create_update_delete() -> None:
    router = (
        Router()
        .add("POST", f"{V4}/K1", "createSecret.ok", "createSecret.duplicate400")
        .add("PATCH", f"{V4}/K1", "updateSecret.renameCommentTags")
        .add("DELETE", f"{V4}/K1", "deleteSecret.ok", "deleteSecret.404")
        .add("GET", TAGS, "listTags.ok")
    )
    tag = fixture("listTags.ok")["body"]["tags"][0]
    with client(router) as c:
        created = c.secrets.create_secret(
            "K1",
            "value-1",
            comment="c",
            tag_ids=["x"],
            tag_slugs=[tag["slug"]],
            type="shared",
            skip_multiline_encoding=True,
            metadata={"b": "2", "a": "1"},
        )
        assert created.version == 1
        body = router.last("POST", f"{V4}/K1").json
        assert body["tagIds"] == ["x", tag["id"]]
        assert body["secretMetadata"] == [{"key": "a", "value": "1"}, {"key": "b", "value": "2"}]
        assert body["projectId"] == PROJECT and body["secretPath"] == "/"
        with pytest.raises(sdk.ConflictError):
            c.secrets.create_secret("K1", "dup")
        with pytest.raises(sdk.ValidationError):
            c.secrets.create_secret("K1", 5)  # type: ignore[arg-type]
        with pytest.raises(sdk.NotFoundError, match="tag nope"):
            c.secrets.create_secret("K1", "v", tag_slugs=["nope"])
        updated = c.secrets.update_secret("K1", new_name="K2", comment="c2", tag_ids=[])
        assert updated.key
        patch = router.last("PATCH", f"{V4}/K1").json
        assert patch["newSecretName"] == "K2" and patch["tagIds"] == []
        assert "secretValue" not in patch
        with pytest.raises(sdk.ValidationError):
            c.secrets.update_secret("K1", new_name="")
        deleted = c.secrets.delete_secret("K1", type="shared")
        assert deleted.key
        assert router.last("DELETE", f"{V4}/K1").json["type"] == "shared"
        with pytest.raises(sdk.NotFoundError):
            c.secrets.delete_secret("K1")


@pytest.mark.parametrize(
    ("name", "error"),
    [
        ("createSecret.folderMissing404", sdk.NotFoundError),
        ("createSecret.invalidName422", sdk.ValidationError),
        ("createSecret.personalAsIdentity400", sdk.ValidationError),
        ("createSecret.403viewer", sdk.PermissionDeniedError),
    ],
)
def test_create_errors(name: str, error: type[sdk.InfisicalError]) -> None:
    router = Router().add("POST", f"{V4}/K", name)
    with client(router) as c, pytest.raises(error) as info:
        c.secrets.create_secret("K", "v")
    assert info.value.http_status == fixture(name)["status"]
    assert info.value.message.startswith("secrets.create K: ")


def test_batch_calls() -> None:
    batch = f"{V4}/batch"
    router = (
        Router()
        .add("POST", batch, "createSecrets.ok", "createSecrets.duplicate400")
        .add("PATCH", batch, "updateSecrets.ok", "updateSecrets.404")
        .add("DELETE", batch, "deleteSecrets.ok")
    )
    with client(router) as c:
        made = c.secrets.create_secrets(
            [
                sdk.BatchCreateSecret("A", "1", comment="x", metadata={"k": "v"}),
                sdk.BatchCreateSecret("B", "2"),
            ],
            secret_path="/app",
        )
        assert len(made) == len(fixture("createSecrets.ok")["body"]["secrets"])
        assert router.last("POST", batch).json["secrets"][0] == {
            "secretKey": "A",
            "secretValue": "1",
            "secretComment": "x",
            "secretMetadata": [{"key": "k", "value": "v"}],
        }
        assert "secretValue" not in repr(sdk.BatchCreateSecret("A", "hidden-value"))
        with pytest.raises(sdk.ConflictError):
            c.secrets.create_secrets([sdk.BatchCreateSecret("A", "1")])
        c.secrets.update_secrets(
            [sdk.BatchUpdateSecret("A", value="3", new_name="AA", secret_path="sub")], mode="upsert"
        )
        sent = router.last("PATCH", batch).json
        assert sent["mode"] == "upsert"
        assert sent["secrets"][0] == {
            "secretKey": "A",
            "secretValue": "3",
            "newSecretName": "AA",
            "secretPath": "/sub",
        }
        with pytest.raises(sdk.NotFoundError):
            c.secrets.update_secrets([sdk.BatchUpdateSecret("NOPE", value="x")])
        with pytest.raises(sdk.ValidationError):
            c.secrets.update_secrets([sdk.BatchUpdateSecret("A")], mode="sometimes")
        c.secrets.delete_secrets(["A", sdk.BatchDeleteSecret("B", type="shared")])
        assert router.last("DELETE", batch).json["secrets"] == [
            {"secretKey": "A"},
            {"secretKey": "B", "type": "shared"},
        ]
        assert c.secrets.create_secrets([]) == []
        assert c.secrets.update_secrets([]) == []
        assert c.secrets.delete_secrets([]) == []
        with pytest.raises(sdk.ValidationError):
            c.secrets.delete_secrets([""])


def test_list_secret_versions() -> None:
    path = "/api/v1/secret/sid-1/secret-versions"
    router = Router().add("GET", path, "listSecretVersions.ok", "listSecretVersions.identity403")
    with client(router) as c:
        versions = c.secrets.list_secret_versions("sid-1", offset=0, limit=50)
        first = versions[0]
        assert (
            first.version == 3 and first.actor is not None and first.actor.actor_type == "identity"
        )
        assert first.value.reveal() and first.created_at is not None
        assert router.last("GET", path).params == {"offset": "0", "limit": "50"}
        with pytest.raises(sdk.PermissionDeniedError):
            c.secrets.list_secret_versions("sid-1")
        for bad in ({"limit": 0}, {"limit": 1001}, {"offset": -1}, {"limit": True}):
            with pytest.raises(sdk.ValidationError):
                c.secrets.list_secret_versions("sid-1", **bad)  # type: ignore[arg-type]


def test_load_env_and_export_dotenv() -> None:
    body = {
        "secrets": [
            secret_body("DEEP", "deep", path="/app/nested/x"),
            secret_body("SHARED", "nested", path="/app/nested"),
            secret_body("SHARED", "direct", path="/app"),
            secret_body("QUOTE", 'a"b\\c\nd\re', path="/app"),
            secret_body("EXISTING", "new", path="/app"),
        ],
        "imports": [
            {
                "environment": "staging",
                "secretPath": "/common",
                "secrets": [secret_body("SHARED", "imported"), secret_body("IMPORTED", "imp")],
            }
        ],
    }
    router = Router().add("GET", V4, reply(200, body))
    environ = {"EXISTING": "old"}
    with client(router) as c:
        set_vars = c.secrets.load_env(secret_path="/app", recursive=True, environ=environ)
        assert set_vars == {
            "DEEP": "DEEP",
            "IMPORTED": "IMPORTED",
            "QUOTE": "QUOTE",
            "SHARED": "SHARED",
        }
        assert environ["SHARED"] == "direct" and environ["EXISTING"] == "old"
        assert environ["DEEP"] == "deep" and environ["IMPORTED"] == "imp"
        assert c.secrets.load_env(secret_path="/app", override=True, environ=environ)["EXISTING"]
        assert environ["EXISTING"] == "new"
        dotenv = c.secrets.export_dotenv(secret_path="/app", include_imports=False)
    assert dotenv.splitlines()[0] == 'DEEP="deep"'
    assert 'QUOTE="a\\"b\\\\c\\nd\\re"\n' in dotenv
    assert router.calls("GET", V4)[-1].params["includeImports"] == "false"
    assert sdk.format_dotenv({}) == ""
    assert sdk.dotenv_quote("x") == '"x"'


def test_load_env_defaults_to_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    router = Router().add("GET", V4, reply(200, {"secrets": [secret_body("GROW_PY_UNIT_X", "1")]}))
    monkeypatch.delenv("GROW_PY_UNIT_X", raising=False)
    with client(router) as c:
        c.secrets.load_env()
    import os

    assert os.environ["GROW_PY_UNIT_X"] == "1"
    monkeypatch.delenv("GROW_PY_UNIT_X")


def test_v3_fallback_on_route_missing() -> None:
    router = (
        Router()
        .add("GET", f"{V3}/K", "getSecret.v3raw-ok")
        .add("POST", f"{V3}/K", "createSecret.v3raw-ok")
    )
    with client(router) as c:
        s = c.secrets.get_secret("K")
        assert s.key and c.api_version() == "v3"
        c.secrets.create_secret("K", "v")
    v4 = router.calls("GET", f"{V4}/K")
    assert len(v4) == 1  # probed once, then remembered
    v3 = router.last("GET", f"{V3}/K")
    assert v3.params["workspaceId"] == PROJECT
    assert v3.params["include_imports"] == "true" and v3.params["expandSecretReferences"] == "true"
    assert router.last("POST", f"{V3}/K").json["workspaceId"] == PROJECT
    assert not router.calls("POST", f"{V4}/K")


def test_forced_v3_and_batch_paths() -> None:
    router = (
        Router()
        .add("GET", V3, "listSecrets.v3raw-ok")
        .add("POST", "/api/v3/secrets/batch/raw", "createSecrets.v3raw-ok")
        .add("PATCH", f"{V3}/K", "updateSecret.v3raw-ok")
        .add("DELETE", f"{V3}/K", "deleteSecret.v3raw-ok")
    )
    with client(router, api_version="v3") as c:
        assert c.api_version() == "v3"
        c.secrets.list_secrets()
        c.secrets.create_secrets([sdk.BatchCreateSecret("A", "1")])
        c.secrets.update_secret("K", value="2")
        c.secrets.delete_secret("K")
        with pytest.raises(sdk.UnsupportedError):  # v3 route missing too: no further fallback
            c.secrets.delete_secrets(["A"])
    assert not [s for s in router.seen if s.path.startswith("/api/v4")]


def test_domain_404_keeps_v4() -> None:
    router = Router().add("GET", f"{V4}/K", "getSecret.404")
    with client(router) as c:
        with pytest.raises(sdk.NotFoundError):
            c.secrets.get_secret("K")
        assert c.api_version() == "v4"


def test_network_error_keeps_version_unknown() -> None:
    import httpx

    def boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    router = Router().add("GET", V4, boom)
    with client(router) as c:
        with pytest.raises(sdk.UnavailableError):
            c.secrets.list_secrets()
        assert c.api_version() == "unknown"


def test_rate_limit_and_error_texts() -> None:
    router = (
        Router()
        .add("GET", V4, "listSecrets.429-synthetic")
        .add(
            "GET",
            f"{V4}/A",
            error_body(
                429, "Rate limit exceeded. Please try again in 9 seconds", "RateLimitExceeded"
            ),
        )
        .add("GET", f"{V4}/B", "listSecrets.serviceTokenRefDenied")
        .add("POST", "/api/v2/folders", "createFolder.422")
    )
    with client(router, retry=sdk.RetryPolicy(max_retries=0)) as c:
        with pytest.raises(sdk.RateLimitError) as info:
            c.secrets.list_secrets()
        assert info.value.retry_after == 7 and info.value.retryable
        with pytest.raises(sdk.RateLimitError) as info2:
            c.secrets.get_secret("A")
        assert info2.value.retry_after == 9
        with pytest.raises(sdk.PermissionDeniedError) as info3:
            c.secrets.get_secret("B")
        assert "Failed to expand" in info3.value.message and "SDK_COMMON" in info3.value.message
        with pytest.raises(sdk.ValidationError) as info4:
            c.folders.create_folder("ok", path="/")
        assert "name: Invalid folder name" in info4.value.message


async def test_async_secrets() -> None:
    router = (
        Router()
        .add("GET", V4, "listSecrets.ok")
        .add("GET", f"{V4}/K", "getSecret.ok")
        .add("POST", f"{V4}/K", "createSecret.ok")
        .add("PATCH", f"{V4}/K", "updateSecret.value")
        .add("DELETE", f"{V4}/K", "deleteSecret.ok")
        .add("POST", f"{V4}/batch", "createSecrets.ok")
        .add("PATCH", f"{V4}/batch", "updateSecrets.ok")
        .add("DELETE", f"{V4}/batch", "deleteSecrets.ok")
        .add("GET", "/api/v1/secret/s/secret-versions", "listSecretVersions.ok")
    )
    async with aclient(router) as c:
        assert (await c.secrets.list_secrets()).secrets
        assert (await c.secrets.get_secret("K")).key
        await c.secrets.create_secret("K", "v")
        await c.secrets.update_secret("K", value="w")
        await c.secrets.delete_secret("K")
        await c.secrets.create_secrets([sdk.BatchCreateSecret("A", "1")])
        await c.secrets.update_secrets([sdk.BatchUpdateSecret("A", value="2")])
        await c.secrets.delete_secrets(["A"])
        assert await c.secrets.list_secret_versions("s")
        env: dict[str, str] = {}
        assert await c.secrets.load_env(environ=env)
        assert "=" in await c.secrets.export_dotenv()


async def test_async_route_missing_fallback() -> None:
    router = Router().add("GET", V3, "listSecrets.v3raw-ok")
    async with aclient(router) as c:
        await c.secrets.list_secrets()
        assert c.api_version() == "v3"
