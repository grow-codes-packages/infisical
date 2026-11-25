"""Every service function against the real Infisical with a round-trip assertion."""

from __future__ import annotations

import asyncio
import secrets as _random
from collections.abc import Iterator

import pytest
from factories import async_core_client, core_client, token_client

import grow_infisical as sdk

RUN = _random.token_hex(4).upper()


def key(name: str) -> str:
    return f"SDK_PY_{RUN}_{name}"


@pytest.fixture
def folder(client: sdk.InfisicalClient) -> Iterator[str]:
    """A fresh folder ``/py-<run>-<n>`` in ``dev`` (deleted afterwards)."""
    name = f"py-{RUN.lower()}-{_random.token_hex(2)}"
    made = client.folders.create_folder(name)
    yield f"/{name}"
    client.folders.delete_folder(made.id, force_delete=True)


# --------------------------------------------------------------------------- secrets


def test_secret_crud_round_trip(client: sdk.InfisicalClient, folder: str) -> None:
    s = client.secrets
    tag = client.tags.create_tag(f"py-{RUN.lower()}", "#00aa00")
    try:
        created = s.create_secret(
            key("ONE"), "v1", secret_path=folder, comment="c1", tag_slugs=[tag.slug]
        )
        assert created.version == 1
        got = s.get_secret(key("ONE"), secret_path=folder)
        assert got.value.reveal() == "v1"
        assert got.comment == "c1"
        assert [t.slug for t in got.tags] == [tag.slug]
        with pytest.raises(sdk.ConflictError):
            s.create_secret(key("ONE"), "dup", secret_path=folder)
        s.update_secret(key("ONE"), value="v2", comment="c2", tag_ids=[], secret_path=folder)
        assert s.get_secret(key("ONE"), secret_path=folder).value.reveal() == "v2"
        assert s.get_secret(key("ONE"), secret_path=folder, version=1).value.reveal() == "v1"
        renamed = s.update_secret(key("ONE"), new_name=key("RENAMED"), secret_path=folder)
        assert renamed.key == key("RENAMED")
        assert renamed.version == 3
        listed = s.list_secrets(secret_path=folder)
        assert [x.key for x in listed.secrets] == [key("RENAMED")]
        assert listed.secrets[0].tags == []
        hidden = s.list_secrets(secret_path=folder, view_secret_value=False)
        assert hidden.secrets[0].value_hidden
        deleted = s.delete_secret(key("RENAMED"), secret_path=folder)
        assert deleted.key == key("RENAMED")
        with pytest.raises(sdk.NotFoundError):
            s.get_secret(key("RENAMED"), secret_path=folder)
        with pytest.raises(sdk.NotFoundError):
            s.create_secret(key("X"), "v", secret_path=f"{folder}/missing")
        assert client.api_version() == "v4"
    finally:
        client.tags.delete_tag(tag.id)


def test_batch_round_trip(client: sdk.InfisicalClient, folder: str) -> None:
    s = client.secrets
    made = s.create_secrets(
        [sdk.BatchCreateSecret(key("A"), "1"), sdk.BatchCreateSecret(key("B"), "2")],
        secret_path=folder,
    )
    assert sorted(x.key for x in made) == [key("A"), key("B")]
    with pytest.raises(sdk.ConflictError):
        s.create_secrets([sdk.BatchCreateSecret(key("A"), "x")], secret_path=folder)
    s.update_secrets(
        [sdk.BatchUpdateSecret(key("A"), value="11"), sdk.BatchUpdateSecret(key("C"), value="3")],
        mode="upsert",
        secret_path=folder,
    )
    values = {x.key: x.value.reveal() for x in s.list_secrets(secret_path=folder).secrets}
    assert values == {key("A"): "11", key("B"): "2", key("C"): "3"}
    with pytest.raises(sdk.NotFoundError):
        s.update_secrets([sdk.BatchUpdateSecret(key("NOPE"), value="x")], secret_path=folder)
    s.delete_secrets([key("A"), sdk.BatchDeleteSecret(key("B")), key("C")], secret_path=folder)
    assert s.list_secrets(secret_path=folder).secrets == []


def test_references_and_imports(
    env: dict[str, str], client: sdk.InfisicalClient, folder: str
) -> None:
    s = client.secrets
    s.create_secret(key("BASE"), "base", secret_path=folder)
    s.create_secret(key("REF"), "${" + key("BASE") + "}-x", secret_path=folder)
    assert s.get_secret(key("REF"), secret_path=folder).value.reveal() == "base-x"
    raw = s.get_secret(key("REF"), secret_path=folder, expand_references=False)
    assert raw.value.reveal().startswith("${")
    imp = client.imports.create_secret_import(
        import_environment=env["INFISICAL_ENVIRONMENT_STAGING"], import_path="/common", path=folder
    )
    try:
        listed = client.imports.list_secret_imports(path=folder)
        assert [i.id for i in listed] == [imp.id]
        assert listed[0].import_environment.slug == env["INFISICAL_ENVIRONMENT_STAGING"]
        with_imports = s.list_secrets(secret_path=folder)
        imported = [x.key for i in with_imports.imports for x in i.secrets]
        assert "SDK_COMMON" in imported
        assert s.list_secrets(secret_path=folder, include_imports=False).imports == []
    finally:
        assert client.imports.delete_secret_import(imp.id, path=folder).id == imp.id
    assert client.imports.list_secret_imports(path=folder) == []


def test_load_env_and_export_dotenv(client: sdk.InfisicalClient, folder: str) -> None:
    s = client.secrets
    sub = folder.strip("/")
    client.folders.create_folder("nested", path=folder)
    s.create_secret(key("TOP"), 'say "hi"', secret_path=folder)
    s.create_secret(key("DEEP"), "deep", secret_path=f"{folder}/nested")
    environ: dict[str, str] = {key("TOP"): "keep"}
    set_vars = s.load_env(secret_path=folder, recursive=True, environ=environ)
    assert set_vars == {key("DEEP"): key("DEEP")}
    assert environ[key("TOP")] == "keep"
    assert environ[key("DEEP")] == "deep"
    s.load_env(secret_path=f"/{sub}", override=True, environ=environ)
    assert environ[key("TOP")] == 'say "hi"'
    dotenv = s.export_dotenv(secret_path=folder, recursive=True)
    assert f'{key("TOP")}="say \\"hi\\""\n' in dotenv
    assert f'{key("DEEP")}="deep"\n' in dotenv


def test_secret_versions(env: dict[str, str], client: sdk.InfisicalClient, folder: str) -> None:
    created = client.secrets.create_secret(key("VER"), "v1", secret_path=folder)
    client.secrets.update_secret(key("VER"), value="v2", secret_path=folder)
    with token_client(env, env["INFISICAL_USER_TOKEN"]) as user:
        versions = user.secrets.list_secret_versions(created.id, limit=10)
    assert [v.version for v in versions][:2] == [2, 1]
    assert versions[0].value.reveal() == "v2"
    assert versions[1].value.reveal() == "v1"
    with pytest.raises(sdk.PermissionDeniedError):  # machine identities: user tokens only
        client.secrets.list_secret_versions(created.id)


def test_personal_secrets_with_user_token(env: dict[str, str], client: sdk.InfisicalClient) -> None:
    name = key("PERSONAL")
    client.secrets.create_secret(name, "shared")
    try:
        with token_client(env, env["INFISICAL_USER_TOKEN"]) as user:
            s = user.secrets
            s.create_secret(name, "mine", type="personal")
            assert s.get_secret(name, type="personal").value.reveal() == "mine"
            assert s.get_secret(name).value.reveal() == "shared"
            overridden = s.list_secrets(include_personal_overrides=True)
            assert {x.key: x.value.reveal() for x in overridden.secrets}[name] == "mine"
            s.delete_secret(name, type="personal")
            with pytest.raises(sdk.NotFoundError):
                s.get_secret(name, type="personal")
        with pytest.raises(sdk.ValidationError):  # identities cannot own personal secrets
            client.secrets.create_secret(key("PERSONAL2"), "x", type="personal")
    finally:
        client.secrets.delete_secret(name)


def test_forced_v3_api(env: dict[str, str], folder: str) -> None:
    with core_client(env, api_version="v3") as c:
        s = c.secrets
        s.create_secret(key("V3"), "three", secret_path=folder)
        assert s.get_secret(key("V3"), secret_path=folder).value.reveal() == "three"
        s.update_secret(key("V3"), value="drei", secret_path=folder)
        assert [x.value.reveal() for x in s.list_secrets(secret_path=folder).secrets] == ["drei"]
        s.create_secrets([sdk.BatchCreateSecret(key("V3B"), "b")], secret_path=folder)
        s.update_secrets([sdk.BatchUpdateSecret(key("V3B"), value="bb")], secret_path=folder)
        s.delete_secrets([key("V3B")], secret_path=folder)
        s.delete_secret(key("V3"), secret_path=folder)
        assert c.api_version() == "v3"
        assert s.list_secrets(secret_path=folder).secrets == []


def test_async_secrets_round_trip(env: dict[str, str], folder: str) -> None:
    async def run() -> None:
        async with async_core_client(env) as c:
            await c.secrets.create_secret(key("ASYNC"), "a", secret_path=folder)
            got = await c.secrets.get_secret(key("ASYNC"), secret_path=folder)
            assert got.value.reveal() == "a"
            assert (await c.provider.get_string(f"{folder.strip('/')}/{key('ASYNC')}")) == "a"
            await c.secrets.delete_secret(key("ASYNC"), secret_path=folder)
            assert (await c.secrets.list_secrets(secret_path=folder)).secrets == []

    asyncio.run(run())


# --------------------------------------------------------------------------- resources


def test_folders_round_trip(client: sdk.InfisicalClient, folder: str) -> None:
    f = client.folders
    made = f.create_folder("child", path=folder, description="d")
    assert made.path == f"{folder}/child"
    with pytest.raises(sdk.ConflictError):
        f.create_folder("child", path=folder)
    updated = f.update_folder(made.id, name="renamed", path=folder)
    assert updated.name == "renamed"
    assert [x.name for x in f.list_folders(path=folder)] == ["renamed"]
    nested = f.list_folders(recursive=True)
    assert any(x.id == made.id for x in nested)
    assert f.delete_folder("renamed", path=folder).id == made.id
    assert f.list_folders(path=folder) == []


def test_projects_and_environments(env: dict[str, str], client: sdk.InfisicalClient) -> None:
    p = client.projects
    page = p.list_projects()
    assert env["INFISICAL_PROJECT_ID"] in [x.id for x in page.projects]
    assert page.total_count >= 1
    project = p.get_project()
    assert project.id == env["INFISICAL_PROJECT_ID"]
    assert p.get_project_by_slug(env["INFISICAL_PROJECT_SLUG"]).id == project.id
    slug = f"py-{RUN.lower()}"
    created = p.create_environment(f"Py {RUN}", slug)
    assert created.slug == slug
    assert slug in [e.slug for e in p.list_environments()]
    with pytest.raises(sdk.ConflictError):
        p.create_environment(f"Py {RUN}", slug)
    with pytest.raises(sdk.NotFoundError):
        p.get_project("00000000-0000-0000-0000-000000000000")


def test_tags_round_trip(client: sdk.InfisicalClient) -> None:
    t = client.tags
    tag = t.create_tag(f"tag-{RUN.lower()}")
    assert tag.slug in [x.slug for x in t.list_tags()]
    with pytest.raises(sdk.ConflictError):
        t.create_tag(tag.slug)
    assert t.delete_tag(tag.id).id == tag.id
    assert tag.slug not in [x.slug for x in t.list_tags()]


def test_provider_set_creates_folders_and_tags(client: sdk.InfisicalClient) -> None:
    base = f"py-prov-{RUN.lower()}"
    p = client.provider
    assert p.set(f"{base}/deep/KEY", "one", tags={f"prov-{RUN.lower()}": "#123456"}) == "1"
    assert p.set(f"{base}/deep/KEY", "two", description="d") == "2"
    meta = p.metadata(f"{base}/deep/KEY")
    assert meta is not None
    assert meta.version == "2"
    assert meta.path == f"/{base}/deep"
    assert p.get_string(f"{base}/deep/KEY", version="1") == "one"
    assert [m.name for m in p.list(f"{base}/deep")] == [f"{base}/deep/KEY"]
    p.delete(f"{base}/deep/KEY")
    assert p.get(f"{base}/deep/KEY") is None
    client.folders.delete_folder(base, force_delete=True)
    for tag in client.tags.list_tags():
        if tag.slug == f"prov-{RUN.lower()}":
            client.tags.delete_tag(tag.id)


def test_load_config_through_the_connector(
    env: dict[str, str], client: sdk.InfisicalClient
) -> None:
    """GRO-1410: ``load_config()`` with the default connector reads ``GROW_SECRETS_PATH``."""
    base = f"py-lc-{RUN.lower()}"
    client.provider.set(f"{base}/svc/DATABASE_URL", "postgres://db")
    client.provider.set(f"{base}/svc/LOG_LEVEL", "debug")
    # GROW_SECRETS_ADDR must win over GROW_INFISICAL_URL; credentials, project and environment
    # come from the package variables in the same environment (Universal Auth).
    target = {
        **env,
        "GROW_SECRETS_PROVIDER": "infisical",
        "GROW_SECRETS_ADDR": env["GROW_INFISICAL_URL"],
        "GROW_SECRETS_PATH": f"{base}/svc",
        "GROW_INFISICAL_URL": "http://127.0.0.1:1",
    }
    values = sdk.load_config(["DATABASE_URL"], env=target)
    assert values == {"DATABASE_URL": "postgres://db", "LOG_LEVEL": "debug"}
    assert target["DATABASE_URL"] == "postgres://db"
    client.folders.delete_folder(base, force_delete=True)
