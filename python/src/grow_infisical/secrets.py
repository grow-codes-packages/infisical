"""Infisical secrets API (API.md §3), service-owned: v4 ``/api/v4/secrets`` with the v3
``/api/v3/secrets/raw`` fallback, batch calls, versions, env injection and dotenv export."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from typing import Any

from ._api import (
    ApiVersion,
    AsyncModule,
    Call,
    Op,
    Session,
    SyncModule,
    arr,
    async_op,
    body_of,
    bounded_int,
    compact,
    fetch,
    field,
    opt_bool,
    require_text,
    secrets_call,
    seg,
    sync_op,
    wire_bool,
)
from ._core import ValidationError
from .models import (
    BatchCreateSecret,
    BatchDeleteSecret,
    BatchUpdateSecret,
    InfisicalSecret,
    SecretList,
    SecretType,
    SecretVersion,
    parse_secret,
    parse_secret_list,
    parse_secret_version,
)
from .resources import resolve_tag_ids

__all__ = ["Secrets", "AsyncSecrets", "dotenv_quote", "format_dotenv"]


def dotenv_quote(value: str) -> str:
    """Quote a value for a dotenv file: ``"…"`` with ``\\``, ``"``, LF and CR escaped."""
    escaped = (
        value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    )
    return f'"{escaped}"'


def format_dotenv(values: Mapping[str, str]) -> str:
    """Render ``key → value`` pairs as a dotenv document (``KEY="value"`` lines sorted by key)."""
    return "".join(f"{k}={dotenv_quote(values[k])}\n" for k in sorted(values))


def _wire_metadata(metadata: Mapping[str, str] | None) -> list[dict[str, str]] | None:
    if metadata is None:
        return None
    return [{"key": k, "value": metadata[k]} for k in sorted(metadata)]


def _project_key(version: ApiVersion) -> str:
    return "projectId" if version == "v4" else "workspaceId"


def _imports_key(version: ApiVersion) -> str:
    return "includeImports" if version == "v4" else "include_imports"


def _single(version: ApiVersion, name: str) -> str:
    if version == "v4":
        return f"/api/v4/secrets/{seg(name)}"
    return f"/api/v3/secrets/raw/{seg(name)}"


def _batch(version: ApiVersion) -> str:
    return "/api/v4/secrets/batch" if version == "v4" else "/api/v3/secrets/batch/raw"


def _secret_of(resp_body: Mapping[str, Any], op: str) -> InfisicalSecret:
    return parse_secret(field(resp_body, "secret", op))


def _secrets_of(resp_body: Mapping[str, Any]) -> list[InfisicalSecret]:
    return [parse_secret(s) for s in arr(resp_body.get("secrets"))]


class _Scope:
    def __init__(
        self,
        session: Session,
        op: str,
        project_id: str | None,
        environment: str | None,
        secret_path: str | None,
    ) -> None:
        self.project_id = session.project_id(project_id, op)
        self.environment = session.environment(environment, op)
        self.secret_path = session.path(secret_path)

    def body(self, version: ApiVersion) -> dict[str, Any]:
        return {
            _project_key(version): self.project_id,
            "environment": self.environment,
            "secretPath": self.secret_path,
        }


class _SecretOps:
    _session: Session

    def _call(self, build: Callable[[ApiVersion], Call]) -> Op[dict[str, Any]]:
        resp = yield from secrets_call(self._session, build)
        return body_of(resp, build("v4").operation)

    # ----------------------------------------------------------------- reads
    def _list_secrets(
        self,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
        recursive: bool = False,
        expand_references: bool | None = None,
        include_imports: bool | None = None,
        tag_slugs: Sequence[str] | None = None,
        view_secret_value: bool | None = None,
        include_personal_overrides: bool | None = None,
    ) -> Op[SecretList]:
        """List the secrets of a folder (``GET /api/v4/secrets``).

        References are expanded and imports included by default (``config``); on v3 every flag
        is sent explicitly. ``tag_slugs`` keeps secrets with these tags; ``view_secret_value=False``
        returns metadata only; ``include_personal_overrides`` replaces shared values by the
        caller's personal ones (user tokens).
        """
        op = "secrets.list"
        s = _Scope(self._session, op, project_id, environment, secret_path)
        cfg = self._session.config
        expand = cfg.expand_secret_references if expand_references is None else expand_references
        imports = cfg.include_imports if include_imports is None else include_imports

        def build(v: ApiVersion) -> Call:
            return Call(
                "GET",
                "/api/v4/secrets" if v == "v4" else "/api/v3/secrets/raw",
                f"{op} {s.secret_path}",
                params={
                    **s.body(v),
                    "recursive": wire_bool(recursive),
                    "expandSecretReferences": wire_bool(expand),
                    _imports_key(v): wire_bool(imports),
                    "tagSlugs": ",".join(tag_slugs) if tag_slugs else None,
                    "viewSecretValue": opt_bool(view_secret_value),
                    "includePersonalOverrides": opt_bool(include_personal_overrides),
                },
            )

        return parse_secret_list((yield from self._call(build)))

    def _get_secret(
        self,
        name: str,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
        version: int | None = None,
        type: SecretType | None = None,  # noqa: A002 - wire name, same in every language
        expand_references: bool | None = None,
        include_imports: bool | None = None,
        view_secret_value: bool | None = None,
    ) -> Op[InfisicalSecret]:
        """Read one secret (``GET /api/v4/secrets/{name}``); :class:`NotFoundError` when
        missing. ``version`` reads an older version; ``type="personal"`` the caller's override."""
        op = f"secrets.get {name}"
        require_text(name, "name", op)
        s = _Scope(self._session, op, project_id, environment, secret_path)
        if version is not None:
            bounded_int(version, "version", op, 1)
        cfg = self._session.config
        expand = cfg.expand_secret_references if expand_references is None else expand_references
        imports = cfg.include_imports if include_imports is None else include_imports

        def build(v: ApiVersion) -> Call:
            return Call(
                "GET",
                _single(v, name),
                op,
                params={
                    **s.body(v),
                    "version": version,
                    "type": type or "shared",
                    "expandSecretReferences": wire_bool(expand),
                    _imports_key(v): wire_bool(imports),
                    "viewSecretValue": opt_bool(view_secret_value),
                },
            )

        return _secret_of((yield from self._call(build)), op)

    # ----------------------------------------------------------------- writes
    def _create_secret(
        self,
        name: str,
        value: str,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
        comment: str | None = None,
        tag_ids: Sequence[str] | None = None,
        tag_slugs: Sequence[str] | None = None,
        type: SecretType | None = None,  # noqa: A002 - wire name, same in every language
        skip_multiline_encoding: bool | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> Op[InfisicalSecret]:
        """Create a secret (``POST /api/v4/secrets/{name}``).

        Folders are not created automatically (:class:`NotFoundError`); an existing key raises
        :class:`ConflictError`. The server trims the value. ``tag_slugs`` are resolved to ids
        (an unknown slug raises :class:`NotFoundError`).
        """
        op = f"secrets.create {name}"
        require_text(name, "name", op)
        if not isinstance(value, str):
            raise ValidationError(f"{op}: value must be a string")
        s = _Scope(self._session, op, project_id, environment, secret_path)
        ids = yield from resolve_tag_ids(self._session, op, s.project_id, tag_ids, tag_slugs)

        def build(v: ApiVersion) -> Call:
            return Call(
                "POST",
                _single(v, name),
                op,
                json=compact(
                    {
                        **s.body(v),
                        "secretValue": value,
                        "secretComment": comment,
                        "tagIds": ids,
                        "type": type,
                        "skipMultilineEncoding": skip_multiline_encoding,
                        "secretMetadata": _wire_metadata(metadata),
                    }
                ),
            )

        return _secret_of((yield from self._call(build)), op)

    def _update_secret(
        self,
        name: str,
        *,
        value: str | None = None,
        new_name: str | None = None,
        comment: str | None = None,
        tag_ids: Sequence[str] | None = None,
        tag_slugs: Sequence[str] | None = None,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
        type: SecretType | None = None,  # noqa: A002 - wire name, same in every language
        skip_multiline_encoding: bool | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> Op[InfisicalSecret]:
        """Update a secret (``PATCH /api/v4/secrets/{name}``): value, rename, comment, tags
        (``tag_ids``/``tag_slugs`` replace the set). Every update bumps the version; when no
        value is sent the returned value is empty."""
        op = f"secrets.update {name}"
        require_text(name, "name", op)
        if new_name is not None:
            require_text(new_name, "new_name", op)
        s = _Scope(self._session, op, project_id, environment, secret_path)
        ids = yield from resolve_tag_ids(self._session, op, s.project_id, tag_ids, tag_slugs)

        def build(v: ApiVersion) -> Call:
            return Call(
                "PATCH",
                _single(v, name),
                op,
                json=compact(
                    {
                        **s.body(v),
                        "secretValue": value,
                        "newSecretName": new_name,
                        "secretComment": comment,
                        "tagIds": ids,
                        "type": type,
                        "skipMultilineEncoding": skip_multiline_encoding,
                        "secretMetadata": _wire_metadata(metadata),
                    }
                ),
            )

        return _secret_of((yield from self._call(build)), op)

    def _delete_secret(
        self,
        name: str,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
        type: SecretType | None = None,  # noqa: A002 - wire name, same in every language
    ) -> Op[InfisicalSecret]:
        """Delete a secret with all its versions (``DELETE /api/v4/secrets/{name}``);
        :class:`NotFoundError` when missing."""
        op = f"secrets.delete {name}"
        require_text(name, "name", op)
        s = _Scope(self._session, op, project_id, environment, secret_path)

        def build(v: ApiVersion) -> Call:
            return Call("DELETE", _single(v, name), op, json=compact({**s.body(v), "type": type}))

        return _secret_of((yield from self._call(build)), op)

    def _batch_call(
        self, method: str, op: str, s: _Scope, extra: Mapping[str, Any]
    ) -> Op[list[InfisicalSecret]]:
        def build(v: ApiVersion) -> Call:
            return Call(method, _batch(v), op, json=compact({**s.body(v), **extra}))

        return _secrets_of((yield from self._call(build)))

    def _create_secrets(
        self,
        secrets: Sequence[BatchCreateSecret],
        *,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
    ) -> Op[list[InfisicalSecret]]:
        """Create several secrets atomically (``POST /api/v4/secrets/batch``); one duplicate
        fails the whole batch (:class:`ConflictError`). The result order is not guaranteed."""
        op = "secrets.create_many"
        if not secrets:
            return []
        s = _Scope(self._session, op, project_id, environment, secret_path)
        items = [
            compact(
                {
                    "secretKey": require_text(i.key, "key", op),
                    "secretValue": i.value,
                    "secretComment": i.comment,
                    "tagIds": i.tag_ids,
                    "skipMultilineEncoding": i.skip_multiline_encoding,
                    "secretMetadata": _wire_metadata(i.metadata),
                }
            )
            for i in secrets
        ]
        return (yield from self._batch_call("POST", op, s, {"secrets": items}))

    def _update_secrets(
        self,
        secrets: Sequence[BatchUpdateSecret],
        *,
        mode: str | None = None,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
    ) -> Op[list[InfisicalSecret]]:
        """Update several secrets (``PATCH /api/v4/secrets/batch``). ``mode``:
        ``failOnNotFound`` (server default), ``upsert`` (create missing) or ``ignore``."""
        op = "secrets.update_many"
        if mode is not None and mode not in ("failOnNotFound", "upsert", "ignore"):
            raise ValidationError(f"{op}: mode must be failOnNotFound, upsert or ignore")
        if not secrets:
            return []
        s = _Scope(self._session, op, project_id, environment, secret_path)
        items = [
            compact(
                {
                    "secretKey": require_text(i.key, "key", op),
                    "secretValue": i.value,
                    "newSecretName": i.new_name,
                    "secretComment": i.comment,
                    "tagIds": i.tag_ids,
                    "secretPath": None
                    if i.secret_path is None
                    else self._session.path(i.secret_path),
                    "skipMultilineEncoding": i.skip_multiline_encoding,
                    "secretMetadata": _wire_metadata(i.metadata),
                }
            )
            for i in secrets
        ]
        return (yield from self._batch_call("PATCH", op, s, {"mode": mode, "secrets": items}))

    def _delete_secrets(
        self,
        secrets: Sequence[str | BatchDeleteSecret],
        *,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
    ) -> Op[list[InfisicalSecret]]:
        """Delete several secrets atomically (``DELETE /api/v4/secrets/batch``); one missing key
        fails the whole batch (:class:`NotFoundError`)."""
        op = "secrets.delete_many"
        if not secrets:
            return []
        s = _Scope(self._session, op, project_id, environment, secret_path)
        items = [
            {"secretKey": require_text(i, "key", op)}
            if isinstance(i, str)
            else compact({"secretKey": require_text(i.key, "key", op), "type": i.type})
            for i in secrets
        ]
        return (yield from self._batch_call("DELETE", op, s, {"secrets": items}))

    def _list_secret_versions(
        self, secret_id: str, *, offset: int = 0, limit: int = 20
    ) -> Op[list[SecretVersion]]:
        """The versions of a secret, newest first (``GET /api/v1/secret/{id}/secret-versions``).

        The route accepts **user tokens only**; machine identities get
        :class:`PermissionDeniedError` (DECISIONS #3). ``limit`` is 1-1000.
        """
        op = f"secrets.versions {secret_id}"
        require_text(secret_id, "secret_id", op)
        bounded_int(offset, "offset", op, 0)
        bounded_int(limit, "limit", op, 1, 1000)
        doc = yield from fetch(
            Call(
                "GET",
                f"/api/v1/secret/{seg(secret_id)}/secret-versions",
                op,
                params={"offset": offset, "limit": limit},
            )
        )
        return [parse_secret_version(v) for v in arr(doc.get("secretVersions"))]

    # ----------------------------------------------------------------- env
    def _values(
        self,
        project_id: str | None,
        environment: str | None,
        secret_path: str | None,
        recursive: bool,
        include_imports: bool | None,
        expand_references: bool | None,
    ) -> Op[dict[str, str]]:
        listed = yield from self._list_secrets(
            project_id=project_id,
            environment=environment,
            secret_path=secret_path,
            recursive=recursive,
            include_imports=include_imports,
            expand_references=expand_references,
        )
        base = self._session.path(secret_path)
        direct = [x for x in listed.secrets if x.secret_path == base]
        nested = sorted(
            (x for x in listed.secrets if x.secret_path != base),
            key=lambda x: x.secret_path.count("/"),
        )
        imported = [x for imp in listed.imports for x in imp.secrets]
        values: dict[str, str] = {}
        for item in [*direct, *nested, *imported]:
            if item.key and item.key not in values:
                values[item.key] = item.value.reveal()
        return values

    def _load_env(
        self,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
        recursive: bool = False,
        include_imports: bool | None = None,
        expand_references: bool | None = None,
        override: bool = False,
        environ: MutableMapping[str, str] | None = None,
    ) -> Op[dict[str, str]]:
        """Set environment variables (default :data:`os.environ`) from the secrets of a folder,
        like ``infisical run``; the key is the variable name.

        Direct secrets win over sub-folders (``recursive``, shallower first) and imports.
        Existing variables are kept unless ``override``. Returns ``{name: key}`` for the
        variables that were set (never values).
        """
        values = yield from self._values(
            project_id, environment, secret_path, recursive, include_imports, expand_references
        )
        target: MutableMapping[str, str] = os.environ if environ is None else environ
        result: dict[str, str] = {}
        for key in sorted(values):
            if not override and key in target:
                continue
            target[key] = values[key]
            result[key] = key
        return result

    def _export_dotenv(
        self,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        secret_path: str | None = None,
        recursive: bool = False,
        include_imports: bool | None = None,
        expand_references: bool | None = None,
    ) -> Op[str]:
        """Render the secrets of a folder as a dotenv document (``KEY="value"`` lines sorted by
        key; see :func:`format_dotenv`). The result contains secret values."""
        values = yield from self._values(
            project_id, environment, secret_path, recursive, include_imports, expand_references
        )
        return format_dotenv(values)


class Secrets(SyncModule, _SecretOps):
    """Secrets of a project environment (``client.secrets``)."""

    list_secrets = sync_op(_SecretOps._list_secrets)
    get_secret = sync_op(_SecretOps._get_secret)
    create_secret = sync_op(_SecretOps._create_secret)
    update_secret = sync_op(_SecretOps._update_secret)
    delete_secret = sync_op(_SecretOps._delete_secret)
    create_secrets = sync_op(_SecretOps._create_secrets)
    update_secrets = sync_op(_SecretOps._update_secrets)
    delete_secrets = sync_op(_SecretOps._delete_secrets)
    list_secret_versions = sync_op(_SecretOps._list_secret_versions)
    load_env = sync_op(_SecretOps._load_env)
    export_dotenv = sync_op(_SecretOps._export_dotenv)


class AsyncSecrets(AsyncModule, _SecretOps):
    """Async :class:`Secrets`."""

    list_secrets = async_op(_SecretOps._list_secrets)
    get_secret = async_op(_SecretOps._get_secret)
    create_secret = async_op(_SecretOps._create_secret)
    update_secret = async_op(_SecretOps._update_secret)
    delete_secret = async_op(_SecretOps._delete_secret)
    create_secrets = async_op(_SecretOps._create_secrets)
    update_secrets = async_op(_SecretOps._update_secrets)
    delete_secrets = async_op(_SecretOps._delete_secrets)
    list_secret_versions = async_op(_SecretOps._list_secret_versions)
    load_env = async_op(_SecretOps._load_env)
    export_dotenv = async_op(_SecretOps._export_dotenv)
