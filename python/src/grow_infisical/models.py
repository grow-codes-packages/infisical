"""Typed Infisical models and their wire (JSON) parsers (service-owned).

Every model is a frozen dataclass; secret values are :class:`~grow_infisical.SecretValue`
(redacting ``repr``). Timestamps are timezone-aware UTC datetimes.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
from collections.abc import Mapping
from typing import Any, Literal

from ._api import arr, integer, obj, opt_text, parse_time, text
from ._secrets import SecretValue

__all__ = [
    "SecretType",
    "Tag",
    "InfisicalSecret",
    "ImportedSecrets",
    "SecretList",
    "SecretActor",
    "SecretVersion",
    "Folder",
    "Environment",
    "Project",
    "ProjectList",
    "SecretImport",
    "BatchCreateSecret",
    "BatchUpdateSecret",
    "BatchDeleteSecret",
]

SecretType = Literal["shared", "personal"]
"""``shared`` (default) or the caller's ``personal`` override (user tokens only)."""


@dataclasses.dataclass(frozen=True)
class Tag:
    """A tag of a project or attached to a secret."""

    id: str
    slug: str
    #: Display name (secrets only; usually the slug).
    name: str | None = None
    color: str | None = None
    project_id: str | None = None
    created_at: _dt.datetime | None = None
    updated_at: _dt.datetime | None = None


@dataclasses.dataclass(frozen=True)
class InfisicalSecret:
    """One secret as returned by the secrets API (``repr`` never shows the value)."""

    id: str
    #: Secret key (name).
    key: str
    #: Value; empty when hidden or when an update did not send a value.
    value: SecretValue
    #: True when the server hid the value (``view_secret_value=False`` or missing permission).
    value_hidden: bool
    version: int
    type: SecretType
    environment: str
    secret_path: str
    comment: str
    tags: list[Tag] = dataclasses.field(default_factory=list)
    metadata: dict[str, str] = dataclasses.field(default_factory=dict)
    skip_multiline_encoding: bool = False
    created_at: _dt.datetime | None = None
    updated_at: _dt.datetime | None = None


@dataclasses.dataclass(frozen=True)
class ImportedSecrets:
    """Secrets reached through one secret import."""

    environment: str
    secret_path: str
    secrets: list[InfisicalSecret]
    folder_id: str | None = None


@dataclasses.dataclass(frozen=True)
class SecretList:
    """Result of ``list_secrets``."""

    secrets: list[InfisicalSecret]
    #: Imported secrets in import priority order (empty unless imports were included).
    imports: list[ImportedSecrets] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class SecretActor:
    """Who wrote a secret version."""

    actor_id: str | None = None
    actor_type: str | None = None
    name: str | None = None


@dataclasses.dataclass(frozen=True)
class SecretVersion:
    """One historical version of a secret."""

    #: Version row id.
    id: str
    version: int
    key: str
    value: SecretValue
    value_hidden: bool
    comment: str
    type: SecretType
    environment: str
    created_at: _dt.datetime | None = None
    actor: SecretActor | None = None


@dataclasses.dataclass(frozen=True)
class Folder:
    """A folder."""

    id: str
    name: str
    version: int
    description: str | None = None
    parent_id: str | None = None
    env_id: str | None = None
    #: Full path of the folder (create/update responses).
    path: str | None = None
    #: Path relative to the listed path (recursive lists).
    relative_path: str | None = None
    created_at: _dt.datetime | None = None
    updated_at: _dt.datetime | None = None


@dataclasses.dataclass(frozen=True)
class Environment:
    """An environment of a project."""

    id: str
    name: str
    slug: str
    position: int | None = None
    project_id: str | None = None


@dataclasses.dataclass(frozen=True)
class Project:
    """A project."""

    id: str
    name: str
    slug: str
    type: str
    org_id: str
    environments: list[Environment] = dataclasses.field(default_factory=list)
    description: str | None = None
    created_at: _dt.datetime | None = None
    updated_at: _dt.datetime | None = None


@dataclasses.dataclass(frozen=True)
class ProjectList:
    """A page of projects."""

    projects: list[Project]
    total_count: int


@dataclasses.dataclass(frozen=True)
class SecretImport:
    """A secret import (secrets of another environment/path visible in a folder)."""

    id: str
    #: Source path.
    import_path: str
    #: Source environment.
    import_environment: Environment
    position: int
    is_replication: bool
    source_project_name: str | None = None
    created_at: _dt.datetime | None = None
    updated_at: _dt.datetime | None = None


@dataclasses.dataclass(frozen=True)
class BatchCreateSecret:
    """One secret of ``create_secrets``."""

    key: str
    value: str = dataclasses.field(repr=False)
    comment: str | None = None
    tag_ids: list[str] | None = None
    skip_multiline_encoding: bool | None = None
    metadata: Mapping[str, str] | None = None


@dataclasses.dataclass(frozen=True)
class BatchUpdateSecret:
    """One secret of ``update_secrets``: only the given fields change."""

    key: str
    value: str | None = dataclasses.field(default=None, repr=False)
    new_name: str | None = None
    comment: str | None = None
    tag_ids: list[str] | None = None
    #: Folder of this secret (default: the call's ``secret_path``).
    secret_path: str | None = None
    skip_multiline_encoding: bool | None = None
    metadata: Mapping[str, str] | None = None


@dataclasses.dataclass(frozen=True)
class BatchDeleteSecret:
    """One secret of ``delete_secrets`` (a plain key string is accepted too)."""

    key: str
    type: SecretType | None = None


# --------------------------------------------------------------------------- parsers


def _secret_type(value: Any) -> SecretType:
    return "personal" if value == "personal" else "shared"


def parse_tag(raw: Any) -> Tag:
    r = obj(raw)
    return Tag(
        id=text(r.get("id")),
        slug=text(r.get("slug")),
        name=opt_text(r.get("name")),
        color=opt_text(r.get("color")),
        project_id=opt_text(r.get("projectId")),
        created_at=parse_time(r.get("createdAt")),
        updated_at=parse_time(r.get("updatedAt")),
    )


def parse_secret(raw: Any) -> InfisicalSecret:
    r = obj(raw)
    version = integer(r.get("version"), 1)
    metadata = {}
    for entry in arr(r.get("secretMetadata")):
        e = obj(entry)
        if isinstance(e.get("key"), str):
            metadata[e["key"]] = text(e.get("value"))
    return InfisicalSecret(
        id=text(r.get("id")),
        key=text(r.get("secretKey")),
        value=SecretValue(text(r.get("secretValue")), str(version)),
        value_hidden=r.get("secretValueHidden") is True,
        version=version,
        type=_secret_type(r.get("type")),
        environment=text(r.get("environment")),
        secret_path=text(r.get("secretPath")) or "/",
        comment=text(r.get("secretComment")),
        tags=[parse_tag(t) for t in arr(r.get("tags"))],
        metadata=metadata,
        skip_multiline_encoding=r.get("skipMultilineEncoding") is True,
        created_at=parse_time(r.get("createdAt")),
        updated_at=parse_time(r.get("updatedAt")),
    )


def parse_secret_list(raw: Any) -> SecretList:
    r = obj(raw)
    imports = []
    for item in arr(r.get("imports")):
        imp = obj(item)
        imports.append(
            ImportedSecrets(
                environment=text(imp.get("environment")),
                secret_path=text(imp.get("secretPath")),
                secrets=[parse_secret(s) for s in arr(imp.get("secrets"))],
                folder_id=opt_text(imp.get("folderId")),
            )
        )
    return SecretList([parse_secret(s) for s in arr(r.get("secrets"))], imports)


def parse_secret_version(raw: Any) -> SecretVersion:
    r = obj(raw)
    version = integer(r.get("version"), 1)
    actor = None
    if isinstance(r.get("actor"), dict):
        a = r["actor"]
        actor = SecretActor(
            opt_text(a.get("actorId")), opt_text(a.get("actorType")), opt_text(a.get("name"))
        )
    return SecretVersion(
        id=text(r.get("id")),
        version=version,
        key=text(r.get("secretKey")),
        value=SecretValue(text(r.get("secretValue")), str(version)),
        value_hidden=r.get("secretValueHidden") is True,
        comment=text(r.get("secretComment")),
        type=_secret_type(r.get("type")),
        environment=text(r.get("environment")),
        created_at=parse_time(r.get("createdAt")),
        actor=actor,
    )


def parse_folder(raw: Any) -> Folder:
    r = obj(raw)
    return Folder(
        id=text(r.get("id")),
        name=text(r.get("name")),
        version=integer(r.get("version"), 1),
        description=opt_text(r.get("description")),
        parent_id=opt_text(r.get("parentId")),
        env_id=opt_text(r.get("envId")),
        path=opt_text(r.get("path")),
        relative_path=opt_text(r.get("relativePath")),
        created_at=parse_time(r.get("createdAt")),
        updated_at=parse_time(r.get("updatedAt")),
    )


def parse_environment(raw: Any) -> Environment:
    r = obj(raw)
    position = r.get("position")
    return Environment(
        id=text(r.get("id")),
        name=text(r.get("name")),
        slug=text(r.get("slug")),
        position=integer(position) if isinstance(position, (int, float)) else None,
        project_id=opt_text(r.get("projectId")),
    )


def parse_project(raw: Any) -> Project:
    r = obj(raw)
    return Project(
        id=text(r.get("id")),
        name=text(r.get("name")),
        slug=text(r.get("slug")),
        type=text(r.get("type")),
        org_id=text(r.get("orgId")),
        environments=[parse_environment(e) for e in arr(r.get("environments"))],
        description=opt_text(r.get("description")),
        created_at=parse_time(r.get("createdAt")),
        updated_at=parse_time(r.get("updatedAt")),
    )


def parse_secret_import(raw: Any) -> SecretImport:
    r = obj(raw)
    return SecretImport(
        id=text(r.get("id")),
        import_path=text(r.get("importPath")),
        import_environment=parse_environment(r.get("importEnv")),
        position=integer(r.get("position")),
        is_replication=r.get("isReplication") is True,
        source_project_name=opt_text(r.get("sourceProjectName")),
        created_at=parse_time(r.get("createdAt")),
        updated_at=parse_time(r.get("updatedAt")),
    )
