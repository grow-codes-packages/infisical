"""Infisical folders (v2), projects + environments (v1), tags (v1) and secret imports (v2) —
API.md §5-§7 (service-owned)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from ._api import (
    AsyncModule,
    Call,
    Op,
    Session,
    SyncModule,
    arr,
    async_op,
    bounded_int,
    compact,
    fetch,
    field,
    integer,
    normalize_path,
    require_text,
    seg,
    sync_op,
)
from ._core import NotFoundError, ValidationError
from .models import (
    Environment,
    Folder,
    Project,
    ProjectList,
    SecretImport,
    Tag,
    parse_environment,
    parse_folder,
    parse_project,
    parse_secret_import,
    parse_tag,
)

__all__ = [
    "DEFAULT_TAG_COLOR",
    "Folders",
    "AsyncFolders",
    "Projects",
    "AsyncProjects",
    "Tags",
    "AsyncTags",
    "Imports",
    "AsyncImports",
]

#: Default color of tags created by the SDK.
DEFAULT_TAG_COLOR = "#888888"

_FOLDER_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def _folder_name(name: Any, op: str) -> str:
    require_text(name, "name", op)
    if not _FOLDER_NAME.match(name):
        raise ValidationError(f"{op}: folder names may contain only letters, digits, - and _")
    return str(name)


def _folder_scope(
    session: Session, op: str, project_id: str | None, environment: str | None, path: str | None
) -> dict[str, str]:
    return {
        "projectId": session.project_id(project_id, op),
        "environment": session.environment(environment, op),
        "path": normalize_path(path),
    }


# --------------------------------------------------------------------------- shared ops


def list_tags_op(session: Session, project_id: str | None) -> Op[list[Tag]]:
    """``GET /api/v1/projects/{id}/tags``."""
    op = "tags.list"
    pid = session.project_id(project_id, op)
    doc = yield from fetch(Call("GET", f"/api/v1/projects/{seg(pid)}/tags", op))
    return [parse_tag(t) for t in arr(doc.get("tags"))]


def create_tag_op(session: Session, slug: str, color: str, project_id: str | None) -> Op[Tag]:
    """``POST /api/v1/projects/{id}/tags``."""
    op = f"tags.create {slug}"
    require_text(slug, "slug", op)
    require_text(color, "color", op)
    pid = session.project_id(project_id, op)
    doc = yield from fetch(
        Call("POST", f"/api/v1/projects/{seg(pid)}/tags", op, json={"slug": slug, "color": color})
    )
    return parse_tag(field(doc, "tag", op))


def create_folder_op(
    session: Session,
    name: str,
    project_id: str | None,
    environment: str | None,
    path: str | None,
    description: str | None,
) -> Op[Folder]:
    """``POST /api/v2/folders``."""
    op = f"folders.create {name}"
    _folder_name(name, op)
    scope = _folder_scope(session, op, project_id, environment, path)
    doc = yield from fetch(
        Call(
            "POST",
            "/api/v2/folders",
            op,
            json=compact({**scope, "name": name, "description": description}),
        )
    )
    return parse_folder(field(doc, "folder", op))


def resolve_tag_ids(
    session: Session,
    op: str,
    project_id: str | None,
    ids: Sequence[str] | None,
    slugs: Sequence[str] | None,
) -> Op[list[str] | None]:
    """Merge tag ids with the ids of tag slugs (``None`` when both are ``None``).

    An unknown slug raises :class:`NotFoundError`.
    """
    if ids is None and slugs is None:
        return None
    out = list(ids or [])
    if not slugs:
        return out
    by_slug = {t.slug: t.id for t in (yield from list_tags_op(session, project_id))}
    for slug in slugs:
        if slug not in by_slug:
            raise NotFoundError(f"{op}: tag {slug} does not exist")
        out.append(by_slug[slug])
    return out


# --------------------------------------------------------------------------- folders


class _FolderOps:
    _session: Session

    def _list_folders(
        self,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        path: str | None = None,
        recursive: bool = False,
    ) -> Op[list[Folder]]:
        """List the folders under ``path`` (``GET /api/v2/folders``); ``recursive`` includes
        nested folders (each with ``relative_path``)."""
        op = "folders.list"
        scope = _folder_scope(self._session, op, project_id, environment, path)
        doc = yield from fetch(
            Call(
                "GET",
                "/api/v2/folders",
                f"{op} {scope['path']}",
                params={**scope, "recursive": "true" if recursive else None},
            )
        )
        return [parse_folder(f) for f in arr(doc.get("folders"))]

    def _create_folder(
        self,
        name: str,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        path: str | None = None,
        description: str | None = None,
    ) -> Op[Folder]:
        """Create folder ``name`` under ``path`` (``POST /api/v2/folders``); an existing
        folder raises :class:`ConflictError`."""
        return (
            yield from create_folder_op(
                self._session, name, project_id, environment, path, description
            )
        )

    def _update_folder(
        self,
        folder_id: str,
        *,
        name: str,
        project_id: str | None = None,
        environment: str | None = None,
        path: str | None = None,
        description: str | None = None,
    ) -> Op[Folder]:
        """Rename a folder / change its description (``PATCH /api/v2/folders/{id}``); ``path``
        is the parent path."""
        op = f"folders.update {folder_id}"
        require_text(folder_id, "folder_id", op)
        _folder_name(name, op)
        scope = _folder_scope(self._session, op, project_id, environment, path)
        doc = yield from fetch(
            Call(
                "PATCH",
                f"/api/v2/folders/{seg(folder_id)}",
                op,
                json=compact({**scope, "name": name, "description": description}),
            )
        )
        return parse_folder(field(doc, "folder", op))

    def _delete_folder(
        self,
        folder_id_or_name: str,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        path: str | None = None,
        force_delete: bool | None = None,
    ) -> Op[Folder]:
        """Delete a folder by id or name under ``path`` (``DELETE /api/v2/folders/{idOrName}``)."""
        op = f"folders.delete {folder_id_or_name}"
        require_text(folder_id_or_name, "folder_id_or_name", op)
        scope = _folder_scope(self._session, op, project_id, environment, path)
        doc = yield from fetch(
            Call(
                "DELETE",
                f"/api/v2/folders/{seg(folder_id_or_name)}",
                op,
                json=compact({**scope, "forceDelete": force_delete}),
            )
        )
        return parse_folder(field(doc, "folder", op))


class Folders(SyncModule, _FolderOps):
    """Folders of a project environment (``client.folders``)."""

    list_folders = sync_op(_FolderOps._list_folders)
    create_folder = sync_op(_FolderOps._create_folder)
    update_folder = sync_op(_FolderOps._update_folder)
    delete_folder = sync_op(_FolderOps._delete_folder)


class AsyncFolders(AsyncModule, _FolderOps):
    """Async :class:`Folders`."""

    list_folders = async_op(_FolderOps._list_folders)
    create_folder = async_op(_FolderOps._create_folder)
    update_folder = async_op(_FolderOps._update_folder)
    delete_folder = async_op(_FolderOps._delete_folder)


# --------------------------------------------------------------------------- projects


class _ProjectOps:
    _session: Session

    def _list_projects(
        self,
        *,
        type: str = "secret-manager",  # noqa: A002 - wire name, same in every language
        limit: int = 100,
        offset: int = 0,
    ) -> Op[ProjectList]:
        """List the projects the caller is a member of (``GET /api/v1/projects``)."""
        op = "projects.list"
        bounded_int(limit, "limit", op, 1, 100)
        bounded_int(offset, "offset", op, 0)
        doc = yield from fetch(
            Call(
                "GET",
                "/api/v1/projects",
                op,
                params={"type": type, "limit": limit, "offset": offset},
            )
        )
        projects = [parse_project(p) for p in arr(doc.get("projects"))]
        return ProjectList(projects, integer(doc.get("totalCount"), len(projects)))

    def _get_project(self, project_id: str | None = None) -> Op[Project]:
        """Read a project by id (``GET /api/v1/projects/{id}``, default ``config.project_id``)."""
        op = "projects.get"
        pid = self._session.project_id(project_id, op)
        doc = yield from fetch(Call("GET", f"/api/v1/projects/{seg(pid)}", f"{op} {pid}"))
        return parse_project(field(doc, "project", op))

    def _get_project_by_slug(self, slug: str) -> Op[Project]:
        """Read a project by slug (``GET /api/v1/projects/slug/{slug}``)."""
        op = f"projects.get_by_slug {slug}"
        require_text(slug, "slug", op)
        doc = yield from fetch(Call("GET", f"/api/v1/projects/slug/{seg(slug)}", op))
        return parse_project(doc)

    def _list_environments(self, project_id: str | None = None) -> Op[list[Environment]]:
        """The environments of a project in display order (from ``get_project``)."""
        return (yield from self._get_project(project_id)).environments

    def _create_environment(
        self,
        name: str,
        slug: str,
        *,
        project_id: str | None = None,
        position: int | None = None,
    ) -> Op[Environment]:
        """Create an environment (project admin; ``POST /api/v1/projects/{id}/environments``)."""
        op = f"projects.create_environment {slug}"
        require_text(name, "name", op)
        require_text(slug, "slug", op)
        pid = self._session.project_id(project_id, op)
        doc = yield from fetch(
            Call(
                "POST",
                f"/api/v1/projects/{seg(pid)}/environments",
                op,
                json=compact({"name": name, "slug": slug, "position": position}),
            )
        )
        return parse_environment(field(doc, "environment", op))


class Projects(SyncModule, _ProjectOps):
    """Projects and environments (``client.projects``)."""

    list_projects = sync_op(_ProjectOps._list_projects)
    get_project = sync_op(_ProjectOps._get_project)
    get_project_by_slug = sync_op(_ProjectOps._get_project_by_slug)
    list_environments = sync_op(_ProjectOps._list_environments)
    create_environment = sync_op(_ProjectOps._create_environment)


class AsyncProjects(AsyncModule, _ProjectOps):
    """Async :class:`Projects`."""

    list_projects = async_op(_ProjectOps._list_projects)
    get_project = async_op(_ProjectOps._get_project)
    get_project_by_slug = async_op(_ProjectOps._get_project_by_slug)
    list_environments = async_op(_ProjectOps._list_environments)
    create_environment = async_op(_ProjectOps._create_environment)


# --------------------------------------------------------------------------- tags


class _TagOps:
    _session: Session

    def _list_tags(self, *, project_id: str | None = None) -> Op[list[Tag]]:
        """List the tags of a project (``GET /api/v1/projects/{id}/tags``)."""
        return (yield from list_tags_op(self._session, project_id))

    def _create_tag(
        self, slug: str, color: str = DEFAULT_TAG_COLOR, *, project_id: str | None = None
    ) -> Op[Tag]:
        """Create a tag (``POST /api/v1/projects/{id}/tags``); :class:`ConflictError` when the
        slug exists."""
        return (yield from create_tag_op(self._session, slug, color, project_id))

    def _delete_tag(self, tag_id: str, *, project_id: str | None = None) -> Op[Tag]:
        """Delete a tag by id (``DELETE /api/v1/projects/{id}/tags/{tagId}``)."""
        op = f"tags.delete {tag_id}"
        require_text(tag_id, "tag_id", op)
        pid = self._session.project_id(project_id, op)
        doc = yield from fetch(
            Call("DELETE", f"/api/v1/projects/{seg(pid)}/tags/{seg(tag_id)}", op)
        )
        return parse_tag(field(doc, "tag", op))


class Tags(SyncModule, _TagOps):
    """Tags of a project (``client.tags``)."""

    list_tags = sync_op(_TagOps._list_tags)
    create_tag = sync_op(_TagOps._create_tag)
    delete_tag = sync_op(_TagOps._delete_tag)


class AsyncTags(AsyncModule, _TagOps):
    """Async :class:`Tags`."""

    list_tags = async_op(_TagOps._list_tags)
    create_tag = async_op(_TagOps._create_tag)
    delete_tag = async_op(_TagOps._delete_tag)


# --------------------------------------------------------------------------- imports


class _ImportOps:
    _session: Session

    def _list_secret_imports(
        self,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        path: str | None = None,
    ) -> Op[list[SecretImport]]:
        """List the imports of a folder (``GET /api/v2/secret-imports``)."""
        op = "imports.list"
        scope = _folder_scope(self._session, op, project_id, environment, path)
        doc = yield from fetch(
            Call("GET", "/api/v2/secret-imports", f"{op} {scope['path']}", params=scope)
        )
        return [parse_secret_import(i) for i in arr(doc.get("secretImports"))]

    def _create_secret_import(
        self,
        *,
        import_environment: str,
        import_path: str | None = None,
        project_id: str | None = None,
        environment: str | None = None,
        path: str | None = None,
        is_replication: bool | None = None,
        source_project_id: str | None = None,
    ) -> Op[SecretImport]:
        """Import the secrets of ``import_environment``/``import_path`` into a folder
        (``POST /api/v2/secret-imports``). The server accepts duplicates and missing sources."""
        op = "imports.create"
        require_text(import_environment, "import_environment", op)
        scope = _folder_scope(self._session, op, project_id, environment, path)
        source = compact(
            {
                "environment": import_environment,
                "path": normalize_path(import_path),
                "sourceProjectId": source_project_id,
            }
        )
        doc = yield from fetch(
            Call(
                "POST",
                "/api/v2/secret-imports",
                op,
                json=compact({**scope, "import": source, "isReplication": is_replication}),
            )
        )
        return parse_secret_import(field(doc, "secretImport", op))

    def _delete_secret_import(
        self,
        import_id: str,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        path: str | None = None,
    ) -> Op[SecretImport]:
        """Delete an import by id (``DELETE /api/v2/secret-imports/{id}``)."""
        op = f"imports.delete {import_id}"
        require_text(import_id, "import_id", op)
        scope = _folder_scope(self._session, op, project_id, environment, path)
        doc = yield from fetch(
            Call("DELETE", f"/api/v2/secret-imports/{seg(import_id)}", op, json=scope)
        )
        return parse_secret_import(field(doc, "secretImport", op))


class Imports(SyncModule, _ImportOps):
    """Secret imports of a folder (``client.imports``)."""

    list_secret_imports = sync_op(_ImportOps._list_secret_imports)
    create_secret_import = sync_op(_ImportOps._create_secret_import)
    delete_secret_import = sync_op(_ImportOps._delete_secret_import)


class AsyncImports(AsyncModule, _ImportOps):
    """Async :class:`Imports`."""

    list_secret_imports = async_op(_ImportOps._list_secret_imports)
    create_secret_import = async_op(_ImportOps._create_secret_import)
    delete_secret_import = async_op(_ImportOps._delete_secret_import)
