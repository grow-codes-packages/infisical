"""SecretsProvider for Infisical (API.md "SecretsProvider mapping", DECISIONS #4), service-owned.

Names may contain ``/``: the last segment is the secret key, the rest is the folder below the
provider's base path (``grow-conformance/ab12/alpha`` → folder ``/grow-conformance/ab12``, key
``alpha``). ``set`` creates missing folders, resolves tag slugs (creating missing tags) and
returns the new version; delete is always permanent and removes every version.
"""

from __future__ import annotations

import builtins
import contextlib
import dataclasses
import re
from collections.abc import Mapping

from ._api import AsyncRunner, Op, Session, SyncRunner, join_path, normalize_path
from ._core import (
    ConflictError,
    NotFoundError,
    ResourceRegistry,
    UnsupportedError,
    ValidationError,
)
from ._secrets import (
    AsyncBaseSecretsProvider,
    BaseSecretsProvider,
    DeleteOptions,
    GetOptions,
    SecretMetadata,
    SecretValue,
    SetOptions,
)
from .models import InfisicalSecret
from .resources import DEFAULT_TAG_COLOR, create_folder_op, create_tag_op, list_tags_op
from .secrets import _SecretOps

__all__ = ["SecretLocation", "InfisicalSecretsProvider", "AsyncInfisicalSecretsProvider"]

_HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$")


@dataclasses.dataclass(frozen=True)
class SecretLocation:
    """Where a provider name lives: folder path and key."""

    secret_path: str
    key: str


class _ProviderCore(_SecretOps):
    """The five SPEC primitives (plus a one-call ``get_all``) as operations."""

    def __init__(
        self,
        session: Session,
        project_id: str | None,
        environment: str | None,
        base_path: str | None,
    ) -> None:
        self._session = session
        self.project_id = project_id
        self.environment = environment
        self.base_path = normalize_path(
            base_path if base_path is not None else session.config.secret_path
        )

    def locate(self, name: str, path: str | None = None) -> SecretLocation:
        base = self.base_path if path is None else join_path(self.base_path, path)
        if not isinstance(name, str) or not name.strip("/") or name.endswith("/"):
            raise ValidationError(f"secrets: invalid secret name {name!r}")
        full = join_path(base, name)
        cut = full.rfind("/")
        return SecretLocation(full[:cut] or "/", full[cut + 1 :])

    def name_of(self, secret_path: str, key: str) -> str:
        base = "" if self.base_path == "/" else self.base_path
        rel = secret_path[len(base) :] if secret_path.startswith(base) else secret_path
        folder = rel.strip("/")
        return f"{folder}/{key}" if folder else key

    def _folder(self, prefix_or_path: str | None) -> str:
        if prefix_or_path is None:
            return self.base_path
        return join_path(self.base_path, prefix_or_path)

    @staticmethod
    def _version(version: str | None) -> int | None:
        if version is None:
            return None
        try:
            number = int(version)
        except ValueError:
            number = 0
        if number < 1:
            raise ValidationError(f"secrets: version {version!r} is not a positive integer")
        return number

    def _metadata(self, s: InfisicalSecret) -> SecretMetadata:
        return SecretMetadata(
            name=self.name_of(s.secret_path, s.key),
            path=s.secret_path,
            version=str(s.version),
            created_at=s.created_at,
            updated_at=s.updated_at,
            tags={t.slug: t.slug for t in s.tags},
            versions=s.version,
            extra={"id": s.id, "comment": s.comment, "type": s.type},
        )

    def fetch_op(self, name: str, opts: GetOptions) -> Op[SecretValue | None]:
        loc = self.locate(name, opts.path)
        version = self._version(opts.version)
        try:
            s = yield from self._get_secret(
                loc.key,
                project_id=self.project_id,
                environment=self.environment,
                secret_path=loc.secret_path,
                version=version,
            )
        except NotFoundError:
            return None
        return SecretValue(s.value.reveal(), str(s.version))

    def metadata_op(self, name: str, opts: GetOptions) -> Op[SecretMetadata | None]:
        loc = self.locate(name, opts.path)
        version = self._version(opts.version)
        try:
            s = yield from self._get_secret(
                loc.key,
                project_id=self.project_id,
                environment=self.environment,
                secret_path=loc.secret_path,
                version=version,
                view_secret_value=False,
            )
        except NotFoundError:
            return None
        return self._metadata(s)

    def list_op(self, prefix_or_path: str | None) -> Op[builtins.list[SecretMetadata]]:
        try:
            listed = yield from self._list_secrets(
                project_id=self.project_id,
                environment=self.environment,
                secret_path=self._folder(prefix_or_path),
                recursive=False,
                include_imports=False,
                view_secret_value=False,
            )
        except NotFoundError:
            return []
        return [self._metadata(s) for s in listed.secrets]

    def get_all_op(self, path: str | None) -> Op[dict[str, SecretValue]]:
        folder = self._folder(path)
        try:
            listed = yield from self._list_secrets(
                project_id=self.project_id,
                environment=self.environment,
                secret_path=folder,
                recursive=False,
            )
        except NotFoundError:
            return {}
        out: dict[str, SecretValue] = {}
        for s in [*listed.secrets, *(x for imp in listed.imports for x in imp.secrets)]:
            name = self.name_of(folder, s.key)
            if s.key and name not in out:
                out[name] = SecretValue(s.value.reveal(), str(s.version))
        return dict(sorted(out.items()))

    def _tag_ids(self, tags: Mapping[str, str]) -> Op[builtins.list[str]]:
        if not tags:
            return []
        existing = {t.slug: t.id for t in (yield from list_tags_op(self._session, self.project_id))}
        ids: list[str] = []
        for slug, wanted in tags.items():
            tag_id = existing.get(slug)
            if tag_id is None:
                color = wanted if _HEX_COLOR.match(wanted or "") else DEFAULT_TAG_COLOR
                try:
                    tag_id = (
                        yield from create_tag_op(self._session, slug, color, self.project_id)
                    ).id
                except ConflictError:
                    again = yield from list_tags_op(self._session, self.project_id)
                    found = next((t.id for t in again if t.slug == slug), None)
                    if found is None:
                        raise
                    tag_id = found
            ids.append(tag_id)
        return ids

    def _ensure_folders(self, secret_path: str) -> Op[None]:
        parent = "/"
        for part in (p for p in secret_path.split("/") if p):
            with contextlib.suppress(ConflictError):
                yield from create_folder_op(
                    self._session, part, self.project_id, self.environment, parent, None
                )
            parent = join_path(parent, part)

    def put_op(self, name: str, data: bytes, opts: SetOptions) -> Op[str]:
        if opts.cas is not None:
            raise UnsupportedError(f"secrets.set {name}: Infisical has no compare-and-set")
        try:
            value = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValidationError(f"secrets.set {name}: Infisical stores UTF-8 text only") from None
        loc = self.locate(name, opts.path)
        tag_ids = None if opts.tags is None else (yield from self._tag_ids(opts.tags))
        pid, env, folder = self.project_id, self.environment, loc.secret_path

        def create() -> Op[InfisicalSecret]:
            return self._create_secret(
                loc.key,
                value,
                comment=opts.description,
                tag_ids=tag_ids,
                project_id=pid,
                environment=env,
                secret_path=folder,
            )

        try:
            try:
                created = yield from create()
            except NotFoundError as err:
                if "folder" not in err.message.lower():
                    raise
                yield from self._ensure_folders(folder)
                created = yield from create()
            return str(created.version)
        except ConflictError:
            updated = yield from self._update_secret(
                loc.key,
                value=value,
                comment=opts.description,
                tag_ids=tag_ids,
                project_id=pid,
                environment=env,
                secret_path=folder,
            )
            return str(updated.version)

    def remove_op(self, name: str, opts: DeleteOptions) -> Op[None]:
        if opts.versions:
            raise UnsupportedError(
                f"secrets.delete {name}: Infisical always deletes every version permanently"
            )
        loc = self.locate(name, opts.path)
        yield from self._delete_secret(
            loc.key,
            project_id=self.project_id,
            environment=self.environment,
            secret_path=loc.secret_path,
        )


class InfisicalSecretsProvider(BaseSecretsProvider):
    """The SPEC §3 ``SecretsProvider`` on top of Infisical (``client.provider`` or
    ``client.secrets_provider(...)``); the environment comes from the config unless given."""

    def __init__(
        self,
        runner: SyncRunner,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        base_path: str | None = None,
        owner: ResourceRegistry | None = None,
    ) -> None:
        super().__init__(owner=owner)
        self._runner = runner
        self._core = _ProviderCore(runner.session, project_id, environment, base_path)

    @property
    def base_path(self) -> str:
        """Base path every name is relative to."""
        return self._core.base_path

    def locate(self, name: str, path: str | None = None) -> SecretLocation:
        """Split a provider name into folder path and key."""
        return self._core.locate(name, path)

    def _fetch_secret(self, name: str, opts: GetOptions) -> SecretValue | None:
        return self._runner.run(self._core.fetch_op(name, opts))

    def _list_secrets(self, path: str | None) -> builtins.list[SecretMetadata]:
        return self._runner.run(self._core.list_op(path))

    def _put_secret(self, name: str, data: bytes, opts: SetOptions) -> str:
        return self._runner.run(self._core.put_op(name, data, opts))

    def _remove_secret(self, name: str, opts: DeleteOptions) -> None:
        self._runner.run(self._core.remove_op(name, opts))

    def _fetch_metadata(self, name: str, opts: GetOptions) -> SecretMetadata | None:
        return self._runner.run(self._core.metadata_op(name, opts))

    def get_all(self, path: str | None = None) -> dict[str, SecretValue]:
        """Every secret directly under ``path`` with one list call (imports per config)."""
        return self._runner.run(self._core.get_all_op(path))


class AsyncInfisicalSecretsProvider(AsyncBaseSecretsProvider):
    """Async :class:`InfisicalSecretsProvider`."""

    def __init__(
        self,
        runner: AsyncRunner,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        base_path: str | None = None,
        owner: ResourceRegistry | None = None,
    ) -> None:
        super().__init__(owner=owner)
        self._runner = runner
        self._core = _ProviderCore(runner.session, project_id, environment, base_path)

    @property
    def base_path(self) -> str:
        """Base path every name is relative to."""
        return self._core.base_path

    def locate(self, name: str, path: str | None = None) -> SecretLocation:
        """Split a provider name into folder path and key."""
        return self._core.locate(name, path)

    async def _fetch_secret(self, name: str, opts: GetOptions) -> SecretValue | None:
        return await self._runner.run(self._core.fetch_op(name, opts))

    async def _list_secrets(self, path: str | None) -> builtins.list[SecretMetadata]:
        return await self._runner.run(self._core.list_op(path))

    async def _put_secret(self, name: str, data: bytes, opts: SetOptions) -> str:
        return await self._runner.run(self._core.put_op(name, data, opts))

    async def _remove_secret(self, name: str, opts: DeleteOptions) -> None:
        await self._runner.run(self._core.remove_op(name, opts))

    async def _fetch_metadata(self, name: str, opts: GetOptions) -> SecretMetadata | None:
        return await self._runner.run(self._core.metadata_op(name, opts))

    async def get_all(self, path: str | None = None) -> dict[str, SecretValue]:
        """Every secret directly under ``path`` with one list call (imports per config)."""
        return await self._runner.run(self._core.get_all_op(path))
