"""Infisical clients (sync and async), service-owned.

>>> client = InfisicalClient.from_env()                              # doctest: +SKIP
>>> client.secrets.create_secret("API_KEY", "s3cret")                # doctest: +SKIP
>>> client.secrets.get_secret("API_KEY").value.reveal()              # doctest: +SKIP
>>> client.provider.get_string("app/DB_PASSWORD")                    # doctest: +SKIP
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Iterator, Mapping
from types import TracebackType
from typing import Any

import httpx

from ._api import AsyncRunner, Call, Op, Session, SyncRunner, body_of, cancel_scope
from ._core import (
    AsyncHttpTransport,
    CancelledError,
    CancelToken,
    ConfigError,
    HealthStatus,
    HttpTransport,
    Request,
    ResourceRegistry,
    Response,
    ServiceError,
    TimeoutError,
    UnavailableError,
    UnsupportedError,
)
from .auth import InfisicalAuth, TokenAuth, UniversalAuth
from .config import InfisicalConfig
from .provider import AsyncInfisicalSecretsProvider, InfisicalSecretsProvider
from .resources import (
    AsyncFolders,
    AsyncImports,
    AsyncProjects,
    AsyncTags,
    Folders,
    Imports,
    Projects,
    Tags,
)
from .secrets import AsyncSecrets, Secrets

__all__ = ["InfisicalClient", "AsyncInfisicalClient", "PING_PATHS", "resolve_auth"]

#: Routes used by ``ping()`` per token kind.
PING_PATHS: Mapping[str, str] = {
    "identity": "/api/v1/identities/details",
    "user": "/api/v2/users/me",
    "service_token": "/api/v2/service-token",
}


def resolve_auth(config: InfisicalConfig) -> InfisicalAuth | None:
    """The auth method of a config: ``auth`` > ``token`` > ``client_id``/``client_secret``."""
    if config.auth is not None:
        return config.auth
    if config.token is not None:
        return TokenAuth(config.token)
    if config.client_id is not None and config.client_secret is not None:
        return UniversalAuth(config.client_id, config.client_secret)
    return None


def _health_op() -> Op[HealthStatus]:
    resp = yield Call("GET", "/api/status", "health", auth=False, max_retries=0)
    try:
        doc = body_of(resp, "health")
    except ServiceError:
        doc = {}
    word = doc.get("message")
    details: dict[str, str] = {}
    for key, value in doc.items():
        if key == "message":
            continue
        if isinstance(value, bool):
            details[key] = "true" if value else "false"
        elif isinstance(value, (str, int, float)):
            details[key] = str(value)
    status = word.lower() if isinstance(word, str) and word else "ok"
    return HealthStatus(healthy=True, status=status, details=details)


def _health_error(err: ServiceError) -> HealthStatus:
    if isinstance(err, (CancelledError, ConfigError)):
        raise err
    word = "unreachable" if isinstance(err, (UnavailableError, TimeoutError)) else "unhealthy"
    if err.http_status is not None:
        word = "unhealthy"
    details = {"error": err.message}
    if err.http_status is not None:
        details["httpStatus"] = str(err.http_status)
    return HealthStatus(healthy=False, status=word, details=details)


def _ping_call(session: Session) -> Call:
    kind = session.auth.token_kind if session.auth is not None else "identity"
    return Call("GET", PING_PATHS[kind], "ping")


def _unsupported_version() -> UnsupportedError:
    return UnsupportedError("server_version: Infisical does not report its version over HTTP")


class _ClientBase:
    config: InfisicalConfig
    _session: Session

    def _setup(self, config: InfisicalConfig | None, clock: Callable[[], float]) -> None:
        if config is None:
            config = InfisicalConfig.from_env()
        self.config = config.validate()
        self._session = Session(self.config, resolve_auth(self.config), clock)
        self._resources = ResourceRegistry()
        self._closed = False

    @property
    def auth(self) -> InfisicalAuth | None:
        """The active auth method (``None`` when no credentials are configured)."""
        return self._session.auth

    @property
    def closed(self) -> bool:
        """Whether :meth:`close` was called."""
        return self._closed

    @property
    def resources(self) -> ResourceRegistry:
        """Background resources (secret watchers) stopped by :meth:`close`."""
        return self._resources

    def api_version(self, resource: str = "secrets") -> str:
        """The secrets API version in use: ``v4``, ``v3`` or ``unknown`` before the first call."""
        if resource != "secrets":
            raise ValueError("api_version: only 'secrets' is version-detected")
        return self._session.secrets_version or "unknown"


class InfisicalClient(_ClientBase):
    """Synchronous Infisical client. Thread-safe; use as a context manager or call
    :meth:`close`.

    Modules: :attr:`secrets`, :attr:`folders`, :attr:`projects`, :attr:`tags`,
    :attr:`imports`, :attr:`provider` (the ``SecretsProvider``) and :attr:`auth`. Cancel calls
    from another thread with ``with client.cancellable(token): ...`` or the ``cancel=``
    argument of the core methods.
    """

    def __init__(
        self,
        config: InfisicalConfig | None = None,
        *,
        http_transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._setup(config, clock)
        self._transport = HttpTransport(
            self.config, known_secrets=self._session.known_secrets, http_transport=http_transport
        )
        self._runner = SyncRunner(self._transport, self._session)
        if self._session.auth is not None:
            self._session.auth._bind(self._runner)
        self.secrets = Secrets(self._runner)
        """Secrets: list/get/create/update/delete, batch, versions, ``load_env``,
        ``export_dotenv``."""
        self.folders = Folders(self._runner)
        """Folders: list/create/update/delete."""
        self.projects = Projects(self._runner)
        """Projects and environments."""
        self.tags = Tags(self._runner)
        """Tags."""
        self.imports = Imports(self._runner)
        """Secret imports."""
        self.provider = self.secrets_provider()
        """The SPEC ``SecretsProvider`` for the configured project/environment/path."""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> InfisicalClient:
        """Build a client from ``GROW_INFISICAL_*`` and ``INFISICAL_*`` variables."""
        return cls(InfisicalConfig.from_env(env, **overrides))

    def secrets_provider(
        self,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        base_path: str | None = None,
    ) -> InfisicalSecretsProvider:
        """A ``SecretsProvider`` for another project, environment or base path; its watchers are
        stopped by :meth:`close`."""
        return InfisicalSecretsProvider(
            self._runner,
            project_id=project_id,
            environment=environment,
            base_path=base_path,
            owner=self._resources,
        )

    @contextlib.contextmanager
    def cancellable(self, token: CancelToken) -> Iterator[CancelToken]:
        """Apply ``token`` to every call made by this thread inside the ``with`` block."""
        with cancel_scope(token):
            yield token

    def request(self, req: Request, *, cancel: CancelToken | None = None) -> Response:
        """Send a raw request through the transport (retries, hooks, redaction; no auth)."""
        return self._transport.request(req, cancel=cancel)

    def health(self, *, cancel: CancelToken | None = None) -> HealthStatus:
        """Unauthenticated liveness (``GET /api/status``); never raises for an unhealthy or
        unreachable service (only :class:`CancelledError` and :class:`ConfigError`)."""
        try:
            with cancel_scope(cancel):
                return self._runner.run(_health_op())
        except ServiceError as err:
            return _health_error(err)

    def ping(self, *, cancel: CancelToken | None = None) -> float:
        """Authenticated round trip; latency in ms. The route depends on the token kind
        (:data:`PING_PATHS`); bad credentials raise :class:`AuthenticationError`."""
        started = time.monotonic()
        with cancel_scope(cancel):
            self._runner.execute(_ping_call(self._session))
        return (time.monotonic() - started) * 1000.0

    def server_version(self, *, cancel: CancelToken | None = None) -> str:
        """Always :class:`UnsupportedError`: Infisical exposes no running version over HTTP."""
        raise _unsupported_version()

    def close(self) -> None:
        """Stop watchers, revoke a login token when ``revoke_on_close`` is set and release
        connections (idempotent)."""
        if self._closed:
            return
        self._closed = True
        self._resources.stop_all()
        auth = self._session.auth
        if auth is not None:
            self._runner.run(auth.close_op(self._session, self.config.revoke_on_close))
        self._transport.close()

    def __enter__(self) -> InfisicalClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"InfisicalClient(config={self.config!r})"


class AsyncInfisicalClient(_ClientBase):
    """Asynchronous Infisical client (same modules and methods, awaitable); use
    ``async with`` or call :meth:`aclose`.

    Cancel a call by cancelling its task: the SDK raises :class:`CancelledError`, which is also
    an :class:`asyncio.CancelledError`.
    """

    def __init__(
        self,
        config: InfisicalConfig | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._setup(config, clock)
        self._transport = AsyncHttpTransport(
            self.config, known_secrets=self._session.known_secrets, http_transport=http_transport
        )
        self._runner = AsyncRunner(self._transport, self._session)
        if self._session.auth is not None:
            self._session.auth._bind(self._runner)
        self.secrets = AsyncSecrets(self._runner)
        """See :attr:`InfisicalClient.secrets`."""
        self.folders = AsyncFolders(self._runner)
        """See :attr:`InfisicalClient.folders`."""
        self.projects = AsyncProjects(self._runner)
        """See :attr:`InfisicalClient.projects`."""
        self.tags = AsyncTags(self._runner)
        """See :attr:`InfisicalClient.tags`."""
        self.imports = AsyncImports(self._runner)
        """See :attr:`InfisicalClient.imports`."""
        self.provider = self.secrets_provider()
        """See :attr:`InfisicalClient.provider`."""

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, **overrides: Any
    ) -> AsyncInfisicalClient:
        """Build a client from ``GROW_INFISICAL_*`` and ``INFISICAL_*`` variables."""
        return cls(InfisicalConfig.from_env(env, **overrides))

    def secrets_provider(
        self,
        *,
        project_id: str | None = None,
        environment: str | None = None,
        base_path: str | None = None,
    ) -> AsyncInfisicalSecretsProvider:
        """See :meth:`InfisicalClient.secrets_provider`."""
        return AsyncInfisicalSecretsProvider(
            self._runner,
            project_id=project_id,
            environment=environment,
            base_path=base_path,
            owner=self._resources,
        )

    async def request(self, req: Request) -> Response:
        """See :meth:`InfisicalClient.request`."""
        return await self._transport.request(req)

    async def health(self) -> HealthStatus:
        """See :meth:`InfisicalClient.health`."""
        try:
            return await self._runner.run(_health_op())
        except ServiceError as err:
            return _health_error(err)

    async def ping(self) -> float:
        """See :meth:`InfisicalClient.ping`."""
        started = time.monotonic()
        await self._runner.execute(_ping_call(self._session))
        return (time.monotonic() - started) * 1000.0

    async def server_version(self) -> str:
        """See :meth:`InfisicalClient.server_version`."""
        raise _unsupported_version()

    async def aclose(self) -> None:
        """See :meth:`InfisicalClient.close`."""
        if self._closed:
            return
        self._closed = True
        self._resources.stop_all()
        auth = self._session.auth
        if auth is not None:
            await self._runner.run(auth.close_op(self._session, self.config.revoke_on_close))
        await self._transport.aclose()

    close = aclose

    async def __aenter__(self) -> AsyncInfisicalClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"AsyncInfisicalClient(config={self.config!r})"
