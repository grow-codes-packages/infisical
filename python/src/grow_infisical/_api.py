"""Internal Infisical request layer (service-owned).

Every service operation is written once as a *generator* that yields :class:`Call` instructions
and receives their :class:`~grow_infisical.Response`. The sync client drives these generators
with blocking I/O, the async client with ``await``; both share request building, response
parsing, the Infisical error mapping (API.md §0, DECISIONS.md #1, #6), authentication with
automatic token refresh and the secrets API version detection (v4 → v3).
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import dataclasses
import datetime as _dt
import functools
import http
import json as _json
import re
import threading
import time
from collections.abc import Callable, Coroutine, Generator, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Concatenate, Literal, ParamSpec, TypeVar, cast
from urllib.parse import quote

from ._core import (
    AsyncHttpTransport,
    AuthenticationError,
    CancelToken,
    ConfigError,
    ConflictError,
    ErrorCode,
    HttpTransport,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    Request,
    Response,
    Secret,
    ServiceError,
    TimeoutError,
    UnavailableError,
    UnsupportedError,
    ValidationError,
    parse_retry_after,
    redact_text,
    truncate,
)

if TYPE_CHECKING:
    from .auth import InfisicalAuth
    from .config import InfisicalConfig

__all__: list[str] = []

T = TypeVar("T")
P = ParamSpec("P")

ApiVersion = Literal["v4", "v3"]
"""A secrets API version the SDK can speak."""

# --------------------------------------------------------------------------- instructions


@dataclasses.dataclass(frozen=True)
class Call:
    """One Infisical API call."""

    method: str
    #: Absolute API path (segments already percent-encoded), e.g. ``/api/v4/secrets``.
    path: str
    #: Operation name used in error messages, e.g. ``secrets.get API_KEY``.
    operation: str
    params: Mapping[str, Any] | None = None
    json: Any = None
    #: Send ``Authorization: Bearer <token>`` from the client's auth method.
    auth: bool = True
    #: Login/renew/revoke endpoint: 400/403 become ``AuthenticationError``.
    login: bool = False
    idempotent: bool | None = None
    max_retries: int | None = None


Op = Generator[Call, Response, T]
"""An operation: yields calls, receives responses, returns ``T``."""

# --------------------------------------------------------------------------- error mapping


class RouteMissingError(UnsupportedError):
    """The route does not exist on this server (404 ``Not Found`` + ``Route …``).

    Internal signal for the v4 → v3 fallback (DECISIONS.md #6); surfaces as
    :class:`UnsupportedError` when no fallback applies.
    """


_TRY_AGAIN = re.compile(r"try again in (\d+(?:\.\d+)?) seconds?", re.IGNORECASE)
_STATUS_CLASSES: dict[int, type[ServiceError]] = {
    400: ValidationError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    408: TimeoutError,
    409: ConflictError,
    412: ConflictError,
    413: ValidationError,
    422: ValidationError,
    429: RateLimitError,
    500: UnavailableError,
    501: UnsupportedError,
    502: UnavailableError,
    503: UnavailableError,
    504: TimeoutError,
}
_RETRYABLE = frozenset({408, 429, 500, 502, 503, 504})


@dataclasses.dataclass(frozen=True)
class ErrorBody:
    """The parts of an Infisical error body (``{"reqId","statusCode","message","error"}``)."""

    text: str
    name: str | None
    request_id: str | None


def _issue_text(issue: Any) -> str:
    if isinstance(issue, str):
        return issue
    if not isinstance(issue, Mapping):
        return ""
    msg = issue.get("message")
    msg = msg if isinstance(msg, str) else ""
    path = issue.get("path")
    where = ".".join(str(p) for p in path) if isinstance(path, list) else ""
    return f"{where}: {msg}" if where and msg else msg


def parse_error_body(content: bytes) -> ErrorBody:
    """Extract message text (zod issues joined, ``details[]`` appended), name and request id."""
    try:
        doc = _json.loads(content) if content else None
    except ValueError:
        doc = None
    if not isinstance(doc, Mapping):
        plain = content.decode("utf-8", errors="replace").strip() if content else ""
        return ErrorBody(plain if len(plain) < 1000 else "", None, None)
    message = doc.get("message")
    if isinstance(message, str):
        text_ = message
    elif isinstance(message, list):
        text_ = "; ".join(t for t in (_issue_text(i) for i in message) if t)
    else:
        text_ = ""
    details = doc.get("details")
    if isinstance(details, list):
        extra = [d for d in details if isinstance(d, str)]
        if extra:
            text_ = f"{text_}: {'; '.join(extra)}" if text_ else "; ".join(extra)
    name = doc.get("error")
    req = doc.get("reqId")
    return ErrorBody(
        text_,
        name if isinstance(name, str) and name else None,
        req if isinstance(req, str) and req else None,
    )


def map_error(
    resp: Response, operation: str, *, login: bool = False, known_secrets: Sequence[str] = ()
) -> ServiceError:
    """Map an Infisical error response to the SPEC error classes (API.md "Error mapping").

    * 400 whose message contains ``already exists`` → ``ConflictError`` (DECISIONS #1);
    * 403 ``TokenError`` → ``AuthenticationError``; login endpoints: 400/403 → authentication;
    * 404 ``Not Found`` + ``Route …`` → :class:`RouteMissingError` (``UnsupportedError``);
    * everything else per SPEC 2.1; the request id comes from the body field ``reqId``.
    """
    status = resp.status
    body = parse_error_body(resp.content)
    if body.text:
        reason = truncate(redact_text(body.text, list(known_secrets)), 300)
    else:
        try:
            reason = http.HTTPStatus(status).phrase.lower()
        except ValueError:
            reason = "error"
    message = redact_text(f"{operation}: {reason} (HTTP {status})", list(known_secrets))
    request_id = body.request_id or resp.request_id
    cls: type[ServiceError] = _STATUS_CLASSES.get(
        status, ValidationError if 400 <= status < 500 else UnavailableError
    )
    if status == 404 and body.name == "Not Found" and body.text.startswith("Route "):
        cls = RouteMissingError
    elif status == 400 and "already exists" in body.text.lower():
        cls = ConflictError
    elif (status == 403 and body.name == "TokenError") or (login and status in (400, 403)):
        cls = AuthenticationError
    retry_after = None
    if status in (429, 503):
        retry_after = parse_retry_after(resp.headers.get("retry-after"))
        if retry_after is None:
            hint = _TRY_AGAIN.search(body.text)
            retry_after = float(hint.group(1)) if hint else None
    return cls(
        message,
        http_status=status,
        request_id=request_id,
        retry_after=retry_after,
        retryable=True if status in _RETRYABLE else None,
    )


def unexpected(operation: str, reason: str) -> UnavailableError:
    """Error for a response that does not have the documented shape."""
    return UnavailableError(f"{operation}: unexpected response ({reason})", retryable=False)


# --------------------------------------------------------------------------- wire helpers


def normalize_path(path: str | None) -> str:
    """Leading ``/``, no duplicate or trailing slashes (``None``/``""`` → ``/``)."""
    if not path:
        return "/"
    return "/" + "/".join(p for p in path.split("/") if p)


def join_path(base: str, child: str) -> str:
    """``/a`` + ``b/c`` → ``/a/b/c``."""
    return normalize_path(f"{base}/{child}")


def seg(value: str) -> str:
    """Percent-encode one path segment."""
    return quote(value, safe="")


def require_text(value: Any, what: str, operation: str) -> str:
    """Reject empty names client side (:class:`ValidationError`)."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{operation}: {what} must not be empty")
    return value


def required(value: str | None, what: str, operation: str) -> str:
    """:class:`ConfigError` naming the missing setting (DECISIONS #5: checked at call time)."""
    if not value:
        raise ConfigError(
            f"{operation}: {what} is required (set it in the config / environment or pass it)"
        )
    return value


def bounded_int(value: Any, what: str, operation: str, low: int, high: int | None = None) -> int:
    """``value`` when it is an int in ``[low, high]``, else :class:`ValidationError`."""
    if isinstance(value, bool) or not isinstance(value, int) or value < low:
        raise ValidationError(f"{operation}: {what} must be an integer >= {low}")
    if high is not None and value > high:
        raise ValidationError(f"{operation}: {what} must be an integer between {low} and {high}")
    return value


def wire_bool(value: bool) -> str:
    """``true`` / ``false``."""
    return "true" if value else "false"


def opt_bool(value: bool | None) -> str | None:
    """:func:`wire_bool` or ``None``."""
    return None if value is None else wire_bool(value)


def obj(value: Any) -> dict[str, Any]:
    """The value when it is a JSON object, else ``{}``."""
    return value if isinstance(value, dict) else {}


def arr(value: Any) -> list[Any]:
    """The value when it is a JSON array, else ``[]``."""
    return value if isinstance(value, list) else []


def text(value: Any) -> str:
    """The value when it is a string, else ``""``."""
    return value if isinstance(value, str) else ""


def opt_text(value: Any) -> str | None:
    """The value when it is a string, else ``None``."""
    return value if isinstance(value, str) else None


def integer(value: Any, default: int = 0) -> int:
    """The value when it is a number (not bool), else ``default``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return int(value)


def compact(body: Mapping[str, Any]) -> dict[str, Any]:
    """Copy without ``None`` values."""
    return {k: v for k, v in body.items() if v is not None}


def parse_time(value: Any) -> _dt.datetime | None:
    """ISO-8601 timestamp → aware UTC datetime (``None`` when absent or invalid)."""
    if not isinstance(value, str) or not value:
        return None
    raw = value.strip()
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def body_of(resp: Response, operation: str) -> dict[str, Any]:
    """The JSON object of a response (``{}`` for an empty body)."""
    if not resp.content.strip():
        return {}
    doc = resp.json()
    if not isinstance(doc, dict):
        raise unexpected(operation, "body is not a JSON object")
    return doc


def field(doc: Mapping[str, Any], key: str, operation: str) -> dict[str, Any]:
    """``doc[key]`` as a JSON object (raises :func:`unexpected` when missing)."""
    value = doc.get(key)
    if not isinstance(value, dict):
        raise unexpected(operation, f"no {key}")
    return value


def send(call: Call) -> Op[Response]:
    """Send ``call``; the raw response."""
    resp = yield call
    return resp


def fetch(call: Call) -> Op[dict[str, Any]]:
    """Send ``call``; the decoded JSON object."""
    resp = yield call
    return body_of(resp, call.operation)


# --------------------------------------------------------------------------- session


class Session:
    """Client state shared by the sync/async runners: config, auth, detected API version."""

    def __init__(
        self,
        config: InfisicalConfig,
        auth: InfisicalAuth | None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.auth = auth
        self.clock = clock
        self.secrets_version: ApiVersion | None = (
            None if config.api_version == "auto" else config.api_version
        )

    def known_secrets(self) -> list[str]:
        """Credential values that must never appear in errors or logs."""
        out = list(self.config.known_secrets())
        if self.auth is not None:
            out.extend(self.auth.known_secrets())
        return out

    def project_id(self, value: str | None, operation: str) -> str:
        """Project id from the argument or the config (:class:`ConfigError` when missing)."""
        return required(value or self.config.project_id, "project_id", operation)

    def environment(self, value: str | None, operation: str) -> str:
        """Environment slug from the argument or the config (:class:`ConfigError` when missing)."""
        return required(value or self.config.environment, "environment", operation)

    def path(self, value: str | None) -> str:
        """Normalised secret path from the argument or the config default."""
        return normalize_path(value if value is not None else self.config.secret_path)

    def request(self, call: Call, token: Secret | None) -> Request:
        headers = {"Authorization": f"Bearer {token.reveal()}"} if token is not None else None
        return Request(
            call.method,
            call.path,
            operation=call.operation,
            params=call.params,
            json=call.json,
            headers=headers,
            idempotent=call.idempotent,
            max_retries=call.max_retries,
            raise_for_status=False,
        )

    def check(self, call: Call, resp: Response) -> Response:
        if resp.status >= 400:
            raise map_error(
                resp, call.operation, login=call.login, known_secrets=self.known_secrets()
            )
        return resp


def secrets_call(session: Session, build: Callable[[ApiVersion], Call]) -> Op[Response]:
    """Send a secrets call on the detected API version (API.md §4, DECISIONS #6).

    While the version is unknown (``auto``), a route-missing 404 on v4 switches to v3 and repeats
    the call once (the server did not run it); any other HTTP answer confirms v4.
    """
    known = session.secrets_version
    version: ApiVersion = known or "v4"
    try:
        resp = yield build(version)
    except RouteMissingError:
        if known is not None:
            raise
        session.secrets_version = "v3"
        resp = yield build("v3")
        return resp
    except ServiceError as err:
        if known is None and err.http_status is not None:
            session.secrets_version = "v4"
        raise
    if session.secrets_version is None:
        session.secrets_version = version
    return resp


# --------------------------------------------------------------------------- runners

_CANCEL: contextvars.ContextVar[CancelToken | None] = contextvars.ContextVar(
    "grow_infisical_cancel", default=None
)


@contextlib.contextmanager
def cancel_scope(token: CancelToken | None) -> Iterator[None]:
    """Apply ``token`` to every sync call made in this context (thread / context var)."""
    if token is None:
        yield
        return
    reset = _CANCEL.set(token)
    try:
        yield
    finally:
        _CANCEL.reset(reset)


def _step(op: Op[T], value: Any, exc: BaseException | None) -> Call:
    if exc is not None:
        return op.throw(exc)
    return op.send(value)


def _is_relogin(err: ServiceError, auth: InfisicalAuth | None, call: Call) -> bool:
    return (
        call.auth
        and auth is not None
        and auth.refreshable
        and isinstance(err, AuthenticationError)
        and err.http_status == 401
    )


class SyncRunner:
    """Drives operations with blocking I/O."""

    def __init__(self, transport: HttpTransport, session: Session) -> None:
        self.transport = transport
        self.session = session
        self._auth_lock = threading.Lock()

    def token(self) -> Secret | None:
        """The current bearer token, logging in / renewing when needed."""
        auth = self.session.auth
        if auth is None:
            return None
        current = auth.valid_token(self.session.clock())
        if current is not None:
            return current
        with self._auth_lock:
            current = auth.valid_token(self.session.clock())
            if current is not None:
                return current
            return self.run(auth.refresh_op(self.session))

    def _send(self, call: Call, token: Secret | None) -> Response:
        resp = self.transport.request(self.session.request(call, token), cancel=_CANCEL.get())
        return self.session.check(call, resp)

    def execute(self, call: Call) -> Response:
        token = self.token() if call.auth else None
        try:
            return self._send(call, token)
        except ServiceError as err:
            auth = self.session.auth
            if not _is_relogin(err, auth, call):
                raise
            assert auth is not None
            auth.invalidate()
            return self._send(call, self.token())

    def run(self, op: Op[T]) -> T:
        value: Any = None
        exc: BaseException | None = None
        while True:
            try:
                call = _step(op, value, exc)
            except StopIteration as stop:
                return cast("T", stop.value)
            value, exc = None, None
            try:
                value = self.execute(call)
            except ServiceError as err:
                if err.code == ErrorCode.CANCELLED:
                    op.close()
                    raise
                exc = err


class AsyncRunner:
    """Drives operations with ``await``."""

    def __init__(self, transport: AsyncHttpTransport, session: Session) -> None:
        self.transport = transport
        self.session = session
        self._auth_lock: asyncio.Lock | None = None

    async def token(self) -> Secret | None:
        """See :meth:`SyncRunner.token`."""
        auth = self.session.auth
        if auth is None:
            return None
        current = auth.valid_token(self.session.clock())
        if current is not None:
            return current
        if self._auth_lock is None:
            self._auth_lock = asyncio.Lock()
        async with self._auth_lock:
            current = auth.valid_token(self.session.clock())
            if current is not None:
                return current
            return await self.run(auth.refresh_op(self.session))

    async def _send(self, call: Call, token: Secret | None) -> Response:
        resp = await self.transport.request(self.session.request(call, token))
        return self.session.check(call, resp)

    async def execute(self, call: Call) -> Response:
        token = await self.token() if call.auth else None
        try:
            return await self._send(call, token)
        except ServiceError as err:
            auth = self.session.auth
            if not _is_relogin(err, auth, call):
                raise
            assert auth is not None
            auth.invalidate()
            return await self._send(call, await self.token())

    async def run(self, op: Op[T]) -> T:
        value: Any = None
        exc: BaseException | None = None
        while True:
            try:
                call = _step(op, value, exc)
            except StopIteration as stop:
                return cast("T", stop.value)
            value, exc = None, None
            try:
                value = await self.execute(call)
            except ServiceError as err:
                if err.code == ErrorCode.CANCELLED:
                    op.close()
                    raise
                exc = err


# --------------------------------------------------------------------------- facades


class SyncModule:
    """Base of the sync service modules (``client.secrets``, ``client.folders`` …)."""

    def __init__(self, runner: SyncRunner) -> None:
        self._runner = runner
        self._session = runner.session

    def _run(self, op: Op[T]) -> T:
        return self._runner.run(op)


class AsyncModule:
    """Base of the async service modules."""

    def __init__(self, runner: AsyncRunner) -> None:
        self._runner = runner
        self._session = runner.session

    async def _run(self, op: Op[T]) -> T:
        return await self._runner.run(op)


def sync_op(fn: Callable[Concatenate[Any, P], Op[T]]) -> Callable[Concatenate[Any, P], T]:
    """Turn an operation generator into a blocking method of a :class:`SyncModule`."""

    def method(self: SyncModule, /, *args: P.args, **kwargs: P.kwargs) -> T:
        return self._run(fn(self, *args, **kwargs))

    return cast("Callable[Concatenate[Any, P], T]", functools.wraps(fn)(method))


def async_op(
    fn: Callable[Concatenate[Any, P], Op[T]],
) -> Callable[Concatenate[Any, P], Coroutine[Any, Any, T]]:
    """Turn an operation generator into a coroutine method of an :class:`AsyncModule`."""

    async def method(self: AsyncModule, /, *args: P.args, **kwargs: P.kwargs) -> T:
        return await self._run(fn(self, *args, **kwargs))

    wrapped = functools.wraps(fn)(method)
    return cast("Callable[Concatenate[Any, P], Coroutine[Any, Any, T]]", wrapped)
