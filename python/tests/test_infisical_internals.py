"""Internal helpers: error body parsing, status mapping, wire helpers, auth refresh edge cases."""

from __future__ import annotations

import datetime as _dt

import httpx
import pytest

import grow_infisical as sdk
from grow_infisical import _api
from grow_infisical._api import AsyncRunner, Call, Session, SyncRunner, map_error, parse_error_body
from infisical_support import Clock, Router, client, config, login_ok


def resp(status: int, content: bytes = b"", headers: dict[str, str] | None = None) -> sdk.Response:
    return sdk.Response(status, httpx.Headers(headers or {}), content, request_id="hdr-id")


def test_core_errors_mapping() -> None:
    """core.errors.mapping (Infisical bodies)"""
    expected = {
        400: sdk.ValidationError,
        401: sdk.AuthenticationError,
        403: sdk.PermissionDeniedError,
        404: sdk.NotFoundError,
        408: sdk.TimeoutError,
        409: sdk.ConflictError,
        412: sdk.ConflictError,
        413: sdk.ValidationError,
        418: sdk.ValidationError,
        422: sdk.ValidationError,
        429: sdk.RateLimitError,
        500: sdk.UnavailableError,
        501: sdk.UnsupportedError,
        502: sdk.UnavailableError,
        503: sdk.UnavailableError,
        504: sdk.TimeoutError,
        599: sdk.UnavailableError,
    }
    for status, cls in expected.items():
        err = map_error(resp(status), "op")
        assert type(err) is cls, status
        assert err.http_status == status and err.request_id == "hdr-id"
    assert map_error(resp(418), "op").message == "op: i'm a teapot (HTTP 418)"
    assert map_error(resp(599), "op").message == "op: error (HTTP 599)"
    unavailable = map_error(resp(503, b"", {"retry-after": "3"}), "op")
    assert unavailable.retry_after == 3 and unavailable.retryable


def test_error_body_parsing_and_redaction() -> None:
    body = parse_error_body(b'{"message":[{"message":"bad","path":["a",0]},"plain",5,{"x":1}]}')
    assert body.text == "a.0: bad; plain"
    assert parse_error_body(b'{"details":["d1",2]}').text == "d1"
    assert parse_error_body(b"oops not json").text == "oops not json"
    assert parse_error_body(b"x" * 2000).text == ""
    assert parse_error_body(b"").text == ""
    assert parse_error_body(b'{"message":{"nested":1},"error":"","reqId":5}') == _api.ErrorBody(
        "", None, None
    )
    err = map_error(
        resp(401, b'{"message":"bad token sekret-value-1","reqId":"req-9"}'),
        "op sekret-value-1",
        known_secrets=["sekret-value-1"],
    )
    assert "sekret-value-1" not in err.message and err.request_id == "req-9"
    tagged = map_error(resp(404, b'{"message":"Route GET:/x not found","error":"Not Found"}'), "op")
    assert isinstance(tagged, _api.RouteMissingError) and isinstance(tagged, sdk.UnsupportedError)


def test_wire_helpers() -> None:
    assert _api.normalize_path(None) == "/"
    assert _api.normalize_path("a//b/") == "/a/b"
    assert _api.join_path("/a", "b/c") == "/a/b/c"
    assert _api.parse_time("2026-11-18T20:28:13.931Z") == _dt.datetime(
        2026, 11, 18, 20, 28, 13, 931000, tzinfo=_dt.timezone.utc
    )
    assert _api.parse_time("2026-11-18T20:28:13") is not None
    assert _api.parse_time("nope") is None
    assert _api.parse_time(5) is None
    assert _api.integer(True, 7) == 7 and _api.integer(2.9) == 2
    assert _api.opt_bool(None) is None and _api.opt_bool(False) == "false"
    with pytest.raises(sdk.UnavailableError, match="no secret"):
        _api.field({}, "secret", "op")
    with pytest.raises(sdk.ValidationError):
        _api.bounded_int("1", "n", "op", 0)
    op = _api.send(Call("GET", "/x", "x"))
    assert next(op).path == "/x"
    with pytest.raises(StopIteration):
        op.send(resp(200))


class FlakyAuth(sdk.InfisicalAuth):
    """valid_token() is empty on the first look and set on the second (lock double-check)."""

    kind = "flaky"

    def __init__(self) -> None:
        super().__init__()
        self.looks = 0

    @property
    def token_kind(self) -> sdk.TokenKind:
        return "identity"

    def valid_token(self, now: float) -> sdk.Secret | None:
        self.looks += 1
        return None if self.looks == 1 else sdk.Secret("tok")

    def refresh_op(self, session: Session) -> _api.Op[sdk.Secret]:  # pragma: no cover
        raise AssertionError("not reached")
        yield

    def known_secrets(self) -> list[str]:
        return []


async def test_token_double_check_under_lock() -> None:
    cfg = config(auth=FlakyAuth())
    session = Session(cfg, cfg.auth)
    sync = SyncRunner(sdk.HttpTransport(cfg), session)
    assert sync.token() == sdk.Secret("tok")
    cfg2 = config(auth=FlakyAuth())
    session2 = Session(cfg2, cfg2.auth)
    runner = AsyncRunner(sdk.AsyncHttpTransport(cfg2), session2)
    assert await runner.token() == sdk.Secret("tok")
    assert repr(cfg2.auth) == "FlakyAuth([REDACTED])"


def test_token_without_max_ttl_and_static_refresh_op() -> None:
    clock = Clock()
    router = (
        Router()
        .add("POST", "/api/v1/auth/universal-auth/login", login_ok("t1", 100, 0))
        .add("POST", "/api/v1/auth/token/renew", login_ok("t2", 100, 0))
        .add("GET", "/api/v1/identities/details", "ping.identity")
    )
    with client(router, client_id="c", client_secret="s", clock=clock) as c:
        c.ping()
        clock.now += 90
        c.ping()
    assert router.calls("POST", "/api/v1/auth/token/renew")
    static = sdk.TokenAuth("abc-token")
    op = static.refresh_op(Session(config(), None))
    with pytest.raises(StopIteration) as stop:
        next(op)
    assert stop.value.value == sdk.Secret("abc-token")


def test_cancel_during_renew_is_not_swallowed() -> None:
    clock = Clock()
    ua = sdk.UniversalAuth("c", "s")
    cfg = config(auth=ua)
    session = Session(cfg, ua, clock)
    op = ua.refresh_op(session)
    call = next(op)
    assert call.path.endswith("/login")
    with pytest.raises(StopIteration):
        op.send(resp(200, b'{"accessToken":"t1","expiresIn":100,"accessTokenMaxTTL":1000}'))
    clock.now += 90
    op = ua.refresh_op(session)
    assert next(op).path.endswith("/renew")
    with pytest.raises(sdk.CancelledError):
        op.throw(sdk.CancelledError("cancelled"))


def test_empty_tag_map_skips_tag_calls() -> None:
    router = Router().add("POST", "/api/v4/secrets/K", "createSecret.ok")
    with client(router) as c:
        assert c.provider.set("K", "v", tags={}) == "1"
    assert router.last("POST", "/api/v4/secrets/K").json["tagIds"] == []
