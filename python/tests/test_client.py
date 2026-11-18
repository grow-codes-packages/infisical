"""Infisical client core surface (sync + async): health, ping, server version, close."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import pytest

import grow_infisical as sdk
from _support import MockServer, Reply, closed_port_url, make_config
from infisical_support import Router, aclient, client, fixture, reply

TOKEN = "client-token-789"
STATUS = "/api/status"


def real(url: str, **kw: Any) -> sdk.InfisicalClient:
    return sdk.InfisicalClient(make_config(url, **kw))


def areal(url: str, **kw: Any) -> sdk.AsyncInfisicalClient:
    return sdk.AsyncInfisicalClient(make_config(url, **kw))


# --------------------------------------------------------------------------- sync


def test_health_from_fixture() -> None:
    router = Router().add("GET", STATUS, "health.ok")
    with client(router) as c:
        status = c.health()
    assert status.healthy and status.status == "ok"
    assert status.details["redisConfigured"] == "true"
    assert status.details["maxIdentityAccessTokenTTL"] == "7776000"
    assert "message" not in status.details
    assert "authorization" not in router.last("GET", STATUS).headers


def test_health_variants(server: MockServer) -> None:
    c = real(server.url)
    server.enqueue(STATUS, Reply(503, {"message": "down"}))
    status = c.health()
    assert (status.healthy, status.status) == (False, "unhealthy")
    assert status.details["httpStatus"] == "503"
    server.enqueue(STATUS, Reply(500, "boom"))
    assert c.health().status == "unhealthy"
    server.enqueue(STATUS, Reply(200, "OK"))
    assert c.health() == sdk.HealthStatus(True, "ok", {})
    server.enqueue(STATUS, Reply(200, {"message": "", "nested": {"x": 1}}))
    assert c.health() == sdk.HealthStatus(True, "ok", {})
    server.enqueue(STATUS, Reply(404, {"message": "nope"}))
    assert c.health().status == "unhealthy"
    assert len([s for s in server.seen if s.path == STATUS]) == 5  # health never retries
    c.close()


def test_core_health_unreachable() -> None:
    """core.health.unreachable"""
    c = real(closed_port_url())
    status = c.health()
    assert status.healthy is False
    assert status.status == "unreachable"
    assert "error" in status.details


def test_health_timeout_is_unreachable(server: MockServer) -> None:
    server.enqueue(STATUS, Reply(200, delay=1.0))
    c = real(server.url, request_timeout=0.1)
    assert c.health().status == "unreachable"


def test_health_raises_only_cancelled_and_config(server: MockServer) -> None:
    c = real(server.url)
    c.close()
    with pytest.raises(sdk.CancelledError):
        c.health()
    token = sdk.CancelToken()
    token.cancel()
    with pytest.raises(sdk.CancelledError):
        real(server.url).health(cancel=token)


@pytest.mark.parametrize(
    ("auth", "path", "name"),
    [
        (None, "/api/v1/identities/details", "ping.identity"),
        (sdk.TokenAuth("st.abc.def"), "/api/v2/service-token", "ping.serviceToken"),
        (
            sdk.TokenAuth("x.eyJhdXRoVG9rZW5UeXBlIjoiYWNjZXNzVG9rZW4ifQ.y"),
            "/api/v2/users/me",
            "ping.user",
        ),
    ],
)
def test_ping_route_per_token_kind(auth: sdk.InfisicalAuth | None, path: str, name: str) -> None:
    router = Router().add("GET", path, name)
    kw: dict[str, Any] = {} if auth is None else {"auth": auth}
    with client(router, **kw) as c:
        assert c.ping() >= 0
    assert router.last("GET", path).headers["authorization"].startswith("Bearer ")


def test_ping_bad_credentials_are_redacted() -> None:
    router = Router().add("GET", "/api/v1/identities/details", "auth.malformedToken")
    with client(router, token=TOKEN) as c, pytest.raises(sdk.AuthenticationError) as info:
        c.ping()
    assert info.value.http_status == 403
    assert info.value.request_id == fixture("auth.malformedToken")["body"]["reqId"]
    assert TOKEN not in str(info.value) and TOKEN not in repr(info.value)


def test_ping_without_credentials() -> None:
    router = Router().add("GET", "/api/v1/identities/details", "auth.noToken")
    c = sdk.InfisicalClient(
        sdk.InfisicalConfig(url="http://infisical.test"), http_transport=router.transport
    )
    assert c.auth is None
    with pytest.raises(sdk.AuthenticationError):
        c.ping()
    assert "authorization" not in router.seen[0].headers


def test_server_version_is_unsupported() -> None:
    with client(Router()) as c, pytest.raises(sdk.UnsupportedError):
        c.server_version()


def test_core_close_idempotent() -> None:
    """core.close.idempotent"""
    c = client(Router())
    stopped: list[int] = []

    class Res:
        def stop(self) -> None:
            stopped.append(1)

    c.resources.register(Res())
    c.close()
    c.close()
    assert c.closed and stopped == [1]
    c.resources.register(Res())  # registering after close stops immediately
    assert stopped == [1, 1]


def test_from_env_raw_request_and_cancellable(
    server: MockServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = {sdk.ENV_PREFIX + "URL": server.url, sdk.ENV_PREFIX + "TOKEN": TOKEN}
    with sdk.InfisicalClient.from_env(env) as c:
        assert c.config.url == server.url
        resp = c.request(sdk.Request("GET", "/anything"))
        assert resp.status == 200
        token = sdk.CancelToken()
        with c.cancellable(token) as t:
            assert t is token
            assert c.health().healthy
        assert TOKEN not in repr(c)
        assert c.api_version() == "unknown"
        with pytest.raises(ValueError, match="secrets"):
            c.api_version("folders")
    monkeypatch.setenv(sdk.ENV_PREFIX + "URL", server.url)
    with sdk.InfisicalClient() as c2:
        assert c2.config.url == server.url
    with pytest.raises(sdk.ConfigError):
        sdk.InfisicalClient.from_env({sdk.ENV_PREFIX + "URL": "nope://x"})


def test_cancelled_sync_call() -> None:
    router = Router().add("GET", "/api/v1/projects/proj-1", "getProject.ok")
    token = sdk.CancelToken()
    token.cancel()
    with client(router) as c, c.cancellable(token), pytest.raises(sdk.CancelledError):
        c.projects.get_project()


# --------------------------------------------------------------------------- async


async def test_async_client(server: MockServer, monkeypatch: pytest.MonkeyPatch) -> None:
    server.enqueue(STATUS, Reply(200, {"message": "Ok"}))
    async with areal(server.url, token=TOKEN) as c:
        assert (await c.health()).healthy
        assert await c.ping() >= 0
        with pytest.raises(sdk.UnsupportedError):
            await c.server_version()
        assert (await c.request(sdk.Request("GET", "/raw"))).status == 200
        assert TOKEN not in repr(c)
        assert c.resources is not None
    await c.close()
    with pytest.raises(sdk.CancelledError):
        await c.health()
    monkeypatch.setenv(sdk.ENV_PREFIX + "URL", server.url)
    c3 = sdk.AsyncInfisicalClient()
    assert c3.config.url == server.url
    await c3.aclose()
    c4 = sdk.AsyncInfisicalClient.from_env({sdk.ENV_PREFIX + "URL": server.url})
    assert c4.auth is None
    await c4.aclose()


async def test_async_health_unreachable() -> None:
    """core.health.unreachable (async)"""
    c = areal(closed_port_url())
    status = await c.health()
    assert (status.healthy, status.status) == (False, "unreachable")
    await c.aclose()


async def test_async_health_cancel(server: MockServer) -> None:
    server.enqueue(STATUS, Reply(200, delay=2.0))
    c = areal(server.url)
    task = asyncio.ensure_future(c.health())
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(sdk.CancelledError):
        await task
    await c.aclose()


async def test_async_ping_routes() -> None:
    router = Router().add("GET", "/api/v2/service-token", "ping.serviceToken")
    async with aclient(router, auth=sdk.TokenAuth("st.a.b")) as c:
        assert await c.ping() >= 0
        assert c.auth is not None and c.auth.token_kind == "service_token"


def test_non_json_success_body() -> None:
    def handle(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[1]")

    router = Router().add("GET", "/api/v1/projects/proj-1", handle)
    with client(router) as c, pytest.raises(sdk.UnavailableError, match="unexpected"):
        c.projects.get_project()
    router.add("GET", "/api/v1/projects", reply(200, None))
    with client(router) as c:
        assert c.projects.list_projects().projects == []


# --------------------------------------------------------------------------- polling


def test_poll_until() -> None:
    values = iter([None, [], [1]])
    assert sdk.poll_until(lambda: next(values), interval_s=0.001) == [1]
    attempts = iter([0, 1, 2, 3])
    assert sdk.poll_until(lambda: next(attempts), predicate=lambda v: v >= 2, interval_s=0) == 2
    errors = iter([sdk.UnavailableError("flaky"), "ok"])

    def flaky() -> str:
        item = next(errors)
        if isinstance(item, Exception):
            raise item
        return item

    assert sdk.poll_until(flaky, interval_s=0) == "ok"
    with pytest.raises(sdk.NotFoundError):
        sdk.poll_until(lambda: (_ for _ in ()).throw(sdk.NotFoundError("gone")))
    started = time.monotonic()
    with pytest.raises(sdk.TimeoutError, match=r"wait\.thing") as info:
        sdk.poll_until(
            lambda: (_ for _ in ()).throw(sdk.UnavailableError("down")),
            timeout_s=0.05,
            interval_s=0.01,
            operation="wait.thing",
        )
    assert isinstance(info.value.cause, sdk.UnavailableError)
    assert time.monotonic() - started < 1.0
    with pytest.raises(sdk.TimeoutError):
        sdk.poll_until(lambda: None, timeout_s=0.02, interval_s=0.005)


async def test_apoll_until() -> None:
    values = iter([None, "", "done"])

    async def fetch() -> str | None:
        return next(values)

    assert await sdk.apoll_until(fetch, interval_s=0.001) == "done"

    async def failing() -> str:
        raise sdk.UnavailableError("down")

    with pytest.raises(sdk.TimeoutError):
        await sdk.apoll_until(failing, timeout_s=0.03, interval_s=0.01)

    async def fatal() -> str:
        raise sdk.AuthenticationError("no")

    with pytest.raises(sdk.AuthenticationError):
        await sdk.apoll_until(fatal)

    async def numbers() -> int:
        return 5

    assert await sdk.apoll_until(numbers, predicate=lambda n: n == 5) == 5


def test_resource_registry() -> None:
    reg = sdk.ResourceRegistry()
    calls: list[str] = []

    class Good:
        def stop(self) -> None:
            calls.append("good")

    class Bad:
        def stop(self) -> None:
            raise RuntimeError("ignored")

    good, bad = Good(), Bad()
    reg.register(bad)
    reg.register(good)
    reg.unregister(good)
    reg.unregister(good)
    reg.register(good)
    assert isinstance(good, sdk.Stoppable)
    assert not reg.closed
    reg.stop_all()
    reg.stop_all()
    assert reg.closed and calls == ["good"]
    reg.register(bad)  # stopped immediately, error ignored


def test_get_logger_is_silent() -> None:
    logger = sdk.get_logger()
    assert logger.name == sdk.LOGGER_NAME == "grow_infisical"
    assert any(type(h).__name__ == "NullHandler" for h in logger.handlers)
