"""Mock Infisical API for unit tests: an ``httpx.MockTransport`` router fed with the recorded
fixtures in ``tests/fixtures`` (``{request, status, body, headers?}``)."""

from __future__ import annotations

import dataclasses
import json
from collections import defaultdict, deque
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

import grow_infisical as sdk
from _support import fast_retry

FIXTURES = Path(__file__).parent / "fixtures"
URL = "http://infisical.test"
PROJECT = "proj-1"
TOKEN = "static-token-abcdef"

Handler = Callable[[httpx.Request], httpx.Response]


def fixture(name: str) -> dict[str, Any]:
    """The recorded fixture ``name`` (without ``.json``)."""
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@dataclasses.dataclass
class Seen:
    method: str
    path: str
    params: dict[str, str]
    json: Any
    headers: httpx.Headers


def reply(status: int = 200, body: Any = None, headers: dict[str, str] | None = None) -> Handler:
    def handle(_: httpx.Request) -> httpx.Response:
        content = b"" if body is None else json.dumps(body).encode()
        hdrs = {"content-type": "application/json", **(headers or {})}
        return httpx.Response(status, content=content, headers=hdrs)

    return handle


def from_fixture(name: str, **overrides: Any) -> Handler:
    doc = fixture(name)
    body = doc.get("body")
    if overrides and isinstance(body, dict):
        body = {**body, **overrides}
    return reply(doc["status"], body, doc.get("headers"))


class Router:
    """Routes ``(METHOD, path)`` to queued handlers (last one repeats); records requests."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], deque[Handler]] = defaultdict(deque)
        self.seen: list[Seen] = []

    def add(self, method: str, path: str, *handlers: Handler | str) -> Router:
        for h in handlers:
            self.routes[(method, path)].append(from_fixture(h) if isinstance(h, str) else h)
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.seen.append(
            Seen(request.method, request.url.path, dict(request.url.params), body, request.headers)
        )
        queue = self.routes.get((request.method, request.url.path))
        if not queue:
            return reply(
                404,
                {
                    "reqId": "req-route",
                    "statusCode": 404,
                    "message": f"Route {request.method}:{request.url.path} not found",
                    "error": "Not Found",
                },
            )(request)
        handler = queue.popleft() if len(queue) > 1 else queue[0]
        return handler(request)

    def calls(self, method: str, path: str) -> list[Seen]:
        return [s for s in self.seen if s.method == method and s.path == path]

    def last(self, method: str, path: str) -> Seen:
        found = self.calls(method, path)
        assert found, f"no {method} {path} in {[(s.method, s.path) for s in self.seen]}"
        return found[-1]

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


def config(**kw: Any) -> sdk.InfisicalConfig:
    kw.setdefault("url", URL)
    kw.setdefault("retry", fast_retry())
    kw.setdefault("project_id", PROJECT)
    kw.setdefault("environment", "dev")
    if "auth" not in kw and "client_id" not in kw:
        kw.setdefault("token", TOKEN)
    return sdk.InfisicalConfig(**kw)


def client(router: Router, **kw: Any) -> sdk.InfisicalClient:
    clock = kw.pop("clock", None)
    extra = {"clock": clock} if clock else {}
    return sdk.InfisicalClient(config(**kw), http_transport=router.transport, **extra)


def aclient(router: Router, **kw: Any) -> sdk.AsyncInfisicalClient:
    clock = kw.pop("clock", None)
    extra = {"clock": clock} if clock else {}
    return sdk.AsyncInfisicalClient(config(**kw), http_transport=router.transport, **extra)


class Clock:
    """Manually advanced epoch clock."""

    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def login_ok(token: str = "ua-token-1", expires: int = 300, max_ttl: int = 3600) -> Handler:
    return reply(
        200,
        {
            "accessToken": token,
            "expiresIn": expires,
            "accessTokenMaxTTL": max_ttl,
            "tokenType": "Bearer",
        },
    )


def secret_body(key: str, value: str = "v", version: int = 1, path: str = "/") -> dict[str, Any]:
    return {
        "id": f"id-{key}",
        "secretKey": key,
        "secretValue": value,
        "version": version,
        "type": "shared",
        "environment": "dev",
        "secretPath": path,
        "secretComment": "",
        "tags": [{"id": "t1", "slug": "team", "name": "team", "color": "#fff"}],
        "secretMetadata": [{"key": "owner", "value": "ops"}],
        "createdAt": "2026-11-18T20:28:13.931Z",
        "updatedAt": "2026-11-18T20:28:13.931Z",
    }


def error_body(status: int, message: Any, name: str) -> Handler:
    return reply(
        status, {"reqId": "req-x1", "statusCode": status, "message": message, "error": name}
    )
