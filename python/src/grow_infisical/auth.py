"""Infisical auth methods (API.md §2), service-owned.

Universal Auth, static tokens (Token Auth, user JWT, legacy service token), Kubernetes Auth and
AWS IAM Auth, with automatic access-token renewal (at 80 % of the lifetime) and re-login (when the
max TTL is reached, renewal fails or an API call answers 401).

Pass an auth method as ``InfisicalConfig(auth=...)``; without one the client uses ``token`` or
``client_id``/``client_secret`` from the config. The method bound to a client is
``client.auth``; login-based methods expose ``login()``/``renew()``/``revoke()`` for the sync
client and ``alogin()``/``arenew()``/``arevoke()`` for the async client.
"""

from __future__ import annotations

import abc
import base64
import binascii
import contextlib
import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Literal

from ._api import (
    AsyncRunner,
    Call,
    Op,
    Session,
    SyncRunner,
    body_of,
    compact,
    integer,
    require_text,
    text,
    unexpected,
)
from ._core import (
    AuthenticationError,
    ConfigError,
    ErrorCode,
    Secret,
    ServiceError,
    ValidationError,
)

__all__ = [
    "TokenKind",
    "AccessToken",
    "InfisicalAuth",
    "TokenAuth",
    "IdentityLoginAuth",
    "UniversalAuth",
    "KubernetesAuth",
    "AwsCredentials",
    "AwsIamAuth",
    "AwsLoginRequest",
    "KUBERNETES_TOKEN_PATH",
    "REFRESH_FACTOR",
    "STS_BODY",
    "detect_token_kind",
    "sign_aws_request",
]

TokenKind = Literal["identity", "user", "serviceToken"]
"""Token kind (wire values shared by every language: ``identity``, ``user``, ``serviceToken``)."""
"""Principal kind of a token (selects the ``ping()`` route)."""

#: Fraction of a token's lifetime after which it is renewed.
REFRESH_FACTOR = 0.8

#: Default path of the Kubernetes service-account token.
KUBERNETES_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # noqa: S105

#: Body of the signed STS request (``sts:GetCallerIdentity``).
STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"


def detect_token_kind(token: str) -> TokenKind:
    """``st.…`` → legacy service token; a JWT with ``authTokenType: accessToken`` → user token;
    everything else → machine identity token."""
    if token.startswith("st."):
        return "serviceToken"
    parts = token.split(".")
    if len(parts) == 3:
        try:
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
        except (ValueError, binascii.Error):
            payload = None
        if isinstance(payload, dict) and payload.get("authTokenType") == "accessToken":
            return "user"
    return "identity"


@dataclasses.dataclass(frozen=True)
class AccessToken:
    """An access token returned by a login or renewal (``repr`` hides the token)."""

    #: The bearer token.
    access_token: Secret
    #: Lifetime of this token in seconds (``expiresIn``).
    expires_in_s: float
    #: Longest lifetime reachable by renewals in seconds (``accessTokenMaxTTL``, 0 = unlimited).
    max_ttl_s: float
    #: Token type (``Bearer``).
    token_type: str
    #: When the token was obtained or last renewed (UTC).
    obtained_at: _dt.datetime


@dataclasses.dataclass(frozen=True)
class _Stored:
    token: AccessToken
    obtained: float  # epoch seconds of this token
    login_at: float  # epoch seconds of the login that started the chain

    def expiry(self) -> float:
        own = self.obtained + self.token.expires_in_s
        if self.token.max_ttl_s > 0:
            return min(own, self.login_at + self.token.max_ttl_s)
        return own

    def needs_refresh(self, now: float) -> bool:
        return now >= self.obtained + (self.expiry() - self.obtained) * REFRESH_FACTOR


def _parse_access_token(resp_body: Mapping[str, Any], operation: str, now: float) -> AccessToken:
    token = resp_body.get("accessToken")
    if not isinstance(token, str) or not token:
        raise unexpected(operation, "no accessToken")
    return AccessToken(
        access_token=Secret(token),
        expires_in_s=float(integer(resp_body.get("expiresIn"))),
        max_ttl_s=float(integer(resp_body.get("accessTokenMaxTTL"))),
        token_type=text(resp_body.get("tokenType")) or "Bearer",
        obtained_at=_dt.datetime.fromtimestamp(now, tz=_dt.timezone.utc),
    )


class InfisicalAuth(abc.ABC):
    """An auth method; the client asks it for a token before every authenticated call."""

    #: Method name (``token``, ``universal-auth``, ``kubernetes-auth``, ``aws-auth``).
    kind: str = ""
    #: Whether a rejected token can be replaced by logging in again.
    refreshable: bool = False

    def __init__(self) -> None:
        self._runner: SyncRunner | AsyncRunner | None = None

    @property
    @abc.abstractmethod
    def token_kind(self) -> TokenKind:
        """Principal kind of the tokens this method produces."""

    def _bind(self, runner: SyncRunner | AsyncRunner) -> None:
        if self._runner is not None and self._runner is not runner:
            raise ConfigError(f"{self.kind}: this auth object is already bound to another client")
        self._runner = runner

    @abc.abstractmethod
    def valid_token(self, now: float) -> Secret | None:
        """The current token when it needs no refresh, else ``None`` (internal)."""

    @abc.abstractmethod
    def refresh_op(self, session: Session) -> Op[Secret]:
        """Obtain a fresh token (internal)."""

    def invalidate(self) -> None:  # noqa: B027 - optional hook, no-op for static tokens
        """Forget the current token (the next call logs in again)."""

    @abc.abstractmethod
    def known_secrets(self) -> list[str]:
        """Credential values to redact from errors."""

    def close_op(self, session: Session, revoke: bool) -> Op[None]:
        """Release the method (internal); login methods may revoke their token."""
        yield from ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}([REDACTED])"

    __str__ = __repr__


class TokenAuth(InfisicalAuth):
    """A static token: machine identity token (Token Auth), user JWT or legacy service token.

    ``kind`` overrides the detected :data:`TokenKind` (see :func:`detect_token_kind`).
    """

    kind = "token"
    refreshable = False

    def __init__(self, token: str | Secret, *, kind: TokenKind | None = None) -> None:
        super().__init__()
        if not isinstance(token, (str, Secret)) or not Secret(token).reveal().strip():
            raise ConfigError("TokenAuth: token must not be empty")
        self._token = Secret(token)
        self._kind: TokenKind = kind or detect_token_kind(self._token.reveal())

    @property
    def token_kind(self) -> TokenKind:
        return self._kind

    @property
    def token(self) -> Secret:
        """The static token."""
        return self._token

    def valid_token(self, now: float) -> Secret | None:
        return self._token

    def refresh_op(self, session: Session) -> Op[Secret]:
        yield from ()
        return self._token

    def known_secrets(self) -> list[str]:
        return [self._token.reveal()]

    def __repr__(self) -> str:
        return f"TokenAuth({self._kind}, [REDACTED])"

    __str__ = __repr__


class IdentityLoginAuth(InfisicalAuth):
    """Base of the login-based machine identity methods: login, renew, revoke and refresh."""

    refreshable = True
    #: Login path, e.g. ``/api/v1/auth/universal-auth/login``.
    login_path: str = ""

    def __init__(self) -> None:
        super().__init__()
        self._stored: _Stored | None = None

    @property
    def token_kind(self) -> TokenKind:
        return "identity"

    @property
    def access_token(self) -> AccessToken | None:
        """The current access token (``None`` before the first login or after revoke)."""
        return None if self._stored is None else self._stored.token

    @abc.abstractmethod
    def _login_body(self, session: Session) -> dict[str, Any]:
        """The login body without ``organizationSlug``."""

    # ----------------------------------------------------------------- operations
    def login_op(self, session: Session) -> Op[AccessToken]:
        """Log in and store the new token (internal)."""
        op = f"auth.{self.kind}.login"
        body = self._login_body(session)
        resp = yield Call(
            "POST",
            self.login_path,
            op,
            json=compact({**body, "organizationSlug": session.config.organization_slug}),
            auth=False,
            login=True,
        )
        now = session.clock()
        token = _parse_access_token(body_of(resp, op), op, now)
        self._stored = _Stored(token, now, now)
        return token

    def renew_op(self, session: Session) -> Op[AccessToken]:
        """Renew the current token and store the returned one (internal)."""
        op = f"auth.{self.kind}.renew"
        current = self._stored
        if current is None:
            raise AuthenticationError(f"{op}: no access token (login first)")
        resp = yield Call(
            "POST",
            "/api/v1/auth/token/renew",
            op,
            json={"accessToken": current.token.access_token.reveal()},
            auth=False,
            login=True,
        )
        now = session.clock()
        token = _parse_access_token(body_of(resp, op), op, now)
        self._stored = _Stored(token, now, current.login_at)
        return token

    def revoke_op(self, session: Session) -> Op[None]:
        """Revoke the current token (no-op without one) (internal)."""
        current = self._stored
        if current is None:
            return
        yield Call(
            "POST",
            "/api/v1/auth/token/revoke",
            f"auth.{self.kind}.revoke",
            json={"accessToken": current.token.access_token.reveal()},
            auth=False,
            login=True,
        )
        if self._stored is current:
            self._stored = None

    def valid_token(self, now: float) -> Secret | None:
        stored = self._stored
        if stored is None or stored.needs_refresh(now):
            return None
        return stored.token.access_token

    def refresh_op(self, session: Session) -> Op[Secret]:
        current = self._stored
        if current is not None:
            now = session.clock()
            max_left = (
                current.login_at + current.token.max_ttl_s - now
                if current.token.max_ttl_s > 0
                else float("inf")
            )
            if (
                max_left > current.token.expires_in_s * (1 - REFRESH_FACTOR)
                and now < current.expiry()
            ):
                try:
                    return (yield from self.renew_op(session)).access_token
                except ServiceError as err:
                    if err.code == ErrorCode.CANCELLED:
                        raise
                    # renewal failed (revoked, max TTL): log in again
        return (yield from self.login_op(session)).access_token

    def invalidate(self) -> None:
        self._stored = None

    def known_secrets(self) -> list[str]:
        return [] if self._stored is None else [self._stored.token.access_token.reveal()]

    def close_op(self, session: Session, revoke: bool) -> Op[None]:
        if revoke and self._stored is not None:
            with contextlib.suppress(ServiceError):
                yield from self.revoke_op(session)
        self._stored = None

    # ----------------------------------------------------------------- public facade
    def _sync(self) -> SyncRunner:
        if not isinstance(self._runner, SyncRunner):
            raise ConfigError(
                f"{self.kind}: pass this auth object to an InfisicalClient first "
                "(use alogin()/arenew()/arevoke() with AsyncInfisicalClient)"
            )
        return self._runner

    def _async(self) -> AsyncRunner:
        if not isinstance(self._runner, AsyncRunner):
            raise ConfigError(
                f"{self.kind}: pass this auth object to an AsyncInfisicalClient first "
                "(use login()/renew()/revoke() with InfisicalClient)"
            )
        return self._runner

    def login(self) -> AccessToken:
        """Log in (``POST <login_path>``) and store the new access token."""
        runner = self._sync()
        return runner.run(self.login_op(runner.session))

    def renew(self) -> AccessToken:
        """Renew the current token (``POST /api/v1/auth/token/renew``); store the returned one."""
        runner = self._sync()
        return runner.run(self.renew_op(runner.session))

    def revoke(self) -> None:
        """Revoke the current token (``POST /api/v1/auth/token/revoke``); no-op without one."""
        runner = self._sync()
        runner.run(self.revoke_op(runner.session))

    async def alogin(self) -> AccessToken:
        """Async :meth:`login`."""
        runner = self._async()
        return await runner.run(self.login_op(runner.session))

    async def arenew(self) -> AccessToken:
        """Async :meth:`renew`."""
        runner = self._async()
        return await runner.run(self.renew_op(runner.session))

    async def arevoke(self) -> None:
        """Async :meth:`revoke`."""
        runner = self._async()
        await runner.run(self.revoke_op(runner.session))


class UniversalAuth(IdentityLoginAuth):
    """Universal Auth (client id + client secret): ``POST /api/v1/auth/universal-auth/login``."""

    kind = "universal-auth"
    login_path = "/api/v1/auth/universal-auth/login"

    def __init__(self, client_id: str, client_secret: str | Secret) -> None:
        super().__init__()
        try:
            self.client_id = require_text(client_id, "client_id", "UniversalAuth")
        except ValidationError as err:
            raise ConfigError(err.message) from None
        if not isinstance(client_secret, (str, Secret)) or not Secret(client_secret).reveal():
            raise ConfigError("UniversalAuth: client_secret must not be empty")
        self._client_secret = Secret(client_secret)

    def _login_body(self, session: Session) -> dict[str, Any]:
        return {"clientId": self.client_id, "clientSecret": self._client_secret.reveal()}

    def known_secrets(self) -> list[str]:
        return [*super().known_secrets(), self._client_secret.reveal()]


class KubernetesAuth(IdentityLoginAuth):
    """Kubernetes Auth: ``POST /api/v1/auth/kubernetes-auth/login`` with a service-account JWT.

    Without ``jwt`` the token is read from ``jwt_path`` at every login.
    """

    kind = "kubernetes-auth"
    login_path = "/api/v1/auth/kubernetes-auth/login"

    def __init__(
        self,
        identity_id: str,
        *,
        jwt: str | Secret | None = None,
        jwt_path: str = KUBERNETES_TOKEN_PATH,
    ) -> None:
        super().__init__()
        if not isinstance(identity_id, str) or not identity_id.strip():
            raise ConfigError("KubernetesAuth: identity_id must not be empty")
        self.identity_id = identity_id
        self.jwt_path = jwt_path
        self._jwt = Secret(jwt) if jwt else None

    def _login_body(self, session: Session) -> dict[str, Any]:
        if self._jwt is not None:
            jwt = self._jwt.reveal()
        else:
            try:
                jwt = Path(self.jwt_path).read_text(encoding="utf-8").strip()
            except OSError:
                raise ConfigError(
                    "KubernetesAuth: cannot read the service-account token file"
                ) from None
        return {"identityId": self.identity_id, "jwt": jwt}

    def known_secrets(self) -> list[str]:
        own = [] if self._jwt is None else [self._jwt.reveal()]
        return [*super().known_secrets(), *own]


@dataclasses.dataclass(frozen=True)
class AwsCredentials:
    """AWS credentials used to sign the STS request (``repr`` hides the secrets)."""

    access_key_id: str
    secret_access_key: str | Secret
    session_token: str | Secret | None = None

    def __post_init__(self) -> None:
        if isinstance(self.secret_access_key, str):
            object.__setattr__(self, "secret_access_key", Secret(self.secret_access_key))
        if isinstance(self.session_token, str):
            token = Secret(self.session_token) if self.session_token else None
            object.__setattr__(self, "session_token", token)


@dataclasses.dataclass(frozen=True)
class AwsLoginRequest:
    """The signed fields of an AWS IAM login body."""

    identity_id: str
    iam_http_request_method: str
    #: base64 of :data:`STS_BODY`.
    iam_request_body: str
    #: base64 of the JSON of the SigV4-signed headers.
    iam_request_headers: str = dataclasses.field(repr=False)

    def to_json(self) -> dict[str, str]:
        """The wire form (camelCase)."""
        return {
            "identityId": self.identity_id,
            "iamHttpRequestMethod": self.iam_http_request_method,
            "iamRequestBody": self.iam_request_body,
            "iamRequestHeaders": self.iam_request_headers,
        }


class AwsIamAuth(IdentityLoginAuth):
    """AWS IAM Auth: signs ``sts:GetCallerIdentity`` (SigV4) and posts it to
    ``/api/v1/auth/aws-auth/login``.

    ``region`` defaults to ``AWS_REGION``, ``AWS_DEFAULT_REGION``, then ``us-east-1``;
    ``credentials`` (an :class:`AwsCredentials` or a callable returning one, e.g. a wrapper of
    the boto3 credential chain) default to ``AWS_ACCESS_KEY_ID``/``AWS_SECRET_ACCESS_KEY``/
    ``AWS_SESSION_TOKEN``. ``env`` replaces ``os.environ`` for these defaults.
    """

    kind = "aws-auth"
    login_path = "/api/v1/auth/aws-auth/login"

    def __init__(
        self,
        identity_id: str,
        *,
        region: str | None = None,
        credentials: AwsCredentials | Callable[[], AwsCredentials] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__()
        if not isinstance(identity_id, str) or not identity_id.strip():
            raise ConfigError("AwsIamAuth: identity_id must not be empty")
        self.identity_id = identity_id
        self._env: Mapping[str, str] = os.environ if env is None else env
        self.region = (
            region
            or self._env.get("AWS_REGION")
            or self._env.get("AWS_DEFAULT_REGION")
            or "us-east-1"
        )
        self._credentials = credentials
        self._last_secrets: list[str] = []

    def _resolve_credentials(self) -> AwsCredentials:
        creds = self._credentials
        if callable(creds):
            return creds()
        if creds is not None:
            return creds
        key_id = self._env.get("AWS_ACCESS_KEY_ID")
        secret = self._env.get("AWS_SECRET_ACCESS_KEY")
        if not key_id or not secret:
            raise ConfigError(
                "AwsIamAuth: no AWS credentials (pass credentials or set "
                "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"
            )
        session_token = self._env.get("AWS_SESSION_TOKEN") or None
        return AwsCredentials(
            key_id, Secret(secret), Secret(session_token) if session_token else None
        )

    def build_login_request(self, date: _dt.datetime | None = None) -> AwsLoginRequest:
        """Build the signed login body for ``date`` (default now; exposed for tests)."""
        creds = self._resolve_credentials()
        secret_key = Secret(creds.secret_access_key).reveal()
        session = Secret(creds.session_token).reveal() if creds.session_token else None
        self._last_secrets = [secret_key, *([session] if session else [])]
        host = f"sts.{self.region}.amazonaws.com"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "Host": host,
        }
        if session:
            headers["X-Amz-Security-Token"] = session
        signed = sign_aws_request(
            method="POST",
            host=host,
            path="/",
            region=self.region,
            service="sts",
            headers=headers,
            body=STS_BODY,
            access_key_id=creds.access_key_id,
            secret_access_key=secret_key,
            date=date or _dt.datetime.now(_dt.timezone.utc),
        )
        return AwsLoginRequest(
            identity_id=self.identity_id,
            iam_http_request_method="POST",
            iam_request_body=base64.b64encode(STS_BODY.encode()).decode("ascii"),
            iam_request_headers=base64.b64encode(
                json.dumps(signed, separators=(",", ":")).encode()
            ).decode("ascii"),
        )

    def _login_body(self, session: Session) -> dict[str, Any]:
        now = _dt.datetime.fromtimestamp(session.clock(), tz=_dt.timezone.utc)
        return self.build_login_request(now).to_json()

    def known_secrets(self) -> list[str]:
        return [*super().known_secrets(), *self._last_secrets]


# --------------------------------------------------------------------------- SigV4


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _hmac(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def _canonical_query(query: str) -> str:
    pairs = []
    for part in query.split("&"):
        if not part:
            continue
        key, _, value = part.partition("=")
        pairs.append((key, value))
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def sign_aws_request(
    *,
    method: str,
    host: str,
    path: str,
    region: str,
    service: str,
    headers: Mapping[str, str],
    body: str,
    access_key_id: str,
    secret_access_key: str,
    date: _dt.datetime,
    query: str = "",
) -> dict[str, str]:
    """Sign a request with AWS Signature Version 4.

    Returns the headers to send: ``headers`` plus ``Host`` (when missing), ``X-Amz-Date`` and
    ``Authorization``. ``path`` is already URI-encoded; ``query`` is the raw query string.
    """
    if not access_key_id or not secret_access_key:
        raise ValidationError("sign_aws_request: credentials must not be empty")
    when = date if date.tzinfo else date.replace(tzinfo=_dt.timezone.utc)
    amz_date = when.astimezone(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    day = amz_date[:8]
    out = dict(headers)
    if not any(k.lower() == "host" for k in out):
        out["Host"] = host
    out["X-Amz-Date"] = amz_date
    canon = sorted((k.lower(), " ".join(v.strip().split())) for k, v in out.items())
    signed_headers = ";".join(k for k, _ in canon)
    canonical_request = "\n".join(
        [
            method.upper(),
            path,
            _canonical_query(query),
            "".join(f"{k}:{v}\n" for k, v in canon),
            signed_headers,
            _sha256_hex(body),
        ]
    )
    scope = f"{day}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, _sha256_hex(canonical_request)]
    )
    key = _hmac(f"AWS4{secret_access_key}".encode(), day)
    key = _hmac(key, region)
    key = _hmac(key, service)
    key = _hmac(key, "aws4_request")
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return out
