"""Auth methods: Universal Auth login/renew/revoke, refresh, re-login, Kubernetes, AWS SigV4."""

from __future__ import annotations

import base64
import datetime as _dt
import json
from pathlib import Path

import pytest

import grow_infisical as sdk
from infisical_support import (
    Clock,
    Router,
    aclient,
    client,
    error_body,
    fixture,
    login_ok,
    reply,
)

UA_LOGIN = "/api/v1/auth/universal-auth/login"
RENEW = "/api/v1/auth/token/renew"
REVOKE = "/api/v1/auth/token/revoke"
DETAILS = "/api/v1/identities/details"


def ua_router() -> Router:
    return Router().add("GET", DETAILS, "ping.identity")


def test_universal_auth_login_on_first_call_without_bearer() -> None:
    router = ua_router().add("POST", UA_LOGIN, login_ok("ua-token-1"))
    with client(router, client_id="cid", client_secret="cs-secret-1", organization_slug="org") as c:
        c.ping()
        login = router.last("POST", UA_LOGIN)
        assert "authorization" not in login.headers
        assert login.json == {
            "clientId": "cid",
            "clientSecret": "cs-secret-1",
            "organizationSlug": "org",
        }
        assert router.last("GET", DETAILS).headers["authorization"] == "Bearer ua-token-1"
        auth = c.auth
        assert isinstance(auth, sdk.UniversalAuth)
        assert auth.access_token is not None
        assert auth.access_token.expires_in_s == 300 and auth.access_token.max_ttl_s == 3600
        assert "ua-token-1" not in repr(auth.access_token)
        assert "cs-secret-1" not in repr(auth) and "ua-token-1" in auth.known_secrets()
        c.ping()
    assert len(router.calls("POST", UA_LOGIN)) == 1


def test_renew_at_80_percent_then_relogin_at_max_ttl() -> None:
    clock = Clock()
    router = (
        ua_router()
        .add("POST", UA_LOGIN, login_ok("t1", 100, 150), login_ok("t3", 100, 150))
        .add("POST", RENEW, login_ok("t2", 100, 150))
    )
    with client(router, client_id="cid", client_secret="cs", clock=clock) as c:
        c.ping()
        clock.now += 79
        c.ping()
        assert not router.calls("POST", RENEW)
        clock.now += 2  # 81 % of the lifetime → renew
        c.ping()
        assert router.last("POST", RENEW).json == {"accessToken": "t1"}
        assert "authorization" not in router.last("POST", RENEW).headers
        assert router.last("GET", DETAILS).headers["authorization"] == "Bearer t2"
        clock.now += 60  # 141 s after login: max TTL (150) nearly reached → login again
        c.ping()
    assert len(router.calls("POST", UA_LOGIN)) == 2
    assert router.last("GET", DETAILS).headers["authorization"] == "Bearer t3"


def test_failed_renew_falls_back_to_login() -> None:
    clock = Clock()
    router = (
        ua_router()
        .add("POST", UA_LOGIN, login_ok("t1"), login_ok("t2"))
        .add("POST", RENEW, "universalAuth.renew.revoked")
    )
    with client(router, client_id="cid", client_secret="cs", clock=clock) as c:
        c.ping()
        clock.now += 250
        c.ping()
    assert len(router.calls("POST", UA_LOGIN)) == 2


def test_401_triggers_one_relogin_and_retry() -> None:
    router = (
        Router()
        .add("POST", UA_LOGIN, login_ok("t1"), login_ok("t2"))
        .add("GET", DETAILS, "auth.revokedToken", "ping.identity")
    )
    with client(router, client_id="cid", client_secret="cs") as c:
        c.ping()
    assert [s.headers["authorization"] for s in router.calls("GET", DETAILS)] == [
        "Bearer t1",
        "Bearer t2",
    ]


def test_static_token_401_is_not_retried() -> None:
    router = Router().add("GET", DETAILS, "auth.revokedToken")
    with client(router) as c, pytest.raises(sdk.AuthenticationError):
        c.ping()
    assert len(router.calls("GET", DETAILS)) == 1


@pytest.mark.parametrize(
    "name",
    [
        "universalAuth.login.401",
        "universalAuth.login.lockedOut401",
        "universalAuth.login.withBearer403",
        "universalAuth.login.unknownClient401",
    ],
)
def test_login_errors_are_authentication(name: str) -> None:
    router = Router().add("POST", UA_LOGIN, name)
    with client(router, client_id="cid", client_secret="cs-secret-xyz") as c:
        with pytest.raises(sdk.AuthenticationError) as info:
            c.ping()
        assert "cs-secret-xyz" not in str(info.value)
        assert info.value.request_id == fixture(name)["body"]["reqId"]


def test_login_422_and_bad_body() -> None:
    router = Router().add("POST", UA_LOGIN, "universalAuth.login.422")
    with (
        client(router, client_id="cid", client_secret="cs") as c,
        pytest.raises(sdk.ValidationError),
    ):
        c.auth.login()  # type: ignore[union-attr]
    router = Router().add("POST", UA_LOGIN, reply(200, {"expiresIn": 1}))
    with (
        client(router, client_id="cid", client_secret="cs") as c,
        pytest.raises(sdk.UnavailableError),
    ):
        c.auth.login()  # type: ignore[union-attr]


def test_explicit_login_renew_revoke_and_revoke_on_close() -> None:
    router = (
        Router()
        .add("POST", UA_LOGIN, "universalAuth.login.ok")
        .add("POST", RENEW, "universalAuth.renew.ok")
        .add("POST", REVOKE, "universalAuth.revoke.ok")
    )
    ua = sdk.UniversalAuth("cid", "cs")
    c = client(router, auth=ua, revoke_on_close=True)
    assert c.auth is ua
    with pytest.raises(sdk.AuthenticationError, match="login first"):
        ua.renew()
    ua.revoke()  # no token: no call
    assert not router.calls("POST", REVOKE)
    token = ua.login()
    assert token.token_type == "Bearer"
    renewed = ua.renew()
    assert renewed.expires_in_s > 0
    ua.revoke()
    assert ua.access_token is None
    ua.login()
    c.close()
    assert len(router.calls("POST", REVOKE)) == 2
    assert ua.access_token is None
    with pytest.raises(sdk.ConfigError, match="alogin"):
        sdk.UniversalAuth("a", "b").login()
    with pytest.raises(sdk.ConfigError, match="already bound"):
        client(router, auth=ua)


def test_revoke_on_close_ignores_errors() -> None:
    router = (
        Router()
        .add("POST", UA_LOGIN, login_ok())
        .add("POST", REVOKE, error_body(500, "boom", "InternalServerError"))
    )
    ua = sdk.UniversalAuth("cid", "cs")
    c = client(router, auth=ua, revoke_on_close=True)
    ua.login()
    c.close()
    assert ua.access_token is None


async def test_async_auth_facade() -> None:
    router = (
        ua_router()
        .add("POST", UA_LOGIN, login_ok("a1"))
        .add("POST", RENEW, login_ok("a2"))
        .add("POST", REVOKE, "universalAuth.revoke.ok")
    )
    ua = sdk.UniversalAuth("cid", "cs")
    async with aclient(router, auth=ua) as c:
        await c.ping()
        assert (await ua.arenew()).access_token.reveal() == "a2"
        await ua.arevoke()
        await ua.alogin()
        with pytest.raises(sdk.ConfigError, match="login\\(\\)"):
            await sdk.UniversalAuth("x", "y").alogin()
    with pytest.raises(sdk.ConfigError):
        ua.login()


async def test_async_401_relogin() -> None:
    router = (
        Router()
        .add("POST", UA_LOGIN, login_ok("t1"), login_ok("t2"))
        .add("GET", DETAILS, "auth.revokedToken", "ping.identity")
    )
    async with aclient(router, client_id="cid", client_secret="cs") as c:
        await c.ping()
        await c.ping()
    assert len(router.calls("POST", UA_LOGIN)) == 2


def test_constructor_validation() -> None:
    with pytest.raises(sdk.ConfigError):
        sdk.UniversalAuth("", "x")
    with pytest.raises(sdk.ConfigError):
        sdk.UniversalAuth("id", "")
    with pytest.raises(sdk.ConfigError):
        sdk.TokenAuth(" ")
    with pytest.raises(sdk.ConfigError):
        sdk.KubernetesAuth("")
    with pytest.raises(sdk.ConfigError):
        sdk.AwsIamAuth(" ")


def test_token_kinds() -> None:
    assert sdk.detect_token_kind("st.a.b") == "serviceToken"
    user = (
        "h."
        + base64.urlsafe_b64encode(b'{"authTokenType":"accessToken"}').decode().rstrip("=")
        + ".s"
    )
    assert sdk.detect_token_kind(user) == "user"
    ident = (
        "h." + base64.urlsafe_b64encode(b'{"authTokenType":"identityAccessToken"}').decode() + ".s"
    )
    assert sdk.detect_token_kind(ident) == "identity"
    assert sdk.detect_token_kind("a.!!!.c") == "identity"
    assert sdk.detect_token_kind("opaque") == "identity"
    auth = sdk.TokenAuth("st.x.y", kind="user")
    assert auth.token_kind == "user" and auth.token.reveal() == "st.x.y"
    assert "st.x.y" not in repr(auth) and not auth.refreshable
    auth.invalidate()


def test_kubernetes_auth(tmp_path: Path) -> None:
    jwt_file = tmp_path / "token"
    jwt_file.write_text("sa-jwt-from-file\n")
    login = "/api/v1/auth/kubernetes-auth/login"
    router = Router().add("POST", login, login_ok("k1"))
    k8s = sdk.KubernetesAuth("ident-1", jwt_path=str(jwt_file))
    with client(router, auth=k8s):
        assert k8s.login().access_token.reveal() == "k1"
    assert router.last("POST", login).json == {"identityId": "ident-1", "jwt": "sa-jwt-from-file"}
    inline = sdk.KubernetesAuth("ident-2", jwt="inline-jwt-123")
    assert "inline-jwt-123" in inline.known_secrets()
    router2 = Router().add("POST", login, "kubernetesAuth.login.notConfigured")
    with client(router2, auth=inline), pytest.raises(sdk.NotFoundError):
        inline.login()
    missing = sdk.KubernetesAuth("ident-3", jwt_path=str(tmp_path / "nope"))
    with client(router, auth=missing), pytest.raises(sdk.ConfigError, match="token file"):
        missing.login()
    assert sdk.KUBERNETES_TOKEN_PATH.endswith("serviceaccount/token")


def test_sigv4_aws_documentation_vector() -> None:
    """The AWS SigV4 test vector (IAM ListUsers, 2015-08-30)."""
    headers = sdk.sign_aws_request(
        method="GET",
        host="iam.amazonaws.com",
        path="/",
        query="Version=2010-05-08&Action=ListUsers",
        region="us-east-1",
        service="iam",
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
        body="",
        access_key_id="AKIDEXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        date=_dt.datetime(2015, 8, 30, 12, 36, 0),
    )
    assert headers["X-Amz-Date"] == "20150830T123600Z"
    assert headers["Host"] == "iam.amazonaws.com"
    assert headers["Authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-date, "
        "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    )
    with pytest.raises(sdk.ValidationError):
        sdk.sign_aws_request(
            method="GET",
            host="h",
            path="/",
            region="r",
            service="s",
            headers={},
            body="",
            access_key_id="",
            secret_access_key="x",
            date=_dt.datetime.now(_dt.timezone.utc),
        )


def test_aws_iam_auth_login_body() -> None:
    clock = Clock(1_440_938_160.0)  # 2015-08-30T12:36:00Z
    login = "/api/v1/auth/aws-auth/login"
    router = Router().add("POST", login, login_ok("aws-1"))
    aws = sdk.AwsIamAuth(
        "ident-aws",
        region="eu-central-1",
        credentials=sdk.AwsCredentials("AKIDEXAMPLE", "aws-secret-key-1", "aws-session-1"),
    )
    with client(router, auth=aws, clock=clock):
        aws.login()
    body = router.last("POST", login).json
    assert body["identityId"] == "ident-aws" and body["iamHttpRequestMethod"] == "POST"
    assert base64.b64decode(body["iamRequestBody"]).decode() == sdk.STS_BODY
    signed = json.loads(base64.b64decode(body["iamRequestHeaders"]))
    assert signed["Host"] == "sts.eu-central-1.amazonaws.com"
    assert signed["X-Amz-Date"] == "20150830T123600Z"
    assert signed["X-Amz-Security-Token"] == "aws-session-1"
    assert "eu-central-1/sts/aws4_request" in signed["Authorization"]
    assert {"aws-secret-key-1", "aws-session-1"} <= set(aws.known_secrets())
    req = aws.build_login_request()
    assert "iam_request_headers" not in repr(req)


def test_aws_credentials_from_env_and_callable() -> None:
    env = {
        "AWS_DEFAULT_REGION": "us-west-2",
        "AWS_ACCESS_KEY_ID": "AKID",
        "AWS_SECRET_ACCESS_KEY": "s",
    }
    aws = sdk.AwsIamAuth("i", env=env)
    assert aws.region == "us-west-2"
    req = aws.build_login_request(_dt.datetime(2020, 1, 1, tzinfo=_dt.timezone.utc))
    signed = json.loads(base64.b64decode(req.iam_request_headers))
    assert "X-Amz-Security-Token" not in signed
    called = sdk.AwsIamAuth("i", env={}, credentials=lambda: sdk.AwsCredentials("K", "S", ""))
    assert called.region == "us-east-1"
    assert called.build_login_request().iam_http_request_method == "POST"
    with pytest.raises(sdk.ConfigError, match="no AWS credentials"):
        sdk.AwsIamAuth("i", env={}).build_login_request()
    router = Router().add("POST", "/api/v1/auth/aws-auth/login", "awsIamAuth.login.notConfigured")
    aws2 = sdk.AwsIamAuth("i", env=env)
    with client(router, auth=aws2), pytest.raises(sdk.NotFoundError):
        aws2.login()
