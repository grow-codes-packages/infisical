"""Auth methods against the real service: Universal Auth login/renew/revoke, automatic re-login,
static tokens, and the Kubernetes / AWS IAM request shapes (no Kubernetes / STS available)."""

from __future__ import annotations

import asyncio

import pytest
from factories import async_core_client, core_client, token_client

import grow_infisical as sdk


def test_universal_auth_login_renew_revoke(env: dict[str, str]) -> None:
    ua = sdk.UniversalAuth(env["INFISICAL_CLIENT_ID"], env["INFISICAL_CLIENT_SECRET"])
    with core_client(env, auth=ua) as c:
        first = ua.login()
        assert first.expires_in_s > 0
        assert first.token_type == "Bearer"  # noqa: S105
        assert c.ping() >= 0
        renewed = ua.renew()
        assert renewed.access_token.reveal()
        assert ua.access_token is renewed
        old = renewed.access_token.reveal()
        ua.revoke()
        assert ua.access_token is None
        # a revoked token is rejected by the server...
        with token_client(env, old) as stale, pytest.raises(sdk.AuthenticationError):
            stale.ping()
        # ...but the client logs in again on its own
        assert c.ping() >= 0
        assert ua.access_token is not None


def test_relogin_after_server_side_revoke(env: dict[str, str]) -> None:
    with core_client(env) as c:
        c.ping()
        auth = c.auth
        assert isinstance(auth, sdk.UniversalAuth)
        assert auth.access_token is not None
        revoker = sdk.UniversalAuth(env["INFISICAL_CLIENT_ID"], env["INFISICAL_CLIENT_SECRET"])
        with core_client(env, auth=revoker):
            revoker.login()
        # revoke the first client's token from outside: the next call gets 401 and re-logs in
        c.request(
            sdk.Request(
                "POST",
                "/api/v1/auth/token/revoke",
                json={"accessToken": auth.access_token.access_token.reveal()},
            )
        )
        assert c.secrets.get_secret(env["INFISICAL_SEED_SECRET_NAME"]).value.reveal()


def test_revoke_on_close(env: dict[str, str]) -> None:
    c = core_client(env, revoke_on_close=True)
    c.ping()
    auth = c.auth
    assert isinstance(auth, sdk.UniversalAuth)
    assert auth.access_token is not None
    token = auth.access_token.access_token.reveal()
    c.close()
    with token_client(env, token) as stale, pytest.raises(sdk.AuthenticationError):
        stale.ping()


def test_async_universal_auth(env: dict[str, str]) -> None:
    async def run() -> None:
        ua = sdk.UniversalAuth(env["INFISICAL_CLIENT_ID"], env["INFISICAL_CLIENT_SECRET"])
        async with async_core_client(env, auth=ua) as c:
            await ua.alogin()
            assert (await ua.arenew()).expires_in_s > 0
            await ua.arevoke()
            assert await c.ping() >= 0

    asyncio.run(run())


@pytest.mark.parametrize(
    "token_var", ["INFISICAL_VIEWER_TOKEN", "INFISICAL_SERVICE_TOKEN", "INFISICAL_USER_TOKEN"]
)
def test_token_auth_reads_seed_secret(env: dict[str, str], token_var: str) -> None:
    with token_client(env, env[token_var]) as c:
        seed = c.secrets.get_secret(env["INFISICAL_SEED_SECRET_NAME"])
        assert seed.value.reveal() == env["INFISICAL_SEED_SECRET_VALUE"]


def test_viewer_cannot_write(env: dict[str, str]) -> None:
    with token_client(env, env["INFISICAL_VIEWER_TOKEN"]) as c:
        with pytest.raises(sdk.PermissionDeniedError):
            c.secrets.create_secret("SDK_VIEWER_DENIED", "x")
        with pytest.raises(sdk.PermissionDeniedError):
            c.projects.create_environment("Denied", "denied")


def test_kubernetes_auth_request_shape(env: dict[str, str]) -> None:
    k8s = sdk.KubernetesAuth(env["INFISICAL_NOACCESS_IDENTITY_ID"], jwt="not-a-real-sa-jwt")
    with core_client(env, auth=k8s), pytest.raises(sdk.NotFoundError) as info:
        k8s.login()
    assert "Kubernetes auth method not found" in info.value.message


def test_aws_iam_auth_request_shape(env: dict[str, str]) -> None:
    aws = sdk.AwsIamAuth(
        env["INFISICAL_NOACCESS_IDENTITY_ID"],
        region="us-east-1",
        credentials=sdk.AwsCredentials("AKIDEXAMPLE", "not-a-real-secret-key"),
    )
    with core_client(env, auth=aws), pytest.raises(sdk.NotFoundError) as info:
        aws.login()
    assert "AWS auth method not found" in info.value.message
