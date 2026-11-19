"""InfisicalConfig: env precedence, vendor aliases, validation, redaction."""

from __future__ import annotations

import pytest

import grow_infisical as sdk
from grow_infisical.client import resolve_auth


def test_core_config_env_precedence() -> None:
    """core.config.env-precedence"""
    env = {
        "GROW_INFISICAL_URL": "http://grow:8080",
        "INFISICAL_API_URL": "http://vendor:8080/api",
        "GROW_INFISICAL_PROJECT_ID": "p-grow",
        "INFISICAL_PROJECT_ID": "p-vendor",
        "INFISICAL_ENVIRONMENT": "staging",
        "INFISICAL_TOKEN": "vendor-token-1",
        "GROW_INFISICAL_SECRET_PATH": "/app",
    }
    cfg = sdk.InfisicalConfig.from_env(env)
    assert cfg.url == "http://grow:8080"
    assert cfg.project_id == "p-grow"
    assert cfg.environment == "staging"
    assert cfg.token is not None and cfg.token.reveal() == "vendor-token-1"
    assert cfg.secret_path == "/app"
    explicit = sdk.InfisicalConfig.from_env(env, project_id="p-explicit")
    assert explicit.project_id == "p-explicit"
    with pytest.raises(sdk.ConfigError) as info:
        sdk.InfisicalConfig.from_env({"GROW_INFISICAL_REQUEST_TIMEOUT": "soon-ish"})
    assert "GROW_INFISICAL_REQUEST_TIMEOUT" in str(info.value)
    assert "soon-ish" not in str(info.value)


def test_vendor_url_strips_api_suffix_and_cli_aliases() -> None:
    cfg = sdk.InfisicalConfig.from_env(
        {
            "INFISICAL_API_URL": "https://app.example.com/api/",
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "cid",
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "csecret-123",
        }
    )
    assert cfg.url == "https://app.example.com"
    assert cfg.client_id == "cid"
    assert cfg.client_secret is not None and cfg.client_secret.reveal() == "csecret-123"
    assert isinstance(resolve_auth(cfg), sdk.UniversalAuth)
    grow = sdk.InfisicalConfig.from_env({"GROW_INFISICAL_URL": "http://x:1/api"})
    assert grow.url == "http://x:1/api"  # only the vendor value is rewritten
    assert sdk.InfisicalConfig.from_env({}).url == sdk.DEFAULT_URL


def test_auth_selection_order() -> None:
    ua = sdk.UniversalAuth("id", "secret-1")
    assert resolve_auth(sdk.InfisicalConfig(auth=ua, token="t-1")) is ua
    assert isinstance(
        resolve_auth(sdk.InfisicalConfig(token="t-1", client_id="a", client_secret="b")),
        sdk.TokenAuth,
    )
    assert resolve_auth(sdk.InfisicalConfig()) is None


@pytest.mark.parametrize(
    ("kw", "fragment"),
    [
        ({"token": "  "}, "token must not be blank"),
        ({"client_id": "only-id"}, "together"),
        ({"client_id": "a", "client_secret": " "}, "client_secret must not be blank"),
        ({"secret_path": "app"}, "secret_path"),
        ({"api_version": "v9"}, "api_version"),
    ],
)
def test_validate(kw: dict[str, str], fragment: str) -> None:
    with pytest.raises(sdk.ConfigError, match=fragment):
        sdk.InfisicalConfig(**kw).validate()  # type: ignore[arg-type]


def test_core_redaction_config() -> None:
    """core.redaction.config"""
    cfg = sdk.InfisicalConfig(
        token="tok-secret-1",
        client_id="cid",
        client_secret="cs-secret-2",
        auth=sdk.UniversalAuth("cid", "ua-secret-3"),
        project_id="",
    )
    text = repr(cfg) + str(cfg)
    for secret in ("tok-secret-1", "cs-secret-2", "ua-secret-3"):
        assert secret not in text
        assert secret in cfg.known_secrets()
    assert cfg.project_id is None
    assert isinstance(cfg.token, sdk.Secret)


def test_api_version_and_revoke_on_close_from_env() -> None:
    cfg = sdk.InfisicalConfig.from_env(
        {"GROW_INFISICAL_API_VERSION": "V3", "GROW_INFISICAL_REVOKE_ON_CLOSE": "true"}
    )
    assert cfg.api_version == "v3"
    assert cfg.revoke_on_close is True
    assert sdk.InfisicalConfig(api_version="").api_version == "auto"  # type: ignore[arg-type]
    with pytest.raises(sdk.ConfigError):
        sdk.InfisicalConfig.from_env({"GROW_INFISICAL_API_VERSION": "v9"})
