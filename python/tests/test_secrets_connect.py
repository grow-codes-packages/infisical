"""Connector of ``load_config()`` (service-owned: generated once by sdk-kit)."""

from __future__ import annotations

import grow_infisical as sdk
from _support import MockServer, Reply
from grow_infisical.secrets_connect import connect_secrets
from infisical_support import PROJECT, secret_body


def test_connect_secrets_returns_the_provider() -> None:
    connection = connect_secrets(
        sdk.SecretsBootstrap(addr="http://127.0.0.1:1"),
        {"GROW_INFISICAL_TOKEN": "t", "GROW_INFISICAL_PROJECT_ID": PROJECT},
    )
    try:
        assert isinstance(connection.provider, sdk.InfisicalSecretsProvider)
        assert callable(connection.provider.get_all)
    finally:
        assert connection.close is not None
        connection.close()


def test_load_config_through_the_connector(server: MockServer) -> None:
    """GRO-1410: ``load_config()`` with the default connector reads the bootstrap path."""
    path = "/services/orders"
    server.enqueue(
        "/api/v4/secrets",
        Reply(
            body={
                "secrets": [
                    secret_body("DATABASE_URL", "postgres://db", path=path),
                    secret_body("LOG_LEVEL", "debug", path=path),
                ],
                "imports": [],
            }
        ),
    )
    env = {
        "GROW_SECRETS_PROVIDER": "infisical",
        "GROW_SECRETS_ADDR": server.url,
        "GROW_SECRETS_PATH": "services/orders",
        "GROW_INFISICAL_URL": "http://127.0.0.1:1",
        "GROW_INFISICAL_TOKEN": "identity-token-value",
        "GROW_INFISICAL_PROJECT_ID": PROJECT,
        "GROW_INFISICAL_ENVIRONMENT": "dev",
        "GROW_INFISICAL_MAX_RETRIES": "0",
    }
    values = sdk.load_config(["DATABASE_URL"], env=env)
    assert values == {"DATABASE_URL": "postgres://db", "LOG_LEVEL": "debug"}
    assert env["DATABASE_URL"] == "postgres://db"
    assert env["LOG_LEVEL"] == "debug"
    listed = [s for s in server.seen if s.path.startswith("/api/v4/secrets")]
    assert listed and "secretPath=%2Fservices%2Forders" in listed[0].path
    assert f"projectId={PROJECT}" in listed[0].path
