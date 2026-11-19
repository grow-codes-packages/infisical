"""Factories the integration suite and the conformance runner use (owned by this repository).

The bootstrap env file (``/bootstrap/env``) provides ``INFISICAL_CLIENT_ID``/``_SECRET`` (a
Universal Auth identity with project admin rights), ``INFISICAL_PROJECT_ID`` and
``INFISICAL_ENVIRONMENT`` (``dev``), so ``from_env`` resolves to Universal Auth.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import grow_infisical as sdk

URL_VAR = "GROW_INFISICAL_URL"

#: Capabilities of the deployment under test for the core scenarios. Infisical exposes no
#: running version over HTTP, so "version" (serverVersion) is not declared (DECISIONS #2).
CORE_CAPABILITIES: set[str] = set()


def core_client(env: Mapping[str, str], **overrides: Any) -> sdk.InfisicalClient:
    """A client configured from the test environment (URL, Universal Auth, project, env)."""
    return sdk.InfisicalClient.from_env(env, **overrides)


def async_core_client(env: Mapping[str, str], **overrides: Any) -> sdk.AsyncInfisicalClient:
    return sdk.AsyncInfisicalClient.from_env(env, **overrides)


def token_client(env: Mapping[str, str], token: str, **overrides: Any) -> sdk.InfisicalClient:
    """A client that authenticates with a static token only (no Universal Auth)."""
    return sdk.InfisicalClient.from_env(env, auth=sdk.TokenAuth(token), **overrides)


#: Capabilities for the secrets scenarios: write, delete, versions (get by version).
SECRETS_CAPABILITIES: set[str] = {"write", "delete", "versions"}


def secrets_provider(client: sdk.InfisicalClient) -> sdk.SecretsProvider | None:
    """The Infisical ``SecretsProvider`` of ``client`` (configured project + environment)."""
    return client.provider  # type: ignore[return-value]
