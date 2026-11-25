"""Connector used by ``load_config()``.

Service-owned: generated once by sdk-kit, then maintained in this repository. It builds a client
from the ``GROW_SECRETS_*`` bootstrap and the package's own environment variables and returns the
provider to read the config keys from.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._secrets.load_config import SecretsBootstrap, SecretsConnection
from .client import InfisicalClient


def connect_secrets(bootstrap: SecretsBootstrap, env: Mapping[str, str]) -> SecretsConnection:
    """Build ``InfisicalClient.from_env(env)`` and return its ``provider``.

    The client reads ``GROW_INFISICAL_*`` / ``INFISICAL_*`` (Universal Auth included) from ``env``;
    ``GROW_SECRETS_ADDR`` overrides the URL when set. ``client.provider`` is the ``SecretsProvider``
    for the configured project and environment (``client.secrets`` is the raw secrets API module).
    """
    overrides: dict[str, Any] = {} if bootstrap.addr is None else {"url": bootstrap.addr}
    client = InfisicalClient.from_env(env, **overrides)
    return SecretsConnection(provider=client.provider, close=client.close)
