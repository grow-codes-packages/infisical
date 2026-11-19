"""Configuration for the Infisical client (service-owned)."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar, Literal, TypeVar

from ._core import BaseConfig, ConfigError, EnvReader, Secret
from ._core.redaction import safe_repr

if TYPE_CHECKING:
    from .auth import InfisicalAuth

__all__ = ["DEFAULT_URL", "VENDOR_ENV", "ApiVersionSetting", "InfisicalConfig"]

#: Default endpoint when neither the config nor the environment sets one.
DEFAULT_URL = "http://127.0.0.1:8080"

#: Vendor variables read after ``GROW_INFISICAL_*``, in order (SPEC §2.2, DECISIONS #5).
VENDOR_ENV: Mapping[str, tuple[str, ...]] = {
    "URL": ("INFISICAL_API_URL",),
    "TOKEN": ("INFISICAL_TOKEN",),
    "CLIENT_ID": ("INFISICAL_CLIENT_ID", "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"),
    "CLIENT_SECRET": ("INFISICAL_CLIENT_SECRET", "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"),
    "PROJECT_ID": ("INFISICAL_PROJECT_ID",),
    "ENVIRONMENT": ("INFISICAL_ENVIRONMENT",),
}

ApiVersionSetting = Literal["auto", "v4", "v3"]
"""Secrets API version: detected at run time (``auto``) or forced."""

_API_SUFFIX = re.compile(r"/api/?$")
_C = TypeVar("_C", bound="InfisicalConfig")


@dataclasses.dataclass(frozen=True, repr=False)
class InfisicalConfig(BaseConfig):
    """Immutable settings for :class:`~grow_infisical.InfisicalClient`.

    Common fields (``url``, timeouts, ``retry``, ``tls``, ``proxy``, ``headers``,
    ``user_agent_suffix``, ``hooks``, ``logger``) come from :class:`BaseConfig`. Durations are
    float seconds; ``datetime.timedelta`` is accepted. Credentials accept ``str`` and are stored
    as :class:`Secret`; ``repr()`` never shows them.

    Service fields:

    * ``token`` — static access token (machine identity token, user JWT or legacy ``st.``
      service token) sent as ``Authorization: Bearer``.
    * ``client_id`` / ``client_secret`` — Universal Auth credentials (login + automatic refresh).
    * ``organization_slug`` — sent with identity logins (sub-organizations).
    * ``auth`` — an explicit auth method (:class:`~grow_infisical.UniversalAuth`,
      :class:`~grow_infisical.TokenAuth`, :class:`~grow_infisical.KubernetesAuth`,
      :class:`~grow_infisical.AwsIamAuth`); wins over ``token`` and ``client_id``.
    * ``project_id``, ``environment`` (slug, e.g. ``dev``) and ``secret_path`` (``/``) — defaults
      of every call. A missing ``project_id``/``environment`` raises :class:`ConfigError` when a
      call needs it, not at construction.
    * ``api_version`` — ``auto`` (v4, falling back to v3 when v4 is missing; ``""`` means
      ``auto``), ``v4`` or ``v3``.
    * ``expand_secret_references`` / ``include_imports`` — read defaults (both ``True``).
    * ``revoke_on_close`` — revoke a login token in ``close()`` (``False``).

    Environment (``from_env``): ``GROW_INFISICAL_<NAME>`` first, then the vendor variables of
    :data:`VENDOR_ENV`. Names: ``URL`` (``INFISICAL_API_URL`` loses one trailing ``/api``),
    ``TOKEN``, ``CLIENT_ID``, ``CLIENT_SECRET``, ``PROJECT_ID``, ``ENVIRONMENT``,
    ``SECRET_PATH``, ``API_VERSION``, ``REVOKE_ON_CLOSE``, ``CONNECT_TIMEOUT``,
    ``REQUEST_TIMEOUT``, ``TOTAL_TIMEOUT``, ``MAX_RETRIES``, ``CA_CERT``, ``CLIENT_CERT``,
    ``CLIENT_KEY``, ``INSECURE_SKIP_VERIFY``, ``PROXY``.
    """

    ENV_VENDOR: ClassVar[Mapping[str, tuple[str, ...]]] = VENDOR_ENV

    url: str = DEFAULT_URL
    token: Secret | None = None
    client_id: str | None = None
    client_secret: Secret | None = None
    organization_slug: str | None = None
    auth: InfisicalAuth | None = None
    project_id: str | None = None
    environment: str | None = None
    secret_path: str = "/"  # noqa: S105 - a folder path, not a secret
    api_version: ApiVersionSetting = "auto"
    expand_secret_references: bool = True
    include_imports: bool = True
    revoke_on_close: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        for name in ("client_id", "organization_slug", "project_id", "environment"):
            if getattr(self, name) == "":
                object.__setattr__(self, name, None)
        if isinstance(self.api_version, str):
            # "" is accepted as an alias of "auto" (the Go/Java spelling); case is ignored.
            version = self.api_version.strip().lower() or "auto"
            object.__setattr__(self, "api_version", version)

    def __repr__(self) -> str:
        # ``secret_path`` is a folder path, not a credential: show it.
        return safe_repr(self).replace(
            "secret_path='[REDACTED]'", f"secret_path={self.secret_path!r}"
        )

    __str__ = __repr__

    @classmethod
    def _env_values(cls, reader: EnvReader) -> dict[str, Any]:
        values = super()._env_values(reader)
        vendor = cls.ENV_VENDOR
        found = reader.lookup("URL", vendor.get("URL", ()))
        if found is not None and found[0] != reader.prefix + "URL":
            values["url"] = _API_SUFFIX.sub("", found[1])
        for name, key in (("TOKEN", "token"), ("CLIENT_SECRET", "client_secret")):
            secret = reader.string(name, vendor.get(name, ()))
            if secret is not None:
                values[key] = Secret(secret)
        for name, key in (
            ("CLIENT_ID", "client_id"),
            ("PROJECT_ID", "project_id"),
            ("ENVIRONMENT", "environment"),
        ):
            value = reader.string(name, vendor.get(name, ()))
            if value is not None:
                values[key] = value
        secret_path = reader.string("SECRET_PATH")
        if secret_path is not None:
            values["secret_path"] = secret_path
        api_version = reader.string("API_VERSION")
        if api_version is not None:
            values["api_version"] = api_version
        revoke = reader.bool("REVOKE_ON_CLOSE")
        if revoke is not None:
            values["revoke_on_close"] = revoke
        return values

    def validate(self: _C) -> _C:
        """Common checks plus service rules; raises :class:`ConfigError`."""
        super().validate()
        problems: list[str] = []
        if self.token is not None and not self.token.reveal().strip():
            problems.append("token must not be blank")
        if (self.client_id is None) != (self.client_secret is None):
            problems.append("client_id and client_secret must be given together")
        if self.client_secret is not None and not self.client_secret.reveal().strip():
            problems.append("client_secret must not be blank")
        if not isinstance(self.secret_path, str) or not self.secret_path.startswith("/"):
            problems.append("secret_path must start with /")
        if self.api_version not in ("auto", "v4", "v3"):
            problems.append("api_version must be auto, v4 or v3")
        if problems:
            raise ConfigError(f"config: {'; '.join(problems)}")
        return self

    def known_secrets(self) -> list[str]:
        """Credential values to redact from error messages and logs."""
        out = super().known_secrets()
        if self.auth is not None:
            out.extend(self.auth.known_secrets())
        return out
