"""Infisical secrets, folders, tags and env injection against a real server.

Needs GROW_INFISICAL_URL (or INFISICAL_API_URL), INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET
(Universal Auth) or INFISICAL_TOKEN, INFISICAL_PROJECT_ID and INFISICAL_ENVIRONMENT.
"""

from __future__ import annotations

import secrets

import grow_infisical as sdk


def main() -> None:
    run = secrets.token_hex(3)
    folder = f"example-{run}"
    with sdk.InfisicalClient.from_env() as client:
        made = client.folders.create_folder(folder)
        try:
            path = f"/{folder}"
            client.secrets.create_secret("DB_USER", "app", secret_path=path, comment="example")
            client.secrets.create_secret("DB_URL", "postgres://${DB_USER}@db", secret_path=path)
            url = client.secrets.get_secret("DB_URL", secret_path=path)
            print("DB_URL =", url.value.reveal(), "(references expanded)")
            client.secrets.update_secret("DB_USER", value="app2", secret_path=path)
            for item in client.secrets.list_secrets(secret_path=path).secrets:
                print(f"{item.key} v{item.version}: {item.value}")  # value prints [REDACTED]
            environ: dict[str, str] = {}
            print("set:", client.secrets.load_env(secret_path=path, environ=environ))
            print(client.secrets.export_dotenv(secret_path=path), end="")
            # The generic SecretsProvider (same API in every Grow Codes secrets SDK)
            client.provider.set(f"{folder}/nested/TOKEN", "t-123", tags={"example": "#0a0"})
            print("provider:", client.provider.get_string(f"{folder}/nested/TOKEN"))
            print("api version:", client.api_version())
        finally:
            client.folders.delete_folder(made.id, force_delete=True)
            for tag in client.tags.list_tags():
                if tag.slug == "example":
                    client.tags.delete_tag(tag.id)


if __name__ == "__main__":
    main()
