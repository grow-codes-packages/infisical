# grow-infisical (Python)

Python SDK for [Infisical](https://grow-codes-packages.github.io/infisical/) by Grow Codes.
Unofficial and community maintained; "Infisical" is a trademark of Infisical, Inc..

```bash
pip install grow-infisical
```

```python
from grow_infisical import BatchCreateSecret, InfisicalClient

# Reads GROW_INFISICAL_URL / INFISICAL_API_URL, INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET
# (Universal Auth) or INFISICAL_TOKEN, INFISICAL_PROJECT_ID and INFISICAL_ENVIRONMENT.
with InfisicalClient.from_env() as client:
    client.secrets.create_secret("API_KEY", "s3cret", comment="demo")
    print(client.secrets.get_secret("API_KEY").value.reveal())
    client.secrets.update_secret("API_KEY", value="rotated")
    client.secrets.create_secrets([BatchCreateSecret("A", "1"), BatchCreateSecret("B", "2")])
    client.secrets.load_env(secret_path="/app")          # like `infisical run`
    print(client.secrets.export_dotenv())                # KEY="value" lines
    client.folders.create_folder("app")
    client.tags.create_tag("team-a", "#00aa00")
    print(client.projects.list_environments())
    # SPEC SecretsProvider: "a/b/KEY" = folder /a/b, key KEY (folders created on set)
    client.provider.set("app/DB_PASSWORD", "pw")
    print(client.provider.get_string("app/DB_PASSWORD"))
```

Auth methods: `UniversalAuth(client_id, client_secret)` (login/renew/revoke, automatic refresh),
`TokenAuth(token)` (identity token, user JWT or `st.` service token), `KubernetesAuth`,
`AwsIamAuth`; pass one as `InfisicalConfig(auth=...)`.

The async client has the same modules and methods:

```python
import asyncio
from grow_infisical import AsyncInfisicalClient

async def main() -> None:
    async with AsyncInfisicalClient.from_env() as client:
        print(await client.health())
        print((await client.secrets.list_secrets()).secrets)

asyncio.run(main())
```

- Python 3.10 or newer, typed (`py.typed`), `httpx` based, environment proxies ignored unless
  configured.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation, hooks and a silent-by-default `logging` logger named `grow_infisical`.
- Credentials are wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_infisical.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/infisical/ ·
Source: https://github.com/grow-codes-packages/infisical · Licence: Apache-2.0
