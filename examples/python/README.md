# Python examples

Install the package, point it at a running Infisical and run an example:

```bash
pip install grow-infisical
export GROW_INFISICAL_URL=http://127.0.0.1:8080
export INFISICAL_CLIENT_ID=... INFISICAL_CLIENT_SECRET=...   # or INFISICAL_TOKEN=...
export INFISICAL_PROJECT_ID=... INFISICAL_ENVIRONMENT=dev
python examples/python/basic.py
```

| File | Shows |
| - | - |
| `basic.py` | sync client: health, ping, server version (unsupported on Infisical), error handling |
| `secrets_api.py` | secrets CRUD, references, folders, tags, `load_env`, `export_dotenv`, the `SecretsProvider` |
| `async_basic.py` | async client, cancellation by task |
| `hooks_and_logging.py` | request hooks, the `grow_infisical` logger, retries and timeouts |
| `secrets_cache.py` | cached secret reads, typed getters, `load_env`, `watch` (in-memory provider) |
