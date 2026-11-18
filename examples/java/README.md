# Java examples

Install the package into your local Maven repository, point it at a running Infisical and run an
example:

```bash
make -C ../../java pack            # builds and installs codes.grow.packages:infisical
export GROW_INFISICAL_URL=http://127.0.0.1:8080
export INFISICAL_CLIENT_ID=... INFISICAL_CLIENT_SECRET=...   # Universal Auth (or INFISICAL_TOKEN)
export INFISICAL_PROJECT_ID=... INFISICAL_ENVIRONMENT=dev
mvn -q compile exec:java                                                  # BasicExample
mvn -q compile exec:java -Dexec.mainClass=codes.grow.packages.infisical.examples.AsyncExample
```

Against the published package, set `-Dsdk.version=<version>` (or edit `pom.xml`) instead of
installing it locally.

| Class | Shows |
| - | - |
| `BasicExample` | real API: config from env (Universal Auth), health, folder + secret round trip, SecretsProvider, dotenv |
| `AsyncExample` | `…Async` methods, combining futures, cancellation |
| `HooksAndLoggingExample` | request hooks, a logger, retries and timeouts |
| `secrets.SecretsCacheExample` | cached secret reads, typed getters, `loadEnv`, `watch` (in-memory provider) |
