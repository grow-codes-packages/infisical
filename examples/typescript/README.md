# TypeScript example

Creates a folder and a secret, updates and reads it, uses the `SecretsProvider`, loads the folder
into an environment object, exports it as dotenv and cleans up.

```sh
(cd ../../typescript && npm install && npm run build)
npm install
GROW_INFISICAL_URL=http://127.0.0.1:8080 \
INFISICAL_CLIENT_ID=... INFISICAL_CLIENT_SECRET=... \
INFISICAL_PROJECT_ID=... INFISICAL_ENVIRONMENT=dev npm start
```

A static token works too (`INFISICAL_TOKEN=...` instead of the client id/secret). Replace the
`file:` dependency in `package.json` with a version (`npm install @grow-codes/infisical`) to run it
against the published package.
