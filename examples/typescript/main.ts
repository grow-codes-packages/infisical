// Infisical TypeScript SDK example: configuration from the environment (Universal Auth or a
// static token), health, ping, secrets CRUD, folders, the SecretsProvider, env injection and
// error handling.
//
//   (cd ../../typescript && npm install && npm run build)   # or use the published package
//   npm install
//   GROW_INFISICAL_URL=http://127.0.0.1:8080 \
//   INFISICAL_CLIENT_ID=... INFISICAL_CLIENT_SECRET=... \
//   INFISICAL_PROJECT_ID=... INFISICAL_ENVIRONMENT=dev npm start

import { InfisicalClient, InfisicalError } from "@grow-codes/infisical";

const client = InfisicalClient.fromEnv({
  // Warnings only; the default logger is silent.
  logger: { debug() {}, info() {}, warn: console.warn, error: console.error },
  hooks: {
    onError(info) {
      if (info.willRetry)
        console.error(`retrying ${info.method} ${info.url} (attempt ${info.attempt})`);
    },
  },
});
console.log(`config: ${client.config}`); // credentials print as [REDACTED]

const run = Math.random().toString(36).slice(2, 8);
const key = `EXAMPLE_${run.toUpperCase()}`;
const folder = `example-${run}`;

try {
  const health = await client.health(); // never throws for an unreachable service
  console.log("health:", health.status);
  if (!health.healthy) process.exit(1);
  console.log(
    `ping: ${(await client.ping({ signal: AbortSignal.timeout(10_000) })).toFixed(1)} ms`,
  );

  // Secrets API (v4, v3 fallback detected at run time)
  await client.folders.createFolder(folder);
  await client.secrets.createSecret(key, "s3cr3t", { secretPath: `/${folder}`, comment: "demo" });
  await client.secrets.updateSecret(key, { secretPath: `/${folder}`, value: "s3cr3t-2" });
  const secret = await client.secrets.getSecret(key, { secretPath: `/${folder}` });
  console.log(`${secret.key} v${secret.version} = ${secret.value}`); // value prints redacted
  console.log("api version:", client.apiVersion());

  // SecretsProvider: names are "<folder>/<key>"
  const p = client.provider;
  await p.set(`${folder}/PORT`, "5432");
  console.log("PORT as number:", await p.getNumber(`${folder}/PORT`));
  console.log(
    "list:",
    (await p.list(folder)).map((m) => `${m.name}@${m.version}`),
  );

  // Env injection
  const target: Record<string, string | undefined> = {};
  console.log(
    "loadEnv set:",
    Object.keys(await client.secrets.loadEnv({ secretPath: `/${folder}`, env: target })),
  );
  console.log(
    "dotenv keys:",
    (await client.secrets.exportDotenv({ secretPath: `/${folder}` }))
      .split("\n")
      .filter(Boolean)
      .map((l) => l.split("=")[0]),
  );

  await client.folders.deleteFolder(folder, { forceDelete: true });

  try {
    await client.serverVersion();
  } catch (err) {
    if (err instanceof InfisicalError && err.code === "UNSUPPORTED") {
      console.log("server version: not reported by Infisical");
    } else {
      throw err;
    }
  }
} catch (err) {
  if (err instanceof InfisicalError) {
    // Canonical code + HTTP status + request id; the message never contains credentials.
    console.error(`${err.code}: ${err.message}`, {
      httpStatus: err.httpStatus,
      requestId: err.requestId,
    });
    process.exitCode = 1;
  } else {
    throw err;
  }
} finally {
  await client.close();
}
