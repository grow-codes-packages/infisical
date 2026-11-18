// Runs the shared conformance scenarios (conformance/scenarios) against the real service.
// Declared capabilities: secrets write + delete. Infisical exposes no server version, so the
// core "version" capability is not declared (docs/compatibility.md).

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { InfisicalClient } from "@grow-codes/infisical";
import { formatReport, runConformance } from "@grow-codes/infisical/testing";
import { loadBootstrapEnv, scenariosDir } from "./env.ts";

const clients: InfisicalClient[] = [];

before(() => {
  loadBootstrapEnv();
});

after(async () => {
  await Promise.all(clients.map((c) => c.close()));
});

test("conformance: core", async () => {
  const report = await runConformance({
    scenariosDir,
    categories: ["core"],
    factories: { core: () => InfisicalClient.fromEnv() },
    capabilities: { core: [] },
  });
  console.log(formatReport(report));
  assert.equal(report.failed, 0, formatReport(report));
  assert.ok(report.passed > 0);
});

test("conformance: secrets", async () => {
  const report = await runConformance({
    scenariosDir,
    categories: ["secrets"],
    factories: {
      secrets: () => {
        const c = InfisicalClient.fromEnv();
        clients.push(c);
        return c.provider;
      },
    },
    capabilities: { secrets: ["write", "delete"] },
  });
  console.log(formatReport(report));
  assert.equal(report.failed, 0, formatReport(report));
  assert.equal(report.skipped, 0, formatReport(report));
  assert.ok(report.passed >= 4);
});
