package codes.grow.packages.infisical.integration;

import codes.grow.packages.infisical.InfisicalClient;
import codes.grow.packages.infisical.core.EnvReader;
import codes.grow.packages.infisical.testing.ConformanceRunner;

/**
 * Conformance targets of this service (owned by the service repository).
 *
 * <p>{@code core} is a client from the bootstrap environment (Universal Auth machine identity);
 * {@code secrets} is its {@code SecretsProvider} over the bootstrap project and environment.
 * "version" is left out of {@link #CAPABILITIES} on purpose: Infisical exposes no server version
 * ({@code serverVersion} is UNSUPPORTED, docs/compatibility.md).
 */
final class Factories {
  /** Capabilities the deployment under test offers (see the scenario {@code requires}). */
  static final String[] CAPABILITIES = {"write", "delete", "versions"};

  private Factories() {}

  static void register(ConformanceRunner.Builder runner, EnvReader env) {
    runner.target("core", scenario -> InfisicalClient.builder().fromEnv(env).build());
    runner.target(
        "secrets",
        scenario -> {
          // closed by the JVM at exit; the provider is all the scenario needs
          InfisicalClient c = InfisicalClient.builder().fromEnv(env).build();
          return c.secrets();
        });
  }
}
