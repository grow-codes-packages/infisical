// Created by sdk-kit 0.1.0; owned by this repository.
package codes.grow.packages.infisical.examples;

import codes.grow.packages.infisical.CreateFolderOptions;
import codes.grow.packages.infisical.CreateSecretOptions;
import codes.grow.packages.infisical.DeleteFolderOptions;
import codes.grow.packages.infisical.EnvOptions;
import codes.grow.packages.infisical.Folder;
import codes.grow.packages.infisical.GetSecretOptions;
import codes.grow.packages.infisical.InfisicalClient;
import codes.grow.packages.infisical.InfisicalConfig;
import codes.grow.packages.infisical.ProjectSecretsProvider;
import codes.grow.packages.infisical.SecretEntry;
import codes.grow.packages.infisical.UpdateSecretOptions;
import codes.grow.packages.infisical.core.AuthenticationException;
import codes.grow.packages.infisical.core.HealthStatus;
import codes.grow.packages.infisical.core.UnsupportedException;
import codes.grow.packages.infisical.secrets.SecretMetadata;

/**
 * The Infisical Java SDK against a real server: configuration from the environment (Universal
 * Auth), health, a secret round trip in a folder of its own, the SecretsProvider and dotenv export.
 *
 * <pre>
 * GROW_INFISICAL_URL=http://127.0.0.1:8080 \
 * INFISICAL_CLIENT_ID=... INFISICAL_CLIENT_SECRET=... \
 * INFISICAL_PROJECT_ID=... INFISICAL_ENVIRONMENT=dev mvn -q compile exec:java
 * </pre>
 */
public final class BasicExample {
  private BasicExample() {}

  /**
   * Runs the example.
   *
   * @param args unused
   */
  public static void main(String[] args) {
    InfisicalConfig config = InfisicalConfig.fromEnv(); // CONFIG error names the variable only
    System.out.println("config: " + config); // credentials print as [REDACTED]
    try (InfisicalClient client = InfisicalClient.create(config)) {
      HealthStatus health = client.health(); // never throws for an unreachable service
      System.out.println("health: healthy=" + health.healthy() + " status=" + health.status());
      if (!health.healthy()) {
        return;
      }
      try {
        client.ping();
      } catch (AuthenticationException e) {
        System.out.println("check INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET: " + e.getMessage());
        return;
      }
      try {
        client.serverVersion();
      } catch (UnsupportedException e) {
        System.out.println("Infisical exposes no server version");
      }

      // A secret round trip in a folder of its own.
      String name = "example-" + System.currentTimeMillis() / 1000;
      Folder folder = client.createFolder(name, null);
      String path = "/" + name;
      client.createSecret(
          "DATABASE_URL",
          "postgres://db:5432/app",
          CreateSecretOptions.builder().secretPath(path).comment("created by the Java example").build());
      client.updateSecret(
          "DATABASE_URL",
          UpdateSecretOptions.builder().secretPath(path).value("postgres://db:5432/app2").build());
      SecretEntry secret =
          client.getSecret("DATABASE_URL", GetSecretOptions.builder().secretPath(path).build());
      // the value prints as [REDACTED]; reveal() only where it is used
      System.out.println(
          "secret " + secret.key() + " version " + secret.version() + ": " + secret.value());

      // The SecretsProvider: names are "<folder>/<KEY>", set creates folders.
      ProjectSecretsProvider secrets = client.secrets();
      secrets.set(name + "/feature/ENABLED", "yes");
      boolean enabled = secrets.getBool(name + "/feature/ENABLED").orElse(false);
      System.out.println("feature enabled: " + enabled);
      for (SecretMetadata m : secrets.list(name + "/")) {
        System.out.println("listed " + m.name() + " version " + m.version().orElse("?"));
      }

      // dotenv export (contains values: handle it like a secret)
      String dotenv = client.exportDotenv(EnvOptions.builder().secretPath(path).build());
      System.out.println("dotenv lines: " + dotenv.lines().count());

      client.deleteFolder(folder.id(), DeleteFolderOptions.builder().force(true).build());
      System.out.println("cleaned up " + path);
    }
  }
}
