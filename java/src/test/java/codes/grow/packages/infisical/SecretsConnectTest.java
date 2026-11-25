// Service-owned: generated once by sdk-kit, then maintained in this repository.
package codes.grow.packages.infisical;

import static org.assertj.core.api.Assertions.assertThat;

import codes.grow.packages.infisical.secrets.ConfigLoader;
import codes.grow.packages.infisical.secrets.ConfigLoader.LoadOptions;
import codes.grow.packages.infisical.secrets.ConfigLoader.SecretsBootstrap;
import codes.grow.packages.infisical.secrets.ConfigLoader.SecretsConnection;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SecretsConnectTest {
  private final Fake fake = new Fake();

  @AfterEach
  void stop() {
    fake.close();
  }

  @Test
  void returnsTheClientsSecretsProvider() {
    SecretsConnection c =
        SecretsConnect.connect(
            new SecretsBootstrap(null, "http://127.0.0.1:1", null, "", "", null, null),
            Map.of("GROW_INFISICAL_TOKEN", "t", "GROW_INFISICAL_PROJECT_ID", "p1"));
    try {
      assertThat(c.provider()).isInstanceOf(ProjectSecretsProvider.class);
      assertThat(c.path()).isNull();
    } finally {
      c.close().run();
    }
  }

  /** GRO-1410 regression: the default connector honours GROW_SECRETS_ADDR and the given env. */
  @Test
  void loadConfigReadsThroughTheConnector() {
    String list =
        "{\"secrets\":["
            + secret("DATABASE_URL", "postgres://db")
            + ","
            + secret("LOG_LEVEL", "debug")
            + "],\"imports\":[]}";
    fake.on("GET", "/api/v4/secrets", 200, list);
    Map<String, String> env = new HashMap<>();
    env.put("GROW_SECRETS_PROVIDER", "infisical");
    env.put("GROW_SECRETS_ADDR", fake.server.url());
    env.put("GROW_SECRETS_PATH", "services/orders");
    env.put("GROW_INFISICAL_URL", "http://127.0.0.1:1");
    env.put("GROW_INFISICAL_TOKEN", "tok-identity");
    env.put("GROW_INFISICAL_PROJECT_ID", "p1");
    env.put("GROW_INFISICAL_ENVIRONMENT", "dev");
    env.put("GROW_INFISICAL_MAX_RETRIES", "0");
    Map<String, String> written = new HashMap<>();
    Map<String, String> values =
        ConfigLoader.load(
            LoadOptions.builder().env(env).required("DATABASE_URL").target(written::put).build());
    assertThat(values)
        .containsExactlyInAnyOrderEntriesOf(
            Map.of("DATABASE_URL", "postgres://db", "LOG_LEVEL", "debug"));
    assertThat(written).containsEntry("DATABASE_URL", "postgres://db");
    Map<String, String> q = Fake.query(fake.last("GET", "/api/v4/secrets"));
    assertThat(q)
        .containsEntry("secretPath", "/services/orders")
        .containsEntry("projectId", "p1")
        .containsEntry("environment", "dev");
  }

  private static String secret(String key, String value) {
    return "{\"id\":\"id-"
        + key
        + "\",\"secretKey\":\""
        + key
        + "\",\"secretValue\":\""
        + value
        + "\",\"version\":1,\"type\":\"shared\",\"environment\":\"dev\","
        + "\"secretPath\":\"/services/orders\",\"secretComment\":\"\","
        + "\"createdAt\":\"2026-11-18T20:28:13.931Z\",\"updatedAt\":\"2026-11-18T20:28:13.931Z\","
        + "\"tags\":[]}";
  }
}
