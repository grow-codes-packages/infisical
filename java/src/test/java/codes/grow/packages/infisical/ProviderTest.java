package codes.grow.packages.infisical;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.infisical.core.NotFoundException;
import codes.grow.packages.infisical.core.PermissionDeniedException;
import codes.grow.packages.infisical.core.UnsupportedException;
import codes.grow.packages.infisical.core.ValidationException;
import codes.grow.packages.infisical.secrets.DeleteOptions;
import codes.grow.packages.infisical.secrets.GetOptions;
import codes.grow.packages.infisical.secrets.SecretMetadata;
import codes.grow.packages.infisical.secrets.SecretValue;
import codes.grow.packages.infisical.secrets.SetOptions;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ProviderTest {
  private static final String NOT_FOUND =
      "{\"statusCode\":404,\"message\":\"Secret with name 'X' not found\",\"error\":\"NotFound\"}";
  private static final String PATH_NOT_FOUND =
      "{\"statusCode\":404,\"message\":\"Folder with path '/x' not found\","
          + "\"error\":\"SecretPathNotFound\"}";
  private static final String DUP =
      "{\"statusCode\":400,\"message\":\"Secret 'K' already exists\",\"error\":\"BadRequest\"}";

  private final Fake fake = new Fake();

  @AfterEach
  void stop() {
    fake.close();
  }

  static String secret(String key, String value, int version, String path) {
    return "{\"id\":\"id-"
        + key
        + "\",\"secretKey\":\""
        + key
        + "\",\"secretValue\":\""
        + value
        + "\",\"version\":"
        + version
        + ",\"type\":\"shared\",\"environment\":\"dev\",\"secretPath\":\""
        + path
        + "\",\"secretComment\":\"cm\",\"createdAt\":\"2026-11-18T20:28:13.931Z\","
        + "\"updatedAt\":\"2026-11-18T20:28:14.000Z\","
        + "\"tags\":[{\"id\":\"t1\",\"slug\":\"s1\",\"name\":\"\"},{\"id\":\"t2\",\"slug\":\"s2\",\"name\":\"Two\"}]}";
  }

  private InfisicalClient client() {
    return fake.client(b -> b.apiVersion("v4"));
  }

  @Test
  void getSplitsNameIntoPathAndKey() {
    fake.on(
        "GET",
        "/api/v4/secrets/PASSWORD",
        200,
        "{\"secret\":" + secret("PASSWORD", "pw", 3, "/base/db") + "}");
    fake.on("GET", "/api/v4/secrets/MISSING", 404, NOT_FOUND);
    try (InfisicalClient c = client()) {
      ProjectSecretsProvider p =
          c.secretsWith(
              SecretsProviderOptions.builder()
                  .basePath("base")
                  .projectId("p2")
                  .environment("prod")
                  .expandReferences(false)
                  .includeImports(false)
                  .build());
      assertThat(p.basePath()).isEqualTo("/base");
      assertThat(p.options().projectId()).isEqualTo("p2");
      SecretValue v = p.get("db/PASSWORD").orElseThrow();
      assertThat(v.reveal()).isEqualTo("pw");
      assertThat(v.version()).contains("3");
      Map<String, String> q = Fake.query(fake.last("GET", "/api/v4/secrets/PASSWORD"));
      assertThat(q)
          .containsEntry("secretPath", "/base/db")
          .containsEntry("projectId", "p2")
          .containsEntry("environment", "prod")
          .containsEntry("expandSecretReferences", "false")
          .containsEntry("includeImports", "false")
          .containsEntry("viewSecretValue", "true");
      p.get("PASSWORD", GetOptions.builder().path("/other").version("2").build());
      q = Fake.query(fake.last("GET", "/api/v4/secrets/PASSWORD"));
      assertThat(q).containsEntry("secretPath", "/other").containsEntry("version", "2");
      assertThat(p.get("MISSING")).isEmpty();
      assertThatThrownBy(() -> p.get("dir/")).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> p.get("K", GetOptions.builder().version("x").build()))
          .isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> p.get("K", GetOptions.builder().version("0").build()))
          .isInstanceOf(ValidationException.class);
      assertThat(p.toString()).contains("/base");
    }
  }

  @Test
  void metadataDoesNotTransferTheValue() {
    fake.on("GET", "/api/v4/secrets/K", 200, "{\"secret\":" + secret("K", "", 2, "/") + "}");
    fake.on("GET", "/api/v4/secrets/GONE", 404, NOT_FOUND);
    try (InfisicalClient c = client()) {
      ProjectSecretsProvider p = c.secrets();
      SecretMetadata m = p.metadata("K").orElseThrow();
      assertThat(Fake.query(fake.last("GET", "/api/v4/secrets/K")))
          .containsEntry("viewSecretValue", "false");
      assertThat(m.name()).isEqualTo("K");
      assertThat(m.version()).contains("2");
      assertThat(m.versions()).hasValue(2);
      assertThat(m.path()).contains("/");
      assertThat(m.tags()).containsEntry("s1", "s1").containsEntry("s2", "Two");
      assertThat(m.extra()).containsEntry("id", "id-K").containsEntry("comment", "cm");
      assertThat(m.createdAt()).isPresent();
      assertThat(p.metadata("GONE")).isEmpty();
      SecretEntry noComment = SecretsApiTest.entry("Z", "/", "v");
      assertThat(ProjectSecretsProvider.metadataOf("Z", noComment).extra())
          .doesNotContainKey("comment");
    }
  }

  @Test
  void permissionErrorsPropagate() {
    fake.fixture("GET", "/api/v4/secrets/K", "listSecrets.403noMembership");
    try (InfisicalClient c = client()) {
      assertThatThrownBy(() -> c.secrets().get("K")).isInstanceOf(PermissionDeniedException.class);
    }
  }

  @Test
  void listFolderOrKeyPrefix() {
    String list =
        "{\"secrets\":["
            + secret("DB_PASS", "", 1, "/app")
            + ","
            + secret("API", "", 1, "/app")
            + ",{\"secretKey\":\"DB_MINE\",\"type\":\"personal\"}]}";
    fake.on("GET", "/api/v4/secrets", 200, list);
    try (InfisicalClient c = client()) {
      List<SecretMetadata> all = c.secrets().list("app/");
      assertThat(all).extracting(SecretMetadata::name).containsExactly("app/API", "app/DB_PASS");
      Map<String, String> q = Fake.query(fake.last("GET", "/api/v4/secrets"));
      assertThat(q)
          .containsEntry("secretPath", "/app")
          .containsEntry("viewSecretValue", "false")
          .containsEntry("includeImports", "false")
          .containsEntry("expandSecretReferences", "false");
      assertThat(c.secrets().list()).extracting(SecretMetadata::name).contains("API");
    }
    // folder app/DB_ does not exist: key prefix DB_ inside app
    fake.reset("GET", "/api/v4/secrets")
        .on("GET", "/api/v4/secrets", 404, PATH_NOT_FOUND)
        .on("GET", "/api/v4/secrets", 200, list);
    try (InfisicalClient c = client()) {
      assertThat(c.secrets().list("app/DB_"))
          .extracting(SecretMetadata::name)
          .containsExactly("app/DB_PASS");
    }
    fake.reset("GET", "/api/v4/secrets")
        .on("GET", "/api/v4/secrets", 404, PATH_NOT_FOUND)
        .on("GET", "/api/v4/secrets", 200, list);
    try (InfisicalClient c = client()) {
      assertThat(c.secrets().list("DB_"))
          .extracting(SecretMetadata::name)
          .containsExactly("DB_PASS");
    }
    fake.reset("GET", "/api/v4/secrets").on("GET", "/api/v4/secrets", 404, PATH_NOT_FOUND);
    try (InfisicalClient c = client()) {
      assertThat(c.secrets().list("missing/")).isEmpty();
      assertThat(c.secrets().list("")).isEmpty();
      assertThat(c.secrets().list("a/b")).isEmpty();
    }
  }

  @Test
  void setCreatesFoldersAndUpdatesExisting() {
    fake.on("POST", "/api/v4/secrets/PASSWORD", 404, PATH_NOT_FOUND)
        .on(
            "POST",
            "/api/v4/secrets/PASSWORD",
            200,
            "{\"secret\":" + secret("PASSWORD", "x", 1, "/b/db") + "}")
        .on("POST", "/api/v4/secrets/PASSWORD", 400, DUP);
    fake.on("POST", "/api/v2/folders", 200, Fake.body("createFolder.ok"))
        .on(
            "POST",
            "/api/v2/folders",
            400,
            "{\"message\":\"Folder with name 'db' already exists\",\"error\":\"BadRequest\"}");
    fake.on(
        "PATCH",
        "/api/v4/secrets/PASSWORD",
        200,
        "{\"secret\":" + secret("PASSWORD", "", 2, "/b/db") + "}");
    fake.on(
        "GET", "/api/v1/projects/p1/tags", 200, "{\"tags\":[{\"id\":\"t-old\",\"slug\":\"old\"}]}");
    fake.on(
        "POST", "/api/v1/projects/p1/tags", 200, "{\"tag\":{\"id\":\"t-new\",\"slug\":\"new\"}}");
    try (InfisicalClient c = client()) {
      ProjectSecretsProvider p =
          c.secretsWith(SecretsProviderOptions.builder().basePath("/b").build());
      String v =
          p.set(
              "db/PASSWORD",
              "pw-1",
              SetOptions.builder()
                  .description("db password")
                  .tag("old", "x")
                  .tag("new", "#123456")
                  .build());
      assertThat(v).isEqualTo("1");
      List<codes.grow.packages.infisical.core.MockServer.Recorded> folders =
          fake.requests("POST", "/api/v2/folders");
      assertThat(folders).hasSize(2);
      assertThat(Fake.json(folders.get(0)).path("name").asText()).isEqualTo("b");
      assertThat(Fake.json(folders.get(0)).path("path").asText()).isEqualTo("/");
      assertThat(Fake.json(folders.get(1)).path("name").asText()).isEqualTo("db");
      assertThat(Fake.json(folders.get(1)).path("path").asText()).isEqualTo("/b");
      JsonNode created = Fake.json(fake.last("POST", "/api/v4/secrets/PASSWORD"));
      assertThat(created.path("secretComment").asText()).isEqualTo("db password");
      assertThat(created.path("tagIds").toString()).isEqualTo("[\"t-new\",\"t-old\"]");
      assertThat(Fake.json(fake.last("POST", "/api/v1/projects/p1/tags")).path("color").asText())
          .isEqualTo("#123456");

      // existing key: update
      assertThat(
              p.set(
                  "db/PASSWORD", Map.of("k", "v"), SetOptions.builder().description("d2").build()))
          .isEqualTo("2");
      JsonNode upd = Fake.json(fake.last("PATCH", "/api/v4/secrets/PASSWORD"));
      assertThat(upd.path("secretValue").asText()).isEqualTo("{\"k\":\"v\"}");
      assertThat(upd.path("secretComment").asText()).isEqualTo("d2");
      assertThat(upd.has("tagIds")).isFalse();
      p.set("db/PASSWORD", "v3", SetOptions.builder().tag("old", "").build());
      upd = Fake.json(fake.last("PATCH", "/api/v4/secrets/PASSWORD"));
      assertThat(upd.has("secretComment")).isFalse();
      assertThat(upd.path("tagIds").get(0).asText()).isEqualTo("t-old");
    }
  }

  @Test
  void setWithoutFolderRetryOnOtherNotFound() {
    fake.on("POST", "/api/v4/secrets/K", 404, NOT_FOUND);
    try (InfisicalClient c = client()) {
      assertThatThrownBy(() -> c.secrets().set("K", "v")).isInstanceOf(NotFoundException.class);
      assertThat(fake.requests("POST", "/api/v2/folders")).isEmpty();
    }
  }

  @Test
  void setRejectsUnsupportedInput() {
    try (InfisicalClient c = client()) {
      ProjectSecretsProvider p = c.secrets();
      assertThatThrownBy(() -> p.set("K", new byte[] {(byte) 0xff}))
          .isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> p.set("K", "v", SetOptions.builder().cas(1).build()))
          .isInstanceOf(UnsupportedException.class);
      assertThatThrownBy(() -> p.delete("K", DeleteOptions.builder().versions("1").build()))
          .isInstanceOf(UnsupportedException.class);
    }
  }

  @Test
  void deleteMapsToDeleteSecret() {
    fake.fixture("DELETE", "/api/v4/secrets/PASSWORD", "deleteSecret.ok");
    fake.on("DELETE", "/api/v4/secrets/GONE", 404, NOT_FOUND);
    try (InfisicalClient c = client()) {
      c.secrets().delete("db/PASSWORD");
      assertThat(
              Fake.json(fake.last("DELETE", "/api/v4/secrets/PASSWORD"))
                  .path("secretPath")
                  .asText())
          .isEqualTo("/db");
      c.secrets().delete("PASSWORD", DeleteOptions.builder().path("/x").build());
      assertThat(
              Fake.json(fake.last("DELETE", "/api/v4/secrets/PASSWORD"))
                  .path("secretPath")
                  .asText())
          .isEqualTo("/x");
      assertThatThrownBy(() -> c.secrets().delete("GONE")).isInstanceOf(NotFoundException.class);
    }
  }

  @Test
  void getAllUsesOneListing() {
    String body =
        "{\"secrets\":["
            + secret("A", "a", 1, "/app")
            + "],\"imports\":[{\"secretPath\":\"/c\",\"environment\":\"staging\",\"secrets\":["
            + secret("B", "b", 4, "/c")
            + ","
            + secret("A", "imp", 1, "/c")
            + "]}]}";
    fake.on("GET", "/api/v4/secrets", 200, body);
    try (InfisicalClient c = client()) {
      Map<String, SecretValue> all = c.secrets().getAll("app");
      assertThat(all.keySet()).containsExactly("app/A", "app/B");
      assertThat(all.get("app/A").reveal()).isEqualTo("a");
      assertThat(all.get("app/B").version()).contains("4");
      assertThat(Fake.query(fake.last("GET", "/api/v4/secrets")))
          .containsEntry("secretPath", "/app")
          .containsEntry("includeImports", "true")
          .containsEntry("viewSecretValue", "true");
      assertThat(c.secrets().getAll(null).keySet()).containsExactly("A", "B");
      Map<String, String> env = new java.util.HashMap<>();
      assertThat(
              c.secrets()
                  .loadEnv(
                      "",
                      codes.grow.packages.infisical.secrets.LoadEnvOptions.builder()
                          .target(codes.grow.packages.infisical.secrets.EnvLoader.map(env))
                          .build()))
          .containsKeys("A", "B");
    }
    fake.reset("GET", "/api/v4/secrets").on("GET", "/api/v4/secrets", 404, PATH_NOT_FOUND);
    try (InfisicalClient c = client()) {
      assertThat(c.secrets().getAll("nope")).isEmpty();
    }
  }
}
