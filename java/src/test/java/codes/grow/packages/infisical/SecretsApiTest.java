package codes.grow.packages.infisical;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.infisical.core.ConflictException;
import codes.grow.packages.infisical.core.NotFoundException;
import codes.grow.packages.infisical.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SecretsApiTest {
  private final Fake fake = new Fake();

  @AfterEach
  void stop() {
    fake.close();
  }

  private InfisicalClient v4() {
    return fake.client(b -> b.apiVersion("v4"));
  }

  private InfisicalClient v3() {
    return fake.client(b -> b.apiVersion("v3"));
  }

  @Test
  void listSecretsQueryAndDecoding() {
    fake.fixture("GET", "/api/v4/secrets", "listSecrets.withImports");
    try (InfisicalClient c = v4()) {
      SecretList l = c.listSecrets();
      Map<String, String> q = Fake.query(fake.last("GET", "/api/v4/secrets"));
      assertThat(q)
          .containsEntry("projectId", "p1")
          .containsEntry("environment", "dev")
          .containsEntry("secretPath", "/")
          .containsEntry("recursive", "false")
          .containsEntry("expandSecretReferences", "true")
          .containsEntry("includeImports", "true")
          .containsEntry("viewSecretValue", "true")
          .doesNotContainKeys("tagSlugs", "includePersonalOverrides");
      assertThat(l.imports()).isNotEmpty();
      assertThat(l.merged()).isNotEmpty();
      c.listSecrets(
          ListSecretsOptions.builder()
              .projectId("p2")
              .environment("prod")
              .secretPath("app/")
              .recursive(true)
              .expandReferences(false)
              .includeImports(false)
              .tagSlugs(List.of("a", "b"))
              .viewSecretValue(false)
              .includePersonalOverrides(true)
              .build());
      q = Fake.query(fake.last("GET", "/api/v4/secrets"));
      assertThat(q)
          .containsEntry("projectId", "p2")
          .containsEntry("environment", "prod")
          .containsEntry("secretPath", "/app")
          .containsEntry("recursive", "true")
          .containsEntry("expandSecretReferences", "false")
          .containsEntry("includeImports", "false")
          .containsEntry("tagSlugs", "a,b")
          .containsEntry("viewSecretValue", "false")
          .containsEntry("includePersonalOverrides", "true");
    }
  }

  @Test
  void listSecretsV3() {
    fake.fixture("GET", "/api/v3/secrets/raw", "listSecrets.v3raw-imports");
    try (InfisicalClient c = v3()) {
      c.listSecrets(
          ListSecretsOptions.builder()
              .tagSlugs(List.of("t"))
              .includePersonalOverrides(true)
              .build());
      Map<String, String> q = Fake.query(fake.last("GET", "/api/v3/secrets/raw"));
      assertThat(q)
          .containsEntry("workspaceId", "p1")
          .containsEntry("include_imports", "true")
          .containsEntry("tagSlugs", "t")
          .doesNotContainKeys("viewSecretValue", "includePersonalOverrides", "projectId");
    }
  }

  @Test
  void mergedPrefersDirectAndShallowSecrets() {
    SecretEntry deep = entry("K", "/a/b", "deep");
    SecretEntry shallow = entry("K", "/a", "shallow");
    SecretEntry imported = entry("K", "/x", "imported");
    SecretEntry only = entry("I", "/x", "only-imported");
    SecretList l =
        new SecretList(
            List.of(deep, shallow),
            List.of(new ImportedSecrets("/x", "staging", "", List.of(imported, only))));
    assertThat(l.merged().get("K").value().reveal()).isEqualTo("shallow");
    assertThat(l.merged().get("I").value().reveal()).isEqualTo("only-imported");
  }

  static SecretEntry entry(String key, String path, String value) {
    return new SecretEntry(
        "id",
        key,
        codes.grow.packages.infisical.core.Secret.of(value),
        false,
        "",
        1,
        SecretType.SHARED,
        "p",
        "dev",
        path,
        List.of(),
        Map.of(),
        false,
        java.util.Optional.empty(),
        java.util.Optional.empty());
  }

  @Test
  void getSecretDecodesEveryField() {
    fake.fixture("GET", "/api/v4/secrets/SDK_49LJ3988_ONE", "getSecret.ok");
    try (InfisicalClient c = v4()) {
      SecretEntry s = c.getSecret("SDK_49LJ3988_ONE");
      assertThat(s.key()).isEqualTo("SDK_49LJ3988_ONE");
      assertThat(s.value().reveal()).isEqualTo("v1-49lj3988");
      assertThat(s.toString()).doesNotContain("v1-49lj3988");
      assertThat(s.comment()).isEqualTo("c1");
      assertThat(s.version()).isEqualTo(1);
      assertThat(s.type()).isEqualTo(SecretType.SHARED);
      assertThat(s.environment()).isEqualTo("dev");
      assertThat(s.secretPath()).isEqualTo("/");
      assertThat(s.projectId()).isNotEmpty();
      assertThat(s.createdAt()).contains(Instant.parse("2026-11-18T20:28:13.931Z"));
      assertThat(s.valueHidden()).isFalse();
      assertThat(s.skipMultilineEncoding()).isFalse();
      Map<String, String> q = Fake.query(fake.last("GET", "/api/v4/secrets/SDK_49LJ3988_ONE"));
      assertThat(q).doesNotContainKeys("version", "type").containsEntry("viewSecretValue", "true");
      c.getSecret(
          "SDK_49LJ3988_ONE",
          GetSecretOptions.builder()
              .version(2)
              .type(SecretType.PERSONAL)
              .expandReferences(false)
              .includeImports(false)
              .viewSecretValue(false)
              .secretPath("/app")
              .build());
      q = Fake.query(fake.last("GET", "/api/v4/secrets/SDK_49LJ3988_ONE"));
      assertThat(q)
          .containsEntry("version", "2")
          .containsEntry("type", "personal")
          .containsEntry("expandSecretReferences", "false")
          .containsEntry("includeImports", "false")
          .containsEntry("viewSecretValue", "false")
          .containsEntry("secretPath", "/app");
      assertThatThrownBy(() -> c.getSecret("X", GetSecretOptions.builder().version(-1).build()))
          .isInstanceOf(ValidationException.class);
    }
  }

  @Test
  void hiddenValuesAndMetadataAndTags() {
    fake.fixture("GET", "/api/v4/secrets", "listSecrets.hiddenValues");
    fake.fixture("GET", "/api/v4/secrets/T", "getSecret.afterRename");
    try (InfisicalClient c = v4()) {
      SecretList l = c.listSecrets();
      assertThat(l.secrets()).allMatch(SecretEntry::valueHidden);
      assertThat(l.secrets().get(0).value().reveal()).isEmpty();
    }
    String withMeta =
        "{\"secret\":{\"id\":\"1\",\"secretKey\":\"K\",\"secretValue\":\"v\",\"version\":2,"
            + "\"type\":\"personal\",\"createdAt\":\"bad-date\",\"skipMultilineEncoding\":true,"
            + "\"tags\":[{\"id\":\"t1\",\"slug\":\"s1\",\"name\":\"N\",\"color\":\"#fff\"}],"
            + "\"secretMetadata\":[{\"key\":\"a\",\"value\":\"b\"}]}}";
    fake.on("GET", "/api/v4/secrets/M", 200, withMeta);
    try (InfisicalClient c = v4()) {
      SecretEntry s = c.getSecret("M");
      assertThat(s.type()).isEqualTo(SecretType.PERSONAL);
      assertThat(s.metadata()).containsEntry("a", "b");
      assertThat(s.tags()).extracting(Tag::slug).containsExactly("s1");
      assertThat(s.createdAt()).isEmpty();
      assertThat(s.skipMultilineEncoding()).isTrue();
    }
  }

  @Test
  void createSecretBodyAndTagSlugs() {
    fake.fixture("POST", "/api/v4/secrets/K", "createSecret.ok");
    fake.fixture("GET", "/api/v1/projects/p1/tags", "listTags.ok");
    String tagSlug =
        Fake.fixture("listTags.ok").path("body").path("tags").get(0).path("slug").asText();
    String tagId = Fake.fixture("listTags.ok").path("body").path("tags").get(0).path("id").asText();
    try (InfisicalClient c = v4()) {
      c.createSecret("K", "v1");
      JsonNode b = Fake.json(fake.last("POST", "/api/v4/secrets/K"));
      assertThat(b.path("projectId").asText()).isEqualTo("p1");
      assertThat(b.path("secretValue").asText()).isEqualTo("v1");
      assertThat(b.has("secretComment")).isFalse();
      assertThat(b.has("tagIds")).isFalse();
      assertThat(b.has("type")).isFalse();
      c.createSecret("K", null, null);
      assertThat(Fake.json(fake.last("POST", "/api/v4/secrets/K")).path("secretValue").asText())
          .isEmpty();
      c.createSecret(
          "K",
          "v1",
          CreateSecretOptions.builder()
              .comment("c")
              .tagIds(List.of("x"))
              .tagSlugs(List.of(tagSlug))
              .type(SecretType.PERSONAL)
              .skipMultilineEncoding(true)
              .metadata(Map.of("z", "1", "a", "2"))
              .build());
      b = Fake.json(fake.last("POST", "/api/v4/secrets/K"));
      assertThat(b.path("secretComment").asText()).isEqualTo("c");
      assertThat(b.path("tagIds").toString()).isEqualTo("[\"x\",\"" + tagId + "\"]");
      assertThat(b.path("type").asText()).isEqualTo("personal");
      assertThat(b.path("skipMultilineEncoding").asBoolean()).isTrue();
      assertThat(b.path("secretMetadata").toString())
          .isEqualTo("[{\"key\":\"a\",\"value\":\"2\"},{\"key\":\"z\",\"value\":\"1\"}]");
      assertThatThrownBy(
              () ->
                  c.createSecret(
                      "K", "v", CreateSecretOptions.builder().tagSlugs(List.of("nope")).build()))
          .isInstanceOf(NotFoundException.class)
          .hasMessageContaining("tag nope");
    }
  }

  @Test
  void createSecretV3UsesWorkspaceId() {
    fake.fixture("POST", "/api/v3/secrets/raw/K", "createSecret.v3raw-ok");
    try (InfisicalClient c = v3()) {
      c.createSecret("K", "v");
      assertThat(Fake.json(fake.last("POST", "/api/v3/secrets/raw/K")).path("workspaceId").asText())
          .isEqualTo("p1");
    }
  }

  @Test
  void updateSecretBody() {
    fake.fixture("PATCH", "/api/v4/secrets/K", "updateSecret.renameCommentTags");
    try (InfisicalClient c = v4()) {
      c.updateSecret("K", null);
      JsonNode b = Fake.json(fake.last("PATCH", "/api/v4/secrets/K"));
      assertThat(b.has("secretValue")).isFalse();
      assertThat(b.has("tagIds")).isFalse();
      assertThat(b.has("newSecretName")).isFalse();
      c.updateSecret(
          "K",
          UpdateSecretOptions.builder()
              .value("v2")
              .newName("K2")
              .comment("c2")
              .tagIds(List.of())
              .type(SecretType.SHARED)
              .skipMultilineEncoding(false)
              .metadata(Map.of("m", "n"))
              .build());
      b = Fake.json(fake.last("PATCH", "/api/v4/secrets/K"));
      assertThat(b.path("secretValue").asText()).isEqualTo("v2");
      assertThat(b.path("newSecretName").asText()).isEqualTo("K2");
      assertThat(b.path("secretComment").asText()).isEqualTo("c2");
      assertThat(b.path("tagIds").isArray()).isTrue();
      assertThat(b.path("tagIds")).isEmpty();
      assertThat(b.path("type").asText()).isEqualTo("shared");
      assertThat(b.path("skipMultilineEncoding").asBoolean(true)).isFalse();
      assertThat(b.path("secretMetadata").get(0).path("key").asText()).isEqualTo("m");
      c.updateSecret("K", UpdateSecretOptions.builder().tagSlugs(List.of()).build());
      assertThat(Fake.json(fake.last("PATCH", "/api/v4/secrets/K")).path("tagIds")).isEmpty();
    }
  }

  @Test
  void deleteSecret() {
    fake.fixture("DELETE", "/api/v4/secrets/K", "deleteSecret.ok");
    fake.fixture("DELETE", "/api/v4/secrets/M", "deleteSecret.404");
    try (InfisicalClient c = v4()) {
      c.deleteSecret("K");
      JsonNode b = Fake.json(fake.last("DELETE", "/api/v4/secrets/K"));
      assertThat(b.path("environment").asText()).isEqualTo("dev");
      assertThat(b.has("type")).isFalse();
      c.deleteSecret("K", DeleteSecretOptions.builder().type(SecretType.PERSONAL).build());
      assertThat(Fake.json(fake.last("DELETE", "/api/v4/secrets/K")).path("type").asText())
          .isEqualTo("personal");
      assertThatThrownBy(() -> c.deleteSecret("M")).isInstanceOf(NotFoundException.class);
    }
  }

  @Test
  void escapesNamesInPaths() {
    fake.fixture("GET", "/api/v4/secrets/a%20b.c", "getSecret.ok");
    try (InfisicalClient c = v4()) {
      c.getSecret("a b.c");
      assertThat(fake.requests("GET", "/api/v4/secrets/a%20b.c")).hasSize(1);
    }
  }

  @Test
  void batchCreate() {
    fake.fixture("POST", "/api/v4/secrets/batch", "createSecrets.ok");
    try (InfisicalClient c = v4()) {
      List<SecretEntry> out =
          c.createSecrets(
              List.of(
                  SecretInput.of("A", "a1"),
                  SecretInput.builder()
                      .key("B")
                      .value("b1")
                      .comment("cb")
                      .tagIds(List.of("t"))
                      .skipMultilineEncoding(true)
                      .metadata(Map.of("k", "v"))
                      .build()),
              BatchScope.builder().secretPath("/app").build());
      assertThat(out).isNotEmpty();
      JsonNode b = Fake.json(fake.last("POST", "/api/v4/secrets/batch"));
      assertThat(b.path("secretPath").asText()).isEqualTo("/app");
      assertThat(b.path("secrets").get(0).has("secretComment")).isFalse();
      assertThat(b.path("secrets").get(0).has("tagIds")).isFalse();
      JsonNode second = b.path("secrets").get(1);
      assertThat(second.path("secretComment").asText()).isEqualTo("cb");
      assertThat(second.path("tagIds").get(0).asText()).isEqualTo("t");
      assertThat(second.path("skipMultilineEncoding").asBoolean()).isTrue();
      assertThat(second.path("secretMetadata").get(0).path("value").asText()).isEqualTo("v");
      assertThatThrownBy(() -> c.createSecrets(List.of(), null))
          .isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.createSecrets(null, null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.createSecrets(List.of(SecretInput.of("", "x")), null))
          .isInstanceOf(ValidationException.class);
    }
    fake.reset("POST", "/api/v4/secrets/batch")
        .fixture("POST", "/api/v4/secrets/batch", "createSecrets.duplicate400");
    try (InfisicalClient c = v4()) {
      assertThatThrownBy(() -> c.createSecrets(List.of(SecretInput.of("A", "x")), null))
          .isInstanceOf(ConflictException.class);
    }
  }

  @Test
  void batchUpdateAndDelete() {
    fake.fixture("PATCH", "/api/v4/secrets/batch", "updateSecrets.ok");
    fake.fixture("DELETE", "/api/v4/secrets/batch", "deleteSecrets.ok");
    try (InfisicalClient c = v4()) {
      c.updateSecrets(List.of(SecretUpdate.of("A", "a2")), null);
      JsonNode b = Fake.json(fake.last("PATCH", "/api/v4/secrets/batch"));
      assertThat(b.has("mode")).isFalse();
      assertThat(b.path("secrets").get(0).path("secretValue").asText()).isEqualTo("a2");
      c.updateSecrets(
          List.of(
              SecretUpdate.builder()
                  .key("A")
                  .newName("A2")
                  .comment("c")
                  .tagIds(List.of())
                  .skipMultilineEncoding(true)
                  .build()),
          UpdateSecretsOptions.builder().mode(BatchUpdateMode.UPSERT).build());
      b = Fake.json(fake.last("PATCH", "/api/v4/secrets/batch"));
      assertThat(b.path("mode").asText()).isEqualTo("upsert");
      JsonNode item = b.path("secrets").get(0);
      assertThat(item.has("secretValue")).isFalse();
      assertThat(item.path("newSecretName").asText()).isEqualTo("A2");
      assertThat(item.path("secretComment").asText()).isEqualTo("c");
      assertThat(item.path("tagIds").isArray()).isTrue();
      assertThat(item.path("skipMultilineEncoding").asBoolean()).isTrue();
      assertThat(BatchUpdateMode.FAIL_ON_NOT_FOUND.wireValue()).isEqualTo("failOnNotFound");
      assertThat(BatchUpdateMode.IGNORE.wireValue()).isEqualTo("ignore");
      assertThatThrownBy(() -> c.updateSecrets(List.of(), null))
          .isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.updateSecrets(null, null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.updateSecrets(List.of(SecretUpdate.of(" ", "x")), null))
          .isInstanceOf(ValidationException.class);

      c.deleteSecrets(List.of("A", "B"), null);
      b = Fake.json(fake.last("DELETE", "/api/v4/secrets/batch"));
      assertThat(b.path("secrets").get(1).path("secretKey").asText()).isEqualTo("B");
      assertThat(b.path("secrets").get(1).has("type")).isFalse();
      c.deleteSecrets(
          List.of("A"), DeleteSecretsOptions.builder().type(SecretType.PERSONAL).build());
      b = Fake.json(fake.last("DELETE", "/api/v4/secrets/batch"));
      assertThat(b.path("secrets").get(0).path("type").asText()).isEqualTo("personal");
      assertThatThrownBy(() -> c.deleteSecrets(List.of(), null))
          .isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.deleteSecrets(null, null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.deleteSecrets(List.of(""), null))
          .isInstanceOf(ValidationException.class);
    }
  }

  @Test
  void batchV3UsesBatchRawRoute() {
    fake.fixture("POST", "/api/v3/secrets/batch/raw", "createSecrets.v3raw-ok");
    try (InfisicalClient c = v3()) {
      c.createSecrets(List.of(SecretInput.of("A", "a")), null);
      assertThat(
              Fake.json(fake.last("POST", "/api/v3/secrets/batch/raw"))
                  .path("workspaceId")
                  .asText())
          .isEqualTo("p1");
    }
  }

  @Test
  void secretTypeWire() {
    assertThat(SecretType.fromWire(null)).isEqualTo(SecretType.SHARED);
    assertThat(SecretType.fromWire("personal")).isEqualTo(SecretType.PERSONAL);
    assertThat(SecretType.SHARED.wireValue()).isEqualTo("shared");
  }
}
