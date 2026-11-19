package codes.grow.packages.infisical;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.infisical.core.ConflictException;
import codes.grow.packages.infisical.core.NotFoundException;
import codes.grow.packages.infisical.core.PermissionDeniedException;
import codes.grow.packages.infisical.core.ValidationException;
import codes.grow.packages.infisical.secrets.EnvLoader;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ResourcesTest {
  private final Fake fake = new Fake();

  @AfterEach
  void stop() {
    fake.close();
  }

  @Test
  void folders() {
    fake.fixture("GET", "/api/v2/folders", "listFolders.recursive");
    fake.fixture("POST", "/api/v2/folders", "createFolder.ok");
    fake.fixture("PATCH", "/api/v2/folders/f1", "updateFolder.ok");
    fake.fixture("DELETE", "/api/v2/folders/f1", "deleteFolder.ok");
    fake.fixture("DELETE", "/api/v2/folders/gone", "deleteFolder.404");
    try (InfisicalClient c = fake.client()) {
      List<Folder> fs = c.listFolders();
      assertThat(fs).isNotEmpty();
      assertThat(fs.get(0).name()).isEqualTo("app");
      assertThat(fs.get(0).environmentId()).isNotEmpty();
      assertThat(Fake.query(fake.last("GET", "/api/v2/folders")))
          .containsEntry("path", "/")
          .doesNotContainKey("recursive");
      c.listFolders(ListFoldersOptions.builder().path("/app").recursive(true).build());
      assertThat(Fake.query(fake.last("GET", "/api/v2/folders")))
          .containsEntry("path", "/app")
          .containsEntry("recursive", "true");

      Folder f = c.createFolder("f-49lj3988", null);
      assertThat(f.version()).isEqualTo(1);
      JsonNode b = Fake.json(fake.last("POST", "/api/v2/folders"));
      assertThat(b.path("name").asText()).isEqualTo("f-49lj3988");
      assertThat(b.path("path").asText()).isEqualTo("/");
      assertThat(b.has("description")).isFalse();
      c.createFolder("x", CreateFolderOptions.builder().path("/app").description("d").build());
      b = Fake.json(fake.last("POST", "/api/v2/folders"));
      assertThat(b.path("description").asText()).isEqualTo("d");
      assertThat(b.path("path").asText()).isEqualTo("/app");

      Folder u =
          c.updateFolder("f1", UpdateFolderOptions.builder().name("g").description("new").build());
      assertThat(u.version()).isEqualTo(2);
      b = Fake.json(fake.last("PATCH", "/api/v2/folders/f1"));
      assertThat(b.path("name").asText()).isEqualTo("g");
      assertThat(b.path("description").asText()).isEqualTo("new");
      c.updateFolder("f1", UpdateFolderOptions.builder().name("g").build());
      assertThat(Fake.json(fake.last("PATCH", "/api/v2/folders/f1")).has("description")).isFalse();
      assertThatThrownBy(() -> c.updateFolder("f1", null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.updateFolder("", null)).isInstanceOf(ValidationException.class);

      c.deleteFolder("f1", DeleteFolderOptions.builder().force(true).build());
      assertThat(
              Fake.json(fake.last("DELETE", "/api/v2/folders/f1")).path("forceDelete").asBoolean())
          .isTrue();
      c.deleteFolder("f1", null);
      assertThat(Fake.json(fake.last("DELETE", "/api/v2/folders/f1")).has("forceDelete")).isFalse();
      assertThatThrownBy(() -> c.deleteFolder("gone", null)).isInstanceOf(NotFoundException.class);
      assertThatThrownBy(() -> c.deleteFolder("", null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.createFolder(null, null)).isInstanceOf(ValidationException.class);
    }
    fake.reset("POST", "/api/v2/folders")
        .fixture("POST", "/api/v2/folders", "createFolder.duplicate400");
    try (InfisicalClient c = fake.client()) {
      assertThatThrownBy(() -> c.createFolder("app", null)).isInstanceOf(ConflictException.class);
    }
  }

  @Test
  void projectsAndEnvironments() {
    fake.fixture("GET", "/api/v1/projects", "listProjects.ok");
    fake.fixture("GET", "/api/v1/projects/p1", "getProject.ok");
    fake.fixture("GET", "/api/v1/projects/slug/sdk-test", "getProjectBySlug.ok");
    fake.fixture("GET", "/api/v1/projects/nope", "getProject.404");
    fake.fixture("POST", "/api/v1/projects/p1/environments", "createEnvironment.ok");
    try (InfisicalClient c = fake.client()) {
      ProjectPage page = c.listProjects(null);
      assertThat(page.totalCount()).isGreaterThanOrEqualTo(1);
      assertThat(page.projects().get(0).slug()).isEqualTo("sdk-test");
      assertThat(Fake.query(fake.last("GET", "/api/v1/projects")))
          .containsEntry("type", "secret-manager")
          .doesNotContainKeys("limit", "offset");
      c.listProjects(ListProjectsOptions.builder().type("kms").limit(10).offset(5).build());
      assertThat(Fake.query(fake.last("GET", "/api/v1/projects")))
          .containsEntry("type", "kms")
          .containsEntry("limit", "10")
          .containsEntry("offset", "5");
      for (ListProjectsOptions bad :
          List.of(
              ListProjectsOptions.builder().limit(-1).build(),
              ListProjectsOptions.builder().limit(101).build(),
              ListProjectsOptions.builder().offset(-1).build())) {
        assertThatThrownBy(() -> c.listProjects(bad)).isInstanceOf(ValidationException.class);
      }

      Project p = c.getProject(null);
      assertThat(p.name()).isEqualTo("SDK Test");
      assertThat(p.type()).isEqualTo("secret-manager");
      assertThat(p.orgId()).isNotEmpty();
      assertThat(p.description()).isNotEmpty();
      assertThat(p.environments()).extracting(Environment::slug).contains("dev", "staging");
      assertThat(c.getProject("p1").id()).isEqualTo(p.id());
      assertThat(c.getProjectBySlug("sdk-test").slug()).isEqualTo("sdk-test");
      assertThatThrownBy(() -> c.getProjectBySlug("")).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.getProject("nope")).isInstanceOf(NotFoundException.class);
      assertThat(c.listEnvironments(null)).extracting(Environment::slug).contains("dev");
      assertThat(c.listEnvironments(ProjectOptions.builder().projectId("p1").build())).isNotEmpty();

      Environment e = c.createEnvironment("E", "e-1", null);
      assertThat(e.position()).isEqualTo(5);
      JsonNode b = Fake.json(fake.last("POST", "/api/v1/projects/p1/environments"));
      assertThat(b.path("slug").asText()).isEqualTo("e-1");
      assertThat(b.has("position")).isFalse();
      c.createEnvironment("E", "e-2", CreateEnvironmentOptions.builder().position(3).build());
      assertThat(
              Fake.json(fake.last("POST", "/api/v1/projects/p1/environments"))
                  .path("position")
                  .asInt())
          .isEqualTo(3);
      assertThatThrownBy(() -> c.createEnvironment("", "x", null))
          .isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.createEnvironment("x", "", null))
          .isInstanceOf(ValidationException.class);
    }
    fake.reset("POST", "/api/v1/projects/p1/environments")
        .fixture("POST", "/api/v1/projects/p1/environments", "createEnvironment.403viewer");
    try (InfisicalClient c = fake.client()) {
      assertThatThrownBy(() -> c.createEnvironment("E", "e", null))
          .isInstanceOf(PermissionDeniedException.class);
    }
  }

  @Test
  void tags() {
    fake.fixture("GET", "/api/v1/projects/p1/tags", "listTags.ok");
    fake.fixture("POST", "/api/v1/projects/p1/tags", "createTag.ok");
    fake.fixture("DELETE", "/api/v1/projects/p1/tags/t1", "deleteTag.ok");
    fake.fixture("DELETE", "/api/v1/projects/p1/tags/gone", "deleteTag.404");
    try (InfisicalClient c = fake.client()) {
      assertThat(c.listTags(null)).isNotEmpty();
      Tag t = c.createTag("t-49lj3988", null, null);
      assertThat(t.color()).isEqualTo("#00aa00");
      assertThat(t.projectId()).isNotEmpty();
      assertThat(Fake.json(fake.last("POST", "/api/v1/projects/p1/tags")).path("color").asText())
          .isEqualTo(InfisicalClient.DEFAULT_TAG_COLOR);
      c.createTag("x", "", null);
      c.createTag("x", "#123456", ProjectOptions.builder().projectId("p1").build());
      assertThat(Fake.json(fake.last("POST", "/api/v1/projects/p1/tags")).path("color").asText())
          .isEqualTo("#123456");
      assertThat(c.deleteTag("t1", null).slug()).isEqualTo("t-49lj3988");
      assertThatThrownBy(() -> c.deleteTag("gone", null)).isInstanceOf(NotFoundException.class);
      assertThatThrownBy(() -> c.deleteTag("", null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.createTag("", null, null)).isInstanceOf(ValidationException.class);
    }
  }

  @Test
  void secretImports() {
    fake.fixture("GET", "/api/v2/secret-imports", "listSecretImports.ok");
    fake.fixture("POST", "/api/v2/secret-imports", "createSecretImport.ok");
    fake.fixture("DELETE", "/api/v2/secret-imports/i1", "deleteSecretImport.ok");
    fake.fixture("DELETE", "/api/v2/secret-imports/gone", "deleteSecretImport.404");
    try (InfisicalClient c = fake.client()) {
      List<SecretImport> l = c.listSecretImports(null);
      assertThat(l).hasSize(1);
      SecretImport i = l.get(0);
      assertThat(i.importPath()).isEqualTo("/common");
      assertThat(i.importEnvironment().slug()).isEqualTo("staging");
      assertThat(i.position()).isEqualTo(1);
      assertThat(i.isReplication()).isFalse();
      assertThat(i.folderId()).isNotEmpty();
      assertThat(Fake.query(fake.last("GET", "/api/v2/secret-imports"))).containsEntry("path", "/");

      c.createSecretImport(
          CreateSecretImportOptions.builder()
              .path("/app")
              .importEnvironment("staging")
              .importPath("common")
              .build());
      JsonNode b = Fake.json(fake.last("POST", "/api/v2/secret-imports"));
      assertThat(b.path("path").asText()).isEqualTo("/app");
      assertThat(b.path("import").path("environment").asText()).isEqualTo("staging");
      assertThat(b.path("import").path("path").asText()).isEqualTo("/common");
      assertThat(b.path("import").has("sourceProjectId")).isFalse();
      assertThat(b.has("isReplication")).isFalse();
      c.createSecretImport(
          CreateSecretImportOptions.builder()
              .importEnvironment("staging")
              .sourceProjectId("p9")
              .isReplication(true)
              .build());
      b = Fake.json(fake.last("POST", "/api/v2/secret-imports"));
      assertThat(b.path("import").path("path").asText()).isEqualTo("/");
      assertThat(b.path("import").path("sourceProjectId").asText()).isEqualTo("p9");
      assertThat(b.path("isReplication").asBoolean()).isTrue();
      assertThatThrownBy(() -> c.createSecretImport(null)).isInstanceOf(ValidationException.class);

      assertThat(
              c.deleteSecretImport("i1", SecretImportOptions.builder().path("/app").build()).id())
          .isNotEmpty();
      assertThat(Fake.json(fake.last("DELETE", "/api/v2/secret-imports/i1")).path("path").asText())
          .isEqualTo("/app");
      assertThatThrownBy(() -> c.deleteSecretImport("gone", null))
          .isInstanceOf(NotFoundException.class);
      assertThatThrownBy(() -> c.deleteSecretImport("", null))
          .isInstanceOf(ValidationException.class);
    }
  }

  @Test
  void secretVersions() {
    fake.fixture("GET", "/api/v1/secret/s1/secret-versions", "listSecretVersions.ok");
    fake.fixture("GET", "/api/v1/secret/s2/secret-versions", "listSecretVersions.identity403");
    String withActor =
        "{\"secretVersions\":[{\"id\":\"v\",\"version\":1,\"secretKey\":\"K\","
            + "\"secretValueHidden\":true,\"actor\":null},{\"id\":\"w\",\"actor\":\"x\"}]}";
    fake.on("GET", "/api/v1/secret/s3/secret-versions", 200, withActor);
    try (InfisicalClient c = fake.client(b -> b.token(Fake.USER_JWT))) {
      List<SecretVersion> vs = c.listSecretVersions("s1", null);
      assertThat(vs).isNotEmpty();
      SecretVersion v = vs.get(0);
      assertThat(v.version()).isEqualTo(3);
      assertThat(v.value().reveal()).isEqualTo("v2-49lj3988");
      assertThat(v.key()).isEqualTo("SDK_49LJ3988_RENAMED");
      assertThat(v.comment()).isEqualTo("c2");
      assertThat(v.environment()).isEqualTo("dev");
      assertThat(v.type()).isEqualTo(SecretType.SHARED);
      assertThat(v.actor()).hasValueSatisfying(a -> assertThat(a.type()).isEqualTo("identity"));
      assertThat(v.createdAt()).isPresent();
      assertThat(Fake.query(fake.last("GET", "/api/v1/secret/s1/secret-versions")))
          .containsEntry("offset", "0")
          .containsEntry("limit", "20");
      c.listSecretVersions("s1", ListSecretVersionsOptions.builder().offset(2).limit(5).build());
      assertThat(Fake.query(fake.last("GET", "/api/v1/secret/s1/secret-versions")))
          .containsEntry("offset", "2")
          .containsEntry("limit", "5");
      c.listSecretVersions("s1", ListSecretVersionsOptions.builder().limit(0).build());
      assertThat(Fake.query(fake.last("GET", "/api/v1/secret/s1/secret-versions")))
          .containsEntry("limit", "20");
      for (ListSecretVersionsOptions bad :
          List.of(
              ListSecretVersionsOptions.builder().offset(-1).build(),
              ListSecretVersionsOptions.builder().limit(-1).build(),
              ListSecretVersionsOptions.builder().limit(1001).build())) {
        assertThatThrownBy(() -> c.listSecretVersions("s1", bad))
            .isInstanceOf(ValidationException.class);
      }
      assertThatThrownBy(() -> c.listSecretVersions("", null))
          .isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.listSecretVersions("s2", null))
          .isInstanceOf(PermissionDeniedException.class);
      List<SecretVersion> hidden = c.listSecretVersions("s3", null);
      assertThat(hidden.get(0).valueHidden()).isTrue();
      assertThat(hidden.get(0).actor()).isEmpty();
      assertThat(hidden.get(1).actor()).isEmpty();
    }
  }

  @Test
  void loadEnvAndDotenv() {
    String body =
        "{\"secrets\":[{\"secretKey\":\"A\",\"secretValue\":\"one\",\"secretPath\":\"/app\"},"
            + "{\"secretKey\":\"B\",\"secretValue\":\"two\\nlines \\\"q\\\" \\\\ \\r\",\"secretPath\":\"/app\"},"
            + "{\"secretKey\":\"A\",\"secretValue\":\"deep\",\"secretPath\":\"/app/x\"}],"
            + "\"imports\":[{\"secretPath\":\"/common\",\"environment\":\"staging\","
            + "\"secrets\":[{\"secretKey\":\"C\",\"secretValue\":\"imp\"},"
            + "{\"secretKey\":\"A\",\"secretValue\":\"imp-a\"}]}]}";
    fake.on("GET", "/api/v4/secrets", 200, body);
    try (InfisicalClient c = fake.client(b -> b.apiVersion("v4"))) {
      Map<String, String> target = new HashMap<>(Map.of("B", "keep"));
      Map<String, String> set =
          c.loadEnv(
              EnvOptions.builder()
                  .secretPath("/app")
                  .recursive(true)
                  .target(EnvLoader.map(target))
                  .build());
      assertThat(set.keySet()).containsExactly("A", "C");
      assertThat(set).containsEntry("A", "A");
      assertThat(target)
          .containsEntry("A", "one")
          .containsEntry("B", "keep")
          .containsEntry("C", "imp");
      Map<String, String> q = Fake.query(fake.last("GET", "/api/v4/secrets"));
      assertThat(q).containsEntry("recursive", "true").containsEntry("secretPath", "/app");
      set =
          c.loadEnv(
              EnvOptions.builder()
                  .override(true)
                  .includeImports(false)
                  .expandReferences(false)
                  .target(EnvLoader.map(target))
                  .build());
      assertThat(set.keySet()).containsExactly("A", "B", "C");
      assertThat(target.get("B")).startsWith("two");
      q = Fake.query(fake.last("GET", "/api/v4/secrets"));
      assertThat(q)
          .containsEntry("includeImports", "false")
          .containsEntry("expandSecretReferences", "false");

      String doc = c.exportDotenv(null);
      assertThat(doc).isEqualTo("A=\"one\"\nB=\"two\\nlines \\\"q\\\" \\\\ \\r\"\nC=\"imp\"\n");
      String prop = "INFISICAL_JAVA_TEST_" + System.nanoTime();
      fake.reset("GET", "/api/v4/secrets")
          .on(
              "GET",
              "/api/v4/secrets",
              200,
              "{\"secrets\":[{\"secretKey\":\"" + prop + "\",\"secretValue\":\"v\"}]}");
      try {
        assertThat(c.loadEnv(null).keySet()).containsExactly(prop);
        assertThat(System.getProperty(prop)).isEqualTo("v");
      } finally {
        System.clearProperty(prop);
      }
    }
    assertThat(InfisicalClient.formatDotenv(Map.of())).isEmpty();
  }
}
