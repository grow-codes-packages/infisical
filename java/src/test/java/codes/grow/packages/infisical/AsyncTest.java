package codes.grow.packages.infisical;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Every {@code …Async} method completes with the blocking result. */
class AsyncTest {
  private final Fake fake = new Fake();

  @AfterEach
  void stop() {
    fake.close();
  }

  @Test
  void asyncVariants() throws Exception {
    fake.fixture("GET", "/api/v4/secrets", "listSecrets.ok");
    fake.fixture("GET", "/api/v4/secrets/K", "getSecret.ok");
    fake.fixture("POST", "/api/v4/secrets/K", "createSecret.ok");
    fake.fixture("PATCH", "/api/v4/secrets/K", "updateSecret.value");
    fake.fixture("DELETE", "/api/v4/secrets/K", "deleteSecret.ok");
    fake.fixture("POST", "/api/v4/secrets/batch", "createSecrets.ok");
    fake.fixture("PATCH", "/api/v4/secrets/batch", "updateSecrets.ok");
    fake.fixture("DELETE", "/api/v4/secrets/batch", "deleteSecrets.ok");
    fake.fixture("GET", "/api/v2/folders", "listFolders.ok");
    fake.fixture("POST", "/api/v2/folders", "createFolder.ok");
    fake.fixture("PATCH", "/api/v2/folders/f", "updateFolder.ok");
    fake.fixture("DELETE", "/api/v2/folders/f", "deleteFolder.ok");
    fake.fixture("GET", "/api/v1/projects", "listProjects.ok");
    fake.fixture("GET", "/api/v1/projects/p1", "getProject.ok");
    fake.fixture("GET", "/api/v1/projects/slug/s", "getProjectBySlug.ok");
    fake.fixture("POST", "/api/v1/projects/p1/environments", "createEnvironment.ok");
    fake.fixture("GET", "/api/v1/projects/p1/tags", "listTags.ok");
    fake.fixture("POST", "/api/v1/projects/p1/tags", "createTag.ok");
    fake.fixture("DELETE", "/api/v1/projects/p1/tags/t", "deleteTag.ok");
    fake.fixture("GET", "/api/v2/secret-imports", "listSecretImports.ok");
    fake.fixture("POST", "/api/v2/secret-imports", "createSecretImport.ok");
    fake.fixture("DELETE", "/api/v2/secret-imports/i", "deleteSecretImport.ok");
    fake.fixture("GET", "/api/v1/secret/s/secret-versions", "listSecretVersions.ok");
    try (InfisicalClient c = fake.client(b -> b.apiVersion("v4"))) {
      assertThat(c.listSecretsAsync(null).get().secrets()).isNotEmpty();
      assertThat(c.getSecretAsync("K", null).get().key()).isNotEmpty();
      assertThat(c.createSecretAsync("K", "v", null).get().version()).isEqualTo(1);
      assertThat(c.updateSecretAsync("K", null).get()).isNotNull();
      assertThat(c.deleteSecretAsync("K", null).get()).isNotNull();
      assertThat(c.createSecretsAsync(List.of(SecretInput.of("A", "a")), null).get()).isNotEmpty();
      assertThat(c.updateSecretsAsync(List.of(SecretUpdate.of("A", "b")), null).get()).isNotEmpty();
      assertThat(c.deleteSecretsAsync(List.of("A"), null).get()).isNotEmpty();
      assertThat(c.listFoldersAsync(null).get()).isNotNull();
      assertThat(c.createFolderAsync("f", null).get().id()).isNotEmpty();
      assertThat(
              c.updateFolderAsync("f", UpdateFolderOptions.builder().name("g").build()).get().id())
          .isNotEmpty();
      assertThat(c.deleteFolderAsync("f", null).get()).isNotNull();
      assertThat(c.listProjectsAsync(null).get().projects()).isNotEmpty();
      assertThat(c.getProjectAsync(null).get().id()).isNotEmpty();
      assertThat(c.getProjectBySlugAsync("s").get().id()).isNotEmpty();
      assertThat(c.listEnvironmentsAsync(null).get()).isNotEmpty();
      assertThat(c.createEnvironmentAsync("E", "e", null).get().slug()).isNotEmpty();
      assertThat(c.listTagsAsync(null).get()).isNotEmpty();
      assertThat(c.createTagAsync("t", null, null).get().id()).isNotEmpty();
      assertThat(c.deleteTagAsync("t", null).get().id()).isNotEmpty();
      assertThat(c.listSecretImportsAsync(null).get()).isNotEmpty();
      assertThat(
              c.createSecretImportAsync(
                      CreateSecretImportOptions.builder().importEnvironment("staging").build())
                  .get()
                  .id())
          .isNotEmpty();
      assertThat(c.deleteSecretImportAsync("i", null).get().id()).isNotEmpty();
      assertThat(c.listSecretVersionsAsync("s", null).get()).isNotEmpty();
      java.util.Map<String, String> target = new java.util.HashMap<>();
      assertThat(
              c.loadEnvAsync(
                      EnvOptions.builder()
                          .target(codes.grow.packages.infisical.secrets.EnvLoader.map(target))
                          .build())
                  .get())
          .isNotEmpty();
      assertThat(c.exportDotenvAsync(null).get()).contains("=\"");
    }
  }
}
