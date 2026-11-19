package codes.grow.packages.infisical.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import codes.grow.packages.infisical.AccessToken;
import codes.grow.packages.infisical.AwsIamAuth;
import codes.grow.packages.infisical.AwsLoginRequest;
import codes.grow.packages.infisical.BatchScope;
import codes.grow.packages.infisical.BatchUpdateMode;
import codes.grow.packages.infisical.CreateFolderOptions;
import codes.grow.packages.infisical.CreateSecretImportOptions;
import codes.grow.packages.infisical.CreateSecretOptions;
import codes.grow.packages.infisical.DeleteFolderOptions;
import codes.grow.packages.infisical.DeleteSecretOptions;
import codes.grow.packages.infisical.EnvOptions;
import codes.grow.packages.infisical.Environment;
import codes.grow.packages.infisical.Folder;
import codes.grow.packages.infisical.GetSecretOptions;
import codes.grow.packages.infisical.InfisicalClient;
import codes.grow.packages.infisical.InfisicalConfig;
import codes.grow.packages.infisical.KubernetesAuth;
import codes.grow.packages.infisical.ListFoldersOptions;
import codes.grow.packages.infisical.ListProjectsOptions;
import codes.grow.packages.infisical.ListSecretVersionsOptions;
import codes.grow.packages.infisical.ListSecretsOptions;
import codes.grow.packages.infisical.Project;
import codes.grow.packages.infisical.ProjectPage;
import codes.grow.packages.infisical.ProjectSecretsProvider;
import codes.grow.packages.infisical.SecretEntry;
import codes.grow.packages.infisical.SecretImport;
import codes.grow.packages.infisical.SecretImportOptions;
import codes.grow.packages.infisical.SecretInput;
import codes.grow.packages.infisical.SecretList;
import codes.grow.packages.infisical.SecretType;
import codes.grow.packages.infisical.SecretUpdate;
import codes.grow.packages.infisical.SecretVersion;
import codes.grow.packages.infisical.SecretsProviderOptions;
import codes.grow.packages.infisical.Tag;
import codes.grow.packages.infisical.TokenAuth;
import codes.grow.packages.infisical.UniversalAuth;
import codes.grow.packages.infisical.UpdateFolderOptions;
import codes.grow.packages.infisical.UpdateSecretOptions;
import codes.grow.packages.infisical.UpdateSecretsOptions;
import codes.grow.packages.infisical.core.AuthenticationException;
import codes.grow.packages.infisical.core.ConflictException;
import codes.grow.packages.infisical.core.EnvReader;
import codes.grow.packages.infisical.core.HealthStatus;
import codes.grow.packages.infisical.core.NotFoundException;
import codes.grow.packages.infisical.core.PermissionDeniedException;
import codes.grow.packages.infisical.core.Secret;
import codes.grow.packages.infisical.core.UnsupportedException;
import codes.grow.packages.infisical.core.ValidationException;
import codes.grow.packages.infisical.secrets.DeleteOptions;
import codes.grow.packages.infisical.secrets.EnvLoader;
import codes.grow.packages.infisical.secrets.GetOptions;
import codes.grow.packages.infisical.secrets.LoadEnvOptions;
import codes.grow.packages.infisical.secrets.SecretCache;
import codes.grow.packages.infisical.secrets.SecretMetadata;
import codes.grow.packages.infisical.secrets.SecretValue;
import codes.grow.packages.infisical.secrets.SetOptions;
import codes.grow.packages.infisical.secrets.WatchHandle;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Integration tests: every public function of the package is called against the real Infisical
 * from docker/compose.yml with a round-trip assertion.
 */
class IntegrationTest {
  private Map<String, String> env;
  private String run;
  private String key;
  private String project;
  private String environment;
  private InfisicalClient c;
  private final List<InfisicalClient> extra = new ArrayList<>();

  @BeforeEach
  void setUp() throws IOException {
    env = ConformanceTest.environment();
    assumeTrue(env.containsKey("GROW_INFISICAL_URL"), "use docker/compose.yml");
    byte[] b = new byte[4];
    new SecureRandom().nextBytes(b);
    run = HexFormat.of().formatHex(b);
    key = "SDKJAVA_" + run.toUpperCase(Locale.ROOT) + "_";
    project = must("INFISICAL_PROJECT_ID");
    environment = must("INFISICAL_ENVIRONMENT");
    c = InfisicalClient.builder().fromEnv(EnvReader.of(env)).build();
  }

  @AfterEach
  void tearDown() {
    if (c != null) {
      c.close();
    }
    extra.forEach(InfisicalClient::close);
  }

  private String must(String name) {
    String v = env.get(name);
    assertNotNull(v, name + " missing from the bootstrap environment");
    return v;
  }

  /** A client for the same server with a different auth (no client id/secret). */
  private InfisicalClient clientWith(Consumer<InfisicalConfig.Builder> mutate) {
    Map<String, String> noUa = new HashMap<>(env);
    noUa.keySet()
        .removeAll(
            List.of(
                "INFISICAL_CLIENT_ID",
                "INFISICAL_CLIENT_SECRET",
                "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID",
                "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET",
                "GROW_INFISICAL_CLIENT_ID",
                "GROW_INFISICAL_CLIENT_SECRET",
                "INFISICAL_TOKEN",
                "GROW_INFISICAL_TOKEN"));
    InfisicalConfig.Builder b = InfisicalConfig.builder();
    mutate.accept(b);
    InfisicalClient x = InfisicalClient.create(b.fromEnv(EnvReader.of(noUa)).build());
    extra.add(x);
    return x;
  }

  private static String reveal(SecretEntry s) {
    return s.value().reveal();
  }

  @Test
  void coreClient() throws Exception {
    HealthStatus h = c.health();
    assertTrue(h.healthy());
    assertEquals("ok", h.status());
    assertTrue(c.healthAsync().get().healthy());
    assertTrue(c.ping().toNanos() > 0);
    assertTrue(c.pingAsync().get().toNanos() > 0);
    assertThrows(UnsupportedException.class, c::serverVersion);
    assertThrows(Exception.class, () -> c.serverVersionAsync().get());
    assertEquals(project, c.config().projectId().orElseThrow());
    assertEquals(environment, c.config().environment().orElseThrow());
    assertFalse(c.config().toString().contains(must("INFISICAL_CLIENT_SECRET")));
    assertFalse(c.toString().contains(must("INFISICAL_CLIENT_SECRET")));
    c.getSecret(must("INFISICAL_SEED_SECRET_NAME"));
    assertEquals("v4", c.apiVersion("secrets"));
    assertEquals("v2", c.apiVersion("folders"));
    assertNotNull(c.transport());
    assertNotNull(InfisicalConfig.fromEnv(env).url());
    c.close();
    c.close();
    assertTrue(c.isClosed());
  }

  @Test
  void authMethods() throws Exception {
    String seed = must("INFISICAL_SEED_SECRET_NAME");
    String seedValue = must("INFISICAL_SEED_SECRET_VALUE");

    // Universal Auth through the token manager
    assertInstanceOf(UniversalAuth.class, c.auth().method().orElseThrow());
    AccessToken tok = c.auth().login();
    assertTrue(tok.expiresIn().toSeconds() > 0 && tok.maxTtl().compareTo(tok.expiresIn()) >= 0);
    assertTrue(tok.expiresAt().isPresent());
    AccessToken renewed = c.auth().renew();
    assertEquals(c.auth().token().orElseThrow().token().reveal(), renewed.token().reveal());
    Secret old = c.auth().token().orElseThrow().token();
    c.auth().revoke();
    assertTrue(c.auth().token().isEmpty());
    InfisicalClient stale = clientWith(b -> b.token(old));
    assertThrows(AuthenticationException.class, stale::ping);
    assertEquals(seedValue, reveal(c.getSecret(seed)));
    c.auth().setToken(old);
    c.ping(); // 401 then one re-login
    assertNotNull(c.auth().loginAsync().get());
    assertNotNull(c.auth().renewAsync().get());
    c.auth().revokeAsync().get();

    // UniversalAuth methods
    UniversalAuth ua =
        new UniversalAuth(must("INFISICAL_CLIENT_ID"), must("INFISICAL_CLIENT_SECRET"));
    AccessToken t1 = ua.login(c);
    AccessToken t2 = ua.renew(c, t1.token());
    assertTrue(t2.expiresIn().toSeconds() > 0);
    ua.revoke(c, t2.token());
    assertThrows(AuthenticationException.class, () -> ua.renew(c, t2.token()));
    AccessToken t3 = ua.loginAsync(c).get();
    ua.renewAsync(c, t3.token()).get();
    ua.revokeAsync(c, t3.token()).get();
    InfisicalClient bad =
        clientWith(
            b -> b.auth(new UniversalAuth(must("INFISICAL_CLIENT_ID"), "wrong-secret-" + run)));
    assertThrows(AuthenticationException.class, bad::ping);

    // Token auth: machine identity token, legacy service token, user JWT
    for (String name :
        List.of("INFISICAL_VIEWER_TOKEN", "INFISICAL_SERVICE_TOKEN", "INFISICAL_USER_TOKEN")) {
      TokenAuth ta = new TokenAuth(must(name));
      InfisicalClient tc = clientWith(b -> b.auth(ta));
      tc.ping();
      assertEquals(seedValue, reveal(tc.getSecret(seed)), name);
      assertEquals(must(name), ta.login(tc).token().reveal());
    }
    InfisicalClient malformed = clientWith(b -> b.token("not-a-token-" + run));
    assertThrows(AuthenticationException.class, malformed::ping);
    InfisicalClient noAccess = clientWith(b -> b.token(must("INFISICAL_NOACCESS_TOKEN")));
    assertThrows(PermissionDeniedException.class, noAccess::listSecrets);

    // Kubernetes and AWS: request shapes (the identity has neither method configured)
    String id = must("INFISICAL_NOACCESS_IDENTITY_ID");
    KubernetesAuth k8s =
        KubernetesAuth.builder()
            .identityId(id)
            .jwt(Secret.of("eyJhbGciOiJSUzI1NiJ9.e30.sig"))
            .build();
    NotFoundException kn = assertThrows(NotFoundException.class, () -> k8s.login(c));
    assertTrue(kn.getMessage().contains("Kubernetes auth method not found"), kn.getMessage());
    AwsIamAuth aws =
        AwsIamAuth.builder()
            .identityId(id)
            .region("us-east-1")
            .accessKeyId("AKIDEXAMPLE")
            .secretAccessKey(Secret.of("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"))
            .build();
    AwsLoginRequest req = aws.loginRequest();
    assertFalse(req.iamRequestHeaders().isEmpty());
    NotFoundException an = assertThrows(NotFoundException.class, () -> aws.login(c));
    assertTrue(an.getMessage().contains("AWS auth method not found"), an.getMessage());
  }

  @Test
  void secretsCrud() throws Exception {
    String k = key + "ONE";
    Tag tag = c.createTag("java-" + run, "#00aa00", null);
    try {
      SecretEntry created =
          c.createSecret(
              k,
              "v1-" + run,
              CreateSecretOptions.builder().comment("c1").tagSlugs(List.of(tag.slug())).build());
      assertEquals(1, created.version());
      SecretEntry got = c.getSecret(k);
      assertEquals("v1-" + run, reveal(got));
      assertEquals("c1", got.comment());
      assertEquals(tag.slug(), got.tags().get(0).slug());
      assertThrows(ConflictException.class, () -> c.createSecret(k, "dup"));

      c.updateSecret(k, UpdateSecretOptions.builder().value("v2-" + run).build());
      got = c.getSecret(k);
      assertEquals("v2-" + run, reveal(got));
      assertEquals(2, got.version());
      assertEquals(
          "v1-" + run, reveal(c.getSecret(k, GetSecretOptions.builder().version(1).build())));
      String renamed = key + "RENAMED";
      c.updateSecret(
          k,
          UpdateSecretOptions.builder().newName(renamed).comment("c2").tagIds(List.of()).build());
      got = c.getSecret(renamed);
      assertEquals("c2", got.comment());
      assertTrue(got.tags().isEmpty());
      assertEquals("v2-" + run, reveal(got));
      assertThrows(NotFoundException.class, () -> c.getSecret(k));

      SecretList list = c.listSecrets();
      assertTrue(list.secrets().stream().anyMatch(s -> s.key().equals(renamed)));
      c.updateSecret(renamed, UpdateSecretOptions.builder().tagSlugs(List.of(tag.slug())).build());
      SecretList tagged =
          c.listSecrets(ListSecretsOptions.builder().tagSlugs(List.of(tag.slug())).build());
      assertEquals(1, tagged.secrets().size());
      assertEquals(renamed, tagged.secrets().get(0).key());
      assertTrue(
          c.getSecret(renamed, GetSecretOptions.builder().viewSecretValue(false).build())
              .valueHidden());

      // references: expanded by default, raw on request
      String host = key + "HOST";
      String dsn = key + "DSN";
      c.createSecret(host, "db.local");
      c.createSecret(dsn, "pg://${" + host + "}/x");
      assertEquals("pg://db.local/x", reveal(c.getSecret(dsn)));
      assertEquals(
          "pg://${" + host + "}/x",
          reveal(c.getSecret(dsn, GetSecretOptions.builder().expandReferences(false).build())));

      // async variants
      String ak = key + "ASYNC";
      c.createSecretAsync(ak, "a1", null).get();
      assertEquals("a1", reveal(c.getSecretAsync(ak, null).get()));
      c.updateSecretAsync(ak, UpdateSecretOptions.builder().value("a2").build()).get();
      assertTrue(
          c.listSecretsAsync(null).get().secrets().stream()
              .anyMatch(s -> s.key().equals(ak) && s.value().reveal().equals("a2")));
      c.deleteSecretAsync(ak, null).get();

      for (String name : List.of(renamed, host, dsn)) {
        c.deleteSecret(name);
      }
      assertThrows(NotFoundException.class, () -> c.getSecret(renamed));
      assertThrows(NotFoundException.class, () -> c.deleteSecret(renamed));
    } finally {
      c.deleteTag(tag.id(), null);
    }
  }

  @Test
  void secretsBatch() throws Exception {
    String a = key + "BA";
    String b = key + "BB";
    String up = key + "UP";
    List<SecretEntry> out =
        c.createSecrets(
            List.of(
                SecretInput.of(a, "a1"),
                SecretInput.builder().key(b).value("b1").comment("cb").build()),
            null);
    assertEquals(2, out.size());
    SecretEntry rb = c.getSecret(b);
    assertEquals("b1", reveal(rb));
    assertEquals("cb", rb.comment());
    assertThrows(
        ConflictException.class, () -> c.createSecrets(List.of(SecretInput.of(a, "dup")), null));
    c.updateSecrets(List.of(SecretUpdate.of(a, "a2")), null);
    assertEquals("a2", reveal(c.getSecret(a)));
    assertThrows(
        NotFoundException.class, () -> c.updateSecrets(List.of(SecretUpdate.of(up, "u")), null));
    c.updateSecrets(
        List.of(SecretUpdate.of(up, "u")),
        UpdateSecretsOptions.builder().mode(BatchUpdateMode.UPSERT).build());
    assertEquals("u", reveal(c.getSecret(up)));
    c.deleteSecrets(List.of(a, b, up), null);
    assertTrue(c.listSecrets().secrets().stream().noneMatch(s -> s.key().startsWith(key)));
    assertThrows(NotFoundException.class, () -> c.deleteSecrets(List.of(a), null));

    String x = key + "AB";
    c.createSecretsAsync(List.of(SecretInput.of(x, "1")), null).get();
    c.updateSecretsAsync(List.of(SecretUpdate.of(x, "2")), null).get();
    assertEquals("2", reveal(c.getSecret(x)));
    c.deleteSecretsAsync(List.of(x), null).get();
  }

  @Test
  void secretsV3Forced() {
    InfisicalClient v3 =
        clientWith(
            b ->
                b.apiVersion(InfisicalConfig.API_VERSION_V3)
                    .clientId(must("INFISICAL_CLIENT_ID"))
                    .clientSecret(must("INFISICAL_CLIENT_SECRET")));
    String k = key + "V3";
    v3.createSecret(k, "r1");
    assertEquals("r1", reveal(v3.getSecret(k)));
    v3.updateSecret(k, UpdateSecretOptions.builder().value("r2").build());
    assertTrue(
        v3.listSecrets().secrets().stream()
            .anyMatch(s -> s.key().equals(k) && s.value().reveal().equals("r2")));
    v3.deleteSecret(k);
    v3.createSecrets(List.of(SecretInput.of(k + "B", "x")), null);
    v3.updateSecrets(List.of(SecretUpdate.of(k + "B", "y")), null);
    assertEquals("y", reveal(c.getSecret(k + "B")));
    v3.deleteSecrets(List.of(k + "B"), null);
    assertEquals("v3", v3.apiVersion("secrets"));
  }

  @Test
  void personalSecretsAndVersions() throws Exception {
    InfisicalClient user = clientWith(b -> b.token(must("INFISICAL_USER_TOKEN")));
    String k = key + "PERS";
    SecretEntry shared = c.createSecret(k, "shared-1");
    c.updateSecret(k, UpdateSecretOptions.builder().value("shared-2").build());
    List<SecretVersion> vs =
        user.listSecretVersions(shared.id(), ListSecretVersionsOptions.builder().limit(10).build());
    assertEquals(2, vs.size());
    assertEquals(2, vs.get(0).version());
    assertEquals("shared-2", vs.get(0).value().reveal());
    assertEquals("shared-1", vs.get(1).value().reveal());
    assertEquals(2, user.listSecretVersionsAsync(shared.id(), null).get().size());
    assertThrows(PermissionDeniedException.class, () -> c.listSecretVersions(shared.id(), null));

    user.createSecret(k, "mine", CreateSecretOptions.builder().type(SecretType.PERSONAL).build());
    SecretEntry mine = user.getSecret(k, GetSecretOptions.builder().type(SecretType.PERSONAL).build());
    assertEquals("mine", reveal(mine));
    assertEquals(SecretType.PERSONAL, mine.type());
    SecretList ov =
        user.listSecrets(ListSecretsOptions.builder().includePersonalOverrides(true).build());
    assertTrue(
        ov.secrets().stream().anyMatch(s -> s.key().equals(k) && s.value().reveal().equals("mine")));
    user.deleteSecret(k, DeleteSecretOptions.builder().type(SecretType.PERSONAL).build());
    assertEquals("shared-2", reveal(c.getSecret(k)));
    assertThrows(
        ValidationException.class,
        () ->
            c.createSecret(
                k + "X", "x", CreateSecretOptions.builder().type(SecretType.PERSONAL).build()));
    c.deleteSecret(k);
  }

  @Test
  void folders() throws Exception {
    String name = "java-" + run;
    Folder folder =
        c.createFolder(name, CreateFolderOptions.builder().path("/").description("d").build());
    assertEquals("/" + name, folder.path());
    c.createFolder("child", CreateFolderOptions.builder().path("/" + name).build());
    List<Folder> fs =
        c.listFolders(ListFoldersOptions.builder().path("/" + name).recursive(true).build());
    assertEquals(1, fs.size());
    assertEquals("child", fs.get(0).name());
    assertThrows(ConflictException.class, () -> c.createFolder(name, null));
    assertThrows(ValidationException.class, () -> c.createFolder("bad name!", null));
    c.updateFolder(folder.id(), UpdateFolderOptions.builder().path("/").name(name + "-r").build());
    assertTrue(c.listFolders().stream().anyMatch(f -> f.name().equals(name + "-r")));
    c.deleteFolder(folder.id(), DeleteFolderOptions.builder().path("/").force(true).build());
    assertTrue(c.listFolders().stream().noneMatch(f -> f.id().equals(folder.id())));
    assertThrows(NotFoundException.class, () -> c.deleteFolder(folder.id(), null));

    String an = "javaa-" + run;
    Folder af = c.createFolderAsync(an, null).get();
    assertTrue(c.listFoldersAsync(null).get().stream().anyMatch(f -> f.id().equals(af.id())));
    c.updateFolderAsync(af.id(), UpdateFolderOptions.builder().name(an + "-r").build()).get();
    c.deleteFolderAsync(af.id(), DeleteFolderOptions.builder().force(true).build()).get();
  }

  @Test
  void projectsEnvironmentsTags() throws Exception {
    ProjectPage page = c.listProjects(ListProjectsOptions.builder().limit(100).build());
    assertTrue(page.projects().stream().anyMatch(p -> p.id().equals(project)));
    assertTrue(page.totalCount() >= 1);
    assertTrue(c.listProjectsAsync(null).get().totalCount() >= 1);
    Project p = c.getProject(null);
    assertEquals(project, p.id());
    assertEquals(must("INFISICAL_PROJECT_SLUG"), p.slug());
    assertEquals(project, c.getProjectAsync(project).get().id());
    assertEquals(p.id(), c.getProjectBySlug(p.slug()).id());
    assertEquals(p.id(), c.getProjectBySlugAsync(p.slug()).get().id());
    String slug = "java-" + run;
    Environment created = c.createEnvironment("Java " + run, slug, null);
    assertEquals(slug, created.slug());
    List<Environment> envs = c.listEnvironments(null);
    assertTrue(envs.stream().anyMatch(e -> e.slug().equals(slug)));
    assertTrue(
        envs.stream().anyMatch(e -> e.slug().equals(must("INFISICAL_ENVIRONMENT_STAGING"))));
    assertTrue(c.listEnvironmentsAsync(null).get().stream().anyMatch(e -> e.slug().equals(slug)));
    assertThrows(ConflictException.class, () -> c.createEnvironment("Dup", slug, null));
    InfisicalClient viewer = clientWith(b -> b.token(must("INFISICAL_VIEWER_TOKEN")));
    assertThrows(
        PermissionDeniedException.class,
        () -> viewer.createEnvironment("No", "no-" + run, null));
    assertEquals(
        "javaa-" + run, c.createEnvironmentAsync("JA " + run, "javaa-" + run, null).get().slug());

    Tag tag = c.createTag("tag-" + run, null, null);
    assertTrue(
        c.listTags(null).stream()
            .anyMatch(t -> t.id().equals(tag.id()) && t.slug().equals("tag-" + run)));
    assertThrows(ConflictException.class, () -> c.createTag("tag-" + run, null, null));
    c.deleteTag(tag.id(), null);
    assertTrue(c.listTags(null).stream().noneMatch(t -> t.id().equals(tag.id())));
    Tag at = c.createTagAsync("taga-" + run, "#112233", null).get();
    assertTrue(c.listTagsAsync(null).get().stream().anyMatch(t -> t.id().equals(at.id())));
    c.deleteTagAsync(at.id(), null).get();
  }

  @Test
  void importsLoadEnvDotenv() throws Exception {
    String folder = "/imp-" + run;
    c.createFolder("imp-" + run, null);
    String k1 = key + "E1";
    String k2 = key + "E2";
    c.createSecrets(
        List.of(SecretInput.of(k1, "one"), SecretInput.of(k2, "two\nlines")),
        BatchScope.builder().secretPath(folder).build());
    String staging = must("INFISICAL_ENVIRONMENT_STAGING");
    SecretImport imp =
        c.createSecretImport(
            CreateSecretImportOptions.builder()
                .path(folder)
                .importEnvironment(staging)
                .importPath("/common")
                .build());
    List<SecretImport> imps =
        c.listSecretImports(SecretImportOptions.builder().path(folder).build());
    assertEquals(1, imps.size());
    assertEquals(imp.id(), imps.get(0).id());
    assertEquals(staging, imps.get(0).importEnvironment().slug());
    assertEquals("/common", imps.get(0).importPath());
    SecretList list = c.listSecrets(ListSecretsOptions.builder().secretPath(folder).build());
    assertEquals(1, list.imports().size());
    assertEquals("common-value-1", list.merged().get("SDK_COMMON").value().reveal());

    Map<String, String> target = new HashMap<>(Map.of(k2, "keep"));
    Map<String, String> names =
        c.loadEnv(EnvOptions.builder().secretPath(folder).target(EnvLoader.map(target)).build());
    assertEquals(k1, names.get(k1));
    assertFalse(names.containsKey(k2));
    assertEquals("one", target.get(k1));
    assertEquals("keep", target.get(k2));
    assertEquals("common-value-1", target.get("SDK_COMMON"));
    // default target: system properties
    try {
      Map<String, String> props =
          c.loadEnvAsync(EnvOptions.builder().secretPath(folder).build()).get();
      assertTrue(props.containsKey(k1));
      assertEquals("one", System.getProperty(k1));
    } finally {
      System.clearProperty(k1);
      System.clearProperty(k2);
      System.clearProperty("SDK_COMMON");
    }
    EnvOptions noImports = EnvOptions.builder().secretPath(folder).includeImports(false).build();
    String want = k1 + "=\"one\"\n" + k2 + "=\"two\\nlines\"\n";
    assertEquals(want, c.exportDotenv(noImports));
    assertEquals(want, c.exportDotenvAsync(noImports).get());
    assertEquals(want, InfisicalClient.formatDotenv(Map.of(k1, "one", k2, "two\nlines")));

    SecretImport imp2 =
        c.createSecretImportAsync(
                CreateSecretImportOptions.builder()
                    .path(folder)
                    .importEnvironment(staging)
                    .importPath("/")
                    .build())
            .get();
    assertEquals(2, c.listSecretImportsAsync(SecretImportOptions.builder().path(folder).build()).get().size());
    c.deleteSecretImportAsync(imp2.id(), SecretImportOptions.builder().path(folder).build()).get();
    c.deleteSecretImport(imp.id(), SecretImportOptions.builder().path(folder).build());
    assertTrue(c.listSecretImports(SecretImportOptions.builder().path(folder).build()).isEmpty());
    assertThrows(
        NotFoundException.class,
        () -> c.deleteSecretImport(imp.id(), SecretImportOptions.builder().path(folder).build()));
    c.deleteFolder("imp-" + run, DeleteFolderOptions.builder().force(true).build());
  }

  @Test
  void secretsProvider() throws Exception {
    ProjectSecretsProvider p =
        c.secretsWith(SecretsProviderOptions.builder().basePath("/prov-" + run).build());
    String v =
        p.set(
            "db/PASSWORD",
            "pw-1",
            SetOptions.builder().description("db password").tag("prov-" + run, "#123456").build());
    assertEquals("1", v);
    assertEquals("2", p.set("db/PASSWORD", Map.of("k", "v")));
    JsonNode obj = p.getJson("db/PASSWORD", JsonNode.class).orElseThrow();
    assertEquals("v", obj.path("k").asText());
    SecretValue v1 = p.get("db/PASSWORD", GetOptions.builder().version("1").build()).orElseThrow();
    assertEquals("pw-1", v1.reveal());
    SecretMetadata md = p.metadata("db/PASSWORD").orElseThrow();
    assertEquals("/prov-" + run + "/db", md.path().orElseThrow());
    assertEquals("2", md.version().orElseThrow());
    assertTrue(md.tags().containsKey("prov-" + run));
    assertEquals("db password", md.extra().get("comment"));
    List<SecretMetadata> mds = p.list("db/");
    assertEquals(1, mds.size());
    assertEquals("db/PASSWORD", mds.get(0).name());
    assertEquals(1, p.getAll("db").size());
    Map<String, String> envTarget = new HashMap<>();
    Map<String, String> loaded =
        p.loadEnv("db", LoadEnvOptions.builder().target(EnvLoader.map(envTarget)).build());
    assertEquals("db/PASSWORD", loaded.get("PASSWORD"));
    try (SecretCache cache = new SecretCache(p)) {
      assertTrue(cache.exists("db/PASSWORD"));
    }
    CountDownLatch deleted = new CountDownLatch(1);
    WatchHandle h =
        p.watch(
            "db/PASSWORD",
            Duration.ofMillis(200),
            (now, before) -> {
              if (now.isEmpty()) {
                deleted.countDown();
              }
            });
    Thread.sleep(500);
    p.delete("db/PASSWORD");
    assertTrue(deleted.await(10, TimeUnit.SECONDS), "watch did not see the deletion");
    h.stop();
    assertThrows(NotFoundException.class, () -> p.delete("db/PASSWORD"));
    assertThrows(
        ValidationException.class, () -> p.set("BIN", new byte[] {(byte) 0xff}));
    // permanent is accepted (Infisical always deletes permanently): the missing key is NOT_FOUND
    assertThrows(
        NotFoundException.class,
        () -> p.delete("X", DeleteOptions.builder().permanent(true).build()));
    assertEquals("/prov-" + run, p.basePath());
    assertNotNull(p.options());
    assertNotNull(c.secrets());
    for (Tag t : c.listTags(null)) {
      if (t.slug().equals("prov-" + run)) {
        c.deleteTag(t.id(), null);
      }
    }
    c.deleteFolder("prov-" + run, DeleteFolderOptions.builder().force(true).build());
  }
}
