package codes.grow.packages.infisical;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.infisical.core.AuthenticationException;
import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.ConflictException;
import codes.grow.packages.infisical.core.ErrorCode;
import codes.grow.packages.infisical.core.HealthStatus;
import codes.grow.packages.infisical.core.Hooks;
import codes.grow.packages.infisical.core.InfisicalException;
import codes.grow.packages.infisical.core.NotFoundException;
import codes.grow.packages.infisical.core.PermissionDeniedException;
import codes.grow.packages.infisical.core.RateLimitException;
import codes.grow.packages.infisical.core.RetryPolicy;
import codes.grow.packages.infisical.core.UnsupportedException;
import codes.grow.packages.infisical.core.ValidationException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class InfisicalClientTest {
  private final Fake fake = new Fake();

  @AfterEach
  void stop() {
    fake.close();
  }

  @Test
  void healthUsesApiStatus() throws Exception {
    fake.fixture("GET", "/api/status", "health.ok");
    try (InfisicalClient c = fake.client()) {
      HealthStatus h = c.health();
      assertThat(h.healthy()).isTrue();
      assertThat(h.status()).isEqualTo("ok");
      assertThat(c.healthAsync().get().healthy()).isTrue();
      assertThat(fake.last("GET", "/api/status").header("Authorization")).isNull();
    }
    fake.reset("GET", "/api/status").on("GET", "/api/status", 503, "{}");
    try (InfisicalClient c = fake.client()) {
      assertThat(c.health().healthy()).isFalse();
    }
  }

  @Test
  void pingRouteDependsOnTokenKind() throws Exception {
    fake.fixture("GET", "/api/v1/identities/details", "ping.identity");
    fake.fixture("GET", "/api/v2/users/me", "ping.user");
    fake.fixture("GET", "/api/v2/service-token", "ping.serviceToken");
    try (InfisicalClient c = fake.client()) {
      assertThat(c.ping()).isPositive();
      assertThat(c.pingAsync().get()).isPositive();
      assertThat(fake.last("GET", "/api/v1/identities/details").header("Authorization"))
          .isEqualTo("Bearer tok-identity");
    }
    try (InfisicalClient c = fake.client(b -> b.token(Fake.USER_JWT))) {
      c.ping();
      assertThat(fake.requests("GET", "/api/v2/users/me")).hasSize(1);
    }
    try (InfisicalClient c = fake.client(b -> b.token("st.abc.def"))) {
      c.ping();
      assertThat(fake.requests("GET", "/api/v2/service-token")).hasSize(1);
    }
  }

  @Test
  void tokenKinds() {
    assertThat(InfisicalClient.tokenKind(null)).isEqualTo(InfisicalClient.TokenKind.IDENTITY);
    assertThat(InfisicalClient.tokenKind("st.x.y")).isEqualTo(InfisicalClient.TokenKind.SERVICE);
    assertThat(InfisicalClient.tokenKind("a.b")).isEqualTo(InfisicalClient.TokenKind.IDENTITY);
    assertThat(InfisicalClient.tokenKind("a.!!!.c")).isEqualTo(InfisicalClient.TokenKind.IDENTITY);
    assertThat(InfisicalClient.tokenKind("a.bm90LWpzb24.c"))
        .isEqualTo(InfisicalClient.TokenKind.IDENTITY);
    assertThat(InfisicalClient.tokenKind(Fake.USER_JWT)).isEqualTo(InfisicalClient.TokenKind.USER);
    assertThat(InfisicalClient.tokenKind(jwt("{\"userId\":\"u\"}")))
        .isEqualTo(InfisicalClient.TokenKind.USER);
    assertThat(InfisicalClient.tokenKind(jwt("{\"userId\":\"u\",\"identityId\":\"i\"}")))
        .isEqualTo(InfisicalClient.TokenKind.IDENTITY);
    assertThat(InfisicalClient.tokenKind(jwt("{\"identityId\":\"i\"}")))
        .isEqualTo(InfisicalClient.TokenKind.IDENTITY);
  }

  static String jwt(String payload) {
    return "h."
        + java.util.Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        + ".s";
  }

  @Test
  void serverVersionIsUnsupported() {
    try (InfisicalClient c = fake.client()) {
      assertThatThrownBy(c::serverVersion).isInstanceOf(UnsupportedException.class);
      assertThatThrownBy(() -> c.serverVersionAsync().get())
          .isInstanceOf(ExecutionException.class)
          .hasCauseInstanceOf(UnsupportedException.class);
    }
  }

  @Test
  void closeIsIdempotentAndClosesResources() throws Exception {
    InfisicalClient c = fake.client();
    ProjectSecretsProvider p = c.secrets();
    assertThat(c.secrets()).isSameAs(p);
    List<String> closed = new CopyOnWriteArrayList<>();
    c.register(() -> closed.add("a"));
    c.register(
        () -> {
          throw new IllegalStateException("ignored");
        });
    c.close();
    c.close();
    assertThat(c.isClosed()).isTrue();
    assertThat(closed).containsExactly("a");
    c.register(() -> closed.add("late"));
    assertThat(closed).containsExactly("a", "late");
    assertThat(c.toString()).contains("InfisicalClient{").doesNotContain("tok-identity");
  }

  @Test
  void factoriesAndBuilder() {
    InfisicalClient c =
        InfisicalClient.builder()
            .url(fake.server.url() + "/api/")
            .token(codes.grow.packages.infisical.core.Secret.of("tok"))
            .projectId("p")
            .environment("dev")
            .secretPath("app")
            .apiVersion("V3")
            .revokeOnClose(true)
            .connectTimeout(Duration.ofSeconds(1))
            .requestTimeout(Duration.ofSeconds(2))
            .totalTimeout(Duration.ofSeconds(3))
            .retry(RetryPolicy.none())
            .tls(codes.grow.packages.infisical.core.TlsOptions.defaults())
            .header("X-A", "b")
            .userAgentSuffix("test")
            .hooks(Hooks.NONE)
            .logger(codes.grow.packages.infisical.core.Logger.NOOP)
            .build();
    assertThat(c.config().url()).isEqualTo(fake.server.url());
    assertThat(c.config().secretPath()).isEqualTo("/app");
    assertThat(c.apiVersion("secrets")).isEqualTo("v3");
    assertThat(c.transport()).isNotNull();
    assertThat(c.auth().method()).containsInstanceOf(TokenAuth.class);
    c.close();
    InfisicalClient d =
        InfisicalClient.builder()
            .fromEnv(codes.grow.packages.infisical.core.EnvReader.of(java.util.Map.of()))
            .clientId("id")
            .clientSecret("secret")
            .proxy("http://proxy:3128")
            .auth(new TokenAuth("x"))
            .token("y")
            .build();
    assertThat(d.auth().method()).containsInstanceOf(TokenAuth.class);
    d.close();
    assertThatThrownBy(() -> InfisicalClient.builder().url("ftp://x").build())
        .isInstanceOf(ConfigException.class);
  }

  @Test
  void apiVersionPerResource() {
    try (InfisicalClient c = fake.client()) {
      assertThat(c.apiVersion("secrets")).isEmpty();
      assertThat(c.apiVersion("folders")).isEqualTo("v2");
      assertThat(c.apiVersion("secret-imports")).isEqualTo("v2");
      for (String r : List.of("projects", "environments", "tags", "secret-versions", "auth")) {
        assertThat(c.apiVersion(r)).isEqualTo("v1");
      }
      assertThat(c.apiVersion("nope")).isEmpty();
    }
  }

  @Test
  void errorMapping() {
    List<Hooks.ErrorInfo> errors = new CopyOnWriteArrayList<>();
    Hooks hooks =
        new Hooks() {
          @Override
          public void onError(Hooks.ErrorInfo info) {
            errors.add(info);
          }
        };
    fake.fixture("POST", "/api/v4/secrets/K", "createSecret.duplicate400");
    fake.fixture("POST", "/api/v4/secrets/V", "createSecret.invalidName422");
    fake.fixture("GET", "/api/v4/secrets/T", "universalAuth.login.withBearer403");
    fake.fixture("GET", "/api/v4/secrets/P", "listSecrets.403noMembership");
    fake.fixture("GET", "/api/v4/secrets/M", "getSecret.404");
    fake.on("GET", "/api/v4/secrets/H", 404, "<html>nope</html>", "Content-Type", "text/html");
    fake.on("GET", "/api/v4/secrets/E", 400, "{\"message\":\"Missing project id\"}");
    try (InfisicalClient c = fake.client(b -> b.hooks(hooks).apiVersion("v4"))) {
      assertThatThrownBy(() -> c.createSecret("K", "v"))
          .isInstanceOfSatisfying(
              ConflictException.class,
              e -> {
                assertThat(e.requestId()).contains("req-gUedbtx3O8pTHI");
                assertThat(e.httpStatus()).hasValue(400);
                assertThat(e.getMessage()).contains("already exists").contains("(HTTP 400)");
              });
      assertThatThrownBy(() -> c.createSecret("V", "v"))
          .isInstanceOf(ValidationException.class)
          .hasMessageContaining("(HTTP 422)");
      assertThatThrownBy(() -> c.getSecret("T")).isInstanceOf(AuthenticationException.class);
      assertThatThrownBy(() -> c.getSecret("P")).isInstanceOf(PermissionDeniedException.class);
      assertThatThrownBy(() -> c.getSecret("M")).isInstanceOf(NotFoundException.class);
      assertThatThrownBy(() -> c.getSecret("H"))
          .isInstanceOfSatisfying(
              NotFoundException.class, e -> assertThat(e.requestId()).isEmpty());
      assertThatThrownBy(() -> c.getSecret("E")).isInstanceOf(ValidationException.class);
    }
    assertThat(errors).hasSize(7);
    assertThat(errors.get(0).willRetry()).isFalse();
    assertThat(errors.get(0).url()).contains("/api/v4/secrets/K");
  }

  @Test
  void hookFailuresAreIgnored() {
    fake.fixture("GET", "/api/v4/secrets/M", "getSecret.404");
    Hooks bad =
        new Hooks() {
          @Override
          public void onError(Hooks.ErrorInfo info) {
            throw new IllegalStateException("boom");
          }
        };
    try (InfisicalClient c = fake.client(b -> b.hooks(bad))) {
      assertThatThrownBy(() -> c.getSecret("M")).isInstanceOf(NotFoundException.class);
    }
  }

  @Test
  void messageText() {
    assertThat(InfisicalClient.messageText(null)).isEmpty();
    assertThat(InfisicalClient.messageText(com.fasterxml.jackson.databind.node.NullNode.instance))
        .isEmpty();
    assertThat(
            InfisicalClient.messageText(
                Fake.fixture("createFolder.422").path("body").path("message")))
        .isEqualTo(
            "name: Invalid folder name. Only alphanumeric characters, dashes, and underscores are"
                + " allowed.");
    assertThat(
            InfisicalClient.messageText(
                codes.grow.packages.infisical.core.Json.tree(
                    "[{\"message\":\"a\"},{\"path\":[],\"message\":\"\"},{\"message\":\"b\",\"path\":[\"x\",0]}]"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8))))
        .isEqualTo("a; x.0: b");
    assertThat(
            InfisicalClient.messageText(
                codes.grow.packages.infisical.core.Json.tree(
                    "{\"a\":1}".getBytes(java.nio.charset.StandardCharsets.UTF_8))))
        .isEqualTo("{\"a\":1}");
  }

  @Test
  void rateLimitTakesWaitFromMessage() {
    fake.fixture("GET", "/api/v4/secrets", "listSecrets.429-synthetic");
    try (InfisicalClient c = fake.client(b -> b.apiVersion("v4"))) {
      assertThatThrownBy(c::listSecrets)
          .isInstanceOfSatisfying(
              RateLimitException.class,
              e -> assertThat(e.retryAfter()).contains(Duration.ofSeconds(7)));
    }
    RateLimitException withHeader =
        (RateLimitException)
            InfisicalException.of(
                ErrorCode.RATE_LIMITED, "x", 429, null, Duration.ofSeconds(2), null);
    assertThat(InfisicalClient.withRetryAfter(withHeader)).isSameAs(withHeader);
    RateLimitException plain = new RateLimitException("rate limited");
    assertThat(InfisicalClient.withRetryAfter(plain)).isSameAs(plain);
    RateLimitException noStatus = new RateLimitException("try again in 3 seconds");
    assertThat(InfisicalClient.withRetryAfter(noStatus).retryAfter())
        .contains(Duration.ofSeconds(3));
  }

  @Test
  void detectsV4AndFallsBackToV3() {
    fake.fixture("GET", "/api/v4/secrets/SDK_SEED", "routeMissing.404");
    fake.fixture("GET", "/api/v3/secrets/raw/SDK_SEED", "getSecret.v3raw-ok");
    try (InfisicalClient c = fake.client()) {
      SecretEntry s = c.getSecret("SDK_SEED");
      assertThat(s.key()).isNotEmpty();
      assertThat(c.apiVersion("secrets")).isEqualTo("v3");
      java.util.Map<String, String> q =
          Fake.query(fake.last("GET", "/api/v3/secrets/raw/SDK_SEED"));
      assertThat(q)
          .containsEntry("workspaceId", "p1")
          .containsEntry("include_imports", "true")
          .containsEntry("expandSecretReferences", "true")
          .doesNotContainKey("viewSecretValue");
      // pinned: the next call goes straight to v3
      c.getSecret("SDK_SEED");
      assertThat(fake.requests("GET", "/api/v4/secrets/SDK_SEED")).hasSize(1);
    }
  }

  @Test
  void v4AnswerPinsV4() {
    fake.fixture("GET", "/api/v4/secrets/A", "getSecret.ok");
    fake.fixture("GET", "/api/v4/secrets/B", "getSecret.404");
    try (InfisicalClient c = fake.client()) {
      c.getSecret("A");
      assertThat(c.apiVersion("secrets")).isEqualTo("v4");
    }
    try (InfisicalClient c = fake.client()) {
      assertThatThrownBy(() -> c.getSecret("B")).isInstanceOf(NotFoundException.class);
      assertThat(c.apiVersion("secrets")).isEqualTo("v4");
    }
    // a network error keeps the version undetected
    try (InfisicalClient c =
        InfisicalClient.create(
            fake.config()
                .url("http://127.0.0.1:1")
                .requestTimeout(Duration.ofSeconds(2))
                .build())) {
      assertThatThrownBy(() -> c.getSecret("A")).isInstanceOf(InfisicalException.class);
      assertThat(c.apiVersion("secrets")).isEmpty();
    }
  }

  @Test
  void forcedVersionNeverFallsBack() {
    fake.fixture("GET", "/api/v4/secrets/A", "routeMissing.404");
    try (InfisicalClient c = fake.client(b -> b.apiVersion("v4"))) {
      assertThatThrownBy(() -> c.getSecret("A"))
          .isInstanceOfSatisfying(
              UnsupportedException.class,
              e -> assertThat(e.getMessage()).contains("does not offer this API route"));
      assertThat(fake.requests("GET", "/api/v3/secrets/raw/A")).isEmpty();
    }
  }

  @Test
  void missingScopeIsConfigError() {
    try (InfisicalClient c =
        InfisicalClient.create(
            InfisicalConfig.builder().url(fake.server.url()).token("t").build())) {
      assertThatThrownBy(c::listSecrets)
          .isInstanceOf(ConfigException.class)
          .hasMessageContaining("projectId is required");
      assertThatThrownBy(() -> c.listSecrets(ListSecretsOptions.builder().projectId("p").build()))
          .isInstanceOf(ConfigException.class)
          .hasMessageContaining("environment is required");
      assertThatThrownBy(() -> c.getSecret(" ")).isInstanceOf(ValidationException.class);
    }
  }

  @Test
  void unauthenticatedClientSendsNoBearer() {
    fake.fixture("GET", "/api/v1/identities/details", "auth.noToken");
    try (InfisicalClient c =
        InfisicalClient.create(InfisicalConfig.builder().url(fake.server.url()).build())) {
      assertThatThrownBy(c::ping).isInstanceOf(AuthenticationException.class);
      assertThat(fake.last("GET", "/api/v1/identities/details").header("Authorization")).isNull();
      assertThatThrownBy(() -> c.auth().login()).isInstanceOf(ConfigException.class);
    }
  }
}
