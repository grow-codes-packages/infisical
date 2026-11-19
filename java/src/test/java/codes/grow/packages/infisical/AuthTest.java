package codes.grow.packages.infisical;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.infisical.core.AuthenticationException;
import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.Json;
import codes.grow.packages.infisical.core.MockServer;
import codes.grow.packages.infisical.core.NotFoundException;
import codes.grow.packages.infisical.core.Secret;
import codes.grow.packages.infisical.core.UnavailableException;
import codes.grow.packages.infisical.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthTest {
  private static final String LOGIN = "/api/v1/auth/universal-auth/login";
  private static final String RENEW = "/api/v1/auth/token/renew";
  private static final String REVOKE = "/api/v1/auth/token/revoke";
  private static final String DETAILS = "/api/v1/identities/details";
  private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

  private final Fake fake = new Fake();

  @AfterEach
  void stop() {
    fake.close();
  }

  /** A clock tests move by hand. */
  static final class MutableClock extends Clock {
    Instant now = Instant.parse("2026-11-18T12:00:00Z");

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }

    void advance(Duration d) {
      now = now.plus(d);
    }
  }

  static String token(String t) {
    return "{\"accessToken\":\""
        + t
        + "\",\"expiresIn\":300,\"accessTokenMaxTTL\":3600,"
        + "\"tokenType\":\"Bearer\"}";
  }

  private InfisicalClient uaClient(MutableClock clock) {
    InfisicalClient c =
        fake.client(b -> b.token((String) null).clientId("cid").clientSecret("csecret-1"));
    c.clock = clock;
    return c;
  }

  @Test
  void universalAuthLogsInOnFirstUseWithoutBearer() {
    fake.on("POST", LOGIN, 200, token("AT-1"));
    fake.fixture("GET", DETAILS, "ping.identity");
    try (InfisicalClient c = uaClient(new MutableClock())) {
      assertThat(c.auth().method()).containsInstanceOf(UniversalAuth.class);
      assertThat(c.auth().token()).isEmpty();
      c.ping();
      MockServer.Recorded login = fake.last("POST", LOGIN);
      assertThat(login.header("Authorization")).isNull();
      JsonNode body = Fake.json(login);
      assertThat(body.path("clientId").asText()).isEqualTo("cid");
      assertThat(body.path("clientSecret").asText()).isEqualTo("csecret-1");
      assertThat(body.has("organizationSlug")).isFalse();
      assertThat(fake.last("GET", DETAILS).header("Authorization")).isEqualTo("Bearer AT-1");
      AccessToken t = c.auth().token().orElseThrow();
      assertThat(t.expiresIn()).isEqualTo(Duration.ofSeconds(300));
      assertThat(t.maxTtl()).isEqualTo(Duration.ofSeconds(3600));
      assertThat(t.tokenType()).isEqualTo("Bearer");
      assertThat(t.expiresAt()).contains(Instant.parse("2026-11-18T12:05:00Z"));
      assertThat(t.toString()).doesNotContain("AT-1");
    }
  }

  @Test
  void renewsAtEightyPercentAndLogsInNearMaxTtl() {
    MutableClock clock = new MutableClock();
    fake.on("POST", LOGIN, 200, token("AT-1")).on("POST", LOGIN, 200, token("AT-3"));
    fake.on("POST", RENEW, 200, token("AT-2"));
    fake.fixture("GET", DETAILS, "ping.identity");
    try (InfisicalClient c = uaClient(clock)) {
      c.ping();
      clock.advance(Duration.ofSeconds(200));
      c.ping();
      assertThat(fake.requests("POST", RENEW)).isEmpty();
      clock.advance(Duration.ofSeconds(50));
      c.ping();
      assertThat(Fake.json(fake.last("POST", RENEW)).path("accessToken").asText())
          .isEqualTo("AT-1");
      assertThat(fake.last("POST", RENEW).header("Authorization")).isNull();
      assertThat(fake.last("GET", DETAILS).header("Authorization")).isEqualTo("Bearer AT-2");
      // close to the maximum TTL: log in again instead of renewing
      clock.advance(Duration.ofSeconds(3200));
      c.ping();
      assertThat(fake.requests("POST", LOGIN)).hasSize(2);
      assertThat(fake.last("GET", DETAILS).header("Authorization")).isEqualTo("Bearer AT-3");
    }
  }

  @Test
  void failedRenewLogsInAgain() {
    MutableClock clock = new MutableClock();
    fake.on("POST", LOGIN, 200, token("AT-1")).on("POST", LOGIN, 200, token("AT-9"));
    fake.fixture("POST", RENEW, "universalAuth.renew.revoked");
    fake.fixture("GET", DETAILS, "ping.identity");
    try (InfisicalClient c = uaClient(clock)) {
      c.ping();
      clock.advance(Duration.ofSeconds(290));
      c.ping();
      assertThat(fake.last("GET", DETAILS).header("Authorization")).isEqualTo("Bearer AT-9");
    }
  }

  @Test
  void authenticationErrorTriggersOneRelogin() {
    fake.on("POST", LOGIN, 200, token("AT-1")).on("POST", LOGIN, 200, token("AT-2"));
    fake.fixture("GET", DETAILS, "auth.revokedToken");
    fake.on("GET", DETAILS, 200, Fake.body("ping.identity"));
    try (InfisicalClient c = uaClient(new MutableClock())) {
      c.ping();
      assertThat(fake.requests("POST", LOGIN)).hasSize(2);
      assertThat(fake.last("GET", DETAILS).header("Authorization")).isEqualTo("Bearer AT-2");
    }
  }

  @Test
  void reloginFailureKeepsTheOriginalError() {
    fake.on("POST", LOGIN, 200, token("AT-1"));
    fake.on("POST", LOGIN, 401, "{\"message\":\"Invalid credentials\"}");
    fake.fixture("GET", DETAILS, "auth.revokedToken");
    try (InfisicalClient c = uaClient(new MutableClock())) {
      assertThatThrownBy(c::ping)
          .isInstanceOf(AuthenticationException.class)
          .hasMessageContaining("ping");
    }
  }

  @Test
  void rejectedLoginIsNotRetried() {
    fake.fixture("POST", LOGIN, "universalAuth.login.lockedOut401");
    try (InfisicalClient c = uaClient(new MutableClock())) {
      assertThatThrownBy(c::ping)
          .isInstanceOf(AuthenticationException.class)
          .hasMessageContaining("auth.universalAuth.login")
          .hasMessageNotContaining("csecret-1");
      assertThat(fake.requests("POST", LOGIN)).hasSize(1);
    }
  }

  @Test
  void staticTokenIsNeverRefreshed() {
    fake.fixture("GET", DETAILS, "auth.revokedToken");
    try (InfisicalClient c = fake.client()) {
      assertThatThrownBy(c::ping).isInstanceOf(AuthenticationException.class);
      assertThat(fake.requests("POST", LOGIN)).isEmpty();
      assertThat(c.auth().token().orElseThrow().expiresAt()).isEmpty();
    }
  }

  @Test
  void reloginSkipsWhenTokenAlreadyReplaced() {
    fake.on("POST", LOGIN, 200, token("AT-1"));
    try (InfisicalClient c = uaClient(new MutableClock())) {
      c.auth().login();
      assertThat(c.auth().relogin("stale")).isEqualTo("AT-1");
      assertThat(fake.requests("POST", LOGIN)).hasSize(1);
    }
  }

  @Test
  void managerOperations() throws Exception {
    fake.on("POST", LOGIN, 200, token("AT-1"));
    fake.on("POST", RENEW, 200, token("AT-2"));
    fake.fixture("POST", REVOKE, "universalAuth.revoke.ok");
    fake.fixture("GET", DETAILS, "ping.identity");
    try (InfisicalClient c = uaClient(new MutableClock())) {
      Auth a = c.auth();
      assertThatThrownBy(a::renew).isInstanceOf(ValidationException.class);
      a.revoke(); // nothing to revoke
      assertThat(fake.requests("POST", REVOKE)).isEmpty();
      assertThat(a.loginAsync().get().token().reveal()).isEqualTo("AT-1");
      assertThat(a.renewAsync().get().token().reveal()).isEqualTo("AT-2");
      assertThat(a.token().orElseThrow().token().reveal()).isEqualTo("AT-2");
      a.revokeAsync().get();
      assertThat(a.token()).isEmpty();
      assertThat(Fake.json(fake.last("POST", REVOKE)).path("accessToken").asText())
          .isEqualTo("AT-2");
      a.setToken(Secret.of("manual-token"));
      c.ping();
      assertThat(fake.last("GET", DETAILS).header("Authorization"))
          .isEqualTo("Bearer manual-token");
      a.setToken(null);
      assertThat(a.token()).isEmpty();
      a.setToken(Secret.of(""));
      assertThat(a.token()).isEmpty();
    }
  }

  @Test
  void revokeOnCloseRevokesOnlyLoginTokens() {
    fake.on("POST", LOGIN, 200, token("AT-1"));
    fake.fixture("POST", REVOKE, "universalAuth.revoke.ok");
    InfisicalClient c =
        fake.client(
            b -> b.token((String) null).clientId("cid").clientSecret("cs").revokeOnClose(true));
    c.auth().login();
    c.close();
    assertThat(fake.requests("POST", REVOKE)).hasSize(1);
    // static token: never revoked
    InfisicalClient s = fake.client(b -> b.revokeOnClose(true));
    s.auth().login();
    s.close();
    assertThat(fake.requests("POST", REVOKE)).hasSize(1);
    // revoke failure on close is ignored
    fake.reset("POST", REVOKE).on("POST", REVOKE, 500, "{}");
    InfisicalClient f =
        fake.client(
            b -> b.token((String) null).clientId("cid").clientSecret("cs").revokeOnClose(true));
    f.auth().login();
    f.close();
    assertThat(f.isClosed()).isTrue();
    // nothing logged in yet: no request
    InfisicalClient n =
        fake.client(
            b -> b.token((String) null).clientId("cid").clientSecret("cs").revokeOnClose(true));
    n.close();
    assertThat(fake.requests("POST", REVOKE)).hasSize(2);
  }

  @Test
  void tokenCallValidation() {
    fake.on("POST", LOGIN, 200, "{\"expiresIn\":300}");
    try (InfisicalClient c = uaClient(new MutableClock())) {
      assertThatThrownBy(() -> c.auth().login()).isInstanceOf(UnavailableException.class);
      assertThatThrownBy(() -> c.renewToken(null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.renewToken(Secret.of(""))).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.revokeToken(null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.revokeToken(Secret.of("")))
          .isInstanceOf(ValidationException.class);
    }
  }

  @Test
  void universalAuthMethods() throws Exception {
    fake.on("POST", LOGIN, 200, token("AT-1"));
    fake.on("POST", RENEW, 200, token("AT-2"));
    fake.fixture("POST", REVOKE, "universalAuth.revoke.alreadyRevoked");
    try (InfisicalClient c = fake.client()) {
      UniversalAuth ua = new UniversalAuth("cid", Secret.of("cs-12345"), "sub-org");
      assertThat(ua.clientId()).isEqualTo("cid");
      assertThat(ua.organizationSlug()).contains("sub-org");
      AccessToken t = ua.login(c);
      assertThat(Fake.json(fake.last("POST", LOGIN)).path("organizationSlug").asText())
          .isEqualTo("sub-org");
      assertThat(ua.loginAsync(c).get().token().reveal()).isEqualTo("AT-1");
      assertThat(ua.renew(c, t.token()).token().reveal()).isEqualTo("AT-2");
      assertThat(ua.renewAsync(c, t.token()).get().token().reveal()).isEqualTo("AT-2");
      ua.revoke(c, t.token());
      ua.revokeAsync(c, t.token()).get();
      assertThat(fake.requests("POST", REVOKE)).hasSize(2);
      assertThat(ua.toString()).contains("cid").doesNotContain("cs-12345");
      assertThatThrownBy(() -> new UniversalAuth("", "x").login(c))
          .isInstanceOf(ConfigException.class);
      assertThatThrownBy(() -> new UniversalAuth("id", (String) null).login(c))
          .isInstanceOf(ConfigException.class);
      assertThatThrownBy(() -> new UniversalAuth(null, Secret.of(""), null).login(c))
          .isInstanceOf(ConfigException.class);
      assertThatThrownBy(() -> new UniversalAuth("id", Secret.of(""), "").login(c))
          .isInstanceOf(ConfigException.class);
      assertThat(new UniversalAuth("id", Secret.of("cs-12345"), "").organizationSlug())
          .contains("");
      new UniversalAuth("id", Secret.of("cs-12345"), "").login(c);
      assertThat(Fake.json(fake.last("POST", LOGIN)).has("organizationSlug")).isFalse();
    }
  }

  @Test
  void tokenAuth() {
    try (InfisicalClient c = fake.client()) {
      TokenAuth t = new TokenAuth("static-token");
      assertThat(t.token().reveal()).isEqualTo("static-token");
      assertThat(t.login(c).token().reveal()).isEqualTo("static-token");
      assertThat(t.toString()).doesNotContain("static-token");
      assertThatThrownBy(() -> new TokenAuth("").login(c)).isInstanceOf(ConfigException.class);
    }
  }

  @Test
  void kubernetesAuth(@TempDir Path dir) throws Exception {
    String path = "/api/v1/auth/kubernetes-auth/login";
    fake.on("POST", path, 200, token("K8S-1"));
    try (InfisicalClient c = fake.client()) {
      KubernetesAuth k =
          KubernetesAuth.builder()
              .identityId("id-1")
              .jwt(Secret.of("sa-jwt-123"))
              .organizationSlug("org")
              .build();
      assertThat(k.identityId()).isEqualTo("id-1");
      assertThat(k.login(c).token().reveal()).isEqualTo("K8S-1");
      JsonNode body = Fake.json(fake.last("POST", path));
      assertThat(body.path("jwt").asText()).isEqualTo("sa-jwt-123");
      assertThat(body.path("organizationSlug").asText()).isEqualTo("org");
      assertThat(k.toString()).doesNotContain("sa-jwt-123");
      Path file = dir.resolve("token");
      Files.writeString(file, "file-jwt-456\n");
      KubernetesAuth.builder().identityId("id-2").tokenPath(file.toString()).build().login(c);
      body = Fake.json(fake.last("POST", path));
      assertThat(body.path("jwt").asText()).isEqualTo("file-jwt-456");
      assertThat(body.has("organizationSlug")).isFalse();
      KubernetesAuth.builder()
          .identityId("id-2")
          .jwt(Secret.of(""))
          .organizationSlug("")
          .tokenPath(file.toString())
          .build()
          .login(c);
      assertThatThrownBy(
              () ->
                  KubernetesAuth.builder()
                      .identityId("id-3")
                      .tokenPath(dir.resolve("missing").toString())
                      .build()
                      .login(c))
          .isInstanceOf(ConfigException.class)
          .hasMessageContaining("cannot be read");
      assertThatThrownBy(() -> KubernetesAuth.builder().tokenPath(null).build().login(c))
          .isInstanceOf(ConfigException.class);
      assertThatThrownBy(() -> KubernetesAuth.builder().identityId("").build().login(c))
          .isInstanceOf(ConfigException.class);
      fake.reset("POST", path).fixture("POST", path, "kubernetesAuth.login.notConfigured");
      assertThatThrownBy(() -> k.login(c))
          .isInstanceOf(NotFoundException.class)
          .hasMessageContaining("Kubernetes auth method not found");
    }
  }

  @Test
  void sigV4Vectors() {
    Instant t = Instant.parse("2015-08-30T12:36:00Z");
    Map<String, String> h =
        SigV4.sign(
            new SigV4.Request(
                "GET",
                "example.amazonaws.com",
                "/",
                "",
                Map.of(),
                null,
                "us-east-1",
                "service",
                "AKIDEXAMPLE",
                AWS_SECRET,
                t));
    assertThat(h.get("Authorization"))
        .isEqualTo(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request,"
                + " SignedHeaders=host;x-amz-date,"
                + " Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    h =
        SigV4.sign(
            new SigV4.Request(
                "GET",
                "example.amazonaws.com",
                "",
                "Param2=value2&Param1=value1",
                Map.of("host", "example.amazonaws.com"),
                new byte[0],
                "us-east-1",
                "service",
                "AKIDEXAMPLE",
                AWS_SECRET,
                t));
    assertThat(h.get("Authorization"))
        .endsWith("Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500");
    assertThat(h).doesNotContainKey("Host");
    SigV4.Request r =
        new SigV4.Request("GET", "h", "/", "", Map.of(), null, "r", "s", "k", "secret", t);
    SigV4.Request same =
        new SigV4.Request("GET", "h", "/", "", Map.of(), null, "r", "s", "k", "other", t);
    assertThat(r).isEqualTo(same).hasSameHashCodeAs(same).isNotEqualTo("x");
    assertThat(r.toString()).doesNotContain("secret");
    assertThat(SigV4.canonicalQuery(null)).isEmpty();
    assertThat(SigV4.hex(new byte[] {0, (byte) 0xff})).isEqualTo("00ff");
  }

  @Test
  void awsIamAuth() {
    Clock fixed = Clock.fixed(Instant.parse("2026-11-18T12:00:00Z"), ZoneOffset.UTC);
    AwsIamAuth a =
        AwsIamAuth.builder()
            .identityId("id-1")
            .region("eu-central-1")
            .accessKeyId("AKIDEXAMPLE")
            .secretAccessKey(Secret.of(AWS_SECRET))
            .sessionToken(Secret.of("sess-TOKEN"))
            .env(Map.of())
            .clock(fixed)
            .build();
    assertThat(a.identityId()).isEqualTo("id-1");
    AwsLoginRequest req = a.loginRequest();
    assertThat(new String(Base64.getDecoder().decode(req.iamRequestBody()), StandardCharsets.UTF_8))
        .isEqualTo("Action=GetCallerIdentity&Version=2011-06-15");
    assertThat(req.iamHttpRequestMethod()).isEqualTo("POST");
    assertThat(req.organizationSlug()).isEmpty();
    JsonNode hdr = Json.tree(Base64.getDecoder().decode(req.iamRequestHeaders()));
    assertThat(hdr.path("Host").asText()).isEqualTo("sts.eu-central-1.amazonaws.com");
    assertThat(hdr.path("X-Amz-Date").asText()).isEqualTo("20261118T120000Z");
    assertThat(hdr.path("X-Amz-Security-Token").asText()).isEqualTo("sess-TOKEN");
    assertThat(hdr.path("Content-Length").asText()).isEqualTo("43");
    String auth = hdr.path("Authorization").asText();
    assertThat(auth)
        .contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token")
        .contains("/20261118/eu-central-1/sts/aws4_request");
    Map<String, String> want =
        SigV4.sign(
            new SigV4.Request(
                "POST",
                "sts.eu-central-1.amazonaws.com",
                "/",
                "",
                Map.of(
                    "Host",
                    "sts.eu-central-1.amazonaws.com",
                    "Content-Type",
                    AwsIamAuth.STS_CONTENT_TYPE,
                    "X-Amz-Security-Token",
                    "sess-TOKEN"),
                AwsIamAuth.STS_BODY.getBytes(StandardCharsets.UTF_8),
                "eu-central-1",
                "sts",
                "AKIDEXAMPLE",
                AWS_SECRET,
                fixed.instant()));
    assertThat(auth).isEqualTo(want.get("Authorization"));
    assertThat(a.toString()).doesNotContain(AWS_SECRET);

    // credentials and region from the environment
    AwsIamAuth env =
        AwsIamAuth.builder()
            .identityId("id-2")
            .organizationSlug("org")
            .env(
                Map.of(
                    "AWS_DEFAULT_REGION", "us-west-2",
                    "AWS_ACCESS_KEY_ID", "AKIAENV",
                    "AWS_SECRET_ACCESS_KEY", "env-secret",
                    "AWS_SESSION_TOKEN", "env-session"))
            .clock(fixed)
            .build();
    AwsLoginRequest er = env.loginRequest();
    JsonNode eh = Json.tree(Base64.getDecoder().decode(er.iamRequestHeaders()));
    assertThat(eh.path("Host").asText()).isEqualTo("sts.us-west-2.amazonaws.com");
    assertThat(eh.path("X-Amz-Security-Token").asText()).isEqualTo("env-session");
    assertThat(eh.path("Authorization").asText()).contains("Credential=AKIAENV/");
    assertThat(er.organizationSlug()).isEqualTo("org");
    // default region; explicit key ignores the environment session token
    AwsIamAuth def =
        AwsIamAuth.builder()
            .identityId("id-3")
            .region("")
            .accessKeyId("AKIDEXAMPLE")
            .secretAccessKey(Secret.of(""))
            .env(Map.of("AWS_SECRET_ACCESS_KEY", "s3cr3t", "AWS_SESSION_TOKEN", "nope"))
            .build();
    JsonNode dh = Json.tree(Base64.getDecoder().decode(def.loginRequest().iamRequestHeaders()));
    assertThat(dh.path("Host").asText()).isEqualTo("sts.us-east-1.amazonaws.com");
    assertThat(dh.has("X-Amz-Security-Token")).isFalse();

    assertThatThrownBy(() -> AwsIamAuth.builder().env(Map.of()).build().loginRequest())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(
            () -> AwsIamAuth.builder().identityId("").env(Map.of()).build().loginRequest())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(
            () -> AwsIamAuth.builder().identityId("x").env(Map.of()).build().loginRequest())
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("AWS credentials are required");
    assertThatThrownBy(
            () ->
                AwsIamAuth.builder()
                    .identityId("x")
                    .env(Map.of("AWS_ACCESS_KEY_ID", "AKIA"))
                    .build()
                    .loginRequest())
        .isInstanceOf(ConfigException.class);

    String path = "/api/v1/auth/aws-auth/login";
    fake.on("POST", path, 200, token("AWS-AT-1"));
    try (InfisicalClient c = fake.client(b -> b.token((String) null).auth(a))) {
      c.auth().login();
      MockServer.Recorded r = fake.last("POST", path);
      assertThat(r.header("Authorization")).isNull();
      JsonNode body = Fake.json(r);
      assertThat(body.path("identityId").asText()).isEqualTo("id-1");
      assertThat(body.path("iamRequestHeaders").asText()).isNotEmpty();
      assertThat(body.has("organizationSlug")).isFalse();
      assertThat(c.auth().token().orElseThrow().token().reveal()).isEqualTo("AWS-AT-1");
      env.login(c);
      assertThat(Fake.json(fake.last("POST", path)).path("organizationSlug").asText())
          .isEqualTo("org");
      fake.reset("POST", path).fixture("POST", path, "awsIamAuth.login.notConfigured");
      assertThatThrownBy(() -> a.login(c)).isInstanceOf(NotFoundException.class);
    }
    assertThat(
            AwsIamAuth.builder()
                .identityId("x")
                .accessKeyId("AKIA")
                .secretAccessKey(Secret.of("sec"))
                .build()
                .loginRequest()
                .identityId())
        .isEqualTo("x");
  }

  @Test
  void accessTokenExpiry() {
    Instant t = Instant.parse("2026-01-01T00:00:00Z");
    assertThat(new AccessToken(Secret.of("x"), Duration.ZERO, Duration.ZERO, "", t).expiresAt())
        .isEmpty();
    assertThat(
            new AccessToken(Secret.of("x"), Duration.ofSeconds(-1), Duration.ZERO, "", t)
                .expiresAt())
        .isEmpty();
    assertThat(
            new AccessToken(Secret.of("x"), Duration.ofSeconds(5), Duration.ZERO, "", t)
                .expiresAt())
        .contains(t.plusSeconds(5));
  }
}
