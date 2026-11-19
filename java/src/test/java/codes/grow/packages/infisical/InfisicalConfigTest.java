package codes.grow.packages.infisical;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.EnvReader;
import codes.grow.packages.infisical.core.Secret;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class InfisicalConfigTest {
  @Test
  void defaults() {
    InfisicalConfig c = InfisicalConfig.builder().build();
    assertThat(c.url()).isEqualTo(InfisicalConfig.DEFAULT_URL);
    assertThat(c.secretPath()).isEqualTo("/");
    assertThat(c.apiVersion()).isEmpty();
    assertThat(c.revokeOnClose()).isFalse();
    assertThat(c.authMethod()).isEmpty();
    assertThat(c.projectId()).isEmpty();
    assertThat(c.environment()).isEmpty();
    assertThat(c.clientId()).isEmpty();
    assertThat(c.clientSecret()).isEmpty();
    assertThat(c.token()).isEmpty();
    assertThat(c.auth()).isEmpty();
    assertThat(c.connectTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(c.requestTimeout()).isEqualTo(Duration.ofSeconds(30));
    assertThat(c.totalTimeout()).isEqualTo(Duration.ofSeconds(120));
    assertThat(c.retry().maxRetries()).isEqualTo(3);
    assertThat(c.proxy()).isEmpty();
    assertThat(c.headers()).isEmpty();
    assertThat(c.userAgentSuffix()).isEmpty();
    assertThat(c.hooks()).isNotNull();
    assertThat(c.logger()).isNotNull();
    assertThat(c.tls()).isNotNull();
    assertThat(c.toTransportConfig().knownSecrets()).isEmpty();
  }

  @Test
  void fromEnvPrecedence() {
    Map<String, String> env =
        Map.ofEntries(
            Map.entry("GROW_INFISICAL_URL", "http://grow:8080"),
            Map.entry("INFISICAL_API_URL", "http://vendor:8080/api"),
            Map.entry("INFISICAL_TOKEN", "vendor-token"),
            Map.entry("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "cli-id"),
            Map.entry("INFISICAL_CLIENT_SECRET", "vendor-secret"),
            Map.entry("INFISICAL_PROJECT_ID", "proj"),
            Map.entry("GROW_INFISICAL_ENVIRONMENT", "staging"),
            Map.entry("INFISICAL_ENVIRONMENT", "dev"),
            Map.entry("GROW_INFISICAL_SECRET_PATH", "app/"),
            Map.entry("GROW_INFISICAL_API_VERSION", "V3"),
            Map.entry("GROW_INFISICAL_REVOKE_ON_CLOSE", "yes"),
            Map.entry("GROW_INFISICAL_CONNECT_TIMEOUT", "2s"),
            Map.entry("GROW_INFISICAL_REQUEST_TIMEOUT", "1500"),
            Map.entry("GROW_INFISICAL_TOTAL_TIMEOUT", "1m"),
            Map.entry("GROW_INFISICAL_MAX_RETRIES", "5"),
            Map.entry("GROW_INFISICAL_PROXY", "http://proxy:3128"),
            Map.entry("GROW_INFISICAL_INSECURE_SKIP_VERIFY", "true"));
    InfisicalConfig c = InfisicalConfig.fromEnv(env);
    assertThat(c.url()).isEqualTo("http://grow:8080");
    assertThat(c.token()).map(Secret::reveal).contains("vendor-token");
    assertThat(c.clientId()).contains("cli-id");
    assertThat(c.clientSecret()).map(Secret::reveal).contains("vendor-secret");
    assertThat(c.projectId()).contains("proj");
    assertThat(c.environment()).contains("staging");
    assertThat(c.secretPath()).isEqualTo("/app");
    assertThat(c.apiVersion()).isEqualTo("v3");
    assertThat(c.revokeOnClose()).isTrue();
    assertThat(c.connectTimeout()).isEqualTo(Duration.ofSeconds(2));
    assertThat(c.requestTimeout()).isEqualTo(Duration.ofMillis(1500));
    assertThat(c.totalTimeout()).isEqualTo(Duration.ofMinutes(1));
    assertThat(c.retry().maxRetries()).isEqualTo(5);
    assertThat(c.proxy()).contains("http://proxy:3128");
    assertThat(c.authMethod()).containsInstanceOf(TokenAuth.class);
    String s = c.toString();
    assertThat(s)
        .doesNotContain("vendor-token")
        .doesNotContain("vendor-secret")
        .contains("TokenAuth");
    assertThat(c.toTransportConfig().knownSecrets()).contains("vendor-token", "vendor-secret");

    InfisicalConfig v =
        InfisicalConfig.fromEnv(
            Map.of(
                "INFISICAL_API_URL", "https://eu.infisical.com/api/",
                "INFISICAL_CLIENT_ID", "id",
                "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "cli-secret"));
    assertThat(v.url()).isEqualTo("https://eu.infisical.com");
    assertThat(v.authMethod()).containsInstanceOf(UniversalAuth.class);
    assertThat(v.toString()).contains("UniversalAuth").doesNotContain("cli-secret");

    // explicit values win over the environment
    InfisicalConfig e =
        InfisicalConfig.builder()
            .url("http://explicit:1")
            .token("t")
            .clientId("c")
            .clientSecret(Secret.of("s"))
            .projectId("p")
            .environment("e")
            .secretPath("/x")
            .apiVersion("v4")
            .revokeOnClose(false)
            .connectTimeout(Duration.ofSeconds(1))
            .requestTimeout(Duration.ofSeconds(1))
            .totalTimeout(Duration.ofSeconds(1))
            .retry(codes.grow.packages.infisical.core.RetryPolicy.none())
            .tls(codes.grow.packages.infisical.core.TlsOptions.defaults())
            .proxy("http://p:1")
            .fromEnv(EnvReader.of(env))
            .build();
    assertThat(e.url()).isEqualTo("http://explicit:1");
    assertThat(e.environment()).contains("e");
    assertThat(e.revokeOnClose()).isFalse();
    assertThat(e.apiVersion()).isEqualTo("v4");
    assertThat(e.retry().maxRetries()).isZero();
  }

  @Test
  void invalidValuesNameTheVariable() {
    assertThatThrownBy(() -> InfisicalConfig.fromEnv(Map.of("GROW_INFISICAL_MAX_RETRIES", "-1")))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("GROW_INFISICAL_MAX_RETRIES");
    assertThatThrownBy(
            () -> InfisicalConfig.fromEnv(Map.of("GROW_INFISICAL_REVOKE_ON_CLOSE", "maybe")))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("GROW_INFISICAL_REVOKE_ON_CLOSE")
        .hasMessageNotContaining("maybe");
  }

  @Test
  void validation() {
    assertThatThrownBy(() -> InfisicalConfig.builder().url("ftp://x").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> InfisicalConfig.builder().url("http://bad host").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> InfisicalConfig.builder().url("http:///nohost").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> InfisicalConfig.builder().url("noscheme").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> InfisicalConfig.builder().connectTimeout(Duration.ZERO).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(
            () -> InfisicalConfig.builder().requestTimeout(Duration.ofSeconds(-1)).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> InfisicalConfig.builder().totalTimeout(Duration.ZERO).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> InfisicalConfig.builder().proxy("no-host").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> InfisicalConfig.builder().proxy("http://bad host").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> InfisicalConfig.builder().apiVersion("v5").build())
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("apiVersion");
    assertThatThrownBy(() -> InfisicalConfig.builder().clientId("id").build())
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("together");
    assertThatThrownBy(() -> InfisicalConfig.builder().clientSecret("s").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> InfisicalConfig.builder().environment("de v").build())
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("environment");
    // a lone client id is fine when another auth is set
    assertThat(InfisicalConfig.builder().clientId("id").token("t").build().authMethod())
        .containsInstanceOf(TokenAuth.class);
    assertThat(
            InfisicalConfig.builder().clientId("id").auth(new TokenAuth("x")).build().authMethod())
        .containsInstanceOf(TokenAuth.class);
    assertThat(InfisicalConfig.builder().clientSecret((String) null).token((String) null).build())
        .isNotNull();
    assertThat(InfisicalConfig.builder().projectId("").environment("").build().projectId())
        .isEmpty();
  }

  @Test
  void toBuilderAndRedaction() {
    InfisicalConfig c =
        InfisicalConfig.builder()
            .url("http://u:p@h:1/")
            .token("tok-1234")
            .clientId("id")
            .clientSecret("sec-1234")
            .header("Authorization", "Bearer x")
            .userAgentSuffix("app/1")
            .proxy("http://user:pw@proxy:1")
            .build();
    InfisicalConfig copy = c.toBuilder().build();
    assertThat(copy.toString()).isEqualTo(c.toString());
    assertThat(c.toString())
        .doesNotContain("tok-1234")
        .doesNotContain("sec-1234")
        .doesNotContain(":pw@")
        .contains("userAgentSuffix=app/1");
    Secret cleared = Secret.of("gone");
    cleared.clear();
    InfisicalConfig withCleared =
        InfisicalConfig.builder().token(cleared).clientSecret(Secret.of("")).build();
    assertThat(withCleared.toTransportConfig().knownSecrets()).isEmpty();
    assertThat(InfisicalConfig.normalizeUrl(" http://h/api// ")).isEqualTo("http://h");
    assertThat(InfisicalConfig.normalizeUrl("http://h/apis")).isEqualTo("http://h/apis");
  }
}
