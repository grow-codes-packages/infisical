package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.EnvReader;
import codes.grow.packages.infisical.core.Hooks;
import codes.grow.packages.infisical.core.Logger;
import codes.grow.packages.infisical.core.Redaction;
import codes.grow.packages.infisical.core.RetryPolicy;
import codes.grow.packages.infisical.core.Secret;
import codes.grow.packages.infisical.core.TlsOptions;
import codes.grow.packages.infisical.core.TransportConfig;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Immutable configuration of a {@link InfisicalClient} (SPEC section 2.2).
 *
 * <p>Build one with {@link #builder()} or read it from the environment with {@link #fromEnv()}.
 * Precedence: explicit builder value &gt; SDK variable ({@code GROW_INFISICAL_<NAME>}) &gt; vendor
 * variables &gt; default. {@link #toString()} never prints credentials.
 *
 * <p>Environment variables:
 *
 * <ul>
 *   <li>{@code url}: {@code GROW_INFISICAL_URL}, {@code INFISICAL_API_URL} (a trailing {@code /api}
 *       is removed); default {@value #DEFAULT_URL}
 *   <li>{@code token}: {@code GROW_INFISICAL_TOKEN}, {@code INFISICAL_TOKEN}
 *   <li>{@code clientId}: {@code GROW_INFISICAL_CLIENT_ID}, {@code INFISICAL_CLIENT_ID}, {@code
 *       INFISICAL_UNIVERSAL_AUTH_CLIENT_ID}
 *   <li>{@code clientSecret}: {@code GROW_INFISICAL_CLIENT_SECRET}, {@code
 *       INFISICAL_CLIENT_SECRET}, {@code INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET}
 *   <li>{@code projectId}: {@code GROW_INFISICAL_PROJECT_ID}, {@code INFISICAL_PROJECT_ID}
 *   <li>{@code environment}: {@code GROW_INFISICAL_ENVIRONMENT}, {@code INFISICAL_ENVIRONMENT}
 *   <li>{@code secretPath}: {@code GROW_INFISICAL_SECRET_PATH} (default {@code /})
 *   <li>{@code apiVersion}: {@code GROW_INFISICAL_API_VERSION} ({@code ""}, {@code v4} or {@code
 *       v3})
 *   <li>{@code revokeOnClose}: {@code GROW_INFISICAL_REVOKE_ON_CLOSE}
 * </ul>
 *
 * <p>plus the common {@code GROW_INFISICAL_CONNECT_TIMEOUT}, {@code REQUEST_TIMEOUT}, {@code
 * TOTAL_TIMEOUT}, {@code MAX_RETRIES}, {@code CA_CERT}, {@code CLIENT_CERT}, {@code CLIENT_KEY},
 * {@code INSECURE_SKIP_VERIFY} and {@code PROXY}.
 *
 * <p>Authentication is chosen in this order: {@link #auth()} (an explicit {@link Authenticator})
 * &gt; {@link #token()} (a static access token, see {@link TokenAuth}) &gt; {@link #clientId()} +
 * {@link #clientSecret()} ({@link UniversalAuth} with automatic token refresh) &gt; none (only
 * {@code health} works).
 */
public final class InfisicalConfig {
  /** Default endpoint (self-hosted standalone image port). */
  public static final String DEFAULT_URL = "http://127.0.0.1:8080";

  /** Default secret path. */
  public static final String DEFAULT_SECRET_PATH = "/";

  /** {@link #apiVersion()} value that detects the secrets API version at run time. */
  public static final String API_VERSION_AUTO = "";

  /** {@link #apiVersion()} value that forces the v4 secrets API ({@code /api/v4/secrets}). */
  public static final String API_VERSION_V4 = "v4";

  /** {@link #apiVersion()} value that forces the deprecated v3 "raw" secrets API. */
  public static final String API_VERSION_V3 = "v3";

  /** Vendor variables read for {@code url} after the SDK variable {@code URL}, in order. */
  static final String[] URL_VENDOR_VARS = {"INFISICAL_API_URL"};

  /** Vendor variables read for {@code token} after the SDK variable {@code TOKEN}, in order. */
  static final String[] TOKEN_VENDOR_VARS = {"INFISICAL_TOKEN"};

  /** Vendor variables read for the CA bundle after the SDK variable {@code CA_CERT}. */
  static final String[] CA_CERT_VENDOR_VARS = {};

  static final String[] CLIENT_ID_VENDOR_VARS = {
    "INFISICAL_CLIENT_ID", "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"
  };
  static final String[] CLIENT_SECRET_VENDOR_VARS = {
    "INFISICAL_CLIENT_SECRET", "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"
  };
  static final String[] PROJECT_ID_VENDOR_VARS = {"INFISICAL_PROJECT_ID"};
  static final String[] ENVIRONMENT_VENDOR_VARS = {"INFISICAL_ENVIRONMENT"};

  private final String url;
  private final Secret token;
  private final Authenticator auth;
  private final String clientId;
  private final Secret clientSecret;
  private final String projectId;
  private final String environment;
  private final String secretPath;
  private final String apiVersion;
  private final boolean revokeOnClose;
  private final Duration connectTimeout;
  private final Duration requestTimeout;
  private final Duration totalTimeout;
  private final RetryPolicy retry;
  private final TlsOptions tls;
  private final String proxy;
  private final Map<String, String> headers;
  private final String userAgentSuffix;
  private final Hooks hooks;
  private final Logger logger;

  private InfisicalConfig(Builder b) {
    this.url = normalizeUrl(b.url != null ? b.url : DEFAULT_URL);
    this.token = b.token;
    this.auth = b.auth;
    this.clientId = blankToNull(b.clientId);
    this.clientSecret = b.clientSecret;
    this.projectId = blankToNull(b.projectId);
    this.environment = blankToNull(b.environment);
    this.secretPath = SecretPaths.normalize(b.secretPath);
    this.apiVersion = b.apiVersion == null ? "" : b.apiVersion.trim().toLowerCase(Locale.ROOT);
    this.revokeOnClose = Boolean.TRUE.equals(b.revokeOnClose);
    this.connectTimeout = b.connectTimeout != null ? b.connectTimeout : Duration.ofSeconds(10);
    this.requestTimeout = b.requestTimeout != null ? b.requestTimeout : Duration.ofSeconds(30);
    this.totalTimeout = b.totalTimeout != null ? b.totalTimeout : Duration.ofSeconds(120);
    this.retry = b.retry != null ? b.retry : RetryPolicy.defaults();
    this.tls = b.tls != null ? b.tls : TlsOptions.defaults();
    this.proxy = b.proxy;
    this.headers = Map.copyOf(b.headers);
    this.userAgentSuffix = b.userAgentSuffix;
    this.hooks = b.hooks != null ? b.hooks : Hooks.NONE;
    this.logger = b.logger != null ? b.logger : Logger.NOOP;
  }

  private static String blankToNull(String s) {
    return s == null || s.isEmpty() ? null : s;
  }

  /** Removes trailing slashes and one trailing {@code /api} (the Infisical CLI form). */
  static String normalizeUrl(String url) {
    String u = url.trim();
    while (u.endsWith("/")) {
      u = u.substring(0, u.length() - 1);
    }
    if (u.endsWith("/api")) {
      u = u.substring(0, u.length() - "/api".length());
    }
    return u;
  }

  /**
   * Starts an empty builder (every field at its default).
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Reads the configuration from the process environment.
   *
   * @return the validated configuration
   * @throws ConfigException when a variable holds an invalid value (the message names the variable,
   *     never the value)
   */
  public static InfisicalConfig fromEnv() {
    return builder().fromEnv(EnvReader.system()).build();
  }

  /**
   * Reads the configuration from an explicit variable map (tests).
   *
   * @param env variable map
   * @return the validated configuration
   */
  public static InfisicalConfig fromEnv(Map<String, String> env) {
    return builder().fromEnv(EnvReader.of(env)).build();
  }

  /**
   * Returns a builder pre-filled with this configuration.
   *
   * @return a new builder
   */
  public Builder toBuilder() {
    Builder b = new Builder();
    b.url = url;
    b.token = token;
    b.auth = auth;
    b.clientId = clientId;
    b.clientSecret = clientSecret;
    b.projectId = projectId;
    b.environment = environment;
    b.secretPath = secretPath;
    b.apiVersion = apiVersion;
    b.revokeOnClose = revokeOnClose;
    b.connectTimeout = connectTimeout;
    b.requestTimeout = requestTimeout;
    b.totalTimeout = totalTimeout;
    b.retry = retry;
    b.tls = tls;
    b.proxy = proxy;
    b.headers.putAll(headers);
    b.userAgentSuffix = userAgentSuffix;
    b.hooks = hooks;
    b.logger = logger;
    return b;
  }

  /**
   * Checks URL scheme, positive timeouts, retry limits, TLS pairs, the API version, the Universal
   * Auth pair and the environment slug.
   *
   * @throws ConfigException when a rule is violated
   */
  public void validate() {
    URI u;
    try {
      u = new URI(url);
    } catch (URISyntaxException e) {
      throw new ConfigException("config: url is not a valid URL");
    }
    String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
    if (!(scheme.equals("http") || scheme.equals("https")) || u.getHost() == null) {
      throw new ConfigException("config: url must use http or https and include a host");
    }
    requirePositive("connectTimeout", connectTimeout);
    requirePositive("requestTimeout", requestTimeout);
    requirePositive("totalTimeout", totalTimeout);
    tls.validate();
    if (proxy != null) {
      try {
        URI p = new URI(proxy);
        if (p.getHost() == null) {
          throw new ConfigException("config: proxy must be an absolute URL");
        }
      } catch (URISyntaxException e) {
        throw new ConfigException("config: proxy is not a valid URL");
      }
    }
    if (!List.of(API_VERSION_AUTO, API_VERSION_V4, API_VERSION_V3).contains(apiVersion)) {
      throw new ConfigException("config: apiVersion must be \"\", \"v4\" or \"v3\"");
    }
    if (auth == null && token == null && (clientId == null) != (clientSecret == null)) {
      throw new ConfigException("config: clientId and clientSecret must be given together");
    }
    if (environment != null && environment.matches(".*[ /\\t\\r\\n].*")) {
      throw new ConfigException("config: environment must be an environment slug");
    }
  }

  private static void requirePositive(String name, Duration d) {
    if (d.isZero() || d.isNegative()) {
      throw new ConfigException("config: " + name + " must be positive");
    }
  }

  /**
   * Translates the common fields into transport settings; the known secrets are the token and the
   * client secret.
   *
   * @return the transport configuration
   */
  public TransportConfig toTransportConfig() {
    return toTransportConfig(List::of);
  }

  /** Transport settings whose known secrets also include {@code extra} (tokens obtained later). */
  TransportConfig toTransportConfig(Supplier<Collection<String>> extra) {
    return TransportConfig.builder(url)
        .connectTimeout(connectTimeout)
        .requestTimeout(requestTimeout)
        .totalTimeout(totalTimeout)
        .retry(retry)
        .tls(tls)
        .proxy(proxy)
        .headers(headers)
        .userAgentSuffix(userAgentSuffix)
        .hooks(hooks)
        .logger(logger)
        .knownSecrets(
            () -> {
              List<String> out = new ArrayList<>(extra.get());
              for (Secret s : new Secret[] {token, clientSecret}) {
                if (s != null && !s.isCleared() && !s.isEmpty()) {
                  out.add(s.reveal());
                }
              }
              return out;
            })
        .build();
  }

  /**
   * Returns the {@link Authenticator} this configuration selects: {@link #auth()} &gt; {@link
   * TokenAuth} for {@link #token()} &gt; {@link UniversalAuth} for {@link #clientId()} and {@link
   * #clientSecret()}.
   *
   * @return the authenticator, or empty when no credentials are configured
   */
  public Optional<Authenticator> authMethod() {
    if (auth != null) {
      return Optional.of(auth);
    }
    if (token != null) {
      return Optional.of(new TokenAuth(token));
    }
    if (clientId != null && clientSecret != null) {
      return Optional.of(new UniversalAuth(clientId, clientSecret, null));
    }
    return Optional.empty();
  }

  /**
   * Returns the endpoint base URL (without a trailing {@code /api}).
   *
   * @return the URL
   */
  public String url() {
    return url;
  }

  /**
   * Returns the static access token: a machine identity access token, a user JWT or a legacy
   * service token ({@code st.…}). It is never refreshed.
   *
   * @return the token, or empty
   */
  public Optional<Secret> token() {
    return Optional.ofNullable(token);
  }

  /**
   * Returns the explicit authentication method; it wins over {@link #token()} and the client id.
   *
   * @return the authenticator, or empty
   */
  public Optional<Authenticator> auth() {
    return Optional.ofNullable(auth);
  }

  /**
   * Returns the Universal Auth client id of a machine identity.
   *
   * @return the client id, or empty
   */
  public Optional<String> clientId() {
    return Optional.ofNullable(clientId);
  }

  /**
   * Returns the Universal Auth client secret of a machine identity.
   *
   * @return the client secret, or empty
   */
  public Optional<Secret> clientSecret() {
    return Optional.ofNullable(clientSecret);
  }

  /**
   * Returns the default project of every project-scoped call.
   *
   * @return the project id, or empty
   */
  public Optional<String> projectId() {
    return Optional.ofNullable(projectId);
  }

  /**
   * Returns the default environment slug (for example {@code dev}). Secret, folder and import calls
   * need one ({@link ConfigException} at call time when missing).
   *
   * @return the slug, or empty
   */
  public Optional<String> environment() {
    return Optional.ofNullable(environment);
  }

  /**
   * Returns the default secret path.
   *
   * @return the normalized absolute path (default {@code /})
   */
  public String secretPath() {
    return secretPath;
  }

  /**
   * Returns the forced secrets API version.
   *
   * @return {@code ""} (detect at run time: v4 first, v3 only when the server lacks the v4 route),
   *     {@code v4} or {@code v3}
   */
  public String apiVersion() {
    return apiVersion;
  }

  /**
   * Returns whether {@link InfisicalClient#close()} revokes a token the client obtained by logging
   * in (Universal, Kubernetes or AWS auth). Static tokens are never revoked.
   *
   * @return the flag (default false)
   */
  public boolean revokeOnClose() {
    return revokeOnClose;
  }

  /**
   * Returns the connect timeout.
   *
   * @return the timeout
   */
  public Duration connectTimeout() {
    return connectTimeout;
  }

  /**
   * Returns the per-attempt timeout.
   *
   * @return the timeout
   */
  public Duration requestTimeout() {
    return requestTimeout;
  }

  /**
   * Returns the total timeout per call including retries.
   *
   * @return the timeout
   */
  public Duration totalTimeout() {
    return totalTimeout;
  }

  /**
   * Returns the retry policy.
   *
   * @return the policy
   */
  public RetryPolicy retry() {
    return retry;
  }

  /**
   * Returns the TLS options.
   *
   * @return the options
   */
  public TlsOptions tls() {
    return tls;
  }

  /**
   * Returns the explicit proxy URL.
   *
   * @return the proxy, or empty
   */
  public Optional<String> proxy() {
    return Optional.ofNullable(proxy);
  }

  /**
   * Returns the extra request headers.
   *
   * @return immutable map
   */
  public Map<String, String> headers() {
    return headers;
  }

  /**
   * Returns the user agent suffix.
   *
   * @return the suffix, or empty
   */
  public Optional<String> userAgentSuffix() {
    return Optional.ofNullable(userAgentSuffix);
  }

  /**
   * Returns the hooks.
   *
   * @return the hooks
   */
  public Hooks hooks() {
    return hooks;
  }

  /**
   * Returns the logger.
   *
   * @return the logger
   */
  public Logger logger() {
    return logger;
  }

  @Override
  public String toString() {
    return "InfisicalConfig{url="
        + Redaction.redactUrl(url)
        + ", auth="
        + authMethod().map(a -> a.getClass().getSimpleName()).orElse("none")
        + ", token="
        + (token == null ? "null" : Redaction.REDACTED)
        + ", clientId="
        + clientId
        + ", clientSecret="
        + (clientSecret == null ? "null" : Redaction.REDACTED)
        + ", projectId="
        + projectId
        + ", environment="
        + environment
        + ", secretPath="
        + secretPath
        + ", apiVersion="
        + apiVersion
        + ", revokeOnClose="
        + revokeOnClose
        + ", connectTimeout="
        + connectTimeout
        + ", requestTimeout="
        + requestTimeout
        + ", totalTimeout="
        + totalTimeout
        + ", retry="
        + retry
        + ", tls="
        + tls
        + ", proxy="
        + (proxy == null ? "null" : Redaction.redactUrl(proxy))
        + ", headers="
        + Redaction.redactHeaders(headers)
        + ", userAgentSuffix="
        + userAgentSuffix
        + "}";
  }

  /**
   * Builder of the configuration.
   *
   * <p>Unset fields take the environment (when {@link #fromEnv(EnvReader)} is called) or the
   * default.
   */
  public static final class Builder {
    private String url;
    private Secret token;
    private Authenticator auth;
    private String clientId;
    private Secret clientSecret;
    private String projectId;
    private String environment;
    private String secretPath;
    private String apiVersion;
    private Boolean revokeOnClose;
    private Duration connectTimeout;
    private Duration requestTimeout;
    private Duration totalTimeout;
    private RetryPolicy retry;
    private TlsOptions tls;
    private String proxy;
    private final Map<String, String> headers = new LinkedHashMap<>();
    private String userAgentSuffix;
    private Hooks hooks;
    private Logger logger;

    private Builder() {}

    /**
     * Fills every field that was not set explicitly from the environment.
     *
     * @param env environment reader
     * @return this builder
     * @throws ConfigException when a variable holds an invalid value
     */
    public Builder fromEnv(EnvReader env) {
      if (url == null) {
        url = env.string("URL", URL_VENDOR_VARS).orElse(null);
      }
      if (token == null) {
        token = env.string("TOKEN", TOKEN_VENDOR_VARS).map(Secret::of).orElse(null);
      }
      if (clientId == null) {
        clientId = env.string("CLIENT_ID", CLIENT_ID_VENDOR_VARS).orElse(null);
      }
      if (clientSecret == null) {
        clientSecret =
            env.string("CLIENT_SECRET", CLIENT_SECRET_VENDOR_VARS).map(Secret::of).orElse(null);
      }
      if (projectId == null) {
        projectId = env.string("PROJECT_ID", PROJECT_ID_VENDOR_VARS).orElse(null);
      }
      if (environment == null) {
        environment = env.string("ENVIRONMENT", ENVIRONMENT_VENDOR_VARS).orElse(null);
      }
      if (secretPath == null) {
        secretPath = env.string("SECRET_PATH").orElse(null);
      }
      if (apiVersion == null) {
        apiVersion = env.string("API_VERSION").orElse(null);
      }
      if (revokeOnClose == null) {
        revokeOnClose = env.bool("REVOKE_ON_CLOSE").orElse(null);
      }
      if (connectTimeout == null) {
        connectTimeout = env.duration("CONNECT_TIMEOUT").orElse(null);
      }
      if (requestTimeout == null) {
        requestTimeout = env.duration("REQUEST_TIMEOUT").orElse(null);
      }
      if (totalTimeout == null) {
        totalTimeout = env.duration("TOTAL_TIMEOUT").orElse(null);
      }
      if (retry == null && env.integer("MAX_RETRIES").isPresent()) {
        int n = env.integer("MAX_RETRIES").getAsInt();
        if (n < 0) {
          String variable = EnvReader.DEFAULT_PREFIX + "MAX_RETRIES";
          throw new ConfigException("config: invalid value in " + variable + " (expected >= 0)");
        }
        retry = RetryPolicy.builder().maxRetries(n).build();
      }
      if (tls == null) {
        TlsOptions.Builder t = TlsOptions.builder();
        env.string("CA_CERT", CA_CERT_VENDOR_VARS).ifPresent(p -> t.caCertPath(Paths.get(p)));
        env.string("CLIENT_CERT").ifPresent(p -> t.clientCertPath(Paths.get(p)));
        env.string("CLIENT_KEY").ifPresent(p -> t.clientKeyPath(Paths.get(p)));
        env.bool("INSECURE_SKIP_VERIFY").ifPresent(t::insecureSkipVerify);
        tls = t.build();
      }
      if (proxy == null) {
        proxy = env.string("PROXY").orElse(null);
      }
      return this;
    }

    /**
     * Sets the endpoint base URL (a trailing {@code /api} is removed).
     *
     * @param url {@code http} or {@code https} URL
     * @return this builder
     */
    public Builder url(String url) {
      this.url = url;
      return this;
    }

    /**
     * Sets a static access token (machine identity token, user JWT or legacy service token).
     *
     * @param token token
     * @return this builder
     */
    public Builder token(Secret token) {
      this.token = token;
      return this;
    }

    /**
     * Sets a static access token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(String token) {
      this.token = token == null ? null : Secret.of(token);
      return this;
    }

    /**
     * Sets an explicit authentication method ({@link UniversalAuth}, {@link TokenAuth}, {@link
     * KubernetesAuth}, {@link AwsIamAuth} or your own).
     *
     * @param auth authenticator
     * @return this builder
     */
    public Builder auth(Authenticator auth) {
      this.auth = auth;
      return this;
    }

    /**
     * Sets the Universal Auth client id.
     *
     * @param clientId client id
     * @return this builder
     */
    public Builder clientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    /**
     * Sets the Universal Auth client secret.
     *
     * @param clientSecret client secret
     * @return this builder
     */
    public Builder clientSecret(Secret clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    /**
     * Sets the Universal Auth client secret.
     *
     * @param clientSecret client secret
     * @return this builder
     */
    public Builder clientSecret(String clientSecret) {
      this.clientSecret = clientSecret == null ? null : Secret.of(clientSecret);
      return this;
    }

    /**
     * Sets the default project id.
     *
     * @param projectId project id
     * @return this builder
     */
    public Builder projectId(String projectId) {
      this.projectId = projectId;
      return this;
    }

    /**
     * Sets the default environment slug.
     *
     * @param environment slug such as {@code dev}
     * @return this builder
     */
    public Builder environment(String environment) {
      this.environment = environment;
      return this;
    }

    /**
     * Sets the default secret path (default {@code /}).
     *
     * @param secretPath path
     * @return this builder
     */
    public Builder secretPath(String secretPath) {
      this.secretPath = secretPath;
      return this;
    }

    /**
     * Forces the secrets API version ({@code v4} or {@code v3}); {@code ""} detects it.
     *
     * @param apiVersion version
     * @return this builder
     */
    public Builder apiVersion(String apiVersion) {
      this.apiVersion = apiVersion;
      return this;
    }

    /**
     * Revokes a token obtained by login on {@link InfisicalClient#close()}.
     *
     * @param revokeOnClose flag
     * @return this builder
     */
    public Builder revokeOnClose(boolean revokeOnClose) {
      this.revokeOnClose = revokeOnClose;
      return this;
    }

    /**
     * Sets the connect timeout (default 10 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      this.connectTimeout = d;
      return this;
    }

    /**
     * Sets the per-attempt timeout (default 30 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      this.requestTimeout = d;
      return this;
    }

    /**
     * Sets the total timeout per call including retries (default 120 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      this.totalTimeout = d;
      return this;
    }

    /**
     * Sets the retry policy (default {@link RetryPolicy#defaults()}).
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      this.retry = retry;
      return this;
    }

    /**
     * Sets the TLS options; environment TLS variables are then ignored.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      this.tls = tls;
      return this;
    }

    /**
     * Sets an explicit proxy URL; environment proxies ({@code HTTPS_PROXY}) are never used.
     *
     * @param proxy proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      this.proxy = proxy;
      return this;
    }

    /**
     * Adds a header sent with every request.
     *
     * @param name header name
     * @param value header value
     * @return this builder
     */
    public Builder header(String name, String value) {
      this.headers.put(name, value);
      return this;
    }

    /**
     * Sets the text appended to the {@code User-Agent}.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      this.userAgentSuffix = suffix;
      return this;
    }

    /**
     * Sets request hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      this.hooks = hooks;
      return this;
    }

    /**
     * Sets the logger (default silent).
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      this.logger = logger;
      return this;
    }

    /**
     * Builds and validates the configuration.
     *
     * @return the configuration
     * @throws ConfigException when a rule is violated
     */
    public InfisicalConfig build() {
      InfisicalConfig c = new InfisicalConfig(this);
      c.validate();
      return c;
    }
  }
}
