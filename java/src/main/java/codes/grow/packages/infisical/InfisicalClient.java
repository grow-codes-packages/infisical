package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.AuthenticationException;
import codes.grow.packages.infisical.core.CancelledException;
import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.EnvReader;
import codes.grow.packages.infisical.core.ErrorCode;
import codes.grow.packages.infisical.core.HealthCheck;
import codes.grow.packages.infisical.core.HealthStatus;
import codes.grow.packages.infisical.core.Hooks;
import codes.grow.packages.infisical.core.HttpTransport;
import codes.grow.packages.infisical.core.InfisicalException;
import codes.grow.packages.infisical.core.Json;
import codes.grow.packages.infisical.core.Logger;
import codes.grow.packages.infisical.core.NotFoundException;
import codes.grow.packages.infisical.core.RateLimitException;
import codes.grow.packages.infisical.core.Redaction;
import codes.grow.packages.infisical.core.RetryPolicy;
import codes.grow.packages.infisical.core.Secret;
import codes.grow.packages.infisical.core.TlsOptions;
import codes.grow.packages.infisical.core.TransportRequest;
import codes.grow.packages.infisical.core.TransportResponse;
import codes.grow.packages.infisical.core.UnavailableException;
import codes.grow.packages.infisical.core.UnsupportedException;
import codes.grow.packages.infisical.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Client for Infisical (SPEC section 2.4). Thread-safe; create one per endpoint and close it when
 * done.
 *
 * <pre>{@code
 * try (InfisicalClient client = InfisicalClient.fromEnv()) {
 *   SecretEntry secret = client.getSecret("DATABASE_URL");
 *   String dsn = secret.value().reveal();
 * }
 * }</pre>
 *
 * <p>Service functions are methods of the client: secrets ({@link #listSecrets}, {@link
 * #getSecret}, {@link #createSecret}, {@link #updateSecret}, {@link #deleteSecret} and the batch
 * variants; v4 API with a run-time v3 fallback), folders, projects and environments, tags, secret
 * imports, secret versions, {@link #loadEnv} and {@link #exportDotenv}. {@link #auth()} returns the
 * token manager, {@link #secrets()} the {@code SecretsProvider} (SPEC section 3).
 *
 * <p>Every I/O method has a blocking form and an {@code …Async} form returning {@link
 * CompletableFuture}; the async forms run the blocking call on a shared daemon executor.
 *
 * <p>Infisical answers duplicates with HTTP 400 "already exists" ({@code ConflictException} here)
 * and malformed tokens with 403 {@code TokenError} ({@code AuthenticationException} here); the
 * request id comes from the error body ({@code reqId}).
 */
public final class InfisicalClient implements AutoCloseable {
  /** Default color of {@link #createTag} when none is given. */
  public static final String DEFAULT_TAG_COLOR = "#bec2c8";

  private static final AtomicInteger THREADS = new AtomicInteger();
  private static final ExecutorService ASYNC =
      Executors.newCachedThreadPool(
          r -> {
            Thread t = new Thread(r, "grow-infisical-async-" + THREADS.incrementAndGet());
            t.setDaemon(true);
            return t;
          });
  private static final int[] ERROR_STATUSES = {400, 401, 403, 404, 405, 409, 412, 413, 415, 422};
  private static final Pattern RETRY_IN = Pattern.compile("(?i)try again in (\\d+) seconds?");

  private final InfisicalConfig config;
  private final HttpTransport transport;
  private final Set<String> knownSecrets = ConcurrentHashMap.newKeySet();
  private final Auth auth;
  private final AtomicBoolean closed = new AtomicBoolean();
  private final List<AutoCloseable> resources = new ArrayList<>();
  private final Object apiLock = new Object();
  private String secretsApi;
  private ProjectSecretsProvider provider;
  Clock clock = Clock.systemUTC();

  private InfisicalClient(InfisicalConfig config) {
    this.config = config;
    this.transport = new HttpTransport(config.toTransportConfig(this::secretList));
    this.secretsApi = config.apiVersion();
    this.auth = new Auth(this, config.authMethod().orElse(null));
  }

  private Collection<String> secretList() {
    return List.copyOf(knownSecrets);
  }

  /**
   * Creates a client. It does not contact the server: a login (Universal, Kubernetes or AWS auth)
   * happens on the first authenticated call or on {@code auth().login()}.
   *
   * @param config validated configuration
   * @return a new client
   * @throws ConfigException when the configuration, TLS or proxy settings are invalid
   */
  public static InfisicalClient create(InfisicalConfig config) {
    config.validate();
    return new InfisicalClient(config);
  }

  /**
   * Creates a client from the SDK and vendor environment variables (see {@link InfisicalConfig}).
   *
   * @return a new client
   */
  public static InfisicalClient fromEnv() {
    return create(InfisicalConfig.fromEnv());
  }

  /**
   * Starts a client builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the configuration.
   *
   * @return the configuration
   */
  public InfisicalConfig config() {
    return config;
  }

  /**
   * Returns the HTTP transport, for service modules built on this client.
   *
   * @return the transport
   */
  public HttpTransport transport() {
    return transport;
  }

  /**
   * Returns the token manager (login, renew, revoke, token, setToken).
   *
   * @return the token manager
   */
  public Auth auth() {
    return auth;
  }

  /**
   * Returns the {@code SecretsProvider} (SPEC section 3) over the configured project, environment
   * and secret path. {@link #close()} stops its watchers.
   *
   * @return the provider (one per client)
   */
  public synchronized ProjectSecretsProvider secrets() {
    if (provider == null) {
      provider = new ProjectSecretsProvider(this, SecretsProviderOptions.defaults());
      register(provider);
    }
    return provider;
  }

  /**
   * Returns a new {@code SecretsProvider} with its own project, environment, base path or read
   * flags. {@link #close()} stops its watchers.
   *
   * @param options provider options
   * @return a new provider
   */
  public ProjectSecretsProvider secretsWith(SecretsProviderOptions options) {
    ProjectSecretsProvider p = new ProjectSecretsProvider(this, options);
    register(p);
    return p;
  }

  /**
   * Returns the API version the client uses for a resource: {@code secrets} ({@code v4} or {@code
   * v3}; {@code ""} until detected by the first secrets call), {@code folders} and {@code
   * secret-imports} ({@code v2}), {@code projects}, {@code environments}, {@code tags}, {@code
   * secret-versions} and {@code auth} ({@code v1}).
   *
   * @param resource resource name
   * @return the version, or {@code ""} for unknown resources
   */
  public String apiVersion(String resource) {
    switch (resource) {
      case "secrets":
        synchronized (apiLock) {
          return secretsApi;
        }
      case "folders":
      case "secret-imports":
        return "v2";
      case "projects":
      case "environments":
      case "tags":
      case "secret-versions":
      case "auth":
        return "v1";
      default:
        return "";
    }
  }

  /**
   * Registers a resource (watcher, provider) closed with the client; closed at once when the client
   * is already closed.
   *
   * @param resource the resource
   */
  public void register(AutoCloseable resource) {
    synchronized (resources) {
      if (!closed.get()) {
        resources.add(resource);
        return;
      }
    }
    closeQuietly(resource);
  }

  private static void closeQuietly(AutoCloseable r) {
    try {
      r.close();
    } catch (Exception ignored) {
      // best effort: close must not throw
    }
  }

  // ----- package helpers used by auth methods and the provider -----

  Instant now() {
    return clock.instant();
  }

  /** Registers values that must never appear in errors or logs. */
  void rememberSecret(String... values) {
    for (String v : values) {
      if (v != null && v.length() >= 4) {
        knownSecrets.add(v);
      }
    }
  }

  <T> CompletableFuture<T> async(Supplier<T> s) {
    return CompletableFuture.supplyAsync(s, ASYNC);
  }

  /** Posts a login/renew body without a bearer and decodes the token. */
  AccessToken tokenCall(String op, String path, Map<String, Object> body) {
    JsonNode out = callJson(new Call("POST", path, op).body(body).noAuth());
    String token = Wire.text(out, "accessToken");
    if (token.isEmpty()) {
      throw new UnavailableException(op + ": the response carries no access token");
    }
    rememberSecret(token);
    return new AccessToken(
        Secret.of(token),
        Duration.ofSeconds(out.path("expiresIn").asLong()),
        Duration.ofSeconds(out.path("accessTokenMaxTTL").asLong()),
        Wire.text(out, "tokenType"),
        now());
  }

  /** Extends a machine identity access token ({@code POST /api/v1/auth/token/renew}). */
  AccessToken renewToken(Secret token) {
    if (token == null || token.isEmpty()) {
      throw new ValidationException("auth.renew: access token is required");
    }
    return tokenCall(
        "auth.renew", "/api/v1/auth/token/renew", Map.of("accessToken", token.reveal()));
  }

  /** Revokes an access token ({@code POST /api/v1/auth/token/revoke}); twice succeeds. */
  void revokeToken(Secret token) {
    if (token == null || token.isEmpty()) {
      throw new ValidationException("auth.revoke: access token is required");
    }
    callJson(
        new Call("POST", "/api/v1/auth/token/revoke", "auth.revoke")
            .body(Map.of("accessToken", token.reveal()))
            .noAuth());
  }

  // ----- core surface -----

  /**
   * Checks the server without credentials ({@code GET /api/status}). Healthy with status {@code ok}
   * when the server answers 200; details carry the status flags. Never throws for an unhealthy or
   * unreachable service.
   *
   * @return the health status
   * @throws CancelledException when interrupted or closed
   */
  public HealthStatus health() {
    return HealthCheck.check(transport, "/api/status");
  }

  /**
   * Asynchronous {@link #health()}.
   *
   * @return a future with the health status
   */
  public CompletableFuture<HealthStatus> healthAsync() {
    return HealthCheck.checkAsync(transport, "/api/status");
  }

  /**
   * Makes an authenticated round trip and returns its latency. The route depends on the token kind:
   * machine identity tokens use {@code GET /api/v1/identities/details}, user JWTs {@code GET
   * /api/v2/users/me} and legacy service tokens {@code GET /api/v2/service-token}.
   *
   * @return the latency
   * @throws AuthenticationException on a missing, invalid or revoked token
   */
  public Duration ping() {
    long start = System.nanoTime();
    String token = auth.bearer();
    String path = "/api/v1/identities/details";
    switch (tokenKind(token)) {
      case SERVICE:
        path = "/api/v2/service-token";
        break;
      case USER:
        path = "/api/v2/users/me";
        break;
      default:
        break;
    }
    send(new Call("GET", path, "ping"));
    return Duration.ofNanos(Math.max(1, System.nanoTime() - start));
  }

  /**
   * Asynchronous {@link #ping()}.
   *
   * @return a future with the latency
   */
  public CompletableFuture<Duration> pingAsync() {
    return async(this::ping);
  }

  /**
   * Always fails: no Infisical endpoint reports the running server version ({@code GET /api/status}
   * has none and the admin config only reports the latest available release).
   *
   * @return never returns
   * @throws UnsupportedException always
   */
  public String serverVersion() {
    throw new UnsupportedException("serverVersion: Infisical exposes no server version over HTTP");
  }

  /**
   * Asynchronous {@link #serverVersion()}; the future fails with {@link UnsupportedException}.
   *
   * @return a failed future
   */
  public CompletableFuture<String> serverVersionAsync() {
    return async(this::serverVersion);
  }

  /**
   * Returns whether {@link #close()} was called.
   *
   * @return true once closed
   */
  public boolean isClosed() {
    return closed.get();
  }

  /**
   * Stops every secrets watcher, revokes a token obtained by login when {@link
   * InfisicalConfig#revokeOnClose()} is set (best effort) and releases the transport. Idempotent.
   */
  @Override
  public void close() {
    List<AutoCloseable> copy;
    synchronized (resources) {
      if (!closed.compareAndSet(false, true)) {
        return;
      }
      copy = new ArrayList<>(resources);
      resources.clear();
    }
    for (int i = copy.size() - 1; i >= 0; i--) {
      closeQuietly(copy.get(i));
    }
    if (config.revokeOnClose()) {
      auth.revokeManaged();
    }
    transport.close();
  }

  @Override
  public String toString() {
    return "InfisicalClient{" + config + "}";
  }

  // ----- token kinds -----

  enum TokenKind {
    IDENTITY,
    USER,
    SERVICE
  }

  /**
   * Classifies a bearer token: legacy service tokens start with {@code st.}; user JWTs carry {@code
   * authTokenType=accessToken} (or a userId without identityId); everything else is a machine
   * identity token.
   */
  static TokenKind tokenKind(String token) {
    if (token == null) {
      return TokenKind.IDENTITY;
    }
    if (token.startsWith("st.")) {
      return TokenKind.SERVICE;
    }
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3) {
      return TokenKind.IDENTITY;
    }
    try {
      byte[] payload = Base64.getUrlDecoder().decode(parts[1].replace("=", ""));
      JsonNode claims = Json.tree(payload);
      if ("accessToken".equals(Wire.text(claims, "authTokenType"))
          || (!Wire.text(claims, "userId").isEmpty()
              && Wire.text(claims, "identityId").isEmpty())) {
        return TokenKind.USER;
      }
    } catch (IllegalArgumentException | InfisicalException e) {
      return TokenKind.IDENTITY;
    }
    return TokenKind.IDENTITY;
  }

  // ----- request plumbing -----

  /** One Infisical API call; the path is absolute ({@code /api/v4/secrets}). */
  static final class Call {
    final String method;
    final String path;
    final String op;
    final Map<String, List<String>> query = new LinkedHashMap<>();
    Object body;
    boolean noAuth;

    Call(String method, String path, String op) {
      this.method = method;
      this.path = path;
      this.op = op;
    }

    Call query(String name, Object value) {
      query.computeIfAbsent(name, k -> new ArrayList<>()).add(String.valueOf(value));
      return this;
    }

    Call body(Object body) {
      this.body = body;
      return this;
    }

    /** Sends no Authorization header (login, renew, revoke answer 403 TokenError otherwise). */
    Call noAuth() {
      this.noAuth = true;
      return this;
    }
  }

  /** Marks a 404 for an API route the server does not have (the v4 to v3 fallback signal). */
  static final class RouteMissing extends RuntimeException {
    private static final long serialVersionUID = 1L;

    RouteMissing() {
      super("api route not found on this server", null, false, false);
    }
  }

  static boolean isRouteMissing(InfisicalException e) {
    return e.getCause() instanceof RouteMissing;
  }

  /**
   * Executes a call with the managed token; an {@code AUTHENTICATION} error with a token obtained
   * by login triggers one re-login and one retry.
   */
  TransportResponse send(Call r) {
    String token = r.noAuth ? null : auth.bearer();
    try {
      return raw(r, token);
    } catch (AuthenticationException e) {
      if (r.noAuth || !auth.managed()) {
        throw e;
      }
      String fresh;
      try {
        fresh = auth.relogin(token);
      } catch (InfisicalException le) {
        throw e;
      }
      return raw(r, fresh);
    }
  }

  private TransportResponse raw(Call r, String token) {
    TransportRequest.Builder b =
        TransportRequest.builder(r.method, r.path).operation(r.op).acceptStatus(ERROR_STATUSES);
    r.query.forEach((k, vs) -> vs.forEach(v -> b.query(k, v)));
    if (token != null && !token.isEmpty() && !r.noAuth) {
      b.header("Authorization", "Bearer " + token);
    }
    if (r.body != null) {
      b.json(r.body);
    }
    TransportResponse resp;
    try {
      resp = transport.send(b.build());
    } catch (RateLimitException e) {
      throw withRetryAfter(e);
    }
    if (resp.status() >= 400) {
      throw mapError(r, resp);
    }
    return resp;
  }

  /** Takes the wait from "try again in N seconds" when the 429 carried no Retry-After. */
  static RateLimitException withRetryAfter(RateLimitException e) {
    if (e.retryAfter().isPresent()) {
      return e;
    }
    Matcher m = RETRY_IN.matcher(String.valueOf(e.getMessage()));
    if (!m.find()) {
      return e;
    }
    return (RateLimitException)
        InfisicalException.of(
            ErrorCode.RATE_LIMITED,
            e.getMessage(),
            e.httpStatus().isPresent() ? e.httpStatus().getAsInt() : null,
            e.requestId().orElse(null),
            Duration.ofSeconds(Long.parseLong(m.group(1))),
            e.getCause());
  }

  /**
   * Maps an Infisical error response (SPEC section 2.1 plus the Infisical rules): 400 with "already
   * exists" is CONFLICT; 403 {@code TokenError} is AUTHENTICATION; 404 {@code Not Found} with a
   * message starting "Route " is a missing API route (UNSUPPORTED).
   */
  private InfisicalException mapError(Call r, TransportResponse resp) {
    int status = resp.status();
    JsonNode body;
    try {
      body = resp.jsonNode();
    } catch (InfisicalException e) {
      body = MissingNode.getInstance();
    }
    String name = Wire.text(body, "error");
    String message = messageText(body.get("message"));
    String reqId = Wire.text(body, "reqId");
    byte[] vendor = message.isEmpty() ? resp.body() : Json.encode(Map.of("message", message));
    String text =
        HttpTransport.errorMessage(
            r.op, status, resp.headers(), vendor, transport.config().knownSecrets());
    ErrorCode code = ErrorCode.forStatus(status);
    Throwable cause = null;
    String lower = message.toLowerCase(java.util.Locale.ROOT);
    if (status == 400 && lower.contains("already exists")) {
      code = ErrorCode.CONFLICT;
    } else if (status == 403 && "TokenError".equals(name)) {
      code = ErrorCode.AUTHENTICATION;
    } else if (status == 404 && "Not Found".equals(name) && message.startsWith("Route ")) {
      code = ErrorCode.UNSUPPORTED;
      text = r.op + ": the server does not offer this API route (HTTP 404)";
      cause = new RouteMissing();
    }
    InfisicalException e =
        InfisicalException.of(
            code,
            text,
            status,
            reqId.isEmpty() ? resp.requestId().orElse(null) : reqId,
            null,
            cause);
    try {
      String url = Redaction.redactUrl(transport.resolve(r.path, r.query));
      config.hooks().onError(new Hooks.ErrorInfo(r.method, url, e, resp.attempts(), false));
    } catch (RuntimeException ignored) {
      // hooks must never break a call (SPEC section 2.5)
    }
    return e;
  }

  /** Turns the error {@code message} field (a string or a zod issue array) into text. */
  static String messageText(JsonNode m) {
    if (m == null || m.isNull()) {
      return "";
    }
    if (m.isTextual()) {
      return m.asText();
    }
    if (m.isArray()) {
      List<String> parts = new ArrayList<>();
      for (JsonNode issue : m) {
        String msg = Wire.text(issue, "message");
        JsonNode path = issue.get("path");
        if (path != null && path.isArray() && path.size() > 0) {
          List<String> segs = new ArrayList<>();
          path.forEach(p -> segs.add(p.asText()));
          msg = String.join(".", segs) + ": " + msg;
        }
        if (!msg.isEmpty()) {
          parts.add(msg);
        }
      }
      return String.join("; ", parts);
    }
    return m.toString();
  }

  /** Executes a call and returns the JSON body (a missing node when empty). */
  JsonNode callJson(Call r) {
    TransportResponse resp = send(r);
    if (resp.text().isBlank()) {
      return MissingNode.getInstance();
    }
    return resp.jsonNode();
  }

  // ----- scope resolution -----

  String projectId(String op, String explicit) {
    if (explicit != null && !explicit.isEmpty()) {
      return explicit;
    }
    return config
        .projectId()
        .orElseThrow(
            () ->
                new ConfigException(
                    op
                        + ": projectId is required (set projectId, GROW_INFISICAL_PROJECT_ID or"
                        + " INFISICAL_PROJECT_ID)"));
  }

  String environment(String op, String explicit) {
    if (explicit != null && !explicit.isEmpty()) {
      return explicit;
    }
    return config
        .environment()
        .orElseThrow(
            () ->
                new ConfigException(
                    op
                        + ": environment is required (set environment, GROW_INFISICAL_ENVIRONMENT"
                        + " or INFISICAL_ENVIRONMENT)"));
  }

  String path(String explicit) {
    return SecretPaths.normalize(
        explicit != null && !explicit.isEmpty() ? explicit : config.secretPath());
  }

  /** Resolved project, environment and path of a call. */
  record Scope(String projectId, String environment, String path) {}

  Scope scope(String op, String projectId, String environment, String path) {
    return new Scope(projectId(op, projectId), environment(op, environment), path(path));
  }

  static void requireArg(String op, String name, String value) {
    if (value == null || value.isBlank()) {
      throw new ValidationException(op + ": " + name + " is required");
    }
  }

  private static String seg(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
  }

  // ----- secrets API version detection -----

  private String secretsVersion() {
    synchronized (apiLock) {
      return secretsApi;
    }
  }

  private void setSecretsVersion(String v) {
    synchronized (apiLock) {
      if (secretsApi.isEmpty() || config.apiVersion().isEmpty()) {
        secretsApi = v;
      }
    }
  }

  /**
   * Runs a secrets request built for v4 or v3. With automatic detection the first call tries v4 and
   * falls back to v3 only when the server answers 404 "Route … not found" (a definitive answer, so
   * replaying a write is safe); any other HTTP answer pins v4.
   */
  JsonNode secretsCall(Function<Boolean, Call> build) {
    String v = secretsVersion();
    boolean auto = v.isEmpty() && config.apiVersion().isEmpty();
    try {
      JsonNode out = callJson(build.apply(InfisicalConfig.API_VERSION_V3.equals(v)));
      if (auto) {
        setSecretsVersion(InfisicalConfig.API_VERSION_V4);
      }
      return out;
    } catch (InfisicalException e) {
      if (!auto) {
        throw e;
      }
      if (isRouteMissing(e)) {
        setSecretsVersion(InfisicalConfig.API_VERSION_V3);
        return callJson(build.apply(true));
      }
      if (e.httpStatus().isPresent()) {
        setSecretsVersion(InfisicalConfig.API_VERSION_V4);
      }
      throw e;
    }
  }

  private static String secretsPath(boolean v3, String suffix) {
    if (v3) {
      return suffix.startsWith("/batch")
          ? "/api/v3/secrets/batch/raw"
          : "/api/v3/secrets/raw" + suffix;
    }
    return "/api/v4/secrets" + suffix;
  }

  private static String projectField(boolean v3) {
    return v3 ? "workspaceId" : "projectId";
  }

  private static String importsField(boolean v3) {
    return v3 ? "include_imports" : "includeImports";
  }

  private static <T> T or(T value, T fallback) {
    return value != null ? value : fallback;
  }

  private Map<String, Object> scopeBody(boolean v3, Scope s) {
    Map<String, Object> b = new LinkedHashMap<>();
    b.put(projectField(v3), s.projectId());
    b.put("environment", s.environment());
    b.put("secretPath", s.path());
    return b;
  }

  private static List<Map<String, String>> metadataList(Map<String, String> m) {
    List<Map<String, String>> out = new ArrayList<>();
    new TreeMap<>(m)
        .forEach(
            (k, v) -> {
              Map<String, String> e = new LinkedHashMap<>();
              e.put("key", k);
              e.put("value", v);
              out.add(e);
            });
    return out;
  }

  // ----- secrets -----

  /**
   * Lists the secrets of the configured path.
   *
   * @return the secrets and imported secrets
   */
  public SecretList listSecrets() {
    return listSecrets(null);
  }

  /**
   * Lists the secrets of a path ({@code GET /api/v4/secrets}, v3 fallback {@code GET
   * /api/v3/secrets/raw}). A missing environment or path is {@link NotFoundException}.
   *
   * @param options selection, may be null for the defaults
   * @return the secrets and imported secrets
   */
  public SecretList listSecrets(ListSecretsOptions options) {
    ListSecretsOptions o = or(options, ListSecretsOptions.defaults());
    String op = "secrets.list";
    Scope s = scope(op, o.projectId(), o.environment(), o.secretPath());
    JsonNode body =
        secretsCall(
            v3 -> {
              Call c =
                  new Call("GET", secretsPath(v3, ""), op + " " + s.path())
                      .query(projectField(v3), s.projectId())
                      .query("environment", s.environment())
                      .query("secretPath", s.path())
                      .query("recursive", o.recursive())
                      .query("expandSecretReferences", o.expandReferences())
                      .query(importsField(v3), o.includeImports());
              if (!o.tagSlugs().isEmpty()) {
                c.query("tagSlugs", String.join(",", o.tagSlugs()));
              }
              if (!v3) {
                c.query("viewSecretValue", o.viewSecretValue());
                if (o.includePersonalOverrides()) {
                  c.query("includePersonalOverrides", true);
                }
              }
              return c;
            });
    return Wire.secretList(body);
  }

  /**
   * Asynchronous {@link #listSecrets(ListSecretsOptions)}.
   *
   * @param options selection, may be null
   * @return a future with the secrets
   */
  public CompletableFuture<SecretList> listSecretsAsync(ListSecretsOptions options) {
    return async(() -> listSecrets(options));
  }

  /**
   * Reads one secret of the configured path.
   *
   * @param name secret name
   * @return the secret
   * @throws NotFoundException when missing
   */
  public SecretEntry getSecret(String name) {
    return getSecret(name, null);
  }

  /**
   * Reads one secret ({@code GET /api/v4/secrets/{name}}, v3 fallback {@code GET
   * /api/v3/secrets/raw/{name}}). A missing secret or version is {@link NotFoundException}.
   *
   * @param name secret name
   * @param options selection, may be null for the defaults
   * @return the secret
   */
  public SecretEntry getSecret(String name, GetSecretOptions options) {
    String op = "secrets.get";
    requireArg(op, "name", name);
    GetSecretOptions o = or(options, GetSecretOptions.defaults());
    if (o.version() < 0) {
      throw new ValidationException(op + ": version must be positive");
    }
    Scope s = scope(op, o.projectId(), o.environment(), o.secretPath());
    JsonNode body =
        secretsCall(
            v3 -> {
              Call c =
                  new Call("GET", secretsPath(v3, "/" + seg(name)), op + " " + name)
                      .query(projectField(v3), s.projectId())
                      .query("environment", s.environment())
                      .query("secretPath", s.path());
              if (o.version() > 0) {
                c.query("version", o.version());
              }
              o.type().ifPresent(t -> c.query("type", t.wireValue()));
              c.query("expandSecretReferences", o.expandReferences());
              c.query(importsField(v3), o.includeImports());
              if (!v3) {
                c.query("viewSecretValue", o.viewSecretValue());
              }
              return c;
            });
    return Wire.secret(body.path("secret"));
  }

  /**
   * Asynchronous {@link #getSecret(String, GetSecretOptions)}.
   *
   * @param name secret name
   * @param options selection, may be null
   * @return a future with the secret
   */
  public CompletableFuture<SecretEntry> getSecretAsync(String name, GetSecretOptions options) {
    return async(() -> getSecret(name, options));
  }

  /**
   * Creates a secret in the configured path.
   *
   * @param name secret name
   * @param value value
   * @return the created secret (version 1)
   */
  public SecretEntry createSecret(String name, String value) {
    return createSecret(name, value, null);
  }

  /**
   * Creates a secret ({@code POST /api/v4/secrets/{name}}). The folder must exist ({@link
   * NotFoundException} otherwise); a duplicate is {@code ConflictException}. Infisical trims
   * surrounding whitespace of the value.
   *
   * @param name secret name
   * @param value value
   * @param options options, may be null
   * @return the created secret
   */
  public SecretEntry createSecret(String name, String value, CreateSecretOptions options) {
    String op = "secrets.create";
    requireArg(op, "name", name);
    CreateSecretOptions o = or(options, CreateSecretOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.secretPath());
    List<String> tagIds = resolveTagIds(op, s.projectId(), o.tagIds(), o.tagSlugs());
    JsonNode body =
        secretsCall(
            v3 -> {
              Map<String, Object> b = scopeBody(v3, s);
              b.put("secretValue", value == null ? "" : value);
              if (!o.comment().isEmpty()) {
                b.put("secretComment", o.comment());
              }
              if (!tagIds.isEmpty()) {
                b.put("tagIds", tagIds);
              }
              o.type().ifPresent(t -> b.put("type", t.wireValue()));
              if (o.skipMultilineEncoding()) {
                b.put("skipMultilineEncoding", true);
              }
              if (!o.metadata().isEmpty()) {
                b.put("secretMetadata", metadataList(o.metadata()));
              }
              return new Call("POST", secretsPath(v3, "/" + seg(name)), op + " " + name).body(b);
            });
    return Wire.secret(body.path("secret"));
  }

  /**
   * Asynchronous {@link #createSecret(String, String, CreateSecretOptions)}.
   *
   * @param name secret name
   * @param value value
   * @param options options, may be null
   * @return a future with the created secret
   */
  public CompletableFuture<SecretEntry> createSecretAsync(
      String name, String value, CreateSecretOptions options) {
    return async(() -> createSecret(name, value, options));
  }

  /**
   * Changes a secret ({@code PATCH /api/v4/secrets/{name}}): value, name, comment and tags. Every
   * update bumps the version. When no new value is sent the returned value is empty (the server
   * does not echo it).
   *
   * @param name secret name
   * @param options changes, may be null
   * @return the updated secret
   */
  public SecretEntry updateSecret(String name, UpdateSecretOptions options) {
    String op = "secrets.update";
    requireArg(op, "name", name);
    UpdateSecretOptions o = or(options, UpdateSecretOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.secretPath());
    List<String> tagIds =
        o.tagIds().isPresent() || o.tagSlugs().isPresent()
            ? resolveTagIds(
                op, s.projectId(), o.tagIds().orElse(List.of()), o.tagSlugs().orElse(List.of()))
            : null;
    JsonNode body =
        secretsCall(
            v3 -> {
              Map<String, Object> b = scopeBody(v3, s);
              o.value().ifPresent(v -> b.put("secretValue", v));
              if (!o.newName().isEmpty()) {
                b.put("newSecretName", o.newName());
              }
              o.comment().ifPresent(c -> b.put("secretComment", c));
              if (tagIds != null) {
                b.put("tagIds", tagIds);
              }
              o.type().ifPresent(t -> b.put("type", t.wireValue()));
              o.skipMultilineEncoding().ifPresent(f -> b.put("skipMultilineEncoding", f));
              o.metadata().ifPresent(m -> b.put("secretMetadata", metadataList(m)));
              return new Call("PATCH", secretsPath(v3, "/" + seg(name)), op + " " + name).body(b);
            });
    return Wire.secret(body.path("secret"));
  }

  /**
   * Asynchronous {@link #updateSecret(String, UpdateSecretOptions)}.
   *
   * @param name secret name
   * @param options changes, may be null
   * @return a future with the updated secret
   */
  public CompletableFuture<SecretEntry> updateSecretAsync(
      String name, UpdateSecretOptions options) {
    return async(() -> updateSecret(name, options));
  }

  /**
   * Deletes a secret of the configured path with all its versions.
   *
   * @param name secret name
   * @return the deleted secret
   */
  public SecretEntry deleteSecret(String name) {
    return deleteSecret(name, null);
  }

  /**
   * Deletes a secret with all its versions ({@code DELETE /api/v4/secrets/{name}}); a missing
   * secret is {@link NotFoundException}.
   *
   * @param name secret name
   * @param options options, may be null
   * @return the deleted secret
   */
  public SecretEntry deleteSecret(String name, DeleteSecretOptions options) {
    String op = "secrets.delete";
    requireArg(op, "name", name);
    DeleteSecretOptions o = or(options, DeleteSecretOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.secretPath());
    JsonNode body =
        secretsCall(
            v3 -> {
              Map<String, Object> b = scopeBody(v3, s);
              o.type().ifPresent(t -> b.put("type", t.wireValue()));
              return new Call("DELETE", secretsPath(v3, "/" + seg(name)), op + " " + name).body(b);
            });
    return Wire.secret(body.path("secret"));
  }

  /**
   * Asynchronous {@link #deleteSecret(String, DeleteSecretOptions)}.
   *
   * @param name secret name
   * @param options options, may be null
   * @return a future with the deleted secret
   */
  public CompletableFuture<SecretEntry> deleteSecretAsync(
      String name, DeleteSecretOptions options) {
    return async(() -> deleteSecret(name, options));
  }

  private List<SecretEntry> batch(
      String op,
      String method,
      Scope s,
      Map<String, Object> extra,
      List<Map<String, Object>> items) {
    JsonNode body =
        secretsCall(
            v3 -> {
              Map<String, Object> b = scopeBody(v3, s);
              b.put("secrets", items);
              b.putAll(extra);
              return new Call(method, secretsPath(v3, "/batch"), op + " " + s.path()).body(b);
            });
    return Wire.list(body.get("secrets"), Wire::secret);
  }

  /**
   * Creates several secrets atomically ({@code POST /api/v4/secrets/batch}): one duplicate fails
   * the batch with {@code ConflictException} and nothing is created. The result order is not
   * guaranteed.
   *
   * @param secrets secrets to create (at least one)
   * @param scope where to create them, may be null
   * @return the created secrets
   */
  public List<SecretEntry> createSecrets(List<SecretInput> secrets, BatchScope scope) {
    String op = "secrets.createBatch";
    if (secrets == null || secrets.isEmpty()) {
      throw new ValidationException(op + ": at least one secret is required");
    }
    BatchScope o = or(scope, BatchScope.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.secretPath());
    List<Map<String, Object>> items = new ArrayList<>();
    for (SecretInput in : secrets) {
      requireArg(op, "key", in.key());
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("secretKey", in.key());
      m.put("secretValue", in.value());
      if (!in.comment().isEmpty()) {
        m.put("secretComment", in.comment());
      }
      in.tagIds().ifPresent(t -> m.put("tagIds", t));
      if (in.skipMultilineEncoding()) {
        m.put("skipMultilineEncoding", true);
      }
      if (!in.metadata().isEmpty()) {
        m.put("secretMetadata", metadataList(in.metadata()));
      }
      items.add(m);
    }
    return batch(op, "POST", s, Map.of(), items);
  }

  /**
   * Asynchronous {@link #createSecrets(List, BatchScope)}.
   *
   * @param secrets secrets to create
   * @param scope where to create them, may be null
   * @return a future with the created secrets
   */
  public CompletableFuture<List<SecretEntry>> createSecretsAsync(
      List<SecretInput> secrets, BatchScope scope) {
    return async(() -> createSecrets(secrets, scope));
  }

  /**
   * Updates several secrets atomically ({@code PATCH /api/v4/secrets/batch}). With the default mode
   * a missing key fails the batch with {@link NotFoundException}.
   *
   * @param secrets updates (at least one)
   * @param options scope and mode, may be null
   * @return the updated secrets
   */
  public List<SecretEntry> updateSecrets(List<SecretUpdate> secrets, UpdateSecretsOptions options) {
    String op = "secrets.updateBatch";
    if (secrets == null || secrets.isEmpty()) {
      throw new ValidationException(op + ": at least one secret is required");
    }
    UpdateSecretsOptions o = or(options, UpdateSecretsOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.secretPath());
    List<Map<String, Object>> items = new ArrayList<>();
    for (SecretUpdate in : secrets) {
      requireArg(op, "key", in.key());
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("secretKey", in.key());
      in.value().ifPresent(v -> m.put("secretValue", v));
      if (!in.newName().isEmpty()) {
        m.put("newSecretName", in.newName());
      }
      in.comment().ifPresent(c -> m.put("secretComment", c));
      in.tagIds().ifPresent(t -> m.put("tagIds", t));
      in.skipMultilineEncoding().ifPresent(f -> m.put("skipMultilineEncoding", f));
      items.add(m);
    }
    Map<String, Object> extra = new LinkedHashMap<>();
    o.mode().ifPresent(mode -> extra.put("mode", mode.wireValue()));
    return batch(op, "PATCH", s, extra, items);
  }

  /**
   * Asynchronous {@link #updateSecrets(List, UpdateSecretsOptions)}.
   *
   * @param secrets updates
   * @param options scope and mode, may be null
   * @return a future with the updated secrets
   */
  public CompletableFuture<List<SecretEntry>> updateSecretsAsync(
      List<SecretUpdate> secrets, UpdateSecretsOptions options) {
    return async(() -> updateSecrets(secrets, options));
  }

  /**
   * Deletes several secrets atomically ({@code DELETE /api/v4/secrets/batch}): one missing key
   * fails the batch with {@link NotFoundException} and nothing is deleted.
   *
   * @param keys secret names (at least one)
   * @param options scope and type, may be null
   * @return the deleted secrets
   */
  public List<SecretEntry> deleteSecrets(List<String> keys, DeleteSecretsOptions options) {
    String op = "secrets.deleteBatch";
    if (keys == null || keys.isEmpty()) {
      throw new ValidationException(op + ": at least one key is required");
    }
    DeleteSecretsOptions o = or(options, DeleteSecretsOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.secretPath());
    List<Map<String, Object>> items = new ArrayList<>();
    for (String k : keys) {
      requireArg(op, "key", k);
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("secretKey", k);
      o.type().ifPresent(t -> m.put("type", t.wireValue()));
      items.add(m);
    }
    return batch(op, "DELETE", s, Map.of(), items);
  }

  /**
   * Asynchronous {@link #deleteSecrets(List, DeleteSecretsOptions)}.
   *
   * @param keys secret names
   * @param options scope and type, may be null
   * @return a future with the deleted secrets
   */
  public CompletableFuture<List<SecretEntry>> deleteSecretsAsync(
      List<String> keys, DeleteSecretsOptions options) {
    return async(() -> deleteSecrets(keys, options));
  }

  // ----- folders (v2) -----

  /**
   * Lists the folders under the configured path.
   *
   * @return the folders
   */
  public List<Folder> listFolders() {
    return listFolders(null);
  }

  /**
   * Lists the folders under a path ({@code GET /api/v2/folders}).
   *
   * @param options selection, may be null
   * @return the folders
   */
  public List<Folder> listFolders(ListFoldersOptions options) {
    String op = "folders.list";
    ListFoldersOptions o = or(options, ListFoldersOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.path());
    Call c =
        new Call("GET", "/api/v2/folders", op + " " + s.path())
            .query("projectId", s.projectId())
            .query("environment", s.environment())
            .query("path", s.path());
    if (o.recursive()) {
      c.query("recursive", true);
    }
    return Wire.list(callJson(c).get("folders"), Wire::folder);
  }

  /**
   * Asynchronous {@link #listFolders(ListFoldersOptions)}.
   *
   * @param options selection, may be null
   * @return a future with the folders
   */
  public CompletableFuture<List<Folder>> listFoldersAsync(ListFoldersOptions options) {
    return async(() -> listFolders(options));
  }

  /**
   * Creates a folder under a path ({@code POST /api/v2/folders}). Names allow letters, digits,
   * {@code -} and {@code _} ({@link ValidationException} otherwise); a duplicate is {@code
   * ConflictException}.
   *
   * @param name folder name
   * @param options parent path and description, may be null
   * @return the folder
   */
  public Folder createFolder(String name, CreateFolderOptions options) {
    String op = "folders.create";
    requireArg(op, "name", name);
    CreateFolderOptions o = or(options, CreateFolderOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.path());
    Map<String, Object> b = new LinkedHashMap<>();
    b.put("projectId", s.projectId());
    b.put("environment", s.environment());
    b.put("name", name);
    b.put("path", s.path());
    if (!o.description().isEmpty()) {
      b.put("description", o.description());
    }
    return Wire.folder(
        callJson(new Call("POST", "/api/v2/folders", op + " " + name).body(b)).path("folder"));
  }

  /**
   * Asynchronous {@link #createFolder(String, CreateFolderOptions)}.
   *
   * @param name folder name
   * @param options options, may be null
   * @return a future with the folder
   */
  public CompletableFuture<Folder> createFolderAsync(String name, CreateFolderOptions options) {
    return async(() -> createFolder(name, options));
  }

  /**
   * Renames a folder or changes its description ({@code PATCH /api/v2/folders/{id}}); an unknown id
   * is {@link NotFoundException}.
   *
   * @param folderId folder id
   * @param options new name (required), description and parent path
   * @return the folder
   */
  public Folder updateFolder(String folderId, UpdateFolderOptions options) {
    String op = "folders.update";
    requireArg(op, "folderId", folderId);
    UpdateFolderOptions o = or(options, UpdateFolderOptions.defaults());
    requireArg(op, "name", o.name());
    Scope s = scope(op, o.projectId(), o.environment(), o.path());
    Map<String, Object> b = new LinkedHashMap<>();
    b.put("projectId", s.projectId());
    b.put("environment", s.environment());
    b.put("name", o.name());
    b.put("path", s.path());
    o.description().ifPresent(d -> b.put("description", d));
    Call c = new Call("PATCH", "/api/v2/folders/" + seg(folderId), op + " " + folderId).body(b);
    return Wire.folder(callJson(c).path("folder"));
  }

  /**
   * Asynchronous {@link #updateFolder(String, UpdateFolderOptions)}.
   *
   * @param folderId folder id
   * @param options changes
   * @return a future with the folder
   */
  public CompletableFuture<Folder> updateFolderAsync(String folderId, UpdateFolderOptions options) {
    return async(() -> updateFolder(folderId, options));
  }

  /**
   * Deletes a folder by id or name ({@code DELETE /api/v2/folders/{idOrName}}); a missing folder is
   * {@link NotFoundException}.
   *
   * @param folderIdOrName folder id or name
   * @param options parent path and force flag, may be null
   * @return the deleted folder
   */
  public Folder deleteFolder(String folderIdOrName, DeleteFolderOptions options) {
    String op = "folders.delete";
    requireArg(op, "folderIdOrName", folderIdOrName);
    DeleteFolderOptions o = or(options, DeleteFolderOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.path());
    Map<String, Object> b = new LinkedHashMap<>();
    b.put("projectId", s.projectId());
    b.put("environment", s.environment());
    b.put("path", s.path());
    if (o.force()) {
      b.put("forceDelete", true);
    }
    Call c =
        new Call("DELETE", "/api/v2/folders/" + seg(folderIdOrName), op + " " + folderIdOrName)
            .body(b);
    return Wire.folder(callJson(c).path("folder"));
  }

  /**
   * Asynchronous {@link #deleteFolder(String, DeleteFolderOptions)}.
   *
   * @param folderIdOrName folder id or name
   * @param options options, may be null
   * @return a future with the deleted folder
   */
  public CompletableFuture<Folder> deleteFolderAsync(
      String folderIdOrName, DeleteFolderOptions options) {
    return async(() -> deleteFolder(folderIdOrName, options));
  }

  // ----- projects + environments (v1) -----

  /**
   * Lists the projects the caller is a member of ({@code GET /api/v1/projects}).
   *
   * @param options type and paging, may be null
   * @return one page of projects
   */
  public ProjectPage listProjects(ListProjectsOptions options) {
    String op = "projects.list";
    ListProjectsOptions o = or(options, ListProjectsOptions.defaults());
    if (o.limit() < 0 || o.limit() > 100 || o.offset() < 0) {
      throw new ValidationException(op + ": limit must be 1-100 and offset >= 0");
    }
    Call c =
        new Call("GET", "/api/v1/projects", op)
            .query("type", o.type().isEmpty() ? "secret-manager" : o.type());
    if (o.limit() > 0) {
      c.query("limit", o.limit());
    }
    if (o.offset() > 0) {
      c.query("offset", o.offset());
    }
    JsonNode body = callJson(c);
    return new ProjectPage(
        Wire.list(body.get("projects"), Wire::project), body.path("totalCount").asInt());
  }

  /**
   * Asynchronous {@link #listProjects(ListProjectsOptions)}.
   *
   * @param options type and paging, may be null
   * @return a future with the page
   */
  public CompletableFuture<ProjectPage> listProjectsAsync(ListProjectsOptions options) {
    return async(() -> listProjects(options));
  }

  /**
   * Reads a project by id ({@code GET /api/v1/projects/{id}}); null or {@code ""} reads the
   * configured project. An unknown id is {@link NotFoundException}.
   *
   * @param projectId project id, may be null
   * @return the project
   */
  public Project getProject(String projectId) {
    String op = "projects.get";
    String id = projectId(op, projectId);
    return Wire.project(
        callJson(new Call("GET", "/api/v1/projects/" + seg(id), op + " " + id)).path("project"));
  }

  /**
   * Asynchronous {@link #getProject(String)}.
   *
   * @param projectId project id, may be null
   * @return a future with the project
   */
  public CompletableFuture<Project> getProjectAsync(String projectId) {
    return async(() -> getProject(projectId));
  }

  /**
   * Reads a project by slug ({@code GET /api/v1/projects/slug/{slug}}).
   *
   * @param slug project slug
   * @return the project
   */
  public Project getProjectBySlug(String slug) {
    String op = "projects.getBySlug";
    requireArg(op, "slug", slug);
    return Wire.project(
        callJson(new Call("GET", "/api/v1/projects/slug/" + seg(slug), op + " " + slug)));
  }

  /**
   * Asynchronous {@link #getProjectBySlug(String)}.
   *
   * @param slug project slug
   * @return a future with the project
   */
  public CompletableFuture<Project> getProjectBySlugAsync(String slug) {
    return async(() -> getProjectBySlug(slug));
  }

  /**
   * Returns the environments of a project, ordered by position (from {@code GET
   * /api/v1/projects/{id}}; Infisical has no list route).
   *
   * @param options project, may be null for the configured one
   * @return the environments
   */
  public List<Environment> listEnvironments(ProjectOptions options) {
    return getProject(or(options, ProjectOptions.defaults()).projectId()).environments();
  }

  /**
   * Asynchronous {@link #listEnvironments(ProjectOptions)}.
   *
   * @param options project, may be null
   * @return a future with the environments
   */
  public CompletableFuture<List<Environment>> listEnvironmentsAsync(ProjectOptions options) {
    return async(() -> listEnvironments(options));
  }

  /**
   * Creates a project environment ({@code POST /api/v1/projects/{id}/environments}; project admin).
   * Slugs allow lower-case letters, digits and {@code -}; a duplicate slug is {@code
   * ConflictException}.
   *
   * @param name display name
   * @param slug slug
   * @param options project and position, may be null
   * @return the environment
   */
  public Environment createEnvironment(String name, String slug, CreateEnvironmentOptions options) {
    String op = "environments.create";
    requireArg(op, "name", name);
    requireArg(op, "slug", slug);
    CreateEnvironmentOptions o = or(options, CreateEnvironmentOptions.defaults());
    String id = projectId(op, o.projectId());
    Map<String, Object> b = new LinkedHashMap<>();
    b.put("name", name);
    b.put("slug", slug);
    if (o.position() > 0) {
      b.put("position", o.position());
    }
    Call c =
        new Call("POST", "/api/v1/projects/" + seg(id) + "/environments", op + " " + slug).body(b);
    return Wire.environment(callJson(c).path("environment"));
  }

  /**
   * Asynchronous {@link #createEnvironment(String, String, CreateEnvironmentOptions)}.
   *
   * @param name display name
   * @param slug slug
   * @param options options, may be null
   * @return a future with the environment
   */
  public CompletableFuture<Environment> createEnvironmentAsync(
      String name, String slug, CreateEnvironmentOptions options) {
    return async(() -> createEnvironment(name, slug, options));
  }

  // ----- tags (v1) -----

  /**
   * Lists the tags of a project ({@code GET /api/v1/projects/{id}/tags}).
   *
   * @param options project, may be null for the configured one
   * @return the tags
   */
  public List<Tag> listTags(ProjectOptions options) {
    String op = "tags.list";
    String id = projectId(op, or(options, ProjectOptions.defaults()).projectId());
    return Wire.list(
        callJson(new Call("GET", "/api/v1/projects/" + seg(id) + "/tags", op)).get("tags"),
        Wire::tag);
  }

  /**
   * Asynchronous {@link #listTags(ProjectOptions)}.
   *
   * @param options project, may be null
   * @return a future with the tags
   */
  public CompletableFuture<List<Tag>> listTagsAsync(ProjectOptions options) {
    return async(() -> listTags(options));
  }

  /**
   * Creates a project tag ({@code POST /api/v1/projects/{id}/tags}). Slugs allow lower-case
   * letters, digits and {@code -}; a null or empty color uses {@link #DEFAULT_TAG_COLOR}; a
   * duplicate slug is {@code ConflictException}.
   *
   * @param slug tag slug
   * @param color color such as {@code #00aa00}, may be null
   * @param options project, may be null
   * @return the tag
   */
  public Tag createTag(String slug, String color, ProjectOptions options) {
    String op = "tags.create";
    requireArg(op, "slug", slug);
    String id = projectId(op, or(options, ProjectOptions.defaults()).projectId());
    String c = color == null || color.isEmpty() ? DEFAULT_TAG_COLOR : color;
    Call call =
        new Call("POST", "/api/v1/projects/" + seg(id) + "/tags", op + " " + slug)
            .body(Map.of("slug", slug, "color", c));
    return Wire.tag(callJson(call).path("tag"));
  }

  /**
   * Asynchronous {@link #createTag(String, String, ProjectOptions)}.
   *
   * @param slug tag slug
   * @param color color, may be null
   * @param options project, may be null
   * @return a future with the tag
   */
  public CompletableFuture<Tag> createTagAsync(String slug, String color, ProjectOptions options) {
    return async(() -> createTag(slug, color, options));
  }

  /**
   * Deletes a tag by id ({@code DELETE /api/v1/projects/{id}/tags/{tagId}}); the tag disappears
   * from every secret. An unknown id is {@link NotFoundException}.
   *
   * @param tagId tag id
   * @param options project, may be null
   * @return the deleted tag
   */
  public Tag deleteTag(String tagId, ProjectOptions options) {
    String op = "tags.delete";
    requireArg(op, "tagId", tagId);
    String id = projectId(op, or(options, ProjectOptions.defaults()).projectId());
    Call c =
        new Call("DELETE", "/api/v1/projects/" + seg(id) + "/tags/" + seg(tagId), op + " " + tagId);
    return Wire.tag(callJson(c).path("tag"));
  }

  /**
   * Asynchronous {@link #deleteTag(String, ProjectOptions)}.
   *
   * @param tagId tag id
   * @param options project, may be null
   * @return a future with the deleted tag
   */
  public CompletableFuture<Tag> deleteTagAsync(String tagId, ProjectOptions options) {
    return async(() -> deleteTag(tagId, options));
  }

  /** Merges ids with the ids of slugs (resolved with listTags; unknown slug: NOT_FOUND). */
  List<String> resolveTagIds(String op, String projectId, List<String> ids, List<String> slugs) {
    List<String> out = new ArrayList<>(ids);
    if (slugs.isEmpty()) {
      return out;
    }
    Map<String, String> bySlug = new LinkedHashMap<>();
    for (Tag t : listTags(ProjectOptions.builder().projectId(projectId).build())) {
      bySlug.put(t.slug(), t.id());
    }
    for (String slug : slugs) {
      String id = bySlug.get(slug);
      if (id == null) {
        throw new NotFoundException(op + ": tag " + slug + " does not exist");
      }
      out.add(id);
    }
    return out;
  }

  // ----- secret imports (v2) -----

  /**
   * Lists the imports of a path ({@code GET /api/v2/secret-imports}).
   *
   * @param options importing path, may be null
   * @return the imports
   */
  public List<SecretImport> listSecretImports(SecretImportOptions options) {
    String op = "secretImports.list";
    SecretImportOptions o = or(options, SecretImportOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.path());
    Call c =
        new Call("GET", "/api/v2/secret-imports", op + " " + s.path())
            .query("projectId", s.projectId())
            .query("environment", s.environment())
            .query("path", s.path());
    return Wire.list(callJson(c).get("secretImports"), Wire::secretImport);
  }

  /**
   * Asynchronous {@link #listSecretImports(SecretImportOptions)}.
   *
   * @param options importing path, may be null
   * @return a future with the imports
   */
  public CompletableFuture<List<SecretImport>> listSecretImportsAsync(SecretImportOptions options) {
    return async(() -> listSecretImports(options));
  }

  /**
   * Imports the secrets of {@code importEnvironment}/{@code importPath} into a path ({@code POST
   * /api/v2/secret-imports}). Infisical accepts duplicates and source paths that do not exist.
   *
   * @param options importing path and source (importEnvironment is required)
   * @return the import
   */
  public SecretImport createSecretImport(CreateSecretImportOptions options) {
    String op = "secretImports.create";
    CreateSecretImportOptions o = or(options, CreateSecretImportOptions.defaults());
    requireArg(op, "importEnvironment", o.importEnvironment());
    Scope s = scope(op, o.projectId(), o.environment(), o.path());
    Map<String, Object> imp = new LinkedHashMap<>();
    imp.put("environment", o.importEnvironment());
    imp.put("path", SecretPaths.normalize(o.importPath()));
    if (!o.sourceProjectId().isEmpty()) {
      imp.put("sourceProjectId", o.sourceProjectId());
    }
    Map<String, Object> b = new LinkedHashMap<>();
    b.put("projectId", s.projectId());
    b.put("environment", s.environment());
    b.put("path", s.path());
    b.put("import", imp);
    if (o.isReplication()) {
      b.put("isReplication", true);
    }
    Call c = new Call("POST", "/api/v2/secret-imports", op + " " + s.path()).body(b);
    return Wire.secretImport(callJson(c).path("secretImport"));
  }

  /**
   * Asynchronous {@link #createSecretImport(CreateSecretImportOptions)}.
   *
   * @param options importing path and source
   * @return a future with the import
   */
  public CompletableFuture<SecretImport> createSecretImportAsync(
      CreateSecretImportOptions options) {
    return async(() -> createSecretImport(options));
  }

  /**
   * Deletes an import by id ({@code DELETE /api/v2/secret-imports/{id}}); an unknown id is {@link
   * NotFoundException}.
   *
   * @param importId import id
   * @param options importing path, may be null
   * @return the deleted import
   */
  public SecretImport deleteSecretImport(String importId, SecretImportOptions options) {
    String op = "secretImports.delete";
    requireArg(op, "importId", importId);
    SecretImportOptions o = or(options, SecretImportOptions.defaults());
    Scope s = scope(op, o.projectId(), o.environment(), o.path());
    Map<String, Object> b = new LinkedHashMap<>();
    b.put("projectId", s.projectId());
    b.put("environment", s.environment());
    b.put("path", s.path());
    Call c =
        new Call("DELETE", "/api/v2/secret-imports/" + seg(importId), op + " " + importId).body(b);
    return Wire.secretImport(callJson(c).path("secretImport"));
  }

  /**
   * Asynchronous {@link #deleteSecretImport(String, SecretImportOptions)}.
   *
   * @param importId import id
   * @param options importing path, may be null
   * @return a future with the deleted import
   */
  public CompletableFuture<SecretImport> deleteSecretImportAsync(
      String importId, SecretImportOptions options) {
    return async(() -> deleteSecretImport(importId, options));
  }

  // ----- secret versions (v1) -----

  /**
   * Lists the versions of a secret by id, newest first ({@code GET
   * /api/v1/secret/{secretId}/secret-versions}). Infisical serves this route to user JWTs only:
   * machine identities get {@code PermissionDeniedException}.
   *
   * @param secretId secret id ({@link SecretEntry#id()})
   * @param options paging, may be null (limit 20)
   * @return the versions
   */
  public List<SecretVersion> listSecretVersions(
      String secretId, ListSecretVersionsOptions options) {
    String op = "secretVersions.list";
    requireArg(op, "secretId", secretId);
    ListSecretVersionsOptions o = or(options, ListSecretVersionsOptions.defaults());
    int limit = o.limit() == 0 ? 20 : o.limit();
    if (o.offset() < 0 || limit < 1 || limit > 1000) {
      throw new ValidationException(op + ": limit must be 1-1000 and offset >= 0");
    }
    Call c =
        new Call("GET", "/api/v1/secret/" + seg(secretId) + "/secret-versions", op + " " + secretId)
            .query("offset", o.offset())
            .query("limit", limit);
    return Wire.list(callJson(c).get("secretVersions"), Wire::version);
  }

  /**
   * Asynchronous {@link #listSecretVersions(String, ListSecretVersionsOptions)}.
   *
   * @param secretId secret id
   * @param options paging, may be null
   * @return a future with the versions
   */
  public CompletableFuture<List<SecretVersion>> listSecretVersionsAsync(
      String secretId, ListSecretVersionsOptions options) {
    return async(() -> listSecretVersions(secretId, options));
  }

  // ----- env injection -----

  private Map<String, String> envSecrets(EnvOptions o) {
    SecretList list =
        listSecrets(
            ListSecretsOptions.builder()
                .projectId(o.projectId())
                .environment(o.environment())
                .secretPath(o.secretPath())
                .recursive(o.recursive())
                .includeImports(o.includeImports())
                .expandReferences(o.expandReferences())
                .build());
    Map<String, String> out = new TreeMap<>();
    list.merged().forEach((k, s) -> out.put(k, s.value().reveal()));
    return out;
  }

  /**
   * Sets one variable per secret of a path (like {@code infisical run}); the variable name is the
   * secret key unchanged. Java cannot change the process environment, so variables become <b>system
   * properties</b> unless {@link EnvOptions#target()} says otherwise. Existing variables (system
   * property or environment variable) are kept unless {@code override} is set.
   *
   * @param options selection, may be null
   * @return the names of the variables set, sorted (never values)
   */
  public List<String> loadEnv(EnvOptions options) {
    EnvOptions o = or(options, EnvOptions.defaults());
    List<String> set = new ArrayList<>();
    envSecrets(o)
        .forEach(
            (k, v) -> {
              if (o.target().exists(k) && !o.override()) {
                return;
              }
              o.target().set(k, v);
              set.add(k);
            });
    return set;
  }

  /**
   * Asynchronous {@link #loadEnv(EnvOptions)}.
   *
   * @param options selection, may be null
   * @return a future with the variable names
   */
  public CompletableFuture<List<String>> loadEnvAsync(EnvOptions options) {
    return async(() -> loadEnv(options));
  }

  /**
   * Renders the secrets of a path as a dotenv document (see {@link #formatDotenv}). The result
   * contains secret values: handle it like a secret.
   *
   * @param options selection, may be null
   * @return the dotenv document
   */
  public String exportDotenv(EnvOptions options) {
    return formatDotenv(envSecrets(or(options, EnvOptions.defaults())));
  }

  /**
   * Asynchronous {@link #exportDotenv(EnvOptions)}.
   *
   * @param options selection, may be null
   * @return a future with the document
   */
  public CompletableFuture<String> exportDotenvAsync(EnvOptions options) {
    return async(() -> exportDotenv(options));
  }

  /**
   * Renders key/value pairs as a dotenv document: one {@code KEY="value"} line per entry, sorted by
   * key, with backslash, double quote, newline and carriage return escaped.
   *
   * @param values key to value
   * @return the document
   */
  public static String formatDotenv(Map<String, String> values) {
    StringBuilder sb = new StringBuilder();
    new TreeMap<>(values)
        .forEach(
            (k, v) ->
                sb.append(k)
                    .append("=\"")
                    .append(
                        v.replace("\\", "\\\\")
                            .replace("\"", "\\\"")
                            .replace("\n", "\\n")
                            .replace("\r", "\\r"))
                    .append("\"\n"));
    return sb.toString();
  }

  /** Builder that configures and creates a client in one chain. */
  public static final class Builder {
    private final InfisicalConfig.Builder config = InfisicalConfig.builder();

    private Builder() {}

    /**
     * Fills unset fields from an environment reader.
     *
     * @param env reader, e.g. {@link EnvReader#system()}
     * @return this builder
     */
    public Builder fromEnv(EnvReader env) {
      config.fromEnv(env);
      return this;
    }

    /**
     * Sets the endpoint base URL.
     *
     * @param url URL
     * @return this builder
     */
    public Builder url(String url) {
      config.url(url);
      return this;
    }

    /**
     * Sets a static access token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(String token) {
      config.token(token);
      return this;
    }

    /**
     * Sets a static access token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(Secret token) {
      config.token(token);
      return this;
    }

    /**
     * Sets an explicit authentication method.
     *
     * @param auth authenticator
     * @return this builder
     */
    public Builder auth(Authenticator auth) {
      config.auth(auth);
      return this;
    }

    /**
     * Sets the Universal Auth client id.
     *
     * @param clientId client id
     * @return this builder
     */
    public Builder clientId(String clientId) {
      config.clientId(clientId);
      return this;
    }

    /**
     * Sets the Universal Auth client secret.
     *
     * @param clientSecret client secret
     * @return this builder
     */
    public Builder clientSecret(String clientSecret) {
      config.clientSecret(clientSecret);
      return this;
    }

    /**
     * Sets the default project id.
     *
     * @param projectId project id
     * @return this builder
     */
    public Builder projectId(String projectId) {
      config.projectId(projectId);
      return this;
    }

    /**
     * Sets the default environment slug.
     *
     * @param environment slug
     * @return this builder
     */
    public Builder environment(String environment) {
      config.environment(environment);
      return this;
    }

    /**
     * Sets the default secret path.
     *
     * @param secretPath path
     * @return this builder
     */
    public Builder secretPath(String secretPath) {
      config.secretPath(secretPath);
      return this;
    }

    /**
     * Forces the secrets API version ({@code v4} or {@code v3}).
     *
     * @param apiVersion version
     * @return this builder
     */
    public Builder apiVersion(String apiVersion) {
      config.apiVersion(apiVersion);
      return this;
    }

    /**
     * Revokes a token obtained by login on close.
     *
     * @param revokeOnClose flag
     * @return this builder
     */
    public Builder revokeOnClose(boolean revokeOnClose) {
      config.revokeOnClose(revokeOnClose);
      return this;
    }

    /**
     * Sets the connect timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      config.connectTimeout(d);
      return this;
    }

    /**
     * Sets the per-attempt timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      config.requestTimeout(d);
      return this;
    }

    /**
     * Sets the total timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      config.totalTimeout(d);
      return this;
    }

    /**
     * Sets the retry policy.
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      config.retry(retry);
      return this;
    }

    /**
     * Sets the TLS options.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      config.tls(tls);
      return this;
    }

    /**
     * Sets the proxy URL.
     *
     * @param proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      config.proxy(proxy);
      return this;
    }

    /**
     * Adds a header.
     *
     * @param name name
     * @param value value
     * @return this builder
     */
    public Builder header(String name, String value) {
      config.header(name, value);
      return this;
    }

    /**
     * Sets the user agent suffix.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      config.userAgentSuffix(suffix);
      return this;
    }

    /**
     * Sets hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      config.hooks(hooks);
      return this;
    }

    /**
     * Sets the logger.
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      config.logger(logger);
      return this;
    }

    /**
     * Builds the configuration and the client.
     *
     * @return a new client
     * @throws ConfigException when the configuration is invalid
     */
    public InfisicalClient build() {
      return create(config.build());
    }
  }
}
