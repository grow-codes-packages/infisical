package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.Redaction;
import codes.grow.packages.infisical.core.Secret;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Logs a machine identity in with a Kubernetes service account token ({@code POST
 * /api/v1/auth/kubernetes-auth/login}). The server validates the token through the Kubernetes
 * TokenReview API.
 */
public final class KubernetesAuth implements Authenticator {
  /** Where the service account token is read from when no JWT is given. */
  public static final String DEFAULT_TOKEN_PATH =
      "/var/run/secrets/kubernetes.io/serviceaccount/token";

  private final String identityId;
  private final Secret jwt;
  private final String tokenPath;
  private final String organizationSlug;

  private KubernetesAuth(Builder b) {
    this.identityId = b.identityId;
    this.jwt = b.jwt;
    this.tokenPath = b.tokenPath;
    this.organizationSlug = b.organizationSlug;
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the machine identity id.
   *
   * @return the id
   */
  public String identityId() {
    return identityId;
  }

  @Override
  public AccessToken login(InfisicalClient client) {
    String op = "auth.kubernetesAuth.login";
    if (identityId == null || identityId.isEmpty()) {
      throw new ConfigException(op + ": identityId is required");
    }
    String token = jwt == null ? "" : jwt.reveal();
    if (token.isEmpty()) {
      try {
        token = Files.readString(Path.of(tokenPath), StandardCharsets.UTF_8).trim();
      } catch (IOException | RuntimeException e) {
        throw new ConfigException(op + ": the service account token file cannot be read");
      }
    }
    client.rememberSecret(token);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("identityId", identityId);
    body.put("jwt", token);
    if (organizationSlug != null && !organizationSlug.isEmpty()) {
      body.put("organizationSlug", organizationSlug);
    }
    return client.tokenCall(op, "/api/v1/auth/kubernetes-auth/login", body);
  }

  @Override
  public String toString() {
    return "KubernetesAuth{identityId=" + identityId + ", jwt=" + Redaction.REDACTED + "}";
  }

  /** Builder of {@link KubernetesAuth}. */
  public static final class Builder {
    private String identityId;
    private Secret jwt;
    private String tokenPath = DEFAULT_TOKEN_PATH;
    private String organizationSlug;

    private Builder() {}

    /**
     * Sets the machine identity id (required).
     *
     * @param identityId id
     * @return this builder
     */
    public Builder identityId(String identityId) {
      this.identityId = identityId;
      return this;
    }

    /**
     * Sets the service account token; when unset the token file is read.
     *
     * @param jwt token
     * @return this builder
     */
    public Builder jwt(Secret jwt) {
      this.jwt = jwt;
      return this;
    }

    /**
     * Sets the service account token file (default {@link KubernetesAuth#DEFAULT_TOKEN_PATH}).
     *
     * @param tokenPath file path
     * @return this builder
     */
    public Builder tokenPath(String tokenPath) {
      this.tokenPath = tokenPath == null ? DEFAULT_TOKEN_PATH : tokenPath;
      return this;
    }

    /**
     * Sets the sub-organization slug.
     *
     * @param organizationSlug slug
     * @return this builder
     */
    public Builder organizationSlug(String organizationSlug) {
      this.organizationSlug = organizationSlug;
      return this;
    }

    /**
     * Builds the method.
     *
     * @return the method
     */
    public KubernetesAuth build() {
      return new KubernetesAuth(this);
    }
  }
}
