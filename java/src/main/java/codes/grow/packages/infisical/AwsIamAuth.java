package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.Json;
import codes.grow.packages.infisical.core.Redaction;
import codes.grow.packages.infisical.core.Secret;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Logs a machine identity in with AWS IAM credentials ({@code POST /api/v1/auth/aws-auth/login}).
 * The client signs an STS {@code GetCallerIdentity} request with AWS Signature Version 4 and sends
 * it to Infisical, which forwards it to AWS STS to verify the caller. Credentials left unset are
 * read from {@code AWS_ACCESS_KEY_ID}, {@code AWS_SECRET_ACCESS_KEY}, {@code AWS_SESSION_TOKEN} and
 * {@code AWS_REGION} / {@code AWS_DEFAULT_REGION} (region default {@code us-east-1}).
 */
public final class AwsIamAuth implements Authenticator {
  static final String STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15";
  static final String STS_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8";
  private static final String OP = "auth.awsIamAuth.login";

  private final String identityId;
  private final String region;
  private final String accessKeyId;
  private final Secret secretAccessKey;
  private final Secret sessionToken;
  private final String organizationSlug;
  private final Map<String, String> env;
  private final Clock clock;

  private AwsIamAuth(Builder b) {
    this.identityId = b.identityId;
    this.region = b.region;
    this.accessKeyId = b.accessKeyId;
    this.secretAccessKey = b.secretAccessKey;
    this.sessionToken = b.sessionToken;
    this.organizationSlug = b.organizationSlug;
    this.env = b.env;
    this.clock = b.clock;
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

  private String envVar(String... names) {
    for (String n : names) {
      String v = env.get(n);
      if (v != null && !v.isEmpty()) {
        return v;
      }
    }
    return "";
  }

  /** Resolved credentials: region, key id, secret, session token ({@code ""} when unset). */
  private String[] credentials() {
    String r =
        region == null || region.isEmpty() ? envVar("AWS_REGION", "AWS_DEFAULT_REGION") : region;
    if (r.isEmpty()) {
      r = "us-east-1";
    }
    boolean explicitKey = accessKeyId != null && !accessKeyId.isEmpty();
    String key = explicitKey ? accessKeyId : envVar("AWS_ACCESS_KEY_ID");
    String secret =
        secretAccessKey != null && !secretAccessKey.isEmpty()
            ? secretAccessKey.reveal()
            : envVar("AWS_SECRET_ACCESS_KEY");
    String session = sessionToken != null ? sessionToken.reveal() : "";
    if (session.isEmpty() && sessionToken == null && !explicitKey) {
      session = envVar("AWS_SESSION_TOKEN");
    }
    return new String[] {r, key, secret, session};
  }

  /**
   * Builds the signed login body without a network call.
   *
   * @return the login body
   * @throws ConfigException when the identity id or the AWS credentials are missing
   */
  public AwsLoginRequest loginRequest() {
    if (identityId == null || identityId.isEmpty()) {
      throw new ConfigException(OP + ": identityId is required");
    }
    String[] c = credentials();
    if (c[1].isEmpty() || c[2].isEmpty()) {
      throw new ConfigException(
          OP
              + ": AWS credentials are required (accessKeyId/secretAccessKey or"
              + " AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)");
    }
    String host = "sts." + c[0] + ".amazonaws.com";
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("Host", host);
    headers.put("Content-Type", STS_CONTENT_TYPE);
    if (!c[3].isEmpty()) {
      headers.put("X-Amz-Security-Token", c[3]);
    }
    Map<String, String> signed =
        SigV4.sign(
            new SigV4.Request(
                "POST",
                host,
                "/",
                "",
                headers,
                STS_BODY.getBytes(StandardCharsets.UTF_8),
                c[0],
                "sts",
                c[1],
                c[2],
                clock.instant()));
    signed.put("Content-Length", Integer.toString(STS_BODY.length()));
    Base64.Encoder b64 = Base64.getEncoder();
    return new AwsLoginRequest(
        identityId,
        "POST",
        b64.encodeToString(STS_BODY.getBytes(StandardCharsets.UTF_8)),
        b64.encodeToString(Json.encode(signed)),
        organizationSlug == null ? "" : organizationSlug);
  }

  @Override
  public AccessToken login(InfisicalClient client) {
    AwsLoginRequest req = loginRequest();
    String[] c = credentials();
    client.rememberSecret(c[1], c[2], c[3]);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("identityId", req.identityId());
    body.put("iamHttpRequestMethod", req.iamHttpRequestMethod());
    body.put("iamRequestBody", req.iamRequestBody());
    body.put("iamRequestHeaders", req.iamRequestHeaders());
    if (!req.organizationSlug().isEmpty()) {
      body.put("organizationSlug", req.organizationSlug());
    }
    return client.tokenCall(OP, "/api/v1/auth/aws-auth/login", body);
  }

  @Override
  public String toString() {
    return "AwsIamAuth{identityId="
        + identityId
        + ", region="
        + region
        + ", secretAccessKey="
        + Redaction.REDACTED
        + "}";
  }

  /** Builder of {@link AwsIamAuth}. */
  public static final class Builder {
    private String identityId;
    private String region;
    private String accessKeyId;
    private Secret secretAccessKey;
    private Secret sessionToken;
    private String organizationSlug;
    private Map<String, String> env = System.getenv();
    private Clock clock = Clock.systemUTC();

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
     * Sets the STS region (default {@code AWS_REGION}, {@code AWS_DEFAULT_REGION}, then {@code
     * us-east-1}).
     *
     * @param region region
     * @return this builder
     */
    public Builder region(String region) {
      this.region = region;
      return this;
    }

    /**
     * Sets the AWS access key id.
     *
     * @param accessKeyId key id
     * @return this builder
     */
    public Builder accessKeyId(String accessKeyId) {
      this.accessKeyId = accessKeyId;
      return this;
    }

    /**
     * Sets the AWS secret access key.
     *
     * @param secretAccessKey secret key
     * @return this builder
     */
    public Builder secretAccessKey(Secret secretAccessKey) {
      this.secretAccessKey = secretAccessKey;
      return this;
    }

    /**
     * Sets the AWS session token of temporary credentials.
     *
     * @param sessionToken session token
     * @return this builder
     */
    public Builder sessionToken(Secret sessionToken) {
      this.sessionToken = sessionToken;
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
     * Replaces the environment the {@code AWS_*} variables are read from (tests).
     *
     * @param env variable map
     * @return this builder
     */
    public Builder env(Map<String, String> env) {
      this.env = Map.copyOf(env);
      return this;
    }

    /**
     * Sets the clock of the signing time (tests).
     *
     * @param clock clock
     * @return this builder
     */
    public Builder clock(Clock clock) {
      this.clock = clock;
      return this;
    }

    /**
     * Builds the method.
     *
     * @return the method
     */
    public AwsIamAuth build() {
      return new AwsIamAuth(this);
    }
  }
}
