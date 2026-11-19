package codes.grow.packages.infisical;

import java.util.Optional;

/**
 * Configures {@link InfisicalClient#updateSecrets}. Build it with {@link #builder()}; immutable.
 */
public final class UpdateSecretsOptions {
  private static final UpdateSecretsOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String secretPath;
  private final BatchUpdateMode mode;

  private UpdateSecretsOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.secretPath = b.secretPath;
    this.mode = b.mode;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static UpdateSecretsOptions defaults() {
    return DEFAULTS;
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
   * Returns the project id (default: the client's projectId).
   *
   * @return the value
   */
  public String projectId() {
    return projectId;
  }

  /**
   * Returns the environment slug (default: the client's environment).
   *
   * @return the value
   */
  public String environment() {
    return environment;
  }

  /**
   * Returns the secret path (default: the client's secretPath).
   *
   * @return the value
   */
  public String secretPath() {
    return secretPath;
  }

  /**
   * Returns how missing keys are treated (server default failOnNotFound).
   *
   * @return the value, or empty when unset
   */
  public Optional<BatchUpdateMode> mode() {
    return Optional.ofNullable(mode);
  }

  /** Builder of {@link UpdateSecretsOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String secretPath = "";
    private BatchUpdateMode mode = null;

    private Builder() {}

    /**
     * Sets the project id (default: the client's projectId).
     *
     * @param projectId the value
     * @return this builder
     */
    public Builder projectId(String projectId) {
      this.projectId = projectId == null ? "" : projectId;
      return this;
    }

    /**
     * Sets the environment slug (default: the client's environment).
     *
     * @param environment the value
     * @return this builder
     */
    public Builder environment(String environment) {
      this.environment = environment == null ? "" : environment;
      return this;
    }

    /**
     * Sets the secret path (default: the client's secretPath).
     *
     * @param secretPath the value
     * @return this builder
     */
    public Builder secretPath(String secretPath) {
      this.secretPath = secretPath == null ? "" : secretPath;
      return this;
    }

    /**
     * Sets how missing keys are treated (server default failOnNotFound).
     *
     * @param mode the value
     * @return this builder
     */
    public Builder mode(BatchUpdateMode mode) {
      this.mode = mode;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public UpdateSecretsOptions build() {
      return new UpdateSecretsOptions(this);
    }
  }
}
