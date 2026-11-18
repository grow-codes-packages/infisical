package codes.grow.packages.infisical;

import java.util.Optional;

/**
 * Configures {@link InfisicalClient#deleteSecrets}. Build it with {@link #builder()}; immutable.
 */
public final class DeleteSecretsOptions {
  private static final DeleteSecretsOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String secretPath;
  private final SecretType type;

  private DeleteSecretsOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.secretPath = b.secretPath;
    this.type = b.type;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static DeleteSecretsOptions defaults() {
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
   * Returns the secret type: shared (default) or personal overrides.
   *
   * @return the value, or empty when unset
   */
  public Optional<SecretType> type() {
    return Optional.ofNullable(type);
  }

  /** Builder of {@link DeleteSecretsOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String secretPath = "";
    private SecretType type = null;

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
     * Sets the secret type: shared (default) or personal overrides.
     *
     * @param type the value
     * @return this builder
     */
    public Builder type(SecretType type) {
      this.type = type;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public DeleteSecretsOptions build() {
      return new DeleteSecretsOptions(this);
    }
  }
}
