package codes.grow.packages.infisical;

import java.util.Optional;

/**
 * Selects the secret {@link InfisicalClient#getSecret} reads. Build it with {@link #builder()};
 * immutable.
 */
public final class GetSecretOptions {
  private static final GetSecretOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String secretPath;
  private final int version;
  private final SecretType type;
  private final boolean expandReferences;
  private final boolean includeImports;
  private final boolean viewSecretValue;

  private GetSecretOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.secretPath = b.secretPath;
    this.version = b.version;
    this.type = b.type;
    this.expandReferences = b.expandReferences;
    this.includeImports = b.includeImports;
    this.viewSecretValue = b.viewSecretValue;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static GetSecretOptions defaults() {
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
   * Returns an older version to read (0, the default, reads the current one).
   *
   * @return the value
   */
  public int version() {
    return version;
  }

  /**
   * Returns the secret type: shared (default) or the caller's personal override.
   *
   * @return the value, or empty when unset
   */
  public Optional<SecretType> type() {
    return Optional.ofNullable(type);
  }

  /**
   * Returns whether references are expanded (default true).
   *
   * @return the value
   */
  public boolean expandReferences() {
    return expandReferences;
  }

  /**
   * Returns whether the key is also found through secret imports (default true).
   *
   * @return the value
   */
  public boolean includeImports() {
    return includeImports;
  }

  /**
   * Returns whether the value is returned (default true); false returns metadata only.
   *
   * @return the value
   */
  public boolean viewSecretValue() {
    return viewSecretValue;
  }

  /** Builder of {@link GetSecretOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String secretPath = "";
    private int version = 0;
    private SecretType type = null;
    private boolean expandReferences = true;
    private boolean includeImports = true;
    private boolean viewSecretValue = true;

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
     * Sets an older version to read (0, the default, reads the current one).
     *
     * @param version the value
     * @return this builder
     */
    public Builder version(int version) {
      this.version = version;
      return this;
    }

    /**
     * Sets the secret type: shared (default) or the caller's personal override.
     *
     * @param type the value
     * @return this builder
     */
    public Builder type(SecretType type) {
      this.type = type;
      return this;
    }

    /**
     * Sets whether references are expanded (default true).
     *
     * @param expandReferences the value
     * @return this builder
     */
    public Builder expandReferences(boolean expandReferences) {
      this.expandReferences = expandReferences;
      return this;
    }

    /**
     * Sets whether the key is also found through secret imports (default true).
     *
     * @param includeImports the value
     * @return this builder
     */
    public Builder includeImports(boolean includeImports) {
      this.includeImports = includeImports;
      return this;
    }

    /**
     * Sets whether the value is returned (default true); false returns metadata only.
     *
     * @param viewSecretValue the value
     * @return this builder
     */
    public Builder viewSecretValue(boolean viewSecretValue) {
      this.viewSecretValue = viewSecretValue;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public GetSecretOptions build() {
      return new GetSecretOptions(this);
    }
  }
}
