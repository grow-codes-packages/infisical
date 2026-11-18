package codes.grow.packages.infisical;

/**
 * Configures a {@link ProjectSecretsProvider}; unset fields fall back to the client configuration.
 * Build it with {@link #builder()}; immutable.
 */
public final class SecretsProviderOptions {
  private static final SecretsProviderOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String basePath;
  private final boolean expandReferences;
  private final boolean includeImports;

  private SecretsProviderOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.basePath = b.basePath;
    this.expandReferences = b.expandReferences;
    this.includeImports = b.includeImports;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static SecretsProviderOptions defaults() {
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
   * Returns the folder secret names are relative to (default: the client's secretPath).
   *
   * @return the value
   */
  public String basePath() {
    return basePath;
  }

  /**
   * Returns whether references are expanded on reads (default true).
   *
   * @return the value
   */
  public boolean expandReferences() {
    return expandReferences;
  }

  /**
   * Returns whether keys are found through secret imports on get and getAll (default true).
   *
   * @return the value
   */
  public boolean includeImports() {
    return includeImports;
  }

  /** Builder of {@link SecretsProviderOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String basePath = "";
    private boolean expandReferences = true;
    private boolean includeImports = true;

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
     * Sets the folder secret names are relative to (default: the client's secretPath).
     *
     * @param basePath the value
     * @return this builder
     */
    public Builder basePath(String basePath) {
      this.basePath = basePath == null ? "" : basePath;
      return this;
    }

    /**
     * Sets whether references are expanded on reads (default true).
     *
     * @param expandReferences the value
     * @return this builder
     */
    public Builder expandReferences(boolean expandReferences) {
      this.expandReferences = expandReferences;
      return this;
    }

    /**
     * Sets whether keys are found through secret imports on get and getAll (default true).
     *
     * @param includeImports the value
     * @return this builder
     */
    public Builder includeImports(boolean includeImports) {
      this.includeImports = includeImports;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public SecretsProviderOptions build() {
      return new SecretsProviderOptions(this);
    }
  }
}
