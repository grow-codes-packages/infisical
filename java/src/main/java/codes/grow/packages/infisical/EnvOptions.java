package codes.grow.packages.infisical;

import codes.grow.packages.infisical.secrets.EnvLoader;

/**
 * Selects the secrets {@link InfisicalClient#loadEnv} and {@link InfisicalClient#exportDotenv} use.
 * Build it with {@link #builder()}; immutable.
 */
public final class EnvOptions {
  private static final EnvOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String secretPath;
  private final boolean recursive;
  private final boolean includeImports;
  private final boolean expandReferences;
  private final boolean override;
  private final EnvLoader.Target target;

  private EnvOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.secretPath = b.secretPath;
    this.recursive = b.recursive;
    this.includeImports = b.includeImports;
    this.expandReferences = b.expandReferences;
    this.override = b.override;
    this.target = b.target;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static EnvOptions defaults() {
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
   * Returns whether every sub-folder is included (shallower paths win on duplicate keys).
   *
   * @return the value
   */
  public boolean recursive() {
    return recursive;
  }

  /**
   * Returns whether secrets of secret imports are included (default true; direct secrets win).
   *
   * @return the value
   */
  public boolean includeImports() {
    return includeImports;
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
   * Returns whether variables that are already set are replaced (loadEnv only).
   *
   * @return the value
   */
  public boolean override() {
    return override;
  }

  /**
   * Returns where loadEnv writes variables (default: system properties, Java cannot change the
   * process environment).
   *
   * @return the value
   */
  public EnvLoader.Target target() {
    return target;
  }

  /** Builder of {@link EnvOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String secretPath = "";
    private boolean recursive = false;
    private boolean includeImports = true;
    private boolean expandReferences = true;
    private boolean override = false;
    private EnvLoader.Target target = EnvLoader.systemProperties();

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
     * Sets whether every sub-folder is included (shallower paths win on duplicate keys).
     *
     * @param recursive the value
     * @return this builder
     */
    public Builder recursive(boolean recursive) {
      this.recursive = recursive;
      return this;
    }

    /**
     * Sets whether secrets of secret imports are included (default true; direct secrets win).
     *
     * @param includeImports the value
     * @return this builder
     */
    public Builder includeImports(boolean includeImports) {
      this.includeImports = includeImports;
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
     * Sets whether variables that are already set are replaced (loadEnv only).
     *
     * @param override the value
     * @return this builder
     */
    public Builder override(boolean override) {
      this.override = override;
      return this;
    }

    /**
     * Sets where loadEnv writes variables (default: system properties, Java cannot change the
     * process environment).
     *
     * @param target the value
     * @return this builder
     */
    public Builder target(EnvLoader.Target target) {
      this.target = target;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public EnvOptions build() {
      return new EnvOptions(this);
    }
  }
}
