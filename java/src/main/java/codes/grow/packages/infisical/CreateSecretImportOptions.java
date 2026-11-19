package codes.grow.packages.infisical;

/**
 * Configures {@link InfisicalClient#createSecretImport}. Build it with {@link #builder()};
 * immutable.
 */
public final class CreateSecretImportOptions {
  private static final CreateSecretImportOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String path;
  private final String importEnvironment;
  private final String importPath;
  private final String sourceProjectId;
  private final boolean isReplication;

  private CreateSecretImportOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.path = b.path;
    this.importEnvironment = b.importEnvironment;
    this.importPath = b.importPath;
    this.sourceProjectId = b.sourceProjectId;
    this.isReplication = b.isReplication;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static CreateSecretImportOptions defaults() {
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
   * Returns the importing path (default: the client's secretPath).
   *
   * @return the value
   */
  public String path() {
    return path;
  }

  /**
   * Returns the source environment slug (required).
   *
   * @return the value
   */
  public String importEnvironment() {
    return importEnvironment;
  }

  /**
   * Returns the source path (default {@code /}).
   *
   * @return the value
   */
  public String importPath() {
    return importPath;
  }

  /**
   * Returns the source project when importing from another project.
   *
   * @return the value
   */
  public String sourceProjectId() {
    return sourceProjectId;
  }

  /**
   * Returns whether the secrets are copied instead of referenced.
   *
   * @return the value
   */
  public boolean isReplication() {
    return isReplication;
  }

  /** Builder of {@link CreateSecretImportOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String path = "";
    private String importEnvironment = "";
    private String importPath = "";
    private String sourceProjectId = "";
    private boolean isReplication = false;

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
     * Sets the importing path (default: the client's secretPath).
     *
     * @param path the value
     * @return this builder
     */
    public Builder path(String path) {
      this.path = path == null ? "" : path;
      return this;
    }

    /**
     * Sets the source environment slug (required).
     *
     * @param importEnvironment the value
     * @return this builder
     */
    public Builder importEnvironment(String importEnvironment) {
      this.importEnvironment = importEnvironment == null ? "" : importEnvironment;
      return this;
    }

    /**
     * Sets the source path (default {@code /}).
     *
     * @param importPath the value
     * @return this builder
     */
    public Builder importPath(String importPath) {
      this.importPath = importPath == null ? "" : importPath;
      return this;
    }

    /**
     * Sets the source project when importing from another project.
     *
     * @param sourceProjectId the value
     * @return this builder
     */
    public Builder sourceProjectId(String sourceProjectId) {
      this.sourceProjectId = sourceProjectId == null ? "" : sourceProjectId;
      return this;
    }

    /**
     * Sets whether the secrets are copied instead of referenced.
     *
     * @param isReplication the value
     * @return this builder
     */
    public Builder isReplication(boolean isReplication) {
      this.isReplication = isReplication;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public CreateSecretImportOptions build() {
      return new CreateSecretImportOptions(this);
    }
  }
}
