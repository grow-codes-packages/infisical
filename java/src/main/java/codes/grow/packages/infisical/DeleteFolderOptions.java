package codes.grow.packages.infisical;

/** Configures {@link InfisicalClient#deleteFolder}. Build it with {@link #builder()}; immutable. */
public final class DeleteFolderOptions {
  private static final DeleteFolderOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String path;
  private final boolean force;

  private DeleteFolderOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.path = b.path;
    this.force = b.force;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static DeleteFolderOptions defaults() {
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
   * Returns the parent path (default: the client's secretPath).
   *
   * @return the value
   */
  public String path() {
    return path;
  }

  /**
   * Returns whether a folder that still holds secrets or folders is deleted.
   *
   * @return the value
   */
  public boolean force() {
    return force;
  }

  /** Builder of {@link DeleteFolderOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String path = "";
    private boolean force = false;

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
     * Sets the parent path (default: the client's secretPath).
     *
     * @param path the value
     * @return this builder
     */
    public Builder path(String path) {
      this.path = path == null ? "" : path;
      return this;
    }

    /**
     * Sets whether a folder that still holds secrets or folders is deleted.
     *
     * @param force the value
     * @return this builder
     */
    public Builder force(boolean force) {
      this.force = force;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public DeleteFolderOptions build() {
      return new DeleteFolderOptions(this);
    }
  }
}
