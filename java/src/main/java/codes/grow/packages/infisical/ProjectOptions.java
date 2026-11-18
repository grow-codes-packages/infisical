package codes.grow.packages.infisical;

/** Selects the project of a project-scoped call. Build it with {@link #builder()}; immutable. */
public final class ProjectOptions {
  private static final ProjectOptions DEFAULTS = builder().build();

  private final String projectId;

  private ProjectOptions(Builder b) {
    this.projectId = b.projectId;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static ProjectOptions defaults() {
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

  /** Builder of {@link ProjectOptions}. */
  public static final class Builder {
    private String projectId = "";

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
     * Builds the options.
     *
     * @return the options
     */
    public ProjectOptions build() {
      return new ProjectOptions(this);
    }
  }
}
