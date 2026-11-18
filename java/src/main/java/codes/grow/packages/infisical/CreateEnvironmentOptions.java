package codes.grow.packages.infisical;

/**
 * Configures {@link InfisicalClient#createEnvironment}. Build it with {@link #builder()};
 * immutable.
 */
public final class CreateEnvironmentOptions {
  private static final CreateEnvironmentOptions DEFAULTS = builder().build();

  private final String projectId;
  private final int position;

  private CreateEnvironmentOptions(Builder b) {
    this.projectId = b.projectId;
    this.position = b.position;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static CreateEnvironmentOptions defaults() {
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
   * Returns the position of the environment (0 appends it last).
   *
   * @return the value
   */
  public int position() {
    return position;
  }

  /** Builder of {@link CreateEnvironmentOptions}. */
  public static final class Builder {
    private String projectId = "";
    private int position = 0;

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
     * Sets the position of the environment (0 appends it last).
     *
     * @param position the value
     * @return this builder
     */
    public Builder position(int position) {
      this.position = position;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public CreateEnvironmentOptions build() {
      return new CreateEnvironmentOptions(this);
    }
  }
}
