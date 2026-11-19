package codes.grow.packages.infisical;

import java.util.Optional;

/** Configures {@link InfisicalClient#updateFolder}. Build it with {@link #builder()}; immutable. */
public final class UpdateFolderOptions {
  private static final UpdateFolderOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String path;
  private final String name;
  private final String description;

  private UpdateFolderOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.path = b.path;
    this.name = b.name;
    this.description = b.description;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static UpdateFolderOptions defaults() {
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
   * Returns the (new) folder name; required by the server.
   *
   * @return the value
   */
  public String name() {
    return name;
  }

  /**
   * Returns the new description.
   *
   * @return the value, or empty when unset
   */
  public Optional<String> description() {
    return Optional.ofNullable(description);
  }

  /** Builder of {@link UpdateFolderOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String path = "";
    private String name = "";
    private String description = null;

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
     * Sets the (new) folder name; required by the server.
     *
     * @param name the value
     * @return this builder
     */
    public Builder name(String name) {
      this.name = name == null ? "" : name;
      return this;
    }

    /**
     * Sets the new description.
     *
     * @param description the value
     * @return this builder
     */
    public Builder description(String description) {
      this.description = description;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public UpdateFolderOptions build() {
      return new UpdateFolderOptions(this);
    }
  }
}
