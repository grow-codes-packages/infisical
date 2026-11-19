package codes.grow.packages.infisical;

/** Configures {@link InfisicalClient#listProjects}. Build it with {@link #builder()}; immutable. */
public final class ListProjectsOptions {
  private static final ListProjectsOptions DEFAULTS = builder().build();

  private final String type;
  private final int limit;
  private final int offset;

  private ListProjectsOptions(Builder b) {
    this.type = b.type;
    this.limit = b.limit;
    this.offset = b.offset;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static ListProjectsOptions defaults() {
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
   * Returns the product type filter (default {@code secret-manager}).
   *
   * @return the value
   */
  public String type() {
    return type;
  }

  /**
   * Returns the page size, 1 to 100 (0 uses the server default).
   *
   * @return the value
   */
  public int limit() {
    return limit;
  }

  /**
   * Returns the number of projects to skip.
   *
   * @return the value
   */
  public int offset() {
    return offset;
  }

  /** Builder of {@link ListProjectsOptions}. */
  public static final class Builder {
    private String type = "";
    private int limit = 0;
    private int offset = 0;

    private Builder() {}

    /**
     * Sets the product type filter (default {@code secret-manager}).
     *
     * @param type the value
     * @return this builder
     */
    public Builder type(String type) {
      this.type = type == null ? "" : type;
      return this;
    }

    /**
     * Sets the page size, 1 to 100 (0 uses the server default).
     *
     * @param limit the value
     * @return this builder
     */
    public Builder limit(int limit) {
      this.limit = limit;
      return this;
    }

    /**
     * Sets the number of projects to skip.
     *
     * @param offset the value
     * @return this builder
     */
    public Builder offset(int offset) {
      this.offset = offset;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public ListProjectsOptions build() {
      return new ListProjectsOptions(this);
    }
  }
}
