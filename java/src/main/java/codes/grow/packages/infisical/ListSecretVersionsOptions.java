package codes.grow.packages.infisical;

/**
 * Pages through {@link InfisicalClient#listSecretVersions}. Build it with {@link #builder()};
 * immutable.
 */
public final class ListSecretVersionsOptions {
  private static final ListSecretVersionsOptions DEFAULTS = builder().build();

  private final int offset;
  private final int limit;

  private ListSecretVersionsOptions(Builder b) {
    this.offset = b.offset;
    this.limit = b.limit;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static ListSecretVersionsOptions defaults() {
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
   * Returns the number of versions to skip (newest first).
   *
   * @return the value
   */
  public int offset() {
    return offset;
  }

  /**
   * Returns the page size, 1 to 1000 (default 20).
   *
   * @return the value
   */
  public int limit() {
    return limit;
  }

  /** Builder of {@link ListSecretVersionsOptions}. */
  public static final class Builder {
    private int offset = 0;
    private int limit = 20;

    private Builder() {}

    /**
     * Sets the number of versions to skip (newest first).
     *
     * @param offset the value
     * @return this builder
     */
    public Builder offset(int offset) {
      this.offset = offset;
      return this;
    }

    /**
     * Sets the page size, 1 to 1000 (default 20).
     *
     * @param limit the value
     * @return this builder
     */
    public Builder limit(int limit) {
      this.limit = limit;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public ListSecretVersionsOptions build() {
      return new ListSecretVersionsOptions(this);
    }
  }
}
