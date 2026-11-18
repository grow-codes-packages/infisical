package codes.grow.packages.infisical;

import java.util.List;
import java.util.Optional;

/**
 * One secret of {@link InfisicalClient#updateSecrets}; unset fields stay unchanged. Build it with
 * {@link #builder()}; immutable.
 */
public final class SecretUpdate {
  private static final SecretUpdate DEFAULTS = builder().build();

  private final String key;
  private final String value;
  private final String newName;
  private final String comment;
  private final List<String> tagIds;
  private final Boolean skipMultilineEncoding;

  private SecretUpdate(Builder b) {
    this.key = b.key;
    this.value = b.value;
    this.newName = b.newName;
    this.comment = b.comment;
    this.tagIds = b.tagIds == null ? null : List.copyOf(b.tagIds);
    this.skipMultilineEncoding = b.skipMultilineEncoding;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static SecretUpdate defaults() {
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
   * Creates an update that sets a new value.
   *
   * @param key the secret name
   * @param value the new value
   * @return the update
   */
  public static SecretUpdate of(String key, String value) {
    return builder().key(key).value(value).build();
  }

  /**
   * Returns the secret name (required).
   *
   * @return the value
   */
  public String key() {
    return key;
  }

  /**
   * Returns the new value.
   *
   * @return the value, or empty when unset
   */
  public Optional<String> value() {
    return Optional.ofNullable(value);
  }

  /**
   * Returns the new name (rename).
   *
   * @return the value
   */
  public String newName() {
    return newName;
  }

  /**
   * Returns the new comment.
   *
   * @return the value, or empty when unset
   */
  public Optional<String> comment() {
    return Optional.ofNullable(comment);
  }

  /**
   * Returns the new tag set by id (an empty list removes every tag).
   *
   * @return the value, or empty when unset
   */
  public Optional<List<String>> tagIds() {
    return Optional.ofNullable(tagIds);
  }

  /**
   * Returns the new multi-line encoding flag.
   *
   * @return the value, or empty when unset
   */
  public Optional<Boolean> skipMultilineEncoding() {
    return Optional.ofNullable(skipMultilineEncoding);
  }

  /** Builder of {@link SecretUpdate}. */
  public static final class Builder {
    private String key = "";
    private String value = null;
    private String newName = "";
    private String comment = null;
    private List<String> tagIds = null;
    private Boolean skipMultilineEncoding = null;

    private Builder() {}

    /**
     * Sets the secret name (required).
     *
     * @param key the value
     * @return this builder
     */
    public Builder key(String key) {
      this.key = key == null ? "" : key;
      return this;
    }

    /**
     * Sets the new value.
     *
     * @param value the value
     * @return this builder
     */
    public Builder value(String value) {
      this.value = value;
      return this;
    }

    /**
     * Sets the new name (rename).
     *
     * @param newName the value
     * @return this builder
     */
    public Builder newName(String newName) {
      this.newName = newName == null ? "" : newName;
      return this;
    }

    /**
     * Sets the new comment.
     *
     * @param comment the value
     * @return this builder
     */
    public Builder comment(String comment) {
      this.comment = comment;
      return this;
    }

    /**
     * Sets the new tag set by id (an empty list removes every tag).
     *
     * @param tagIds the value
     * @return this builder
     */
    public Builder tagIds(List<String> tagIds) {
      this.tagIds = tagIds;
      return this;
    }

    /**
     * Sets the new multi-line encoding flag.
     *
     * @param skipMultilineEncoding the value
     * @return this builder
     */
    public Builder skipMultilineEncoding(Boolean skipMultilineEncoding) {
      this.skipMultilineEncoding = skipMultilineEncoding;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public SecretUpdate build() {
      return new SecretUpdate(this);
    }
  }
}
