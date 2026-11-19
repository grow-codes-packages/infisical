package codes.grow.packages.infisical;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * One secret of {@link InfisicalClient#createSecrets}. Build it with {@link #builder()}; immutable.
 */
public final class SecretInput {
  private static final SecretInput DEFAULTS = builder().build();

  private final String key;
  private final String value;
  private final String comment;
  private final List<String> tagIds;
  private final boolean skipMultilineEncoding;
  private final Map<String, String> metadata;

  private SecretInput(Builder b) {
    this.key = b.key;
    this.value = b.value;
    this.comment = b.comment;
    this.tagIds = b.tagIds == null ? null : List.copyOf(b.tagIds);
    this.skipMultilineEncoding = b.skipMultilineEncoding;
    this.metadata = Map.copyOf(b.metadata);
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static SecretInput defaults() {
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
   * Creates an input with a key and a value.
   *
   * @param key the secret name
   * @param value the value
   * @return the input
   */
  public static SecretInput of(String key, String value) {
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
   * Returns the value.
   *
   * @return the value
   */
  public String value() {
    return value;
  }

  /**
   * Returns the comment.
   *
   * @return the value
   */
  public String comment() {
    return comment;
  }

  /**
   * Returns the tags to attach, by id.
   *
   * @return the value, or empty when unset
   */
  public Optional<List<String>> tagIds() {
    return Optional.ofNullable(tagIds);
  }

  /**
   * Returns whether multi-line values are stored without encoding.
   *
   * @return the value
   */
  public boolean skipMultilineEncoding() {
    return skipMultilineEncoding;
  }

  /**
   * Returns the secret metadata.
   *
   * @return the value
   */
  public Map<String, String> metadata() {
    return metadata;
  }

  /** Builder of {@link SecretInput}. */
  public static final class Builder {
    private String key = "";
    private String value = "";
    private String comment = "";
    private List<String> tagIds = null;
    private boolean skipMultilineEncoding = false;
    private Map<String, String> metadata = Map.of();

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
     * Sets the value.
     *
     * @param value the value
     * @return this builder
     */
    public Builder value(String value) {
      this.value = value == null ? "" : value;
      return this;
    }

    /**
     * Sets the comment.
     *
     * @param comment the value
     * @return this builder
     */
    public Builder comment(String comment) {
      this.comment = comment == null ? "" : comment;
      return this;
    }

    /**
     * Sets the tags to attach, by id.
     *
     * @param tagIds the value
     * @return this builder
     */
    public Builder tagIds(List<String> tagIds) {
      this.tagIds = tagIds;
      return this;
    }

    /**
     * Sets whether multi-line values are stored without encoding.
     *
     * @param skipMultilineEncoding the value
     * @return this builder
     */
    public Builder skipMultilineEncoding(boolean skipMultilineEncoding) {
      this.skipMultilineEncoding = skipMultilineEncoding;
      return this;
    }

    /**
     * Sets the secret metadata.
     *
     * @param metadata the value
     * @return this builder
     */
    public Builder metadata(Map<String, String> metadata) {
      this.metadata = metadata == null ? Map.of() : new LinkedHashMap<>(metadata);
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public SecretInput build() {
      return new SecretInput(this);
    }
  }
}
