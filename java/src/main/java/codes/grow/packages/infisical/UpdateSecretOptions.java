package codes.grow.packages.infisical;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Configures {@link InfisicalClient#updateSecret}; unset fields stay unchanged. Build it with
 * {@link #builder()}; immutable.
 */
public final class UpdateSecretOptions {
  private static final UpdateSecretOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String secretPath;
  private final String value;
  private final String newName;
  private final String comment;
  private final List<String> tagIds;
  private final List<String> tagSlugs;
  private final SecretType type;
  private final Boolean skipMultilineEncoding;
  private final Map<String, String> metadata;

  private UpdateSecretOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.secretPath = b.secretPath;
    this.value = b.value;
    this.newName = b.newName;
    this.comment = b.comment;
    this.tagIds = b.tagIds == null ? null : List.copyOf(b.tagIds);
    this.tagSlugs = b.tagSlugs == null ? null : List.copyOf(b.tagSlugs);
    this.type = b.type;
    this.skipMultilineEncoding = b.skipMultilineEncoding;
    this.metadata = b.metadata == null ? null : Map.copyOf(b.metadata);
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static UpdateSecretOptions defaults() {
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
   * Returns the new value.
   *
   * @return the value, or empty when unset
   */
  public Optional<String> value() {
    return Optional.ofNullable(value);
  }

  /**
   * Returns the new secret name (rename).
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
   * Returns the new tag set by slug (merged with tagIds).
   *
   * @return the value, or empty when unset
   */
  public Optional<List<String>> tagSlugs() {
    return Optional.ofNullable(tagSlugs);
  }

  /**
   * Returns the secret type: shared (default) or the caller's personal override.
   *
   * @return the value, or empty when unset
   */
  public Optional<SecretType> type() {
    return Optional.ofNullable(type);
  }

  /**
   * Returns the new multi-line encoding flag.
   *
   * @return the value, or empty when unset
   */
  public Optional<Boolean> skipMultilineEncoding() {
    return Optional.ofNullable(skipMultilineEncoding);
  }

  /**
   * Returns the new secret metadata (replaces the old one).
   *
   * @return the value, or empty when unset
   */
  public Optional<Map<String, String>> metadata() {
    return Optional.ofNullable(metadata);
  }

  /** Builder of {@link UpdateSecretOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String secretPath = "";
    private String value = null;
    private String newName = "";
    private String comment = null;
    private List<String> tagIds = null;
    private List<String> tagSlugs = null;
    private SecretType type = null;
    private Boolean skipMultilineEncoding = null;
    private Map<String, String> metadata = null;

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
     * Sets the new secret name (rename).
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
     * Sets the new tag set by slug (merged with tagIds).
     *
     * @param tagSlugs the value
     * @return this builder
     */
    public Builder tagSlugs(List<String> tagSlugs) {
      this.tagSlugs = tagSlugs;
      return this;
    }

    /**
     * Sets the secret type: shared (default) or the caller's personal override.
     *
     * @param type the value
     * @return this builder
     */
    public Builder type(SecretType type) {
      this.type = type;
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
     * Sets the new secret metadata (replaces the old one).
     *
     * @param metadata the value
     * @return this builder
     */
    public Builder metadata(Map<String, String> metadata) {
      this.metadata = metadata == null ? null : new LinkedHashMap<>(metadata);
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public UpdateSecretOptions build() {
      return new UpdateSecretOptions(this);
    }
  }
}
