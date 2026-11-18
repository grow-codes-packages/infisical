package codes.grow.packages.infisical;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Configures {@link InfisicalClient#createSecret}. Build it with {@link #builder()}; immutable. */
public final class CreateSecretOptions {
  private static final CreateSecretOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String secretPath;
  private final String comment;
  private final List<String> tagIds;
  private final List<String> tagSlugs;
  private final SecretType type;
  private final boolean skipMultilineEncoding;
  private final Map<String, String> metadata;

  private CreateSecretOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.secretPath = b.secretPath;
    this.comment = b.comment;
    this.tagIds = List.copyOf(b.tagIds);
    this.tagSlugs = List.copyOf(b.tagSlugs);
    this.type = b.type;
    this.skipMultilineEncoding = b.skipMultilineEncoding;
    this.metadata = Map.copyOf(b.metadata);
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static CreateSecretOptions defaults() {
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
   * Returns the secret comment.
   *
   * @return the value
   */
  public String comment() {
    return comment;
  }

  /**
   * Returns the tags to attach, by id.
   *
   * @return the value
   */
  public List<String> tagIds() {
    return tagIds;
  }

  /**
   * Returns the tags to attach, by slug (resolved with listTags; an unknown slug is NOT_FOUND).
   *
   * @return the value
   */
  public List<String> tagSlugs() {
    return tagSlugs;
  }

  /**
   * Returns the secret type: shared (default) or a personal override (user tokens only).
   *
   * @return the value, or empty when unset
   */
  public Optional<SecretType> type() {
    return Optional.ofNullable(type);
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
   * Returns the secret metadata (key/value pairs).
   *
   * @return the value
   */
  public Map<String, String> metadata() {
    return metadata;
  }

  /** Builder of {@link CreateSecretOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String secretPath = "";
    private String comment = "";
    private List<String> tagIds = List.of();
    private List<String> tagSlugs = List.of();
    private SecretType type = null;
    private boolean skipMultilineEncoding = false;
    private Map<String, String> metadata = Map.of();

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
     * Sets the secret comment.
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
      this.tagIds = tagIds == null ? List.of() : tagIds;
      return this;
    }

    /**
     * Sets the tags to attach, by slug (resolved with listTags; an unknown slug is NOT_FOUND).
     *
     * @param tagSlugs the value
     * @return this builder
     */
    public Builder tagSlugs(List<String> tagSlugs) {
      this.tagSlugs = tagSlugs == null ? List.of() : tagSlugs;
      return this;
    }

    /**
     * Sets the secret type: shared (default) or a personal override (user tokens only).
     *
     * @param type the value
     * @return this builder
     */
    public Builder type(SecretType type) {
      this.type = type;
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
     * Sets the secret metadata (key/value pairs).
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
    public CreateSecretOptions build() {
      return new CreateSecretOptions(this);
    }
  }
}
