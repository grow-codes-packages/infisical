package codes.grow.packages.infisical;

import java.util.List;

/**
 * Selects the secrets {@link InfisicalClient#listSecrets} returns. Build it with {@link
 * #builder()}; immutable.
 */
public final class ListSecretsOptions {
  private static final ListSecretsOptions DEFAULTS = builder().build();

  private final String projectId;
  private final String environment;
  private final String secretPath;
  private final boolean recursive;
  private final boolean expandReferences;
  private final boolean includeImports;
  private final List<String> tagSlugs;
  private final boolean viewSecretValue;
  private final boolean includePersonalOverrides;

  private ListSecretsOptions(Builder b) {
    this.projectId = b.projectId;
    this.environment = b.environment;
    this.secretPath = b.secretPath;
    this.recursive = b.recursive;
    this.expandReferences = b.expandReferences;
    this.includeImports = b.includeImports;
    this.tagSlugs = List.copyOf(b.tagSlugs);
    this.viewSecretValue = b.viewSecretValue;
    this.includePersonalOverrides = b.includePersonalOverrides;
  }

  /**
   * Returns the options with every field at its default.
   *
   * @return the default options
   */
  public static ListSecretsOptions defaults() {
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
   * Returns whether every sub-folder is listed too (default false).
   *
   * @return the value
   */
  public boolean recursive() {
    return recursive;
  }

  /**
   * Returns whether {@code ${KEY}} / {@code ${env.path.KEY}} references are expanded (default
   * true).
   *
   * @return the value
   */
  public boolean expandReferences() {
    return expandReferences;
  }

  /**
   * Returns whether the secrets of secret imports are included (default true).
   *
   * @return the value
   */
  public boolean includeImports() {
    return includeImports;
  }

  /**
   * Returns the tag slugs; only secrets carrying one of them are returned.
   *
   * @return the value
   */
  public List<String> tagSlugs() {
    return tagSlugs;
  }

  /**
   * Returns whether values are returned (default true); false returns metadata only.
   *
   * @return the value
   */
  public boolean viewSecretValue() {
    return viewSecretValue;
  }

  /**
   * Returns whether the caller's personal values replace the shared ones (user tokens).
   *
   * @return the value
   */
  public boolean includePersonalOverrides() {
    return includePersonalOverrides;
  }

  /** Builder of {@link ListSecretsOptions}. */
  public static final class Builder {
    private String projectId = "";
    private String environment = "";
    private String secretPath = "";
    private boolean recursive = false;
    private boolean expandReferences = true;
    private boolean includeImports = true;
    private List<String> tagSlugs = List.of();
    private boolean viewSecretValue = true;
    private boolean includePersonalOverrides = false;

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
     * Sets whether every sub-folder is listed too (default false).
     *
     * @param recursive the value
     * @return this builder
     */
    public Builder recursive(boolean recursive) {
      this.recursive = recursive;
      return this;
    }

    /**
     * Sets whether {@code ${KEY}} / {@code ${env.path.KEY}} references are expanded (default true).
     *
     * @param expandReferences the value
     * @return this builder
     */
    public Builder expandReferences(boolean expandReferences) {
      this.expandReferences = expandReferences;
      return this;
    }

    /**
     * Sets whether the secrets of secret imports are included (default true).
     *
     * @param includeImports the value
     * @return this builder
     */
    public Builder includeImports(boolean includeImports) {
      this.includeImports = includeImports;
      return this;
    }

    /**
     * Sets the tag slugs; only secrets carrying one of them are returned.
     *
     * @param tagSlugs the value
     * @return this builder
     */
    public Builder tagSlugs(List<String> tagSlugs) {
      this.tagSlugs = tagSlugs == null ? List.of() : tagSlugs;
      return this;
    }

    /**
     * Sets whether values are returned (default true); false returns metadata only.
     *
     * @param viewSecretValue the value
     * @return this builder
     */
    public Builder viewSecretValue(boolean viewSecretValue) {
      this.viewSecretValue = viewSecretValue;
      return this;
    }

    /**
     * Sets whether the caller's personal values replace the shared ones (user tokens).
     *
     * @param includePersonalOverrides the value
     * @return this builder
     */
    public Builder includePersonalOverrides(boolean includePersonalOverrides) {
      this.includePersonalOverrides = includePersonalOverrides;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public ListSecretsOptions build() {
      return new ListSecretsOptions(this);
    }
  }
}
