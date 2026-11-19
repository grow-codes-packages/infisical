package codes.grow.packages.infisical;

/** How {@link InfisicalClient#updateSecrets} treats keys that do not exist. */
public enum BatchUpdateMode {
  /** Fails the whole batch when a key is missing (server default). */
  FAIL_ON_NOT_FOUND("failOnNotFound"),
  /** Creates missing keys. */
  UPSERT("upsert"),
  /** Skips missing keys. */
  IGNORE("ignore");

  private final String wire;

  BatchUpdateMode(String wire) {
    this.wire = wire;
  }

  /**
   * Returns the value Infisical uses on the wire.
   *
   * @return {@code failOnNotFound}, {@code upsert} or {@code ignore}
   */
  public String wireValue() {
    return wire;
  }
}
