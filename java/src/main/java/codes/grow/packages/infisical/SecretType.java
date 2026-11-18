package codes.grow.packages.infisical;

/** The type of a secret: shared (the default) or a user's personal override (user tokens only). */
public enum SecretType {
  /** A secret shared by every member of the environment. */
  SHARED("shared"),
  /** A user's personal override of a shared secret. */
  PERSONAL("personal");

  private final String wire;

  SecretType(String wire) {
    this.wire = wire;
  }

  /**
   * Returns the value Infisical uses on the wire.
   *
   * @return {@code shared} or {@code personal}
   */
  public String wireValue() {
    return wire;
  }

  /**
   * Parses a wire value; anything but {@code personal} is {@link #SHARED}.
   *
   * @param value wire value, may be null
   * @return the type
   */
  public static SecretType fromWire(String value) {
    return PERSONAL.wire.equals(value) ? PERSONAL : SHARED;
  }
}
