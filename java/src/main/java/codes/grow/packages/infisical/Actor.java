package codes.grow.packages.infisical;

/**
 * Who wrote a secret version.
 *
 * @param id actor id
 * @param type actor type ({@code user}, {@code identity}, …)
 * @param name display name ({@code ""} when unknown)
 */
public record Actor(String id, String type, String name) {}
