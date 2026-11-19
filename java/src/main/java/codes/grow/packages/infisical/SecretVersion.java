package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.Secret;
import java.time.Instant;
import java.util.Optional;

/**
 * One stored version of a secret. The value is a {@link Secret} and never prints.
 *
 * @param id version row id
 * @param version version number
 * @param key secret name at this version
 * @param value value at this version (empty when hidden)
 * @param valueHidden whether the server hid the value
 * @param comment comment at this version
 * @param type shared or personal
 * @param environment environment slug ({@code ""} when unknown)
 * @param actor who wrote the version, when known
 * @param createdAt when the version was written
 */
public record SecretVersion(
    String id,
    int version,
    String key,
    Secret value,
    boolean valueHidden,
    String comment,
    SecretType type,
    String environment,
    Optional<Actor> actor,
    Optional<Instant> createdAt) {}
