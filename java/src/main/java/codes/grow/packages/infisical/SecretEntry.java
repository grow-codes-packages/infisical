package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.Secret;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A secret as Infisical returns it. The value is a {@link Secret} and never prints.
 *
 * @param id secret id (stable across versions and renames)
 * @param key secret name
 * @param value the (reference-expanded unless disabled) value; empty when {@code valueHidden} is
 *     true or the server omitted it (an update without a new value)
 * @param valueHidden whether the server hid the value ({@code viewSecretValue=false} or a missing
 *     permission)
 * @param comment comment ({@code ""} when none)
 * @param version version number (every update bumps it)
 * @param type shared or personal
 * @param projectId project id
 * @param environment environment slug
 * @param secretPath folder of the secret (for an imported secret the import's path)
 * @param tags attached tags
 * @param metadata secret metadata (key/value pairs)
 * @param skipMultilineEncoding whether multi-line values are stored without encoding
 * @param createdAt creation time
 * @param updatedAt last update time
 */
public record SecretEntry(
    String id,
    String key,
    Secret value,
    boolean valueHidden,
    String comment,
    int version,
    SecretType type,
    String projectId,
    String environment,
    String secretPath,
    List<Tag> tags,
    Map<String, String> metadata,
    boolean skipMultilineEncoding,
    Optional<Instant> createdAt,
    Optional<Instant> updatedAt) {}
