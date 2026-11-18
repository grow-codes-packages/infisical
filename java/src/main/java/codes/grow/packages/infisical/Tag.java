package codes.grow.packages.infisical;

import java.time.Instant;
import java.util.Optional;

/**
 * A project tag.
 *
 * @param id tag id
 * @param slug tag slug (lower-case letters, digits and {@code -})
 * @param name display name ({@code ""} when the server sends none)
 * @param color color such as {@code #bec2c8}
 * @param projectId project id ({@code ""} when unknown)
 * @param createdAt creation time
 * @param updatedAt last update time
 */
public record Tag(
    String id,
    String slug,
    String name,
    String color,
    String projectId,
    Optional<Instant> createdAt,
    Optional<Instant> updatedAt) {}
