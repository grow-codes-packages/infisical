package codes.grow.packages.infisical;

import java.time.Instant;
import java.util.Optional;

/**
 * A project environment.
 *
 * @param id environment id
 * @param name display name
 * @param slug slug used by every secret call (for example {@code dev})
 * @param position order of the environment (0 when unknown)
 * @param projectId project id ({@code ""} when unknown)
 * @param createdAt creation time
 * @param updatedAt last update time
 */
public record Environment(
    String id,
    String name,
    String slug,
    int position,
    String projectId,
    Optional<Instant> createdAt,
    Optional<Instant> updatedAt) {}
