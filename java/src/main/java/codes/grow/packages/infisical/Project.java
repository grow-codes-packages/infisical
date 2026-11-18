package codes.grow.packages.infisical;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * An Infisical project.
 *
 * @param id project id
 * @param name display name
 * @param slug project slug
 * @param description description ({@code ""} when none)
 * @param type product type ({@code secret-manager}, …)
 * @param orgId organization id
 * @param environments environments ordered by position
 * @param createdAt creation time
 * @param updatedAt last update time
 */
public record Project(
    String id,
    String name,
    String slug,
    String description,
    String type,
    String orgId,
    List<Environment> environments,
    Optional<Instant> createdAt,
    Optional<Instant> updatedAt) {}
