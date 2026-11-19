package codes.grow.packages.infisical;

import java.time.Instant;
import java.util.Optional;

/**
 * A secret folder.
 *
 * @param id folder id
 * @param name folder name
 * @param description description ({@code ""} when none)
 * @param path absolute path of the folder (create and update responses; {@code ""} otherwise)
 * @param relativePath path below the listed path (recursive listings; {@code ""} otherwise)
 * @param version folder version
 * @param environmentId environment id
 * @param parentId parent folder id
 * @param createdAt creation time
 * @param updatedAt last update time
 */
public record Folder(
    String id,
    String name,
    String description,
    String path,
    String relativePath,
    int version,
    String environmentId,
    String parentId,
    Optional<Instant> createdAt,
    Optional<Instant> updatedAt) {}
