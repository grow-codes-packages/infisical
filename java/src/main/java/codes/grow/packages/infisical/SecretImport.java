package codes.grow.packages.infisical;

import java.time.Instant;
import java.util.Optional;

/**
 * A secret import: makes the secrets of another environment and path visible in a path.
 *
 * @param id import id
 * @param importPath source path
 * @param importEnvironment source environment
 * @param position order of the import (lower first)
 * @param isReplication whether the secrets are copied instead of referenced
 * @param folderId folder id of the importing path ({@code ""} when unknown)
 * @param sourceProjectName source project name for cross-project imports ({@code ""} otherwise)
 * @param createdAt creation time
 * @param updatedAt last update time
 */
public record SecretImport(
    String id,
    String importPath,
    Environment importEnvironment,
    int position,
    boolean isReplication,
    String folderId,
    String sourceProjectName,
    Optional<Instant> createdAt,
    Optional<Instant> updatedAt) {}
