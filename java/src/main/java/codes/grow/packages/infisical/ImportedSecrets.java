package codes.grow.packages.infisical;

import java.util.List;

/**
 * The secrets one secret import contributes to a listing.
 *
 * @param secretPath source path of the import
 * @param environment source environment slug
 * @param folderId source folder id ({@code ""} when unknown)
 * @param secrets the imported secrets
 */
public record ImportedSecrets(
    String secretPath, String environment, String folderId, List<SecretEntry> secrets) {}
