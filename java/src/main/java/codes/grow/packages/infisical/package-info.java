/**
 * Grow Codes SDK for Infisical.
 *
 * <p>Start with {@link codes.grow.packages.infisical.InfisicalClient#fromEnv()} (reads {@code
 * GROW_INFISICAL_URL} or {@code INFISICAL_API_URL}, {@code INFISICAL_CLIENT_ID} + {@code
 * INFISICAL_CLIENT_SECRET} or {@code INFISICAL_TOKEN}, {@code INFISICAL_PROJECT_ID}, {@code
 * INFISICAL_ENVIRONMENT}, …).
 *
 * <p>Authentication: {@link codes.grow.packages.infisical.UniversalAuth} (tokens renewed at 80 % of
 * their lifetime and re-obtained when needed), {@link codes.grow.packages.infisical.TokenAuth}
 * (machine identity token, user JWT or legacy service token), {@link
 * codes.grow.packages.infisical.KubernetesAuth} and {@link
 * codes.grow.packages.infisical.AwsIamAuth} (SigV4-signed STS request); the token manager is {@link
 * codes.grow.packages.infisical.Auth}.
 *
 * <p>Service functions are client methods: secrets (v4 API with a run-time v3 fallback), folders,
 * projects and environments, tags, secret imports, secret versions, {@code loadEnv} and {@code
 * exportDotenv}. {@link codes.grow.packages.infisical.InfisicalClient#secrets()} returns the Grow
 * {@code SecretsProvider}.
 *
 * <p>Shared building blocks live in {@code core} (errors, transport, redaction); the category API
 * in {@code secrets}; in-memory fakes and the conformance runner in {@code testing}.
 *
 * <p>Infisical is a trademark of Infisical, Inc. This package is not affiliated with or endorsed by
 * Infisical, Inc.
 */
package codes.grow.packages.infisical;
