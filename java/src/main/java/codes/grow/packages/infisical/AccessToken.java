package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.Secret;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * An Infisical access token with its lifetime. The token is a {@link Secret} and never prints.
 *
 * @param token the bearer token
 * @param expiresIn lifetime from {@code issuedAt} ({@link Duration#ZERO}: the token does not expire
 *     or its lifetime is unknown, as for static tokens)
 * @param maxTtl maximum lifetime reachable by renewals ({@link Duration#ZERO}: unknown)
 * @param tokenType token type reported by the server ({@code Bearer})
 * @param issuedAt when the client received the token
 */
public record AccessToken(
    Secret token, Duration expiresIn, Duration maxTtl, String tokenType, Instant issuedAt) {
  /**
   * Returns {@code issuedAt + expiresIn}.
   *
   * @return the expiry, or empty when the token does not expire
   */
  public Optional<Instant> expiresAt() {
    if (expiresIn.isZero() || expiresIn.isNegative()) {
      return Optional.empty();
    }
    return Optional.of(issuedAt.plus(expiresIn));
  }
}
