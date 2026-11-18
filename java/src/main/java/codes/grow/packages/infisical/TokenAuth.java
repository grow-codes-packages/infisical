package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.Redaction;
import codes.grow.packages.infisical.core.Secret;
import java.time.Duration;
import java.util.Objects;

/**
 * A static access token: a token-auth machine identity token, a user JWT or a legacy service token
 * ({@code st.…}). It is never refreshed.
 */
public final class TokenAuth implements Authenticator {
  private final Secret token;

  /**
   * Creates the method.
   *
   * @param token the static bearer token
   */
  public TokenAuth(Secret token) {
    this.token = Objects.requireNonNull(token, "token");
  }

  /**
   * Creates the method.
   *
   * @param token the static bearer token
   */
  public TokenAuth(String token) {
    this(Secret.of(Objects.requireNonNull(token, "token")));
  }

  /**
   * Returns the token.
   *
   * @return the token
   */
  public Secret token() {
    return token;
  }

  /** Returns the static token without a request. */
  @Override
  public AccessToken login(InfisicalClient client) {
    if (token.isEmpty()) {
      throw new ConfigException("auth.tokenAuth: token is required");
    }
    client.rememberSecret(token.reveal());
    return new AccessToken(token, Duration.ZERO, Duration.ZERO, "Bearer", client.now());
  }

  @Override
  public String toString() {
    return "TokenAuth{token=" + Redaction.REDACTED + "}";
  }
}
