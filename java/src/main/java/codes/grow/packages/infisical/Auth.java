package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.CancelledException;
import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.InfisicalException;
import codes.grow.packages.infisical.core.Secret;
import codes.grow.packages.infisical.core.ValidationException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * The client's token manager ({@link InfisicalClient#auth()}).
 *
 * <p>It logs in on first use, renews the token at 80 % of its lifetime (logging in again when
 * renewal fails or the maximum TTL is reached) and logs in once more when a call fails with {@code
 * AUTHENTICATION}. Static tokens ({@link InfisicalConfig#token()}, {@link TokenAuth}) are used as
 * they are. Thread-safe.
 */
public final class Auth {
  static final double REFRESH_FACTOR = 0.8;

  private final InfisicalClient client;
  private final Authenticator method;
  private final boolean staticToken;
  private AccessToken token;
  private Instant loginAt;

  Auth(InfisicalClient client, Authenticator method) {
    this.client = client;
    this.method = method;
    this.staticToken = method instanceof TokenAuth;
  }

  /**
   * Returns the configured authentication method.
   *
   * @return the method, or empty when none is configured
   */
  public Optional<Authenticator> method() {
    return Optional.ofNullable(method);
  }

  /** Whether tokens come from a login that can be repeated. */
  boolean managed() {
    return method != null && !staticToken;
  }

  /**
   * Obtains a new token with the configured method and stores it.
   *
   * @return the token
   * @throws ConfigException when no method is configured
   */
  public synchronized AccessToken login() {
    return loginLocked();
  }

  /**
   * Asynchronous {@link #login()}.
   *
   * @return a future with the token
   */
  public CompletableFuture<AccessToken> loginAsync() {
    return client.async(this::login);
  }

  private AccessToken loginLocked() {
    if (method == null) {
      throw new ConfigException(
          "auth.login: no authentication method configured (set auth, token or"
              + " clientId/clientSecret)");
    }
    AccessToken t = method.login(client);
    token = t;
    loginAt = t.issuedAt();
    return t;
  }

  /**
   * Extends the current token on the server and stores the result.
   *
   * @return the renewed token
   * @throws ValidationException when there is no token yet
   */
  public synchronized AccessToken renew() {
    if (token == null) {
      throw new ValidationException("auth.renew: no access token to renew; log in first");
    }
    token = client.renewToken(token.token());
    return token;
  }

  /**
   * Asynchronous {@link #renew()}.
   *
   * @return a future with the renewed token
   */
  public CompletableFuture<AccessToken> renewAsync() {
    return client.async(this::renew);
  }

  /**
   * Revokes the current token on the server and forgets it; the next call logs in again (a static
   * token is revoked too and then fails).
   */
  public synchronized void revoke() {
    if (token == null) {
      return;
    }
    client.revokeToken(token.token());
    token = null;
  }

  /**
   * Asynchronous {@link #revoke()}.
   *
   * @return a future completed when revoked
   */
  public CompletableFuture<Void> revokeAsync() {
    return client.async(
        () -> {
          revoke();
          return null;
        });
  }

  /** Revokes a token obtained by login (best effort, used by close). */
  synchronized void revokeManaged() {
    if (token == null || !managed()) {
      return;
    }
    try {
      client.revokeToken(token.token());
    } catch (InfisicalException ignored) {
      // best effort
    }
    token = null;
  }

  /**
   * Returns the current access token.
   *
   * @return the token, or empty before the first login
   */
  public synchronized Optional<AccessToken> token() {
    return Optional.ofNullable(token);
  }

  /**
   * Replaces the current token with a static one (no refresh until the next login); an empty secret
   * or null forgets the token.
   *
   * @param newToken the token
   */
  public synchronized void setToken(Secret newToken) {
    if (newToken == null || newToken.isEmpty()) {
      token = null;
      return;
    }
    client.rememberSecret(newToken.reveal());
    token = new AccessToken(newToken, Duration.ZERO, Duration.ZERO, "Bearer", client.now());
  }

  /** Returns a valid bearer token for the next call ({@code null} when no auth is configured). */
  synchronized String bearer() {
    if (token == null) {
      if (method == null) {
        return null;
      }
      return loginLocked().token().reveal();
    }
    AccessToken t = token;
    if (t.expiresIn().isZero() || !managed()) {
      return t.token().reveal();
    }
    Instant now = client.now();
    Instant refreshAt = t.issuedAt().plusNanos((long) (t.expiresIn().toNanos() * REFRESH_FACTOR));
    if (now.isBefore(refreshAt)) {
      return t.token().reveal();
    }
    Instant base = loginAt != null ? loginAt : t.issuedAt();
    boolean maxReached =
        !t.maxTtl().isZero() && !now.plus(t.expiresIn()).isBefore(base.plus(t.maxTtl()));
    if (!maxReached) {
      try {
        token = client.renewToken(t.token());
        return token.token().reveal();
      } catch (CancelledException e) {
        throw e;
      } catch (InfisicalException e) {
        // renewal failed: log in again below
      }
    }
    return loginLocked().token().reveal();
  }

  /** Logs in again unless another call already replaced {@code stale}. */
  synchronized String relogin(String stale) {
    if (token != null && !token.token().reveal().equals(stale)) {
      return token.token().reveal();
    }
    return loginLocked().token().reveal();
  }
}
