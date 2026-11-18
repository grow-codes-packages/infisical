package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.ConfigException;
import codes.grow.packages.infisical.core.Redaction;
import codes.grow.packages.infisical.core.Secret;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Logs a machine identity in with a client id and secret ({@code POST
 * /api/v1/auth/universal-auth/login}). The client's token manager renews tokens at 80 % of their
 * lifetime and logs in again when renewal is no longer possible.
 *
 * <p>Infisical locks a Universal Auth identity after repeated failed logins (default 3 failures,
 * 300 s, during which even the right secret fails); the client never retries a rejected login.
 */
public final class UniversalAuth implements Authenticator {
  private final String clientId;
  private final Secret clientSecret;
  private final String organizationSlug;

  /**
   * Creates the method.
   *
   * @param clientId Universal Auth client id
   * @param clientSecret Universal Auth client secret
   */
  public UniversalAuth(String clientId, String clientSecret) {
    this(clientId, clientSecret == null ? null : Secret.of(clientSecret), null);
  }

  /**
   * Creates the method.
   *
   * @param clientId Universal Auth client id
   * @param clientSecret Universal Auth client secret
   * @param organizationSlug sub-organization slug, may be null
   */
  public UniversalAuth(String clientId, Secret clientSecret, String organizationSlug) {
    this.clientId = clientId == null ? "" : clientId;
    this.clientSecret = clientSecret;
    this.organizationSlug = organizationSlug;
  }

  /**
   * Returns the client id.
   *
   * @return the client id
   */
  public String clientId() {
    return clientId;
  }

  /**
   * Returns the sub-organization slug.
   *
   * @return the slug, or empty
   */
  public Optional<String> organizationSlug() {
    return Optional.ofNullable(organizationSlug);
  }

  @Override
  public AccessToken login(InfisicalClient client) {
    if (clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty()) {
      throw new ConfigException("auth.universalAuth: clientId and clientSecret are required");
    }
    client.rememberSecret(clientSecret.reveal());
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("clientId", clientId);
    body.put("clientSecret", clientSecret.reveal());
    if (organizationSlug != null && !organizationSlug.isEmpty()) {
      body.put("organizationSlug", organizationSlug);
    }
    return client.tokenCall("auth.universalAuth.login", "/api/v1/auth/universal-auth/login", body);
  }

  /**
   * Asynchronous {@link #login(InfisicalClient)}.
   *
   * @param client the client
   * @return a future with the token
   */
  public CompletableFuture<AccessToken> loginAsync(InfisicalClient client) {
    return client.async(() -> login(client));
  }

  /**
   * Extends a token on the server ({@code POST /api/v1/auth/token/renew}). Always keep the returned
   * token (it may be byte-identical); it cannot outlive its maximum TTL.
   *
   * @param client the client
   * @param token the token to renew
   * @return the renewed token
   */
  public AccessToken renew(InfisicalClient client, Secret token) {
    return client.renewToken(token);
  }

  /**
   * Asynchronous {@link #renew(InfisicalClient, Secret)}.
   *
   * @param client the client
   * @param token the token to renew
   * @return a future with the renewed token
   */
  public CompletableFuture<AccessToken> renewAsync(InfisicalClient client, Secret token) {
    return client.async(() -> renew(client, token));
  }

  /**
   * Revokes a token ({@code POST /api/v1/auth/token/revoke}); revoking twice succeeds.
   *
   * @param client the client
   * @param token the token to revoke
   */
  public void revoke(InfisicalClient client, Secret token) {
    client.revokeToken(token);
  }

  /**
   * Asynchronous {@link #revoke(InfisicalClient, Secret)}.
   *
   * @param client the client
   * @param token the token to revoke
   * @return a future completed when revoked
   */
  public CompletableFuture<Void> revokeAsync(InfisicalClient client, Secret token) {
    return client.async(
        () -> {
          revoke(client, token);
          return null;
        });
  }

  @Override
  public String toString() {
    return "UniversalAuth{clientId=" + clientId + ", clientSecret=" + Redaction.REDACTED + "}";
  }
}
