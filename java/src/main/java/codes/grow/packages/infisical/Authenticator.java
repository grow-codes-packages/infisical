package codes.grow.packages.infisical;

/**
 * Obtains an Infisical access token. {@link UniversalAuth}, {@link TokenAuth}, {@link
 * KubernetesAuth} and {@link AwsIamAuth} implement it; a custom implementation gets the same
 * automatic re-login on {@code AUTHENTICATION} errors (unless it is a {@link TokenAuth}).
 */
public interface Authenticator {
  /**
   * Obtains a new access token through {@code client} (login calls are sent without an {@code
   * Authorization} header).
   *
   * @param client the client the token is for
   * @return the token
   */
  AccessToken login(InfisicalClient client);
}
