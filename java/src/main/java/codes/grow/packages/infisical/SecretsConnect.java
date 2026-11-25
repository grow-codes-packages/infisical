// Service-owned: generated once by sdk-kit, then maintained in this repository.
package codes.grow.packages.infisical;

import codes.grow.packages.infisical.secrets.ConfigLoader.SecretsBootstrap;
import codes.grow.packages.infisical.secrets.ConfigLoader.SecretsConnection;
import java.util.HashMap;
import java.util.Map;

/** Connector of {@code ConfigLoader.load()} for Infisical. */
public final class SecretsConnect {
  private static final String PREFIX = "GROW_INFISICAL_";

  private SecretsConnect() {}

  /**
   * Builds a client from the package's own variables ({@code GROW_INFISICAL_*} / {@code
   * INFISICAL_*}, Universal Auth included) read from {@code env}, with the address from {@code
   * GROW_SECRETS_ADDR} when set, and returns {@code client.secrets()} (the {@code SecretsProvider}
   * for the configured project and environment).
   *
   * @param bootstrap parsed GROW_SECRETS_* bootstrap
   * @param env environment the bootstrap was read from
   * @return the connection
   */
  public static SecretsConnection connect(SecretsBootstrap bootstrap, Map<String, String> env) {
    Map<String, String> merged = new HashMap<>(env);
    if (bootstrap.addr() != null) {
      merged.put(PREFIX + "URL", bootstrap.addr());
    }
    InfisicalClient client = InfisicalClient.create(InfisicalConfig.fromEnv(merged));
    return new SecretsConnection(client.secrets(), null, client::close);
  }
}
