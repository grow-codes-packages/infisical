package codes.grow.packages.infisical;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The result of {@link InfisicalClient#listSecrets}.
 *
 * @param secrets the secrets of the path (and of sub-folders when recursive)
 * @param imports the secrets contributed by secret imports ({@code includeImports})
 */
public record SecretList(List<SecretEntry> secrets, List<ImportedSecrets> imports) {
  /**
   * Returns the effective key to secret map: direct secrets win over imported ones; with a
   * recursive listing, shallower paths win.
   *
   * @return key to secret, in listing order
   */
  public Map<String, SecretEntry> merged() {
    Map<String, SecretEntry> out = new LinkedHashMap<>();
    List<SecretEntry> direct = new ArrayList<>(secrets);
    direct.sort(Comparator.comparingInt(s -> SecretPaths.segments(s.secretPath()).size()));
    for (SecretEntry s : direct) {
      out.putIfAbsent(s.key(), s);
    }
    for (ImportedSecrets imp : imports) {
      for (SecretEntry s : imp.secrets()) {
        out.putIfAbsent(s.key(), s);
      }
    }
    return out;
  }
}
