package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.ConflictException;
import codes.grow.packages.infisical.core.NotFoundException;
import codes.grow.packages.infisical.core.UnsupportedException;
import codes.grow.packages.infisical.core.ValidationException;
import codes.grow.packages.infisical.secrets.BaseSecretsProvider;
import codes.grow.packages.infisical.secrets.DeleteOptions;
import codes.grow.packages.infisical.secrets.GetOptions;
import codes.grow.packages.infisical.secrets.SecretMetadata;
import codes.grow.packages.infisical.secrets.SecretValue;
import codes.grow.packages.infisical.secrets.SetOptions;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * The {@code SecretsProvider} (SPEC section 3) over one Infisical project and environment.
 *
 * <p>Model: a name may contain {@code /}: the last segment is the secret key, the rest is the
 * folder below the base path ({@code app/db/PASSWORD} is path {@code <basePath>/app/db}, key {@code
 * PASSWORD}). {@code GetOptions.path}, {@code SetOptions.path} and {@code DeleteOptions.path}
 * replace the base path. {@code set} creates missing folders, updates an existing secret and
 * returns the new version; values are UTF-8 text (other bytes are a {@link ValidationException})
 * and Infisical trims surrounding whitespace. Versions are the Infisical version numbers as
 * strings. {@code delete} is always permanent and removes every version ({@code
 * DeleteOptions.versions} and {@code SetOptions.cas} are {@link UnsupportedException}; {@code
 * DeleteOptions.permanent} is accepted and has no effect). {@code SetOptions.tags} keys are tag
 * slugs (created when missing, with the value as the color when it starts with {@code #}); {@code
 * SecretMetadata.tags} maps slug to name.
 */
public final class ProjectSecretsProvider extends BaseSecretsProvider {
  private final InfisicalClient client;
  private final SecretsProviderOptions options;
  private final String basePath;

  ProjectSecretsProvider(InfisicalClient client, SecretsProviderOptions options) {
    this.client = client;
    this.options = options == null ? SecretsProviderOptions.defaults() : options;
    this.basePath =
        SecretPaths.normalize(
            this.options.basePath().isEmpty()
                ? client.config().secretPath()
                : this.options.basePath());
  }

  /**
   * Returns the provider options.
   *
   * @return the options
   */
  public SecretsProviderOptions options() {
    return options;
  }

  /**
   * Returns the effective base path secret names are relative to.
   *
   * @return the normalized base path
   */
  public String basePath() {
    return basePath;
  }

  /** Folder path and key of a name. */
  private record Location(String path, String key) {}

  private Location locate(String op, String name, Optional<String> override) {
    String base = override.filter(p -> !p.isEmpty()).map(SecretPaths::normalize).orElse(basePath);
    int i = name.lastIndexOf('/');
    String dir = i >= 0 ? name.substring(0, i) : "";
    String key = i >= 0 ? name.substring(i + 1) : name;
    if (key.isBlank()) {
      throw new ValidationException(op + ": secret name must end with a key");
    }
    return new Location(SecretPaths.join(base, dir), key);
  }

  private GetSecretOptions getOptions(String path, GetOptions o, boolean view) {
    GetSecretOptions.Builder b =
        GetSecretOptions.builder()
            .projectId(options.projectId())
            .environment(options.environment())
            .secretPath(path)
            .expandReferences(options.expandReferences())
            .includeImports(options.includeImports())
            .viewSecretValue(view);
    if (o.version().isPresent()) {
      int n;
      try {
        n = Integer.parseInt(o.version().get());
      } catch (NumberFormatException e) {
        n = 0;
      }
      if (n <= 0) {
        throw new ValidationException("secrets.get: version must be a positive integer");
      }
      b.version(n);
    }
    return b.build();
  }

  private Optional<SecretEntry> read(String op, String name, GetOptions opts, boolean view) {
    Location l = locate(op, name, opts.path());
    try {
      return Optional.of(client.getSecret(l.key(), getOptions(l.path(), opts, view)));
    } catch (NotFoundException e) {
      return Optional.empty();
    }
  }

  @Override
  protected Optional<SecretValue> fetchSecret(String name, GetOptions opts) {
    return read("secrets.get", name, opts, true)
        .map(s -> SecretValue.of(s.value().reveal(), Integer.toString(s.version())));
  }

  @Override
  protected Optional<SecretMetadata> fetchMetadata(String name, GetOptions opts) {
    return read("secrets.metadata", name, opts, false).map(s -> metadataOf(name, s));
  }

  static SecretMetadata metadataOf(String name, SecretEntry s) {
    Map<String, String> tags = new LinkedHashMap<>();
    for (Tag t : s.tags()) {
      tags.put(t.slug(), t.name().isEmpty() ? t.slug() : t.name());
    }
    SecretMetadata.Builder b =
        SecretMetadata.builder(name)
            .path(s.secretPath())
            .version(Integer.toString(s.version()))
            .createdAt(s.createdAt().orElse(null))
            .updatedAt(s.updatedAt().orElse(null))
            .versions(s.version())
            .tags(tags)
            .extra("id", s.id())
            .extra("type", s.type().wireValue())
            .extra("environment", s.environment());
    if (!s.comment().isEmpty()) {
      b.extra("comment", s.comment());
    }
    return b.build();
  }

  /**
   * Lists a folder below the base path ({@code app/} or {@code app}); when no such folder exists
   * the argument is a key prefix inside its parent folder ({@code app/DB_} lists keys starting with
   * {@code DB_} in {@code app}). Names in the result resolve with {@code get}.
   */
  @Override
  protected List<SecretMetadata> listSecrets(String prefixOrPath) {
    String rel = trimSlashes(prefixOrPath);
    try {
      return listFolder(rel, "");
    } catch (NotFoundException e) {
      if (rel.isEmpty() || prefixOrPath.endsWith("/")) {
        return List.of();
      }
    }
    int i = rel.lastIndexOf('/');
    String dir = i >= 0 ? rel.substring(0, i) : "";
    String keyPrefix = i >= 0 ? rel.substring(i + 1) : rel;
    try {
      return listFolder(dir, keyPrefix);
    } catch (NotFoundException e) {
      return List.of();
    }
  }

  private static String trimSlashes(String s) {
    int a = 0;
    int b = s.length();
    while (a < b && s.charAt(a) == '/') {
      a++;
    }
    while (b > a && s.charAt(b - 1) == '/') {
      b--;
    }
    return s.substring(a, b);
  }

  private List<SecretMetadata> listFolder(String rel, String keyPrefix) {
    SecretList list =
        client.listSecrets(
            ListSecretsOptions.builder()
                .projectId(options.projectId())
                .environment(options.environment())
                .secretPath(SecretPaths.join(basePath, rel))
                .expandReferences(false)
                .includeImports(false)
                .viewSecretValue(false)
                .build());
    List<SecretMetadata> out = new ArrayList<>();
    for (SecretEntry s : list.secrets()) {
      if (!s.key().startsWith(keyPrefix) || s.type() == SecretType.PERSONAL) {
        continue;
      }
      out.add(metadataOf(rel.isEmpty() ? s.key() : rel + "/" + s.key(), s));
    }
    out.sort(Comparator.comparing(SecretMetadata::name));
    return out;
  }

  /** Creates the secret, or updates it when the key exists; missing folders are created. */
  @Override
  protected String putSecret(String name, byte[] value, SetOptions opts) {
    String op = "secrets.set";
    if (opts.cas().isPresent()) {
      throw new UnsupportedException(op + ": Infisical has no check-and-set");
    }
    String text = utf8(op, value);
    Location l = locate(op, name, opts.path());
    List<String> tagIds = opts.tags().isEmpty() ? List.of() : ensureTags(opts.tags());
    CreateSecretOptions create =
        CreateSecretOptions.builder()
            .projectId(options.projectId())
            .environment(options.environment())
            .secretPath(l.path())
            .comment(opts.description().orElse(""))
            .tagIds(tagIds)
            .build();
    SecretEntry s;
    try {
      s = createWithFolders(l, text, create);
    } catch (ConflictException e) {
      UpdateSecretOptions.Builder u =
          UpdateSecretOptions.builder()
              .projectId(options.projectId())
              .environment(options.environment())
              .secretPath(l.path())
              .value(text);
      if (!tagIds.isEmpty()) {
        u.tagIds(tagIds);
      }
      opts.description().filter(d -> !d.isEmpty()).ifPresent(u::comment);
      s = client.updateSecret(l.key(), u.build());
    }
    return Integer.toString(s.version());
  }

  private SecretEntry createWithFolders(Location l, String text, CreateSecretOptions create) {
    try {
      return client.createSecret(l.key(), text, create);
    } catch (NotFoundException e) {
      if (!String.valueOf(e.getMessage()).toLowerCase(Locale.ROOT).contains("folder")) {
        throw e;
      }
      ensureFolders(l.path());
      return client.createSecret(l.key(), text, create);
    }
  }

  private static String utf8(String op, byte[] value) {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(value))
          .toString();
    } catch (CharacterCodingException e) {
      throw new ValidationException(
          op + ": Infisical stores text only; the value is not valid UTF-8");
    }
  }

  /** Creates every folder of {@code path} that does not exist yet. */
  private void ensureFolders(String path) {
    String parent = "/";
    for (String seg : SecretPaths.segments(path)) {
      try {
        client.createFolder(
            seg,
            CreateFolderOptions.builder()
                .projectId(options.projectId())
                .environment(options.environment())
                .path(parent)
                .build());
      } catch (ConflictException ignored) {
        // already exists
      }
      parent = SecretPaths.join(parent, seg);
    }
  }

  /** Resolves tag slugs to ids, creating missing tags. */
  private List<String> ensureTags(Map<String, String> tags) {
    ProjectOptions project = ProjectOptions.builder().projectId(options.projectId()).build();
    Map<String, String> bySlug = new LinkedHashMap<>();
    for (Tag t : client.listTags(project)) {
      bySlug.put(t.slug(), t.id());
    }
    List<String> ids = new ArrayList<>();
    for (Map.Entry<String, String> e : new TreeMap<>(tags).entrySet()) {
      String id = bySlug.get(e.getKey());
      if (id == null) {
        String color = e.getValue() != null && e.getValue().startsWith("#") ? e.getValue() : null;
        id = client.createTag(e.getKey(), color, project).id();
      }
      ids.add(id);
    }
    return ids;
  }

  @Override
  protected void removeSecret(String name, DeleteOptions opts) {
    String op = "secrets.delete";
    // permanent is accepted (Infisical always deletes permanently); false is the default and
    // cannot be told apart from "not set", so it is not rejected.
    if (!opts.versions().isEmpty()) {
      throw new UnsupportedException(
          op + ": Infisical always deletes a secret permanently with all its versions");
    }
    Location l = locate(op, name, opts.path());
    client.deleteSecret(
        l.key(),
        DeleteSecretOptions.builder()
            .projectId(options.projectId())
            .environment(options.environment())
            .secretPath(l.path())
            .build());
  }

  /**
   * Returns every secret directly under {@code path} with one listing (plus imported keys when
   * {@code includeImports} is on; direct secrets win). A missing folder gives an empty map.
   */
  @Override
  public Map<String, SecretValue> getAll(String path) {
    String rel = trimSlashes(path == null ? "" : path);
    SecretList list;
    try {
      list =
          client.listSecrets(
              ListSecretsOptions.builder()
                  .projectId(options.projectId())
                  .environment(options.environment())
                  .secretPath(SecretPaths.join(basePath, rel))
                  .expandReferences(options.expandReferences())
                  .includeImports(options.includeImports())
                  .build());
    } catch (NotFoundException e) {
      return Map.of();
    }
    Map<String, SecretValue> out = new TreeMap<>();
    list.merged()
        .forEach(
            (key, s) ->
                out.put(
                    rel.isEmpty() ? key : rel + "/" + key,
                    SecretValue.of(s.value().reveal(), Integer.toString(s.version()))));
    return new LinkedHashMap<>(out);
  }

  @Override
  public String toString() {
    return "ProjectSecretsProvider{basePath=" + basePath + "}";
  }
}
