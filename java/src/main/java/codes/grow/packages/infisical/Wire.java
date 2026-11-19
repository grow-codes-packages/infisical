package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.Secret;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/** Decodes Infisical JSON responses into the SDK models. */
final class Wire {
  private Wire() {}

  static String text(JsonNode n, String field) {
    JsonNode v = n == null ? null : n.get(field);
    return v == null || v.isNull() ? "" : v.asText();
  }

  static int integer(JsonNode n, String field) {
    JsonNode v = n == null ? null : n.get(field);
    return v == null ? 0 : v.asInt();
  }

  static boolean bool(JsonNode n, String field) {
    JsonNode v = n == null ? null : n.get(field);
    return v != null && v.asBoolean();
  }

  static Optional<Instant> instant(JsonNode n, String field) {
    String s = text(n, field);
    if (s.isEmpty()) {
      return Optional.empty();
    }
    try {
      return Optional.of(Instant.parse(s));
    } catch (DateTimeParseException e) {
      return Optional.empty();
    }
  }

  static <T> List<T> list(JsonNode array, Function<JsonNode, T> f) {
    List<T> out = new ArrayList<>();
    if (array != null && array.isArray()) {
      for (JsonNode n : array) {
        out.add(f.apply(n));
      }
    }
    return Collections.unmodifiableList(out);
  }

  static Tag tag(JsonNode n) {
    return new Tag(
        text(n, "id"),
        text(n, "slug"),
        text(n, "name"),
        text(n, "color"),
        text(n, "projectId"),
        instant(n, "createdAt"),
        instant(n, "updatedAt"));
  }

  static SecretEntry secret(JsonNode n) {
    boolean hidden = bool(n, "secretValueHidden");
    Map<String, String> metadata = new LinkedHashMap<>();
    JsonNode md = n.get("secretMetadata");
    if (md != null && md.isArray()) {
      for (JsonNode m : md) {
        metadata.put(text(m, "key"), text(m, "value"));
      }
    }
    return new SecretEntry(
        text(n, "id"),
        text(n, "secretKey"),
        Secret.of(hidden ? "" : text(n, "secretValue")),
        hidden,
        text(n, "secretComment"),
        integer(n, "version"),
        SecretType.fromWire(text(n, "type")),
        text(n, "workspace"),
        text(n, "environment"),
        text(n, "secretPath"),
        list(n.get("tags"), Wire::tag),
        Collections.unmodifiableMap(metadata),
        bool(n, "skipMultilineEncoding"),
        instant(n, "createdAt"),
        instant(n, "updatedAt"));
  }

  static SecretList secretList(JsonNode body) {
    List<ImportedSecrets> imports =
        list(
            body.get("imports"),
            i ->
                new ImportedSecrets(
                    text(i, "secretPath"),
                    text(i, "environment"),
                    text(i, "folderId"),
                    list(i.get("secrets"), Wire::secret)));
    return new SecretList(list(body.get("secrets"), Wire::secret), imports);
  }

  static Folder folder(JsonNode n) {
    return new Folder(
        text(n, "id"),
        text(n, "name"),
        text(n, "description"),
        text(n, "path"),
        text(n, "relativePath"),
        integer(n, "version"),
        text(n, "envId"),
        text(n, "parentId"),
        instant(n, "createdAt"),
        instant(n, "updatedAt"));
  }

  static Environment environment(JsonNode n) {
    return new Environment(
        text(n, "id"),
        text(n, "name"),
        text(n, "slug"),
        integer(n, "position"),
        text(n, "projectId"),
        instant(n, "createdAt"),
        instant(n, "updatedAt"));
  }

  static Project project(JsonNode n) {
    return new Project(
        text(n, "id"),
        text(n, "name"),
        text(n, "slug"),
        text(n, "description"),
        text(n, "type"),
        text(n, "orgId"),
        list(n.get("environments"), Wire::environment),
        instant(n, "createdAt"),
        instant(n, "updatedAt"));
  }

  static SecretImport secretImport(JsonNode n) {
    return new SecretImport(
        text(n, "id"),
        text(n, "importPath"),
        environment(n.path("importEnv")),
        integer(n, "position"),
        bool(n, "isReplication"),
        text(n, "folderId"),
        text(n, "sourceProjectName"),
        instant(n, "createdAt"),
        instant(n, "updatedAt"));
  }

  static SecretVersion version(JsonNode n) {
    boolean hidden = bool(n, "secretValueHidden");
    JsonNode a = n.get("actor");
    Optional<Actor> actor =
        a == null || a.isNull() || !a.isObject()
            ? Optional.empty()
            : Optional.of(new Actor(text(a, "actorId"), text(a, "actorType"), text(a, "name")));
    return new SecretVersion(
        text(n, "id"),
        integer(n, "version"),
        text(n, "secretKey"),
        Secret.of(hidden ? "" : text(n, "secretValue")),
        hidden,
        text(n, "secretComment"),
        SecretType.fromWire(text(n, "type")),
        text(n, "environment"),
        actor,
        instant(n, "createdAt"));
  }
}
