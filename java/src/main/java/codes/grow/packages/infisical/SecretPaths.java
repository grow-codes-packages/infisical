package codes.grow.packages.infisical;

import java.util.ArrayList;
import java.util.List;

/** Secret path helpers (absolute, no trailing slash). */
final class SecretPaths {
  private SecretPaths() {}

  /**
   * Returns an absolute secret path without a trailing slash ({@code ""} and {@code /} give {@code
   * /}; {@code a//b/} gives {@code /a/b}).
   */
  static String normalize(String path) {
    return "/" + String.join("/", segments(path));
  }

  /** Joins path parts into a normalized absolute path. */
  static String join(String... parts) {
    return normalize(String.join("/", parts));
  }

  /** Returns the folder names of a path. */
  static List<String> segments(String path) {
    List<String> out = new ArrayList<>();
    if (path == null) {
      return out;
    }
    for (String s : path.split("/")) {
      String t = s.trim();
      if (!t.isEmpty()) {
        out.add(t);
      }
    }
    return out;
  }
}
