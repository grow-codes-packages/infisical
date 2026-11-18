package codes.grow.packages.infisical;

import codes.grow.packages.infisical.core.Json;
import codes.grow.packages.infisical.core.MockServer;
import codes.grow.packages.infisical.core.RetryPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/** A scripted Infisical server for unit tests (routes by method and path, fixtures). */
final class Fake implements AutoCloseable {
  /** A JWT whose payload marks a user token ({@code authTokenType=accessToken}). */
  static final String USER_JWT =
      "eyJhbGciOiJIUzI1NiJ9."
          + java.util.Base64.getUrlEncoder()
              .withoutPadding()
              .encodeToString(
                  "{\"authTokenType\":\"accessToken\",\"userId\":\"u1\"}"
                      .getBytes(StandardCharsets.UTF_8))
          + ".sig";

  record Resp(int status, String body, String[] headers) {}

  final MockServer server;
  private final Map<String, Deque<Resp>> routes = new ConcurrentHashMap<>();

  Fake() {
    try {
      server = MockServer.start();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    server.fallback(
        ex -> {
          String key = ex.getRequestMethod() + " " + ex.getRequestURI().getRawPath();
          Deque<Resp> q = routes.get(key);
          Resp r;
          synchronized (this) {
            r = q == null || q.isEmpty() ? null : (q.size() > 1 ? q.poll() : q.peek());
          }
          if (r == null) {
            MockServer.send(ex, 418, "{\"message\":\"unmocked " + key + "\"}");
            return;
          }
          for (int i = 0; i + 1 < r.headers().length; i += 2) {
            ex.getResponseHeaders().add(r.headers()[i], r.headers()[i + 1]);
          }
          MockServer.send(ex, r.status(), r.body());
        });
  }

  /** Queues a response; the last response of a route repeats. */
  Fake on(String method, String path, int status, String body, String... headers) {
    routes
        .computeIfAbsent(method + " " + path, k -> new ArrayDeque<>())
        .add(new Resp(status, body, headers));
    return this;
  }

  /** Forgets the responses of a route. */
  Fake reset(String method, String path) {
    routes.remove(method + " " + path);
    return this;
  }

  Fake fixture(String method, String path, String name) {
    JsonNode f = fixture(name);
    return on(method, path, f.path("status").asInt(), Json.stringify(f.path("body")));
  }

  static JsonNode fixture(String name) {
    try (InputStream in = Fake.class.getResourceAsStream("/fixtures/" + name + ".json")) {
      if (in == null) {
        throw new IllegalArgumentException("no fixture " + name);
      }
      return Json.tree(in.readAllBytes());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static String body(String name) {
    return Json.stringify(fixture(name).path("body"));
  }

  List<MockServer.Recorded> requests(String method, String path) {
    List<MockServer.Recorded> out = new ArrayList<>();
    for (MockServer.Recorded r : server.requests()) {
      String p = r.uri().contains("?") ? r.uri().substring(0, r.uri().indexOf('?')) : r.uri();
      if (r.method().equals(method) && p.equals(path)) {
        out.add(r);
      }
    }
    return out;
  }

  MockServer.Recorded last(String method, String path) {
    List<MockServer.Recorded> l = requests(method, path);
    if (l.isEmpty()) {
      throw new AssertionError("no request " + method + " " + path + " in " + server.requests());
    }
    return l.get(l.size() - 1);
  }

  static Map<String, String> query(MockServer.Recorded r) {
    Map<String, String> out = new LinkedHashMap<>();
    int q = r.uri().indexOf('?');
    if (q < 0) {
      return out;
    }
    for (String kv : r.uri().substring(q + 1).split("&")) {
      int eq = kv.indexOf('=');
      out.put(
          URLDecoder.decode(kv.substring(0, eq), StandardCharsets.UTF_8),
          URLDecoder.decode(kv.substring(eq + 1), StandardCharsets.UTF_8));
    }
    return out;
  }

  static JsonNode json(MockServer.Recorded r) {
    return Json.tree(r.body().getBytes(StandardCharsets.UTF_8));
  }

  InfisicalConfig.Builder config() {
    return InfisicalConfig.builder()
        .url(server.url())
        .token("tok-identity")
        .projectId("p1")
        .environment("dev")
        .retry(RetryPolicy.builder().maxRetries(0).build());
  }

  InfisicalClient client() {
    return client(b -> {});
  }

  InfisicalClient client(Consumer<InfisicalConfig.Builder> mutate) {
    InfisicalConfig.Builder b = config();
    mutate.accept(b);
    return InfisicalClient.create(b.build());
  }

  @Override
  public void close() {
    server.close();
  }
}
