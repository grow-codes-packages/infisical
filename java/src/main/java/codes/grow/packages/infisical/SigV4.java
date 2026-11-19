package codes.grow.packages.infisical;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** AWS Signature Version 4, as used by {@link AwsIamAuth} to sign the STS request. */
public final class SigV4 {
  private static final DateTimeFormatter AMZ_DATE =
      DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
  private static final DateTimeFormatter DATE =
      DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

  private SigV4() {}

  /**
   * A request to sign.
   *
   * @param method HTTP method
   * @param host host name
   * @param path URI path, already URI-encoded ({@code /} when empty)
   * @param query raw query string, already encoded (may be empty)
   * @param headers headers to sign in addition to {@code Host} and {@code X-Amz-Date}
   * @param body request body
   * @param region AWS region
   * @param service AWS service ({@code sts})
   * @param accessKeyId signing access key id
   * @param secretAccessKey signing secret access key
   * @param time signing time
   */
  public record Request(
      String method,
      String host,
      String path,
      String query,
      Map<String, String> headers,
      byte[] body,
      String region,
      String service,
      String accessKeyId,
      String secretAccessKey,
      Instant time) {
    @Override
    public boolean equals(Object o) {
      return o instanceof Request && toString().equals(o.toString());
    }

    @Override
    public int hashCode() {
      return toString().hashCode();
    }

    @Override
    public String toString() {
      return "SigV4.Request{" + method + " " + host + path + " region=" + region + "}";
    }
  }

  /**
   * Signs a request and returns every header to send: the given headers plus {@code Host}, {@code
   * X-Amz-Date} and {@code Authorization}.
   *
   * @param r the request
   * @return the headers to send
   */
  public static Map<String, String> sign(Request r) {
    String amzDate = AMZ_DATE.format(r.time());
    String date = DATE.format(r.time());
    Map<String, String> out = new LinkedHashMap<>(r.headers());
    boolean hasHost = out.keySet().stream().anyMatch(k -> k.equalsIgnoreCase("host"));
    if (!hasHost) {
      out.put("Host", r.host());
    }
    out.put("X-Amz-Date", amzDate);
    TreeMap<String, String> canon = new TreeMap<>();
    out.forEach(
        (k, v) -> canon.put(k.toLowerCase(Locale.ROOT), String.join(" ", v.trim().split("\\s+"))));
    StringBuilder canonHeaders = new StringBuilder();
    canon.forEach((k, v) -> canonHeaders.append(k).append(':').append(v).append('\n'));
    String signedHeaders = String.join(";", canon.keySet());
    String path = r.path() == null || r.path().isEmpty() ? "/" : r.path();
    String canonical =
        String.join(
            "\n",
            r.method(),
            path,
            canonicalQuery(r.query()),
            canonHeaders.toString(),
            signedHeaders,
            hex(sha256(r.body() == null ? new byte[0] : r.body())));
    String scope = date + "/" + r.region() + "/" + r.service() + "/aws4_request";
    String toSign =
        "AWS4-HMAC-SHA256\n"
            + amzDate
            + "\n"
            + scope
            + "\n"
            + hex(sha256(canonical.getBytes(StandardCharsets.UTF_8)));
    byte[] key = hmac(("AWS4" + r.secretAccessKey()).getBytes(StandardCharsets.UTF_8), date);
    key = hmac(key, r.region());
    key = hmac(key, r.service());
    key = hmac(key, "aws4_request");
    String sig = hex(hmac(key, toSign));
    out.put(
        "Authorization",
        "AWS4-HMAC-SHA256 Credential="
            + r.accessKeyId()
            + "/"
            + scope
            + ", SignedHeaders="
            + signedHeaders
            + ", Signature="
            + sig);
    return out;
  }

  static String canonicalQuery(String q) {
    if (q == null || q.isEmpty()) {
      return "";
    }
    List<String> parts = new ArrayList<>(Arrays.asList(q.split("&")));
    parts.sort(null);
    return String.join("&", parts);
  }

  static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  static byte[] hmac(byte[] key, String data) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA256 unavailable", e);
    }
  }

  static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) {
      sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
    }
    return sb.toString();
  }
}
