//! Request plumbing, Infisical error mapping and tolerant response parsing shared by the
//! service modules.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::core::redact::truncate;
use crate::core::{Error, ErrorCode, Method, Result, Secret};

/// Longest vendor error text kept in messages (same limit as the core transport).
const MAX_VENDOR_MESSAGE: usize = 300;

/// Statuses whose Infisical error body the client reads itself (the transport handles
/// 429, 5xx and the remaining 4xx statuses with retries and the SPEC mapping).
pub(crate) const BODY_MAPPED_STATUSES: [u16; 6] = [400, 401, 403, 404, 409, 422];

/// One Infisical API call; `path` is absolute (`/api/v4/secrets`).
#[derive(Debug, Clone)]
pub(crate) struct Call {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    pub op: String,
    /// Sends no `Authorization` header (login, renew, revoke: any bearer there makes
    /// Infisical answer 403 `TokenError`).
    pub no_auth: bool,
    /// Overrides the managed token for this call.
    pub token: Option<Secret>,
}

impl Call {
    pub fn new(method: Method, path: impl Into<String>, op: impl Into<String>) -> Self {
        Call {
            method,
            path: path.into(),
            query: Vec::new(),
            body: None,
            op: op.into(),
            no_auth: false,
            token: None,
        }
    }
    pub fn get(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self::new(Method::GET, path, op)
    }
    pub fn post(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self::new(Method::POST, path, op)
    }
    pub fn patch(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self::new(Method::PATCH, path, op)
    }
    pub fn delete(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self::new(Method::DELETE, path, op)
    }
    pub fn query(mut self, name: &str, value: impl Into<String>) -> Self {
        self.query.push((name.to_owned(), value.into()));
        self
    }
    pub fn json(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }
    pub fn no_auth(mut self) -> Self {
        self.no_auth = true;
        self
    }
}

/// Marker cause of an `UNSUPPORTED` error for a route the server does not have (the signal
/// for the v4 → v3 secrets API fallback).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RouteMissing;

impl fmt::Display for RouteMissing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("api route not found on this server")
    }
}

impl std::error::Error for RouteMissing {}

/// Whether `err` reports a missing API route.
pub(crate) fn is_route_missing(err: &Error) -> bool {
    err.cause()
        .is_some_and(|c| c.downcast_ref::<RouteMissing>().is_some())
}

/// The parts of an Infisical error body (`{"reqId","statusCode","message","error"}`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ErrorBody {
    pub req_id: String,
    pub name: String,
    pub message: String,
}

impl ErrorBody {
    pub fn parse(body: &[u8]) -> ErrorBody {
        let Ok(v) = serde_json::from_slice::<Value>(body) else {
            let text = String::from_utf8_lossy(body);
            let first = text.trim().lines().next().unwrap_or("").to_owned();
            let message = if first.starts_with('<') {
                String::new()
            } else {
                first
            };
            return ErrorBody {
                message,
                ..ErrorBody::default()
            };
        };
        ErrorBody {
            req_id: s(&v, "reqId"),
            name: s(&v, "error"),
            message: message_text(v.get("message")),
        }
    }
}

/// Turns the `message` field (a string or a zod issue array) into text.
pub(crate) fn message_text(raw: Option<&Value>) -> String {
    match raw {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(issues)) => issues
            .iter()
            .filter_map(|issue| {
                let msg = s(issue, "message");
                let path: Vec<String> = match issue.get("path") {
                    Some(Value::Array(p)) => p
                        .iter()
                        .map(|seg| match seg {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                let msg = if path.is_empty() {
                    msg
                } else {
                    format!("{}: {msg}", path.join("."))
                };
                (!msg.is_empty()).then_some(msg)
            })
            .collect::<Vec<_>>()
            .join("; "),
        Some(other) => other.to_string(),
    }
}

/// Builds the SDK error for an Infisical error response and applies the Infisical rules on
/// top of SPEC §2.1:
///
/// - 400 whose message contains `already exists` is `CONFLICT` (Infisical never uses 409
///   for duplicates);
/// - 403 with error `TokenError` (malformed token, bad signature, stray bearer on login) is
///   `AUTHENTICATION`;
/// - 404 with error `Not Found` and a message starting with `Route ` is a missing API route:
///   `UNSUPPORTED` caused by [`RouteMissing`].
///
/// `redact` scrubs known secrets from the vendor text.
pub(crate) fn map_error_body(
    op: &str,
    status: u16,
    body: &[u8],
    redact: impl Fn(&str) -> String,
) -> Error {
    let parsed = ErrorBody::parse(body);
    let lower = parsed.message.to_ascii_lowercase();
    let mut code = ErrorCode::from_http_status(status).unwrap_or(ErrorCode::Unavailable);
    let mut err = None;
    match status {
        400 if lower.contains("already exists") => code = ErrorCode::Conflict,
        403 if parsed.name == "TokenError" => code = ErrorCode::Authentication,
        404 if parsed.name == "Not Found" && parsed.message.starts_with("Route ") => {
            err = Some(
                Error::unsupported(format!(
                    "{op}: the server does not offer this API route (HTTP 404)"
                ))
                .with_source(RouteMissing),
            );
        }
        _ => {}
    }
    let err = err.unwrap_or_else(|| {
        let reason = if parsed.message.trim().is_empty() {
            code.reason().to_owned()
        } else {
            let text = truncate(&redact(parsed.message.trim()), MAX_VENDOR_MESSAGE);
            format!("{}: {text}", code.reason())
        };
        Error::new(code, format!("{op}: {reason} (HTTP {status})"))
    });
    let err = err.with_status(status);
    if parsed.req_id.is_empty() {
        err
    } else {
        err.with_request_id(parsed.req_id)
    }
}

/// Adds the wait of a 429 message (`try again in N seconds`) when `Retry-After` was absent.
pub(crate) fn rate_limit_hint(err: Error) -> Error {
    if err.code() != ErrorCode::RateLimited || err.retry_after().is_some() {
        return err;
    }
    let lower = err.message().to_ascii_lowercase();
    let Some(idx) = lower.find("try again in ") else {
        return err;
    };
    let digits: String = lower[idx + "try again in ".len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    match digits.parse::<u64>() {
        Ok(n) => err.with_retry_after(Duration::from_secs(n)),
        Err(_) => err,
    }
}

/// `VALIDATION` error `"<op>: <reason>"`.
pub(crate) fn invalid(op: &str, reason: &str) -> Error {
    Error::validation(format!("{op}: {reason}"))
}

/// `VALIDATION` error when `value` is blank.
pub(crate) fn require_arg(op: &str, name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(op, &format!("{name} is required")));
    }
    Ok(())
}

/// Percent-encodes one path segment (RFC 3986 unreserved characters, `:` and `@` are kept).
pub(crate) fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// An absolute secret path without a trailing slash (`""`/`"/"` → `"/"`, `"a//b/"` → `"/a/b"`).
pub fn normalize_path(path: &str) -> String {
    let parts: Vec<&str> = path
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    format!("/{}", parts.join("/"))
}

/// Joins secret path parts into a normalized absolute path.
pub(crate) fn join_path(parts: &[&str]) -> String {
    normalize_path(&parts.join("/"))
}

/// The folder names of a path.
pub(crate) fn path_segments(path: &str) -> Vec<String> {
    normalize_path(path)
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `Some(non-empty)` or `None`.
pub(crate) fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.trim().is_empty())
}

// --- tolerant field readers -------------------------------------------------

/// String field (numbers and booleans are rendered; missing/null → `""`).
pub(crate) fn s(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// Unsigned integer field (numbers or numeric strings; otherwise 0).
pub(crate) fn u(v: &Value, key: &str) -> u64 {
    match v.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
            .unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// Boolean field (`true` or the string `"true"`).
pub(crate) fn b(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Array field (missing/null → empty).
pub(crate) fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    match v.get(key) {
        Some(Value::Array(items)) => items,
        _ => &[],
    }
}

/// Timestamp field (RFC 3339 text); empty and null → `None`.
pub(crate) fn time(v: &Value, key: &str) -> Option<SystemTime> {
    match v.get(key)? {
        Value::String(s) => parse_rfc3339(s.trim()),
        _ => None,
    }
}

/// `[{key, value}]` metadata list → map.
pub(crate) fn metadata_map(v: &Value, key: &str) -> BTreeMap<String, String> {
    arr(v, key)
        .iter()
        .map(|m| (s(m, "key"), s(m, "value")))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// Map → `[{key, value}]` metadata list (sorted by key).
pub(crate) fn metadata_list(m: &BTreeMap<String, String>) -> Value {
    Value::Array(
        m.iter()
            .map(|(k, v)| serde_json::json!({"key": k, "value": v}))
            .collect(),
    )
}

/// Parses an RFC 3339 timestamp (`2026-11-18T19:30:00.123Z`, offsets allowed).
pub(crate) fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<i64> { text.get(a..b)?.parse().ok() };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, min, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let mut rest = &text[19..];
    let mut nanos: u64 = 0;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let mut scaled = frac[..digits.min(9)].to_owned();
        while scaled.len() < 9 {
            scaled.push('0');
        }
        nanos = scaled.parse().ok()?;
        rest = &frac[digits..];
    }
    let offset_secs: i64 = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) => {
            let h: i64 = rest.get(1..3)?.parse().ok()?;
            let m: i64 = rest.get(4..6)?.parse().ok()?;
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            sign * (h * 3600 + m * 60)
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let total = days * 86_400 + hour * 3600 + min * 60 + sec - offset_secs;
    if total < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(total as u64) + Duration::from_nanos(nanos))
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc3339_parsing() {
        let t = parse_rfc3339("1970-01-02T00:00:01.5Z").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap(),
            Duration::from_millis(86_401_500)
        );
        let t = parse_rfc3339("2026-11-18T19:30:00.123456789123+01:00").unwrap();
        let z = parse_rfc3339("2026-11-18T18:30:00.123456789Z").unwrap();
        assert_eq!(t, z);
        let neg = parse_rfc3339("2026-11-18T18:30:00-00:30").unwrap();
        assert_eq!(neg.duration_since(z).unwrap().as_secs(), 1799);
        for bad in [
            "",
            "2026-11-18",
            "2026/11/18T18:30:00Z",
            "2026-13-18T18:30:00Z",
            "2026-11-18T18:30:00.Z",
            "2026-11-18T18:30:00+0100",
            "2026-11-18T18:30:00",
            "1900-01-01T00:00:00Z",
        ] {
            assert!(parse_rfc3339(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn field_readers() {
        let v = json!({
            "s": "x", "n": 5, "f": 2.7, "neg": -1.0, "t": true, "ts": "TRUE", "ns": "7",
            "list": [1, 2], "t1": "1970-01-02T00:00:00Z", "t2": 5,
            "md": [{"key": "a", "value": "1"}, {"key": "", "value": "x"}]
        });
        assert_eq!(s(&v, "s"), "x");
        assert_eq!(s(&v, "n"), "5");
        assert_eq!(s(&v, "t"), "true");
        assert_eq!(s(&v, "missing"), "");
        assert_eq!(u(&v, "n"), 5);
        assert_eq!(u(&v, "f"), 2);
        assert_eq!(u(&v, "neg"), 0);
        assert_eq!(u(&v, "ns"), 7);
        assert_eq!(u(&v, "t"), 0);
        assert!(b(&v, "t") && b(&v, "ts") && !b(&v, "n"));
        assert_eq!(arr(&v, "list").len(), 2);
        assert!(arr(&v, "s").is_empty());
        assert!(time(&v, "t1").is_some());
        assert!(time(&v, "t2").is_none());
        assert!(time(&v, "missing").is_none());
        let md = metadata_map(&v, "md");
        assert_eq!(md.len(), 1);
        assert_eq!(metadata_list(&md), json!([{"key": "a", "value": "1"}]));
    }

    #[test]
    fn paths_and_args() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("a//b/ "), "/a/b");
        assert_eq!(join_path(&["/base/", "x/y"]), "/base/x/y");
        assert_eq!(path_segments("/a/b"), vec!["a", "b"]);
        assert!(path_segments("/").is_empty());
        assert_eq!(encode_segment("A b:/é@?"), "A%20b:%2F%C3%A9@%3F");
        assert_eq!(non_empty(Some(" ")), None);
        assert_eq!(non_empty(Some("x")), Some("x"));
        assert!(require_arg("op", "name", " ").is_err());
        assert!(require_arg("op", "name", "x").is_ok());
        assert_eq!(
            RouteMissing.to_string(),
            "api route not found on this server"
        );
    }

    #[test]
    fn error_bodies() {
        let id = |t: &str| t.to_owned();
        let e = map_error_body(
            "op",
            400,
            br#"{"reqId":"req-1","message":"Secret 'X' already exists","error":"BadRequest"}"#,
            id,
        );
        assert_eq!(e.code(), ErrorCode::Conflict);
        assert_eq!(e.request_id(), Some("req-1"));
        assert_eq!(e.http_status(), Some(400));
        assert!(e.message().starts_with("op: conflict: Secret"));
        let e = map_error_body("op", 400, br#"{"message":"nope"}"#, id);
        assert_eq!(e.code(), ErrorCode::Validation);
        assert_eq!(e.request_id(), None);
        let e = map_error_body(
            "op",
            403,
            br#"{"message":"malformed","error":"TokenError"}"#,
            id,
        );
        assert_eq!(e.code(), ErrorCode::Authentication);
        let e = map_error_body(
            "op",
            403,
            br#"{"message":"no","error":"PermissionDenied"}"#,
            id,
        );
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
        let e = map_error_body(
            "op",
            404,
            br#"{"message":"Route GET:/api/v5 not found","error":"Not Found"}"#,
            id,
        );
        assert_eq!(e.code(), ErrorCode::Unsupported);
        assert!(is_route_missing(&e));
        let e = map_error_body("op", 404, br#"{"message":"gone","error":"NotFound"}"#, id);
        assert_eq!(e.code(), ErrorCode::NotFound);
        assert!(!is_route_missing(&e));
        let e = map_error_body(
            "op",
            422,
            br#"{"message":[{"message":"bad","path":["a",0]},{"message":"worse"},{"path":["x"]}],"error":"ValidationFailure"}"#,
            id,
        );
        assert_eq!(e.code(), ErrorCode::Validation);
        assert!(e.message().contains("a.0: bad; worse"), "{}", e.message());
        let e = map_error_body("op", 401, b"", id);
        assert_eq!(e.message(), "op: authentication failed (HTTP 401)");
        let e = map_error_body("op", 401, b"plain text\nmore", id);
        assert!(e.message().contains("plain text"));
        let e = map_error_body("op", 401, b"<html>", id);
        assert_eq!(e.message(), "op: authentication failed (HTTP 401)");
        let e = map_error_body("op", 409, br#"{"message":{"x":1}}"#, |t| {
            t.replace('1', "#")
        });
        assert_eq!(e.code(), ErrorCode::Conflict);
        assert!(e.message().contains("{\"x\":#}"));
        assert_eq!(message_text(Some(&Value::Null)), "");
    }

    #[test]
    fn rate_limit_hints() {
        let e = rate_limit_hint(Error::from_status(
            429,
            "op: rate limited: Rate limit exceeded. Please try again in 7 seconds (HTTP 429)",
        ));
        assert_eq!(e.retry_after(), Some(Duration::from_secs(7)));
        let kept = rate_limit_hint(
            Error::from_status(429, "try again in 7 seconds")
                .with_retry_after(Duration::from_secs(1)),
        );
        assert_eq!(kept.retry_after(), Some(Duration::from_secs(1)));
        assert!(rate_limit_hint(Error::from_status(429, "slow down"))
            .retry_after()
            .is_none());
        assert!(
            rate_limit_hint(Error::from_status(429, "try again in soon"))
                .retry_after()
                .is_none()
        );
        assert!(
            rate_limit_hint(Error::from_status(404, "try again in 3 seconds"))
                .retry_after()
                .is_none()
        );
    }
}
