package infisical

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bool returns a pointer to v (for optional boolean options).
func Bool(v bool) *bool { return &v }

// String returns a pointer to v (for optional string options).
func String(v string) *string { return &v }

// boolDefaultTrue returns *p, or true when p is nil.
func boolDefaultTrue(p *bool) bool {
	if p == nil {
		return true
	}
	return *p
}

func boolString(v bool) string { return strconv.FormatBool(v) }

// normalizePath returns an absolute secret path without a trailing slash
// ("" and "/" give "/"; "a//b/" gives "/a/b").
func normalizePath(p string) string {
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}

// joinPath joins secret path segments into a normalized absolute path.
func joinPath(parts ...string) string { return normalizePath(strings.Join(parts, "/")) }

// pathSegments returns the folder names of a normalized path.
func pathSegments(p string) []string {
	p = strings.Trim(normalizePath(p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// flexTime decodes ISO-8601 strings and null (zero time).
type flexTime struct{ time.Time }

func (t *flexTime) UnmarshalJSON(b []byte) error {
	t.Time = time.Time{}
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if v, err := time.Parse(time.RFC3339Nano, s); err == nil {
		t.Time = v.UTC()
	}
	return nil
}

// --- error capture and mapping ------------------------------------------------

// errorBody is the Infisical error response body.
type errorBody struct {
	ReqID      string          `json:"reqId"`
	StatusCode int             `json:"statusCode"`
	Message    json.RawMessage `json:"message"`
	Error      string          `json:"error"`
}

// errorInfo is what the capture transport learned from the last error response.
type errorInfo struct {
	status  int
	name    string
	message string
}

// errorCapture collects the error body of the last attempt of one call.
type errorCapture struct {
	mu   sync.Mutex
	info *errorInfo
}

func (c *errorCapture) set(i *errorInfo) {
	c.mu.Lock()
	c.info = i
	c.mu.Unlock()
}

func (c *errorCapture) get() *errorInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info
}

type captureKey struct{}

// maxErrorBody bounds how much of an error response is inspected.
const maxErrorBody = 64 << 10

// captureTransport wraps the HTTP transport: for error responses it reads the
// Infisical error body, exposes its reqId as X-Request-Id (Infisical sends no
// request id header) and hands the error name and message to the call's
// errorCapture. The body is restored unchanged.
type captureTransport struct{ next http.RoundTripper }

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil || resp.StatusCode < 400 {
		return resp, err
	}
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if rerr == nil {
		inspectErrorBody(req, resp, data)
	}
	return resp, nil
}

// inspectErrorBody records the Infisical error body of resp for the call.
func inspectErrorBody(req *http.Request, resp *http.Response, data []byte) {
	var body errorBody
	if json.Unmarshal(data, &body) != nil {
		return
	}
	if body.ReqID != "" && resp.Header.Get("X-Request-Id") == "" {
		resp.Header.Set("X-Request-Id", body.ReqID)
	}
	if c, ok := req.Context().Value(captureKey{}).(*errorCapture); ok {
		c.set(&errorInfo{status: resp.StatusCode, name: body.Error, message: messageText(body.Message)})
	}
}

// CloseIdleConnections forwards to the wrapped transport.
func (t *captureTransport) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// messageText turns the "message" field (a string or a zod issue array) into text.
func messageText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var issues []map[string]any
	if json.Unmarshal(raw, &issues) == nil {
		parts := make([]string, 0, len(issues))
		for _, is := range issues {
			msg, _ := is["message"].(string)
			if p, ok := is["path"].([]any); ok && len(p) > 0 {
				segs := make([]string, len(p))
				for i, v := range p {
					segs[i] = strings.Trim(string(mustJSON(v)), `"`)
				}
				msg = strings.Join(segs, ".") + ": " + msg
			}
			if msg != "" {
				parts = append(parts, msg)
			}
		}
		return strings.Join(parts, "; ")
	}
	return string(raw)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// errRouteMissing marks a 404 for a route the server does not have (the
// signal for the v4 → v3 secrets API fallback).
var errRouteMissing = errors.New("api route not found on this server")

var retryInSeconds = regexp.MustCompile(`(?i)try again in (\d+) seconds?`)

// mapError rebuilds a status error from the captured Infisical error body and
// applies the Infisical rules on top of SPEC §2.1:
//
//   - 400 whose message contains "already exists" is CONFLICT (Infisical never uses 409 for duplicates);
//   - 403 with error "TokenError" (malformed token, bad signature) is AUTHENTICATION;
//   - 404 with error "Not Found" and a message starting with "Route " is a
//     missing API route: UNSUPPORTED, wrapping errRouteMissing;
//   - 429 without Retry-After takes the wait from "try again in N seconds".
func (c *Client) mapError(op string, err error, capture *errorCapture) error {
	var e *Error
	if !errors.As(err, &e) || e.HTTPStatus == 0 {
		return err
	}
	info := capture.get()
	if info == nil || info.status != e.HTTPStatus {
		return e
	}
	ne := StatusError(op, e.HTTPStatus, e.RequestID, info.message, c.transport.knownSecrets())
	ne.RetryAfter = e.RetryAfter
	lower := strings.ToLower(info.message)
	switch e.HTTPStatus {
	case http.StatusBadRequest:
		if strings.Contains(lower, "already exists") {
			ne.Code = ErrorCodeConflict
		}
	case http.StatusForbidden:
		if info.name == "TokenError" {
			ne.Code = ErrorCodeAuthentication
		}
	case http.StatusNotFound:
		if info.name == "Not Found" && strings.HasPrefix(info.message, "Route ") {
			ne.Code = ErrorCodeUnsupported
			ne.Message = op + ": the server does not offer this API route (HTTP 404)"
			ne.Err = errRouteMissing
		}
	case http.StatusTooManyRequests:
		if ne.RetryAfter == 0 {
			if m := retryInSeconds.FindStringSubmatch(info.message); m != nil {
				n, _ := strconv.Atoi(m[1])
				ne.RetryAfter = time.Duration(n) * time.Second
			}
		}
	}
	ne.Retryable = ne.Code.Retryable()
	return ne
}

func withCapture(ctx context.Context) (context.Context, *errorCapture) {
	c := &errorCapture{}
	return context.WithValue(ctx, captureKey{}, c), c
}

// requireArg returns a VALIDATION error when value is blank.
func requireArg(op, name, value string) error {
	if strings.TrimSpace(value) == "" {
		return ValidationError(op, name+" is required")
	}
	return nil
}
