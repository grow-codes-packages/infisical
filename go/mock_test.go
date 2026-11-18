package infisical

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	testProject = "d4ac094e-aa12-4d7f-96ab-1ebb84162b30"
	testEnv     = "dev"
)

// recorded is one request seen by the mock server.
type recorded struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   map[string]any
}

// reply is a mock response.
type reply struct {
	status int
	body   any
	header map[string]string
}

type handlerFunc func(r *recorded) reply

// mockServer routes "METHOD /path" to handlers; unknown routes answer like
// Infisical: 404 {"error":"Not Found","message":"Route … not found"}.
type mockServer struct {
	*httptest.Server
	mu     sync.Mutex
	routes map[string]handlerFunc
	reqs   []*recorded
}

func newMock(t *testing.T) *mockServer {
	t.Helper()
	m := &mockServer{routes: map[string]handlerFunc{}}
	m.Server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.Close)
	return m
}

func (m *mockServer) serve(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	rec := &recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone()}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &rec.Body)
	}
	m.mu.Lock()
	m.reqs = append(m.reqs, rec)
	h, ok := m.routes[r.Method+" "+r.URL.Path]
	m.mu.Unlock()
	rep := reply{status: 404, body: map[string]any{
		"reqId": "req-route", "statusCode": 404, "error": "Not Found",
		"message": "Route " + r.Method + ":" + r.URL.RequestURI() + " not found",
	}}
	if ok {
		rep = h(rec)
	}
	for k, v := range rep.header {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rep.status)
	switch b := rep.body.(type) {
	case nil:
	case []byte:
		_, _ = w.Write(b)
	case string:
		_, _ = w.Write([]byte(b))
	default:
		_ = json.NewEncoder(w).Encode(b)
	}
}

func (m *mockServer) on(method, path string, h handlerFunc) {
	m.mu.Lock()
	m.routes[method+" "+path] = h
	m.mu.Unlock()
}

// json answers status with body.
func (m *mockServer) json(method, path string, status int, body any) {
	m.on(method, path, func(*recorded) reply { return reply{status: status, body: body} })
}

// fixture answers with a recorded fixture (status + body).
func (m *mockServer) fixture(t *testing.T, method, path, name string) {
	t.Helper()
	status, body := loadFixture(t, name)
	m.on(method, path, func(*recorded) reply { return reply{status: status, body: body} })
}

func (m *mockServer) requests(method, path string) []*recorded {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*recorded
	for _, r := range m.reqs {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func (m *mockServer) last(t *testing.T, method, path string) *recorded {
	t.Helper()
	rs := m.requests(method, path)
	if len(rs) == 0 {
		t.Fatalf("no %s %s request", method, path)
	}
	return rs[len(rs)-1]
}

func (m *mockServer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reqs)
}

// loadFixture returns the status and raw body of testdata/fixtures/<name>.json.
func loadFixture(t *testing.T, name string) (int, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixtures", name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	var f struct {
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return f.Status, f.Body
}

// errBody is an Infisical error body.
func errBody(status int, name, message string) map[string]any {
	return map[string]any{"reqId": "req-test", "statusCode": status, "error": name, "message": message}
}

// newMockClient builds a client against m with a static token, project and environment.
func newMockClient(t *testing.T, m *mockServer, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		CommonConfig: CommonConfig{URL: m.URL, Retry: fastRetry(2)},
		Token:        NewSecret(testToken), ProjectID: testProject, Environment: testEnv,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func wantCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	_ = wantErr(t, err, code)
}

// wantErr asserts err is an *Error with code and returns it.
func wantErr(t *testing.T, err error, code ErrorCode) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want %s error, got %v", code, err)
	}
	if e.Code != code {
		t.Fatalf("want %s, got %s (%v)", code, e.Code, err)
	}
	return e
}

func bg() context.Context { return context.Background() }

func str(v any) string {
	s, _ := v.(string)
	return s
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
