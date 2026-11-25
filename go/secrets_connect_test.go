package infisical

// Service-owned: generated once by sdk-kit, then maintained in this repository.

import (
	"context"
	"errors"
	"testing"
)

// TestConnectSecretsDefault checks the connector without network I/O: it either returns a
// provider or reports UNSUPPORTED.
func TestConnectSecretsDefault(t *testing.T) {
	conn, err := connectSecrets(context.Background(), &SecretsBootstrap{Addr: "http://127.0.0.1:1"}, map[string]string{})
	if err != nil {
		if !errors.Is(err, ErrUnsupported) && !errors.Is(err, ErrConfig) {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if conn.Provider == nil {
		t.Fatal("nil provider")
	}
	if conn.Close != nil {
		_ = conn.Close()
	}
}

// TestLoadConfigThroughConnector is the GRO-1410 regression: LoadConfig with the default
// connector reads GROW_SECRETS_PATH from the server named by GROW_SECRETS_ADDR, using the
// package variables from the given environment.
func TestLoadConfigThroughConnector(t *testing.T) {
	m := newMock(t)
	secret := func(key, value string) map[string]any {
		return map[string]any{
			"id": "id-" + key, "secretKey": key, "secretValue": value, "version": 1,
			"type": "shared", "environment": "dev", "secretPath": "/services/orders",
			"secretComment": "", "createdAt": "2026-11-18T20:28:13.931Z",
			"updatedAt": "2026-11-18T20:28:13.931Z", "tags": []any{},
		}
	}
	m.json("GET", "/api/v4/secrets", 200, map[string]any{
		"secrets": []any{secret("DATABASE_URL", "postgres://db"), secret("LOG_LEVEL", "debug")},
		"imports": []any{},
	})
	env := map[string]string{
		"GROW_SECRETS_PROVIDER":      "infisical",
		"GROW_SECRETS_ADDR":          m.URL,
		"GROW_SECRETS_PATH":          "services/orders",
		"GROW_INFISICAL_URL":         "http://127.0.0.1:1",
		"GROW_INFISICAL_TOKEN":       "identity-token-value",
		"GROW_INFISICAL_PROJECT_ID":  "proj-1",
		"GROW_INFISICAL_ENVIRONMENT": "dev",
		"GROW_INFISICAL_MAX_RETRIES": "0",
	}
	values, err := LoadConfig(context.Background(), LoadOptions{Env: env, Required: []string{"DATABASE_URL"}, IntoEnv: true})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(values) != 2 || values["DATABASE_URL"] != "postgres://db" || values["LOG_LEVEL"] != "debug" {
		t.Fatalf("values = %v", values)
	}
	if env["DATABASE_URL"] != "postgres://db" {
		t.Fatalf("env not written: %v", env["DATABASE_URL"])
	}
	q := m.last(t, "GET", "/api/v4/secrets").Query
	if q.Get("secretPath") != "/services/orders" || q.Get("projectId") != "proj-1" || q.Get("environment") != "dev" {
		t.Fatalf("query = %v", q)
	}
}
