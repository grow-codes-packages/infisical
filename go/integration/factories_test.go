package integration

import (
	"context"
	"strings"
	"testing"

	infisical "github.com/grow-codes-packages/infisical/go"
	"github.com/grow-codes-packages/infisical/go/testkit"
)

// capabilities the deployment under test offers (see conformance "requires").
// "version" is left out on purpose: Infisical exposes no server version
// (ServerVersion is UNSUPPORTED, docs/compatibility.md).
var capabilities = []string{"write", "delete", "versions"}

// categories runs "core" plus this service's categories.
func categories() []string {
	return append([]string{"core"}, strings.Split("secrets", ",")...)
}

// factories builds the conformance targets from the bootstrap environment
// (Universal Auth machine identity, project and environment from /bootstrap/env).
func factories(t *testing.T) testkit.Factories {
	t.Helper()
	return testkit.Factories{
		"core": testkit.CoreFactory(func(context.Context) (testkit.CoreTarget, error) {
			return infisical.NewClientFromEnv()
		}),
		"secrets": testkit.SecretsFactory(func(context.Context) (infisical.SecretsProvider, error) {
			c, err := infisical.NewClientFromEnv()
			if err != nil {
				return nil, err
			}
			t.Cleanup(func() { _ = c.Close() })
			return c.Secrets(), nil
		}),
	}
}
