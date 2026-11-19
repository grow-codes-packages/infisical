package infisical

import (
	"context"
	"os"
	"sort"
	"strings"
)

// EnvOptions select the secrets LoadEnv and ExportDotenv use. Empty
// ProjectID, Environment and SecretPath fall back to the client Config.
type EnvOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string
	// Recursive includes every sub-folder (shallower paths win on duplicate keys).
	Recursive bool
	// IncludeImports includes secrets of secret imports (default true; direct
	// secrets win over imported ones).
	IncludeImports *bool
	// ExpandReferences expands references (default true).
	ExpandReferences *bool
	// Override replaces variables that are already set (LoadEnv only).
	Override bool
}

// envSecrets lists the effective key → value map of a scope.
func (c *Client) envSecrets(ctx context.Context, o EnvOptions) (map[string]string, error) {
	list, err := c.ListSecrets(ctx, &ListSecretsOptions{
		ProjectID: o.ProjectID, Environment: o.Environment, SecretPath: o.SecretPath, Recursive: o.Recursive,
		IncludeImports: Bool(boolDefaultTrue(o.IncludeImports)), ExpandReferences: Bool(boolDefaultTrue(o.ExpandReferences)),
	})
	if err != nil {
		return nil, err
	}
	merged := list.Merged()
	out := make(map[string]string, len(merged))
	for k, s := range merged {
		out[k] = s.Value.Reveal()
	}
	return out, nil
}

// LoadEnv sets one process environment variable per secret of a path (like
// "infisical run"): the variable name is the secret key unchanged. Existing
// variables are kept unless Override is set. It returns the variables it set
// as env name → secret key (never values), like SecretsProvider.LoadEnv.
func (c *Client) LoadEnv(ctx context.Context, opts *EnvOptions) (map[string]string, error) {
	var o EnvOptions
	if opts != nil {
		o = *opts
	}
	values, err := c.envSecrets(ctx, o)
	if err != nil {
		return nil, err
	}
	set := make(map[string]string, len(values))
	for _, k := range sortedKeys(values) {
		if _, exists := os.LookupEnv(k); exists && !o.Override {
			continue
		}
		if err := os.Setenv(k, values[k]); err != nil {
			return set, ValidationError("loadEnv", "variable "+k+" cannot be set")
		}
		set[k] = k
	}
	return set, nil
}

// ExportDotenv renders the secrets of a path as a dotenv document: one
// KEY="value" line per secret, sorted by key, with \, ", newline and
// carriage return escaped. The result contains secret values: handle it
// like a secret.
func (c *Client) ExportDotenv(ctx context.Context, opts *EnvOptions) (string, error) {
	var o EnvOptions
	if opts != nil {
		o = *opts
	}
	values, err := c.envSecrets(ctx, o)
	if err != nil {
		return "", err
	}
	return FormatDotenv(values), nil
}

// FormatDotenv renders key → value pairs as a dotenv document (see ExportDotenv).
func FormatDotenv(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + `="` + r.Replace(values[k]) + "\"\n")
	}
	return b.String()
}
