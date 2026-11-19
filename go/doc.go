// Package infisical is the Grow Codes SDK for Infisical.
//
// Create a client from the environment (GROW_INFISICAL_URL or
// INFISICAL_API_URL, INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET or
// INFISICAL_TOKEN, INFISICAL_PROJECT_ID, INFISICAL_ENVIRONMENT, …) or from a
// Config literal:
//
//	client, err := infisical.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	secret, err := client.GetSecret(ctx, "DATABASE_URL", nil)
//	if err != nil {
//		return err
//	}
//	dsn := secret.Value.Reveal()
//
// Authentication: Universal Auth (client id + secret, tokens renewed at 80 %
// of their lifetime and re-obtained when needed), static tokens (TokenAuth:
// machine identity, user JWT or legacy service token), Kubernetes Auth and
// AWS IAM Auth (SigV4-signed STS request). See Config and Auth.
//
// Service functions are client methods: secrets (ListSecrets, GetSecret,
// CreateSecret, UpdateSecret, DeleteSecret, CreateSecrets, UpdateSecrets,
// DeleteSecrets; v4 API with a run-time v3 fallback), folders, projects and
// environments, tags, secret imports, secret versions, LoadEnv and
// ExportDotenv. Client.Secrets returns the SecretsProvider of the Grow
// secrets interface (Get, GetString, Set, List, LoadEnv, Watch, …).
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, infisical.ErrNotFound)). Infisical answers
// duplicates with HTTP 400 "already exists" (CONFLICT here) and malformed
// tokens with 403 TokenError (AUTHENTICATION here). Credentials and secret
// values are wrapped in Secret and never appear in errors, hooks or logs.
//
// Infisical is a trademark of Infisical, Inc. This package is not affiliated
// with or endorsed by Infisical, Inc.
package infisical
