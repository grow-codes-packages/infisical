// Package infisical is the Grow Codes SDK for Infisical.
//
// Create a client from the environment (GROW_INFISICAL_URL,
// GROW_INFISICAL_TOKEN, ...) or from a Config literal:
//
//	client, err := infisical.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, infisical.ErrNotFound)). Credentials are wrapped in
// Secret and never appear in errors, hooks or logs.
//
// Infisical is a trademark of Infisical, Inc.. This package is not affiliated
// with or endorsed by Infisical, Inc..
package infisical
