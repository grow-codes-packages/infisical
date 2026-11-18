// Command example shows the Infisical Go SDK against a real server:
// configuration from the environment (Universal Auth), health, a secret round
// trip, folders, the SecretsProvider and dotenv export.
//
//	GROW_INFISICAL_URL=http://127.0.0.1:8080 \
//	INFISICAL_CLIENT_ID=... INFISICAL_CLIENT_SECRET=... \
//	INFISICAL_PROJECT_ID=... INFISICAL_ENVIRONMENT=dev go run .
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	infisical "github.com/grow-codes-packages/infisical/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := infisical.ConfigFromEnv()
	if err != nil {
		return err // CONFIG error naming the variable, never its value
	}
	fmt.Println("config:", cfg) // credentials print as [REDACTED]

	client, err := infisical.NewClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("health: healthy=%t status=%s\n", health.Healthy, health.Status)

	if _, err := client.Ping(ctx); errors.Is(err, infisical.ErrAuthentication) {
		return fmt.Errorf("check INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET: %w", err)
	} else if err != nil {
		return err
	}

	// A secret round trip in a folder of its own.
	folder := fmt.Sprintf("example-%d", time.Now().Unix())
	created, err := client.CreateFolder(ctx, folder, nil)
	if err != nil {
		return err
	}
	path := "/" + folder
	if _, err := client.CreateSecret(ctx, "DATABASE_URL", "postgres://db:5432/app", &infisical.CreateSecretOptions{
		SecretPath: path, Comment: "created by the Go example",
	}); err != nil {
		return err
	}
	if _, err := client.UpdateSecret(ctx, "DATABASE_URL", &infisical.UpdateSecretOptions{
		SecretPath: path, Value: infisical.String("postgres://db:5432/app2"),
	}); err != nil {
		return err
	}
	secret, err := client.GetSecret(ctx, "DATABASE_URL", &infisical.GetSecretOptions{SecretPath: path})
	if err != nil {
		return err
	}
	fmt.Printf("secret %s version %d: %s\n", secret.Key, secret.Version, secret.Value) // value prints as [REDACTED]

	// The SecretsProvider: names are "<folder>/<KEY>", Set creates folders.
	secrets := client.Secrets()
	if _, err := secrets.Set(ctx, folder+"/feature/ENABLED", "yes", nil); err != nil {
		return err
	}
	enabled, ok, err := secrets.GetBool(ctx, folder+"/feature/ENABLED", nil)
	if err != nil {
		return err
	}
	fmt.Println("feature enabled:", enabled, ok)

	dotenv, err := client.ExportDotenv(ctx, &infisical.EnvOptions{SecretPath: path})
	if err != nil {
		return err
	}
	fmt.Printf("dotenv export: %d bytes\n", len(dotenv))

	// Clean up.
	if _, err := client.DeleteFolder(ctx, created.ID, &infisical.DeleteFolderOptions{Force: true}); err != nil {
		return err
	}
	fmt.Println("done; secrets API version:", client.APIVersion("secrets"))
	return nil
}
