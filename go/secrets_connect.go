package infisical

// Service-owned: generated once by sdk-kit, then maintained in this repository.

import "context"

// connectSecrets is the LoadConfig connector: Infisical keeps its own variables
// (GROW_INFISICAL_* incl. Universal Auth); GROW_SECRETS_ADDR overrides the URL when set.
func connectSecrets(_ context.Context, b *SecretsBootstrap, env map[string]string) (*SecretsConnection, error) {
	explicit := Config{}
	explicit.URL = b.Addr
	cfg, err := ConfigFromEnvWith(explicit, env)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &SecretsConnection{Provider: client.Secrets(), Close: client.Close}, nil
}
