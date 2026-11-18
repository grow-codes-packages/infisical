package infisical

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// SecretsProviderOptions configure a ProjectSecretsProvider. Zero values fall
// back to the client Config.
type SecretsProviderOptions struct {
	// ProjectID is the project (default Config.ProjectID).
	ProjectID string
	// Environment is the environment slug (default Config.Environment).
	Environment string
	// BasePath is the folder names are relative to (default Config.SecretPath).
	BasePath string
	// ExpandReferences expands references on reads (default true).
	ExpandReferences *bool
	// IncludeImports finds keys through secret imports on Get and GetAll (default true).
	IncludeImports *bool
}

// ProjectSecretsProvider is the SecretsProvider (SPEC §3) over one Infisical
// project and environment.
//
// Model: a name may contain "/": the last segment is the secret key, the rest
// is the folder below BasePath ("app/db/PASSWORD" → path "<BasePath>/app/db",
// key "PASSWORD"). GetOptions.Path / SetOptions.Path / DeleteOptions.Path
// replace BasePath. Set creates missing folders, updates an existing secret
// and returns the new version; values are UTF-8 text (other bytes are a
// VALIDATION error) and Infisical trims surrounding whitespace. Versions are
// the Infisical version numbers as strings. Delete is always permanent and
// removes every version (DeleteOptions.Versions / Permanent are UNSUPPORTED,
// as is SetOptions.CAS). SetOptions.Tags keys are tag slugs (created when
// missing, with the value as the color when it starts with "#");
// SecretMetadata.Tags maps slug → name.
type ProjectSecretsProvider struct {
	*BaseSecretsProvider
	prims *infisicalPrimitives
}

func newProjectSecretsProvider(c *Client, o SecretsProviderOptions) *ProjectSecretsProvider {
	if o.BasePath == "" {
		o.BasePath = c.cfg.SecretPath
	}
	o.BasePath = normalizePath(o.BasePath)
	prims := &infisicalPrimitives{c: c, opts: o}
	return &ProjectSecretsProvider{BaseSecretsProvider: NewSecretsProvider(prims), prims: prims}
}

// Options returns the effective provider options.
func (p *ProjectSecretsProvider) Options() SecretsProviderOptions { return p.prims.opts }

type infisicalPrimitives struct {
	c    *Client
	opts SecretsProviderOptions
}

var _ SecretPrimitives = (*infisicalPrimitives)(nil)

// locate splits name into its folder path and key.
func (p *infisicalPrimitives) locate(op, name, override string) (path, key string, err error) {
	base := p.opts.BasePath
	if override != "" {
		base = normalizePath(override)
	}
	dir, key := "", name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		dir, key = name[:i], name[i+1:]
	}
	if strings.TrimSpace(key) == "" {
		return "", "", ValidationError(op, "secret name must end with a key")
	}
	return joinPath(base, dir), key, nil
}

func (p *infisicalPrimitives) getOptions(path string, o GetOptions, view bool) (*GetSecretOptions, error) {
	g := &GetSecretOptions{
		ProjectID: p.opts.ProjectID, Environment: p.opts.Environment, SecretPath: path,
		ExpandReferences: Bool(boolDefaultTrue(p.opts.ExpandReferences)), IncludeImports: Bool(boolDefaultTrue(p.opts.IncludeImports)),
		ViewSecretValue: Bool(view),
	}
	if o.Version != "" {
		n, err := strconv.Atoi(o.Version)
		if err != nil || n <= 0 {
			return nil, ValidationError("secrets.get", "version must be a positive integer")
		}
		g.Version = n
	}
	return g, nil
}

// FetchSecret implements SecretPrimitives.
func (p *infisicalPrimitives) FetchSecret(ctx context.Context, name string, opts GetOptions) (*SecretValue, error) {
	path, key, err := p.locate("secrets.get", name, opts.Path)
	if err != nil {
		return nil, err
	}
	g, err := p.getOptions(path, opts, true)
	if err != nil {
		return nil, err
	}
	s, err := p.c.GetSecret(ctx, key, g)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return NewSecretString(s.Value.Reveal(), strconv.Itoa(s.Version)), nil
}

// FetchMetadata implements SecretPrimitives (the value is not transferred).
func (p *infisicalPrimitives) FetchMetadata(ctx context.Context, name string, opts GetOptions) (*SecretMetadata, error) {
	path, key, err := p.locate("secrets.metadata", name, opts.Path)
	if err != nil {
		return nil, err
	}
	g, err := p.getOptions(path, opts, false)
	if err != nil {
		return nil, err
	}
	s, err := p.c.GetSecret(ctx, key, g)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	md := metadataOf(name, *s)
	return &md, nil
}

func metadataOf(name string, s SecretEntry) SecretMetadata {
	md := SecretMetadata{
		Name: name, Path: s.SecretPath, Version: strconv.Itoa(s.Version), CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
		Versions: s.Version, Tags: map[string]string{},
		Extra: map[string]string{"id": s.ID, "type": string(s.Type), "environment": s.Environment},
	}
	if s.Comment != "" {
		md.Extra["comment"] = s.Comment
	}
	for _, t := range s.Tags {
		v := t.Name
		if v == "" {
			v = t.Slug
		}
		md.Tags[t.Slug] = v
	}
	return md
}

// ListSecrets implements SecretPrimitives. prefixOrPath is a folder below
// BasePath ("app/" or "app"); when no such folder exists it is treated as a
// key prefix inside its parent folder ("app/DB_" lists keys starting with
// DB_ in "app"). Names in the result resolve with Get.
func (p *infisicalPrimitives) ListSecrets(ctx context.Context, prefixOrPath string) ([]SecretMetadata, error) {
	rel := strings.Trim(prefixOrPath, "/")
	mds, err := p.listFolder(ctx, rel, "")
	if err == nil || !isNotFound(err) || rel == "" || strings.HasSuffix(prefixOrPath, "/") {
		if isNotFound(err) {
			return []SecretMetadata{}, nil
		}
		return mds, err
	}
	dir, keyPrefix := "", rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		dir, keyPrefix = rel[:i], rel[i+1:]
	}
	mds, err = p.listFolder(ctx, dir, keyPrefix)
	if isNotFound(err) {
		return []SecretMetadata{}, nil
	}
	return mds, err
}

func (p *infisicalPrimitives) listFolder(ctx context.Context, rel, keyPrefix string) ([]SecretMetadata, error) {
	list, err := p.c.ListSecrets(ctx, &ListSecretsOptions{
		ProjectID: p.opts.ProjectID, Environment: p.opts.Environment, SecretPath: joinPath(p.opts.BasePath, rel),
		ExpandReferences: Bool(false), IncludeImports: Bool(false), ViewSecretValue: Bool(false),
	})
	if err != nil {
		return nil, err
	}
	out := make([]SecretMetadata, 0, len(list.Secrets))
	for _, s := range list.Secrets {
		if !strings.HasPrefix(s.Key, keyPrefix) || s.Type == SecretTypePersonal {
			continue
		}
		name := s.Key
		if rel != "" {
			name = rel + "/" + s.Key
		}
		out = append(out, metadataOf(name, s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// PutSecret implements SecretPrimitives: create, or update when the key
// exists; missing folders are created.
func (p *infisicalPrimitives) PutSecret(ctx context.Context, name string, value []byte, opts SetOptions) (string, error) {
	const op = "secrets.set"
	if opts.CAS != nil {
		return "", UnsupportedError(op, "Infisical has no check-and-set")
	}
	if !utf8.Valid(value) {
		return "", ValidationError(op, "Infisical stores text only; the value is not valid UTF-8")
	}
	path, key, err := p.locate(op, name, opts.Path)
	if err != nil {
		return "", err
	}
	var tagIDs []string
	if len(opts.Tags) > 0 {
		if tagIDs, err = p.ensureTags(ctx, opts.Tags); err != nil {
			return "", err
		}
	}
	text := string(value)
	create := &CreateSecretOptions{ProjectID: p.opts.ProjectID, Environment: p.opts.Environment, SecretPath: path,
		Comment: opts.Description, TagIDs: tagIDs}
	s, err := p.c.CreateSecret(ctx, key, text, create)
	if isNotFound(err) && strings.Contains(strings.ToLower(err.Error()), "folder") {
		if ferr := p.ensureFolders(ctx, path); ferr != nil {
			return "", ferr
		}
		s, err = p.c.CreateSecret(ctx, key, text, create)
	}
	if errors.Is(err, ErrConflict) {
		upd := &UpdateSecretOptions{ProjectID: p.opts.ProjectID, Environment: p.opts.Environment, SecretPath: path,
			Value: &text, TagIDs: tagIDs}
		if opts.Description != "" {
			upd.Comment = &opts.Description
		}
		s, err = p.c.UpdateSecret(ctx, key, upd)
	}
	if err != nil {
		return "", err
	}
	return strconv.Itoa(s.Version), nil
}

// ensureFolders creates every folder of path that does not exist yet.
func (p *infisicalPrimitives) ensureFolders(ctx context.Context, path string) error {
	parent := "/"
	for _, seg := range pathSegments(path) {
		_, err := p.c.CreateFolder(ctx, seg, &CreateFolderOptions{ProjectID: p.opts.ProjectID, Environment: p.opts.Environment, Path: parent})
		if err != nil && !errors.Is(err, ErrConflict) {
			return err
		}
		parent = joinPath(parent, seg)
	}
	return nil
}

// ensureTags resolves tag slugs to ids, creating missing tags.
func (p *infisicalPrimitives) ensureTags(ctx context.Context, tags map[string]string) ([]string, error) {
	existing, err := p.c.ListTags(ctx, &ProjectOptions{ProjectID: p.opts.ProjectID})
	if err != nil {
		return nil, err
	}
	bySlug := map[string]string{}
	for _, t := range existing {
		bySlug[t.Slug] = t.ID
	}
	ids := make([]string, 0, len(tags))
	for _, slug := range sortedKeys(tags) {
		if id, ok := bySlug[slug]; ok {
			ids = append(ids, id)
			continue
		}
		color := ""
		if strings.HasPrefix(tags[slug], "#") {
			color = tags[slug]
		}
		t, err := p.c.CreateTag(ctx, slug, color, &ProjectOptions{ProjectID: p.opts.ProjectID})
		if err != nil {
			return nil, err
		}
		ids = append(ids, t.ID)
	}
	return ids, nil
}

// RemoveSecret implements SecretPrimitives; a missing secret is NOT_FOUND.
func (p *infisicalPrimitives) RemoveSecret(ctx context.Context, name string, opts DeleteOptions) error {
	const op = "secrets.delete"
	if len(opts.Versions) > 0 || opts.Permanent {
		return UnsupportedError(op, "Infisical always deletes a secret permanently with all its versions")
	}
	path, key, err := p.locate(op, name, opts.Path)
	if err != nil {
		return err
	}
	_, err = p.c.DeleteSecret(ctx, key, &DeleteSecretOptions{ProjectID: p.opts.ProjectID, Environment: p.opts.Environment, SecretPath: path})
	return err
}

// GetAll implements SecretsProvider with one listing: every secret directly
// under path (plus imported keys when IncludeImports is on; direct secrets win).
func (p *ProjectSecretsProvider) GetAll(ctx context.Context, path string) (map[string]*SecretValue, error) {
	rel := strings.Trim(path, "/")
	list, err := p.prims.c.ListSecrets(ctx, &ListSecretsOptions{
		ProjectID: p.prims.opts.ProjectID, Environment: p.prims.opts.Environment,
		SecretPath:       joinPath(p.prims.opts.BasePath, rel),
		ExpandReferences: Bool(boolDefaultTrue(p.prims.opts.ExpandReferences)),
		IncludeImports:   Bool(boolDefaultTrue(p.prims.opts.IncludeImports)),
	})
	if isNotFound(err) {
		return map[string]*SecretValue{}, nil
	}
	if err != nil {
		return nil, err
	}
	merged := list.Merged()
	out := make(map[string]*SecretValue, len(merged))
	for key, s := range merged {
		name := key
		if rel != "" {
			name = rel + "/" + key
		}
		out[name] = NewSecretString(s.Value.Reveal(), strconv.Itoa(s.Version))
	}
	return out, nil
}
