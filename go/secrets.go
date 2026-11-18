package infisical

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SecretType is the type of a secret: shared (the default) or a user's
// personal override (user JWTs only).
type SecretType string

// Secret types.
const (
	SecretTypeShared   SecretType = "shared"
	SecretTypePersonal SecretType = "personal"
)

// BatchUpdateMode is how UpdateSecrets treats keys that do not exist.
type BatchUpdateMode string

// Batch update modes.
const (
	// BatchModeFailOnNotFound fails the whole batch when a key is missing (server default).
	BatchModeFailOnNotFound BatchUpdateMode = "failOnNotFound"
	// BatchModeUpsert creates missing keys.
	BatchModeUpsert BatchUpdateMode = "upsert"
	// BatchModeIgnore skips missing keys.
	BatchModeIgnore BatchUpdateMode = "ignore"
)

// Tag is a project tag.
type Tag struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name,omitempty"`
	Color     string    `json:"color,omitempty"`
	ProjectID string    `json:"projectId,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitzero"`
	UpdatedAt time.Time `json:"updatedAt,omitzero"`
}

// SecretEntry is a secret as Infisical returns it. Value never prints.
type SecretEntry struct {
	// ID is the secret id (stable across versions and renames).
	ID string `json:"id"`
	// Key is the secret name.
	Key string `json:"key"`
	// Value is the (reference-expanded unless disabled) value; empty when
	// ValueHidden is true or the server omitted it (an update without a new value).
	Value Secret `json:"value"`
	// ValueHidden reports that the server hid the value (viewSecretValue=false or missing permission).
	ValueHidden bool       `json:"valueHidden"`
	Comment     string     `json:"comment,omitempty"`
	Version     int        `json:"version"`
	Type        SecretType `json:"type"`
	ProjectID   string     `json:"projectId,omitempty"`
	Environment string     `json:"environment"`
	// SecretPath is the folder of the secret (for an imported secret Infisical
	// reports the importing path).
	SecretPath            string            `json:"secretPath,omitempty"`
	Tags                  []Tag             `json:"tags"`
	Metadata              map[string]string `json:"metadata,omitempty"`
	SkipMultilineEncoding bool              `json:"skipMultilineEncoding,omitempty"`
	CreatedAt             time.Time         `json:"createdAt,omitzero"`
	UpdatedAt             time.Time         `json:"updatedAt,omitzero"`
}

// ImportedSecrets are the secrets one import contributes to a listing.
type ImportedSecrets struct {
	SecretPath  string        `json:"secretPath"`
	Environment string        `json:"environment"`
	FolderID    string        `json:"folderId,omitempty"`
	Secrets     []SecretEntry `json:"secrets"`
}

// SecretList is the result of ListSecrets.
type SecretList struct {
	// Secrets are the secrets of the path (and of sub-folders when recursive).
	Secrets []SecretEntry `json:"secrets"`
	// Imports are the secrets contributed by secret imports (IncludeImports).
	Imports []ImportedSecrets `json:"imports"`
}

// Merged returns the effective key → secret map: direct secrets win over
// imported ones; with a recursive listing, shallower paths win.
func (l *SecretList) Merged() map[string]SecretEntry {
	out := map[string]SecretEntry{}
	for _, s := range sortedByDepth(l.Secrets) {
		if _, ok := out[s.Key]; !ok {
			out[s.Key] = s
		}
	}
	for _, imp := range l.Imports {
		for _, s := range imp.Secrets {
			if _, ok := out[s.Key]; !ok {
				out[s.Key] = s
			}
		}
	}
	return out
}

func sortedByDepth(in []SecretEntry) []SecretEntry {
	out := append([]SecretEntry(nil), in...)
	depth := func(s SecretEntry) int { return len(pathSegments(s.SecretPath)) }
	for i := 1; i < len(out); i++ { // stable insertion sort by depth
		for j := i; j > 0 && depth(out[j]) < depth(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// --- wire types ---------------------------------------------------------------

type tagJSON struct {
	ID        string   `json:"id"`
	Slug      string   `json:"slug"`
	Name      string   `json:"name"`
	Color     string   `json:"color"`
	ProjectID string   `json:"projectId"`
	CreatedAt flexTime `json:"createdAt"`
	UpdatedAt flexTime `json:"updatedAt"`
}

func (t tagJSON) tag() Tag {
	return Tag{ID: t.ID, Slug: t.Slug, Name: t.Name, Color: t.Color, ProjectID: t.ProjectID,
		CreatedAt: t.CreatedAt.Time, UpdatedAt: t.UpdatedAt.Time}
}

type secretJSON struct {
	ID                    string    `json:"id"`
	Workspace             string    `json:"workspace"`
	Environment           string    `json:"environment"`
	Version               int       `json:"version"`
	Type                  string    `json:"type"`
	SecretKey             string    `json:"secretKey"`
	SecretValue           string    `json:"secretValue"`
	SecretComment         string    `json:"secretComment"`
	SecretValueHidden     bool      `json:"secretValueHidden"`
	SecretPath            string    `json:"secretPath"`
	SkipMultilineEncoding bool      `json:"skipMultilineEncoding"`
	CreatedAt             flexTime  `json:"createdAt"`
	UpdatedAt             flexTime  `json:"updatedAt"`
	Tags                  []tagJSON `json:"tags"`
	SecretMetadata        []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"secretMetadata"`
}

func (c *Client) entry(s secretJSON) SecretEntry {
	e := SecretEntry{
		ID: s.ID, Key: s.SecretKey, ValueHidden: s.SecretValueHidden, Comment: s.SecretComment,
		Version: s.Version, Type: SecretType(s.Type), ProjectID: s.Workspace, Environment: s.Environment,
		SecretPath: s.SecretPath, SkipMultilineEncoding: s.SkipMultilineEncoding,
		CreatedAt: s.CreatedAt.Time, UpdatedAt: s.UpdatedAt.Time, Tags: make([]Tag, 0, len(s.Tags)),
	}
	if !s.SecretValueHidden {
		e.Value = NewSecret(s.SecretValue)
	}
	for _, t := range s.Tags {
		e.Tags = append(e.Tags, t.tag())
	}
	if len(s.SecretMetadata) > 0 {
		e.Metadata = make(map[string]string, len(s.SecretMetadata))
		for _, m := range s.SecretMetadata {
			e.Metadata[m.Key] = m.Value
		}
	}
	return e
}

func (c *Client) entries(in []secretJSON) []SecretEntry {
	out := make([]SecretEntry, 0, len(in))
	for _, s := range in {
		out = append(out, c.entry(s))
	}
	return out
}

// --- API version detection ------------------------------------------------------

func (c *Client) secretsVersion() string {
	c.apiMu.Lock()
	defer c.apiMu.Unlock()
	return c.secretsAPI
}

func (c *Client) setSecretsVersion(v string) {
	c.apiMu.Lock()
	if c.secretsAPI == "" || c.cfg.APIVersion == APIVersionAuto {
		c.secretsAPI = v
	}
	c.apiMu.Unlock()
}

// secretsCall runs a secrets request built for v4 or v3. With automatic
// detection the first call tries v4 and falls back to v3 only when the
// server answers 404 "Route … not found" (a definitive answer, so replaying
// a write is safe); any other answer pins v4.
func (c *Client) secretsCall(ctx context.Context, build func(v3 bool) call, out any) error {
	v := c.secretsVersion()
	r := build(v == APIVersionV3)
	err := c.callJSON(ctx, r, out)
	if v != APIVersionAuto || c.cfg.APIVersion != APIVersionAuto {
		return err
	}
	switch {
	case errors.Is(err, errRouteMissing):
		c.setSecretsVersion(APIVersionV3)
		return c.callJSON(ctx, build(true), out)
	case err == nil:
		c.setSecretsVersion(APIVersionV4)
	default:
		var e *Error
		if errors.As(err, &e) && e.HTTPStatus != 0 {
			c.setSecretsVersion(APIVersionV4)
		}
	}
	return err
}

// secretsPath returns the route for v4 or v3 ("/api/v4/secrets" + suffix).
func secretsPath(v3 bool, suffix string) string {
	if v3 {
		if strings.HasPrefix(suffix, "/batch") {
			return "/api/v3/secrets/batch/raw"
		}
		return "/api/v3/secrets/raw" + suffix
	}
	return "/api/v4/secrets" + suffix
}

// projectField is "projectId" on v4 and "workspaceId" on v3.
func projectField(v3 bool) string {
	if v3 {
		return "workspaceId"
	}
	return "projectId"
}

// importsField is "includeImports" on v4 and "include_imports" on v3.
func importsField(v3 bool) string {
	if v3 {
		return "include_imports"
	}
	return "includeImports"
}

func secretNamePath(name string) string { return "/" + url.PathEscape(name) }

// --- list / get -------------------------------------------------------------------

// ListSecretsOptions select the secrets ListSecrets returns. Empty ProjectID,
// Environment and SecretPath fall back to the client Config.
type ListSecretsOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string
	// Recursive also lists every sub-folder.
	Recursive bool
	// ExpandReferences expands ${KEY} / ${env.path.KEY} references (default true).
	ExpandReferences *bool
	// IncludeImports adds the secrets of secret imports (default true).
	IncludeImports *bool
	// TagSlugs keeps only secrets carrying one of these tags.
	TagSlugs []string
	// ViewSecretValue returns values (default true); false returns metadata only.
	ViewSecretValue *bool
	// IncludePersonalOverrides returns the caller's personal values instead of
	// the shared ones (user JWTs).
	IncludePersonalOverrides bool
}

// ListSecrets lists the secrets of a path (GET /api/v4/secrets, v3 fallback
// GET /api/v3/secrets/raw). A missing environment or path is NOT_FOUND.
func (c *Client) ListSecrets(ctx context.Context, opts *ListSecretsOptions) (*SecretList, error) {
	const op = "secrets.list"
	var o ListSecretsOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.SecretPath)
	if err != nil {
		return nil, err
	}
	var body struct {
		Secrets []secretJSON `json:"secrets"`
		Imports []struct {
			SecretPath  string       `json:"secretPath"`
			Environment string       `json:"environment"`
			FolderID    string       `json:"folderId"`
			Secrets     []secretJSON `json:"secrets"`
		} `json:"imports"`
	}
	build := func(v3 bool) call {
		q := url.Values{}
		q.Set(projectField(v3), s.projectID)
		q.Set("environment", s.environment)
		q.Set("secretPath", s.path)
		q.Set("recursive", boolString(o.Recursive))
		q.Set("expandSecretReferences", boolString(boolDefaultTrue(o.ExpandReferences)))
		q.Set(importsField(v3), boolString(boolDefaultTrue(o.IncludeImports)))
		if len(o.TagSlugs) > 0 {
			q.Set("tagSlugs", strings.Join(o.TagSlugs, ","))
		}
		if !v3 {
			q.Set("viewSecretValue", boolString(boolDefaultTrue(o.ViewSecretValue)))
			if o.IncludePersonalOverrides {
				q.Set("includePersonalOverrides", "true")
			}
		}
		return call{method: http.MethodGet, path: secretsPath(v3, ""), query: q, op: op + " " + s.path}
	}
	if err := c.secretsCall(ctx, build, &body); err != nil {
		return nil, err
	}
	out := &SecretList{Secrets: c.entries(body.Secrets), Imports: make([]ImportedSecrets, 0, len(body.Imports))}
	for _, imp := range body.Imports {
		out.Imports = append(out.Imports, ImportedSecrets{
			SecretPath: imp.SecretPath, Environment: imp.Environment, FolderID: imp.FolderID, Secrets: c.entries(imp.Secrets),
		})
	}
	return out, nil
}

// GetSecretOptions select the secret GetSecret reads.
type GetSecretOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string
	// Version reads an older version (0: the current one).
	Version int
	// Type selects the shared secret (default) or the caller's personal override.
	Type SecretType
	// ExpandReferences expands references (default true).
	ExpandReferences *bool
	// IncludeImports also finds the key through secret imports (default true).
	IncludeImports *bool
	// ViewSecretValue returns the value (default true); false returns metadata only.
	ViewSecretValue *bool
}

// GetSecret reads one secret (GET /api/v4/secrets/{name}, v3 fallback
// GET /api/v3/secrets/raw/{name}). A missing secret or version is NOT_FOUND.
func (c *Client) GetSecret(ctx context.Context, name string, opts *GetSecretOptions) (*SecretEntry, error) {
	const op = "secrets.get"
	if err := requireArg(op, "name", name); err != nil {
		return nil, err
	}
	var o GetSecretOptions
	if opts != nil {
		o = *opts
	}
	if o.Version < 0 {
		return nil, ValidationError(op, "version must be positive")
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.SecretPath)
	if err != nil {
		return nil, err
	}
	var body struct {
		Secret secretJSON `json:"secret"`
	}
	build := func(v3 bool) call {
		q := url.Values{}
		q.Set(projectField(v3), s.projectID)
		q.Set("environment", s.environment)
		q.Set("secretPath", s.path)
		if o.Version > 0 {
			q.Set("version", strconv.Itoa(o.Version))
		}
		if o.Type != "" {
			q.Set("type", string(o.Type))
		}
		q.Set("expandSecretReferences", boolString(boolDefaultTrue(o.ExpandReferences)))
		q.Set(importsField(v3), boolString(boolDefaultTrue(o.IncludeImports)))
		if !v3 {
			q.Set("viewSecretValue", boolString(boolDefaultTrue(o.ViewSecretValue)))
		}
		return call{method: http.MethodGet, path: secretsPath(v3, secretNamePath(name)), query: q, op: op + " " + name}
	}
	if err := c.secretsCall(ctx, build, &body); err != nil {
		return nil, err
	}
	e := c.entry(body.Secret)
	return &e, nil
}

// --- create / update / delete -------------------------------------------------------

// CreateSecretOptions configure CreateSecret.
type CreateSecretOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string
	Comment     string
	// TagIDs attaches tags by id.
	TagIDs []string
	// TagSlugs attaches tags by slug (resolved with ListTags; an unknown slug is NOT_FOUND).
	TagSlugs []string
	// Type creates a personal override (user JWTs only) instead of a shared secret.
	Type SecretType
	// SkipMultilineEncoding stores multi-line values without encoding.
	SkipMultilineEncoding bool
	// Metadata is stored as secret metadata (key/value pairs).
	Metadata map[string]string
}

// CreateSecret creates a secret (POST /api/v4/secrets/{name}). The folder
// must exist (NOT_FOUND otherwise); a duplicate is CONFLICT. Infisical trims
// surrounding whitespace of the value.
func (c *Client) CreateSecret(ctx context.Context, name, value string, opts *CreateSecretOptions) (*SecretEntry, error) {
	const op = "secrets.create"
	if err := requireArg(op, "name", name); err != nil {
		return nil, err
	}
	var o CreateSecretOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.SecretPath)
	if err != nil {
		return nil, err
	}
	tagIDs, err := c.resolveTagIDs(ctx, op, s.projectID, o.TagIDs, o.TagSlugs)
	if err != nil {
		return nil, err
	}
	var body struct {
		Secret secretJSON `json:"secret"`
	}
	build := func(v3 bool) call {
		b := map[string]any{projectField(v3): s.projectID, "environment": s.environment, "secretPath": s.path, "secretValue": value}
		if o.Comment != "" {
			b["secretComment"] = o.Comment
		}
		if tagIDs != nil {
			b["tagIds"] = tagIDs
		}
		if o.Type != "" {
			b["type"] = string(o.Type)
		}
		if o.SkipMultilineEncoding {
			b["skipMultilineEncoding"] = true
		}
		if len(o.Metadata) > 0 {
			b["secretMetadata"] = metadataList(o.Metadata)
		}
		return call{method: http.MethodPost, path: secretsPath(v3, secretNamePath(name)), body: b, op: op + " " + name}
	}
	if err := c.secretsCall(ctx, build, &body); err != nil {
		return nil, err
	}
	e := c.entry(body.Secret)
	return &e, nil
}

func metadataList(m map[string]string) []map[string]string {
	keys := sortedKeys(m)
	out := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]string{"key": k, "value": m[k]})
	}
	return out
}

// UpdateSecretOptions configure UpdateSecret; nil / empty fields stay unchanged.
type UpdateSecretOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string
	// Value is the new value.
	Value *string
	// NewName renames the secret.
	NewName string
	// Comment replaces the comment.
	Comment *string
	// TagIDs replaces the tag set (a non-nil empty slice removes every tag).
	TagIDs []string
	// TagSlugs replaces the tag set by slug (merged with TagIDs).
	TagSlugs []string
	// Type updates the caller's personal override instead of the shared secret.
	Type SecretType
	// SkipMultilineEncoding changes the multi-line encoding flag.
	SkipMultilineEncoding *bool
	// Metadata replaces the secret metadata.
	Metadata map[string]string
}

// UpdateSecret changes a secret (PATCH /api/v4/secrets/{name}): value,
// name, comment and tags. Every update bumps the version. When no new value
// is sent the returned Value is empty (the server does not echo it).
func (c *Client) UpdateSecret(ctx context.Context, name string, opts *UpdateSecretOptions) (*SecretEntry, error) {
	const op = "secrets.update"
	if err := requireArg(op, "name", name); err != nil {
		return nil, err
	}
	var o UpdateSecretOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.SecretPath)
	if err != nil {
		return nil, err
	}
	tagIDs, err := c.resolveTagIDs(ctx, op, s.projectID, o.TagIDs, o.TagSlugs)
	if err != nil {
		return nil, err
	}
	var body struct {
		Secret secretJSON `json:"secret"`
	}
	build := func(v3 bool) call {
		b := map[string]any{projectField(v3): s.projectID, "environment": s.environment, "secretPath": s.path}
		if o.Value != nil {
			b["secretValue"] = *o.Value
		}
		if o.NewName != "" {
			b["newSecretName"] = o.NewName
		}
		if o.Comment != nil {
			b["secretComment"] = *o.Comment
		}
		if tagIDs != nil {
			b["tagIds"] = tagIDs
		}
		if o.Type != "" {
			b["type"] = string(o.Type)
		}
		if o.SkipMultilineEncoding != nil {
			b["skipMultilineEncoding"] = *o.SkipMultilineEncoding
		}
		if o.Metadata != nil {
			b["secretMetadata"] = metadataList(o.Metadata)
		}
		return call{method: http.MethodPatch, path: secretsPath(v3, secretNamePath(name)), body: b, op: op + " " + name}
	}
	if err := c.secretsCall(ctx, build, &body); err != nil {
		return nil, err
	}
	e := c.entry(body.Secret)
	return &e, nil
}

// DeleteSecretOptions configure DeleteSecret.
type DeleteSecretOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string
	// Type deletes the caller's personal override instead of the shared secret.
	Type SecretType
}

// DeleteSecret deletes a secret with all its versions
// (DELETE /api/v4/secrets/{name}); a missing secret is NOT_FOUND.
func (c *Client) DeleteSecret(ctx context.Context, name string, opts *DeleteSecretOptions) (*SecretEntry, error) {
	const op = "secrets.delete"
	if err := requireArg(op, "name", name); err != nil {
		return nil, err
	}
	var o DeleteSecretOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.SecretPath)
	if err != nil {
		return nil, err
	}
	var body struct {
		Secret secretJSON `json:"secret"`
	}
	build := func(v3 bool) call {
		b := map[string]any{projectField(v3): s.projectID, "environment": s.environment, "secretPath": s.path}
		if o.Type != "" {
			b["type"] = string(o.Type)
		}
		return call{method: http.MethodDelete, path: secretsPath(v3, secretNamePath(name)), body: b, op: op + " " + name}
	}
	if err := c.secretsCall(ctx, build, &body); err != nil {
		return nil, err
	}
	e := c.entry(body.Secret)
	return &e, nil
}

// --- batch --------------------------------------------------------------------------

// SecretInput is one secret of CreateSecrets.
type SecretInput struct {
	Key                   string
	Value                 string
	Comment               string
	TagIDs                []string
	SkipMultilineEncoding bool
	Metadata              map[string]string
}

// SecretUpdate is one secret of UpdateSecrets; nil / empty fields stay unchanged.
type SecretUpdate struct {
	Key string
	// Value is the new value.
	Value *string
	// NewName renames the secret.
	NewName string
	// Comment replaces the comment.
	Comment *string
	// TagIDs replaces the tag set (non-nil empty removes every tag).
	TagIDs []string
	// SkipMultilineEncoding changes the multi-line encoding flag.
	SkipMultilineEncoding *bool
}

// BatchScope selects where a batch operation runs; empty fields fall back
// to the client Config.
type BatchScope struct {
	ProjectID   string
	Environment string
	SecretPath  string
}

// UpdateSecretsOptions configure UpdateSecrets.
type UpdateSecretsOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string
	// Mode is failOnNotFound (server default), upsert or ignore.
	Mode BatchUpdateMode
}

// DeleteSecretsOptions configure DeleteSecrets.
type DeleteSecretsOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string
	// Type deletes personal overrides instead of shared secrets.
	Type SecretType
}

func (c *Client) batch(ctx context.Context, op, method string, s scope, extra map[string]any, items []map[string]any) ([]SecretEntry, error) {
	var body struct {
		Secrets []secretJSON `json:"secrets"`
	}
	build := func(v3 bool) call {
		b := map[string]any{projectField(v3): s.projectID, "environment": s.environment, "secretPath": s.path, "secrets": items}
		for k, v := range extra {
			b[k] = v
		}
		return call{method: method, path: secretsPath(v3, "/batch"), body: b, op: op + " " + s.path}
	}
	if err := c.secretsCall(ctx, build, &body); err != nil {
		return nil, err
	}
	return c.entries(body.Secrets), nil
}

// CreateSecrets creates several secrets atomically (POST /api/v4/secrets/batch):
// one duplicate fails the batch with CONFLICT and nothing is created. The
// result order is not guaranteed.
func (c *Client) CreateSecrets(ctx context.Context, secrets []SecretInput, opts *BatchScope) ([]SecretEntry, error) {
	const op = "secrets.createBatch"
	if len(secrets) == 0 {
		return nil, ValidationError(op, "at least one secret is required")
	}
	var o BatchScope
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.SecretPath)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(secrets))
	for _, in := range secrets {
		if err := requireArg(op, "key", in.Key); err != nil {
			return nil, err
		}
		m := map[string]any{"secretKey": in.Key, "secretValue": in.Value}
		if in.Comment != "" {
			m["secretComment"] = in.Comment
		}
		if in.TagIDs != nil {
			m["tagIds"] = in.TagIDs
		}
		if in.SkipMultilineEncoding {
			m["skipMultilineEncoding"] = true
		}
		if len(in.Metadata) > 0 {
			m["secretMetadata"] = metadataList(in.Metadata)
		}
		items = append(items, m)
	}
	return c.batch(ctx, op, http.MethodPost, s, nil, items)
}

// UpdateSecrets updates several secrets atomically (PATCH /api/v4/secrets/batch).
// With the default mode a missing key fails the batch with NOT_FOUND.
func (c *Client) UpdateSecrets(ctx context.Context, secrets []SecretUpdate, opts *UpdateSecretsOptions) ([]SecretEntry, error) {
	const op = "secrets.updateBatch"
	if len(secrets) == 0 {
		return nil, ValidationError(op, "at least one secret is required")
	}
	var o UpdateSecretsOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.SecretPath)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(secrets))
	for _, in := range secrets {
		if err := requireArg(op, "key", in.Key); err != nil {
			return nil, err
		}
		m := map[string]any{"secretKey": in.Key}
		if in.Value != nil {
			m["secretValue"] = *in.Value
		}
		if in.NewName != "" {
			m["newSecretName"] = in.NewName
		}
		if in.Comment != nil {
			m["secretComment"] = *in.Comment
		}
		if in.TagIDs != nil {
			m["tagIds"] = in.TagIDs
		}
		if in.SkipMultilineEncoding != nil {
			m["skipMultilineEncoding"] = *in.SkipMultilineEncoding
		}
		items = append(items, m)
	}
	var extra map[string]any
	if o.Mode != "" {
		extra = map[string]any{"mode": string(o.Mode)}
	}
	return c.batch(ctx, op, http.MethodPatch, s, extra, items)
}

// DeleteSecrets deletes several secrets atomically (DELETE /api/v4/secrets/batch):
// one missing key fails the batch with NOT_FOUND and nothing is deleted.
func (c *Client) DeleteSecrets(ctx context.Context, keys []string, opts *DeleteSecretsOptions) ([]SecretEntry, error) {
	const op = "secrets.deleteBatch"
	if len(keys) == 0 {
		return nil, ValidationError(op, "at least one key is required")
	}
	var o DeleteSecretsOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.SecretPath)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		if err := requireArg(op, "key", k); err != nil {
			return nil, err
		}
		m := map[string]any{"secretKey": k}
		if o.Type != "" {
			m["type"] = string(o.Type)
		}
		items = append(items, m)
	}
	return c.batch(ctx, op, http.MethodDelete, s, nil, items)
}
