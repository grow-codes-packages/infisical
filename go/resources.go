package infisical

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// DefaultTagColor is the color CreateTag uses when none is given.
const DefaultTagColor = "#bec2c8"

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- folders (v2) ----------------------------------------------------------------

// Folder is a secret folder.
type Folder struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Path is the absolute path of the folder (create/update responses).
	Path string `json:"path,omitempty"`
	// RelativePath is the path below the listed path (recursive listings).
	RelativePath  string    `json:"relativePath,omitempty"`
	Version       int       `json:"version"`
	EnvironmentID string    `json:"environmentId,omitempty"`
	ParentID      string    `json:"parentId,omitempty"`
	CreatedAt     time.Time `json:"createdAt,omitzero"`
	UpdatedAt     time.Time `json:"updatedAt,omitzero"`
}

type folderJSON struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  *string  `json:"description"`
	Path         string   `json:"path"`
	RelativePath string   `json:"relativePath"`
	Version      int      `json:"version"`
	EnvID        string   `json:"envId"`
	ParentID     string   `json:"parentId"`
	CreatedAt    flexTime `json:"createdAt"`
	UpdatedAt    flexTime `json:"updatedAt"`
}

func (f folderJSON) folder() Folder {
	out := Folder{ID: f.ID, Name: f.Name, Path: f.Path, RelativePath: f.RelativePath, Version: f.Version,
		EnvironmentID: f.EnvID, ParentID: f.ParentID, CreatedAt: f.CreatedAt.Time, UpdatedAt: f.UpdatedAt.Time}
	if f.Description != nil {
		out.Description = *f.Description
	}
	return out
}

// FolderOptions select the parent path of a folder operation; empty fields
// fall back to the client Config (Path to Config.SecretPath).
type FolderOptions struct {
	ProjectID   string
	Environment string
	// Path is the parent path (default Config.SecretPath).
	Path string
}

// ListFoldersOptions configure ListFolders.
type ListFoldersOptions struct {
	ProjectID   string
	Environment string
	Path        string
	// Recursive lists every descendant (each with RelativePath).
	Recursive bool
}

// ListFolders lists the folders under a path (GET /api/v2/folders).
func (c *Client) ListFolders(ctx context.Context, opts *ListFoldersOptions) ([]Folder, error) {
	const op = "folders.list"
	var o ListFoldersOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.Path)
	if err != nil {
		return nil, err
	}
	q := url.Values{"projectId": {s.projectID}, "environment": {s.environment}, "path": {s.path}}
	if o.Recursive {
		q.Set("recursive", "true")
	}
	var body struct {
		Folders []folderJSON `json:"folders"`
	}
	if err := c.callJSON(ctx, call{method: http.MethodGet, path: "/api/v2/folders", query: q, op: op + " " + s.path}, &body); err != nil {
		return nil, err
	}
	out := make([]Folder, 0, len(body.Folders))
	for _, f := range body.Folders {
		out = append(out, f.folder())
	}
	return out, nil
}

// CreateFolderOptions configure CreateFolder.
type CreateFolderOptions struct {
	ProjectID   string
	Environment string
	// Path is the parent path (default Config.SecretPath).
	Path        string
	Description string
}

// CreateFolder creates a folder under a path (POST /api/v2/folders). Names
// allow letters, digits, "-" and "_" (VALIDATION otherwise); a duplicate is CONFLICT.
func (c *Client) CreateFolder(ctx context.Context, name string, opts *CreateFolderOptions) (*Folder, error) {
	const op = "folders.create"
	if err := requireArg(op, "name", name); err != nil {
		return nil, err
	}
	var o CreateFolderOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.Path)
	if err != nil {
		return nil, err
	}
	b := map[string]any{"projectId": s.projectID, "environment": s.environment, "name": name, "path": s.path}
	if o.Description != "" {
		b["description"] = o.Description
	}
	var body struct {
		Folder folderJSON `json:"folder"`
	}
	if err := c.callJSON(ctx, call{method: http.MethodPost, path: "/api/v2/folders", body: b, op: op + " " + name}, &body); err != nil {
		return nil, err
	}
	f := body.Folder.folder()
	return &f, nil
}

// UpdateFolderOptions configure UpdateFolder.
type UpdateFolderOptions struct {
	ProjectID   string
	Environment string
	// Path is the parent path of the folder (default Config.SecretPath).
	Path string
	// Name is the (new) folder name; required by the server.
	Name        string
	Description *string
}

// UpdateFolder renames a folder or changes its description
// (PATCH /api/v2/folders/{id}); an unknown id is NOT_FOUND.
func (c *Client) UpdateFolder(ctx context.Context, folderID string, opts *UpdateFolderOptions) (*Folder, error) {
	const op = "folders.update"
	if err := requireArg(op, "folderId", folderID); err != nil {
		return nil, err
	}
	var o UpdateFolderOptions
	if opts != nil {
		o = *opts
	}
	if err := requireArg(op, "name", o.Name); err != nil {
		return nil, err
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.Path)
	if err != nil {
		return nil, err
	}
	b := map[string]any{"projectId": s.projectID, "environment": s.environment, "name": o.Name, "path": s.path}
	if o.Description != nil {
		b["description"] = *o.Description
	}
	var body struct {
		Folder folderJSON `json:"folder"`
	}
	r := call{method: http.MethodPatch, path: "/api/v2/folders/" + url.PathEscape(folderID), body: b, op: op + " " + folderID}
	if err := c.callJSON(ctx, r, &body); err != nil {
		return nil, err
	}
	f := body.Folder.folder()
	return &f, nil
}

// DeleteFolderOptions configure DeleteFolder.
type DeleteFolderOptions struct {
	ProjectID   string
	Environment string
	// Path is the parent path of the folder (default Config.SecretPath).
	Path string
	// Force deletes a folder that still holds secrets or folders.
	Force bool
}

// DeleteFolder deletes a folder by id or name (DELETE /api/v2/folders/{idOrName});
// a missing folder is NOT_FOUND.
func (c *Client) DeleteFolder(ctx context.Context, folderIDOrName string, opts *DeleteFolderOptions) (*Folder, error) {
	const op = "folders.delete"
	if err := requireArg(op, "folderIdOrName", folderIDOrName); err != nil {
		return nil, err
	}
	var o DeleteFolderOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.Path)
	if err != nil {
		return nil, err
	}
	b := map[string]any{"projectId": s.projectID, "environment": s.environment, "path": s.path}
	if o.Force {
		b["forceDelete"] = true
	}
	var body struct {
		Folder folderJSON `json:"folder"`
	}
	r := call{method: http.MethodDelete, path: "/api/v2/folders/" + url.PathEscape(folderIDOrName), body: b, op: op + " " + folderIDOrName}
	if err := c.callJSON(ctx, r, &body); err != nil {
		return nil, err
	}
	f := body.Folder.folder()
	return &f, nil
}

// --- projects + environments (v1) ---------------------------------------------------

// Environment is a project environment.
type Environment struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Position  int       `json:"position,omitempty"`
	ProjectID string    `json:"projectId,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitzero"`
	UpdatedAt time.Time `json:"updatedAt,omitzero"`
}

type environmentJSON struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Slug      string   `json:"slug"`
	Position  int      `json:"position"`
	ProjectID string   `json:"projectId"`
	CreatedAt flexTime `json:"createdAt"`
	UpdatedAt flexTime `json:"updatedAt"`
}

func (e environmentJSON) environment() Environment {
	return Environment{ID: e.ID, Name: e.Name, Slug: e.Slug, Position: e.Position, ProjectID: e.ProjectID,
		CreatedAt: e.CreatedAt.Time, UpdatedAt: e.UpdatedAt.Time}
}

// Project is an Infisical project.
type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	// Type is the product type ("secret-manager", …).
	Type  string `json:"type"`
	OrgID string `json:"orgId"`
	// Environments are ordered by position.
	Environments []Environment `json:"environments"`
	CreatedAt    time.Time     `json:"createdAt,omitzero"`
	UpdatedAt    time.Time     `json:"updatedAt,omitzero"`
}

type projectJSON struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Slug         string            `json:"slug"`
	Description  *string           `json:"description"`
	Type         string            `json:"type"`
	OrgID        string            `json:"orgId"`
	Environments []environmentJSON `json:"environments"`
	CreatedAt    flexTime          `json:"createdAt"`
	UpdatedAt    flexTime          `json:"updatedAt"`
}

func (p projectJSON) project() Project {
	out := Project{ID: p.ID, Name: p.Name, Slug: p.Slug, Type: p.Type, OrgID: p.OrgID,
		CreatedAt: p.CreatedAt.Time, UpdatedAt: p.UpdatedAt.Time, Environments: make([]Environment, 0, len(p.Environments))}
	if p.Description != nil {
		out.Description = *p.Description
	}
	for _, e := range p.Environments {
		out.Environments = append(out.Environments, e.environment())
	}
	return out
}

// ListProjectsOptions configure ListProjects.
type ListProjectsOptions struct {
	// Type filters by product type (default "secret-manager").
	Type string
	// Limit is the page size (1–100; 0 uses the server default).
	Limit int
	// Offset skips projects.
	Offset int
}

// ProjectPage is one page of ListProjects.
type ProjectPage struct {
	Projects []Project `json:"projects"`
	// TotalCount is the number of projects visible to the caller.
	TotalCount int `json:"totalCount"`
}

// ListProjects lists the projects the caller is a member of (GET /api/v1/projects).
func (c *Client) ListProjects(ctx context.Context, opts *ListProjectsOptions) (*ProjectPage, error) {
	const op = "projects.list"
	var o ListProjectsOptions
	if opts != nil {
		o = *opts
	}
	if o.Limit < 0 || o.Limit > 100 || o.Offset < 0 {
		return nil, ValidationError(op, "limit must be 1–100 and offset >= 0")
	}
	q := url.Values{}
	q.Set("type", "secret-manager")
	if o.Type != "" {
		q.Set("type", o.Type)
	}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.Offset > 0 {
		q.Set("offset", strconv.Itoa(o.Offset))
	}
	var body struct {
		Projects   []projectJSON `json:"projects"`
		TotalCount int           `json:"totalCount"`
	}
	if err := c.callJSON(ctx, call{method: http.MethodGet, path: "/api/v1/projects", query: q, op: op}, &body); err != nil {
		return nil, err
	}
	page := &ProjectPage{Projects: make([]Project, 0, len(body.Projects)), TotalCount: body.TotalCount}
	for _, p := range body.Projects {
		page.Projects = append(page.Projects, p.project())
	}
	return page, nil
}

// GetProject reads a project by id (GET /api/v1/projects/{id}); "" reads
// Config.ProjectID. An unknown id is NOT_FOUND.
func (c *Client) GetProject(ctx context.Context, projectID string) (*Project, error) {
	const op = "projects.get"
	id, err := c.projectID(op, projectID)
	if err != nil {
		return nil, err
	}
	var body struct {
		Project projectJSON `json:"project"`
	}
	if err := c.callJSON(ctx, call{method: http.MethodGet, path: "/api/v1/projects/" + url.PathEscape(id), op: op + " " + id}, &body); err != nil {
		return nil, err
	}
	p := body.Project.project()
	return &p, nil
}

// GetProjectBySlug reads a project by slug (GET /api/v1/projects/slug/{slug}).
func (c *Client) GetProjectBySlug(ctx context.Context, slug string) (*Project, error) {
	const op = "projects.getBySlug"
	if err := requireArg(op, "slug", slug); err != nil {
		return nil, err
	}
	var body projectJSON
	if err := c.callJSON(ctx, call{method: http.MethodGet, path: "/api/v1/projects/slug/" + url.PathEscape(slug), op: op + " " + slug}, &body); err != nil {
		return nil, err
	}
	p := body.project()
	return &p, nil
}

// ProjectOptions select the project of a project-scoped call (default Config.ProjectID).
type ProjectOptions struct {
	ProjectID string
}

func projectOf(o *ProjectOptions) string {
	if o == nil {
		return ""
	}
	return o.ProjectID
}

// ListEnvironments returns the environments of a project, ordered by
// position (from GET /api/v1/projects/{id}; Infisical has no list route).
func (c *Client) ListEnvironments(ctx context.Context, opts *ProjectOptions) ([]Environment, error) {
	p, err := c.GetProject(ctx, projectOf(opts))
	if err != nil {
		return nil, err
	}
	return p.Environments, nil
}

// CreateEnvironmentOptions configure CreateEnvironment.
type CreateEnvironmentOptions struct {
	ProjectID string
	// Position orders the environment (0: appended last).
	Position int
}

// CreateEnvironment creates a project environment (POST
// /api/v1/projects/{id}/environments; project admin). Slugs allow lower-case
// letters, digits and "-"; a duplicate slug is CONFLICT.
func (c *Client) CreateEnvironment(ctx context.Context, name, slug string, opts *CreateEnvironmentOptions) (*Environment, error) {
	const op = "environments.create"
	if err := requireArg(op, "name", name); err != nil {
		return nil, err
	}
	if err := requireArg(op, "slug", slug); err != nil {
		return nil, err
	}
	var o CreateEnvironmentOptions
	if opts != nil {
		o = *opts
	}
	id, err := c.projectID(op, o.ProjectID)
	if err != nil {
		return nil, err
	}
	b := map[string]any{"name": name, "slug": slug}
	if o.Position > 0 {
		b["position"] = o.Position
	}
	var body struct {
		Environment environmentJSON `json:"environment"`
	}
	r := call{method: http.MethodPost, path: "/api/v1/projects/" + url.PathEscape(id) + "/environments", body: b, op: op + " " + slug}
	if err := c.callJSON(ctx, r, &body); err != nil {
		return nil, err
	}
	e := body.Environment.environment()
	return &e, nil
}

// --- tags (v1) ------------------------------------------------------------------------

// ListTags lists the tags of a project (GET /api/v1/projects/{id}/tags).
func (c *Client) ListTags(ctx context.Context, opts *ProjectOptions) ([]Tag, error) {
	const op = "tags.list"
	id, err := c.projectID(op, projectOf(opts))
	if err != nil {
		return nil, err
	}
	var body struct {
		Tags []tagJSON `json:"tags"`
	}
	if err := c.callJSON(ctx, call{method: http.MethodGet, path: "/api/v1/projects/" + url.PathEscape(id) + "/tags", op: op}, &body); err != nil {
		return nil, err
	}
	out := make([]Tag, 0, len(body.Tags))
	for _, t := range body.Tags {
		out = append(out, t.tag())
	}
	return out, nil
}

// CreateTag creates a project tag (POST /api/v1/projects/{id}/tags). Slugs
// allow lower-case letters, digits and "-"; color "" uses DefaultTagColor; a
// duplicate slug is CONFLICT.
func (c *Client) CreateTag(ctx context.Context, slug, color string, opts *ProjectOptions) (*Tag, error) {
	const op = "tags.create"
	if err := requireArg(op, "slug", slug); err != nil {
		return nil, err
	}
	id, err := c.projectID(op, projectOf(opts))
	if err != nil {
		return nil, err
	}
	if color == "" {
		color = DefaultTagColor
	}
	var body struct {
		Tag tagJSON `json:"tag"`
	}
	r := call{method: http.MethodPost, path: "/api/v1/projects/" + url.PathEscape(id) + "/tags",
		body: map[string]string{"slug": slug, "color": color}, op: op + " " + slug}
	if err := c.callJSON(ctx, r, &body); err != nil {
		return nil, err
	}
	t := body.Tag.tag()
	return &t, nil
}

// DeleteTag deletes a tag by id (DELETE /api/v1/projects/{id}/tags/{tagId});
// the tag disappears from every secret. An unknown id is NOT_FOUND.
func (c *Client) DeleteTag(ctx context.Context, tagID string, opts *ProjectOptions) (*Tag, error) {
	const op = "tags.delete"
	if err := requireArg(op, "tagId", tagID); err != nil {
		return nil, err
	}
	id, err := c.projectID(op, projectOf(opts))
	if err != nil {
		return nil, err
	}
	var body struct {
		Tag tagJSON `json:"tag"`
	}
	r := call{method: http.MethodDelete, path: "/api/v1/projects/" + url.PathEscape(id) + "/tags/" + url.PathEscape(tagID), op: op + " " + tagID}
	if err := c.callJSON(ctx, r, &body); err != nil {
		return nil, err
	}
	t := body.Tag.tag()
	return &t, nil
}

// resolveTagIDs merges ids with the ids of slugs (nil when both are nil).
func (c *Client) resolveTagIDs(ctx context.Context, op, projectID string, ids, slugs []string) ([]string, error) {
	if ids == nil && slugs == nil {
		return nil, nil
	}
	out := append([]string{}, ids...)
	if len(slugs) == 0 {
		return out, nil
	}
	tags, err := c.ListTags(ctx, &ProjectOptions{ProjectID: projectID})
	if err != nil {
		return nil, err
	}
	bySlug := make(map[string]string, len(tags))
	for _, t := range tags {
		bySlug[t.Slug] = t.ID
	}
	for _, s := range slugs {
		id, ok := bySlug[s]
		if !ok {
			return nil, NotFoundError(op, "tag "+s+" does not exist")
		}
		out = append(out, id)
	}
	return out, nil
}

// --- secret imports (v2) ---------------------------------------------------------------

// SecretImport makes the secrets of another environment/path visible in a path.
type SecretImport struct {
	ID string `json:"id"`
	// ImportPath is the source path.
	ImportPath string `json:"importPath"`
	// ImportEnvironment is the source environment.
	ImportEnvironment Environment `json:"importEnvironment"`
	// Position orders imports (lower first).
	Position          int       `json:"position"`
	IsReplication     bool      `json:"isReplication"`
	FolderID          string    `json:"folderId,omitempty"`
	SourceProjectName string    `json:"sourceProjectName,omitempty"`
	CreatedAt         time.Time `json:"createdAt,omitzero"`
	UpdatedAt         time.Time `json:"updatedAt,omitzero"`
}

type secretImportJSON struct {
	ID                string          `json:"id"`
	ImportPath        string          `json:"importPath"`
	ImportEnv         environmentJSON `json:"importEnv"`
	Position          int             `json:"position"`
	IsReplication     bool            `json:"isReplication"`
	FolderID          string          `json:"folderId"`
	SourceProjectName string          `json:"sourceProjectName"`
	CreatedAt         flexTime        `json:"createdAt"`
	UpdatedAt         flexTime        `json:"updatedAt"`
}

func (s secretImportJSON) secretImport() SecretImport {
	return SecretImport{ID: s.ID, ImportPath: s.ImportPath, ImportEnvironment: s.ImportEnv.environment(),
		Position: s.Position, IsReplication: s.IsReplication, FolderID: s.FolderID,
		SourceProjectName: s.SourceProjectName, CreatedAt: s.CreatedAt.Time, UpdatedAt: s.UpdatedAt.Time}
}

// SecretImportOptions select the importing path (empty fields fall back to the Config).
type SecretImportOptions struct {
	ProjectID   string
	Environment string
	// Path is the importing path (default Config.SecretPath).
	Path string
}

// ListSecretImports lists the imports of a path (GET /api/v2/secret-imports).
func (c *Client) ListSecretImports(ctx context.Context, opts *SecretImportOptions) ([]SecretImport, error) {
	const op = "secretImports.list"
	var o SecretImportOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.Path)
	if err != nil {
		return nil, err
	}
	q := url.Values{"projectId": {s.projectID}, "environment": {s.environment}, "path": {s.path}}
	var body struct {
		SecretImports []secretImportJSON `json:"secretImports"`
	}
	if err := c.callJSON(ctx, call{method: http.MethodGet, path: "/api/v2/secret-imports", query: q, op: op + " " + s.path}, &body); err != nil {
		return nil, err
	}
	out := make([]SecretImport, 0, len(body.SecretImports))
	for _, i := range body.SecretImports {
		out = append(out, i.secretImport())
	}
	return out, nil
}

// CreateSecretImportOptions configure CreateSecretImport.
type CreateSecretImportOptions struct {
	ProjectID   string
	Environment string
	// Path is the importing path (default Config.SecretPath).
	Path string
	// ImportEnvironment is the source environment slug (required).
	ImportEnvironment string
	// ImportPath is the source path (default "/").
	ImportPath string
	// SourceProjectID imports from another project.
	SourceProjectID string
	// IsReplication copies the secrets instead of referencing them.
	IsReplication bool
}

// CreateSecretImport imports the secrets of ImportEnvironment/ImportPath into
// a path (POST /api/v2/secret-imports). Infisical accepts duplicates and
// source paths that do not exist.
func (c *Client) CreateSecretImport(ctx context.Context, opts *CreateSecretImportOptions) (*SecretImport, error) {
	const op = "secretImports.create"
	var o CreateSecretImportOptions
	if opts != nil {
		o = *opts
	}
	if err := requireArg(op, "importEnvironment", o.ImportEnvironment); err != nil {
		return nil, err
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.Path)
	if err != nil {
		return nil, err
	}
	imp := map[string]any{"environment": o.ImportEnvironment, "path": normalizePath(o.ImportPath)}
	if o.SourceProjectID != "" {
		imp["sourceProjectId"] = o.SourceProjectID
	}
	b := map[string]any{"projectId": s.projectID, "environment": s.environment, "path": s.path, "import": imp}
	if o.IsReplication {
		b["isReplication"] = true
	}
	var body struct {
		SecretImport secretImportJSON `json:"secretImport"`
	}
	if err := c.callJSON(ctx, call{method: http.MethodPost, path: "/api/v2/secret-imports", body: b, op: op + " " + s.path}, &body); err != nil {
		return nil, err
	}
	si := body.SecretImport.secretImport()
	return &si, nil
}

// DeleteSecretImport deletes an import by id (DELETE /api/v2/secret-imports/{id});
// an unknown id is NOT_FOUND.
func (c *Client) DeleteSecretImport(ctx context.Context, importID string, opts *SecretImportOptions) (*SecretImport, error) {
	const op = "secretImports.delete"
	if err := requireArg(op, "importId", importID); err != nil {
		return nil, err
	}
	var o SecretImportOptions
	if opts != nil {
		o = *opts
	}
	s, err := c.scope(op, o.ProjectID, o.Environment, o.Path)
	if err != nil {
		return nil, err
	}
	b := map[string]any{"projectId": s.projectID, "environment": s.environment, "path": s.path}
	var body struct {
		SecretImport secretImportJSON `json:"secretImport"`
	}
	r := call{method: http.MethodDelete, path: "/api/v2/secret-imports/" + url.PathEscape(importID), body: b, op: op + " " + importID}
	if err := c.callJSON(ctx, r, &body); err != nil {
		return nil, err
	}
	si := body.SecretImport.secretImport()
	return &si, nil
}

// --- secret versions (v1) ---------------------------------------------------------------

// Actor is who wrote a secret version.
type Actor struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

// SecretVersion is one stored version of a secret. Value never prints.
type SecretVersion struct {
	// ID is the version row id.
	ID          string     `json:"id"`
	Version     int        `json:"version"`
	Key         string     `json:"key"`
	Value       Secret     `json:"value"`
	ValueHidden bool       `json:"valueHidden"`
	Comment     string     `json:"comment,omitempty"`
	Type        SecretType `json:"type"`
	Environment string     `json:"environment"`
	Actor       *Actor     `json:"actor,omitempty"`
	CreatedAt   time.Time  `json:"createdAt,omitzero"`
}

// ListSecretVersionsOptions page through ListSecretVersions.
type ListSecretVersionsOptions struct {
	// Offset skips versions (newest first).
	Offset int
	// Limit is the page size (default 20, max 1000).
	Limit int
}

// ListSecretVersions lists the versions of a secret by id, newest first
// (GET /api/v1/secret/{secretId}/secret-versions). Infisical serves this
// route to user JWTs only: machine identities get PERMISSION_DENIED.
func (c *Client) ListSecretVersions(ctx context.Context, secretID string, opts *ListSecretVersionsOptions) ([]SecretVersion, error) {
	const op = "secretVersions.list"
	if err := requireArg(op, "secretId", secretID); err != nil {
		return nil, err
	}
	o := ListSecretVersionsOptions{Limit: 20}
	if opts != nil {
		o.Offset = opts.Offset
		if opts.Limit != 0 {
			o.Limit = opts.Limit
		}
	}
	if o.Offset < 0 || o.Limit < 1 || o.Limit > 1000 {
		return nil, ValidationError(op, "limit must be 1–1000 and offset >= 0")
	}
	q := url.Values{"offset": {strconv.Itoa(o.Offset)}, "limit": {strconv.Itoa(o.Limit)}}
	var body struct {
		SecretVersions []struct {
			secretJSON
			Actor *struct {
				ActorID   string `json:"actorId"`
				ActorType string `json:"actorType"`
				Name      string `json:"name"`
			} `json:"actor"`
		} `json:"secretVersions"`
	}
	r := call{method: http.MethodGet, path: "/api/v1/secret/" + url.PathEscape(secretID) + "/secret-versions", query: q, op: op + " " + secretID}
	if err := c.callJSON(ctx, r, &body); err != nil {
		return nil, err
	}
	out := make([]SecretVersion, 0, len(body.SecretVersions))
	for _, v := range body.SecretVersions {
		sv := SecretVersion{ID: v.ID, Version: v.Version, Key: v.SecretKey, ValueHidden: v.SecretValueHidden,
			Comment: v.SecretComment, Type: SecretType(v.Type), Environment: v.Environment, CreatedAt: v.CreatedAt.Time}
		if !v.SecretValueHidden {
			sv.Value = NewSecret(v.SecretValue)
		}
		if v.Actor != nil {
			sv.Actor = &Actor{ID: v.Actor.ActorID, Type: v.Actor.ActorType, Name: v.Actor.Name}
		}
		out = append(out, sv)
	}
	return out, nil
}
