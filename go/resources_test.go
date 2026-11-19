package infisical

import (
	"net/http"
	"testing"
)

func TestFolders(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v2/folders", "listFolders.recursive")
	m.fixture(t, http.MethodPost, "/api/v2/folders", "createFolder.ok")
	m.fixture(t, http.MethodPatch, "/api/v2/folders/e182ee25", "updateFolder.ok")
	m.fixture(t, http.MethodDelete, "/api/v2/folders/e182ee25", "deleteFolder.ok")
	c := newMockClient(t, m, nil)

	fs, err := c.ListFolders(bg(), &ListFoldersOptions{Path: "/", Recursive: true})
	if err != nil || len(fs) != 3 || fs[2].RelativePath != "/app/nested" || fs[0].EnvironmentID == "" || fs[0].CreatedAt.IsZero() {
		t.Fatalf("list: %v %+v", err, fs)
	}
	if q := m.last(t, http.MethodGet, "/api/v2/folders").Query; q.Get("path") != "/" || q.Get("recursive") != "true" || q.Get("projectId") != testProject {
		t.Fatalf("query: %v", q)
	}
	if _, err := c.ListFolders(bg(), nil); err != nil {
		t.Fatal(err)
	}
	if q := m.last(t, http.MethodGet, "/api/v2/folders").Query; q.Has("recursive") {
		t.Fatal("recursive omitted by default")
	}
	f, err := c.CreateFolder(bg(), "f-49lj3988", &CreateFolderOptions{Path: "/", Description: "d"})
	if err != nil || f.Path != "/f-49lj3988" || f.Version != 1 {
		t.Fatalf("create: %v %+v", err, f)
	}
	if b := m.last(t, http.MethodPost, "/api/v2/folders").Body; str(b["name"]) != "f-49lj3988" || str(b["path"]) != "/" || str(b["description"]) != "d" {
		t.Fatalf("create body: %v", b)
	}
	if _, err := c.UpdateFolder(bg(), "e182ee25", &UpdateFolderOptions{Name: "g", Description: String("new")}); err != nil {
		t.Fatal(err)
	}
	if b := m.last(t, http.MethodPatch, "/api/v2/folders/e182ee25").Body; str(b["name"]) != "g" || str(b["description"]) != "new" {
		t.Fatalf("update body: %v", b)
	}
	if _, err := c.DeleteFolder(bg(), "e182ee25", &DeleteFolderOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if b := m.last(t, http.MethodDelete, "/api/v2/folders/e182ee25").Body; b["forceDelete"] != true || str(b["path"]) != "/" {
		t.Fatalf("delete body: %v", b)
	}
	m.json(http.MethodPost, "/api/v2/folders", 200, map[string]any{"folder": map[string]any{"id": "x", "name": "n", "description": "desc"}})
	if f, err := c.CreateFolder(bg(), "n", nil); err != nil || f.Description != "desc" {
		t.Fatalf("description: %v", err)
	}

	m.fixture(t, http.MethodPost, "/api/v2/folders", "createFolder.duplicate400")
	_, err = c.CreateFolder(bg(), "app", nil)
	wantCode(t, err, ErrorCodeConflict)
	m.fixture(t, http.MethodPost, "/api/v2/folders", "createFolder.422")
	_, err = c.CreateFolder(bg(), "bad/name", nil)
	wantCode(t, err, ErrorCodeValidation)
	m.fixture(t, http.MethodPatch, "/api/v2/folders/missing", "updateFolder.404")
	_, err = c.UpdateFolder(bg(), "missing", &UpdateFolderOptions{Name: "x"})
	wantCode(t, err, ErrorCodeNotFound)
	m.fixture(t, http.MethodDelete, "/api/v2/folders/missing", "deleteFolder.404")
	_, err = c.DeleteFolder(bg(), "missing", nil)
	wantCode(t, err, ErrorCodeNotFound)
	m.json(http.MethodGet, "/api/v2/folders", 404, errBody(404, "NotFound", "Environment not found"))
	_, err = c.ListFolders(bg(), nil)
	wantCode(t, err, ErrorCodeNotFound)

	for _, fn := range []func() error{
		func() error { _, err := c.CreateFolder(bg(), "", nil); return err },
		func() error { _, err := c.UpdateFolder(bg(), "", nil); return err },
		func() error { _, err := c.UpdateFolder(bg(), "id", nil); return err },
		func() error { _, err := c.DeleteFolder(bg(), "", nil); return err },
	} {
		wantCode(t, fn(), ErrorCodeValidation)
	}
	nc := newMockClient(t, m, func(cfg *Config) { cfg.Environment = "" })
	for _, fn := range []func() error{
		func() error { _, err := nc.ListFolders(bg(), nil); return err },
		func() error { _, err := nc.CreateFolder(bg(), "x", nil); return err },
		func() error { _, err := nc.UpdateFolder(bg(), "id", &UpdateFolderOptions{Name: "x"}); return err },
		func() error { _, err := nc.DeleteFolder(bg(), "id", nil); return err },
		func() error { _, err := nc.ListSecretImports(bg(), nil); return err },
		func() error {
			_, err := nc.CreateSecretImport(bg(), &CreateSecretImportOptions{ImportEnvironment: "staging"})
			return err
		},
		func() error { _, err := nc.DeleteSecretImport(bg(), "id", nil); return err },
	} {
		wantCode(t, fn(), ErrorCodeConfig)
	}
}

func TestProjectsEnvironments(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v1/projects", "listProjects.ok")
	m.fixture(t, http.MethodGet, "/api/v1/projects/"+testProject, "getProject.ok")
	m.fixture(t, http.MethodGet, "/api/v1/projects/slug/sdk-test", "getProjectBySlug.ok")
	m.fixture(t, http.MethodPost, "/api/v1/projects/"+testProject+"/environments", "createEnvironment.ok")
	c := newMockClient(t, m, nil)

	page, err := c.ListProjects(bg(), &ListProjectsOptions{Limit: 10, Offset: 1, Type: "secret-manager"})
	if err != nil || page.TotalCount < 1 || len(page.Projects) == 0 || page.Projects[0].Slug == "" || len(page.Projects[0].Environments) == 0 {
		t.Fatalf("list projects: %v %+v", err, page)
	}
	if q := m.last(t, http.MethodGet, "/api/v1/projects").Query; q.Get("limit") != "10" || q.Get("offset") != "1" || q.Get("type") != "secret-manager" {
		t.Fatalf("query: %v", q)
	}
	if _, err := c.ListProjects(bg(), nil); err != nil {
		t.Fatal(err)
	}
	if q := m.last(t, http.MethodGet, "/api/v1/projects").Query; q.Has("limit") || q.Has("offset") {
		t.Fatalf("defaults: %v", q)
	}
	_, err = c.ListProjects(bg(), &ListProjectsOptions{Limit: 101})
	wantCode(t, err, ErrorCodeValidation)

	p, err := c.GetProject(bg(), "")
	if err != nil || p.ID != testProject || p.Slug != "sdk-test" || p.Description == "" || len(p.Environments) != 4 || p.Environments[0].Slug != "dev" {
		t.Fatalf("get project: %v %+v", err, p)
	}
	if p, err := c.GetProjectBySlug(bg(), "sdk-test"); err != nil || p.Slug != "sdk-test" {
		t.Fatalf("by slug: %v", err)
	}
	_, err = c.GetProjectBySlug(bg(), "")
	wantCode(t, err, ErrorCodeValidation)
	envs, err := c.ListEnvironments(bg(), nil)
	if err != nil || len(envs) != 4 {
		t.Fatalf("envs: %v", err)
	}
	e, err := c.CreateEnvironment(bg(), "E 49lj3988", "e-49lj3988", &CreateEnvironmentOptions{Position: 5})
	if err != nil || e.Slug != "e-49lj3988" || e.Position != 5 || e.ProjectID != testProject {
		t.Fatalf("create env: %v %+v", err, e)
	}
	if b := m.last(t, http.MethodPost, "/api/v1/projects/"+testProject+"/environments").Body; b["position"] != float64(5) || str(b["name"]) != "E 49lj3988" {
		t.Fatalf("env body: %v", b)
	}
	if _, err := c.CreateEnvironment(bg(), "N", "n", nil); err != nil {
		t.Fatal(err)
	}
	if b := m.last(t, http.MethodPost, "/api/v1/projects/"+testProject+"/environments").Body; b["position"] != nil {
		t.Fatal("position omitted")
	}
	_, err = c.CreateEnvironment(bg(), "", "s", nil)
	wantCode(t, err, ErrorCodeValidation)
	_, err = c.CreateEnvironment(bg(), "n", "", nil)
	wantCode(t, err, ErrorCodeValidation)
	m.fixture(t, http.MethodPost, "/api/v1/projects/"+testProject+"/environments", "createEnvironment.duplicate400")
	_, err = c.CreateEnvironment(bg(), "D", "dev", nil)
	wantCode(t, err, ErrorCodeConflict)
	m.fixture(t, http.MethodPost, "/api/v1/projects/"+testProject+"/environments", "createEnvironment.403viewer")
	_, err = c.CreateEnvironment(bg(), "D", "d", nil)
	wantCode(t, err, ErrorCodePermissionDenied)
	m.fixture(t, http.MethodGet, "/api/v1/projects/missing", "getProject.404")
	_, err = c.GetProject(bg(), "missing")
	wantCode(t, err, ErrorCodeNotFound)
	_, err = c.ListEnvironments(bg(), &ProjectOptions{ProjectID: "missing"})
	wantCode(t, err, ErrorCodeNotFound)

	nc := newMockClient(t, m, func(cfg *Config) { cfg.ProjectID = "" })
	for _, fn := range []func() error{
		func() error { _, err := nc.GetProject(bg(), ""); return err },
		func() error { _, err := nc.CreateEnvironment(bg(), "n", "s", nil); return err },
		func() error { _, err := nc.ListTags(bg(), nil); return err },
		func() error { _, err := nc.CreateTag(bg(), "s", "", nil); return err },
		func() error { _, err := nc.DeleteTag(bg(), "id", nil); return err },
	} {
		wantCode(t, fn(), ErrorCodeConfig)
	}
	m.fixture(t, http.MethodGet, "/api/v1/projects", "listProjects.empty")
	if page, err := nc.ListProjects(bg(), nil); err != nil || len(page.Projects) != 0 {
		t.Fatalf("empty: %v", err)
	}
}

func TestTags(t *testing.T) {
	m := newMock(t)
	base := "/api/v1/projects/" + testProject + "/tags"
	m.fixture(t, http.MethodGet, base, "listTags.ok")
	m.fixture(t, http.MethodPost, base, "createTag.ok")
	m.fixture(t, http.MethodDelete, base+"/8ec93966", "deleteTag.ok")
	c := newMockClient(t, m, nil)

	tags, err := c.ListTags(bg(), &ProjectOptions{ProjectID: testProject})
	if err != nil || len(tags) != 1 || tags[0].Slug != "t-49lj3988" || tags[0].Color != "#00aa00" {
		t.Fatalf("list: %v", err)
	}
	tag, err := c.CreateTag(bg(), "t-49lj3988", "#00aa00", nil)
	if err != nil || tag.ID == "" {
		t.Fatalf("create: %v", err)
	}
	if _, err := c.CreateTag(bg(), "t2", "", nil); err != nil {
		t.Fatal(err)
	}
	if b := m.last(t, http.MethodPost, base).Body; str(b["color"]) != DefaultTagColor {
		t.Fatalf("default color: %v", b)
	}
	if _, err := c.DeleteTag(bg(), "8ec93966", nil); err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateTag(bg(), "", "", nil)
	wantCode(t, err, ErrorCodeValidation)
	_, err = c.DeleteTag(bg(), "", nil)
	wantCode(t, err, ErrorCodeValidation)
	m.fixture(t, http.MethodPost, base, "createTag.duplicate400")
	_, err = c.CreateTag(bg(), "dup", "", nil)
	wantCode(t, err, ErrorCodeConflict)
	m.fixture(t, http.MethodPost, base, "createTag.422")
	_, err = c.CreateTag(bg(), "Bad Slug", "", nil)
	wantCode(t, err, ErrorCodeValidation)
	m.fixture(t, http.MethodDelete, base+"/missing", "deleteTag.404")
	_, err = c.DeleteTag(bg(), "missing", nil)
	wantCode(t, err, ErrorCodeNotFound)
	m.json(http.MethodGet, base, 403, errBody(403, "PermissionDenied", "no"))
	_, err = c.ListTags(bg(), nil)
	wantCode(t, err, ErrorCodePermissionDenied)
	if ids, err := c.resolveTagIDs(bg(), "op", testProject, []string{"a"}, nil); err != nil || len(ids) != 1 {
		t.Fatal("ids only")
	}
}

func TestSecretImports(t *testing.T) {
	m := newMock(t)
	m.fixture(t, http.MethodGet, "/api/v2/secret-imports", "listSecretImports.ok")
	m.fixture(t, http.MethodPost, "/api/v2/secret-imports", "createSecretImport.ok")
	m.fixture(t, http.MethodDelete, "/api/v2/secret-imports/643ebf45", "deleteSecretImport.ok")
	c := newMockClient(t, m, nil)

	imps, err := c.ListSecretImports(bg(), &SecretImportOptions{Path: "/app"})
	if err != nil || len(imps) != 1 || imps[0].ImportPath != "/common" || imps[0].ImportEnvironment.Slug != "staging" || imps[0].SourceProjectName != "SDK Test" {
		t.Fatalf("list: %v %+v", err, imps)
	}
	if q := m.last(t, http.MethodGet, "/api/v2/secret-imports").Query; q.Get("path") != "/app" {
		t.Fatalf("query: %v", q)
	}
	si, err := c.CreateSecretImport(bg(), &CreateSecretImportOptions{Path: "/app", ImportEnvironment: "staging", ImportPath: "common",
		SourceProjectID: "other", IsReplication: true})
	if err != nil || si.ID == "" || si.Position != 1 {
		t.Fatalf("create: %v", err)
	}
	b := m.last(t, http.MethodPost, "/api/v2/secret-imports").Body
	imp := b["import"].(map[string]any)
	if str(imp["environment"]) != "staging" || str(imp["path"]) != "/common" || str(imp["sourceProjectId"]) != "other" || b["isReplication"] != true {
		t.Fatalf("create body: %v", b)
	}
	if _, err := c.DeleteSecretImport(bg(), "643ebf45", &SecretImportOptions{Path: "/app"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateSecretImport(bg(), nil)
	wantCode(t, err, ErrorCodeValidation)
	_, err = c.DeleteSecretImport(bg(), "", nil)
	wantCode(t, err, ErrorCodeValidation)
	m.fixture(t, http.MethodDelete, "/api/v2/secret-imports/missing", "deleteSecretImport.404")
	_, err = c.DeleteSecretImport(bg(), "missing", nil)
	wantCode(t, err, ErrorCodeNotFound)
	m.json(http.MethodGet, "/api/v2/secret-imports", 404, errBody(404, "NotFound", "folder"))
	_, err = c.ListSecretImports(bg(), nil)
	wantCode(t, err, ErrorCodeNotFound)
	m.json(http.MethodPost, "/api/v2/secret-imports", 403, errBody(403, "PermissionDenied", "no"))
	_, err = c.CreateSecretImport(bg(), &CreateSecretImportOptions{ImportEnvironment: "staging"})
	wantCode(t, err, ErrorCodePermissionDenied)
}

func TestSecretVersions(t *testing.T) {
	m := newMock(t)
	id := "805cfac2-aef1-4b20-850a-5495bb4795d1"
	path := "/api/v1/secret/" + id + "/secret-versions"
	m.fixture(t, http.MethodGet, path, "listSecretVersions.ok")
	c := newMockClient(t, m, nil)
	vs, err := c.ListSecretVersions(bg(), id, &ListSecretVersionsOptions{Offset: 0, Limit: 50})
	if err != nil || len(vs) < 3 || vs[0].Version != 3 || vs[0].Key != "SDK_49LJ3988_RENAMED" || vs[0].Value.Reveal() != "v2-49lj3988" ||
		vs[0].Actor == nil || vs[0].Actor.Type != "identity" || vs[0].CreatedAt.IsZero() {
		t.Fatalf("versions: %v %+v", err, vs)
	}
	if q := m.last(t, http.MethodGet, path).Query; q.Get("limit") != "50" || q.Get("offset") != "0" {
		t.Fatalf("query: %v", q)
	}
	if _, err := c.ListSecretVersions(bg(), id, nil); err != nil {
		t.Fatal(err)
	}
	if q := m.last(t, http.MethodGet, path).Query; q.Get("limit") != "20" {
		t.Fatalf("default limit: %v", q)
	}
	m.json(http.MethodGet, "/api/v1/secret/h/secret-versions", 200, map[string]any{"secretVersions": []map[string]any{{"version": 1, "secretValueHidden": true}}})
	if vs, err := c.ListSecretVersions(bg(), "h", nil); err != nil || !vs[0].ValueHidden || vs[0].Actor != nil {
		t.Fatalf("hidden: %v", err)
	}
	_, err = c.ListSecretVersions(bg(), "", nil)
	wantCode(t, err, ErrorCodeValidation)
	_, err = c.ListSecretVersions(bg(), id, &ListSecretVersionsOptions{Limit: 1001})
	wantCode(t, err, ErrorCodeValidation)
	m.fixture(t, http.MethodGet, path, "listSecretVersions.identity403")
	_, err = c.ListSecretVersions(bg(), id, nil)
	wantCode(t, err, ErrorCodePermissionDenied)
}
