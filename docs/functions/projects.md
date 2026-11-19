# Projects and environments

Read access to projects (Infisical calls them workspaces in older APIs) and their environments,
plus `createEnvironment` for admins. All calls use the **v1** API. Without an explicit project id
the config's `projectId` is used (`CONFIG` error when neither is set).

| Function | Endpoint (v1) | Notes |
| - | - | - |
| `listProjects({type, limit, offset})` | `GET /api/v1/projects` | projects the caller can see; returns `projects` + `totalCount` (`ProjectList` in TypeScript/Python, `ProjectPage` in Go, Rust and Java) |
| `getProject(projectId?)` | `GET /api/v1/projects/{id}` | includes the environments; TypeScript takes `{ projectId }` |
| `getProjectBySlug(slug)` | `GET /api/v1/projects/slug/{slug}` | |
| `listEnvironments(projectId?)` | from `getProject` | `id`, `name`, `slug`, `position` |
| `createEnvironment(name, slug, {projectId, position})` | `POST /api/v1/projects/{id}/environments` | admin permission; an existing slug → `CONFLICT`; viewer → `PERMISSION_DENIED` |

=== "TypeScript"

    ```ts
    const { projects, totalCount } = await client.projects.listProjects({ limit: 50 });
    const project = await client.projects.getProject(); // config projectId
    const same = await client.projects.getProjectBySlug(project.slug);
    const envs = await client.projects.listEnvironments();
    const qa = await client.projects.createEnvironment("QA", "qa", { position: 4 });
    ```

=== "Rust"

    ```rust
    use grow_infisical::ListProjectsOptions;

    let page = client.list_projects(Some(&ListProjectsOptions { limit: Some(50), ..Default::default() })).await?;
    let project = client.get_project(None).await?; // config project_id
    let same = client.get_project_by_slug(&project.slug).await?;
    let envs = client.list_environments(None).await?;
    let qa = client.create_environment("QA", "qa", None).await?;
    ```

=== "Go"

    ```go
    page, err := client.ListProjects(ctx, &infisical.ListProjectsOptions{Limit: 50})
    project, err := client.GetProject(ctx, "") // config ProjectID
    same, err := client.GetProjectBySlug(ctx, project.Slug)
    envs, err := client.ListEnvironments(ctx, nil)
    qa, err := client.CreateEnvironment(ctx, "QA", "qa", &infisical.CreateEnvironmentOptions{Position: 4})
    ```

=== "Python"

    ```python
    page = client.projects.list_projects(limit=50)
    project = client.projects.get_project()  # config project_id
    same = client.projects.get_project_by_slug(project.slug)
    envs = client.projects.list_environments()
    qa = client.projects.create_environment("QA", "qa", position=4)
    ```

=== "Java"

    ```java
    ProjectPage page = client.listProjects(ListProjectsOptions.builder().limit(50).build());
    Project project = client.getProject(null); // config projectId
    Project same = client.getProjectBySlug(project.slug());
    List<Environment> envs = client.listEnvironments(null);
    Environment qa = client.createEnvironment("QA", "qa", null);
    ```
