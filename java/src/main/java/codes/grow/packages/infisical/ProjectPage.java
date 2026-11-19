package codes.grow.packages.infisical;

import java.util.List;

/**
 * One page of {@link InfisicalClient#listProjects}.
 *
 * @param projects the projects of the page
 * @param totalCount the number of projects visible to the caller
 */
public record ProjectPage(List<Project> projects, int totalCount) {}
