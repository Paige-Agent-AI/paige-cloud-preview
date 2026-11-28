export const developerCapabilitiesPath = "/api/cloud/v1/developer/capabilities";

const projects = "/api/cloud/v1/organizations/{organization}/projects";
const applications = projects + "/{project}/applications";
const environment = applications + "/{application}/environments/{environment}";

export function developerCapabilities(observation) {
  const operations = [
    { id: "registry.projects.list", name: "List projects", method: "GET", path: projects,
      access: "Active organization membership and project grants" },
    { id: "registry.applications.list", name: "List applications and environments", method: "GET", path: applications,
      access: "Active project grant" },
    { id: "repository.binding.read", name: "Read the repository binding", method: "GET", path: environment + "/repository-binding",
      access: "Active project grant for the registered environment" },
    { id: "configuration.read", name: "Read saved configuration", method: "GET", path: environment + "/configuration",
      access: "Active project grant for the registered environment" }
  ];
  if (observation) {
    operations.push({ id: "workload.inspection.read", name: "Inspect the running workload", method: "POST", path: environment + "/inspection",
      access: "Bound workload, scoped decision and inspection quota" });
    if (observation.releasesAvailable) {
      operations.push({ id: "workload.releases.read", name: "Read published versions", method: "POST", path: environment + "/published-releases",
        access: "Bound workload, scoped decision and inspection quota" });
    }
  }
  return { schema: "paige.cloud.developer-capabilities.v1", authentication: "cloud-account-session", operations };
}
