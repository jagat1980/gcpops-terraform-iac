# terraform/artifact_registry.tf
resource "google_artifact_registry_repository" "oneshield_repo" {
  depends_on    = [google_project_service.enabled_apis]
  location      = var.gcp_region
  repository_id = "oneshield-repo"
  description   = "Docker container repository for OneShield Vulnerability Engine & MCP Servers"
  format        = "DOCKER"

  labels = {
    environment = var.environment
    app         = "oneshield"
  }
}
