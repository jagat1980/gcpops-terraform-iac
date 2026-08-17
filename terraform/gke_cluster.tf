# terraform/gke_cluster.tf
resource "google_container_cluster" "oneshield_gke" {
  depends_on       = [google_project_service.enabled_apis]
  name             = "oneshield-gke-cluster"
  location         = var.gcp_region
  enable_autopilot = true

  release_channel {
    channel = "REGULAR"
  }
}
