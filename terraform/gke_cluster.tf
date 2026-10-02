# terraform/gke_cluster.tf
resource "google_container_cluster" "oneshield_gke" {
  count               = var.enable_ephemeral_compute ? 1 : 0
  depends_on          = [google_project_service.enabled_apis]
  name                = "oneshield-gke-cluster"
  location            = var.gcp_region
  enable_autopilot    = true
  deletion_protection = false

  release_channel {
    channel = "REGULAR"
  }
}
