# terraform/outputs.tf
output "artifact_registry_url" {
  value       = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project_id}/${google_artifact_registry_repository.oneshield_repo.repository_id}"
  description = "Google Artifact Registry Repository URL for container image pushes."
}

output "gke_cluster_name" {
  value       = try(google_container_cluster.oneshield_gke[0].name, "DECOMMISSIONED_LOGOFF")
  description = "GKE Cluster Name."
}

output "gke_cluster_endpoint" {
  value       = try(google_container_cluster.oneshield_gke[0].endpoint, "DECOMMISSIONED_LOGOFF")
  description = "GKE Cluster Endpoint."
}

output "cloud_sql_connection_name" {
  value       = google_sql_database_instance.oneshield_db_instance.connection_name
  description = "Cloud SQL Instance Connection Name."
}
