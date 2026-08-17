# terraform/outputs.tf
output "artifact_registry_url" {
  value       = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project_id}/${google_artifact_registry_repository.oneshield_repo.repository_id}"
  description = "Google Artifact Registry Repository URL for container image pushes."
}

output "gke_cluster_name" {
  value       = google_container_cluster.oneshield_gke.name
  description = "GKE Cluster Name."
}

output "gke_cluster_endpoint" {
  value       = google_container_cluster.oneshield_gke.endpoint
  description = "GKE Cluster Endpoint."
}

output "cloud_sql_connection_name" {
  value       = google_sql_database_instance.oneshield_db_instance.connection_name
  description = "Cloud SQL Instance Connection Name."
}
