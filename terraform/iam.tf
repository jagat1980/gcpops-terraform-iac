resource "google_project_iam_member" "gke_cloud_trace_user" {
  project = var.gcp_project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.oneshield_sa.email}"
}