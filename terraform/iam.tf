# terraform/iam.tf
resource "google_project_iam_member" "gke_cloud_trace_user" {
  project = var.gcp_project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:oneshield-terraform-sa@${var.gcp_project_id}.iam.gserviceaccount.com"
}