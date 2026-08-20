# terraform/secrets.tf
resource "google_secret_manager_secret" "openai_key" {
  depends_on = [google_project_service.enabled_apis]
  secret_id  = "oneshield-openai-key"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "openai_key_version" {
  count       = length(var.openai_api_key) > 0 ? 1 : 0
  secret      = google_secret_manager_secret.openai_key.id
  secret_data = var.openai_api_key
}

resource "google_secret_manager_secret" "oneshield_auth_key" {
  depends_on = [google_project_service.enabled_apis]
  secret_id  = "oneshield-auth-key"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "oneshield_auth_key_version" {
  count       = length(var.oneshield_api_key) > 0 ? 1 : 0
  secret      = google_secret_manager_secret.oneshield_auth_key.id
  secret_data = var.oneshield_api_key
}
