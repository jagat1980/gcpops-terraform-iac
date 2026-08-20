# terraform/imports.tf
# Native Terraform 1.5+ import blocks to adopt resources created in previous run

import {
  to = google_artifact_registry_repository.oneshield_repo
  id = "projects/project-644b97eb-9375-4ec7-82e/locations/us-central1/repositories/oneshield-repo"
}

import {
  to = google_container_cluster.oneshield_gke
  id = "projects/project-644b97eb-9375-4ec7-82e/locations/us-central1/clusters/oneshield-gke-cluster"
}

import {
  to = google_sql_database_instance.oneshield_db_instance
  id = "projects/project-644b97eb-9375-4ec7-82e/instances/oneshield-db-instance-prod"
}

import {
  to = google_secret_manager_secret.openai_key
  id = "projects/project-644b97eb-9375-4ec7-82e/secrets/oneshield-openai-key"
}

import {
  to = google_secret_manager_secret.oneshield_auth_key
  id = "projects/project-644b97eb-9375-4ec7-82e/secrets/oneshield-auth-key"
}
