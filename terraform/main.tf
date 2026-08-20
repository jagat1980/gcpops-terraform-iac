# terraform/main.tf
terraform {
  required_version = ">= 1.5.0"

  # 🗄️ Remote GCS State Backend (Enterprise Best Practice for GitHub Actions)
  backend "gcs" {
    bucket = "oneshield-tfstate-644b97eb"
    prefix = "terraform/state"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.15.0"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# 🔌 Enable Required GCP Service APIs automatically via Terraform
resource "google_project_service" "enabled_apis" {
  for_each = toset([
    "artifactregistry.googleapis.com",
    "run.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudbuild.googleapis.com"
  ])

  project            = var.gcp_project_id
  service            = each.value
  disable_on_destroy = false
}
