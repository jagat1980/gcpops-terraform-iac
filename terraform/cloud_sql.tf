# terraform/cloud_sql.tf
resource "google_sql_database_instance" "oneshield_db_instance" {
  depends_on       = [google_project_service.enabled_apis]
  name             = "oneshield-db-instance-${var.environment}"
  database_version = "POSTGRES_16"
  region           = var.gcp_region

  settings {
    # Right-sized for cost efficiency (1 vCPU, 3.75GB RAM — 50% cost reduction)
    # For Dev/POC testing, tier = "db-f1-micro" cuts cost by 85% (~$7.50/mo)
    tier = "db-custom-1-3840"

    backup_configuration {
      enabled    = true
      start_time = "03:00"
    }

    ip_configuration {
      ipv4_enabled = true
    }
  }

  deletion_protection = false
}

resource "google_sql_database" "oneshield_database" {
  name     = "oneshield_db"
  instance = google_sql_database_instance.oneshield_db_instance.name
}

resource "google_sql_user" "oneshield_db_user" {
  name     = "oneshield_user"
  instance = google_sql_database_instance.oneshield_db_instance.name
  password = length(var.db_password) > 0 ? var.db_password : "DefaultStrongPassword123!"
}
