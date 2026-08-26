# terraform/vpc_sc.tf
# Enterprise Banking VPC Service Controls Perimeter (Dry-Run Mode)

data "google_project" "current" {
  project_id = var.gcp_project_id
}

resource "google_access_context_manager_service_perimeter" "banking_perimeter" {
  count          = var.access_policy_id != "" ? 1 : 0
  parent         = "accessPolicies/${var.access_policy_id}"
  name           = "accessPolicies/${var.access_policy_id}/servicePerimeters/shiftshield_banking_perimeter"
  title          = "ShiftShield Banking Security Perimeter (Dry-Run)"
  perimeter_type = "PERIMETER_TYPE_REGULAR"

  # 🧪 ENABLE DRY-RUN MODE (Non-disruptive testing)
  use_explicit_dry_run_spec = true

  spec {
    # 1. Projects inside security boundary (resources argument in Google Provider)
    resources = [
      "projects/${data.google_project.current.number}"
    ]

    # 2. GCP Managed Services Restricted in Dry-Run
    restricted_services = [
      "sqladmin.googleapis.com",          # Cloud SQL PostgreSQL
      "artifactregistry.googleapis.com", # Artifact Registry Container Repo
      "secretmanager.googleapis.com",    # Secret Manager API Keys
      "cloudtrace.googleapis.com",       # Cloud Trace Observability
      "logging.googleapis.com"           # Cloud Logging Event Store
    ]

    # 3. Ingress Rule: Allow GitHub Actions Workload Identity to Push Images
    ingress_policies {
      ingress_from {
        identities = [
          "serviceAccount:oneshield-terraform-sa@${var.gcp_project_id}.iam.gserviceaccount.com"
        ]
        sources {
          access_level = "*"
        }
      }
      ingress_to {
        resources = ["*"]
        operations {
          service_name = "artifactregistry.googleapis.com"
          method_selectors {
            method = "*"
          }
        }
      }
    }

    # 4. Egress Rule: Allow GKE Pods Outbound Egress to OpenAI & EPSS
    egress_policies {
      egress_from {
        identities = [
          "serviceAccount:oneshield-terraform-sa@${var.gcp_project_id}.iam.gserviceaccount.com"
        ]
      }
      egress_to {
        resources = ["*"]
        operations {
          service_name = "*"
        }
      }
    }
  }
}