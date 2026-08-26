# terraform/variables.tf
variable "gcp_project_id" {
  type        = string
  description = "The GCP Project ID where resources will be provisioned."
}

variable "gcp_region" {
  type        = string
  description = "GCP region for regional resources."
  default     = "us-central1"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)."
  default     = "prod"
}

variable "db_password" {
  type        = string
  description = "Root password for Cloud SQL PostgreSQL."
  sensitive   = true
}

variable "openai_api_key" {
  type        = string
  description = "OpenAI API Key stored securely in GCP Secret Manager."
  sensitive   = true
}

variable "oneshield_api_key" {
  type        = string
  description = "Authentication API Key for incoming scan-handler webhooks."
  sensitive   = true
}

variable "access_policy_id" {
  type        = string
  description = "Optional GCP Access Context Manager Policy ID for VPC Service Controls."
  default     = ""
}
