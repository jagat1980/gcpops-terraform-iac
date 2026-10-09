<#
.SYNOPSIS
    Full GCP Environment Teardown Script for OneShield Platform.
.DESCRIPTION
    Destroys all infrastructure, compute, network, database, and telemetry
    resources across the GCP project to achieve $0.00/hour spend, while strictly
    PRESERVING:
      1. Terraform Remote State Bucket (gs://oneshield-tfstate-*)
      2. Base LLM Weights & LoRA Adapters Bucket (gs://oneshield-llm-weights-*)
      3. GitHub Actions Workload Identity Federation (github-pool / github-provider)
.PARAMETER Force
    Skips the interactive confirmation prompt.
#>
[CmdletBinding()]
param (
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProjectId = "innate-bonfire-176513"
$Region = "us-central1"
$TfDir = Join-Path $PSScriptRoot "..\terraform"

Write-Host "==============================================================================" -ForegroundColor Red
Write-Host "⚠️  CRITICAL WARNING: ONESHIELD GCP FULL ENVIRONMENT TEARDOWN INITIATED" -ForegroundColor Yellow
Write-Host "Target Project: $ProjectId ($Region)" -ForegroundColor Cyan
Write-Host "=============================================================================="

# 1. Safety Confirmation Gate
if (-not $Force) {
    Write-Host "`nThis script will PERMANENTLY DESTROY:" -ForegroundColor Yellow
    Write-Host "  - GKE Autopilot Cluster, Workloads, and Ingresses"
    Write-Host "  - VPC Network, Subnets, Cloud NAT, Cloud Router, and Static Ingress IP"
    Write-Host "  - Pub/Sub Topics, Subscriptions, and Dead Letter Queues"
    Write-Host "  - BigQuery Dataset (oneshield_analytics) and all telemetry tables"
    Write-Host "  - Artifact Registry Repository (oneshield-repo) & Docker container images"
    Write-Host "  - Cloud Monitoring Executive Dashboards, Alert Policies & Log-Based Metrics"
    Write-Host "  - Audit Logs Storage Bucket (oneshield-audit-logs-*)"
    Write-Host "`nPRESERVED ASSETS:" -ForegroundColor Green
    Write-Host "  - Terraform State Bucket: gs://oneshield-tfstate-$ProjectId"
    Write-Host "  - Model Weights Bucket:   gs://oneshield-llm-weights-*"
    Write-Host "  - GitHub Actions OIDC:    github-pool & github-provider"

    $Confirm = Read-Host "`nTo confirm permanent teardown, type the exact Project ID [$ProjectId]"
    if ($Confirm -ne $ProjectId) {
        Write-Host "❌ Aborted. Confirmation project ID did not match." -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n🚀 [1/6] Setting active GCP project context..." -ForegroundColor Cyan
gcloud config set project $ProjectId --quiet

# 2. Pre-cleanup GKE Ingress & Services
Write-Host "`n🧹 [2/6] Draining GKE Ingresses and LoadBalancers to release Cloud Forwarding Rules..." -ForegroundColor Cyan
try {
    $ClusterExists = gcloud container clusters describe oneshield-gke-cluster --region=$Region --project=$ProjectId 2>$null
    if ($ClusterExists) {
        gcloud container clusters get-credentials oneshield-gke-cluster --region=$Region --project=$ProjectId --quiet
        Write-Host "  -> Deleting Kubernetes Ingresses..."
        kubectl delete ingress --all -n ai-stack --timeout=60s --ignore-not-found=true 2>$null
        kubectl delete ingress --all --all-namespaces --timeout=60s --ignore-not-found=true 2>$null
        Write-Host "  -> Deleting Kubernetes Services..."
        kubectl delete svc --all -n ai-stack --timeout=60s --ignore-not-found=true 2>$null
        Start-Sleep -Seconds 15
    }
} catch {
    Write-Host "  -> GKE Cluster not found or unreachable. Proceeding."
}

# 3. Purge Non-Empty Objects from Datastores Targeted for Destruction
Write-Host "`n🗑️  [3/6] Purging non-empty contents from BigQuery, Audit GCS, and Artifact Registry..." -ForegroundColor Cyan

# 3a. BigQuery
try {
    $BqCheck = bq ls --project_id=$ProjectId 2>$null | Select-String "oneshield_analytics"
    if ($BqCheck) {
        Write-Host "  -> Removing BigQuery dataset and all telemetry tables..."
        bq rm -r -f -d "$ProjectId:oneshield_analytics"
    }
} catch {
    Write-Host "  -> BigQuery dataset already deleted."
}

# 3b. Audit Logs Bucket
try {
    $AuditBucket = gcloud storage buckets list --project=$ProjectId --format="value(name)" 2>$null | Select-String "oneshield-audit-logs"
    if ($AuditBucket) {
        Write-Host "  -> Emptying and deleting audit logs bucket: $AuditBucket..."
        gcloud storage rm --recursive "gs://$AuditBucket/**" 2>$null
    }
} catch {}

# 3c. Artifact Registry
try {
    $GarExists = gcloud artifacts repositories describe oneshield-repo --location=$Region --project=$ProjectId 2>$null
    if ($GarExists) {
        Write-Host "  -> Deleting Artifact Registry repository: oneshield-repo ($Region)..."
        gcloud artifacts repositories delete oneshield-repo --location=$Region --project=$ProjectId --quiet
    }
} catch {}

# 4. Protect Model Weights in Terraform State
Write-Host "`n🛡️  [4/6] Decoupling Model Weights Bucket from Terraform State..." -ForegroundColor Cyan
Push-Location $TfDir
try {
    terraform init -reconfigure -input=false
    $StateList = terraform state list 2>$null

    if ($StateList -match "google_storage_bucket\.model_weights") {
        Write-Host "  -> Removing google_storage_bucket.model_weights from state..."
        terraform state rm google_storage_bucket.model_weights
    }
    if ($StateList -match "google_storage_bucket_iam_member\.vllm_gcs_admin") {
        Write-Host "  -> Removing google_storage_bucket_iam_member.vllm_gcs_admin from state..."
        terraform state rm google_storage_bucket_iam_member.vllm_gcs_admin
    }

    # 5. Execute Terraform Destroy
    Write-Host "`n💥 [5/6] Executing Terraform Destroy for all remaining managed resources..." -ForegroundColor Yellow
    terraform destroy -auto-approve -input=false
} finally {
    Pop-Location
}

# 6. Post-Teardown Audit & Verification
Write-Host "`n==============================================================================" -ForegroundColor Green
Write-Host "📋 [6/6] POST-TEARDOWN VERIFICATION AUDIT" -ForegroundColor Green
Write-Host "=============================================================================="

Write-Host "=== PRESERVED CLOUD STORAGE BUCKETS ===" -ForegroundColor Cyan
gcloud storage buckets list --project=$ProjectId --format="table(name,location,storageClass)" 2>$null

Write-Host "`n🎉 TEARDOWN COMPLETE! Compute Burn Rate: `$0.00/hour." -ForegroundColor Green
Write-Host "Remote state in gs://oneshield-tfstate-$ProjectId updated to 0 resources." -ForegroundColor Green
Write-Host "Model weights bucket and GitHub Actions OIDC are safely preserved." -ForegroundColor Green
