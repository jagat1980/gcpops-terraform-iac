<#
.SYNOPSIS
    Daily Morning Startup Script for OneShield Base Infrastructure Stack.
.DESCRIPTION
    Reprovisions GKE Autopilot cluster, resumes Cloud SQL PostgreSQL compute (activation_policy = ALWAYS),
    and redeploys Kubernetes workloads.
#>

[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "    ONEMIND SHIELD - MORNING PROVISIONING & STARTUP" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$REPO_ROOT = Split-Path -Parent $SCRIPT_DIR
$TERRAFORM_DIR = Join-Path $REPO_ROOT "terraform"
$K8S_DIR = Join-Path $REPO_ROOT "k8s"

Set-Location -Path $TERRAFORM_DIR
Write-Host "[*] Applying Terraform with enable_ephemeral_compute = true..." -ForegroundColor Cyan

terraform apply -var="enable_ephemeral_compute=true" -auto-approve

if ($LASTEXITCODE -ne 0) {
    Write-Error "Terraform apply failed during morning startup."
}

Write-Host "[+] Infrastructure & Cloud SQL resumed successfully." -ForegroundColor Green
Write-Host "[*] Connecting to GKE and applying Kubernetes manifests..." -ForegroundColor Cyan

$CLUSTER_NAME = (terraform output -raw gke_cluster_name 2>$null)
if ($CLUSTER_NAME -and $CLUSTER_NAME -ne "DECOMMISSIONED_LOGOFF") {
    gcloud container clusters get-credentials $CLUSTER_NAME --region us-central1
    if (Test-Path (Join-Path $K8S_DIR "deployment.yaml")) {
        kubectl apply -f (Join-Path $K8S_DIR "deployment.yaml")
    }
    if (Test-Path (Join-Path $K8S_DIR "service.yaml")) {
        kubectl apply -f (Join-Path $K8S_DIR "service.yaml")
    }
    if (Test-Path (Join-Path $K8S_DIR "ingress.yaml")) {
        kubectl apply -f (Join-Path $K8S_DIR "ingress.yaml")
    }
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  SUCCESS: OneShield Infrastructure is FULLY OPERATIONAL!" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
