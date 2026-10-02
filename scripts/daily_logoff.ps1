<#
.SYNOPSIS
    Daily Logoff Teardown Script for OneShield Base Infrastructure Stack.
.DESCRIPTION
    Safely tears down GKE Autopilot cluster and suspends Cloud SQL PostgreSQL compute
    before logging off for the day to avoid overnight and weekend GCP billing charges.
    
    Preserves:
    - Artifact Registry images
    - Cloud SQL PostgreSQL storage and database tables (activation_policy = NEVER stops CPU/RAM charges)
    - Secret Manager secrets & IAM bindings
#>

[CmdletBinding()]
param (
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "    ONEMIND SHIELD - DAILY LOGOFF INFRASTRUCTURE TEARDOWN" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$TERRAFORM_DIR = Join-Path (Split-Path -Parent $SCRIPT_DIR) "terraform"

Write-Host "Resources to be DECOMMISSIONED / SUSPENDED (Zero Spend Overnight):" -ForegroundColor Red
Write-Host "  [-] GKE Autopilot Cluster: Destroyed (Saves ~$0.10/hr flat fee + all pod compute)" -ForegroundColor DarkRed
Write-Host "  [-] Cloud SQL PostgreSQL: Suspended / Stopped (Saves 100% of CPU and RAM compute)" -ForegroundColor DarkRed
Write-Host ""
Write-Host "Resources PRESERVED (Near-Zero Idle Cost):" -ForegroundColor Green
Write-Host "  [+] Cloud SQL Databases, Tables & Data (activation_policy=NEVER)" -ForegroundColor DarkGreen
Write-Host "  [+] Artifact Registry Container Images" -ForegroundColor DarkGreen
Write-Host "  [+] Secret Manager & IAM Roles" -ForegroundColor DarkGreen
Write-Host ""

if (-not $Force) {
    $Confirmation = Read-Host "Are you sure you want to decommission ephemeral compute for the day? (y/N)"
    if ($Confirmation -notmatch "^[yY]$") {
        Write-Host "[*] Teardown cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

Set-Location -Path $TERRAFORM_DIR
Write-Host "[*] Executing safe ephemeral teardown via Terraform Feature Flag..." -ForegroundColor Yellow

terraform apply -var="enable_ephemeral_compute=false" -auto-approve

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host "  SUCCESS: Daily Teardown Complete! Zero active compute charges." -ForegroundColor Green
    Write-Host "  Run .\scripts\daily_startup.ps1 tomorrow morning to resume." -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Green
} else {
    Write-Error "Terraform apply failed during ephemeral teardown."
}
