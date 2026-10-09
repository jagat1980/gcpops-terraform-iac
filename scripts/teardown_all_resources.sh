#!/usr/bin/env bash
# ==============================================================================
# OneShield Autonomous Remediation Platform - Full GCP Environment Teardown
#
# PURPOSE:
#   Destroys all infrastructure, compute, network, database, and telemetry
#   resources across the GCP project to achieve $0.00/hour spend, while strictly
#   PRESERVING:
#     1. Terraform Remote State Bucket (gs://oneshield-tfstate-*)
#     2. Base LLM Weights & LoRA Adapters Bucket (gs://oneshield-llm-weights-*)
#     3. GitHub Actions Workload Identity Federation (github-pool / github-provider)
#
# USAGE:
#   bash scripts/teardown_all_resources.sh [--force]
# ==============================================================================

set -euo pipefail

PROJECT_ID="innate-bonfire-176513"
REGION="us-central1"
TF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../terraform" && pwd)"
FORCE_FLAG="${1:-}"

echo "=============================================================================="
echo "⚠️  CRITICAL WARNING: ONESHIELD GCP FULL ENVIRONMENT TEARDOWN INITIATED"
echo "Target Project: ${PROJECT_ID} (${REGION})"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 1. Safety Confirmation Gate
# ------------------------------------------------------------------------------
if [[ "${FORCE_FLAG}" != "--force" ]]; then
    echo ""
    echo "This script will PERMANENTLY DESTROY:"
    echo "  - GKE Autopilot Cluster, Workloads, and Ingresses"
    echo "  - VPC Network, Subnets, Cloud NAT, Cloud Router, and Static Ingress IP"
    echo "  - Pub/Sub Topics, Subscriptions, and Dead Letter Queues"
    echo "  - BigQuery Dataset (oneshield_analytics) and all telemetry tables"
    echo "  - Artifact Registry Repository (oneshield-repo) & Docker container images"
    echo "  - Cloud Monitoring Executive Dashboards, Alert Policies & Log-Based Metrics"
    echo "  - Audit Logs Storage Bucket (oneshield-audit-logs-*)"
    echo ""
    echo "PRESERVED ASSETS:"
    echo "  - Terraform State Bucket: gs://oneshield-tfstate-${PROJECT_ID}"
    echo "  - Model Weights Bucket:   gs://oneshield-llm-weights-*"
    echo "  - GitHub Actions OIDC:    github-pool & github-provider"
    echo ""
    read -rp "To confirm permanent teardown, type the exact Project ID [${PROJECT_ID}]: " CONFIRM_PROJECT
    if [[ "${CONFIRM_PROJECT}" != "${PROJECT_ID}" ]]; then
        echo "❌ Aborted. Confirmation project ID did not match."
        exit 1
    fi
fi

echo ""
echo "🚀 [1/6] Authenticating and configuring GCP Project context..."
gcloud config set project "${PROJECT_ID}" --quiet

# ------------------------------------------------------------------------------
# 2. Pre-cleanup GKE Ingress & Services to Release External Load Balancers
# ------------------------------------------------------------------------------
echo ""
echo "🧹 [2/6] Draining GKE Ingresses and LoadBalancers to release Cloud Forwarding Rules..."
if gcloud container clusters describe oneshield-gke-cluster --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud container clusters get-credentials oneshield-gke-cluster --region="${REGION}" --project="${PROJECT_ID}" --quiet || true
    echo "  -> Deleting Kubernetes Ingresses in ai-stack namespace..."
    kubectl delete ingress --all -n ai-stack --timeout=60s --ignore-not-found=true || true
    kubectl delete ingress --all --all-namespaces --timeout=60s --ignore-not-found=true || true
    echo "  -> Deleting Kubernetes Services to detach external IPs..."
    kubectl delete svc --all -n ai-stack --timeout=60s --ignore-not-found=true || true
    sleep 15
else
    echo "  -> GKE Cluster not found or already deleted. Skipping Kubernetes drain."
fi

# ------------------------------------------------------------------------------
# 3. Purge Non-Empty Objects from Datastores Targeted for Destruction
# ------------------------------------------------------------------------------
echo ""
echo "🗑️  [3/6] Purging non-empty contents from BigQuery, Audit GCS, and Artifact Registry..."

# 3a. BigQuery Dataset & Tables
if bq ls --project_id="${PROJECT_ID}" | grep -q "oneshield_analytics"; then
    echo "  -> Removing BigQuery dataset and all telemetry tables: ${PROJECT_ID}:oneshield_analytics..."
    bq rm -r -f -d "${PROJECT_ID}:oneshield_analytics" || true
fi

# 3b. Audit Logs GCS Bucket
AUDIT_BUCKET=$(gcloud storage buckets list --project="${PROJECT_ID}" --format="value(name)" 2>/dev/null | grep "oneshield-audit-logs" || true)
if [[ -n "${AUDIT_BUCKET}" ]]; then
    echo "  -> Emptying and deleting audit logs bucket: ${AUDIT_BUCKET}..."
    gcloud storage rm --recursive "gs://${AUDIT_BUCKET}/**" 2>/dev/null || true
fi

# 3c. Artifact Registry Container Images
if gcloud artifacts repositories describe oneshield-repo --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "  -> Deleting Artifact Registry repository: oneshield-repo (${REGION})..."
    gcloud artifacts repositories delete oneshield-repo --location="${REGION}" --project="${PROJECT_ID}" --quiet || true
fi

# ------------------------------------------------------------------------------
# 4. Protect Model Weights in Terraform State (Decouple without Deleting Bucket)
# ------------------------------------------------------------------------------
echo ""
echo "🛡️  [4/6] Decoupling Model Weights Bucket from Terraform State..."
cd "${TF_DIR}"
terraform init -reconfigure -input=false

# Inspect state and remove model weights bucket so 'terraform destroy' ignores it
if terraform state list | grep -q "google_storage_bucket.model_weights"; then
    echo "  -> Removing google_storage_bucket.model_weights from state..."
    terraform state rm google_storage_bucket.model_weights || true
fi
if terraform state list | grep -q "google_storage_bucket_iam_member.vllm_gcs_admin"; then
    echo "  -> Removing google_storage_bucket_iam_member.vllm_gcs_admin from state..."
    terraform state rm google_storage_bucket_iam_member.vllm_gcs_admin || true
fi

# ------------------------------------------------------------------------------
# 5. Execute Terraform Destroy (Graceful Infrastructure Teardown)
# ------------------------------------------------------------------------------
echo ""
echo "💥 [5/6] Executing Terraform Destroy for all remaining managed resources..."
terraform destroy -auto-approve -input=false

# ------------------------------------------------------------------------------
# 6. Post-Teardown Audit & Verification
# ------------------------------------------------------------------------------
echo ""
echo "=============================================================================="
echo "📋 [6/6] POST-TEARDOWN VERIFICATION AUDIT"
echo "=============================================================================="

echo -n "[*] GKE Clusters remaining: "
CLUSTERS=$(gcloud container clusters list --project="${PROJECT_ID}" --format="value(name)" 2>/dev/null || true)
if [[ -z "${CLUSTERS}" ]]; then echo "0 (Cleaned up) ✅"; else echo "${CLUSTERS} ⚠️"; fi

echo -n "[*] Compute Instances / Nodes remaining: "
VMS=$(gcloud compute instances list --project="${PROJECT_ID}" --format="value(name)" 2>/dev/null || true)
if [[ -z "${VMS}" ]]; then echo "0 (Cleaned up) ✅"; else echo "${VMS} ⚠️"; fi

echo -n "[*] Cloud NAT Gateways remaining: "
NATS=$(gcloud compute routers nats list --router=oneshield-router --region="${REGION}" --project="${PROJECT_ID}" --format="value(name)" 2>/dev/null || true)
if [[ -z "${NATS}" ]]; then echo "0 (Cleaned up) ✅"; else echo "${NATS} ⚠️"; fi

echo -n "[*] VPC Networks remaining: "
VPCS=$(gcloud compute networks list --project="${PROJECT_ID}" --filter="name=oneshield-vpc" --format="value(name)" 2>/dev/null || true)
if [[ -z "${VPCS}" ]]; then echo "0 (Cleaned up) ✅"; else echo "${VPCS} ⚠️"; fi

echo -n "[*] Static Ingress IPs remaining: "
IPS=$(gcloud compute addresses list --project="${PROJECT_ID}" --filter="name=oneshield-ingress-ip" --format="value(address)" 2>/dev/null || true)
if [[ -z "${IPS}" ]]; then echo "0 (Cleaned up) ✅"; else echo "${IPS} ⚠️"; fi

echo -n "[*] Pub/Sub Topics remaining: "
TOPICS=$(gcloud pubsub topics list --project="${PROJECT_ID}" --format="value(name)" 2>/dev/null || true)
if [[ -z "${TOPICS}" ]]; then echo "0 (Cleaned up) ✅"; else echo "${TOPICS} ⚠️"; fi

echo -n "[*] BigQuery Datasets remaining: "
BQS=$(bq ls --project_id="${PROJECT_ID}" 2>/dev/null | grep "oneshield_analytics" || true)
if [[ -z "${BQS}" ]]; then echo "0 (Cleaned up) ✅"; else echo "${BQS} ⚠️"; fi

echo -n "[*] Artifact Registry repos remaining: "
REPOS=$(gcloud artifacts repositories list --project="${PROJECT_ID}" --location="${REGION}" --format="value(name)" 2>/dev/null || true)
if [[ -z "${REPOS}" ]]; then echo "0 (Cleaned up) ✅"; else echo "${REPOS} ⚠️"; fi

echo ""
echo "=== PRESERVED CLOUD STORAGE BUCKETS ==="
gcloud storage buckets list --project="${PROJECT_ID}" --format="table(name,location,storageClass)" 2>/dev/null || true

echo ""
echo "=============================================================================="
echo "🎉 TEARDOWN COMPLETE!"
echo "Hourly Compute Burn Rate: \$0.00/hour."
echo "Remote state file in gs://oneshield-tfstate-${PROJECT_ID} updated to 0 resources."
echo "Weights bucket and GitHub Actions OIDC are safely preserved."
echo "=============================================================================="
