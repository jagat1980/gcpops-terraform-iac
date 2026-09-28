# 🛡️ OneShield: Infrastructure as Code (Terraform & GKE Autopilot)

Enterprise Multi-Agent AI Vulnerability Management & Remediation Platform infrastructure, powered by **Terraform**, **Google Kubernetes Engine (GKE Autopilot)**, **Cloud Storage**, **Google Cloud Pub/Sub**, and **Cloud Monitoring**.

---

## 🏗️ Architecture Overview

* **GKE Autopilot Cluster**: `oneshield-gke-cluster` in `us-central1`.
* **AI Compute Stack (`ai-stack` namespace)**:
  * `oneshield-app`: FastAPI + LangGraph Multi-Agent Swarm with **Jev System 1 In-Process Intelligence** (<0.05ms benign filter).
  * `sglang-server`: SGLang inference engine on **NVIDIA L4 (24GB)** serving Qwen2.5-Coder-7B with dynamic Multi-LoRA.
  * `sglang-pubsub-scaler`: **KEDA ScaledObject** scaling `sglang-server` from 0 to 1 based on Pub/Sub queue depth (`minReplica: 0`).
* **Ingress & Networking**:
  * External HTTP Load Balancer: `http://34.8.57.243` routing to `oneshield-api-service`.
  * Private VPC with Cloud Router & Cloud NAT for secure egress.
* **Event Ingestion & Message Broker**:
  * Topic: `projects/project-517889ec-8518-4856-a51/topics/vulnerability-scan-queue`.
  * Subscription: `projects/project-517889ec-8518-4856-a51/subscriptions/vulnerability-scan-worker-sub`.
* **Model Storage**:
  * `gs://oneshield-llm-weights-87d68625/` (Base models and LoRA adapters: `oracle-sql`, `java-spring`, `judge-reachability`, `judge-governance`).
* **Observability & SRE**:
  * Cloud Logging structured JSON with OpenTelemetry trace correlation (`Cloud Trace`).
  * Custom AI Metrics exported to Google Managed Prometheus (`GMP`).
  * Cloud Monitoring alert policies for circuit breaker trips and SLA breaches.

---

## 🚀 Quick Verification Commands

### 1. Ingress Health Check
```powershell
curl.exe -i http://34.8.57.243/health
```

### 2. Inspect Cluster Resources in `ai-stack`
```powershell
kubectl get pods,deployments,scaledobjects -n ai-stack
```

### 3. Check Live Prometheus AI Metrics
```powershell
kubectl exec -n ai-stack deployment/oneshield-app -- python -c "import urllib.request; data = urllib.request.urlopen('http://localhost:8080/metrics').read().decode(); print('\n'.join([line for line in data.splitlines() if 'oneshield_' in line]))"
```

For the complete testing, verification, and Day 2 operational runbooks, see:
* [Testing & Verification Manual](file:///C:/myailearn/projects/vulnerability-management-localmodel-fineturning/docs/TESTING_AND_VERIFICATION.md)
* [Day 2 Operations & Maintenance Manual](file:///C:/myailearn/projects/vulnerability-management-localmodel-fineturning/docs/DAY2_OPERATIONS.md)
* [SRE Incident Runbooks](file:///C:/myailearn/projects/vulnerability-management-localmodel-fineturning/docs/runbooks/)
