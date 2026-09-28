# Runbook RB-05: Weekly Observability, Throughput & GPU Cost Audit (P3 Informational)

## 1. Overview
* **Severity**: **P3 (Informational)**
* **Frequency**: Weekly (Every Monday morning).
* **Audience**: AppSec Lead, SRE Lead, and Cloud Platform FinOps.
* **Notification Channel**: Weekly Email Digest.

---

## 2. Key Weekly Metrics & KPI Checklist

| Metric | Target / Benchmark | Action Threshold | Remediation Reference |
| :--- | :--- | :--- | :--- |
| **Total Scans Triaged** | $> 500\text{ scans/week}$ | $< 50\text{ scans/week}$ (Check webhook ingestion health) | Check Ingress & API Gateway logs |
| **Jev Benign Fast-Discard Ratio** | $\approx 40\text{--}60\%$ | $< 20\%$ (Check scanner rule changes) | Inspect AST regex rules in `JevEngine` |
| **CISA KEV 24h SLA Compliance** | **$100\%$** | $< 100\%$ (Regulatory breach) | Runbook RB-01 |
| **GPU Scale-to-Zero Efficiency** | Idle $\ge 80\%$ of time | Scaled up $> 50\%$ with 0 queue | Check KEDA cooldown period / idle metric |
| **DLQ Message Count** | **`0`** | $> 0$ | Runbook RB-02 |
| **Gate 3 Average Safety Score** | $\ge 0.90$ | $< 0.85$ | Runbook RB-04 |

---

## 3. Data Extraction Commands

### 3.1 Scrape Swarm Metrics from GKE
```powershell
kubectl exec -n ai-stack deployment/oneshield-app -- python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/metrics').read().decode())"
```

### 3.2 Audit GPU Node Utilization & Scaling Events in GCP
```bash
gcloud logging read 'resource.type="k8s_cluster" AND jsonPayload.message=~"sglang"' --limit=20 --project=project-517889ec-8518-4856-a51
```

### 3.3 Verify Threat Intel Synchronization Freshness
```powershell
kubectl exec -n default deployment/oneshield-api-gateway -- redis-cli -h redis-master.default GET cisa:kev:last_sync
```

---

## 4. Reporting Template
Format and email the weekly report to stakeholders:
```text
Subject: [OneShield SRE Report] Weekly Vulnerability Swarm Telemetry - Week <WEEK_NUM>

1. Throughput & Routing Efficiency:
   - Total Scans Ingested: XXX
   - Jev In-Process Fast-Discards ($0 GPU Cost): XXX (XX%)
   - CISA KEV Emergency Fast-Path Scans: XXX (100% within SLA)
   - Dual-Track Judge Consensus Invocations: XXX

2. AI Quality & Safety Gates:
   - Gate 1 (AST Syntax) Pass Rate: XX.X%
   - Gate 2 (Secrets Scan) Pass Rate: 100%
   - Gate 3 (Jev Safety Score) Average: 0.XX
   - 1-Shot Self-Correction Triggers: XX (X.X%)

3. Infrastructure & FinOps:
   - GPU (NVIDIA L4) Active Run Hours: XX hours
   - KEDA Scale-to-Zero Idle Savings: $XXX.XX estimated
   - DLQ Poison Messages: 0
   - Infrastructure Drift: Clean (0 diff)
```
