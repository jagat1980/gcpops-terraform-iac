# Runbook RB-04: Gate 3 Safety Score Regression (P2 Warning)

## 1. Incident Overview
* **Severity**: **P2 (Warning)**
* **Trigger Condition**: Average Gate 3 Jev Safety Score falls below **0.85**, or the 1-Shot Self-Correction rate exceeds **15%** over a 24-hour evaluation window.
* **Escalation Notification**: **Email** sent to `appsec-team@bank.com`.
* **Target Ack Time**: $< 4\text{ hours}$.

---

## 2. Technical Context & Gate 3 Evaluation Flywheel
All patches synthesized by the SGLang coding model must pass through the **Three-Gate Flywheel**:
* **Gate 1**: Lexical / AST Delimiter Integrity (matching parentheses, brackets, quotes).
* **Gate 2**: Secret & Credential Leak Scan (detects API keys, passwords, private keys).
* **Gate 3**: Jev TypeSafe Safety & Regression Risk Scoring (deterministic scoring $\in [0.0, 1.0]$ based on parameterization quality, regression risk, and semantic drift).

If a patch scores $< 0.85$ on Gate 3:
1. The 1-Shot Self-Correction Loop is engaged.
2. Jev injects a structured critique into the context.
3. The SGLang model attempts **one corrective retry**.
4. If the retry fails, the finding is escalated to human DBA/AppSec engineers.

---

## 3. Immediate Diagnostic Steps

1. **Inspect Prometheus Safety Metrics**:
   ```powershell
   kubectl exec -n ai-stack deployment/oneshield-app -- python -c "import urllib.request; data = urllib.request.urlopen('http://localhost:8080/metrics').read().decode(); print('\n'.join([l for l in data.splitlines() if 'gate3' in l]))"
   ```
   Check:
   * `oneshield_gate3_safety_score_bucket`: Distribution of scores.
   * `oneshield_gate3_self_corrections_total`: Frequency of retry loops.

2. **Query Cloud Logging for Gate Failures**:
   ```bash
   gcloud logging read 'resource.type="k8s_container" AND resource.labels.namespace_name="ai-stack" AND textPayload=~"Gate 3"' --limit=10 --project=project-517889ec-8518-4856-a51
   ```

3. **Check LoRA Adapter Version in SGLang**:
   Verify whether a newly deployed LoRA adapter (e.g. `oracle-sql-v2`) is causing regression:
   ```bash
   kubectl logs deployment/sglang-server -n ai-stack --tail=50
   ```

---

## 4. Remediation & Rollback Procedures

### Scenario A: Flawed LoRA Model Promotion
If the safety score regression correlates directly with a recent LoRA adapter hot-reload:
1. Roll back SGLang to the previous verified LoRA adapter version in GCS:
   ```bash
   kubectl exec -n ai-stack deployment/oneshield-app -- python3 -c "
   import requests
   res = requests.post(
       'http://sglang-service.ai-stack.svc.cluster.local:8000/load_lora_adapter',
       json={'adapter_name': 'oracle-sql', 'adapter_path': '/mnt/gcs-weights/lora/oracle-v1'}
   )
   print('Rollback result:', res.status_code)
   "
   ```
2. Verify that Gate 3 safety scores immediately return to $\ge 0.95$.

### Scenario B: Novel Code Patterns (Need Training Data)
If the regression is driven by complex legacy SQL or esoteric ORM patterns:
1. Export the failed patch attempts and human corrections.
2. Add them to the supervised fine-tuning dataset for the next monthly retraining cycle.
