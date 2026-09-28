# Runbook RB-03: Confidence Circuit Breaker Surge (P2 Warning)

## 1. Incident Overview
* **Severity**: **P2 (Warning)**
* **Trigger Condition**: Swarm Confidence Circuit Breaker trips exceed **5%** of all triaged scans within a 1-hour window.
* **Escalation Notification**: **Email** sent to `appsec-team@bank.com`.
* **Target Ack Time**: $< 2\text{ hours}$.

---

## 2. Technical Context & Circuit Breaker Logic
The OneShield swarm employs two confidence defense layers:
1. **Layer 1 (Jev System 1 Pre-Router Anomaly Detector)**: Trips if input contains missing keys, empty code, or illegal delimiter structures.
2. **Layer 2 (Judging Panel Confidence Breaker)**: Trips if either Judge A or Judge B reports a self-confidence score $< 0.70$, or if the consensus divergence between reachability and governance judges exceeds the safe divergence threshold.

When tripped, autonomous patch synthesis is immediately halted, state is cryptographically signed, and the finding is escalated to human engineers with an `escalation_reason`.

---

## 3. Immediate Diagnostic Steps

1. **Query Cloud Logging for Escalated Findings**:
   ```bash
   gcloud logging read 'resource.type="k8s_container" AND resource.labels.namespace_name="ai-stack" AND jsonPayload.circuit_breaker_tripped=true' --limit=10 --project=project-517889ec-8518-4856-a51 --format="table(timestamp,jsonPayload.vulnerability_id,jsonPayload.message)"
   ```

2. **Check Prometheus Circuit Breaker Metric**:
   ```powershell
   kubectl exec -n ai-stack deployment/oneshield-app -- python -c "import urllib.request; data = urllib.request.urlopen('http://localhost:8080/metrics').read().decode(); print('\n'.join([l for l in data.splitlines() if 'circuit_breaker' in l]))"
   ```

3. **Analyze Common Patterns in Tripped Scans**:
   * Are the alerts from an exotic programming language not supported by current LoRA adapters (e.g. Cobol, Rust, Go)?
   * Has a new scanner rule been deployed that generates highly ambiguous AST snippets?
   * Is the SGLang inference temperature fluctuating or is KV cache memory constrained?

---

## 4. Remediation Procedures

1. **Review Escalated Tickets**: Inspect the escalated findings queued for security team review.
2. **LoRA Retraining Trigger**: If the surge is due to a new framework version (e.g. Spring Boot 3.3 synthetic methods), tag the findings and export them into the continuous retraining dataset.
3. **Temporary Circuit Breaker Tuning**: If a specific scanner rule ID is known to be overly ambiguous, update the scanner exclusion policy in NeMo Guardrails or adjust the confidence threshold via environment variables:
   ```yaml
   env:
   - name: CONFIDENCE_THRESHOLD
     value: "0.65" # Temporarily lowered from 0.70 during rule recalibration
   ```
