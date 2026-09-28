# Runbook RB-02: Pub/Sub Dead-Letter Queue (DLQ) Triage (P1 Critical)

## 1. Incident Overview
* **Severity**: **P1 (Critical)**
* **Trigger Condition**: One or more vulnerability alert messages have failed delivery 5 consecutive times and have been moved to the Dead-Letter Queue (`vulnerability-scan-dlq`).
* **Escalation Notification**: PagerDuty / Push notification to On-Call SRE.
* **Target Ack Time**: $< 30\text{ minutes}$.

---

## 2. Immediate Diagnostic Steps

1. **Check DLQ Backlog Depth**:
   ```bash
   gcloud pubsub subscriptions describe vulnerability-scan-dlq-sub \
     --project=project-517889ec-8518-4856-a51 \
     --format="value(numUndeliveredMessages)"
   ```

2. **Pull and Inspect Dead-Lettered Payloads (Without Auto-Ack)**:
   ```bash
   gcloud pubsub subscriptions pull vulnerability-scan-dlq-sub \
     --project=project-517889ec-8518-4856-a51 \
     --limit=3 \
     --format="json"
   ```

3. **Determine Cause of Failure**:
   * **Malformed JSON**: Syntax error (e.g. unescaped quotes or invalid ASCII characters).
   * **Schema Mismatch**: Missing required fields (`vulnerability_id`, `code_snippet`, or `metadata`).
   * **Worker Out-of-Memory / Crash**: Pod restarted while processing the payload.
   * Check worker logs around the failure timestamp:
     ```bash
     gcloud logging read 'resource.type="k8s_container" AND resource.labels.namespace_name="ai-stack" AND severity>=ERROR' --limit=10 --project=project-517889ec-8518-4856-a51
     ```

---

## 3. Remediation & Replay Procedures

### Scenario A: Poison Payload from Upstream Scanner
If the payload is corrupted or contains illegal syntax:
1. Copy the raw payload for engineering post-mortem.
2. Acknowledge and purge the poisoned message from the DLQ subscription:
   ```bash
   gcloud pubsub subscriptions pull vulnerability-scan-dlq-sub --auto-ack --limit=1
   ```
3. File a bug report with the scanner integration team (e.g. SonarQube / Checkmarx webhook payload format).

### Scenario B: Transient Downstream Outage (e.g. SGLang or Cloud Storage Glitch)
If the message failed due to a temporary service disruption that is now resolved:
1. Re-publish the sanitized message back to the primary queue:
   ```bash
   gcloud pubsub topics publish vulnerability-scan-queue \
     --project=project-517889ec-8518-4856-a51 \
     --message='<SANITIZED_JSON_PAYLOAD>'
   ```
2. Verify that the worker successfully ingests the finding:
   ```bash
   kubectl logs deployment/oneshield-app -n ai-stack --tail=20
   ```
3. Acknowledge and remove the message from the DLQ.

---

## 4. Post-Incident Checklist
- [ ] Ensure DLQ subscription backlog has returned to `0`.
- [ ] Confirm the primary `oneshield-app` subscriber pod remains healthy and in `Running` status.
- [ ] Resolve the PagerDuty incident with resolution notes detailing the root cause.
