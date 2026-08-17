# app/graph.py
import os
import logging
import langsmith
from typing import Literal, Optional
from langchain_openai import ChatOpenAI
from pydantic import BaseModel as PydanticBaseModel, Field as PydanticField
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from app.schemas import AgentState
from app.schemas import CodeAnalysisFinding
from app.jira_client import create_jira_block_issue
from app.threat_intel import fetch_threat_intel

logger = logging.getLogger("vulnerability-lifecycle-supervisor")


# ==============================================================================
# 📊 STRUCTURED OUTPUT MODELS FOR LLM ANALYSIS
# ==============================================================================

class ReachabilityVerdict(PydanticBaseModel):
    """Structured output for LLM reachability analysis."""
    is_reachable: bool = PydanticField(
        description="Whether the vulnerability is reachable in production code paths"
    )
    justification: str = PydanticField(
        description="Technical explanation of why the code is or isn't reachable"
    )
    confidence: float = PydanticField(
        description="Confidence score between 0.0 and 1.0"
    )


# ==============================================================================
# 🧠 SUPERVISOR NODE
# ==============================================================================
# The central orchestration brain. Evaluates the shared blackboard state
# and determines the next specialized worker node assignment.

def supervisor_node(state: AgentState) -> dict:
    """The central orchestration brain. Evaluates the shared blackboard state 
    and determines the next specialized worker node assignment.
    """
    logger.info(f"🧠 Supervisor evaluating current state engine line for Image: {state.image_sha}")
    
    # ──> PATH 1: PILLAR 1 - INGESTION AND TRIAGE DISPATCHING
    # If raw telemetry exists but hasn't been parsed into the clean schema, dispatch to triage workers
    if state.raw_sast_results and not any(f.source_engine == "SAST" for f in state.triaged_findings):
        logger.info("➡️ Routing state to: SAST Triage Agent")
        return {"next_worker": "sast_triage", "action_log": state.action_log + ["Supervisor routed control to sast_triage."]}
        
    if state.raw_dast_results and not any(f.source_engine == "DAST" for f in state.triaged_findings):
        logger.info("➡️ Routing state to: DAST Report Analysis Agent")
        return {"next_worker": "dast_analysis", "action_log": state.action_log + ["Supervisor routed control to dast_analysis."]}

    if state.raw_container_results and not any(f.source_engine == "CONTAINER" for f in state.triaged_findings):
        logger.info("➡️ Routing state to: Container Image Scan Analysis Agent")
        return {"next_worker": "container_scan", "action_log": state.action_log + ["Supervisor routed control to container_scan."]}

    # If no triaged findings were pulled from any engine, drop out early
    if not state.triaged_findings:
        logger.info("🛑 No actionable scanning records resolved. Terminating workflow.")
        return {"next_worker": "end", "action_log": state.action_log + ["Supervisor terminated run: No findings located."]}

    # ──> PATH 2: PILLAR 2 - DEEP THREAT VERIFICATION
    # If findings are clean, but we haven't run reachability evaluations yet, call the auditor
    if not state.reachability_map:
        logger.info("➡️ Routing state to: Secure Code Review Agent")
        return {"next_worker": "secure_code_review", "action_log": state.action_log + ["Supervisor routed control to secure_code_review."]}

    # ──> PATH 3: GOVERNANCE EVALUATION & POLICY ENFORCEMENT
    # Evaluate the active reachability map against the target domain's rules to pick a strategy
    chosen_strategy: Literal["ALLOW_SIGN", "BLOCK_ALERT", "AUTO_PATCH"] = "ALLOW_SIGN"
    has_reachable_vulnerabilities = any(state.reachability_map.values())

    if has_reachable_vulnerabilities:
        # Rule Tier 1: Core Financial/Sod Isolation Gate
        if state.domain == "InvestmentBank" and any(f.source_engine == "SAST" for f in state.triaged_findings):
            chosen_strategy = "BLOCK_ALERT"
            logger.warning("⚠️ Policy Violation: Tier 1 Human SoD Gate Triggered for InvestmentBank SAST.")
        
        # Rule Tier 2: Architectural Web Edge Controls Gate
        elif any(f.source_engine in ["DAST", "OWASP"] for f in state.triaged_findings):
            chosen_strategy = "BLOCK_ALERT"
            logger.warning("⚠️ Policy Violation: Tier 2 Edge Perimeter Gate Triggered.")
        
        # Rule Tier 3: Standard SCA Autonomous Patch Path
        else:
            chosen_strategy = "AUTO_PATCH"
            logger.info("✅ Compliance Match: Tier 3 Autonomous Dependency Patch Authorized.")
    else:
        logger.info("🟢 All findings verified as unreachable at runtime. Pass-through authorized.")

    # ──> PATH 4: PILLAR 3 & 4 - MITIGATION RUNTIME EXECUTION
    # Route to the appropriate worker based on the resolved policy tier strategy
    if chosen_strategy == "BLOCK_ALERT":
        if state.governance_gate.status == "NOT_TRIGGERED":
            logger.info("➡️ Routing state to: Human Intervention Agent (Jira Ingestion)")
            return {
                "next_worker": "human_intervention", 
                "resolution_strategy": "BLOCK_ALERT",
                "action_log": state.action_log + ["Supervisor routed control to human_intervention."]
            }
        elif state.governance_gate.status == "PENDING_APPROVAL":
            logger.info("⏸️ Execution thread halted: Awaiting out-of-band Human signature verification.")
            return {"next_worker": "end"}
        elif state.governance_gate.status == "APPROVED":
            logger.info("🔓 Human signature verified. Advancing state directly to fixing advisors.")
            chosen_strategy = "AUTO_PATCH"  # Overriding strategy to allow patching post-approval

    if chosen_strategy == "AUTO_PATCH":
        # Direct the payload to the correct specialized code or manifest refactorer
        for finding in state.triaged_findings:
            if state.reachability_map.get(finding.finding_id, False) and finding.finding_id not in state.proposed_patches:
                if finding.source_engine == "SAST":
                    logger.info(f"➡️ Routing finding {finding.finding_id} to: SAST Fixing Advisor Agent")
                    return {"next_worker": "sast_fixing_advisor", "resolution_strategy": "AUTO_PATCH"}
                elif finding.source_engine in ["DAST", "OWASP"]:
                    logger.info(f"➡️ Routing finding {finding.finding_id} to: OWASP Report Fixing Agent")
                    return {"next_worker": "owasp_fixing_agent", "resolution_strategy": "AUTO_PATCH"}

    # ──> BASELINE: Pipeline Sign-off and Completion
    logger.info("🏁 All scheduled worker nodes completed their cycles. Wrapping up graph loops.")
    return {
        "next_worker": "end", 
        "resolution_strategy": chosen_strategy,
        "action_log": state.action_log + ["Supervisor successfully wrapped up orchestration workflow run."]
    }

def supervisor_conditional_router(state: AgentState) -> str:
    """Inspects the state ledger's next_worker string to dictate the absolute 
    physical node transition edge inside LangGraph.
    """
    worker = state.next_worker
    if worker == "end":
        return END
    return worker


# ==============================================================================
# 🔬 SAST TRIAGE AGENT (Worker Node)
# ==============================================================================
# Ingests raw static analysis vulnerability alerts, isolates first-party
# source paths, filters noise, and normalizes findings.

def sast_triage_agent(state: AgentState) -> dict:
    """Worker Node: Ingests raw static analysis vulnerability alerts, isolates 
    first-party source paths, filters noise, and normalizes findings.
    """
    logger.info("🔬 SAST Triage Agent parsing raw static security payloads...")
    
    current_triaged = list(state.triaged_findings)
    logs = []
    
    for raw_alert in state.raw_sast_results:
        # Extract fields out of the underlying payload scanner block
        issue_data = raw_alert.get("issue", {})
        rule_id = issue_data.get("ruleId", "UNKNOWN_SAST_RULE")
        package_name = issue_data.get("packageName", "unknown.package")
        severity = issue_data.get("severity", "HIGH").upper()
        description = issue_data.get("description", "")
        
        # Determine the target source file context by evaluating the package naming convention
        # In a real environment, this translates Java dot notation to real directory coordinates
        file_suffix = ".java" if "bank" in package_name.lower() else ".py"
        derived_file_path = f"src/main/java/{package_name.replace('.', '/')}{file_suffix}"
        
        # 🛡️ NOISE FILTER / DE-DUPLICATION ENGINE
        # Bypass alerts if they don't contain actionable vulnerability markers
        if "test" in package_name.lower() or "mock" in package_name.lower():
            logs.append(f"SAST Triage: Ignored test/mock block anomaly found in {package_name}.")
            continue
            
        # Ensure the severity maps cleanly to our strict schema rules
        clean_severity = "HIGH"
        if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            clean_severity = severity

        # Extract line number dynamically if available in scanner metrics
        extracted_line = issue_data.get("lineNumber", issue_data.get("line", 42))

        # Construct the normalized finding signature object
        finding = CodeAnalysisFinding(
            finding_id=rule_id,
            source_engine="SAST",
            severity=clean_severity,
            package_name=package_name,
            target_file_path=derived_file_path,
            line_number=extracted_line if isinstance(extracted_line, int) else 42,
            raw_payload_snippet=raw_alert
        )
        
        # Prevent appending duplicate findings if the agent executes multiple routing loops
        if not any(f.finding_id == finding.finding_id for f in current_triaged):
            current_triaged.append(finding)
            logs.append(f"SAST Triage: Normalized code security finding signature -> {rule_id}")

    logger.info(f"🔬 SAST Triage finished processing. Total normalized findings: {len(current_triaged)}")
    
    # Return the mutations back to the shared state graph canvas
    return {
        "triaged_findings": current_triaged,
        "action_log": state.action_log + logs
    }


# ==============================================================================
# 🔬 SECURE CODE REVIEW AGENT (Worker Node)
# ==============================================================================
# Combines external threat intelligence (EPSS + CISA KEV) with internal
# code-level LLM analysis to determine runtime exploitability.

@langsmith.traceable(name="fetch_threat_intel", run_type="tool")
def mock_fetch_threat_intel(finding_id: str) -> dict:
    """Simulates a live look up against the CISA KEV catalog and EPSS API endpoints.
    
    In production, this would hit:
    - EPSS: https://api.first.org/data/v1/epss?cve={finding_id}
    - CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    """
    if finding_id == "CVE-2026-3001":
        return {"cisa_kev": True, "epss_score": 0.92}  # High active exploitation in the wild
    if finding_id == "JAVA-S2077" or finding_id == "OWASP-2021-A03:CWE-89":
        return {"cisa_kev": False, "epss_score": 0.45} # Weakness category with active exploitation potential
    return {"cisa_kev": False, "epss_score": 0.01}     # Low risk / No active exploits spotted

def get_task_specific_llm(task_type: str, finding: Optional[CodeAnalysisFinding] = None) -> ChatOpenAI:
    """Factory selecting paid model tier based on task complexity & tech stack layer."""
    high_model = os.environ.get("LLM_MODEL_HIGH_REASONING", "gpt-5.6-sol")
    mid_model  = os.environ.get("LLM_MODEL_WORKHORSE", "gpt-5.6-terra")
    low_model  = os.environ.get("LLM_MODEL_BUDGET", "gpt-5.6-luna")

    if task_type == "PATCH_GENERATION":
        # Highest complexity: Code refactoring requires top agentic capabilities
        return ChatOpenAI(model=high_model, temperature=0)

    if task_type == "REACHABILITY_ANALYSIS" and finding:
        target_file = finding.target_file_path.lower()
        # Java Spring & Oracle PL/SQL call-chain analysis -> High reasoning model
        if target_file.endswith(".java") or "oracle" in target_file or "sql" in target_file:
            return ChatOpenAI(model=high_model, temperature=0)
        # React/Angular Frontend & Configs -> Workhorse model
        elif target_file.endswith((".js", ".jsx", ".ts", ".tsx", ".html")):
            return ChatOpenAI(model=mid_model, temperature=0)
        # Low complexity SCA / Dockerfile dependency triage -> Budget model
        elif finding.source_engine == "CONTAINER":
            return ChatOpenAI(model=low_model, temperature=0)

    # Default fallback workhorse model
    return ChatOpenAI(model=mid_model, temperature=0)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    reraise=True
)
async def safe_structured_llm_invoke(structured_llm, prompt: str):
    """Invokes structured LLM with exponential backoff retry logic for transient API issues."""
    return await structured_llm.ainvoke(prompt)


async def secure_code_review_agent(state: AgentState) -> dict:
    """Worker Node: Combines external threat intelligence (EPSS + CISA KEV) 
    with internal code-level LLM analysis to determine runtime exploitability.
    """
    logger.info("🔬 Secure Code Review Agent running deep threat verification loop...")
    
    updated_reachability = dict(state.reachability_map)
    updated_verdicts = dict(state.detailed_audit_verdicts)
    logs = []

    # Process each triaged finding sitting on the blackboard canvas
    for finding in state.triaged_findings:
        fid = finding.finding_id
        
        # Select dynamic task-specific LLM (e.g. GPT-5.6-Sol for Java/Oracle, Terra for React, Luna for SCA)
        llm = get_task_specific_llm(task_type="REACHABILITY_ANALYSIS", finding=finding)
        structured_llm = llm.with_structured_output(ReachabilityVerdict)
        
        # 🌐 STEP 1: Gather External Threat Intelligence (Real EPSS + CISA KEV APIs)
        # The @langsmith.traceable decorator captures inputs/outputs as a "tool" span
        intel = await fetch_threat_intel(fid)
        is_kev = intel["cisa_kev"]
        epss = intel["epss_score"]
        
        logs.append(f"Threat Intel Context [{fid}]: EPSS Probability = {epss * 100}%, CISA KEV = {is_kev}")

        # 🌐 STEP 1.5: Retrieve Security Grounding Context via MCP RAG Knowledge Server
        from app.mcp_client import MCPClientManager
        mcp_manager = MCPClientManager()
        
        mcp_res = await mcp_manager.invoke_mcp_tool(
            "security-rag-docs",
            "search_security_docs",
            {"target_file_path": finding.target_file_path, "finding_id": fid}
        )
        
        if mcp_res and "result" in mcp_res and "content" in mcp_res["result"]:
            rag_context = mcp_res["result"]["content"][0].get("text", "")
            logs.append(f"MCP Tool [security-rag-docs]: Retrieved grounded context via MCP server protocol.")
        else:
            # Fallback to local RAG store if MCP server daemon is offline
            from app.rag_store import OneShieldRAGStore
            rag_store = OneShieldRAGStore()
            rag_context = rag_store.retrieve_relevant_context(finding.target_file_path, fid)
            logs.append(f"RAG Fallback: Retrived local context for [{fid}].")

        # 🛡️ STEP 2: LLM-Powered Code Path Reachability Check (MCP + RAG Grounded)
        prompt = (
            f"Analyze the following vulnerability for runtime reachability:\n"
            f"- Finding ID: {fid}\n"
            f"- Source Engine: {finding.source_engine}\n"
            f"- Package: {finding.package_name}\n"
            f"- Target File: {finding.target_file_path}\n"
            f"- Severity: {finding.severity}\n"
            f"- EPSS Score: {epss}\n"
            f"- CISA KEV Listed: {is_kev}\n\n"
            f"SECURITY REFERENCE CONTEXT (MCP Grounded Docs):\n{rag_context}\n\n"
            f"Determine if this vulnerability is reachable in a production "
            f"code path and could be actively exploited. Consider whether the "
            f"package is imported in application-facing code or only in test/build "
            f"infrastructure."
        )

        # GUARDRAIL: Wrap LLM call with retry logic & error handling to prevent pipeline crash
        try:
            verdict = await safe_structured_llm_invoke(structured_llm, prompt)
        except Exception as ex:
            logger.error(f"LLM reachability analysis failed for {fid}: {ex}")
            # FAIL-SAFE: Treat as reachable to avoid dangerous false negatives
            verdict = ReachabilityVerdict(
                is_reachable=True,
                justification=f"LLM error fallback — treating as reachable for safety. Error: {str(ex)[:100]}",
                confidence=0.0
            )

        # GUARDRAIL: Reject low-confidence LLM outputs (Layer 3 hallucination prevention)
        if verdict.confidence < 0.70:
            logger.warning(
                f"Low confidence ({verdict.confidence:.2f}) for {fid} — "
                f"defaulting to REACHABLE for safety"
            )
            is_code_reachable = True  # Fail-safe: uncertain = reachable
        else:
            is_code_reachable = verdict.is_reachable

        logs.append(
            f"LLM Reachability [{fid}]: reachable={is_code_reachable}, "
            f"confidence={verdict.confidence:.2f}, "
            f"confidence_gate={'PASS' if verdict.confidence >= 0.70 else 'FAIL-SAFE'}, "
            f"reason='{verdict.justification[:80]}...'"
        )

        # 📊 STEP 3: Synthesize the Final Prioritization Verdict
        # Combine LLM reachability analysis with external threat intelligence
        # to produce a weighted, explainable verdict.
        #
        # Priority Matrix:
        #   - KEV-listed OR (high EPSS + reachable) → CRITICAL EXPOSURE
        #   - Reachable but low external threat velocity → HIGH RISK
        #   - Unreachable (LLM determined dead code) → LOW RISK
        if is_kev or (epss > 0.70 and is_code_reachable):
            updated_reachability[fid] = True
            verdict_text = (
                f"CRITICAL EXPOSURE VERDICT: Finding {fid} targeting package '{finding.package_name}' "
                f"is actively verified as REACHABLE in our codebase. Furthermore, external threat intel "
                f"confirms active exploit velocity (EPSS: {epss}, CISA KEV: {is_kev}). "
                f"LLM Confidence: {verdict.confidence}. Justification: {verdict.justification}. "
                f"Immediate remediation required."
            )
        elif is_code_reachable:
            # Code is reachable but no mass active exploits are tracked in the wild yet
            updated_reachability[fid] = True
            verdict_text = (
                f"HIGH RISK VERDICT: Finding {fid} is reachable via path '{finding.target_file_path}', "
                f"but external threat velocity is currently stable (EPSS: {epss}). "
                f"LLM Confidence: {verdict.confidence}. Justification: {verdict.justification}. "
                f"Gating patch recommended."
            )
        else:
            # Code path is completely dead or unreachable
            updated_reachability[fid] = False
            verdict_text = (
                f"LOW RISK VERDICT: Finding {fid} is dead/unreachable code. "
                f"LLM Confidence: {verdict.confidence}. Justification: {verdict.justification}. "
                f"Exploit risk mitigated."
            )

        updated_verdicts[fid] = verdict_text
        logs.append(f"Secure Code Reviewer finalized analysis for: {fid}")

    return {
        "reachability_map": updated_reachability,
        "detailed_audit_verdicts": updated_verdicts,
        "action_log": state.action_log + logs
    }


# ==============================================================================
# 🌐 DAST ANALYSIS AGENT (Worker Node)
# ==============================================================================
# Ingests dynamic DAST logs and maps endpoint targets.

def dast_analysis_agent(state: AgentState) -> dict:
    """Worker Node: Ingests dynamic DAST logs and maps endpoint targets."""
    logger.info("🌐 DAST Analysis Agent parsing runtime transaction vulnerabilities...")
    current_triaged = list(state.triaged_findings)
    logs = []
    
    for raw in state.raw_dast_results:
        alert = raw.get("alert", {})
        rule_id = alert.get("ruleId", "UNKNOWN_DAST_CWE")
        pkg = alert.get("packageName", "/api/v1/edge")
        
        target_file = alert.get("target_file", alert.get("file", alert.get("targetUrl", "kubernetes/ingress-routing-edge.yaml")))

        finding = CodeAnalysisFinding(
            finding_id=rule_id,
            source_engine="DAST",
            severity=alert.get("severity", "HIGH").upper(),
            package_name=pkg,
            target_file_path=target_file,
            raw_payload_snippet=raw
        )
        if not any(f.finding_id == finding.finding_id for f in current_triaged):
            current_triaged.append(finding)
            logs.append(f"DAST Analyzer: Isolated dynamic web asset threat signature -> {rule_id}")

    return {"triaged_findings": current_triaged, "action_log": state.action_log + logs}


# ==============================================================================
# 🐳 CONTAINER SCAN AGENT (Worker Node)
# ==============================================================================
# Ingests container base-image CVE vulnerabilities.

def container_scan_agent(state: AgentState) -> dict:
    """Worker Node: Ingests container base-image CVE vulnerabilities."""
    logger.info("🐳 Container Scan Agent auditing base-image dependencies...")
    current_triaged = list(state.triaged_findings)
    logs = []
    
    for raw in state.raw_container_results:
        vuln = raw.get("vulnerability", {})
        cve_id = vuln.get("cveId", "UNKNOWN_CVE")
        pkg = vuln.get("packageName", "unknown-binary")
        
        finding = CodeAnalysisFinding(
            finding_id=cve_id,
            source_engine="CONTAINER",
            severity=vuln.get("severity", "HIGH").upper(),
            package_name=pkg,
            target_file_path="Dockerfile",
            raw_payload_snippet=raw
        )
        if not any(f.finding_id == finding.finding_id for f in current_triaged):
            current_triaged.append(finding)
            logs.append(f"Container Analyzer: Normalized base-image dependency threat -> {cve_id}")

    return {"triaged_findings": current_triaged, "action_log": state.action_log + logs}


# ==============================================================================
# 🛠️ SAST FIXING ADVISOR AGENT (Worker Node)
# ==============================================================================
# Refactors first-party code files using secure design patterns.

async def sast_fixing_advisor_agent(state: AgentState) -> dict:
    """Worker Node: Refactors first-party code files using secure design patterns."""
    logger.info("🛠️ SAST Fixing Advisor Agent synthesizing first-party code patch...")
    from app.schemas import CodePatchArtifact
    
    updated_patches = dict(state.proposed_patches)
    logs = []
    
    # Use top-tier reasoning LLM for patch generation (e.g. GPT-5.6 Sol / Claude Fable 5)
    llm = get_task_specific_llm(task_type="PATCH_GENERATION")
    structured_llm = llm.with_structured_output(CodePatchArtifact)
    
    for finding in state.triaged_findings:
        if finding.source_engine == "SAST" and state.reachability_map.get(finding.finding_id, False):
            prompt = (
                f"Generate a secure code patch for the following vulnerability:\n"
                f"- Rule ID: {finding.finding_id}\n"
                f"- Target File: {finding.target_file_path}\n"
                f"- Package: {finding.package_name}\n\n"
                f"Provide the original vulnerable code snippet, the secure remediated code block, "
                f"and a clear technical explanation of the fix (e.g., converting dynamic concatenation to PreparedStatement)."
            )
            try:
                artifact = await structured_llm.ainvoke(prompt)
            except Exception as ex:
                logger.warning(f"Fallback to structured template patch for {finding.finding_id}: {ex}")
                artifact = CodePatchArtifact(
                    target_file_path=finding.target_file_path,
                    original_code_block="String query = \"SELECT * FROM users WHERE id = '\" + input + \"'\";",
                    remediated_code_block="PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setString(1, input);",
                    explanation="Refactored dynamic SQL query concatenation into a secure Parameterized PreparedStatement."
                )
            updated_patches[finding.finding_id] = artifact
            logs.append(f"SAST Advisor: Created patch code block modification for {finding.finding_id}")
            
    return {"proposed_patches": updated_patches, "action_log": state.action_log + logs}


# ==============================================================================
# 🛡️ OWASP FIXING AGENT (Worker Node)
# ==============================================================================
# Refactors perimeter infrastructure manifests and security headers.

async def owasp_fixing_agent(state: AgentState) -> dict:
    """Worker Node: Corrects perimeter infrastructure manifests or security headers."""
    logger.info("🛡️ OWASP Fixing Agent modifying edge infrastructure manifests...")
    from app.schemas import CodePatchArtifact
    
    updated_patches = dict(state.proposed_patches)
    logs = []
    
    llm = get_task_specific_llm(task_type="PATCH_GENERATION")
    structured_llm = llm.with_structured_output(CodePatchArtifact)
    
    for finding in state.triaged_findings:
        if finding.source_engine == "DAST" and state.reachability_map.get(finding.finding_id, False):
            prompt = (
                f"Generate a secure perimeter manifest patch for OWASP finding:\n"
                f"- Finding ID: {finding.finding_id}\n"
                f"- Target File: {finding.target_file_path}\n\n"
                f"Provide original code block, remediated code block with security headers/SSL flags, and explanation."
            )
            try:
                artifact = await structured_llm.ainvoke(prompt)
            except Exception as ex:
                logger.warning(f"Fallback to perimeter template patch for {finding.finding_id}: {ex}")
                artifact = CodePatchArtifact(
                    target_file_path=finding.target_file_path,
                    original_code_block="nginx.ingress.kubernetes.io/ssl-redirect: \"false\"",
                    remediated_code_block="nginx.ingress.kubernetes.io/ssl-redirect: \"true\"\nnginx.ingress.kubernetes.io/configuration-snippet: |\n  more_set_headers \"X-Frame-Options: DENY\";",
                    explanation="Injected missing secure perimeter transmission flags and frame transport protections."
                )
            updated_patches[finding.finding_id] = artifact
            logs.append(f"OWASP Advisor: Injected perimeter transport control protections for {finding.finding_id}")
            
    return {"proposed_patches": updated_patches, "action_log": state.action_log + logs}


# ==============================================================================
# 👥 HUMAN INTERVENTION AGENT (Worker Node)
# ==============================================================================
# Dispatches detailed security alerts to Jira Cloud when a governance
# policy boundary is crossed.

async def human_intervention_agent(state: AgentState) -> dict:
    """Worker Node: Dispatches detailed security alerts to Jira Cloud 
    when a governance policy boundary is crossed.
    """
    logger.info("👥 Human Intervention Agent generating governance compliance ticket...")
    
    # Isolate the target finding that ACTUALLY triggered the block
    # (pick the first reachable finding, not blindly index 0)
    target_finding = next(
        (f for f in state.triaged_findings
         if state.reachability_map.get(f.finding_id, False)),
        state.triaged_findings[0]  # fallback if none marked reachable
    )
    fid = target_finding.finding_id
    verdict_context = state.detailed_audit_verdicts.get(fid, "Policy exception restriction enforced.")
    
    # Fire the async Jira client — @langsmith.traceable on create_jira_block_issue
    # captures the full request/response cycle as a "tool" span in the trace
    ticket_url = await create_jira_block_issue(
        cve_id=fid,
        package_name=target_finding.package_name,
        domain=state.domain,
        target_file=target_finding.target_file_path,
        analysis_text=verdict_context
    )
    
    # Mutate the governance gate ledger state
    updated_gate = state.governance_gate.model_copy(update={
        "status": "PENDING_APPROVAL",
        "jira_ticket_key": ticket_url.split("/")[-1],
        "jira_ticket_url": ticket_url
    })
    
    return {
        "governance_gate": updated_gate,
        "action_log": state.action_log + [f"Human Intervention Gate: Raised tracking item card -> {ticket_url}"]
    }


# ==============================================================================
# 🕸️ THE LANGGRAPH PIPELINE ASSEMBLY ENGINE
# ==============================================================================
workflow = StateGraph(AgentState)

# 1. Register the centralized agent orchestration team nodes
workflow.add_node("supervisor", supervisor_node)
workflow.add_node("sast_triage", sast_triage_agent)
workflow.add_node("dast_analysis", dast_analysis_agent)
workflow.add_node("container_scan", container_scan_agent)
workflow.add_node("secure_code_review", secure_code_review_agent)
workflow.add_node("sast_fixing_advisor", sast_fixing_advisor_agent)
workflow.add_node("owasp_fixing_agent", owasp_fixing_agent)
workflow.add_node("human_intervention", human_intervention_agent)

# 2. Wire the hub-and-spoke entry and conditional feedback edges
workflow.set_entry_point("supervisor")

workflow.add_conditional_edges(
    "supervisor",
    supervisor_conditional_router,
    {
        "sast_triage": "sast_triage",
        "dast_analysis": "dast_analysis",
        "container_scan": "container_scan",
        "secure_code_review": "secure_code_review",
        "sast_fixing_advisor": "sast_fixing_advisor",
        "owasp_fixing_agent": "owasp_fixing_agent",
        "human_intervention": "human_intervention",
        END: END
    }
)

# 3. Direct all worker returns straight back to the supervisor router hub
workflow.add_edge("sast_triage", "supervisor")
workflow.add_edge("dast_analysis", "supervisor")
workflow.add_edge("container_scan", "supervisor")
workflow.add_edge("secure_code_review", "supervisor")
workflow.add_edge("sast_fixing_advisor", "supervisor")
workflow.add_edge("owasp_fixing_agent", "supervisor")
workflow.add_edge("human_intervention", "supervisor")

# 4. Compile the runtime agent pipeline artifact with persistent MemorySaver checkpointer
checkpointer = MemorySaver()
app_orchestration_agent = workflow.compile(checkpointer=checkpointer)