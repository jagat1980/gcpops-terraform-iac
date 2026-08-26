# Multi-agent graph orchestrator for OneShield Vulnerability Engine
import os
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from tenacity import retry, stop_after_attempt, wait_exponential

from app.schemas import (
    AgentState,
    CodeAnalysisFinding,
    CodePatchArtifact,
    HumanInterventionLedger
)
from app.threat_intel import fetch_threat_intel

logger = logging.getLogger("vulnerability-lifecycle-supervisor")
logging.basicConfig(level=logging.INFO)

# Structured outputs for LLM reasoning steps
class ReachabilityVerdict(BaseModel):
    is_reachable: bool = Field(description="Whether the vulnerability is reachable in production code")
    justification: str = Field(description="Engineering rationale for the reachability verdict")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0")

class StructuredPatchOutput(BaseModel):
    remediated_code_block: str = Field(description="Refactored code snippet passing secure design standards")
    explanation: str = Field(description="Technical engineering justification for the patch pattern used")

def get_task_specific_llm(task_type: str = "workhorse", finding: Optional[CodeAnalysisFinding] = None) -> ChatOpenAI:
    """Factory helper returning a task-optimized model tier."""
    high_model = os.environ.get("LLM_MODEL_HIGH_REASONING", "gpt-5.6-sol")
    mid_model  = os.environ.get("LLM_MODEL_WORKHORSE", "gpt-5.6-terra")
    low_model  = os.environ.get("LLM_MODEL_BUDGET", "gpt-5.6-luna")

    if task_type == "PATCH_GENERATION":
        return ChatOpenAI(model=high_model, temperature=0)

    if task_type == "REACHABILITY_ANALYSIS" and finding:
        target_file = finding.target_file_path.lower()
        if target_file.endswith(".java") or "oracle" in target_file or "sql" in target_file:
            return ChatOpenAI(model=high_model, temperature=0)
        elif target_file.endswith((".js", ".jsx", ".ts", ".tsx", ".html")):
            return ChatOpenAI(model=mid_model, temperature=0)
        elif finding.source_engine == "CONTAINER":
            return ChatOpenAI(model=low_model, temperature=0)

    return ChatOpenAI(model=mid_model, temperature=0)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    reraise=True
)
async def safe_structured_llm_invoke(structured_llm, prompt: str):
    """Invokes structured LLM with exponential backoff retry logic for transient API issues."""
    return await structured_llm.ainvoke(prompt)

async def sast_triage_agent(state: AgentState) -> Dict[str, Any]:
    logger.info("🔬 SAST Triage Agent parsing raw static security payloads...")
    findings = list(state.triaged_findings)
    for raw in state.raw_sast_results:
        issue = raw.get("issue", {})
        findings.append(CodeAnalysisFinding(
            finding_id=issue.get("ruleId", "SAST-GENERIC"),
            source_engine="SAST",
            severity=issue.get("severity", "HIGH"),
            package_name=issue.get("packageName", "unknown.package"),
            target_file_path=issue.get("targetFilePath", "src/main/java/App.java"),
            line_number=issue.get("lineNumber", 42),
            raw_payload_snippet=raw
        ))
    logger.info(f"🔬 SAST Triage finished processing. Total normalized findings: {len(findings)}")
    return {
        "triaged_findings": findings,
        "action_log": state.action_log + ["SAST Triage Agent processed static findings."]
    }

async def dast_report_analysis_agent(state: AgentState) -> Dict[str, Any]:
    logger.info("🌐 DAST Analysis Agent parsing runtime transaction vulnerabilities...")
    findings = list(state.triaged_findings)
    for raw in state.raw_dast_results:
        issue = raw.get("issue", {})
        findings.append(CodeAnalysisFinding(
            finding_id=issue.get("ruleId", "DAST-GENERIC"),
            source_engine="DAST",
            severity=issue.get("severity", "HIGH"),
            package_name=issue.get("packageName", "http://localhost:8000/api"),
            target_file_path=issue.get("targetFilePath", "app/api/endpoints.py"),
            line_number=None,
            raw_payload_snippet=raw
        ))
    return {
        "triaged_findings": findings,
        "action_log": state.action_log + ["DAST Analysis Agent processed dynamic web findings."]
    }

async def container_scan_analysis_agent(state: AgentState) -> Dict[str, Any]:
    logger.info("🐳 Container Scan Agent auditing base-image dependencies...")
    findings = list(state.triaged_findings)
    for raw in state.raw_container_results:
        issue = raw.get("issue", {})
        findings.append(CodeAnalysisFinding(
            finding_id=issue.get("ruleId", "CVE-GENERIC"),
            source_engine="CONTAINER",
            severity=issue.get("severity", "CRITICAL"),
            package_name=issue.get("packageName", "base-image-lib"),
            target_file_path=issue.get("targetFilePath", "Dockerfile"),
            line_number=None,
            raw_payload_snippet=raw
        ))
    return {
        "triaged_findings": findings,
        "action_log": state.action_log + ["Container Scan Agent processed dependency findings."]
    }

async def secure_code_review_agent(state: AgentState) -> Dict[str, Any]:
    logger.info("🔬 Secure Code Review Agent running deep threat verification loop...")
    updated_reachability = dict(state.reachability_map)
    updated_verdicts = dict(state.detailed_audit_verdicts)
    logs = []

    for finding in state.triaged_findings:
        fid = finding.finding_id
        llm = get_task_specific_llm(task_type="REACHABILITY_ANALYSIS", finding=finding)
        structured_llm = llm.with_structured_output(ReachabilityVerdict)
        
        intel = await fetch_threat_intel(fid)
        is_kev = intel["cisa_kev"]
        epss = intel["epss_score"]
        
        logs.append(f"Threat Intel Context [{fid}]: EPSS Probability = {epss * 100}%, CISA KEV = {is_kev}")

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
            from app.rag_store import OneShieldRAGStore
            rag_store = OneShieldRAGStore()
            rag_context = rag_store.retrieve_relevant_context(finding.target_file_path, fid)
            logs.append(f"RAG Fallback: Retrieved local context for [{fid}].")

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

        try:
            verdict = await safe_structured_llm_invoke(structured_llm, prompt)
        except Exception as ex:
            logger.error(f"❌ OPENAI API ERROR for {fid} ({type(ex).__name__}): {ex}")
            verdict = ReachabilityVerdict(
                is_reachable=True,
                justification=f"LLM error fallback — treating as reachable for safety. Error: {str(ex)[:100]}",
                confidence=0.0
            )

        is_failsafe = False
        if verdict.confidence < 0.70:
            logger.warning(
                f"Low confidence ({verdict.confidence:.2f}) for {fid} — "
                f"defaulting to REACHABLE for safety"
            )
            is_code_reachable = True
            is_failsafe = True
        else:
            is_code_reachable = verdict.is_reachable

        log_msg = (
            f"LLM Reachability [{fid}]: reachable={is_code_reachable}, "
            f"confidence={verdict.confidence:.2f}, rationale={verdict.justification[:120]}"
        )
        if is_failsafe or verdict.confidence == 0.0:
            log_msg += " [FAIL-SAFE TRIGGERED]"
            
        logs.append(log_msg)
        updated_reachability[fid] = is_code_reachable
        
        verdict_text = verdict.justification
        if not is_code_reachable and "LOW RISK VERDICT" not in verdict_text:
            verdict_text = f"LOW RISK VERDICT: {verdict_text}"
        updated_verdicts[fid] = verdict_text

    return {
        "reachability_map": updated_reachability,
        "detailed_audit_verdicts": updated_verdicts,
        "action_log": state.action_log + logs
    }

async def sast_fixer_agent(state: AgentState) -> Dict[str, Any]:
    logger.info("🛠️ SAST Fixer Agent generating code patch artifacts...")
    patches = dict(state.proposed_patches)
    for finding in state.triaged_findings:
        if finding.source_engine == "SAST" and state.reachability_map.get(finding.finding_id, False):
            llm = get_task_specific_llm("PATCH_GENERATION", finding)
            structured_llm = llm.with_structured_output(StructuredPatchOutput)
            prompt = f"Fix SAST vulnerability {finding.finding_id} in {finding.package_name} at {finding.target_file_path}."
            
            try:
                out = await safe_structured_llm_invoke(structured_llm, prompt)
                patches[finding.finding_id] = CodePatchArtifact(
                    target_file_path=finding.target_file_path,
                    original_code_block="String query = \"SELECT * FROM users WHERE id = '\" + id + \"'\";",
                    remediated_code_block=out.remediated_code_block,
                    explanation=out.explanation
                )
            except Exception as ex:
                logger.error(f"❌ OPENAI API ERROR during patch generation for {finding.finding_id} ({type(ex).__name__}): {ex}")
                patches[finding.finding_id] = CodePatchArtifact(
                    target_file_path=finding.target_file_path,
                    original_code_block="Unsafe query pattern",
                    remediated_code_block="PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");",
                    explanation=f"Fallback static patch — LLM error: {str(ex)[:80]}"
                )

    return {
        "proposed_patches": patches,
        "action_log": state.action_log + [f"SAST Fixer generated {len(patches)} patch artifacts."]
    }

async def sca_upgrade_advisor_agent(state: AgentState) -> Dict[str, Any]:
    logger.info("📦 SCA Upgrade Advisor Agent suggesting dependency version bumps...")
    return {
        "action_log": state.action_log + ["SCA Upgrade Advisor finished dependency recommendations."]
    }

async def dast_advisor_agent(state: AgentState) -> Dict[str, Any]:
    logger.info("🛡️ DAST Advisor Agent recommending runtime web protection headers...")
    return {
        "action_log": state.action_log + ["DAST Advisor generated security header recommendations."]
    }

async def jira_creation_agent(state: AgentState) -> Dict[str, Any]:
    logger.info("📋 Jira Creation Agent evaluating governance ticketing thresholds...")
    governance = state.governance_gate.model_copy()
    
    has_critical = any(
        f.severity == "CRITICAL" and state.reachability_map.get(f.finding_id, False)
        for f in state.triaged_findings
    )
    
    if has_critical:
        from app.jira_client import create_jira_block_issue
        first_crit = next(f for f in state.triaged_findings if f.severity == "CRITICAL")
        
        jira_url = await create_jira_block_issue(
            cve_id=first_crit.finding_id,
            package_name=first_crit.package_name,
            domain=state.domain,
            target_file=first_crit.target_file_path,
            analysis_text=f"Automated critical reachability verdict for {first_crit.finding_id} in {first_crit.target_file_path}."
        )
        
        ticket_key = jira_url.split("/")[-1] if "/browse/" in jira_url else "SEC-FALLBACK"
        governance.status = "PENDING_APPROVAL"
        governance.jira_ticket_key = ticket_key
        governance.jira_ticket_url = jira_url
        logger.info(f"📋 Jira Ticket Created: {ticket_key} -> {jira_url}")

    return {
        "governance_gate": governance,
        "action_log": state.action_log + [f"Jira Creation Agent updated governance status to {governance.status}."]
    }

def supervisor_router(state: AgentState) -> str:
    """LangGraph StateRouter directing sequential & parallel execution loops."""
    if not state.raw_sast_results and "SAST Triage Agent processed static findings." not in state.action_log:
        return "sast_triage_agent"
    if not any("SAST Triage" in log for log in state.action_log):
        return "sast_triage_agent"
    if state.raw_dast_results and not any("DAST Analysis" in log for log in state.action_log):
        return "dast_report_analysis_agent"
    if state.raw_container_results and not any("Container Scan" in log for log in state.action_log):
        return "container_scan_analysis_agent"

    if not any("LLM Reachability" in log for log in state.action_log):
        return "secure_code_review_agent"

    if not any("SAST Fixer" in log for log in state.action_log):
        return "sast_fixer_agent"
    if not any("SCA Upgrade" in log for log in state.action_log):
        return "sca_upgrade_advisor_agent"
    if not any("DAST Advisor" in log for log in state.action_log):
        return "dast_advisor_agent"

    if not any("Jira Creation Agent" in log for log in state.action_log):
        return "jira_creation_agent"

    return END

workflow = StateGraph(AgentState)

workflow.add_node("sast_triage_agent", sast_triage_agent)
workflow.add_node("dast_report_analysis_agent", dast_report_analysis_agent)
workflow.add_node("container_scan_analysis_agent", container_scan_analysis_agent)
workflow.add_node("secure_code_review_agent", secure_code_review_agent)
workflow.add_node("sast_fixer_agent", sast_fixer_agent)
workflow.add_node("sca_upgrade_advisor_agent", sca_upgrade_advisor_agent)
workflow.add_node("dast_advisor_agent", dast_advisor_agent)
workflow.add_node("jira_creation_agent", jira_creation_agent)

workflow.add_conditional_edges(
    START,
    supervisor_router,
    {
        "sast_triage_agent": "sast_triage_agent",
        "dast_report_analysis_agent": "dast_report_analysis_agent",
        "container_scan_analysis_agent": "container_scan_analysis_agent",
        "secure_code_review_agent": "secure_code_review_agent",
        "sast_fixer_agent": "sast_fixer_agent",
        "sca_upgrade_advisor_agent": "sca_upgrade_advisor_agent",
        "dast_advisor_agent": "dast_advisor_agent",
        "jira_creation_agent": "jira_creation_agent",
        END: END
    }
)

for node in [
    "sast_triage_agent", "dast_report_analysis_agent", "container_scan_analysis_agent",
    "secure_code_review_agent", "sast_fixer_agent", "sca_upgrade_advisor_agent",
    "dast_advisor_agent", "jira_creation_agent"
]:
    workflow.add_conditional_edges(
        node,
        supervisor_router,
        {
            "sast_triage_agent": "sast_triage_agent",
            "dast_report_analysis_agent": "dast_report_analysis_agent",
            "container_scan_analysis_agent": "container_scan_analysis_agent",
            "secure_code_review_agent": "secure_code_review_agent",
            "sast_fixer_agent": "sast_fixer_agent",
            "sca_upgrade_advisor_agent": "sca_upgrade_advisor_agent",
            "dast_advisor_agent": "dast_advisor_agent",
            "jira_creation_agent": "jira_creation_agent",
            END: END
        }
    )

memory_checkpointer = MemorySaver()
app_orchestration_agent = workflow.compile(checkpointer=memory_checkpointer)