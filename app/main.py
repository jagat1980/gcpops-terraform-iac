# app/main.py
import os
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import unquote
from dotenv import load_dotenv
from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from app.otel_tracer import setup_gcp_opentelemetry
from pydantic import BaseModel
from langchain_core.runnables import RunnableConfig

from app.schemas import AgentState
from app.graph import app_orchestration_agent

# Initialize environment variables
load_dotenv()

# Initialize GCP OpenTelemetry Cloud Trace Instrumentation
setup_gcp_opentelemetry(app)

# Configure logging
logger = logging.getLogger("vulnerability-lifecycle-gateway")
logging.basicConfig(level=logging.INFO)

# In-memory store for tracking execution results (#13)
workflow_execution_store: Dict[str, Dict[str, Any]] = {}

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Validates the request API key against ShiftSHIELD_API_KEY if configured."""
    expected_key = os.environ.get("ONESHIELD_API_KEY", "")
    if not expected_key:
        return  # No key configured = auth disabled (dev mode)
    if api_key != expected_key:
        raise HTTPException(status_code=403, detail="Invalid API key")

app = FastAPI(
    title="ShiftShield Vulnerability Engine Gateway",
    version="1.0.0",
    description="Multi-agent orchestration gateway for enterprise vulnerability remediation."
)

class GenericWebhookPayload(BaseModel):
    image_sha: str
    domain: str
    repo_owner: Optional[str] = ""
    repo_name: Optional[str] = ""
    base_branch: Optional[str] = "main"
    scan_data: List[Dict[str, Any]]

@app.get("/health")
async def health_check():
    """Health readiness probe endpoint (#20)."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "service": "oneshield-vulnerability-engine",
        "auth_enabled": bool(os.environ.get("ONESHIELD_API_KEY"))
    }

@app.get("/v1/scan-status/{image_sha:path}", dependencies=[Depends(verify_api_key)])
async def get_scan_status(image_sha: str):
    """Execution status lookup endpoint (#13)."""
    raw_sha = unquote(image_sha)
    if raw_sha in workflow_execution_store:
        return workflow_execution_store[raw_sha]
    if image_sha in workflow_execution_store:
        return workflow_execution_store[image_sha]
    raise HTTPException(status_code=404, detail=f"No execution record found for image_sha: {image_sha}")

async def execute_agent_workflow(initial_state: AgentState):
    """Asynchronously triggers the LangGraph multi-agent orchestration pool."""
    sha = initial_state.image_sha
    workflow_execution_store[sha] = {
        "status": "RUNNING",
        "image_sha": sha,
        "domain": initial_state.domain,
        "resolution_strategy": None,
        "action_log": initial_state.action_log
    }

    try:
        logger.info(f"⚡ Background multi-agent lifecycle orchestration workflow spinning up for {sha}...")
        
        run_config = RunnableConfig(
             run_name=f"oneshield-{sha[:16]}",
             tags=[
                 f"domain:{initial_state.domain}",
                 "pipeline:vulnerability-lifecycle",
             ],
             metadata={
                 "image_sha": sha,
                 "domain": initial_state.domain,
                 "repo_owner": initial_state.repo_owner,
                 "repo_name": initial_state.repo_name,
             },
        )

        # Thread config for MemorySaver checkpointer persistence
        thread_config = {**run_config, "configurable": {"thread_id": sha}}

        final_state = await app_orchestration_agent.ainvoke(
             initial_state.model_dump(), config=thread_config
        )
        
        strategy = final_state.get("resolution_strategy", "ALLOW_SIGN")
        action_log = final_state.get("action_log", [])

        workflow_execution_store[sha] = {
            "status": "COMPLETED",
            "image_sha": sha,
            "domain": initial_state.domain,
            "resolution_strategy": strategy,
            "triaged_findings_count": len(final_state.get("triaged_findings", [])),
            "reachability_map": final_state.get("reachability_map", {}),
            "proposed_patches_count": len(final_state.get("proposed_patches", {})),
            "governance_gate": final_state.get("governance_gate", {}),
            "action_log": action_log
        }

        logger.info(f"🏁 BACKGROUND MULTI-AGENT REMEDIATION RUN COMPLETE for {sha}. Final strategy: {strategy}")
    except Exception as e:
        logger.error(f"Critical error down the multi-agent graph chain execution path for {sha}: {str(e)}")
        workflow_execution_store[sha] = {
            "status": "FAILED",
            "image_sha": sha,
            "error": str(e)
        }

@app.post("/v1/scan-handler", status_code=202, dependencies=[Depends(verify_api_key)])
async def scan_handler(payload: GenericWebhookPayload, background_tasks: BackgroundTasks):
    """Ingest endpoint sorting raw payloads into their matching agent slots."""
    logger.info(f"Ingested new webhook payload target signature for image: {payload.image_sha}")
    
    sast_list = []
    dast_list = []
    container_list = []
    
    for item in payload.scan_data:
        tool_name = item.get("tool", "").lower()
        if "sast" in tool_name:
            sast_list.append(item)
        elif "dast" in tool_name or "zap" in tool_name or "alert" in item:
            dast_list.append(item)
        elif "sca" in tool_name or "trivy" in tool_name or "vulnerability" in item:
            container_list.append(item)
        else:
            sast_list.append(item)

    initial_state = AgentState(
        image_sha=payload.image_sha,
        domain=payload.domain,
        repo_owner=payload.repo_owner,
        repo_name=payload.repo_name,
        base_branch=payload.base_branch,
        raw_sast_results=sast_list,
        raw_dast_results=dast_list,
        raw_container_results=container_list,
        triaged_findings=[],
        reachability_map={},
        detailed_audit_verdicts={},
        resolution_strategy="ALLOW_SIGN",
        proposed_patches={},
        action_log=["Gateway initialized orchestration ledger payload frameworks."],
        next_worker="supervisor"
    )
    
    background_tasks.add_task(execute_agent_workflow, initial_state)
    return {
        "status": "Accepted",
        "message": "Multi-agent orchestration workflow triggered successfully.",
        "image_sha": payload.image_sha,
        "status_url": f"/v1/scan-status/{payload.image_sha}"
    }