# tests/test_agent.py
"""API Gateway and full multi-agent orchestration end-to-end integration tests."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock

from app.main import app, workflow_execution_store
from app.schemas import AgentState, CodeAnalysisFinding

client = TestClient(app)

# ==============================================================================
# 🌐 API GATEWAY ROUTING TESTS
# ==============================================================================

def test_service_health_check_endpoint():
    """Validates that the service health check endpoint returns 200 OK."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "oneshield-vulnerability-engine"

def test_api_endpoint_handles_async_webhook_receipt():
    """Validates that the scan handler accepts payloads and returns 202 Accepted."""
    payload = {
        "image_sha": "sha256:7f77b8b9c0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
        "domain": "CorporateBank",
        "scan_data": [
            {
                "tool": "sast-sonar",
                "issue": {
                    "ruleId": "JAVA-S2077",
                    "packageName": "com.bank.dao.AccountRepository",
                    "severity": "CRITICAL"
                }
            }
        ]
    }
    response = client.post("/v1/scan-handler", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "Accepted"
    assert "image_sha" in data
    assert "status_url" in data

def test_status_endpoint_returns_404_for_unknown_sha():
    """Validates status endpoint 404 for unknown runs."""
    response = client.get("/v1/scan-status/unknown-sha-999")
    assert response.status_code == 404

def test_status_endpoint_returns_execution_record():
    """Validates status endpoint returns execution state."""
    sha = "sha256:status_test_123"
    workflow_execution_store[sha] = {
        "status": "COMPLETED",
        "image_sha": sha,
        "resolution_strategy": "AUTO_PATCH"
    }
    response = client.get(f"/v1/scan-status/{sha}")
    assert response.status_code == 200
    assert response.json()["status"] == "COMPLETED"
    assert response.json()["resolution_strategy"] == "AUTO_PATCH"

# ==============================================================================
# 🧠 CORE LANGGRAPH END-TO-END ORCHESTRATION TESTS
# ==============================================================================

@patch("app.graph.fetch_threat_intel", new_callable=AsyncMock, return_value={"cisa_kev": False, "epss_score": 0.01})
@patch("app.graph.ChatOpenAI")
def test_full_graph_orchestration_execution(mock_chat_openai, mock_threat_intel):
    """Executes the full LangGraph multi-agent pipeline with mock LLM."""
    import asyncio
    from app.graph import app_orchestration_agent

    mock_verdict = MagicMock()
    mock_verdict.is_reachable = False
    mock_verdict.justification = "Code path is not reachable in production"
    mock_verdict.confidence = 0.90

    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value.ainvoke = AsyncMock(return_value=mock_verdict)
    mock_chat_openai.return_value = mock_llm

    initial_state = AgentState(
        image_sha="sha256:full_graph_test_001",
        domain="CorporateBank",
        raw_sast_results=[
            {
                "issue": {
                    "ruleId": "JAVA-S2077",
                    "packageName": "com.bank.service.PaymentService",
                    "severity": "HIGH"
                }
            }
        ],
        raw_dast_results=[],
        raw_container_results=[],
        triaged_findings=[],
        reachability_map={},
        detailed_audit_verdicts={},
        resolution_strategy="ALLOW_SIGN",
        proposed_patches={},
        action_log=[],
        next_worker="supervisor"
    )

    config = {"configurable": {"thread_id": "sha256:full_graph_test_001"}}
    final_state = asyncio.run(app_orchestration_agent.ainvoke(initial_state.model_dump(), config=config))

    assert "triaged_findings" in final_state
    assert len(final_state["triaged_findings"]) == 1
    assert final_state["reachability_map"]["JAVA-S2077"] is False
    assert final_state["resolution_strategy"] == "ALLOW_SIGN"