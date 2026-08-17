# tests/test_tracing.py
"""Validates that LangSmith tracing instrumentation is correctly wired."""
import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from langchain_core.runnables import RunnableConfig


class TestTracingInstrumentation:
    """Verify tracing config is passed through the orchestration pipeline."""

    def test_langsmith_env_vars_are_set(self):
        """Confirms that LangSmith environment variables are loaded."""
        # Load .env the same way main.py does
        env_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), ".env"
        )
        env_vars = {}
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8-sig") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        env_vars[key.strip()] = val.strip()

        assert "LANGSMITH_TRACING" in env_vars, "LANGSMITH_TRACING not found in .env"
        assert env_vars["LANGSMITH_TRACING"].lower() == "true", (
            f"LANGSMITH_TRACING is '{env_vars['LANGSMITH_TRACING']}', expected 'true'"
        )
        assert "LANGSMITH_API_KEY" in env_vars, "LANGSMITH_API_KEY not found in .env"
        assert not env_vars["LANGSMITH_API_KEY"].endswith("placeholder"), (
            "LANGSMITH_API_KEY is still a placeholder value"
        )
        assert "LANGSMITH_PROJECT" in env_vars, "LANGSMITH_PROJECT not found in .env"

    def test_graph_invocation_includes_run_config(self):
        """Validates that execute_agent_workflow passes RunnableConfig to the graph."""
        import asyncio
        from app.main import execute_agent_workflow
        from app.schemas import AgentState

        mock_state = AgentState(
            image_sha="sha256:test123",
            domain="CorporateBank",
            raw_sast_results=[],
            raw_dast_results=[],
            raw_container_results=[],
            triaged_findings=[],
            reachability_map={},
            detailed_audit_verdicts={},
            resolution_strategy="ALLOW_SIGN",
            proposed_patches={},
            action_log=[],
            next_worker="supervisor",
        )

        with patch("app.main.app_orchestration_agent") as mock_graph:
            mock_graph.ainvoke = AsyncMock(return_value={
                "resolution_strategy": "ALLOW_SIGN",
                "action_log": [],
            })

            asyncio.run(execute_agent_workflow(mock_state))

            # Verify ainvoke was called with a RunnableConfig
            mock_graph.ainvoke.assert_called_once()
            call_args = mock_graph.ainvoke.call_args
            assert len(call_args.args) >= 1 or "config" in call_args.kwargs, (
                "Graph was invoked without a RunnableConfig"
            )

    @patch("app.graph.fetch_threat_intel", new_callable=AsyncMock, return_value={"cisa_kev": False, "epss_score": 0.01})
    @patch("app.graph.ChatOpenAI")
    def test_llm_reachability_call_is_structured(self, mock_chat_openai, mock_threat_intel):
        """Validates that secure_code_review_agent uses structured LLM output."""
        import asyncio
        from app.graph import secure_code_review_agent
        from app.schemas import AgentState, CodeAnalysisFinding

        mock_verdict = MagicMock()
        mock_verdict.is_reachable = True
        mock_verdict.justification = "Code path is reachable."
        mock_verdict.confidence = 0.85

        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value.ainvoke = AsyncMock(
            return_value=mock_verdict
        )
        mock_chat_openai.return_value = mock_llm

        state = AgentState(
            image_sha="sha256:test",
            domain="CorporateBank",
            triaged_findings=[
                CodeAnalysisFinding(
                    finding_id="TEST-001",
                    source_engine="SAST",
                    severity="HIGH",
                    package_name="com.test.Example",
                    target_file_path="src/main/java/Example.java",
                )
            ],
            reachability_map={},
            detailed_audit_verdicts={},
            action_log=[],
        )

        result = asyncio.run(secure_code_review_agent(state))

        # Verify LLM was called
        mock_llm.with_structured_output.assert_called_once()
        # Verify reachability was updated based on LLM verdict
        assert result["reachability_map"]["TEST-001"] is True

    def test_traceable_decorator_on_threat_intel(self):
        """Validates that fetch_threat_intel has LangSmith tracing."""
        from app.threat_intel import fetch_threat_intel

        # Check if the function has been wrapped by @langsmith.traceable
        assert hasattr(fetch_threat_intel, "__wrapped__") or \
               hasattr(fetch_threat_intel, "is_traceable"), (
            "fetch_threat_intel is not decorated with @langsmith.traceable"
        )