# tests/test_e2e_payloads.py
"""End-to-end integration tests with stack-specific payloads (Java/Oracle, React, Container)."""
import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.schemas import AgentState, CodeAnalysisFinding
from app.graph import secure_code_review_agent, get_task_specific_llm, ReachabilityVerdict

class TestStackPayloads:
    """Test full multi-task payloads for React/Angular, Java/Oracle, and Container SCA."""

    @patch("app.graph.fetch_threat_intel", new_callable=AsyncMock, return_value={"cisa_kev": False, "epss_score": 0.45})
    @patch("app.graph.ChatOpenAI")
    def test_java_oracle_sast_payload(self, mock_chat_openai, mock_threat_intel):
        """Simulate a Java/Oracle SQL injection SAST payload."""
        mock_verdict = ReachabilityVerdict(
            is_reachable=True,
            justification="SQL injection path reaches Oracle DB via AccountRepository.java",
            confidence=0.95
        )
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value.ainvoke = AsyncMock(return_value=mock_verdict)
        mock_chat_openai.return_value = mock_llm

        state = AgentState(
            image_sha="sha256:java_oracle_backend_001",
            domain="InvestmentBank",
            triaged_findings=[
                CodeAnalysisFinding(
                    finding_id="JAVA-S2077",
                    source_engine="SAST",
                    severity="CRITICAL",
                    package_name="com.bank.dao.AccountRepository",
                    target_file_path="src/main/java/com/bank/dao/AccountRepository.java"
                )
            ],
            reachability_map={},
            detailed_audit_verdicts={},
            action_log=[]
        )

        result = asyncio.run(secure_code_review_agent(state))

        # Assert reachability maps correctly for Java/Oracle
        assert result["reachability_map"]["JAVA-S2077"] is True
        assert "AccountRepository.java" in result["detailed_audit_verdicts"]["JAVA-S2077"]

    @patch("app.graph.fetch_threat_intel", new_callable=AsyncMock, return_value={"cisa_kev": False, "epss_score": 0.01})
    @patch("app.graph.ChatOpenAI")
    def test_react_frontend_xss_payload(self, mock_chat_openai, mock_threat_intel):
        """Simulate a React dangerouslySetInnerHTML DAST payload."""
        mock_verdict = ReachabilityVerdict(
            is_reachable=True,
            justification="dangerouslySetInnerHTML exposed in UserProfile.jsx component",
            confidence=0.88
        )
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value.ainvoke = AsyncMock(return_value=mock_verdict)
        mock_chat_openai.return_value = mock_llm

        state = AgentState(
            image_sha="sha256:react_frontend_002",
            domain="CorporateBank",
            triaged_findings=[
                CodeAnalysisFinding(
                    finding_id="XSS-REACT-DOM",
                    source_engine="DAST",
                    severity="HIGH",
                    package_name="frontend-profile",
                    target_file_path="src/components/UserProfile.jsx"
                )
            ],
            reachability_map={},
            detailed_audit_verdicts={},
            action_log=[]
        )

        result = asyncio.run(secure_code_review_agent(state))

        assert result["reachability_map"]["XSS-REACT-DOM"] is True
        assert len(result["action_log"]) > 0

    @patch("app.graph.fetch_threat_intel", new_callable=AsyncMock, return_value={"cisa_kev": False, "epss_score": 0.01})
    @patch("app.graph.ChatOpenAI")
    def test_container_sca_payload(self, mock_chat_openai, mock_threat_intel):
        """Simulate a Container CVE payload."""
        mock_verdict = ReachabilityVerdict(
            is_reachable=False,
            justification="Container vulnerability is unreachable in build sandbox",
            confidence=0.90
        )
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value.ainvoke = AsyncMock(return_value=mock_verdict)
        mock_chat_openai.return_value = mock_llm

        state = AgentState(
            image_sha="sha256:docker_container_003",
            domain="CorporateBank",
            triaged_findings=[
                CodeAnalysisFinding(
                    finding_id="CVE-BASIC-001",
                    source_engine="CONTAINER",
                    severity="MEDIUM",
                    package_name="test-binary",
                    target_file_path="Dockerfile"
                )
            ],
            reachability_map={},
            detailed_audit_verdicts={},
            action_log=[]
        )

        result = asyncio.run(secure_code_review_agent(state))

        assert result["reachability_map"]["CVE-BASIC-001"] is False
        assert "LOW RISK VERDICT" in result["detailed_audit_verdicts"]["CVE-BASIC-001"]

    @patch("app.graph.fetch_threat_intel", new_callable=AsyncMock, return_value={"cisa_kev": False, "epss_score": 0.01})
    @patch("app.graph.ChatOpenAI")
    def test_low_confidence_triggers_failsafe(self, mock_chat_openai, mock_threat_intel):
        """Verify that low-confidence LLM outputs trigger the fail-safe guardrail."""
        mock_verdict = ReachabilityVerdict(
            is_reachable=False,
            justification="Uncertain analysis — limited code context",
            confidence=0.30  # Below 0.70 threshold
        )
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value.ainvoke = AsyncMock(return_value=mock_verdict)
        mock_chat_openai.return_value = mock_llm

        state = AgentState(
            image_sha="sha256:confidence_test_004",
            domain="CorporateBank",
            triaged_findings=[
                CodeAnalysisFinding(
                    finding_id="LOW-CONF-001",
                    source_engine="SAST",
                    severity="HIGH",
                    package_name="com.bank.service.PaymentService",
                    target_file_path="src/main/java/com/bank/service/PaymentService.java"
                )
            ],
            reachability_map={},
            detailed_audit_verdicts={},
            action_log=[]
        )

        result = asyncio.run(secure_code_review_agent(state))

        # FAIL-SAFE: Low confidence should override is_reachable=False to True
        assert result["reachability_map"]["LOW-CONF-001"] is True
        # Verify the confidence gate logged correctly
        assert any("FAIL-SAFE" in log for log in result["action_log"])

    @patch("app.graph.fetch_threat_intel", new_callable=AsyncMock, return_value={"cisa_kev": False, "epss_score": 0.01})
    @patch("app.graph.ChatOpenAI")
    def test_llm_error_triggers_failsafe(self, mock_chat_openai, mock_threat_intel):
        """Verify that LLM API errors trigger graceful fallback (not crash)."""
        # Simulate LLM throwing an exception
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value.ainvoke = AsyncMock(
            side_effect=Exception("OpenAI rate limit exceeded")
        )
        mock_chat_openai.return_value = mock_llm

        state = AgentState(
            image_sha="sha256:error_test_005",
            domain="CorporateBank",
            triaged_findings=[
                CodeAnalysisFinding(
                    finding_id="ERR-TEST-001",
                    source_engine="SAST",
                    severity="HIGH",
                    package_name="com.bank.service.TransferService",
                    target_file_path="src/main/java/com/bank/service/TransferService.java"
                )
            ],
            reachability_map={},
            detailed_audit_verdicts={},
            action_log=[]
        )

        # Should NOT crash — should return safely with fail-safe verdicts
        result = asyncio.run(secure_code_review_agent(state))

        # FAIL-SAFE: Error should default to reachable=True
        assert result["reachability_map"]["ERR-TEST-001"] is True
        assert "ERR-TEST-001" in result["detailed_audit_verdicts"]
