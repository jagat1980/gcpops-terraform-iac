# tests/test_task_models.py
"""Tests for dynamic task-specific LLM routing (Paid Model Strategy)."""
import os
import pytest
from dotenv import load_dotenv

# Load .env variables so ChatOpenAI instantiation has OPENAI_API_KEY
load_dotenv()

from app.schemas import CodeAnalysisFinding
from app.graph import get_task_specific_llm

def test_get_task_specific_llm_patch_generation():
    """Verify patch generation routes to high-tier agentic model."""
    llm = get_task_specific_llm("PATCH_GENERATION")
    assert llm.model_name in ["gpt-5.6-sol", "gpt-4o"]

def test_get_task_specific_llm_java_oracle():
    """Verify Java/Oracle reachability analysis routes to high-reasoning model."""
    finding = CodeAnalysisFinding(
        finding_id="JAVA-S2077",
        source_engine="SAST",
        severity="CRITICAL",
        package_name="com.bank.dao.AccountRepository",
        target_file_path="src/main/java/com/bank/dao/AccountRepository.java"
    )
    llm = get_task_specific_llm("REACHABILITY_ANALYSIS", finding)
    assert llm.model_name in ["gpt-5.6-sol", "gpt-4o"]

def test_get_task_specific_llm_react_frontend():
    """Verify React/Frontend reachability analysis routes to workhorse model."""
    finding = CodeAnalysisFinding(
        finding_id="XSS-REACT-01",
        source_engine="DAST",
        severity="HIGH",
        package_name="frontend-client",
        target_file_path="src/components/UserProfile.jsx"
    )
    llm = get_task_specific_llm("REACHABILITY_ANALYSIS", finding)
    assert llm.model_name in ["gpt-5.6-terra", "gpt-4o-mini"]

def test_get_task_specific_llm_container_sca():
    """Verify Container/SCA dependency triage routes to fast budget model."""
    finding = CodeAnalysisFinding(
        finding_id="CVE-2026-3001",
        source_engine="CONTAINER",
        severity="HIGH",
        package_name="nginx-ingress",
        target_file_path="Dockerfile"
    )
    llm = get_task_specific_llm("REACHABILITY_ANALYSIS", finding)
    assert llm.model_name in ["gpt-5.6-luna", "gpt-4o-mini"]
