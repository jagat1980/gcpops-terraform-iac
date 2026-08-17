# tests/test_local_rag_integration.py
"""Integration test suite for Google OSV, Knowledge Graph, and RAG Store modules."""
import pytest
import asyncio
from app.osv_client import is_version_affected_by_osv
from app.knowledge_graph import DependencyKnowledgeGraph
from app.rag_store import OneShieldRAGStore
from app.schemas import CodeAnalysisFinding

def test_osv_version_matching():
    """Validates OSV version range matching logic."""
    mock_osv_record = {
        "affected": [
            {
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.5.0"}
                        ]
                    }
                ]
            }
        ]
    }
    assert is_version_affected_by_osv(mock_osv_record, "1.2.0") is True
    assert is_version_affected_by_osv(mock_osv_record, "1.5.0") is False

def test_knowledge_graph_banking_stack():
    """Validates NetworkX dependency graph call-chain path tracing."""
    graph = DependencyKnowledgeGraph()
    graph.build_banking_stack_graph()
    
    path = graph.trace_call_chain_to_database("Component:UserProfile.jsx")
    assert len(path) == 4
    assert path[0] == "Component:UserProfile.jsx"
    assert path[-1] == "Database:Oracle_PLSQL_DAO"

def test_knowledge_graph_filters_disconnected_test_code():
    """Validates $0 LLM cost filtering of test/mock code."""
    graph = DependencyKnowledgeGraph()
    findings = [
        CodeAnalysisFinding(
            finding_id="TEST-DEAD-01",
            source_engine="SAST",
            severity="HIGH",
            package_name="com.bank.test.MockAccountService",
            target_file_path="src/test/java/MockAccountService.java"
        ),
        CodeAnalysisFinding(
            finding_id="REAL-PROD-01",
            source_engine="SAST",
            severity="CRITICAL",
            package_name="com.bank.dao.AccountRepository",
            target_file_path="src/main/java/AccountRepository.java"
        )
    ]
    retained, logs = graph.filter_non_affected_findings(findings)
    assert len(retained) == 1
    assert retained[0].finding_id == "REAL-PROD-01"
    assert any("AUTO-DROPPED" in log for log in logs)

def test_rag_store_context_retrieval():
    """Validates that RAG Store retrieves relevant security guidelines."""
    store = OneShieldRAGStore()
    
    # Retrieve Java/Spring context
    java_context = store.retrieve_relevant_context("AccountRepository.java", "JAVA-S2077")
    assert "Spring Security" in java_context or "SQL" in java_context
    
    # Retrieve React context
    react_context = store.retrieve_relevant_context("UserProfile.jsx", "XSS-REACT")
    assert "React" in react_context or "dangerouslySetInnerHTML" in react_context
