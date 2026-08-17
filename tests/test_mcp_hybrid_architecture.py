# tests/test_mcp_hybrid_architecture.py
"""Test suite for the Enterprise Hybrid MCP + RAG Architecture."""
import pytest
import asyncio
from app.mcp_rag_server import handle_jsonrpc_request
from app.mcp_client import MCPClientManager, StdioMCPClient
from app.schemas import AgentState, CodeAnalysisFinding

def test_mcp_rag_server_handshake_and_tool_listing():
    """Validates JSON-RPC initialize and tools/list capabilities of mcp_rag_server."""
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }
    init_res = handle_jsonrpc_request(init_req)
    assert init_res["result"]["serverInfo"]["name"] == "oneshield-security-rag-docs"
    
    list_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }
    list_res = handle_jsonrpc_request(list_req)
    tools = list_res["result"]["tools"]
    assert len(tools) == 1
    assert tools[0]["name"] == "search_security_docs"

def test_mcp_rag_server_tool_execution():
    """Validates execution of search_security_docs tool via JSON-RPC."""
    call_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "search_security_docs",
            "arguments": {
                "target_file_path": "AccountRepository.java",
                "finding_id": "JAVA-S2077"
            }
        }
    }
    call_res = handle_jsonrpc_request(call_req)
    assert "result" in call_res
    content = call_res["result"]["content"][0]["text"]
    assert "Spring Security" in content or "SQL" in content

def test_mcp_client_manager_tool_invocation():
    """Validates MCPClientManager spawning and invoking security-rag-docs MCP tool."""
    manager = MCPClientManager()
    assert "security-rag-docs" in manager.servers_config

    res = asyncio.run(manager.invoke_mcp_tool(
        "security-rag-docs",
        "search_security_docs",
        {
            "target_file_path": "UserProfile.jsx",
            "finding_id": "XSS-REACT-DOM"
        }
    ))

    assert res is not None
    assert "result" in res
    content = res["result"]["content"][0]["text"]
    assert "React" in content or "dangerouslySetInnerHTML" in content
