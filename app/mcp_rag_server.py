# app/mcp_rag_server.py
"""Stdio MCP Server module exposing OneShield RAG Store security doc search as a standardized MCP tool."""
import sys
import json
import logging
from typing import Dict, Any
from app.rag_store import OneShieldRAGStore

logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("mcp-rag-server")

rag_store = OneShieldRAGStore()

def handle_jsonrpc_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """Processes incoming JSON-RPC 2.0 requests for MCP initialization, tool listing, and tool calls."""
    msg_type = request.get("method")
    req_id = request.get("id")

    if msg_type == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "oneshield-security-rag-docs",
                    "version": "1.0.0"
                }
            }
        }

    elif msg_type == "notifications/initialized":
        return None  # Standard JSON-RPC notification (no response body required)
    
    elif msg_type == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "search_security_docs",
                        "description": "Searches grounded security documentation and guidelines for Spring, Oracle, React, Angular, and OWASP.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target_file_path": {
                                    "type": "string",
                                    "description": "Target source file path or component name (e.g. AccountRepository.java, UserProfile.jsx)"
                                },
                                "finding_id": {
                                    "type": "string",
                                    "description": "Vulnerability rule or CVE ID (e.g. JAVA-S2077, XSS-REACT-DOM)"
                                }
                            },
                            "required": ["target_file_path", "finding_id"]
                        }
                    }
                ]
            }
        }

    elif msg_type == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        if tool_name == "search_security_docs":
            target_path = args.get("target_file_path", "")
            fid = args.get("finding_id", "")
            context = rag_store.retrieve_relevant_context(target_path, fid)

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": context if context else "No matching security doc context found."
                        }
                    ]
                }
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Tool '{tool_name}' not found."
                }
            }

    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{msg_type}' not supported."
            }
        }

def main():
    """Main stdio loop reading JSON-RPC lines from stdin and emitting to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = handle_jsonrpc_request(req)
            if resp:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
