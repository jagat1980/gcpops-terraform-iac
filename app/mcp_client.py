# app/mcp_client.py
"""Stdio MCP Client and Ecosystem Manager."""
import os
import json
import sys
import asyncio
import logging
import subprocess
from typing import Dict, Any, Optional

logger = logging.getLogger("mcp-client-core")

class StdioMCPClient:
    """A thread-safe, standard subprocess-based Model Context Protocol client
    engineered to bypass Windows Selector Event Loop routing blockades.
    """
    def __init__(self, command: str, args: list, env_context: Optional[Dict[str, str]] = None):
        self.command = command
        self.args = args
        self.env = {**os.environ, **(env_context or {})}
        self.process: Optional[subprocess.Popen] = None
        self._request_id = 1
    
    async def connect(self):
        """Spawns the target daemon process safely via a background worker thread."""
        logger.info(f"Spawning MCP Server process: {self.command} {' '.join(self.args)}")
        full_command = f"{self.command} {' '.join(self.args)}"
        
        def _spawn():
            return subprocess.Popen(
                full_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True,
                encoding="utf-8",
                env=self.env
            )
            
        self.process = await asyncio.to_thread(_spawn)
        await self._initialize_handshake()

    async def _initialize_handshake(self):
        """Executes the protocol handshake loop utilizing threaded stream I/O."""
        init_payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": self._request_id,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "oneshield-security-orchestrator", "version": "1.0.0"}
            }
        }
        
        try:
            await self._send_notification(init_payload)
            
            raw_response = await asyncio.to_thread(self.process.stdout.readline)
            if not raw_response:
                raw_stderr = await asyncio.to_thread(self.process.stderr.read)
                raise RuntimeError(f"MCP server exited during handshake. Trace: {raw_stderr.strip()}")
            
            self._request_id += 1
            notify_payload = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }
            await self._send_notification(notify_payload)
            logger.info("MCP Server handshake finalized successfully.")
            
        except Exception as e:
            await asyncio.to_thread(self.disconnect)
            raise e

    async def _send_notification(self, payload: Dict[str, Any]):
        def _write():
            self.process.stdin.write(json.dumps(payload) + "\n")
            self.process.stdin.flush()
        await asyncio.to_thread(_write)

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Invokes a functional endpoint exposed by the target MCP server."""
        if not self.process or self.process.poll() is not None:
            raise RuntimeError("Cannot execute tool call: MCP process is offline.")
        
        self._request_id += 1
        request_payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": self._request_id,
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }
        
        await self._send_notification(request_payload)
        
        raw_response = await asyncio.to_thread(self.process.stdout.readline)
        if not raw_response:
            return {"error": "Received empty tracking response block from server."}
            
        return json.loads(raw_response)

    def disconnect(self):
        """Gracefully kills the underlying process handle."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
                logger.info("MCP process pipeline cleaned up successfully.")
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass


class MCPClientManager:
    """Manager reading .mcp.json and handling dynamic tool invocation across registered MCP servers."""

    def __init__(self, config_path: Optional[str] = None):
        if not config_path:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".mcp.json")
        self.config_path = config_path
        self.servers_config: Dict[str, Any] = {}
        self._active_clients: Dict[str, StdioMCPClient] = {}
        self._load_config()

    def _load_config(self):
        """Reads .mcp.json definitions."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.servers_config = data.get("mcpServers", {})
            except Exception as e:
                logger.error(f"Failed to load .mcp.json: {e}")

    async def invoke_mcp_tool(self, server_name: str, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Invokes a tool on a named MCP server from .mcp.json."""
        if server_name not in self.servers_config:
            return {"error": f"Server '{server_name}' not configured in .mcp.json"}

        srv = self.servers_config[server_name]
        cmd = srv.get("command", "")
        args = srv.get("args", [])
        env = srv.get("env", {})

        # Resolve env var placeholders (e.g. ${env:PYTHONPATH})
        resolved_env = {}
        for k, v in env.items():
            if isinstance(v, str) and v.startswith("${env:") and v.endswith("}"):
                env_key = v[6:-1]
                resolved_env[k] = os.environ.get(env_key, "")
            else:
                resolved_env[k] = v

        client = StdioMCPClient(command=cmd, args=args, env_context=resolved_env)
        try:
            await client.connect()
            result = await client.call_tool(tool_name, arguments)
            return result
        finally:
            client.disconnect()