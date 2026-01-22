import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx


@dataclass
class MCPClient:
    """
    Minimal JSON-RPC client for an MCP server exposed over HTTP.

    This is intentionally tiny for demo use:
      - list_tools(): calls method "tools/list"
      - call_tool(): calls method "tools/call" with {"name": ..., "arguments": {...}}

    If your Splunk MCP deployment uses a slightly different endpoint/method naming,
    we'll adapt after first real connection.
    """
    base_url: str
    headers: Dict[str, str]

    def _rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }
        with httpx.Client(timeout=60.0, headers=self.headers) as client:
            r = client.post(self.base_url, json=payload)
            r.raise_for_status()
            data = r.json()

        if isinstance(data, dict) and "error" in data:
            raise RuntimeError(f"RPC error: {data['error']}")
        return data.get("result") if isinstance(data, dict) else data

    def list_tools(self) -> Any:
        return self._rpc("tools/list")

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})
