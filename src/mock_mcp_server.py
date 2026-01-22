from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict


def jsonrpc_result(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def jsonrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def fake_splunk_rows_for_query(query: str) -> Dict[str, Any]:
    """
    Mock behavior:
      - If query looks like a discovery probe (index=notable ... head 5), return a small sample.
      - Otherwise return up to 3 fake incidents.
    """
    q = (query or "").lower()

    if "fieldsummary" in q:
        return {
            "type": "splunk_query_result",
            "query_kind": "fieldsummary",
            "rows": [
                {"field": "mitre_tactic", "distinct_values": 3, "top_values": ["command-and-control", "exfiltration", "lateral-movement"]},
                {"field": "rule_name", "distinct_values": 12, "top_values": ["C2 Beaconing", "Suspicious RDP", "Large Data Transfer"]},
                {"field": "severity", "distinct_values": 3, "top_values": ["low", "medium", "high"]},
            ],
            "meta": {"note": "Mock fieldsummary response"},
        }

    if "index=notable" in q and "head 5" in q:
        return {
            "type": "splunk_query_result",
            "query_kind": "discovery_probe",
            "rows": [
                {"_time": "2026-01-20T18:42:10Z", "rule_name": "C2 Beaconing", "mitre_tactic": "command-and-control", "severity": "high"},
                {"_time": "2026-01-20T19:05:44Z", "rule_name": "Suspicious RDP", "mitre_tactic": "lateral-movement", "severity": "medium"},
            ],
            "meta": {"note": "Mock discovery results"},
        }

    # Export-style query: return some fake incidents
    return {
        "type": "splunk_query_result",
        "query_kind": "export",
        "rows": [
            {
                "_time": "2026-01-19T03:10:21Z",
                "label": "C2",
                "rule_name": "C2 Beaconing",
                "severity": "high",
                "src": "10.0.1.10",
                "dest": "198.51.100.22",
                "user": "alice",
                "host": "host-a",
                "signature": "beaconing-interval",
            },
            {
                "_time": "2026-01-18T22:41:09Z",
                "label": "EXFIL",
                "rule_name": "Large Data Transfer",
                "severity": "high",
                "src": "10.0.2.15",
                "dest": "203.0.113.9",
                "user": "bob",
                "host": "host-b",
                "signature": "bytes-out-threshold",
            },
            {
                "_time": "2026-01-18T19:02:55Z",
                "label": "LATERAL",
                "rule_name": "Suspicious RDP",
                "severity": "medium",
                "src": "10.0.3.7",
                "dest": "10.0.4.8",
                "user": "carol",
                "host": "host-c",
                "signature": "rdp-admin-share",
            },
        ],
        "meta": {"note": "Mock export rows (not actually filtered)"},
    }


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            req = json.loads(raw or "{}")
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON: {e}"})
            return

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        # Minimal MCP-ish JSON-RPC surface:
        # - tools/list
        # - tools/call {name, arguments}
        if method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "run_splunk_query",
                        "description": "Mock: execute SPL and return rows",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}},
                            "required": ["query"],
                        },
                    }
                ]
            }
            self._send_json(200, jsonrpc_result(req_id, result))
            return

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if name != "run_splunk_query":
                self._send_json(200, jsonrpc_error(req_id, -32602, f"Unknown tool: {name}"))
                return
            query = arguments.get("query", "")
            result = fake_splunk_rows_for_query(query)
            self._send_json(200, jsonrpc_result(req_id, result))
            return

        self._send_json(200, jsonrpc_error(req_id, -32601, f"Method not found: {method}"))

    def log_message(self, fmt: str, *args):
        # keep console clean
        return

    def _send_json(self, status: int, body: Dict[str, Any]):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    host = "127.0.0.1"
    port = 8765
    print(f"Mock MCP server listening on http://{host}:{port}")
    server = HTTPServer((host, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
