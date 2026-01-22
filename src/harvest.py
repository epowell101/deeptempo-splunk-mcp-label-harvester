import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from src.mcp_client import MCPClient

DEFAULT_DISCOVERY_SPL = r"""
(index=notable earliest=-30d | head 5) OR (sourcetype=notable earliest=-30d | head 5)
""".strip()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def build_export_spl(base_search: str, label: str, rules: List[Dict[str, Any]], n: int) -> str:
    where_clauses = []
    for r in rules:
        field = r["field"]
        vals = r["values"]
        quoted = ",".join([f"\"{v}\"" for v in vals])
        where_clauses.append(f'{field} IN ({quoted})')

    where_expr = " OR ".join([f"({w})" for w in where_clauses]) if where_clauses else "true()"

    return f"""
{base_search}
| eval label="{label}"
| where {where_expr}
| sort 0 - _time
| dedup rule_name, src, dest, label
| head {n}
| table _time label rule_name severity src dest user host signature
""".strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mcp-url", required=True, help="HTTP URL for MCP JSON-RPC endpoint")
    ap.add_argument("--token", required=False, help="Bearer token if required")
    ap.add_argument("--tool", default="run_splunk_query", help="MCP tool name for running SPL")
    ap.add_argument("--discovery-spl", default=None, help="Optional path to discovery SPL file")
    ap.add_argument("--mapping", default="schemas/label_mapping.json", help="Path to label mapping JSON")
    ap.add_argument("--base-search", default="index=notable earliest=-90d", help="Base SPL search for incidents")
    ap.add_argument("--n", type=int, default=100, help="Number of incidents per label")
    ap.add_argument("--out", default="examples/sample_output.json", help="Output JSON path")
    args = ap.parse_args()

    headers: Dict[str, str] = {}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    client = MCPClient(base_url=args.mcp_url, headers=headers)

    tools = client.list_tools()
    tool_names = [t.get("name") for t in tools.get("tools", [])]
    print("MCP tools available:", tool_names)

    discovery_spl = DEFAULT_DISCOVERY_SPL
    if args.discovery_spl:
        discovery_spl = Path(args.discovery_spl).read_text(encoding="utf-8")

    print("\nRunning discovery probe...\n")
    discovery_res = client.call_tool(args.tool, {"query": discovery_spl})
    if isinstance(discovery_res, dict):
        print("Discovery result keys:", list(discovery_res.keys()))

    mapping = load_json(Path(args.mapping))
    results = []

    for label in ["C2", "EXFIL", "LATERAL"]:
        rules = mapping.get(label, [])
        print(f"\nExporting {args.n} incidents for label={label} ...")
        spl = build_export_spl(args.base_search, label, rules, args.n)
        res = client.call_tool(args.tool, {"query": spl})
        results.append({"label": label, "spl": spl, "result": res})

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nWrote output to: {out_path}")


if __name__ == "__main__":
    main()
