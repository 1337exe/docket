"""Minimal MCP server (stdio, newline-delimited JSON-RPC) so an agent can try its own findings before reporting."""
from __future__ import annotations

from . import __version__

import json
import sys

from .court import Court

TOOL = {"name": "court_try_finding",
        "description": "Put one security finding on trial before reporting it. Returns survived / needs-human / "
                       "killed / duplicate with the reason each check passed or failed. Do not report findings that are killed.",
        "inputSchema": {"type": "object", "required": ["finding"], "properties": {"finding": {
            "type": "object", "required": ["id", "title"], "properties": {
                "id": {"type": "string"}, "title": {"type": "string"}, "impact": {"type": "string"},
                "vuln_class": {"type": "string"}, "target": {"type": "string"}, "found_by": {"type": "string"},
                "assumptions": {"type": "array", "items": {"type": "object"}},
                "evidence": {"type": "array", "items": {"type": "object"}},
                "probes": {"type": "array", "items": {"type": "object"}},
                "root_cause": {"type": "object"}, "repro_steps": {"type": "array", "items": {"type": "string"}}}}}}}


TOOLS_EXTRA = [
    {"name": "court_scope", "description": "Read the scope contract BEFORE hunting: which impacts are accepted, which attacker states and "
     "targets count, what is ineligible. Plan from the accepted impact, not from the vulnerability class.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "court_stats", "description": "How many findings this session were survived / killed / needs-human / duplicate, "
     "and which check kills most. Use it to see which of your own habits waste a reviewer's time.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def handle(court: Court, msg: dict):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:  # notification
        return None
    ok = lambda r: {"jsonrpc": "2.0", "id": mid, "result": r}
    if method == "initialize":
        return ok({"protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2024-11-05"),
                   "capabilities": {"tools": {}}, "serverInfo": {"name": "docket", "version": __version__}})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": [TOOL] + TOOLS_EXTRA})
    if method == "tools/call":
        p = msg.get("params") or {}
        if p.get("name") == "court_scope":
            return ok({"content": [{"type": "text", "text": json.dumps(court.scope_summary(), indent=2)}]})
        if p.get("name") == "court_stats":
            return ok({"content": [{"type": "text", "text": json.dumps(court.stats(), indent=2)}]})
        if p.get("name") != TOOL["name"]:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        try:
            res = court.try_one((p.get("arguments") or {}).get("finding") or {})
            return ok({"content": [{"type": "text", "text": json.dumps(res, indent=2)}]})
        except ValueError as e:
            return ok({"isError": True, "content": [{"type": "text", "text": f"invalid finding: {e}"}]})
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}


def serve(court: Court, stdin=None, stdout=None):
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        resp = handle(court, msg)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
