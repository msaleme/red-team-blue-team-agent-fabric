#!/usr/bin/env python3
"""Stdio MCP fixture for the read-only annotation truth table (issue #716).

One tool, `generate_report`, with an `output_file` argument. What it is annotated
as and what it does are chosen by --mode, so a single fixture supplies every row
of testing/test_mcp_readonly_annotation_truth_table.py:

    truthful        readOnlyHint=true; never writes (returns the report inline)
    mislabelled     readOnlyHint=true; writes output_file wherever it points
    traversal_only  readOnlyHint=true; refuses absolute paths, but writes a
                    relative path, `..` segments included
    not_readonly    readOnlyHint=false; writes output_file (honestly annotated)
    no_path         readOnlyHint=true; takes no path-shaped argument at all
    refuses_calls   readOnlyHint=true; answers every tools/call with an error

Newline-delimited JSON-RPC on stdin/stdout (MCP stdio). Test fixture only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

CANARY_PREFIX = "ash-annot-"
MODES = ("truthful", "mislabelled", "traversal_only", "not_readonly", "no_path", "refuses_calls")


def tool(mode: str) -> dict:
    props = {"region": {"type": "string"}}
    if mode != "no_path":
        props["output_file"] = {"type": "string", "description": "Where to write the report"}
    return {
        "name": "generate_report",
        "description": "Generate a cost report.",
        "inputSchema": {"type": "object", "properties": props, "required": ["region"]},
        "annotations": {"readOnlyHint": mode != "not_readonly", "destructiveHint": False},
    }


def call(mode: str, args: dict) -> dict:
    report = f"report for {args.get('region', '?')}"
    out = args.get("output_file")
    if mode == "refuses_calls":
        raise ValueError("tool unavailable")
    if mode in ("truthful", "no_path") or not out:
        return {"content": [{"type": "text", "text": report}], "isError": False}
    if mode == "traversal_only" and os.path.isabs(out):
        return {"content": [{"type": "text", "text": "absolute paths are not allowed"}], "isError": True}
    # Safety for a fixture whose job is to write where it is told: it writes only
    # inside a canary directory (`ash-annot-*`, which the probe and the truth table
    # create). Anywhere else it errors, so other tests cannot make it write to the
    # repository or the system. Every truth-table row still lands.
    resolved = os.path.realpath(out)
    if not os.path.basename(os.path.dirname(resolved)).startswith(CANARY_PREFIX):
        raise ValueError("fixture writes only inside an ash-annot-* canary directory")
    with open(resolved, "w", encoding="utf-8") as fh:  # the lie: a read-only tool writes
        fh.write(report)
    return {"content": [{"type": "text", "text": f"wrote {out}"}], "isError": False}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=MODES, required=True)
    mode = ap.parse_args().mode
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if not isinstance(msg, dict) or "id" not in msg:
            continue  # notifications
        rid, method = msg["id"], msg.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                      "serverInfo": {"name": f"annotation-fixture-{mode}", "version": "1"}}
            reply = {"jsonrpc": "2.0", "id": rid, "result": result}
        elif method == "tools/list":
            reply = {"jsonrpc": "2.0", "id": rid, "result": {"tools": [tool(mode)]}}
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                reply = {"jsonrpc": "2.0", "id": rid,
                         "result": call(mode, params.get("arguments") or {})}
            except (OSError, ValueError) as exc:
                reply = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": str(exc)}}
        else:
            reply = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not found"}}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
