"""Reference target shapes for APB-001..003.

These are not tests and they are not evidence about any real system. Each is a
runtime whose approval behaviour is known by construction, one per row of the
truth table in `docs/proposals/APPROVAL-BINDING-RUNTIME.md`, so the control
suite can pin every verdict and `--self-test` can show the exit status is
capable of 0, 1 and 2.
"""

from __future__ import annotations

import json

#: Truth-table rows, in the order the proposal lists them.
SHAPES = ("BOUND", "STANDING", "NAME_KEYED", "NAME_KEYED_SINGLE_USE",
          "REUSABLE_DECLARED_SINGLE", "POLICY_UNENFORCED", "REFUSES_ALL",
          "NO_APPROVALS", "BLIND", "UNREACHABLE",
          "DEDUP_RECORD", "LAST_ONLY_RECORD", "NAME_KEYED_LAST_ONLY",
          "BOUND_DEDUP_RECORD")

#: Record shapes (#657): a known runtime behind an execution record that is not
#: complete. Each maps to (runtime shape, record mode). The runtime decides what
#: executes; the record mode decides what the adapter reports.
#:   dedup      identical entries collapse to one, as a set would
#:   last_only  only the most recent execution is reported
RECORD_SHAPES = {
    "DEDUP_RECORD": ("REUSABLE_DECLARED_SINGLE", "dedup"),
    "LAST_ONLY_RECORD": ("REUSABLE_DECLARED_SINGLE", "last_only"),
    "NAME_KEYED_LAST_ONLY": ("NAME_KEYED", "last_only"),
    "BOUND_DEDUP_RECORD": ("BOUND", "dedup"),
}


def _key(tool: str, args: dict) -> str:
    return tool + "\x00" + json.dumps(args, sort_keys=True)


def make_target(shape: str):
    """A runtime fixture per truth-table row. Closes over its own state."""
    if shape not in SHAPES:
        raise ValueError(f"unknown shape {shape!r}")
    shape, record = RECORD_SHAPES.get(shape, (shape, "faithful"))

    keyed_on_name = shape in ("NAME_KEYED", "NAME_KEYED_SINGLE_USE")
    consumes = shape in ("BOUND", "NAME_KEYED_SINGLE_USE", "POLICY_UNENFORCED")
    declares_single = shape in ("BOUND", "NAME_KEYED_SINGLE_USE",
                                "REUSABLE_DECLARED_SINGLE", "POLICY_UNENFORCED",
                                "REFUSES_ALL")
    enforces_policy = shape != "POLICY_UNENFORCED"

    approvals: dict[str, int] = {}   # approval key -> remaining uses (-1: standing)
    denied: set[str] = set()
    executed: list[dict] = []

    def approval_key(tool: str, args: dict) -> str:
        return tool if keyed_on_name else _key(tool, args)

    def target(request: dict) -> dict | None:
        if shape == "UNREACHABLE":
            return None
        op = request.get("op")
        tool, args = request.get("tool", ""), request.get("args") or {}

        if op == "profile":
            return {"_status": 200, "single_use": declares_single}

        if op == "declare":
            rule = request.get("deny") or {}
            denied.add(_key(rule.get("tool", ""), rule.get("args") or {}))
            return {"_status": 200, "declared": True}

        if op == "executions":
            if shape == "BLIND":
                return {"_status": 200}
            if record == "last_only":
                shown = executed[-1:]
            elif record == "dedup":
                shown = [e for i, e in enumerate(executed) if e not in executed[:i]]
            else:
                shown = executed
            return {"_status": 200, "executions": [dict(e) for e in shown]}

        if op == "approve":
            # REFUSES_ALL grants every approval and then runs nothing: the shape
            # the positive controls exist for. NO_APPROVALS never grants one.
            if shape == "NO_APPROVALS":
                return {"_status": 200, "approved": False}
            approvals[approval_key(tool, args)] = 1 if consumes else -1
            return {"_status": 200, "approved": True}

        if op == "call":
            if shape in ("REFUSES_ALL", "NO_APPROVALS"):
                return {"_status": 403, "error": "approval required"}
            if enforces_policy and _key(tool, args) in denied:
                return {"_status": 403, "error": "denied by policy"}
            k = approval_key(tool, args)
            left = approvals.get(k, 0)
            if left == 0:
                return {"_status": 403, "error": "approval required"}
            if left > 0:
                approvals[k] = left - 1
            executed.append({"tool": tool, "args": dict(args)})
            return {"_status": 200, "result": "ok"}

        return {"_status": 400, "error": f"unknown op {op!r}"}

    return target
