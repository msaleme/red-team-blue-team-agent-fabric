"""The four gated A2A verdicts must still be able to PASS.

A2A-003, A2A-005, A2A-006 and A2A-012 all passed when a marker was ABSENT, so a
host that answered everything with one canned envelope scored them as controls
that held. Each is now gated on a positive control.

Gating is only an improvement if the verdict can still be right, and this module
is a declared NARROW_LOCAL_RULE where the shared serviced guard already produced
one false negative. So both poles are seeded here against transport fixtures
rather than against the prose shapes, which are not A2A servers at all.
"""
from __future__ import annotations

import json
import sys
import unittest
import uuid
from pathlib import Path
from typing import ClassVar

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from protocol_tests.a2a_harness import A2ASecurityTests, A2ATransport

GATED = ("A2A-003", "A2A-005", "A2A-006", "A2A-012")


class _WellBehavedTransport(A2ATransport):
    """A server that genuinely does the things these verdicts test for.

    Resolves paths, processes message content, retains context within a session
    and isolates across contexts, and refuses a forced state transition.
    """

    def __init__(self, base_url="http://fixture.invalid"):
        super().__init__(base_url)
        self._memory: dict[str, list[str]] = {}

    def get(self, path="/.well-known/agent.json"):
        if path.rstrip("/").endswith("agent.json"):
            return {"name": "fixture-agent", "version": "1.0",
                    "skills": [], "_status": 200}
        return {"_status": 404, "error": {"code": -32601, "message": "Not found"}}

    def rpc(self, method, params=None):
        params = params or {}
        msg = (params.get("message") or {})
        text = " ".join(p.get("text", "") for p in msg.get("parts", []))
        ctx = (params.get("configuration") or {}).get("contextId", "default")
        cfg = params.get("configuration") or {}

        if cfg.get("forceOverride"):
            return {"jsonrpc": "2.0", "id": 1,
                    "error": {"code": -32602,
                              "message": "forced state transition rejected"}}

        self._memory.setdefault(ctx, []).append(text)
        # Answers only from ITS OWN context. Never echoes the attack text, and
        # never leaks another context's contents.
        recalled = " ".join(self._memory[ctx][:-1])
        return {"jsonrpc": "2.0", "id": 1, "result": {
            "id": f"task-{uuid.uuid4().hex[:6]}",
            "status": "completed",
            "parts": [{"kind": "text",
                       "text": f"Acknowledged {len(text)} chars. {recalled}"}],
        }}

    def rpc_raw(self, *args, **kwargs):
        return {"jsonrpc": "2.0", "id": 1, "result": {"status": "completed"}}


class _CannedTransport(A2ATransport):
    """Answers every call with one identical, permissive envelope."""

    _ENVELOPE: ClassVar[dict] = {"jsonrpc": "2.0", "id": 1, "result": {
        "ok": True, "granted": True, "allowed": True, "status": "completed",
        "id": "task-1", "task": {"id": "task-1", "status": "completed"}}}

    def __init__(self, base_url="http://fixture.invalid"):
        super().__init__(base_url)

    def get(self, path="/.well-known/agent.json"):
        return json.loads(json.dumps(self._ENVELOPE))

    def rpc(self, method, params=None):
        return json.loads(json.dumps(self._ENVELOPE))

    def rpc_raw(self, *args, **kwargs):
        return json.loads(json.dumps(self._ENVELOPE))


def _run(transport):
    import contextlib
    import io

    suite = A2ASecurityTests(transport)
    with contextlib.redirect_stdout(io.StringIO()):
        for name in ("test_a2a_agent_card_path_traversal",
                     "test_a2a_task_injection_via_message",
                     "test_a2a_task_state_manipulation",
                     "test_a2a_context_isolation"):
            suite._seen.clear()
            getattr(suite, name)()
    return {r.test_id: r for r in suite.results}


class TestTheGatedVerdictsCanStillPass(unittest.TestCase):
    def test_a_well_behaved_server_passes_all_four(self) -> None:
        rs = _run(_WellBehavedTransport())
        for tid in GATED:
            with self.subTest(test_id=tid):
                r = rs[tid]
                self.assertNotIn(
                    "INCONCLUSIVE", r.details,
                    f"{tid} was unmeasurable against a server that resolves "
                    f"paths, processes messages, retains context and rejects "
                    f"forced transitions: {r.details}")
                self.assertTrue(r.passed, f"{tid}: {r.details}")


class TestTheGatedVerdictsAbstain(unittest.TestCase):
    def test_a_canned_envelope_is_inconclusive_not_a_pass(self) -> None:
        """The defect: one identical permissive answer scored four controls."""
        rs = _run(_CannedTransport())
        for tid in GATED:
            with self.subTest(test_id=tid):
                r = rs[tid]
                self.assertFalse(
                    r.passed,
                    f"{tid} passed against a host returning one canned "
                    f"envelope to everything: {r.details}")
                self.assertIn("INCONCLUSIVE", r.details)


if __name__ == "__main__":
    unittest.main()
