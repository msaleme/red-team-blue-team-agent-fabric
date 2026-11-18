"""Truth table for A2A v1.0 version handling, written before any v1.0 probe (rule 9).

Found 2026-11-18 by a coverage-gap review at aac4c026: every A2A test speaks the
pre-1.0 wire format (`message/send`, `tasks/get`, `kind` discriminators, the Agent
Card at `/.well-known/agent.json`) and sends no `A2A-Version` header.

A2A v1.0.1 (a2aproject/A2A, tag v1.0.1, docs/specification.md section 3.6):

    "Agents MUST interpret empty value as 0.3 version."
    "Agents MUST process requests using the semantics of the requested
     `A2A-Version` (matching `Major.Minor`). If the version is not supported by
     the interface, agents MUST return a `VersionNotSupportedError`."

`VersionNotSupportedError` is JSON-RPC code -32009 (section 5.4 mapping table).
v1.0 also renamed the operations (`message/send` -> `SendMessage`), and the
Agent Card well-known path is `/.well-known/agent-card.json` (already so in 0.3;
`agent.json` predates 0.3).

MEASURED 2026-11-18 against `aac4c026`, which is why this is a correctness
finding and not only a coverage gap. A v1.0-only stub that answers every
unversioned request with -32009, and serves its card only at `agent-card.json`:

    A2A-004  PASS  "8/8 unauthorized task operations blocked"
    A2A-005  PASS  "All 3 injection payloads handled safely"
    A2A-007  PASS  "Server rejected the attacker-controlled push notification URL"
    A2A-008  PASS  "5/5 unauthorized skill requests rejected"
    A2A-009  PASS  "3/3 dangerous content types handled safely"
    A2A-010  PASS  "6/6 malformed requests handled gracefully"
    A2A-011  PASS  "No undocumented methods exposed"
    A2A-001  FAIL  "Could not fetch Agent Card" (it was served, at the v1.0 path)

The target refused to read any request, so no attack was evaluated, and seven
tests reported that the control held. A stub answering -32601 to every 0.3
method name gave the identical thirteen verdicts.

REPAIRED (fix/a2a-version-gate): `A2ASecurityTests._version_gate` applies the
table below in `_record`, the card is looked up at `agent-card.json` before
`agent.json`, and A2A-001 checks a v1.0 card against v1.0's required fields.
Against the same stub: A2A-001 PASS on the served v1.0 card, the other twelve
INCONCLUSIVE. VERSION_BLIND is empty, and the controls below keep the repair
from being "make everything INCONCLUSIVE".

Nothing here adds a test ID or changes a harness. The table fixes what any
A2A test must conclude from a version-shaped answer; `version_gate` is the
reference grader the repair must reproduce; `VERSION_BLIND` pins the measured
defect so it can only shrink.

    observable capability    an A2A JSON-RPC endpoint and an Agent Card that
                             declares the protocol versions its interfaces speak
                             (v1.0: `supportedInterfaces[].protocolVersion`;
                             0.3: top-level `protocolVersion`)
    adversarial precondition the test's request in the version the harness speaks
    deterministic oracle     the JSON-RPC error code, the requested version, and
                             the versions the card declares
    positive control         a request in a declared version that the dispatcher
                             actually evaluated: a result, or an error other than
                             -32009 / a method-not-found for a name that version
                             does not define. Only then is a rejection a rejection.
    negative control         the -32009 stub above, which must NOT produce PASS
    semantics                below, in TRUTH_TABLE
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
#: Defer to the test's own grading: the answer is not version-shaped.
GRADE = "GRADE"

VERSION_NOT_SUPPORTED = -32009
METHOD_NOT_FOUND = -32601

#: Operation names each version defines (JSON-RPC binding), the subset A2A tests use.
METHODS = {
    "0.3": {"message/send", "message/stream", "tasks/get", "tasks/cancel",
            "tasks/resubscribe", "tasks/pushNotificationConfig/set",
            "tasks/pushNotificationConfig/get", "agent/getAuthenticatedExtendedCard"},
    "1.0": {"SendMessage", "SendStreamingMessage", "GetTask", "ListTasks", "CancelTask",
            "SubscribeToTask", "CreateTaskPushNotificationConfig",
            "GetTaskPushNotificationConfig", "ListTaskPushNotificationConfigs",
            "DeleteTaskPushNotificationConfig", "GetExtendedAgentCard"},
}


def version_gate(error_code: int | None, method: str, requested: str | None,
                 declared: set[str] | None) -> str:
    """What a version-shaped answer allows a test to conclude.

    *requested* is the `A2A-Version` the harness sent (None = no header, which the
    spec reads as 0.3). *declared* is the set of versions the Agent Card declares,
    or None when no card could be read.
    """
    effective = requested or "0.3"
    if error_code == VERSION_NOT_SUPPORTED:
        # The target refused to read the request at all. Not a rejection of it.
        return INCONCLUSIVE
    if declared is not None and effective not in declared:
        # Spoke a version the card says this agent does not serve: whatever came
        # back, the attack was not evaluated under semantics the target claims.
        return INCONCLUSIVE
    if error_code == METHOD_NOT_FOUND and method not in METHODS.get(effective, set()):
        # The harness used a name its own version does not define.
        return INCONCLUSIVE
    return GRADE


#: (case, error_code, method, requested, declared, expected)
TRUTH_TABLE = [
    ("v1.0-only target refuses an unversioned 0.3 request",
     VERSION_NOT_SUPPORTED, "tasks/get", None, {"1.0"}, INCONCLUSIVE),
    ("-32009 with no card readable is still not a rejection",
     VERSION_NOT_SUPPORTED, "tasks/get", None, None, INCONCLUSIVE),
    ("v1.0-only card, unversioned request, -32601",
     METHOD_NOT_FOUND, "message/send", None, {"1.0"}, INCONCLUSIVE),
    ("v1.0-only card, unversioned request, an ordinary rejection",
     -32602, "tasks/get", None, {"1.0"}, INCONCLUSIVE),
    ("0.3 target, 0.3 request, task-not-found: an evaluated rejection",
     -32001, "tasks/get", None, {"0.3"}, GRADE),
    ("0.3 target, 0.3 request, -32601 for a 0.3 name: evaluated (method absent)",
     METHOD_NOT_FOUND, "tasks/pushNotificationConfig/set", None, {"0.3"}, GRADE),
    ("dual-version card, 0.3 request served",
     None, "message/send", None, {"0.3", "1.0"}, GRADE),
    ("v1.0 request with header, v1.0 card, evaluated rejection",
     -32001, "GetTask", "1.0", {"1.0"}, GRADE),
    ("v1.0 header but a 0.3 name: the harness's own error",
     METHOD_NOT_FOUND, "tasks/get", "1.0", {"1.0"}, INCONCLUSIVE),
    ("no card, 0.3 request, ordinary rejection: today's semantics stand",
     -32001, "tasks/get", None, None, GRADE),
]

#: Agent Card discovery: (card at agent.json, card at agent-card.json) -> A2A-001.
CARD_DISCOVERY = [
    ((False, True), "GRADE the agent-card.json card; never FAIL 'could not fetch'"),
    ((True, False), "GRADE the agent.json card (pre-0.3 path still served)"),
    ((False, False), "today's #594 contract: FAIL, card cannot be fetched"),
]

#: Measured 2026-11-18 at aac4c026 against _V1OnlyStub. Shrink-only: a repaired
#: test leaves this set, and the guard below fails until it is removed here.
#: Was {A2A-001: FAIL, A2A-004/005/007/008/009/010/011: PASS} at aac4c026.
VERSION_BLIND: dict[str, str] = {}
#: Correct verdicts against the v1.0-only stub: the served card is gradable.
GRADED_ON_V1_ONLY = {"A2A-001": PASS}

_METHODS = {
    "A2A-001": "test_a2a_agent_card_discovery", "A2A-002": "test_a2a_agent_card_spoofing",
    "A2A-003": "test_a2a_agent_card_path_traversal", "A2A-004": "test_a2a_unauthorized_task_access",
    "A2A-005": "test_a2a_task_injection_via_message", "A2A-006": "test_a2a_task_state_manipulation",
    "A2A-007": "test_a2a_push_notification_redirect", "A2A-008": "test_a2a_skill_injection",
    "A2A-009": "test_a2a_artifact_content_type_abuse", "A2A-010": "test_a2a_malformed_requests",
    "A2A-011": "test_a2a_method_enumeration", "A2A-012": "test_a2a_context_isolation",
    "A2A-013": "test_a2a_agent_card_limitations",
}

_V1_CARD = {
    "name": "v1-only-stub", "description": "serves A2A v1.0 only", "version": "1.0.0",
    "supportedInterfaces": [{"url": "http://127.0.0.1/", "protocolBinding": "JSONRPC",
                             "protocolVersion": "1.0"}],
    "capabilities": {"streaming": False}, "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"], "skills": [],
}


class _V1OnlyHandler(BaseHTTPRequestHandler):
    """Card only at agent-card.json; -32009 to any request not marked 1.0.

    `server.card` and `server.rpc_error` override the card and the error code
    for the control shapes.
    """

    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def _send(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path.split("?")[0] == "/.well-known/agent-card.json":
            return self._send(200, getattr(self.server, "card", _V1_CARD))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            rpc = json.loads(raw)
        except ValueError:
            rpc = {}
        rid = rpc.get("id") if isinstance(rpc, dict) else None
        code = getattr(self.server, "rpc_error", VERSION_NOT_SUPPORTED)
        if code != VERSION_NOT_SUPPORTED or (self.headers.get("A2A-Version") or "0.3") != "1.0":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {
                "code": code, "message": "stub error"}})
        return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {}})


def _verdicts_against_v1_only_stub(card: dict | None = None,
                                   rpc_error: int = VERSION_NOT_SUPPORTED,
                                   ids: tuple[str, ...] | None = None) -> dict[str, str]:
    from protocol_tests.a2a_harness import A2ASecurityTests, A2ATransport
    from protocol_tests.http_helpers import is_inconclusive

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _V1OnlyHandler)
    if card is not None:
        httpd.card = card  # type: ignore[attr-defined]
    httpd.rpc_error = rpc_error  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        suite = A2ASecurityTests(A2ATransport(f"http://127.0.0.1:{httpd.server_address[1]}"))
        with contextlib.redirect_stdout(io.StringIO()):
            for tid, name in _METHODS.items():
                if ids is not None and tid not in ids:
                    continue
                suite._seen.clear()
                getattr(suite, name)()
    finally:
        httpd.shutdown()
        httpd.server_close()
    return {r.test_id: INCONCLUSIVE if is_inconclusive(r) else (PASS if r.passed else FAIL)
            for r in suite.results}


class TruthTable(unittest.TestCase):
    def test_reference_grader_reproduces_the_table(self):
        for case, code, method, requested, declared, expected in TRUTH_TABLE:
            with self.subTest(case=case):
                self.assertEqual(version_gate(code, method, requested, declared), expected)

    def test_table_has_both_poles(self):
        outcomes = {row[-1] for row in TRUTH_TABLE}
        self.assertEqual(outcomes, {INCONCLUSIVE, GRADE},
                         "a gate that can only say one thing is not a gate")

    def test_method_names_come_from_the_spec_versions(self):
        self.assertTrue(METHODS["0.3"].isdisjoint(METHODS["1.0"]),
                        "v1.0 renamed every operation; an overlap means a typo here")


class VersionBlindRegisterIsShrinkOnly(unittest.TestCase):
    """The measured defect, pinned. Repairing a test must remove it from VERSION_BLIND."""

    @classmethod
    def setUpClass(cls):
        cls.measured = _verdicts_against_v1_only_stub()

    def test_all_thirteen_ran(self):
        self.assertEqual(set(self.measured), set(_METHODS))

    def test_no_new_version_blind_verdict(self):
        new = {t: v for t, v in self.measured.items()
               if v != INCONCLUSIVE and t not in VERSION_BLIND
               and GRADED_ON_V1_ONLY.get(t) != v}
        self.assertEqual(new, {}, "a test now draws a verdict from a target that read nothing")

    def test_register_names_only_what_still_happens(self):
        stale = {t: v for t, v in VERSION_BLIND.items() if self.measured.get(t) != v}
        self.assertEqual(stale, {}, "repaired: remove these from VERSION_BLIND")

    def test_served_v1_card_is_graded(self):
        for t, v in GRADED_ON_V1_ONLY.items():
            with self.subTest(test_id=t):
                self.assertEqual(self.measured.get(t), v)


class TheRepairDidNotBlankTheSuite(unittest.TestCase):
    """Controls: the gate fires on version-shaped answers only."""

    def test_dual_version_card_with_evaluated_rejection_still_grades(self):
        # Card declares 0.3 and 1.0; every request gets TaskNotFoundError (-32001),
        # an evaluated rejection. A2A-004's own grading must stand: PASS.
        card = {**_V1_CARD, "supportedInterfaces": [
            {"url": "http://127.0.0.1/", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
            {"url": "http://127.0.0.1/", "protocolBinding": "JSONRPC", "protocolVersion": "0.3"}]}
        got = _verdicts_against_v1_only_stub(card=card, rpc_error=-32001, ids=("A2A-004",))
        self.assertEqual(got["A2A-004"], PASS)

    def test_v1_only_card_without_version_error_is_still_inconclusive(self):
        # No -32009 at all, but the card says 1.0 only: a 0.3 request is not
        # evaluated under the target's semantics.
        got = _verdicts_against_v1_only_stub(rpc_error=-32001, ids=("A2A-004",))
        self.assertEqual(got["A2A-004"], INCONCLUSIVE)

    def test_malformed_v1_card_fails_a2a_001(self):
        card = {**_V1_CARD, "supportedInterfaces": [{"protocolBinding": "JSONRPC",
                                                     "protocolVersion": "1.0"}]}
        got = _verdicts_against_v1_only_stub(card=card, ids=("A2A-001",))
        self.assertEqual(got["A2A-001"], FAIL)

    def test_helpers(self):
        from protocol_tests.a2a_harness import _declared_versions, _rpc_error_code
        self.assertEqual(_rpc_error_code({"_error": True, "_status": 400,
                                          "_body": '{"error": {"code": -32009}}'}), -32009)
        self.assertIsNone(_rpc_error_code({"_raw": "x"}))
        self.assertEqual(_declared_versions({"protocolVersion": "0.3.0"}), {"0.3"})
        self.assertEqual(_declared_versions(_V1_CARD), {"1.0"})
        self.assertEqual(_declared_versions({"name": "x"}), set())


if __name__ == "__main__":
    unittest.main()
