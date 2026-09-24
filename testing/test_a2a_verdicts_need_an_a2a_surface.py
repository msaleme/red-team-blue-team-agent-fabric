"""A2A rejections count only from an A2A surface that could have accepted.

The pole-pilot follow-up review (2026-09-24, pinned at c7d4347) drove
a2a_harness against four local poles -- allow-all, refuse-all, 404-everywhere
and a closed port -- and found six tests scoring PASS against a host that
answered HTTP 404 to every request:

    A2A-004  "8/8 unauthorized task operations blocked"
    A2A-007  "Server rejected the attacker-controlled push notification URL"
    A2A-008  "5/5 unauthorized skill requests rejected"
    A2A-009  "3/3 dangerous content types handled safely"
    A2A-010  "6/6 malformed requests handled gracefully"
    A2A-011  "No undocumented methods exposed: all 8 were rejected"

Each read any `_error` or status >= 400 as "the server actively rejected the
request". A route-level 404 comes back before any A2A dispatcher, task store
or parser sees the request, so it is not evidence the target rejected THIS
request. A2A-010 also counted no response as "handled gracefully"; A2A-008,
A2A-009 and A2A-011 could count an unanswered request as rejected.

The same defect class as the PraisonAI/CrewAI verdicts fixed in #591
(testing/test_cve_verdicts_are_target_differentials.py), and the fix has the
same shape: a positive control for the surface, then three values.

    surface absent (404/405 bare, closed port, no answer)    INCONCLUSIVE
    surface present, request rejected (JSON-RPC error, 401/403, or a non-2xx
      once the endpoint has shown itself an A2A surface)     PASS
    surface present, request accepted                        FAIL

"Surface present" is `_shows_a2a_surface` over the test's own responses, or,
failing that, over a benign `tasks/get` sent to the same URL
(`A2ASecurityTests._surface_present`).

A2A-013 is the seventh finding: an unavailable Agent Card was a FAIL although
an absent `limitations` member on a fetched card is already INCONCLUSIVE. The
owner's decision: unavailable card -> INCONCLUSIVE with an explicit reason.

A2A-001 is contract-consistent (fetch and validate the card; a 404 FAILs it)
and is pinned here as UNCHANGED.

Every pole below is a real stdlib HTTP server on loopback, not a transport
fixture: the defect lived in how the transport's view of an HTTP error was
read, so the evidence has to cross a socket.
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

from protocol_tests.a2a_harness import (
    A2ASecurityTests,
    A2ATransport,
    _shows_a2a_surface,
)
from protocol_tests.http_helpers import is_inconclusive

CLOSED_PORT_URL = "http://127.0.0.1:9"

#: The six tests whose rejection-counting verdicts were target-blind.
SURFACE_GATED = ("A2A-004", "A2A-007", "A2A-008", "A2A-009", "A2A-010", "A2A-011")

_METHODS = {
    "A2A-001": "test_a2a_agent_card_discovery",
    "A2A-004": "test_a2a_unauthorized_task_access",
    "A2A-007": "test_a2a_push_notification_redirect",
    "A2A-008": "test_a2a_skill_injection",
    "A2A-009": "test_a2a_artifact_content_type_abuse",
    "A2A-010": "test_a2a_malformed_requests",
    "A2A-011": "test_a2a_method_enumeration",
    "A2A-013": "test_a2a_agent_card_limitations",
}

_CARD = {"name": "stub-agent", "url": "http://127.0.0.1/", "version": "1.0.0",
         "capabilities": {"streaming": False}, "skills": []}


# ---------------------------------------------------------------------------
# A stub A2A server whose answer to each request is decided by a callable
# ---------------------------------------------------------------------------

DROP = object()  # route return value: close the socket without answering


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):  # silence
        pass

    def _serve(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            rpc = json.loads(raw) if raw else None
        except ValueError:
            rpc = None
        if not isinstance(rpc, dict):
            rpc = None
        out = self.server.route(self.command, self.path, raw, rpc)  # type: ignore[attr-defined]
        if out is DROP:
            self.close_connection = True
            return
        status, body = out
        payload = b"" if body is None else (
            body.encode() if isinstance(body, str) else json.dumps(body).encode())
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _serve
    do_POST = _serve


class StubServer:
    """``route(verb, path, raw_body, parsed_rpc_or_None) -> (status, body) | DROP``."""

    def __init__(self, route):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.route = route  # type: ignore[attr-defined]
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(timeout=5)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}"


def _rpc_error(rpc, code=-32602, message="rejected"):
    return {"jsonrpc": "2.0", "id": (rpc or {}).get("id"),
            "error": {"code": code, "message": message}}


def _rpc_result(rpc, result=None):
    return {"jsonrpc": "2.0", "id": (rpc or {}).get("id"),
            "result": result if result is not None else {
                "id": "task-1", "kind": "task",
                "status": {"state": "completed"}}}


# --- the poles --------------------------------------------------------------

def not_found_everywhere(verb, path, raw, rpc):
    """No A2A surface: every verb, every path, a bare 404."""
    return 404, "Not Found"


def generic_json_404(verb, path, raw, rpc):
    """A web framework's JSON 404 page: an `error` object, but not JSON-RPC."""
    return 404, {"error": {"code": 404, "message": "Not Found"}}


def method_not_allowed(verb, path, raw, rpc):
    return 405, "Method Not Allowed"


def refusing_dispatcher(verb, path, raw, rpc):
    """A reachable A2A dispatcher that rejects every request at protocol level."""
    if verb == "GET":
        return (200, _CARD) if path.endswith("agent.json") else (404, "no")
    if rpc is None:
        return 200, {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": "Parse error"}}
    return 200, _rpc_error(rpc)


def forbidding_endpoint(verb, path, raw, rpc):
    """A reachable endpoint that answers every call with an explicit 403."""
    return 403, "Forbidden"


def accepting_dispatcher(verb, path, raw, rpc):
    """A reachable A2A dispatcher that processes everything it is sent."""
    if verb == "GET":
        return (200, _CARD) if path.endswith("agent.json") else (404, "no")
    return 200, _rpc_result(rpc)


def _run(url, ids):
    suite = A2ASecurityTests(A2ATransport(url))
    with contextlib.redirect_stdout(io.StringIO()):
        for tid in ids:
            suite._seen.clear()
            getattr(suite, _METHODS[tid])()
    return {r.test_id: r for r in suite.results}


def _verdict(result):
    if is_inconclusive(result):
        return "INCONCLUSIVE"
    return "PASS" if result.passed else "FAIL"


def _against(route, ids=SURFACE_GATED):
    with StubServer(route) as srv:
        return _run(srv.base_url, ids)


# ---------------------------------------------------------------------------
# The six surface-gated tests, four poles each
# ---------------------------------------------------------------------------

class TestSurfaceAbsentIsInconclusive(unittest.TestCase):
    def _assert_all_inconclusive(self, rs):
        for tid in SURFACE_GATED:
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(rs[tid]), "INCONCLUSIVE", rs[tid].details)

    def test_closed_port(self):
        self._assert_all_inconclusive(_run(CLOSED_PORT_URL, SURFACE_GATED))

    def test_404_everywhere(self):
        """The review's finding: this pole scored PASS on all six."""
        rs = _against(not_found_everywhere)
        self._assert_all_inconclusive(rs)
        for tid in SURFACE_GATED:
            with self.subTest(test_id=tid):
                self.assertIn("no A2A JSON-RPC surface", rs[tid].details)

    def test_generic_json_404_page(self):
        """An `{"error": {...}}` 404 body is a route answering, not a dispatcher."""
        self._assert_all_inconclusive(_against(generic_json_404))

    def test_405_everywhere(self):
        self._assert_all_inconclusive(_against(method_not_allowed))


class TestSurfacePresentAndRejectingIsPass(unittest.TestCase):
    def test_jsonrpc_error_from_a_reachable_dispatcher(self):
        rs = _against(refusing_dispatcher)
        for tid in SURFACE_GATED:
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(rs[tid]), "PASS", rs[tid].details)

    def test_explicit_403_from_the_endpoint(self):
        """An authorization refusal is an answer from an endpoint that exists."""
        rs = _against(forbidding_endpoint)
        for tid in SURFACE_GATED:
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(rs[tid]), "PASS", rs[tid].details)

    def test_plain_400_counts_once_the_benign_control_is_answered(self):
        """A2A-010: a parser that answers garbage with a bare 400 is handling
        it, provided the endpoint answers a well-formed request as JSON-RPC.
        This is the path where the benign `tasks/get` control is what
        establishes the surface."""
        def route(verb, path, raw, rpc):
            if rpc is None or rpc.get("jsonrpc") != "2.0" or "method" not in rpc:
                return 400, "Bad Request"
            if rpc.get("method") == "tasks/get":
                return 200, _rpc_error(rpc, -32001, "Task not found")
            return 400, "Bad Request"
        rs = _against(route, ("A2A-010",))
        self.assertEqual(_verdict(rs["A2A-010"]), "PASS", rs["A2A-010"].details)

    def test_plain_400_everywhere_is_inconclusive(self):
        """The same 400s with no answered control: nothing shows a parser."""
        rs = _against(lambda *a: (400, "Bad Request"), ("A2A-010",))
        self.assertEqual(_verdict(rs["A2A-010"]), "INCONCLUSIVE", rs["A2A-010"].details)


class TestSurfacePresentAndAcceptingIsFail(unittest.TestCase):
    def test_a_dispatcher_that_processes_everything(self):
        rs = _against(accepting_dispatcher)
        for tid in SURFACE_GATED:
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(rs[tid]), "FAIL", rs[tid].details)


class TestNoAnswerIsNotARejection(unittest.TestCase):
    """Partial silence from a present surface: nothing accepted, not everything
    observed being rejected. Previously A2A-010 counted no response as handled,
    and A2A-008/009/011 could count an unanswered request as rejected."""

    def test_dropped_adversarial_requests_are_inconclusive(self):
        def route(verb, path, raw, rpc):
            # The benign control is answered; every adversarial request is
            # dropped on the floor.
            if rpc and rpc.get("method") == "tasks/get" and str(
                    (rpc.get("params") or {}).get("id", "")).startswith("ash-surface-probe"):
                return 200, _rpc_error(rpc, -32001, "Task not found")
            return DROP
        rs = _against(route)
        for tid in SURFACE_GATED:
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(rs[tid]), "INCONCLUSIVE", rs[tid].details)


    def test_some_dropped_rest_rejected_is_inconclusive(self):
        """The discriminating case. The all-dropped pole above is also caught
        by `_record`'s silence guard; this one is not, because most requests
        ARE answered. Before the repair A2A-009 and A2A-011 PASSed here (the
        dropped request was tallied as handled/rejected), A2A-004, A2A-008 and
        A2A-010 FAILed (a dropped request is not an acceptance)."""
        dropped_whole = (b'not json', b'{"jsonrpc": "2.0"}')   # A2A-010: 2 of 6
        dropped_containing = (
            b'"admin-task-1"',                          # A2A-004: get + cancel of one id
            b'"system_shell"', b'"disable_security"',   # A2A-008: 2 of 5
            b'subprocess.Popen',                        # A2A-009: 1 of 3
            b'"system/exec"',                           # A2A-011: 1 of 8
        )

        def route(verb, path, raw, rpc):
            if raw in dropped_whole or any(m in raw for m in dropped_containing):
                return DROP
            if rpc is None:
                return 200, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "Parse error"}}
            return 200, _rpc_error(rpc)
        partial = ("A2A-004", "A2A-008", "A2A-009", "A2A-010", "A2A-011")
        rs = _against(route, partial)
        for tid in partial:
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(rs[tid]), "INCONCLUSIVE", rs[tid].details)


class TestTheVerdictDependsOnTheTarget(unittest.TestCase):
    """The core property: three poles, three different verdicts, per test."""

    def test_three_poles_three_verdicts(self):
        absent = _against(not_found_everywhere)
        refuse = _against(refusing_dispatcher)
        accept = _against(accepting_dispatcher)
        for tid in SURFACE_GATED:
            with self.subTest(test_id=tid):
                self.assertEqual(
                    {_verdict(absent[tid]), _verdict(refuse[tid]), _verdict(accept[tid])},
                    {"INCONCLUSIVE", "PASS", "FAIL"})


class TestSurfaceClassifier(unittest.TestCase):
    """The per-response rule, at the unit level."""

    def test_shapes(self):
        cases = [
            ({"_error": True, "_exception": "refused"}, False),
            ({"_error": True, "_status": 404, "_body": "Not Found"}, False),
            ({"_error": True, "_status": 405, "_body": ""}, False),
            ({"_error": True, "_status": 404,
              "_body": '{"error": {"code": 404, "message": "Not Found"}}'}, False),
            ({"_error": True, "_status": 500, "_body": "oops"}, False),
            ({"_error": True, "_status": 400,
              "_body": '{"jsonrpc": "2.0", "id": null, "error": {"code": -32700}}'}, True),
            ({"_error": True, "_status": 401, "_body": ""}, True),
            ({"_error": True, "_status": 403, "_body": "Forbidden"}, True),
            ({"error": {"code": -32601, "message": "Method not found"}}, True),
            ({"result": {}}, True),
            ({}, True),  # a 2xx with an empty body: the route took the POST
        ]
        for resp, expected in cases:
            with self.subTest(resp=resp):
                self.assertIs(_shows_a2a_surface(resp), expected)


# ---------------------------------------------------------------------------
# A2A-013 changed; A2A-001 did not
# ---------------------------------------------------------------------------

class TestA2A013UnavailableCardIsInconclusive(unittest.TestCase):
    def test_closed_port(self):
        r = _run(CLOSED_PORT_URL, ("A2A-013",))["A2A-013"]
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)

    def test_card_404(self):
        r = _against(not_found_everywhere, ("A2A-013",))["A2A-013"]
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)
        self.assertIn("could not be fetched", r.details)
        self.assertIn("HTTP 404", r.details)

    def test_after_a2a_001_failed_on_the_same_card(self):
        """In a full run A2A-001 fetches first; its FAIL must not become 013's."""
        rs = _against(not_found_everywhere, ("A2A-001", "A2A-013"))
        self.assertEqual(_verdict(rs["A2A-001"]), "FAIL", rs["A2A-001"].details)
        self.assertEqual(_verdict(rs["A2A-013"]), "INCONCLUSIVE", rs["A2A-013"].details)

    def test_a_fetched_card_is_still_graded(self):
        def route(verb, path, raw, rpc):
            return 200, dict(_CARD, limitations="none")
        r = _against(route, ("A2A-013",))["A2A-013"]
        self.assertEqual(_verdict(r), "FAIL", r.details)


class TestA2A001IsUnchanged(unittest.TestCase):
    """Contract-consistent per the review: fetch and validate the Agent Card."""

    def test_404_fails(self):
        r = _against(not_found_everywhere, ("A2A-001",))["A2A-001"]
        self.assertEqual(_verdict(r), "FAIL", r.details)
        self.assertIn("Could not fetch Agent Card", r.details)

    def test_closed_port_is_inconclusive(self):
        r = _run(CLOSED_PORT_URL, ("A2A-001",))["A2A-001"]
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)

    def test_valid_card_passes(self):
        r = _against(accepting_dispatcher, ("A2A-001",))["A2A-001"]
        self.assertEqual(_verdict(r), "PASS", r.details)


if __name__ == "__main__":
    unittest.main()
