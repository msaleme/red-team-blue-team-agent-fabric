"""Truth table for MCP negotiated-version handling, written before any repair (rule 9).

Found 2026-11-18 while checking whether the A2A version-blind defect
(`test_a2a_v1_version_truth_table.py`) recurs in MCP. In legacy mode the harness
requests `2025-03-26` in `initialize`, ignores the version the server answers
with, and sends no `MCP-Protocol-Version` header afterwards.

MCP specification 2025-06-18 (modelcontextprotocol/modelcontextprotocol,
docs/specification/2025-06-18/basic/):

    transports.mdx  "If using HTTP, the client MUST include the
                     `MCP-Protocol-Version: <protocol-version>` HTTP header on all
                     subsequent requests to the MCP server"
                    "If the server receives a request with an invalid or
                     unsupported `MCP-Protocol-Version`, it MUST respond with
                     `400 Bad Request`."
    lifecycle.mdx   "If the server supports the requested protocol version, it
                     MUST respond with the same version. Otherwise, the server
                     MUST respond with another protocol version it supports."
                    "If the client does not support the version in the server's
                     response, it SHOULD disconnect."

The same clauses are in 2025-11-25.

MEASURED 2026-11-18 at `aac4c026`, legacy and `--protocol-version auto` alike,
against _StrictStub: a server that supports only `2025-06-18`, answers
`initialize` with it, and answers every later request that lacks the negotiated
header with HTTP 400 "Unsupported protocol version":

    MCP-002  PASS  "Server correctly rejected unknown tool"
    MCP-005  PASS  "4/4 traversal attempts blocked"
    MCP-008  PASS  "7/7 malformed messages handled gracefully"
    MCP-009  PASS  "Server answered the 1000-message batch"
    MCP-011  PASS  "Server properly handled oversized tool description"
    MCP-016  PASS  "6/6 SSRF resource URIs blocked"
    MCP-018  PASS  "Server rejected 10.0 MB body (413/error)"

The server read none of those requests. MCP-003 and MCP-004 also PASS, and
correctly: they grade the `initialize` response itself, which was served. A stub
answering 400 to everything, `initialize` included, gives 34 of 34 INCONCLUSIVE,
also correct; the defect needs a served handshake.

REPAIRED (fix/mcp-negotiated-version-header). `initialize()` adopts a negotiated
2025-06-18 or 2025-11-25 and sends it as `MCP-Protocol-Version` on every later
request; any other negotiated version disconnects, as lifecycle.mdx directs; and
`_record` reports INCONCLUSIVE for a test in which the server refused a request
for its protocol version. Against _StrictStub the six tests above now read real
answers (it serves everything, so MCP-002/005/008/018 FAIL, which is correct);
MCP-009's PASS there is now earned. The register is measured against
_RefusingStub instead, which refuses every post-handshake request whatever it
carries: no request-graded test may PASS there.

Severity is lower than the A2A finding in practice, because common SDKs still
accept `2025-03-26` without a header. The verdicts are wrong whenever one does not.

    observable capability    an MCP Streamable HTTP server and its `initialize` result
    adversarial precondition the test's request, sent after the handshake
    deterministic oracle     the version requested, the version negotiated, whether
                             the request carried `MCP-Protocol-Version`, and the
                             answer's status and error
    positive control         a request carrying the negotiated version that the
                             server evaluated; only then is a rejection a rejection
    negative control         _StrictStub, which must not produce a request-graded PASS
    semantics                TRUTH_TABLE below
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

PASS, FAIL, INCONCLUSIVE, GRADE = "PASS", "FAIL", "INCONCLUSIVE", "GRADE"
#: Versions the harness implements (mcp_harness LEGACY, HEADER_DEFINING_LEGACY, MODERN).
HARNESS_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}


def mcp_version_gate(requested: str, negotiated: str | None, sent_header: str | None,
                     status: int | None, unsupported_version_error: bool) -> str:
    """What a post-handshake answer allows a request-graded test to conclude."""
    if unsupported_version_error:
        # The server refused to read the request at the version it was sent in.
        return INCONCLUSIVE
    if negotiated is not None and negotiated != requested and negotiated not in HARNESS_VERSIONS:
        # Spec: the client SHOULD disconnect. Nothing after the handshake was
        # exchanged under semantics both sides share.
        return INCONCLUSIVE
    # 2025-03-26 predates the header, so its absence there is correct. (The first
    # draft of this grader required it unconditionally; the "legacy agreed,
    # served rejection" row caught that.)
    # 2024-11-05 predates it as well; older SDKs still negotiate it (the integration
    # suite's mock server does, which is how the repair's first draft was caught
    # disconnecting from it).
    header_required = negotiated not in (None, "2024-11-05", "2025-03-26")
    if header_required and sent_header != negotiated:
        # A request without the MUST header, at a version that defines it.
        return INCONCLUSIVE
    return GRADE


#: (case, requested, negotiated, sent_header, status, unsupported_error, expected)
TRUTH_TABLE = [
    ("server negotiates 2025-06-18, request has no header, 400 version error",
     "2025-03-26", "2025-06-18", None, 400, True, INCONCLUSIVE),
    ("server negotiates 2025-06-18, request has no header, any 400",
     "2025-03-26", "2025-06-18", None, 400, False, INCONCLUSIVE),
    ("server negotiates 2025-06-18, request has no header, served",
     "2025-03-26", "2025-06-18", None, 200, False, INCONCLUSIVE),
    ("legacy agreed both ways, no header defined, ordinary error",
     "2025-03-26", "2025-03-26", None, 200, False, GRADE),
    ("legacy agreed, served rejection",
     "2025-03-26", "2025-03-26", None, 400, False, GRADE),
    ("negotiated header sent and matched, evaluated rejection",
     "2025-06-18", "2025-06-18", "2025-06-18", 400, False, GRADE),
    ("modern stateless, header sent, evaluated",
     "2026-07-28", "2026-07-28", "2026-07-28", 200, False, GRADE),
    ("modern header sent, server answers unsupported-version",
     "2026-07-28", "2026-07-28", "2026-07-28", 400, True, INCONCLUSIVE),
    ("server negotiates 2024-11-05, which predates the header",
     "2025-03-26", "2024-11-05", None, 200, False, GRADE),
    ("server negotiates a version the harness does not implement",
     "2025-03-26", "2099-01-01", None, 200, False, INCONCLUSIVE),
    ("server negotiates 2025-11-25, header sent and matched, served",
     "2025-03-26", "2025-11-25", "2025-11-25", 200, False, GRADE),
]

#: Request-graded tests that PASS on a server which read none of their requests.
#: Measured against _StrictStub at aac4c026 as {MCP-002, 005, 008, 009, 011, 016, 018};
#: emptied by the repair and now measured against _RefusingStub. Shrink-only.
MCP_VERSION_BLIND: set[str] = set()
#: Request-graded tests that must get a real verdict on _StrictStub once the header is
#: sent: the positive control that the repair did not blank the suite.
GRADED_ON_STRICT_STUB = {"MCP-002", "MCP-005", "MCP-008", "MCP-018"}
#: Tests that grade the initialize response itself; PASS on _StrictStub is correct.
HANDSHAKE_GRADED = {"MCP-003", "MCP-004"}


class _StrictHandler(BaseHTTPRequestHandler):
    """Supports only 2025-06-18; requires the negotiated header after initialize."""

    protocol_version = "HTTP/1.0"
    negotiate = "2025-06-18"
    refuse_all = False   #: refuse every post-handshake request, header or not
    seen_headers: list = []  #: MCP-Protocol-Version of each post-handshake request

    def log_message(self, *args):
        pass

    def _send(self, status, body, extra=None):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._send(405, {"error": "method not allowed"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            rpc = json.loads(raw)
        except ValueError:
            rpc = {}
        rpc = rpc if isinstance(rpc, dict) else {}
        rid = rpc.get("id")
        if rpc.get("method") == "initialize" and not type(self).seen_headers:
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": self.negotiate, "capabilities": {"tools": {}},
                "serverInfo": {"name": "strict-stub", "version": "1"}}},
                {"Mcp-Session-Id": "stub-session"})
        type(self).seen_headers.append(self.headers.get("MCP-Protocol-Version"))
        if self.refuse_all or self.headers.get("MCP-Protocol-Version") != self.negotiate:
            return self._send(400, {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32600, "message": "Bad Request: Unsupported protocol version"}})
        return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {}})


class _RefusingHandler(_StrictHandler):
    """Negotiates 2025-06-18, then refuses every request for its version."""
    refuse_all = True
    seen_headers: list = []


class _UnknownVersionHandler(_StrictHandler):
    """Negotiates a version no harness revision implements."""
    negotiate = "2099-01-01"
    seen_headers: list = []


class _LegacyHandler(_StrictHandler):
    """Answers 2025-03-26, which predates the header; serves everything."""
    negotiate = "2025-03-26"
    seen_headers: list = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            rpc = json.loads(raw)
        except ValueError:
            rpc = {}
        rpc = rpc if isinstance(rpc, dict) else {}
        if rpc.get("method") == "initialize" and not type(self).seen_headers:
            return self._send(200, {"jsonrpc": "2.0", "id": rpc.get("id"), "result": {
                "protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                "serverInfo": {"name": "legacy-stub", "version": "1"}}})
        type(self).seen_headers.append(self.headers.get("MCP-Protocol-Version"))
        return self._send(200, {"jsonrpc": "2.0", "id": rpc.get("id"), "result": {}})


def _verdicts_against_strict_stub(handler=_StrictHandler) -> dict[str, str]:
    handler.seen_headers.clear()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01},
                     daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            subprocess.run(
                [sys.executable, "-m", "protocol_tests.mcp_harness", "--transport", "http",
                 "--url", f"http://127.0.0.1:{httpd.server_address[1]}/mcp",
                 "--json", "--report", str(report)],
                cwd=REPO_ROOT, capture_output=True, timeout=240, check=False)
            results = json.loads(report.read_text())["results"]
    finally:
        httpd.shutdown()
        httpd.server_close()

    def verdict(r):
        if str(r.get("details", "")).startswith("INCONCLUSIVE"):
            return INCONCLUSIVE
        return PASS if r.get("passed") else FAIL

    return {r["test_id"]: verdict(r) for r in results}


class TruthTable(unittest.TestCase):
    def test_reference_grader_reproduces_the_table(self):
        for case, req, neg, hdr, status, unsup, expected in TRUTH_TABLE:
            with self.subTest(case=case):
                self.assertEqual(mcp_version_gate(req, neg, hdr, status, unsup), expected)

    def test_table_has_both_poles(self):
        self.assertEqual({row[-1] for row in TRUTH_TABLE}, {INCONCLUSIVE, GRADE})


class VersionBlindRegisterIsShrinkOnly(unittest.TestCase):
    """Negative control: _RefusingStub read no request after the handshake."""

    @classmethod
    def setUpClass(cls):
        cls.measured = _verdicts_against_strict_stub(_RefusingHandler)

    def test_the_run_produced_rows(self):
        self.assertGreaterEqual(len(self.measured), 30, "the harness did not run")

    def test_no_new_version_blind_pass(self):
        new = {t for t, v in self.measured.items()
               if v == PASS and t not in MCP_VERSION_BLIND | HANDSHAKE_GRADED}
        self.assertEqual(new, set(), "a test PASSes on a request the server never read")

    def test_register_names_only_what_still_happens(self):
        stale = {t for t in MCP_VERSION_BLIND if self.measured.get(t) != PASS}
        self.assertEqual(stale, set(), "repaired: remove these from MCP_VERSION_BLIND")

    def test_handshake_graded_tests_still_pass(self):
        # Positive control: the stub's served handshake is gradable, and a repair
        # that made everything INCONCLUSIVE would be the opposite defect.
        for t in HANDSHAKE_GRADED:
            with self.subTest(test_id=t):
                self.assertEqual(self.measured.get(t), PASS)


class TheRepairDidNotBlankTheSuite(unittest.TestCase):
    """Positive controls: the header goes out, and served requests are graded."""

    @classmethod
    def setUpClass(cls):
        cls.measured = _verdicts_against_strict_stub(_StrictHandler)
        cls.headers = list(_StrictHandler.seen_headers)

    def test_every_post_handshake_request_carries_the_negotiated_version(self):
        self.assertGreater(len(self.headers), 30, "the harness sent almost nothing")
        self.assertEqual(set(self.headers), {"2025-06-18"})

    def test_served_requests_get_a_real_verdict(self):
        for t in GRADED_ON_STRICT_STUB:
            with self.subTest(test_id=t):
                self.assertIn(self.measured.get(t), {PASS, FAIL})


class VersionRejectionDetector(unittest.TestCase):
    """`_is_version_rejection` must not read an ordinary 400 as a version refusal."""

    def setUp(self):
        sys.path.insert(0, str(REPO_ROOT))
        from protocol_tests.mcp_harness import _is_version_rejection
        self.f = _is_version_rejection

    def test_final_and_rc_codes(self):
        self.assertTrue(self.f(400, {"error": {"code": -32022, "message": "x"}}))
        self.assertTrue(self.f(400, {"error": {"code": -32004, "message": "x"}}))

    def test_legacy_400_naming_the_version(self):
        self.assertTrue(self.f(400, b'{"error":{"code":-32600,"message":"Unsupported protocol version"}}'))

    def test_an_ordinary_400_is_not_a_version_refusal(self):
        # Negative control: a server rejecting malformed input is grading the attack.
        self.assertFalse(self.f(400, {"error": {"code": -32600, "message": "Invalid Request"}}))
        self.assertFalse(self.f(400, b"Bad Request"))

    def test_only_400_counts(self):
        self.assertFalse(self.f(200, {"error": {"code": -32022}}))
        self.assertFalse(self.f(500, b"unsupported protocol version"))


class OtherNegotiatedVersions(unittest.TestCase):
    def test_a_version_the_harness_does_not_implement_disconnects(self):
        measured = _verdicts_against_strict_stub(_UnknownVersionHandler)
        self.assertGreaterEqual(len(measured), 30)
        self.assertEqual(set(measured.values()), {INCONCLUSIVE})
        self.assertEqual(_UnknownVersionHandler.seen_headers, [],
                         "nothing may be sent after a version the client cannot speak")

    def test_2025_03_26_gets_no_header(self):
        measured = _verdicts_against_strict_stub(_LegacyHandler)
        self.assertGreaterEqual(len(measured), 30)
        self.assertTrue(_LegacyHandler.seen_headers)
        self.assertEqual(set(_LegacyHandler.seen_headers), {None})


if __name__ == "__main__":
    unittest.main()
