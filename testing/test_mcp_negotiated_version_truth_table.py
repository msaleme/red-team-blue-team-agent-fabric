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
#: Versions the harness implements today (mcp_harness LEGACY/MODERN constants).
HARNESS_VERSIONS = {"2025-03-26", "2026-07-28"}


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
    header_required = negotiated not in (None, "2025-03-26")
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
]

#: Request-graded tests measured PASSing against _StrictStub at aac4c026.
#: Shrink-only, checked in both directions.
MCP_VERSION_BLIND = {"MCP-002", "MCP-005", "MCP-008", "MCP-009", "MCP-011", "MCP-016", "MCP-018"}
#: Tests that grade the initialize response itself; PASS on _StrictStub is correct.
HANDSHAKE_GRADED = {"MCP-003", "MCP-004"}


class _StrictHandler(BaseHTTPRequestHandler):
    """Supports only 2025-06-18; requires the negotiated header after initialize."""

    protocol_version = "HTTP/1.0"

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
        if rpc.get("method") == "initialize":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "strict-stub", "version": "1"}}},
                {"Mcp-Session-Id": "stub-session"})
        if self.headers.get("MCP-Protocol-Version") != "2025-06-18":
            return self._send(400, {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32600, "message": "Bad Request: Unsupported protocol version"}})
        return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {}})


def _verdicts_against_strict_stub() -> dict[str, str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _StrictHandler)
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
    @classmethod
    def setUpClass(cls):
        cls.measured = _verdicts_against_strict_stub()

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


if __name__ == "__main__":
    unittest.main()
