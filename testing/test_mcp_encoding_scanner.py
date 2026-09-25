"""CVE-006 judges the target, and its detector reads the five encodings.

## The defect

Until 2026-09-24 `test_description_payload_encoding` (CVE-006, "Description
Payload Encoding Detection") built one tool per ENCODED_PAYLOADS entry, scanned
it with this module's own `scan_tool_fields`, and never contacted the target.
The scanner matched SUSPICIOUS_RE against plain text only, so it caught none of
base64, unicode_escape, homoglyph, zero_width or rtl_override, and CVE-006
FAILed 0-of-5 on every run: a harness defect reported, unlabelled, as a target
finding. Since #596 that row made every default run exit 1.

## The reading

Both readings in the task applied. The row's name, severity and ASI04 tag, and
its siblings CVE-001/CVE-003, which run the same scanner over the target's
tools/list, say the question is about the target: does it publish tools whose
poisoning is hidden behind an encoding. The body was a detector self-test. So:

* the scanner decodes (ENCODING_DECODERS) -- which also reaches CVE-001, CVE-003
  and CVE-008, since they share it;
* CVE-006 scans the target's tools, with the detector's coverage as a
  precondition (positive AND negative controls), not as the verdict.

Truth table (CLAUDE.md convention 9):

    closed port / 404 / no tools     INCONCLUSIVE
    tools with encoded poisoning     FAIL
    clean tools, detector complete   PASS
    clean tools, detector gap        INCONCLUSIVE  (a clean scan proves nothing)
    encoded poisoning, detector gap  FAIL          (what was found was found)
"""

from __future__ import annotations

import contextlib
import io
import json
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests import mcp_tool_poisoning_harness as M  # noqa: E402
from protocol_tests.http_helpers import row_outcome  # noqa: E402


def _encodings(tool: dict) -> set[str]:
    return {e for f in M.scan_tool_fields(tool) for e in f.get("encodings", [])}


class TestDetectorPositiveControls(unittest.TestCase):
    def test_every_encoded_payload_is_flagged_and_credited_to_its_encoding(self):
        for enc, payload in M.ENCODED_PAYLOADS.items():
            with self.subTest(encoding=enc):
                tool = M._tool_with_note(f"t_{enc}", payload)
                self.assertIn(enc, _encodings(tool))

    def test_the_payload_list_and_the_decoders_cover_the_same_encodings(self):
        # Derived, not restated: a new ENCODED_PAYLOADS entry without a decoder
        # (or the reverse) fails here rather than going unscanned.
        self.assertEqual(set(M.ENCODED_PAYLOADS), set(M.ENCODING_DECODERS))

    def test_the_encoded_payloads_are_invisible_to_a_plain_text_scan(self):
        # Otherwise the positive controls would pass without any decoding.
        for enc, payload in M.ENCODED_PAYLOADS.items():
            with self.subTest(encoding=enc):
                self.assertEqual(M._matches(f"User input. Note: {payload}"), [])

    def test_layered_encodings_are_read(self):
        homoglyph_in_base64 = M.base64.b64encode(
            M.ENCODED_PAYLOADS["homoglyph"].encode()).decode()
        tool = M._tool_with_note("layered", homoglyph_in_base64)
        self.assertTrue(_encodings(tool), M.scan_tool_fields(tool))

    def test_coverage_reports_complete(self):
        self.assertEqual(M.encoding_detector_coverage(),
                         {"missed": [], "false_positives": []})


class TestDetectorNegativeControls(unittest.TestCase):
    def test_no_benign_encoded_string_is_flagged(self):
        for name, text in M.BENIGN_ENCODED.items():
            with self.subTest(control=name):
                self.assertEqual(M.scan_tool_fields(M._tool_with_note(name, text)), [])

    def test_the_negative_controls_exercise_the_decoders(self):
        # A negative control no decoder touches proves nothing about false
        # positives. Every encoding must see at least one benign input.
        exercised = set()
        for text in M.BENIGN_ENCODED.values():
            exercised.update(name for name, _ in M.decoded_views(text))
        self.assertLessEqual(set(M.ENCODING_DECODERS), exercised)

    def test_clean_fixture_tools_stay_clean(self):
        for tool in M.CLEAN_TOOLS:
            with self.subTest(tool=tool["name"]):
                self.assertEqual(M.scan_tool_fields(tool), [])

    def test_plain_findings_carry_no_encoding(self):
        for tool in M.POISONED_TOOLS:
            findings = M.scan_tool_fields(tool)
            self.assertTrue(findings)
            self.assertFalse([f for f in findings if "encodings" in f], findings)


# ---------------------------------------------------------------------------
# CVE-006 as a target differential
# ---------------------------------------------------------------------------

def _stub(status: int, body):
    raw = (json.dumps(body) if body is not None else "not found").encode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(n)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = do_POST

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever,
                     kwargs={"poll_interval": 0.01}, daemon=True).start()
    return httpd


@contextlib.contextmanager
def _serving(status: int, body):
    httpd = _stub(status, body)
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _tools(tools):
    return {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}


def _closed_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def _cve006(url=None, **kw):
    suite = M.MCPToolPoisoningTests(url, **kw)
    with contextlib.redirect_stdout(io.StringIO()):
        suite.run_all(categories=["encoding"])
    (row,) = suite.results
    assert row.test_id == "CVE-006", row
    return row


class TestCve006IsATargetDifferential(unittest.TestCase):
    def test_closed_port_is_inconclusive(self):
        self.assertEqual(row_outcome(_cve006(_closed_url())), "INCONCLUSIVE")

    def test_404_is_inconclusive(self):
        with _serving(404, None) as url:
            self.assertEqual(row_outcome(_cve006(url)), "INCONCLUSIVE")

    def test_an_empty_tool_list_is_inconclusive(self):
        with _serving(200, _tools([])) as url:
            self.assertEqual(row_outcome(_cve006(url)), "INCONCLUSIVE")

    def test_registry_only_mode_has_no_tools_and_is_inconclusive(self):
        row = _cve006(None, registry_url="http://127.0.0.1:9")
        self.assertEqual(row_outcome(row), "INCONCLUSIVE")

    def test_encoded_poisoned_tools_fail(self):
        with _serving(200, _tools(M.encoded_fixture_tools())) as url:
            row = _cve006(url)
        self.assertEqual(row_outcome(row), "FAIL", row.details)
        found = {e for h in row.response_received["encoded_poisoning"]
                 for e in h["encodings"]}
        self.assertEqual(found, set(M.ENCODED_PAYLOADS))

    def test_clean_tools_pass(self):
        with _serving(200, _tools(M.CLEAN_TOOLS)) as url:
            row = _cve006(url)
        self.assertEqual(row_outcome(row), "PASS", row.details)

    def test_plain_poisoning_is_not_cve_006s_finding(self):
        # CVE-001 owns plain-text poisoning; CVE-006 must not double-count it.
        with _serving(200, _tools(M.POISONED_TOOLS)) as url:
            row = _cve006(url)
        self.assertEqual(row_outcome(row), "PASS", row.details)

    def test_the_verdict_changes_with_the_target(self):
        outcomes = set()
        for tools in (M.CLEAN_TOOLS, M.encoded_fixture_tools()):
            with _serving(200, _tools(tools)) as url:
                outcomes.add(row_outcome(_cve006(url)))
        self.assertEqual(outcomes, {"PASS", "FAIL"})

    def test_it_is_not_a_local_verdict(self):
        with _serving(200, _tools(M.CLEAN_TOOLS)) as url:
            self.assertFalse(_cve006(url).locally_decided)

    def test_simulate_scans_the_encoded_fixture_server_and_fails(self):
        row = _cve006(None, simulate=True)
        self.assertEqual(row_outcome(row), "FAIL", row.details)


class TestDetectorGapIsAPrecondition(unittest.TestCase):
    GAP = {"missed": ["rtl_override"], "false_positives": []}

    def test_a_clean_scan_with_a_detector_gap_is_inconclusive_not_pass(self):
        with mock.patch.object(M, "encoding_detector_coverage", return_value=self.GAP), \
                _serving(200, _tools(M.CLEAN_TOOLS)) as url:
            row = _cve006(url)
        self.assertEqual(row_outcome(row), "INCONCLUSIVE", row.details)

    def test_a_finding_with_a_detector_gap_still_fails(self):
        with mock.patch.object(M, "encoding_detector_coverage", return_value=self.GAP), \
                _serving(200, _tools(M.encoded_fixture_tools())) as url:
            row = _cve006(url)
        self.assertEqual(row_outcome(row), "FAIL", row.details)


if __name__ == "__main__":
    unittest.main()
