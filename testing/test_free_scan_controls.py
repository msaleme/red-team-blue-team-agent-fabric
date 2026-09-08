"""Known-good and deliberately-broken controls for the public free-scan wrapper.

`scripts/free_scan.py::run_free_scan` called five `MCPSecurityTests` methods
that record their result on the suite and return None, dereferenced
`.status` on that None, caught its own AttributeError and published it as
five failed tests, grade F and "The scan detected 5 issue(s)" -- against
the shipped mock and against a closed port alike. `mcp_server/server.py`
exposes the same function as the `scan_mcp_server` tool (R4-06, fourth
external review, 2026-09-08).

The underlying methods had tests. The wrapper had none, so a wrapper error
masqueraded as a security result. These are the two controls every public
wrapper needs: a target whose shape is known (the shipped mock: MCP-001 and
MCP-008 FAIL, the rest PASS) and a target that cannot be evaluated (a closed
port: every row INCONCLUSIVE, no grade, no detected issue).
"""

from __future__ import annotations

import contextlib
import io
import os
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts import free_scan  # noqa: E402

CLOSED_PORT_URL = "http://127.0.0.1:9/mcp"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.05)
    return False


class _MockServer(unittest.TestCase):
    """The shipped `protocol_tests.mock_mcp_server` on a free loopback port."""

    proc = None
    url = ""

    @classmethod
    def setUpClass(cls):
        port = _free_port()
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "protocol_tests.mock_mcp_server",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=REPO_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=dict(os.environ, AGENT_SECURITY_TELEMETRY="off"),
        )
        if not _wait_for(port):
            cls._stop()
            raise RuntimeError(f"mock MCP server did not start on {port}")
        cls.url = f"http://127.0.0.1:{port}/mcp"

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    @classmethod
    def _stop(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()

    @staticmethod
    def _scan(url: str) -> tuple[dict, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            report = free_scan.run_free_scan(url)
        return report, out.getvalue()


class TestKnownGoodControl(_MockServer):
    """The shipped mock has a known shape; the wrapper must report exactly it."""

    def test_the_mock_is_graded_by_what_it_did(self):
        report, stdout = self._scan(self.url)
        by_id = {r["id"]: r for r in report["results"]}
        self.assertEqual(sorted(by_id), ["MCP-001", "MCP-003", "MCP-004", "MCP-008", "MCP-010"])
        # The mock ships a tool whose description exfiltrates, and handles
        # 3 of 7 malformed messages: both are real FAILs of the target.
        self.assertEqual(by_id["MCP-001"]["status"], "FAIL", by_id["MCP-001"])
        self.assertEqual(by_id["MCP-008"]["status"], "FAIL", by_id["MCP-008"])
        for tid in ("MCP-003", "MCP-004", "MCP-010"):
            self.assertEqual(by_id[tid]["status"], "PASS", by_id[tid])
        for row in report["results"]:
            self.assertNotIn("NoneType", row["detail"])
            self.assertNotEqual(row["status"], "ERROR")
        self.assertEqual(report["tests_passed"], 3)
        self.assertEqual(report["tests_failed"], 2)
        self.assertEqual(report["tests_inconclusive"], 0)
        self.assertEqual(report["tests_evaluated"], 5)
        self.assertEqual(report["grade"], "C")
        self.assertEqual(report["grade_status"], "established")
        self.assertTrue(report["recommendation"].startswith("The scan detected 2 issue(s)"),
                        report["recommendation"])
        self.assertEqual(stdout, "", "the wrapper must not write console lines to stdout")


class TestDeliberatelyBrokenControl(unittest.TestCase):
    """A closed port cannot be evaluated: no grade, no detected issue."""

    def test_closed_port_is_inconclusive_with_no_grade(self):
        report, _ = _MockServer._scan(CLOSED_PORT_URL)
        self.assertEqual(len(report["results"]), 5)
        for row in report["results"]:
            self.assertEqual(row["status"], "INCONCLUSIVE", row)
            self.assertIn(free_scan.COULD_NOT_EVALUATE, row["detail"])
            self.assertNotIn("NoneType", row["detail"])
        self.assertEqual(report["tests_passed"], 0)
        self.assertEqual(report["tests_failed"], 0)
        self.assertEqual(report["tests_inconclusive"], 5)
        self.assertEqual(report["tests_evaluated"], 0)
        self.assertIsNone(report["grade"])
        self.assertEqual(report["grade_status"], free_scan.GRADE_NOT_ESTABLISHED)
        self.assertIn("could not evaluate", report["recommendation"])
        self.assertNotIn("detected", report["recommendation"])

    def test_markdown_renders_the_state_without_inventing_an_error(self):
        report, _ = _MockServer._scan(CLOSED_PORT_URL)
        md = free_scan.format_markdown(report)
        self.assertIn("**Grade:** not established", md)
        self.assertIn("| INCONCLUSIVE |", md)
        self.assertNotIn("| ERROR |", md)


class TestWrapperFaultsAreNotSecurityResults(_MockServer):
    """The R4-06 mechanism: the wrapper's own failure must never grade the target."""

    def test_a_method_that_raises_is_inconclusive_not_a_detected_issue(self):
        def boom(self):
            raise RuntimeError("synthetic wrapper fault")
        with mock.patch.object(free_scan.MCPSecurityTests, "test_mcp_malformed_jsonrpc", boom):
            report, _ = self._scan(self.url)
        by_id = {r["id"]: r for r in report["results"]}
        self.assertEqual(by_id["MCP-008"]["status"], "INCONCLUSIVE")
        self.assertIn(free_scan.COULD_NOT_EVALUATE, by_id["MCP-008"]["detail"])
        self.assertIn("synthetic wrapper fault", by_id["MCP-008"]["detail"])
        # The other four were still evaluated against the real mock.
        self.assertEqual(by_id["MCP-001"]["status"], "FAIL")
        self.assertEqual(report["tests_failed"], 1)
        self.assertEqual(report["tests_inconclusive"], 1)
        self.assertIsNone(report["grade"])
        self.assertIn("could not evaluate 1 of 5", report["recommendation"])

    def test_a_method_that_records_nothing_is_inconclusive(self):
        with mock.patch.object(free_scan.MCPSecurityTests, "test_mcp_tool_argument_injection",
                               lambda self: None):
            report, _ = self._scan(self.url)
        by_id = {r["id"]: r for r in report["results"]}
        self.assertEqual(by_id["MCP-010"]["status"], "INCONCLUSIVE")
        self.assertIn("recorded no result", by_id["MCP-010"]["detail"])
        self.assertIsNone(report["grade"])

    def test_the_wrapper_reads_the_recorded_result_not_a_return_value(self):
        """Every selected method returns None by contract; the wrapper must not care."""
        for test_def in free_scan.FREE_SCAN_TESTS:
            self.assertTrue(hasattr(free_scan.MCPSecurityTests, test_def["method"]), test_def)
        report, _ = self._scan(self.url)
        self.assertEqual(report["tests_inconclusive"], 0, report["results"])


class TestGradeIsAClaimOverEvaluatedTests(unittest.TestCase):
    def test_zero_evaluated_is_no_grade_not_an_f(self):
        self.assertIsNone(free_scan.compute_grade(0, 0))

    def test_recommendation_never_calls_an_unevaluated_row_an_issue(self):
        rows = [{"id": "MCP-001", "name": "A", "status": "INCONCLUSIVE", "detail": ""},
                {"id": "MCP-003", "name": "B", "status": "PASS", "detail": ""}]
        text = free_scan.build_recommendation(rows, None)
        self.assertIn("could not evaluate 1 of 2", text)
        self.assertNotIn("detected", text)


if __name__ == "__main__":
    unittest.main()
