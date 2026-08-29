"""An unreachable MCP target must not exit 0 with an empty, error-free report.

Found by an external clean-room execution review, 2026-08-28, against v4.15.0,
the published PyPI wheel, and main. All three behaved the same way:

    agent-security test mcp --transport http --url <closed port> --json --report r.json
    -> exit 0
    -> {"summary": {"total": 0, "passed": 0, "failed": 0}, "results": []}
    -> the --report FILE dropped the connection error that stdout carried

Three separate things had to line up for that to be reachable, which is why it
survived: `build_report` had no field distinguishing "ran nothing" from "ran
cleanly"; `generate_report` did not take the `error` argument its stdout
counterpart was already being passed; and the exit code read
`1 if failed > 0 else 0`, where an empty result list makes `failed` zero.

A CI job reading the exit status, or reading only the generated report, would
treat "no test ever ran" as a pass. That is the harness's own documented rule
turned on itself: absence of a detected failure is not evidence a control held.

Note what the fix does NOT do. It does not synthesise one failed result per test
that would have run. "32 tests failed" is a different and false statement; the
accurate one is "not executed", carried as an explicit status with a nonzero exit
for automation.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.mcp_harness import (
    MCPTestResult,
    build_report,
    generate_report,
)

# Nothing listens on port 9 (discard). Same target the serviced-guard suite uses.
CLOSED_PORT_URL = "http://127.0.0.1:9"


def _passing_result() -> MCPTestResult:
    """Built from the dataclass rather than a hand-written field list.

    The first version of this helper guessed `attack_category` and broke on a
    field named `category`. Introspecting is the same fix `_build` in
    test_serviced_guard.py already carries, for the same reason.
    """
    from dataclasses import MISSING, fields

    kw = {"passed": True}
    for f in fields(MCPTestResult):
        if f.name in kw or f.default is not MISSING or f.default_factory is not MISSING:
            continue
        kw[f.name] = True if f.type in ("bool", bool) else "fixture"
    return MCPTestResult(**kw)


class TestBuildReportStatus(unittest.TestCase):
    """The unit half: a report has to say which of the two things happened."""

    def test_empty_with_error_is_inconclusive_and_keeps_the_error(self):
        report = build_report([], error="Initialize failed: Connection refused")
        self.assertEqual(report["status"], "inconclusive")
        self.assertIn("error", report)
        self.assertIn("Connection refused", report["error"])

    def test_empty_without_error_is_still_inconclusive(self):
        """Zero tests is never a completed evaluation, however it came about.

        The defect needed only an empty result list; the error was a second,
        separate signal that the file happened to be dropping. Keying the status
        on the error alone would leave every other zero-test path reading as a
        clean run.
        """
        self.assertEqual(build_report([])["status"], "inconclusive")

    def test_a_real_result_set_is_completed(self):
        """The guard must be able to pass, or it is not a guard."""
        report = build_report([_passing_result()])
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["summary"], {"total": 1, "passed": 1, "failed": 0})
        self.assertNotIn("error", report)

    def test_generate_report_writes_the_error_to_the_file(self):
        """The written file is the surface CI reads, and it was the one dropping it."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "report.json"
            generate_report([], str(path), error="Initialize failed: Connection refused")
            written = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(written["status"], "inconclusive")
        self.assertIn("Connection refused", written.get("error", ""))


class TestUnreachableTargetExitStatus(unittest.TestCase):
    """The subprocess half: the exit code is what automation actually branches on."""

    def test_closed_port_exits_nonzero_with_an_inconclusive_report(self):
        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "report.json"
            proc = subprocess.run(
                [sys.executable, "-m", "protocol_tests.mcp_harness",
                 "--transport", "http", "--url", CLOSED_PORT_URL,
                 "--json", "--report", str(report_path)],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=False,
            )

            self.assertNotEqual(
                proc.returncode, 0,
                "an unreachable target exited 0. A CI job branching on the exit status "
                "would read 'no test ever ran' as a pass.")

            self.assertTrue(report_path.is_file(), "--report wrote no file")
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(
            report.get("status"), "inconclusive",
            f"report file must carry an explicit inconclusive status, got "
            f"{report.get('status')!r} with summary {report.get('summary')!r}")
        self.assertTrue(
            report.get("error"),
            "the report file dropped the connection error that stdout carried")
        self.assertEqual(
            report.get("results"), [],
            "no results should be synthesised; 'not executed' is the accurate "
            "statement, not 'every test failed'")


if __name__ == "__main__":
    unittest.main()
