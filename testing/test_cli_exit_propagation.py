"""The CLI dispatcher exits with the code the harness asked for.

`protocol_tests/cli.py` caught the child's SystemExit into `_harness_exit`,
finished the HTML and telemetry work, and then called `sys.exit(0)`
unconditionally. Its own comment promised to "exit with the code the harness
asked for". So

    agent-security test skill-security --url http://127.0.0.1:9 --report out.json

printed argparse's "unrecognized arguments" from the child, wrote no report,
and exited 0 (R4-08, fourth external review, 2026-09-08). Invalid syntax
must not become a successful run, and a requested file that never appeared
must not be silent.

All three shapes are exercised through the public entry point.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLOSED = "http://127.0.0.1:9/mcp"


def _run(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "protocol_tests.cli", *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout, check=False,
        env=dict(os.environ, AGENT_SECURITY_TELEMETRY="off"),
    )


class TestUsageErrorsAreNotSuccess(unittest.TestCase):
    def test_unsupported_flag_exits_with_the_childs_code_and_names_the_missing_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            r = _run("test", "skill-security", "--url", CLOSED, "--report", out)
            self.assertEqual(r.returncode, 2,
                             f"argparse exits 2 in the child; the parent exited {r.returncode}\n{r.stderr[-400:]}")
            self.assertIn("unrecognized arguments", r.stderr)
            self.assertIn("no file was written", r.stderr)
            self.assertFalse(os.path.exists(out))


class TestAFailingChildKeepsItsCode(unittest.TestCase):
    def test_the_cli_exit_equals_the_modules_own_exit(self):
        direct = subprocess.run(
            [sys.executable, "-m", "protocol_tests.mcp_harness",
             "--transport", "http", "--url", CLOSED, "--json"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=180, check=False,
            env=dict(os.environ, AGENT_SECURITY_TELEMETRY="off"),
        )
        via_cli = _run("test", "mcp", "--url", CLOSED, "--json")
        self.assertNotEqual(direct.returncode, 0, "the module itself must refuse a closed port")
        self.assertEqual(via_cli.returncode, direct.returncode,
                         f"module exited {direct.returncode}, CLI exited {via_cli.returncode}")

    def test_html_is_still_written_and_the_failure_is_still_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "live.html")
            r = _run("test", "mcp", "--url", CLOSED, "--html", out)
            self.assertTrue(os.path.exists(out), r.stderr[-400:])
            self.assertNotEqual(r.returncode, 0)


class TestAGoodRunExitsZero(unittest.TestCase):
    def test_a_local_fixture_harness_exits_zero(self):
        r = _run("test", "receipt-claim", "--json")
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertIn('"passed": true', r.stdout)

    def test_the_childs_own_help_exit_is_zero(self):
        r = _run("test", "skill-security", "--help")
        self.assertEqual(r.returncode, 0, r.stderr[-400:])


if __name__ == "__main__":
    unittest.main()
