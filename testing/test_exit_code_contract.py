"""One exit-status contract for every harness entry point.

Owner decision 2026-09-24 (ASH pole-pilot follow-up, section 4):

    0  every result PASSED
    1  at least one genuine FAIL
    2  no FAIL, but at least one result INCONCLUSIVE or not executed, or no
       result at all ("nothing established")

Before this, most harness mains ended ``sys.exit(1 if failed > 0 else 0)`` with
``failed = sum(1 for r in results if not r.passed)``. An INCONCLUSIVE row also
has ``passed=False``, so exit 1 conflated a failed control with "could not
tell". Five payment modules went the other way (0 over a wholly INCONCLUSIVE
run) and mcp_harness exited 1 over one. The rule now lives in one function,
`protocol_tests.http_helpers.exit_code`, and this file pins:

* the truth table of that function;
* that no harness computes an exit status from results any other way (derived
  from source, not from a list), with the declared exceptions named;
* end to end, as subprocesses against stdlib stubs: A2A and MCP against a
  closed port, 404-everywhere, 403-everywhere and a permissive target, and a
  self-test harness whose every row passes (the positive control for 0);
* that a failed MCP bootstrap emits one NOT_EXECUTED row per registered test,
  derived from the same registry `run_all` executes, and exits 2.
"""

from __future__ import annotations

import ast
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.harness_base import exit_status  # noqa: E402
from protocol_tests.http_helpers import (  # noqa: E402
    EXIT_FAILED,
    EXIT_INCONCLUSIVE,
    EXIT_PASSED,
    INCONCLUSIVE_PREFIX,
    exit_code,
)

ENV = dict(os.environ, AGENT_SECURITY_TELEMETRY="off")


def _row(passed: bool, inconclusive: bool = False, **extra) -> dict:
    details = f"{INCONCLUSIVE_PREFIX}not serviced" if inconclusive else "observed"
    return {"test_id": "T-001", "passed": passed, "details": details,
            "not_evaluated": inconclusive, **extra}


PASS = _row(True)
FAIL = _row(False)
INCONCLUSIVE = _row(False, inconclusive=True)


class ExitCodeTruthTable(unittest.TestCase):
    def test_the_codes_are_the_documented_numbers(self):
        self.assertEqual((EXIT_PASSED, EXIT_FAILED, EXIT_INCONCLUSIVE), (0, 1, 2))

    def test_all_pass_is_zero(self):
        self.assertEqual(exit_code([PASS, PASS]), 0)

    def test_any_fail_is_one(self):
        self.assertEqual(exit_code([PASS, FAIL]), 1)
        self.assertEqual(exit_code([FAIL]), 1)

    def test_only_inconclusive_is_two(self):
        self.assertEqual(exit_code([INCONCLUSIVE]), 2)
        self.assertEqual(exit_code([PASS, INCONCLUSIVE]), 2)

    def test_fail_beats_inconclusive(self):
        self.assertEqual(exit_code([FAIL, INCONCLUSIVE]), 1)
        self.assertEqual(exit_code([INCONCLUSIVE, PASS, FAIL]), 1)

    def test_empty_is_two_because_nothing_was_established(self):
        """Zero failures out of zero tests is not a green run."""
        self.assertEqual(exit_code([]), 2)

    def test_a_run_level_error_raises_a_clean_run_to_two_and_never_lowers_a_fail(self):
        self.assertEqual(exit_code([PASS], run_error="connection refused"), 2)
        self.assertEqual(exit_code([FAIL], run_error="connection refused"), 1)
        self.assertEqual(exit_code([PASS], run_error=None), 0)

    def test_every_inconclusive_marker_the_package_uses_is_two_not_one(self):
        """The prefix alone, the field alone, and identity's `informational`."""
        prefix_only = {"passed": False, "details": f"{INCONCLUSIVE_PREFIX}x"}
        field_only = {"passed": False, "details": "x", "not_evaluated": True}
        informational = {"passed": False, "details": "x", "informational": True}
        for row in (prefix_only, field_only, informational):
            with self.subTest(row=row):
                self.assertEqual(exit_code([row]), 2)

    def test_objects_and_dicts_agree(self):
        from protocol_tests.harness_base import HarnessResult

        def obj(passed, details):
            return HarnessResult(test_id="T-1", name="n", owasp_asi="", severity="",
                                 passed=passed, details=details)
        self.assertEqual(exit_code([obj(True, "ok")]), 0)
        self.assertEqual(exit_code([obj(False, "held? no")]), 1)
        self.assertEqual(exit_code([obj(False, f"{INCONCLUSIVE_PREFIX}x")]), 2)

    def test_exit_status_over_a_report_is_the_same_function(self):
        for rows, want in (([PASS], 0), ([FAIL], 1), ([INCONCLUSIVE], 2), ([], 2)):
            with self.subTest(want=want):
                self.assertEqual(exit_status({"results": rows, "summary": {}}), want)


# ---------------------------------------------------------------------------
# Source: no harness computes an exit status from results any other way
# ---------------------------------------------------------------------------

#: Result-derived exits that deliberately do not use the helper, with reasons.
#: May shrink; must not grow without a reason here.
DECLARED_OTHER_EXITS = {
    # `--trials N` statistical paths. They count a trial pass or not-pass and
    # never track INCONCLUSIVE per trial, so the state cannot be expressed; they
    # stay 0/1 (`tr.pass_rate < 1.0`).
    ("l402_harness.py", "_run_statistical"),
    ("x402_harness.py", "_run_statistical"),
}

#: Registered harnesses whose `main` sets no exit status from its results at
#: all (it exits 0 whatever the rows say). A pre-existing gap recorded
#: 2026-09-24, not changed by the exit-code contract because it would turn a
#: run that always exited 0 into one that exits 1: a separate decision. This
#: set may shrink and must not grow.
NO_RESULT_EXIT_STATUS = {
    "protocol_tests.receipt_claim_harness",
    "protocol_tests.cloud_agent_harness",
    "protocol_tests.autogen_harness",
    "protocol_tests.crewai_cve_harness",
    "protocol_tests.mcp_tool_poisoning_harness",
    "protocol_tests.capability_residue_harness",
}

_RESULT_WORDS = ("passed", "failed", "blocked", "results", "not_evaluated", "pass_rate")


def _result_derived_exits(directory: Path | None = None) -> set[tuple[str, str]]:
    """(file, function) of every exit whose value is computed from verdict words.

    Scans `sys.exit(<expr>)` and `return <IfExp>` inside a `main`: the forms the
    old convention took. An expression that calls `exit_code`/`exit_status` is
    the shared helper and is not reported.
    """
    found = set()
    for path in sorted((directory or REPO_ROOT / "protocol_tests").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                expr = None
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "exit" and node.args):
                    expr = node.args[0]
                elif (fn.name == "main" and isinstance(node, ast.Return)
                        and isinstance(node.value, ast.IfExp)):
                    expr = node.value
                if expr is None or isinstance(expr, ast.Constant):
                    continue
                src = ast.unparse(expr)
                if "exit_code(" in src or "exit_status(" in src:
                    continue
                if any(w in src for w in _RESULT_WORDS):
                    found.add((path.name, fn.name))
    return found


class NoParallelExitConvention(unittest.TestCase):
    def test_every_result_derived_exit_uses_the_shared_helper(self):
        measured = _result_derived_exits()
        self.assertEqual(
            measured, DECLARED_OTHER_EXITS,
            "an exit status computed from results outside http_helpers.exit_code "
            "(or a declared exception that no longer exists). Use "
            "`sys.exit(exit_code(results))` so the 0/1/2 contract cannot drift.")

    def test_the_scan_can_see_the_old_convention(self):
        """Positive control: the detector must fire on the form it replaced."""
        tree = ast.parse("def main():\n    failed = 1\n    sys.exit(1 if failed > 0 else 0)\n")
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        self.assertTrue(any(w in ast.unparse(node.args[0]) for w in _RESULT_WORDS))

    def test_the_no_exit_status_set_is_measured_not_asserted(self):
        from protocol_tests.cli import HARNESSES
        modules = sorted({info["module"] for info in HARNESSES.values()})
        silent = set()
        for mod in modules:
            src = (REPO_ROOT / (mod.replace(".", "/") + ".py")).read_text(encoding="utf-8")
            tree = ast.parse(src)
            mains = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"]
            if not mains:
                silent.add(mod)
                continue
            body = ast.unparse(mains[0])
            if "exit_code(" not in body and "exit_status(" not in body \
                    and "_run_statistical" not in body:
                silent.add(mod)
        self.assertEqual(silent, NO_RESULT_EXIT_STATUS)


# ---------------------------------------------------------------------------
# End to end, against stdlib stubs
# ---------------------------------------------------------------------------

def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Stub(BaseHTTPRequestHandler):
    mode = "not_found"

    def log_message(self, *a):  # noqa: D401 - silence
        pass

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.mode == "permissive":
            try:
                req = json.loads(raw or b"{}")
            except ValueError:
                req = {}
            rid = req.get("id", 1) if isinstance(req, dict) else 1
            body = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}}).encode()
            status, ctype = 200, "application/json"
        elif self.mode == "forbidden":
            body, status, ctype = b"Forbidden", 403, "text/plain"
        else:
            body, status, ctype = b"Not Found", 404, "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = _answer


class _Server:
    def __init__(self, mode: str):
        handler = type(f"Stub_{mode}", (_Stub,), {"mode": mode})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _run_module(module: str, *args: str, timeout: int = 300):
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "report.json"
        proc = subprocess.run(
            [sys.executable, "-m", module, *args, "--report", str(report)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout,
            check=False, env=ENV)
        doc = json.loads(report.read_text(encoding="utf-8")) if report.exists() else None
    return proc, doc


def _mcp_registry_ids() -> list[str]:
    from protocol_tests.mcp_harness import MCPSecurityTests, _test_identity
    suite = MCPSecurityTests(None, json_output=True)
    return [_test_identity(fn)[0]
            for tests in suite.test_registry().values() for fn in tests]


class McpBootstrapFailureIsNotExecuted(unittest.TestCase):
    """403, 404 and a closed port all stop MCP at `initialize()`."""

    @classmethod
    def setUpClass(cls):
        cls.expected_ids = _mcp_registry_ids()
        cls.runs = {}
        cls.runs["closed_port"] = _run_module(
            "protocol_tests.mcp_harness", "--transport", "http",
            "--url", f"http://127.0.0.1:{_closed_port()}/mcp")
        for mode in ("not_found", "forbidden"):
            with _Server(mode) as srv:
                cls.runs[mode] = _run_module(
                    "protocol_tests.mcp_harness", "--transport", "http",
                    "--url", f"{srv.url}/mcp")

    def test_the_registry_is_the_whole_suite(self):
        """Derived, then sanity-checked: one ID per test, no duplicates."""
        self.assertGreaterEqual(len(self.expected_ids), 30)
        self.assertEqual(len(self.expected_ids), len(set(self.expected_ids)))
        self.assertTrue(all(i.startswith("MCP-") for i in self.expected_ids))

    def test_one_not_executed_row_per_registered_test_and_exit_two(self):
        for pole, (proc, doc) in self.runs.items():
            with self.subTest(pole=pole):
                self.assertEqual(proc.returncode, 2, proc.stderr[-600:])
                self.assertIsNotNone(doc, "--report wrote no file")
                ids = [r["test_id"] for r in doc["results"]]
                self.assertEqual(ids, self.expected_ids)
                for r in doc["results"]:
                    self.assertFalse(r["passed"])
                    self.assertTrue(r["not_evaluated"])
                    self.assertTrue(r["details"].startswith(
                        f"{INCONCLUSIVE_PREFIX}NOT_EXECUTED: MCP bootstrap failed"))
                self.assertEqual(doc["status"], "inconclusive")
                self.assertTrue(doc.get("error"))

    def test_the_rows_name_the_bootstrap_failure(self):
        _, doc = self.runs["forbidden"]
        self.assertIn("403", doc["results"][0]["details"])
        _, doc = self.runs["not_found"]
        self.assertIn("404", doc["results"][0]["details"])

    def test_no_not_executed_row_is_counted_as_a_pass_or_a_fail(self):
        for pole, (_, doc) in self.runs.items():
            with self.subTest(pole=pole):
                s = doc["summary"]
                self.assertEqual((s["passed"], s["failed"]), (0, 0))
                self.assertEqual(s["inconclusive"], len(self.expected_ids))
                self.assertEqual(s["serviced"], 0)
                self.assertIsNone(s["pass_rate"])

    def test_a_category_filter_emits_only_that_categorys_tests(self):
        from protocol_tests.mcp_harness import MCPSecurityTests, _test_identity
        want = [_test_identity(fn)[0] for fn in
                MCPSecurityTests(None, json_output=True).test_registry(["ssrf"])["ssrf"]]
        proc, doc = _run_module(
            "protocol_tests.mcp_harness", "--transport", "http",
            "--url", f"http://127.0.0.1:{_closed_port()}/mcp", "--categories", "ssrf")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual([r["test_id"] for r in doc["results"]], want)


class McpPermissiveTargetRuns(unittest.TestCase):
    def test_a_target_that_answers_the_handshake_runs_the_tests(self):
        with _Server("permissive") as srv:
            proc, doc = _run_module("protocol_tests.mcp_harness", "--transport",
                                    "http", "--url", f"{srv.url}/mcp")
        self.assertFalse(any("NOT_EXECUTED" in r["details"] for r in doc["results"]))
        self.assertGreater(doc["summary"]["serviced"], 0)
        self.assertEqual(proc.returncode, exit_code(doc["results"]))
        self.assertIn(proc.returncode, (1, 2))


class A2AExitCodes(unittest.TestCase):
    """A2A's verdict logic is under separate review; these pin the exit status
    against whatever the rows say, plus the two poles whose rows are settled."""

    def test_closed_port_is_inconclusive_so_exit_two(self):
        proc, doc = _run_module("protocol_tests.a2a_harness",
                                "--url", f"http://127.0.0.1:{_closed_port()}")
        self.assertTrue(doc["results"])
        self.assertTrue(all(not r["passed"] for r in doc["results"]))
        self.assertEqual(exit_code(doc["results"]), 2)
        self.assertEqual(proc.returncode, 2, proc.stderr[-600:])

    def test_every_stub_pole_exits_with_what_its_rows_say(self):
        for mode in ("not_found", "forbidden", "permissive"):
            with self.subTest(pole=mode), _Server(mode) as srv:
                proc, doc = _run_module("protocol_tests.a2a_harness", "--url", srv.url)
                self.assertTrue(doc["results"])
                self.assertEqual(proc.returncode, exit_code(doc["results"]),
                                 proc.stderr[-600:])
                self.assertNotEqual(proc.returncode, 0)

    def test_a_missing_agent_card_is_a_genuine_fail_so_exit_one(self):
        """A2A-001 FAILs on a 404 Agent Card (contract-consistent per the pilot)."""
        with _Server("not_found") as srv:
            proc, doc = _run_module("protocol_tests.a2a_harness", "--url", srv.url,
                                    "--categories", "agent_card")
        rows = {r["test_id"]: r for r in doc["results"]}
        self.assertIn("A2A-001", rows)
        self.assertFalse(rows["A2A-001"]["passed"])
        self.assertFalse(rows["A2A-001"].get("not_evaluated"))
        self.assertEqual(proc.returncode, 1, proc.stderr[-600:])


class PositiveControlForZero(unittest.TestCase):
    def test_a_run_whose_every_row_passes_exits_zero(self):
        """The contract must be able to say 0, or it is not a contract."""
        proc, doc = _run_module("protocol_tests.hidden_instruction_harness", "--self-test")
        self.assertTrue(doc["results"])
        self.assertTrue(all(r["passed"] for r in doc["results"]))
        self.assertEqual(proc.returncode, 0, proc.stdout[-600:])


class CliPropagatesAndExplains(unittest.TestCase):
    def test_the_cli_exits_two_and_says_what_two_means(self):
        proc = subprocess.run(
            [sys.executable, "-m", "protocol_tests.cli", "test", "mcp",
             "--url", f"http://127.0.0.1:{_closed_port()}/mcp", "--json"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
            check=False, env=ENV)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("INCONCLUSIVE or not executed", proc.stderr)

    def test_simulate_exits_two(self):
        proc = subprocess.run(
            [sys.executable, "-m", "protocol_tests.cli", "test", "a2a", "--simulate"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
            check=False, env=ENV)
        self.assertEqual(proc.returncode, 2, proc.stderr[-400:])

    def test_help_documents_the_contract(self):
        proc = subprocess.run(
            [sys.executable, "-m", "protocol_tests.cli", "--help"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
            check=False, env=ENV)
        self.assertIn("Exit status of `agent-security test`", proc.stdout)
        for line in ("0  every result PASSED", "1  at least one genuine FAIL"):
            self.assertIn(line, proc.stdout)


if __name__ == "__main__":
    unittest.main()
