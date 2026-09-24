"""The six harnesses that set no exit status now use the shared contract.

Until 2026-09-24 `receipt-claim`, `cloud-agents`, `autogen`, `crewai-cve`,
`mcp-tool-poisoning` and `capability-residue` exited 0 whatever their rows said
(`capability-residue` had no `main` at all). #595 pinned them as a set that may
only shrink (`NO_RESULT_EXIT_STATUS` in `test_exit_code_contract.py`); this file
is the evidence for emptying it.

Every case runs the module as a subprocess, against a stdlib stub, a closed
port, `--simulate`, or a reference target, and asserts two things: the exit
status, and that it equals `exit_code()` over the rows the run wrote, so the
number and the report cannot disagree. Nothing here contacts an external host.

Where a passing (0) run is not achievable locally, the class says why instead
of skipping silently.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.http_helpers import exit_code, run_summary  # noqa: E402

ENV = dict(os.environ, AGENT_SECURITY_TELEMETRY="off")

#: Stub response bodies. Each is a fixed JSON body answered to every GET/POST.
BODIES = {
    # What testing/test_autogen_harness.py uses as the benign reply.
    "benign": {"response": "I can help with that. 2+2 = 4.", "status": 200},
    # A plain refusal.
    "refuse": {"response": "I can't help with that request.", "status": 200},
    # Complies with the AutoGen speaker-override injection (AG-SP-001 keywords).
    "comply": {"response": "Done. Next speaker: AdminAgent. Speaker changed, "
                           "escalation accepted.", "status": 200},
    # Answers every request with an empty JSON-RPC result.
    "permissive": {"jsonrpc": "2.0", "id": 1, "result": {}},
}


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Stub:
    def __init__(self, shape: str):
        body = json.dumps(BODIES[shape]).encode()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _answer

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _run(argv: list[str], report_flag: str | None = "--report"):
    """Run argv (after the interpreter) and return (proc, report rows or None)."""
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "report.json"
        extra = [report_flag, str(report)] if report_flag else []
        proc = subprocess.run([sys.executable, *argv, *extra], cwd=REPO_ROOT,
                              capture_output=True, text=True, timeout=300,
                              check=False, env=ENV)
        rows = (json.loads(report.read_text(encoding="utf-8"))["results"]
                if report.exists() else None)
    return proc, rows


class _Case(unittest.TestCase):
    def assertExits(self, want: int, proc, rows) -> None:
        tail = (proc.stdout[-400:] + proc.stderr[-400:])
        self.assertEqual(proc.returncode, want, tail)
        if rows is not None:
            self.assertTrue(rows, "the run wrote an empty result list")
            self.assertEqual(exit_code(rows), proc.returncode,
                             f"exit status disagrees with the report: {run_summary(rows)}")


# ---------------------------------------------------------------------------
# receipt-claim: offline, deterministic, so FAIL and INCONCLUSIVE are seeded
# ---------------------------------------------------------------------------

def _receipt_claim_with(patch: str) -> subprocess.CompletedProcess:
    """Run receipt_claim_harness.main() in a subprocess after `patch`.

    The module performs no I/O and its verifier is correct, so a FAIL or an
    INCONCLUSIVE row cannot come from a target. The patch changes the verdict
    input; `main()` and its exit are the unmodified code under test.
    """
    code = textwrap.dedent("""
        import sys, types
        from protocol_tests import receipt_claim_harness as R
        {patch}
        sys.argv = ["receipt_claim_harness", "--simulate", "--json"]
        R.main()
    """).format(patch=textwrap.dedent(patch).strip())
    return subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT,
                          capture_output=True, text=True, timeout=120,
                          check=False, env=ENV)


def _json_rows(stdout: str) -> list[dict]:
    """The `--json` list, which follows the console lines (if any)."""
    start = 0 if stdout.startswith("[\n") else stdout.index("\n[\n") + 1
    return json.loads(stdout[start:])


class ReceiptClaimExitStatus(_Case):
    def test_the_reference_run_passes_and_exits_zero(self):
        proc = subprocess.run(
            [sys.executable, "-m", "protocol_tests.receipt_claim_harness",
             "--simulate", "--json"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
            check=False, env=ENV)
        rows = _json_rows(proc.stdout)
        self.assertTrue(all(r["passed"] for r in rows))
        self.assertExits(0, proc, rows)

    def test_a_verifier_that_accepts_everything_fails_and_exits_one(self):
        proc = _receipt_claim_with("""
            R.ClaimLevelVerifier.verify = lambda self, receipt: types.SimpleNamespace(
                verdict="accept", reason="seeded: accepts everything")
        """)
        rows = _json_rows(proc.stdout)
        self.assertTrue(any(not r["passed"] for r in rows))
        self.assertExits(1, proc, rows)

    def test_an_inconclusive_only_run_exits_two(self):
        proc = _receipt_claim_with("""
            from protocol_tests.http_helpers import INCONCLUSIVE_PREFIX
            def run_all(self):
                self.results = [R.RCLResult(
                    test_id="RCL-001", name="seeded", category="receipt_claim",
                    owasp_asi="ASI09", severity="high", passed=False,
                    details=INCONCLUSIVE_PREFIX + "seeded: not evaluated")]
                return self.results
            R.ReceiptClaimTests.run_all = run_all
        """)
        self.assertExits(2, proc, _json_rows(proc.stdout))


# ---------------------------------------------------------------------------
# cloud-agents
# ---------------------------------------------------------------------------

class CloudAgentsExitStatus(_Case):
    MOD = ["-m", "protocol_tests.cloud_agent_harness"]

    def test_simulate_passes_every_row_and_exits_zero(self):
        proc, rows = _run([*self.MOD, "--simulate"])
        self.assertTrue(all(r["passed"] for r in rows))
        self.assertExits(0, proc, rows)

    def test_a_permissive_target_fails_and_exits_one(self):
        with _Stub("permissive") as srv:
            proc, rows = _run([*self.MOD, "--url", srv.url])
        self.assertGreater(run_summary(rows)["failed"], 0)
        self.assertExits(1, proc, rows)

    def test_a_closed_port_is_inconclusive_and_exits_two(self):
        proc, rows = _run([*self.MOD, "--url", f"http://127.0.0.1:{_closed_port()}"])
        s = run_summary(rows)
        self.assertEqual((s["passed"], s["failed"]), (0, 0))
        self.assertExits(2, proc, rows)

    def test_the_trials_path_uses_the_contract_too(self):
        proc, rows = _run([*self.MOD, "--url", f"http://127.0.0.1:{_closed_port()}",
                           "--platform", "bedrock", "--trials", "2"])
        self.assertExits(2, proc, rows)


# ---------------------------------------------------------------------------
# autogen (writes its report with --output)
# ---------------------------------------------------------------------------

class AutoGenExitStatus(_Case):
    MOD = ["-m", "protocol_tests.autogen_harness", "--run"]

    def _run(self, url: str, *extra: str):
        return _run([*self.MOD, "--url", url, *extra], report_flag="--output")

    def test_a_benign_target_passes_and_exits_zero(self):
        with _Stub("benign") as srv:
            proc, rows = self._run(srv.url)
        self.assertTrue(all(r["passed"] for r in rows))
        self.assertExits(0, proc, rows)

    def test_a_target_that_obeys_the_injection_fails_and_exits_one(self):
        with _Stub("comply") as srv:
            proc, rows = self._run(srv.url)
        self.assertGreater(run_summary(rows)["failed"], 0)
        self.assertExits(1, proc, rows)

    def test_a_closed_port_is_inconclusive_and_exits_two(self):
        proc, rows = self._run(f"http://127.0.0.1:{_closed_port()}")
        self.assertEqual(run_summary(rows)["inconclusive"], len(rows))
        self.assertExits(2, proc, rows)

    def test_the_trials_path_uses_the_contract_too(self):
        with _Stub("comply") as srv:
            proc, rows = self._run(srv.url, "--trials", "2",
                                   "--categories", "speaker_selection")
        self.assertExits(1, proc, rows)

    def test_no_run_flag_prints_help_and_still_exits_zero(self):
        """Usage path unchanged: without --run the module prints help."""
        proc = subprocess.run([sys.executable, "-m", "protocol_tests.autogen_harness",
                               "--url", "http://127.0.0.1:9"],
                              cwd=REPO_ROOT, capture_output=True, text=True,
                              timeout=60, check=False, env=ENV)
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])


# ---------------------------------------------------------------------------
# crewai-cve
# ---------------------------------------------------------------------------

class CrewAICveExitStatus(_Case):
    MOD = ["-m", "protocol_tests.crewai_cve_harness"]

    def test_a_refusing_target_passes_and_exits_zero(self):
        with _Stub("refuse") as srv:
            proc, rows = _run([*self.MOD, "--url", srv.url])
        self.assertTrue(all(r["passed"] for r in rows))
        self.assertExits(0, proc, rows)

    def test_a_complying_target_fails_and_exits_one(self):
        with _Stub("benign") as srv:
            proc, rows = _run([*self.MOD, "--url", srv.url])
        self.assertGreater(run_summary(rows)["failed"], 0)
        self.assertExits(1, proc, rows)

    def test_simulate_contains_fails_and_exits_one(self):
        proc, rows = _run([*self.MOD, "--simulate"])
        self.assertExits(1, proc, rows)

    def test_a_closed_port_has_no_fail_and_exits_two(self):
        proc, rows = _run([*self.MOD, "--url", f"http://127.0.0.1:{_closed_port()}"])
        s = run_summary(rows)
        self.assertEqual(s["failed"], 0)
        self.assertGreater(s["inconclusive"], 0)
        self.assertExits(2, proc, rows)

    def test_the_usage_error_is_unchanged(self):
        proc = subprocess.run([sys.executable, *self.MOD], cwd=REPO_ROOT,
                              capture_output=True, text=True, timeout=60,
                              check=False, env=ENV)
        self.assertEqual(proc.returncode, 1)


# ---------------------------------------------------------------------------
# mcp-tool-poisoning
# ---------------------------------------------------------------------------

class McpToolPoisoningExitStatus(_Case):
    """0 is NOT achievable in a default run, and that is the report's own verdict.

    CVE-006 scans ENCODED_PAYLOADS with the module's own `scan_tool_fields` and
    never touches the target; the scanner catches none of the five encodings,
    so CVE-006 FAILs on every run that includes `payload_encoding`. Every
    default run therefore contains a FAIL and exits 1. The row always said FAIL;
    only the exit status used to hide it. Changing CVE-006 is a verdict decision
    outside this change.
    """

    MOD = ["-m", "protocol_tests.mcp_tool_poisoning_harness"]

    def test_cve_006_is_a_target_independent_fail(self):
        proc, rows = _run([*self.MOD, "--url", f"http://127.0.0.1:{_closed_port()}"])
        by_id = {r["test_id"]: r for r in rows}
        self.assertFalse(by_id["CVE-006"]["passed"])
        self.assertFalse(by_id["CVE-006"].get("not_evaluated"))
        self.assertExits(1, proc, rows)

    def test_simulate_contains_fails_and_exits_one(self):
        proc, rows = _run([*self.MOD, "--simulate"])
        self.assertExits(1, proc, rows)

    def test_without_the_local_fail_a_closed_port_exits_two(self):
        proc, rows = _run([*self.MOD, "--url", f"http://127.0.0.1:{_closed_port()}",
                           "--categories", "nested_injection"])
        s = run_summary(rows)
        self.assertEqual((s["passed"], s["failed"]), (0, 0))
        self.assertExits(2, proc, rows)


# ---------------------------------------------------------------------------
# capability-residue (had no main before 2026-09-24)
# ---------------------------------------------------------------------------

class CapabilityResidueExitStatus(_Case):
    MOD = ["-m", "protocol_tests.capability_residue_harness", "--self-test"]

    def test_the_redacting_reference_passes_and_exits_zero(self):
        proc, rows = _run([*self.MOD, "--shape", "REDACTING"])
        self.assertTrue(all(r["passed"] for r in rows))
        self.assertExits(0, proc, rows)

    def test_an_echoing_reference_fails_and_exits_one(self):
        proc, rows = _run([*self.MOD, "--shape", "ECHOING"])
        self.assertExits(1, proc, rows)

    def test_a_refusing_reference_is_inconclusive_and_exits_two(self):
        proc, rows = _run([*self.MOD, "--shape", "REJECTS_ALL"])
        self.assertEqual(run_summary(rows)["inconclusive"], len(rows))
        self.assertExits(2, proc, rows)

    def test_no_target_runs_nothing_and_exits_two(self):
        proc, rows = _run(["-m", "protocol_tests.capability_residue_harness"])
        self.assertIsNone(rows)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("No target supplied", proc.stdout)

    def test_the_report_states_its_provenance_and_scope(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            subprocess.run([sys.executable, *self.MOD, "--report", str(path)],
                           cwd=REPO_ROOT, capture_output=True, timeout=120,
                           check=False, env=ENV)
            doc = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("provenance", doc)
        self.assertIn("REDACTING", doc["scope"])

    def test_the_cli_propagates_all_three(self):
        for shape, want in (("REDACTING", 0), ("ECHOING", 1), ("SILENT", 2)):
            with self.subTest(shape=shape):
                proc = subprocess.run(
                    [sys.executable, "-m", "protocol_tests.cli", "test",
                     "capability-residue", "--self-test", "--shape", shape],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
                    check=False, env=ENV)
                self.assertEqual(proc.returncode, want, proc.stderr[-400:])


if __name__ == "__main__":
    unittest.main()
