"""Community runner: a "live" run contacts the target or says it did not.

`_do_send_message`, `_do_send_jsonrpc` and `_do_call_tool` returned
`{"status": "sent", "response": None}` with the comment "Populated by
harness integration". A run with `--url http://127.0.0.1:9` therefore never
opened a socket, and an absence assertion ("response must not contain X")
searched a synthetic structure and PASSED against a target that was never
reached. Dry-run assigned `passed = True` outright. A synthetic plugin
produced one PASS and zero inconclusive in both modes (R4-07, fourth
external review, 2026-09-08).

Validation also accepted a non-object evidence schema, an unknown action
and an unknown assertion type; the pattern time budget was checked only
before each step; and nothing capped the assertion count (R4-14).

The fixture plugin here is synthetic and assembled at run time under a
temporary directory with a hash-bound MANIFEST.yaml, the way the runner
trusts any plugin; it contains no credentials and is never committed.
"""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from protocol_tests import community_runner as cr  # noqa: E402
from protocol_tests.http_helpers import is_inconclusive  # noqa: E402

CLOSED = "http://127.0.0.1:9/mcp"
SYNTHETIC_TOKEN = "zq7hunter2wq"  # appears nowhere but in the assertion


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


def _pattern(**over) -> cr.AttackPattern:
    base = dict(
        id="CP-9901", version="1.0.0", name="synthetic absence probe", description="",
        framework="mcp", severity="low", owasp_category="OWASP-AGENT-01",
        attack_steps=[{"action": "send_jsonrpc", "target": "server",
                       "payload": {"method": "tools/list", "params": {}}}],
        assertions=[{"type": "response_must_not_contain", "field": "response",
                     "value": SYNTHETIC_TOKEN, "description": "token absent"}],
        evidence_schema={"response_received": "object"},
    )
    base.update(over)
    return cr.AttackPattern(**base)


PLUGIN_YAML = textwrap.dedent(f"""\
    id: CP-9901
    version: "1.0.0"
    name: Synthetic absence probe (test fixture)
    description: Asks that a synthetic token not appear, and that a real tool name does.
    framework: mcp
    severity: low
    owasp_category: OWASP-AGENT-01
    attack_steps:
      - action: send_jsonrpc
        target: server
        payload:
          method: tools/list
          params: {{}}
      - action: call_tool
        target: server
        payload:
          tool_name: get_safety_procedures
          arguments:
            pipeline_id: fixture-1
    assertions:
      - type: response_must_not_contain
        field: response
        value: "{SYNTHETIC_TOKEN}"
      - type: response_must_contain
        field: response
        value: "vulnerable_tool_discovery"
    evidence_schema:
      response_received: object
    """)


def _write_fixture(root: Path) -> tuple[str, str]:
    """A hash-bound, community-tier plugin under *root*; returns (dir, file)."""
    cdir = root / "community_modules"
    (cdir / "contrib").mkdir(parents=True)
    pfile = cdir / "contrib" / "synthetic_absence.yaml"
    pfile.write_text(PLUGIN_YAML, encoding="utf-8")
    digest = hashlib.sha256(pfile.read_bytes()).hexdigest()
    (cdir / cr.MANIFEST_FILE).write_text(textwrap.dedent(f"""\
        spec_version: '1.0'
        patterns:
        - file: contrib/synthetic_absence.yaml
          id: CP-9901
          sha256: {digest}
          trust: community
          reviewed_by: test-fixture
          reviewed_at: '2026-09-08'
        """), encoding="utf-8")
    return str(cdir), str(pfile)


class _MockServer(unittest.TestCase):
    proc = None
    url = ""

    @classmethod
    def setUpClass(cls):
        port = _free_port()
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "protocol_tests.mock_mcp_server",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=REPO_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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


class TestALivePluginActuallySends(_MockServer):
    def test_the_manifest_bound_plugin_reaches_the_loopback_mock(self):
        with tempfile.TemporaryDirectory() as tmp:
            cdir, pfile = _write_fixture(Path(tmp))
            with mock.patch("sys.stdout"):
                summary = cr.run_community_tests(
                    community_dir=cdir, pattern_file=pfile, target_url=self.url)
        self.assertEqual(summary["patterns_run"], 1, summary)
        row = summary["results"][0]
        self.assertEqual(row["requests_sent"], 2, row)
        self.assertEqual(row["requests_answered"], 2, row)
        self.assertFalse(row["not_evaluated"], row["details"])
        self.assertTrue(row["passed"], row["details"])
        self.assertEqual(row["assertions_passed"], 2)
        self.assertEqual((summary["passed"], summary["failed"], summary["inconclusive"]), (1, 0, 0))

    def test_a_presence_assertion_that_the_target_does_not_satisfy_is_a_real_fail(self):
        pat = _pattern(assertions=[{"type": "response_must_contain", "field": "response",
                                    "value": SYNTHETIC_TOKEN}])
        r = cr.run_pattern(pat, target_url=self.url)
        self.assertEqual((r.requests_sent, r.requests_answered), (1, 1))
        self.assertFalse(r.passed)
        self.assertFalse(r.not_evaluated, "a target that answered and lacked the value is FAIL")
        self.assertFalse(is_inconclusive(r))

    def test_send_message_is_an_a2a_request_on_the_wire(self):
        seen: list[dict] = []

        class Spy(cr.HttpJsonRpcAdapter):
            def send_jsonrpc(self, message):
                seen.append(message)
                return super().send_jsonrpc(message)

        pat = _pattern(attack_steps=[{"action": "send_message", "target": "agent",
                                      "payload": {"role": "user", "content": "hello"}}])
        r = cr.run_pattern(pat, target_url=self.url, adapter=Spy(self.url))
        self.assertEqual(seen[0]["method"], "message/send")
        self.assertEqual(seen[0]["params"]["message"]["parts"][0]["text"], "hello")
        self.assertEqual(r.requests_sent, 1)


class TestNoContactIsNeverAPass(unittest.TestCase):
    def test_closed_port_is_inconclusive(self):
        r = cr.run_pattern(_pattern(), target_url=CLOSED)
        self.assertGreaterEqual(r.requests_sent, 1)
        self.assertEqual(r.requests_answered, 0)
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated)
        self.assertEqual(r.assertions_inconclusive, 1)
        self.assertIn("answered none of", r.details)

    def test_no_url_means_no_adapter_and_says_so(self):
        r = cr.run_pattern(_pattern(), target_url="")
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated)
        self.assertIn(cr.NO_ADAPTER_DETAIL, r.details)
        self.assertEqual(r.requests_sent, 0)

    def test_a_framework_without_a_live_adapter_is_inconclusive_even_with_a_url(self):
        r = cr.run_pattern(_pattern(framework="crewai"), target_url=CLOSED)
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated)
        self.assertIn("no live adapter for framework 'crewai'", r.details)
        self.assertEqual(r.requests_sent, 0)

    def test_only_simulated_steps_never_contact_the_target(self):
        pat = _pattern(attack_steps=[{"action": "register_tool", "target": "server",
                                      "payload": {"tool_name": "t", "description": "d"}}])
        r = cr.run_pattern(pat, target_url=CLOSED)
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated)
        self.assertIn("the target was not contacted", r.details)


class TestDryRunIsInconclusive(unittest.TestCase):
    def test_dry_run_assertions_are_not_evaluated_and_not_passed(self):
        r = cr.run_pattern(_pattern(), target_url=CLOSED, dry_run=True)
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated)
        self.assertEqual(r.assertions_passed, 0)
        self.assertEqual(r.assertions_inconclusive, 1)
        self.assertIn("(dry run", r.details)
        self.assertIn("not evaluated)", r.details)
        self.assertEqual(r.requests_sent, 0)

    def test_the_summary_counts_a_dry_run_as_inconclusive_and_the_cli_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            cdir, pfile = _write_fixture(Path(tmp))
            with mock.patch("sys.stdout"):
                summary = cr.run_community_tests(
                    community_dir=cdir, pattern_file=pfile, dry_run=True)
            self.assertEqual((summary["passed"], summary["failed"], summary["inconclusive"]), (0, 0, 1))
            proc = subprocess.run(
                [sys.executable, "-m", "protocol_tests.community_runner",
                 "--pattern", os.path.relpath(pfile, tmp), "--community-dir", cdir, "--dry-run"],
                cwd=tmp, capture_output=True, text=True, timeout=120, check=False,
                env=dict(os.environ, PYTHONPATH=REPO_ROOT, AGENT_SECURITY_TELEMETRY="off"),
            )
        self.assertEqual(proc.returncode, 2, proc.stdout[-400:] + proc.stderr[-400:])
        self.assertIn("INCONCLUSIVE CP-9901", proc.stdout)


class TestValidationEnums(unittest.TestCase):
    """R4-14: enums derived from the dispatch tables, not hand-written twice."""

    def _data(self, **over) -> dict:
        base = dict(id="CP-9902", version="1", name="n", description="d", framework="generic",
                    severity="low", owasp_category="OWASP-AGENT-01",
                    attack_steps=[{"action": "send_message", "target": "agent", "payload": {}}],
                    assertions=[{"type": "no_data_exfiltration"}],
                    evidence_schema={"x": "string"})
        base.update(over)
        return base

    def _errors(self, data) -> list[str]:
        _, errs = cr.validate_pattern(data, "case.yaml")
        return [str(e) for e in errs]

    def test_the_baseline_is_accepted(self):
        self.assertEqual(self._errors(self._data()), [])

    def test_non_object_evidence_schema_is_rejected(self):
        errs = self._errors(self._data(evidence_schema="string"))
        self.assertTrue(any("[evidence_schema]" in e and "object" in e for e in errs), errs)

    def test_unknown_action_is_rejected(self):
        errs = self._errors(self._data(attack_steps=[{"action": "teleport", "target": "agent", "payload": {}}]))
        self.assertTrue(any("[attack_steps[0].action]" in e and "teleport" in e for e in errs), errs)

    def test_unknown_assertion_type_is_rejected(self):
        errs = self._errors(self._data(assertions=[{"type": "vibes_ok"}]))
        self.assertTrue(any("[assertions[0].type]" in e and "vibes_ok" in e for e in errs), errs)

    def test_enums_are_the_dispatch_tables(self):
        self.assertEqual(cr.VALID_ACTIONS, {n[4:] for n in vars(cr.StepExecutor) if n.startswith("_do_")})
        self.assertEqual(cr.VALID_ASSERTION_TYPES,
                         {n[7:] for n in vars(cr.AssertionEvaluator) if n.startswith("_check_")})
        for name in ("send_message", "send_jsonrpc", "call_tool", "wait"):
            self.assertIn(name, cr.VALID_ACTIONS)
        for name in ("response_must_not_contain", "field_matches"):
            self.assertIn(name, cr.VALID_ASSERTION_TYPES)

    def test_assertion_count_is_capped(self):
        ok = [{"type": "no_data_exfiltration"}] * cr.MAX_ASSERTIONS
        self.assertEqual(self._errors(self._data(assertions=ok)), [])
        errs = self._errors(self._data(assertions=ok + [{"type": "no_data_exfiltration"}]))
        self.assertTrue(any("Too many assertions" in e for e in errs), errs)
        self.assertEqual(cr.MAX_ASSERTIONS, 50)

    def test_the_shipped_plugins_still_validate(self):
        with mock.patch("sys.stdout"):
            summary = cr.run_community_tests(
                community_dir=os.path.join(REPO_ROOT, "community_modules"), validate_only=True)
        self.assertEqual(summary["patterns_valid"], summary["patterns_found"], summary["errors"])


class _AnsweringAdapter:
    """Answers every request instantly so the assertion phase is reachable."""

    def __init__(self):
        self.calls = 0

    def send_jsonrpc(self, message):
        self.calls += 1
        return {"_status": 200, "_body": "{}", "response": {"result": {}}}


class TestPatternDeadlineCoversStepsAndAssertions(unittest.TestCase):
    """R4-14: with a 50 ms budget, a 200 ms wait step must not end in PASS."""

    def test_overrun_after_the_last_step_is_inconclusive(self):
        pat = _pattern(framework="generic",
                       attack_steps=[{"action": "wait", "target": "server",
                                      "payload": {"duration_ms": 200}}])
        with mock.patch.object(cr, "MAX_PATTERN_EXECUTION_TIMEOUT_S", 0.05):
            r = cr.run_pattern(pat, target_url=CLOSED, adapter=_AnsweringAdapter())
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated)
        self.assertIn(cr.PATTERN_BUDGET_EXCEEDED, r.details)
        self.assertIn("after step 1/1", r.details)
        self.assertEqual(r.assertions_inconclusive, r.assertions_total)

    def test_overrun_during_assertions_is_inconclusive(self):
        pat = _pattern(framework="generic",
                       assertions=[{"type": "no_data_exfiltration"}, {"type": "no_data_exfiltration"}])

        def slow(self, assertion):
            time.sleep(0.1)
            return True, "ok"

        with mock.patch.object(cr, "MAX_PATTERN_EXECUTION_TIMEOUT_S", 0.05), \
                mock.patch.object(cr.AssertionEvaluator, "evaluate", slow):
            r = cr.run_pattern(pat, target_url=CLOSED, adapter=_AnsweringAdapter())
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated)
        self.assertIn("after assertion 1/2", r.details)

    def test_within_budget_a_pattern_still_passes(self):
        r = cr.run_pattern(_pattern(framework="generic"), target_url=CLOSED,
                           adapter=_AnsweringAdapter())
        self.assertTrue(r.passed, r.details)
        self.assertFalse(r.not_evaluated)


if __name__ == "__main__":
    unittest.main()
