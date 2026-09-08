"""A native `--simulate --report` run publishes no pass, anywhere a row is read.

Six harnesses handle `--simulate` in their own `main()`: ap2, x402_fireblocks,
ucp_acp, card_token, settlement_finality and aiuc1_compliance. The CLI facade
(`agent-security test ap2 --simulate`) never reaches them -- `cli._simulate_harness`
intercepts and writes INCONCLUSIVE rows -- so `tests/test_simulate_does_not_claim_a_pass.py`
proved the facade and nothing else. Run directly, the five payment modules
wrote 17/17/12/12/8 = 66 rows `passed: true` with `serviced: N` and a Wilson
interval; `attestation.migrate_legacy_report` turned them into attestations
carrying 66 passes and `telemetry.verdict_counts` counted 66 passed. aiuc1's
rows were marked INCONCLUSIVE and its own summary said `passed 0 / failed 12`.
Fourth external review, R4-05 (High), 2026-09-08; maintainer reproduced.

This file runs the six module entry points in a subprocess, exactly as a
consumer would, and checks three layers of the same file: every row, the
summary, and each consumer that reads rows -- attestation migration, the
evidence pack, the HTML renderer, top10_failures and the telemetry counter.
The grandfather list in `test_simulated_passes_are_scoped.py` never stopped a
consumer publishing a grandfathered row; this does.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

from protocol_tests import attestation, telemetry  # noqa: E402
from protocol_tests.http_helpers import (  # noqa: E402
    INCONCLUSIVE_PREFIX,
    REFERENCE_VERDICT_SCOPE,
    SIMULATED_ROW_SCOPE,
)

#: Module -> rows a native simulated run writes. The counts are the review's.
NATIVE = {
    "protocol_tests.ap2_harness": 17,
    "protocol_tests.x402_fireblocks_harness": 17,
    "protocol_tests.ucp_acp_harness": 12,
    "protocol_tests.card_token_harness": 12,
    "protocol_tests.settlement_finality_harness": 8,
    "protocol_tests.aiuc1_compliance_harness": 12,
}


class NativeSimulateIsScoped(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="native-sim-"))
        cls.runs = {}
        for mod in NATIVE:
            path = cls.tmp / f"{mod.rsplit('.', 1)[1]}.json"
            done = subprocess.run(
                [sys.executable, "-m", mod, "--simulate", "--report", str(path)],
                capture_output=True, text=True, timeout=180, cwd=str(REPO))
            report = json.loads(path.read_text()) if path.exists() else None
            cls.runs[mod] = (done, path, report)

    def _each(self):
        for mod, expected in NATIVE.items():
            done, path, report = self.runs[mod]
            with self.subTest(module=mod):
                self.assertIsNotNone(report, f"no report written: {done.stderr[-800:]}")
                self.assertEqual(len(report["results"]), expected, "a simulated row went missing")
                yield mod, done, path, report

    # -- rows ---------------------------------------------------------------

    def test_every_row_is_inconclusive_and_labelled(self):
        for mod, _, _, report in self._each():
            for r in report["results"]:
                with self.subTest(module=mod, test_id=r.get("test_id")):
                    self.assertIs(r["passed"], False, "a simulated row claimed a pass")
                    self.assertIs(r["not_evaluated"], True, "canonical structural marker")
                    self.assertIs(r["simulated"], True)
                    self.assertEqual(r["verdict_scope"], SIMULATED_ROW_SCOPE)
                    self.assertTrue(str(r["details"]).startswith(INCONCLUSIVE_PREFIX),
                                    "the details string must agree with the field")

    def test_the_fabricated_verdict_is_preserved_under_its_own_scope(self):
        """The reference model's answer is kept, labelled, and never in `passed`."""
        for mod, _, _, report in self._each():
            reference_passes = 0
            for r in report["results"]:
                with self.subTest(module=mod, test_id=r.get("test_id")):
                    ref = r["reference_verdict"]
                    self.assertIsInstance(ref, dict)
                    self.assertIsInstance(ref["passed"], bool)
                    self.assertTrue(ref["reason"])
                    self.assertEqual(ref["scope"], REFERENCE_VERDICT_SCOPE)
                    reference_passes += ref["passed"]
            # The answers were authored to satisfy the checks; that outcome is
            # recorded, so it is visible, and scoped, so it is not a claim.
            self.assertGreater(reference_passes, 0, f"{mod}: no reference verdict survived")

    # -- summary ------------------------------------------------------------

    def test_the_summary_is_three_state_with_no_denominator(self):
        for mod, _, _, report in self._each():
            s = report["summary"]
            n = len(report["results"])
            self.assertEqual(
                {k: s[k] for k in ("total", "passed", "failed", "inconclusive",
                                   "serviced", "status", "pass_rate", "wilson_95_ci")},
                {"total": n, "passed": 0, "failed": 0, "inconclusive": n,
                 "serviced": 0, "status": "inconclusive",
                 "pass_rate": None, "wilson_95_ci": None},
                f"{mod}: rows and summary disagree, or a rate was computed over nothing")

    def test_the_report_says_what_was_reached(self):
        for mod, _, _, report in self._each():
            scope = report["verdict_scope"]
            self.assertIs(scope["live_requested"], False)
            self.assertIn("reference-model self-test", scope["statement"])

    def test_nothing_failed_so_the_exit_status_is_zero(self):
        """INCONCLUSIVE is not FAIL. ap2 and x402_fireblocks exited 1 on any
        non-pass; three others never set a status. One rule: a serviced FAIL."""
        for mod, done, _, _ in self._each():
            self.assertEqual(done.returncode, 0, done.stderr[-800:])

    def test_aiuc1_requirement_coverage_is_the_same_answer_as_the_rows(self):
        """The second summary in the aiuc1 report said every requirement FAIL."""
        _, _, report = self.runs["protocol_tests.aiuc1_compliance_harness"]
        cov = report["aiuc1_requirement_coverage"]
        self.assertTrue(cov)
        for req, counts in cov.items():
            with self.subTest(requirement=req):
                self.assertEqual((counts["passed"], counts["failed"]), (0, 0))
                self.assertEqual(counts["inconclusive"], counts["total"])
                self.assertEqual(counts["status"], "INCONCLUSIVE")

    # -- consumers ----------------------------------------------------------

    def test_attestation_migration_publishes_zero_passes(self):
        for mod, _, _, report in self._each():
            att = attestation.migrate_legacy_report(report)
            self.assertEqual(att["summary"]["passed"], 0, f"{mod}: a pass reached an attestation")
            self.assertEqual(att["summary"].get("failed", 0), 0)
            self.assertEqual({e["result"] for e in att["entries"]}, {"inconclusive"})
            self.assertEqual(len(att["entries"]), len(report["results"]))

    def test_telemetry_counter_publishes_zero_passes(self):
        for mod, _, _, report in self._each():
            n = len(report["results"])
            self.assertEqual(telemetry.verdict_counts(report["results"]),
                             {"tests": n, "passed": 0, "failed": 0, "inconclusive": n},
                             f"{mod}: the telemetry counter counted a pass")

    def test_evidence_pack_publishes_zero_passes(self):
        from evidence_pack import build_evidence_pack

        for mod, _, path, report in self._each():
            out = self.tmp / f"pack-{mod.rsplit('.', 1)[1]}"
            build_evidence_pack(str(path), "simulated-no-target", str(out))
            summary = json.loads((out / "evidence-summary.json").read_text())["summary"]
            n = len(report["results"])
            self.assertEqual(
                {k: summary[k] for k in ("total_tests", "passed", "failed",
                                         "inconclusive", "serviced", "pass_rate")},
                {"total_tests": n, "passed": 0, "failed": 0, "inconclusive": n,
                 "serviced": 0, "pass_rate": None},
                f"{mod}: the evidence pack published a pass")

    def test_html_report_renders_no_pass_and_no_fail(self):
        from html_report import generate_html

        for mod, _, _, report in self._each():
            html = generate_html(report)
            self.assertIn('class="badge badge-inconclusive"', html)
            self.assertNotIn('class="badge badge-pass"', html, f"{mod}: a PASS badge")
            self.assertNotIn('class="badge badge-fail"', html, f"{mod}: a FAIL badge")
            self.assertIn('<div class="value green">0</div>', html)

    def test_top10_failures_finds_no_failure(self):
        from top10_failures import build_top10

        for mod, _, path, _ in self._each():
            out = json.loads(build_top10([str(path)], as_json=True))
            self.assertEqual(out["total_unique_failures"], 0, f"{mod}: an INCONCLUSIVE row became a failure")
            self.assertEqual(out["top_failures"], [])


if __name__ == "__main__":
    unittest.main()
