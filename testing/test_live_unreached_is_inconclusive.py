"""A live target that was never reached must not inherit the reference model's PASS.

## The defect (R3-01, third external review, 2026-09-07)

Five payment conformance modules -- ap2, x402_fireblocks, ucp_acp, card_token
and settlement_finality -- fold a reference-model verdict with a live probe of
the target. Each `_finish` started from `passed = model_pass` and, when the
live probe came back `unreachable`, rewrote only `details`:

    else:
        details = f"{model_reason}; live verifier unreachable — verdict from reference model"

So against a closed port, the published 4.21.0 reported 17/17, 17/17, 12/12,
12/12 and 8/8 passed, `mode: live`, `pass_rate: 1.0`, a Wilson interval, and
`migrate_legacy_report` turned that into a 17-pass attestation. The reference
model had been asked about itself and the answer was filed under the target.

## What this pins

Run through the CLI -- the path an operator takes -- against a port nobody is
listening on, every row of every one of the five is INCONCLUSIVE: `passed`
False, `not_evaluated` True, `details` prefixed, the reference-model verdict
kept SEPARATELY under `reference_verdict` with its own scope statement. The
summary services nothing and computes no rate; the report says live was
requested and not reached; migration yields `inconclusive: N, passed: 0`.

The shared fold (`http_helpers.fold_live_verdict`) is unit-tested on its own
so the policy has one place to be wrong.

## What this does not establish

That a live `rejected` from a real verifier is graded correctly beyond what
the fold says: none of the five rows sends a legitimate variant, so none has a
positive control, and a live rejection is recorded but not scored as a pass.
A module that adds a positive control passes `positive_control=True` and the
same fold returns a PASS. That is a decision for the module, not for this file.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.attestation import migrate_legacy_report  # noqa: E402
from protocol_tests.http_helpers import (  # noqa: E402
    INCONCLUSIVE_PREFIX,
    REFERENCE_VERDICT_SCOPE,
    fold_live_verdict,
    is_inconclusive,
    live_run_scope,
    run_summary,
)

#: Nothing listens here. Same target the dead-host sweep uses.
CLOSED_PORT = "http://127.0.0.1:9"

#: Registry name -> the row count its own description advertises. A floor, so
#: a suite that emits nothing cannot satisfy "every row is INCONCLUSIVE".
AFFECTED = {
    "ap2": 17,
    "x402-fireblocks": 17,
    "ucp-acp": 12,
    "card-token": 12,
    "settlement-finality": 8,
}


def _run_cli(name: str, tmp: Path) -> dict:
    report = tmp / f"{name}.json"
    env = dict(os.environ, AGENT_SECURITY_TELEMETRY="off")
    subprocess.run(
        [sys.executable, "-m", "protocol_tests.cli", "test", name,
         "--url", CLOSED_PORT, "--report", str(report)],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=180,
        check=False,
    )
    return json.loads(report.read_text(encoding="utf-8"))


class TestTheFiveAgainstAClosedPort(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="r3-01-"))
        cls.reports = {name: _run_cli(name, cls.tmp) for name in AFFECTED}

    def test_every_suite_produced_its_advertised_rows(self):
        for name, floor in AFFECTED.items():
            with self.subTest(harness=name):
                self.assertGreaterEqual(
                    len(self.reports[name]["results"]), floor,
                    f"{name} emitted fewer rows than it advertises; an empty "
                    f"suite would satisfy every assertion below vacuously")

    def test_every_row_is_inconclusive_with_the_structural_field(self):
        for name, report in self.reports.items():
            for row in report["results"]:
                with self.subTest(harness=name, test_id=row.get("test_id")):
                    self.assertIs(row["passed"], False)
                    self.assertIs(row["not_evaluated"], True)
                    self.assertTrue(row["details"].startswith(INCONCLUSIVE_PREFIX))
                    self.assertTrue(is_inconclusive(row))

    def test_the_reference_verdict_is_preserved_separately_and_scoped(self):
        for name, report in self.reports.items():
            for row in report["results"]:
                with self.subTest(harness=name, test_id=row.get("test_id")):
                    ref = row.get("reference_verdict")
                    self.assertIsInstance(ref, dict, "reference_verdict missing")
                    self.assertIsInstance(ref["passed"], bool)
                    self.assertIsInstance(ref["reason"], str)
                    self.assertTrue(ref["reason"])
                    self.assertEqual(ref["scope"], REFERENCE_VERDICT_SCOPE)
                    # The whole point: the reference model's PASS never lands
                    # in the row's own `passed`.
                    self.assertNotEqual(
                        (row["passed"], ref["passed"]), (True, True),
                        "reference PASS leaked into the row's passed")

    def test_no_row_observed_anything_live(self):
        for name, report in self.reports.items():
            for row in report["results"]:
                with self.subTest(harness=name, test_id=row.get("test_id")):
                    ev = row.get("live_evidence")
                    if ev is not None:
                        self.assertEqual(ev["verdict"], "unreachable")

    def test_the_summary_services_nothing_and_computes_no_rate(self):
        for name, report in self.reports.items():
            with self.subTest(harness=name):
                s = report["summary"]
                self.assertEqual(s["serviced"], 0)
                self.assertEqual(s["passed"], 0)
                self.assertEqual(s["failed"], 0)
                self.assertEqual(s["inconclusive"], s["total"])
                self.assertIsNone(s["pass_rate"])
                self.assertIsNone(s["wilson_95_ci"])
                self.assertEqual(s["status"], "inconclusive")

    def test_the_report_says_live_was_requested_and_not_reached(self):
        for name, report in self.reports.items():
            with self.subTest(harness=name):
                self.assertEqual(report["mode"], "live")
                scope = report["verdict_scope"]
                self.assertIs(scope["live_requested"], True)
                self.assertEqual(scope["target"], CLOSED_PORT)
                self.assertEqual(scope["rows_with_live_observation"], 0)
                self.assertEqual(scope["rows_scored"], 0)
                self.assertIn("requested", scope["statement"])
                self.assertIn("NOT reached", scope["statement"])

    def test_migration_yields_inconclusive_n_and_passed_zero(self):
        for name, report in self.reports.items():
            with self.subTest(harness=name):
                migrated = migrate_legacy_report(report)["summary"]
                n = len(report["results"])
                self.assertEqual(migrated["inconclusive"], n)
                self.assertEqual(migrated["passed"], 0)
                self.assertEqual(migrated["failed"], 0)


class TestTheFold(unittest.TestCase):
    """`fold_live_verdict` is the one policy; each branch is pinned."""

    def test_simulate_is_unchanged_and_carries_no_reference_verdict(self):
        passed, details, ref = fold_live_verdict(
            live_requested=False, verdict="unreachable",
            model_pass=True, model_reason="the reference rejected it")
        self.assertIs(passed, True)
        self.assertEqual(details, "the reference rejected it")
        self.assertIsNone(ref)

    def test_unreachable_is_inconclusive_and_keeps_the_reference_apart(self):
        passed, details, ref = fold_live_verdict(
            live_requested=True, verdict="unreachable",
            model_pass=True, model_reason="r")
        self.assertIs(passed, False)
        self.assertTrue(details.startswith(INCONCLUSIVE_PREFIX))
        self.assertIn("not observed", details)
        self.assertEqual(ref, {"passed": True, "reason": "r",
                               "scope": REFERENCE_VERDICT_SCOPE})

    def test_a_row_with_no_live_probe_is_inconclusive_in_live_mode(self):
        passed, details, ref = fold_live_verdict(
            live_requested=True, verdict=None, model_pass=True, model_reason="r")
        self.assertIs(passed, False)
        self.assertTrue(details.startswith(INCONCLUSIVE_PREFIX))
        self.assertIn("no live probe", details)
        self.assertEqual(ref["passed"], True)

    def test_a_reference_fail_stays_a_fail_in_the_reference_field_only(self):
        passed, details, ref = fold_live_verdict(
            live_requested=True, verdict="unreachable",
            model_pass=False, model_reason="reference model accepted the attack")
        self.assertIs(passed, False)
        self.assertTrue(details.startswith(INCONCLUSIVE_PREFIX))
        self.assertIs(ref["passed"], False)

    def test_accepted_is_a_fail(self):
        passed, details, ref = fold_live_verdict(
            live_requested=True, verdict="accepted",
            model_pass=True, model_reason="r", subject="live endpoint")
        self.assertIs(passed, False)
        self.assertFalse(is_inconclusive(details))
        self.assertIn("ACCEPTED", details)
        self.assertEqual(ref["passed"], True)

    def test_rejected_without_a_positive_control_is_not_a_pass(self):
        passed, details, ref = fold_live_verdict(
            live_requested=True, verdict="rejected",
            model_pass=True, model_reason="r")
        self.assertIs(passed, False)
        self.assertTrue(details.startswith(INCONCLUSIVE_PREFIX))
        self.assertIn("no positive control", details)
        self.assertEqual(ref["passed"], True)

    def test_rejected_with_a_positive_control_is_the_reference_verdict(self):
        passed, details, ref = fold_live_verdict(
            live_requested=True, verdict="rejected",
            model_pass=True, model_reason="r", positive_control=True)
        self.assertIs(passed, True)
        self.assertFalse(is_inconclusive(details))
        self.assertEqual(ref["passed"], True)

    def test_run_summary_over_folded_unreachable_rows_services_nothing(self):
        class R:
            def __init__(self, details):
                self.passed, self.details, _ = fold_live_verdict(
                    live_requested=True, verdict="unreachable",
                    model_pass=True, model_reason=details)
                self.not_evaluated = is_inconclusive(self.details)
        s = run_summary([R("a"), R("b"), R("c")])
        self.assertEqual((s["serviced"], s["passed"], s["inconclusive"]), (0, 0, 3))
        self.assertIsNone(s["pass_rate"])

    def test_scope_statement_distinguishes_requested_from_reached(self):
        class R:
            live_evidence = {"verdict": "unreachable", "status": 0}
            details = INCONCLUSIVE_PREFIX + "x"
            not_evaluated = True
            passed = False
        scope = live_run_scope([R(), R()], live_requested=True, target="http://t")
        self.assertIs(scope["live_requested"], True)
        self.assertEqual(scope["rows_with_live_observation"], 0)
        self.assertIn("NOT reached", scope["statement"])
        sim = live_run_scope([R()], live_requested=False, target=None)
        self.assertIs(sim["live_requested"], False)
        self.assertIn("reference-model self-test", sim["statement"])


if __name__ == "__main__":
    unittest.main()
