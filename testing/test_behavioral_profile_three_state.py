"""Behavioural drift must not score an unevaluated result as a failure.

## Why

`scripts/behavioral_profile.py` compared runs on `.get("passed", False)` alone.
An INCONCLUSIVE result carries `passed=False`, so it was indistinguishable from
a FAIL, and both consequences ran in the direction that hides a problem:

* `FAIL -> INCONCLUSIVE` compared equal, so a target that stopped answering
  scored as **stable, no drift**.
* `PASS -> INCONCLUSIVE` was reported as `PASS -> FAIL`, a regression alarm
  naming a cause that did not happen.

A third: an empty comparison returned `score: 100.0`, asserting perfect
stability from zero observations.

Found 2026-09-11 by a second reader tracing a comparison-table row to its source
(CP-04). The row advertised behavioural drift detection and did not disclose that
the observation boundary was two-state. The script is the shipped artifact behind
that row, so the defect was live, not documentary.

This is the same class the harnesses fought through `INCONCLUSIVE_FIELDS`,
`console_status` and the serviced guard. It reached a `scripts/` tool because
nothing shared was imported there.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))

import behavioral_profile as bp  # noqa: E402


def row(tid, passed, **kw):
    return {"test_id": tid, "name": tid, "passed": passed, **kw}


def idx(*rows):
    return {r["test_id"]: r for r in rows}


class VerdictState(unittest.TestCase):

    def test_the_three_states_are_distinguishable(self):
        self.assertEqual(bp.verdict_state(row("T", True)), bp.PASS)
        self.assertEqual(bp.verdict_state(row("T", False)), bp.FAIL)
        self.assertEqual(
            bp.verdict_state(row("T", False, not_evaluated=True)), bp.INCONCLUSIVE)

    def test_both_canonical_markers_are_read(self):
        """`not_evaluated` and `informational` are not synonyms and both count.

        `identity_harness` uses the second. Reading only the first made a whole
        module's results look like failures elsewhere in this repository.
        """
        for field in ("not_evaluated", "informational"):
            with self.subTest(field=field):
                self.assertEqual(
                    bp.verdict_state(row("T", False, **{field: True})),
                    bp.INCONCLUSIVE)

    def test_an_inconclusive_result_outranks_its_passed_flag(self):
        """A result carrying both must not be scored on `passed`."""
        self.assertEqual(
            bp.verdict_state(row("T", True, not_evaluated=True)), bp.INCONCLUSIVE)


class StabilityDoesNotScoreTheUnevaluated(unittest.TestCase):

    def test_fail_to_inconclusive_is_not_recorded_as_stable(self):
        """The defect, stated as a test. Both sides carry passed=False."""
        out = bp.compute_stability(
            idx(row("T-1", False)),
            idx(row("T-1", False, not_evaluated=True)))
        detail = out["details"][0]
        self.assertIsNot(
            detail["stable"], True,
            "a target that stopped producing a verdict scored as stable, which "
            "is the two-state comparison this file exists to prevent")
        self.assertEqual(detail["reason"], "inconclusive")
        self.assertEqual(out["inconclusive"], 1)
        self.assertEqual(out["comparable"], 0)

    def test_an_inconclusive_pair_is_excluded_from_the_score(self):
        out = bp.compute_stability(
            idx(row("T-1", True), row("T-2", True)),
            idx(row("T-1", True), row("T-2", False, not_evaluated=True)))
        self.assertEqual(out["comparable"], 1)
        self.assertEqual(out["matching"], 1)
        self.assertEqual(out["inconclusive"], 1)
        self.assertEqual(out["score"], 100.0,
                         "the one comparable pair matched, so the score is 100 "
                         "over that pair and the inconclusive one is reported "
                         "separately rather than silently scored")

    def test_a_real_regression_is_still_detected(self):
        """The opposing direction. Excluding INCONCLUSIVE must not excuse FAIL."""
        out = bp.compute_stability(idx(row("T-1", True)), idx(row("T-1", False)))
        self.assertEqual(out["details"][0]["stable"], False)
        self.assertEqual(out["details"][0]["reason"], "result_changed")
        self.assertEqual(out["score"], 0.0)

    def test_nothing_comparable_is_not_perfect_stability(self):
        """`score: 100.0` over zero observations asserted stability from nothing."""
        self.assertIsNone(bp.compute_stability({}, {})["score"])
        both_out = bp.compute_stability(
            idx(row("T-1", False, not_evaluated=True)),
            idx(row("T-1", False, not_evaluated=True)))
        self.assertIsNone(
            both_out["score"],
            "every pair was inconclusive, so there is no stability figure to "
            "report; 100% over zero comparable tests is the same defect")


class DriftNamesTheRightCause(unittest.TestCase):

    def _one(self, b, c):
        d = bp.detect_drift(idx(b), idx(c))
        return d[0] if d else None

    def test_pass_to_inconclusive_is_not_a_regression(self):
        ev = self._one(row("T-1", True), row("T-1", False, not_evaluated=True))
        self.assertIsNotNone(ev, "the transition must still be reported")
        self.assertEqual(
            ev["category"], "evidence_lost",
            "reporting this as a regression names a cause that did not happen: "
            "the target did not start failing, it stopped being measurable")
        self.assertEqual(ev["new_result"], bp.INCONCLUSIVE)

    def test_fail_to_inconclusive_is_reported_at_all(self):
        """Previously invisible: both sides were `passed=False`, so it was skipped."""
        ev = self._one(row("T-1", False), row("T-1", False, not_evaluated=True))
        self.assertIsNotNone(ev, "a verdict that became unavailable was silently dropped")
        self.assertEqual(ev["category"], "evidence_lost")

    def test_inconclusive_to_pass_is_not_an_improvement(self):
        ev = self._one(row("T-1", False, not_evaluated=True), row("T-1", True))
        self.assertEqual(
            ev["category"], "evidence_gained",
            "the target may always have passed; what changed is that a verdict "
            "could be established")

    def test_genuine_regression_and_improvement_still_classify(self):
        self.assertEqual(self._one(row("T-1", True), row("T-1", False))["category"],
                         "regression")
        self.assertEqual(self._one(row("T-1", False), row("T-1", True))["category"],
                         "improvement")

    def test_an_unchanged_state_produces_no_event(self):
        for r in (row("T-1", True), row("T-1", False),
                  row("T-1", False, not_evaluated=True)):
            with self.subTest(state=bp.verdict_state(r)):
                self.assertIsNone(self._one(r, dict(r)))


class TheSourceCannotSilentlyRevert(unittest.TestCase):

    def test_no_two_state_comparison_remains_in_the_script(self):
        """The repair was to two call sites; a third would reintroduce it."""
        src = (REPO_ROOT / "scripts" / "behavioral_profile.py").read_text(encoding="utf-8")
        for bad in ('b.get("passed"', 'c.get("passed"'):
            self.assertNotIn(
                bad, src,
                f"{bad!r} reads the pass flag directly and cannot see the third "
                "state. Use verdict_state().")

    def test_the_canonical_markers_are_imported_not_restated(self):
        """A local copy of the marker list drifts from the harnesses it reads."""
        src = (REPO_ROOT / "scripts" / "behavioral_profile.py").read_text(encoding="utf-8")
        self.assertIn("from protocol_tests.http_helpers import", src)
        self.assertIn("INCONCLUSIVE_FIELDS", src)


if __name__ == "__main__":
    unittest.main()
