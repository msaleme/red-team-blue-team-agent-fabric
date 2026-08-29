"""INCONCLUSIVE is a result class, not a residual bucket (#404).

After #402 stopped `return_channel` and `capability_profile` reporting a false
PASS against a closed port, they reported this instead::

    summary: {total: 8, passed: 0, failed: 8}
    WILSON 95% CI for pass rate: [0.0000, 0.3244]

Every one of those eight results was INCONCLUSIVE and none of them was a
failure. Two things were wrong and they are opposite in direction to the defect
#402 fixed:

- `failed` was the residual bucket, so a run that established nothing was
  reported as a run in which the target failed everything;
- a Wilson interval was computed over a pass rate whose denominator included
  observations that never happened, presenting the absence of a target as a
  measurement with quantified uncertainty.

The root cause was that INCONCLUSIVE had no structural existence. It was a
prefix on a prose field, so a summary could ask `passed?` and nothing else.

## Scope, and why it is eight modules rather than twenty-five

Twenty-five modules emit a Wilson summary and eighteen can produce an
INCONCLUSIVE result. Only the intersection can miscount one, and that is eight.
The other seventeen summary sites are not wrong today; they are simply not
reachable by this defect, and changing them would be churn.

That intersection is derived below rather than listed, so a module that gains a
guard tomorrow is caught the day it does.
"""

from __future__ import annotations

import pathlib
import re
import unittest

from protocol_tests.http_helpers import (
    INCONCLUSIVE_PREFIX,
    is_inconclusive,
    run_summary,
    summary_lines,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOCOL_TESTS = REPO_ROOT / "protocol_tests"

# The defect shape: a residual-bucket failed count.
RESIDUAL_FAILED = re.compile(r'"failed":\s*total\s*-\s*passed')

# "Emits a run summary", in EITHER idiom. Matching only the old one -- the
# WILSON/wilson_95_ci literals -- was the first version of this file, and it was
# useless: adopting run_summary() removes those literals, so the affected set
# collapsed to nothing the moment the migration landed and the ratchet below
# guarded an empty loop. A detector keyed to the thing being removed stops
# detecting exactly when it starts mattering.
EMITS_SUMMARY = re.compile(r"WILSON 95%|wilson_95_ci|run_summary|summary_lines")

# http_helpers defines the guard and the shared summary, and quotes the defect
# in run_summary's docstring as the thing it replaces. It is the fix, not a
# harness, so it is not a candidate.
NOT_A_HARNESS = {"http_helpers", "harness_base"}

# Modules that can produce INCONCLUSIVE, emit a summary, and have NOT adopted
# the shared one. May shrink. Must never grow -- a new entry means a module was
# written against the pattern this issue exists to remove.
GRANDFATHERED: set[str] = set()


class _R:
    """Minimal stand-in with the two attributes run_summary reads."""

    def __init__(self, passed: bool, details: str):
        self.passed = passed
        self.details = details


def _inconclusive(n: int) -> list[_R]:
    return [_R(False, f"{INCONCLUSIVE_PREFIX}target did not service the request")
            for _ in range(n)]


class TestInconclusiveIsCountedSeparately(unittest.TestCase):
    def test_a_wholly_unserviced_run_has_no_failures(self):
        """The #404 headline: eight inconclusives are not eight failures."""
        s = run_summary(_inconclusive(8))
        self.assertEqual(s["inconclusive"], 8)
        self.assertEqual(s["failed"], 0, "inconclusive results counted as failures")
        self.assertEqual(s["passed"], 0)
        self.assertEqual(s["status"], "inconclusive")

    def test_no_pass_rate_or_interval_without_a_serviced_observation(self):
        """None, not 0.0. A rate of zero is a claim; absence is not."""
        s = run_summary(_inconclusive(8))
        self.assertEqual(s["serviced"], 0)
        self.assertIsNone(s["pass_rate"])
        self.assertIsNone(s["wilson_95_ci"])

    def test_buckets_still_sum_to_total(self):
        """A consumer that adds the buckets must not be broken by the new class."""
        results = [_R(True, "ok"), _R(False, "real failure")] + _inconclusive(3)
        s = run_summary(results)
        self.assertEqual(s["passed"] + s["failed"] + s["inconclusive"], s["total"])

    def test_rate_is_over_serviced_observations_only(self):
        """1 pass and 1 failure among 3 results is 50%, not 33%."""
        s = run_summary([_R(True, "ok"), _R(False, "real failure")] + _inconclusive(1))
        self.assertEqual(s["serviced"], 2)
        self.assertEqual(s["pass_rate"], 0.5)
        self.assertIsNotNone(s["wilson_95_ci"])
        self.assertEqual(s["status"], "completed")

    def test_a_clean_serviced_run_is_unaffected(self):
        """The common case must not change, or the fix costs more than the defect."""
        s = run_summary([_R(True, "ok"), _R(True, "ok"), _R(False, "real failure")])
        self.assertEqual((s["passed"], s["failed"], s["inconclusive"]), (2, 1, 0))
        self.assertEqual(s["pass_rate"], round(2 / 3, 4))
        self.assertEqual(s["status"], "completed")

    def test_empty_run_is_empty_not_inconclusive(self):
        self.assertEqual(run_summary([])["status"], "empty")


class TestSummaryLinesSayWhatHappened(unittest.TestCase):
    def test_unserviced_run_states_it_plainly(self):
        lines = "\n".join(summary_lines(run_summary(_inconclusive(8))))
        self.assertIn("INCONCLUSIVE", lines)
        self.assertIn("none serviced", lines)
        self.assertNotIn("WILSON", lines,
                         "an interval must not be printed over unserviced observations")

    def test_serviced_run_still_reports_an_interval(self):
        lines = "\n".join(summary_lines(run_summary([_R(True, "ok"), _R(False, "f")])))
        self.assertIn("WILSON 95%", lines)


class TestIsInconclusive(unittest.TestCase):
    def test_detects_the_prefix_and_nothing_else(self):
        self.assertTrue(is_inconclusive(f"{INCONCLUSIVE_PREFIX}whatever"))
        self.assertFalse(is_inconclusive("the control held"))
        self.assertFalse(is_inconclusive(None))
        self.assertFalse(is_inconclusive(""))


class TestNoModuleKeepsTheResidualBucket(unittest.TestCase):
    """The ratchet. Derived, so module nine is caught the day it is written."""

    def _affected(self) -> set[str]:
        out = set()
        for path in sorted(PROTOCOL_TESTS.glob("*.py")):
            src = path.read_text(encoding="utf-8")
            if path.stem in NOT_A_HARNESS:
                continue
            if "inconclusive_detail" in src and EMITS_SUMMARY.search(src):
                out.add(path.stem)
        return out

    def test_the_affected_set_is_not_empty(self):
        """Assert a positive expected set, so a broken scan cannot read as success.

        If the detection stopped matching -- a renamed helper, a changed summary
        idiom -- the residual-bucket assertion below would iterate nothing and
        pass while every module carried the defect.
        """
        self.assertGreaterEqual(
            len(self._affected()), 8,
            "fewer affected modules found than the eight known at #404; the "
            "detection is probably broken rather than the repo improved")

    def test_no_affected_module_computes_failed_as_a_residual(self):
        for name in sorted(self._affected() - GRANDFATHERED):
            with self.subTest(module=name):
                src = (PROTOCOL_TESTS / f"{name}.py").read_text(encoding="utf-8")
                self.assertIsNone(
                    RESIDUAL_FAILED.search(src),
                    f"{name} can produce INCONCLUSIVE and still computes "
                    f'"failed": total - passed, so an inconclusive result is '
                    f"reported as a target failure. Use run_summary() from "
                    f"protocol_tests.http_helpers.")

    def test_grandfather_list_is_empty_and_may_only_shrink(self):
        self.assertEqual(
            GRANDFATHERED, set(),
            "every affected module was migrated at #404. A non-empty list means "
            "one regressed or a new one was added against the old pattern.")


if __name__ == "__main__":
    unittest.main()
