"""R3-07: a community `field_matches` regex cannot hang the runner.

`community_runner.py` evaluates YAML plugins it does not trust, and a
`field_matches` assertion hands the runner an attacker-chosen regular
expression. The pre-existing guard capped the pattern length, capped the
input length and rejected one syntactic shape (nested quantifiers). None of
that bounds running time: `(a|aa)+$` passes every check and, on 37 `a`s
followed by `!`, does not return within four seconds.

The fix runs the match in a child interpreter that is killed at
MAX_REGEX_EVAL_SECONDS, and reports the kill as INCONCLUSIVE. These tests
pin the three properties that matter: bounded wall clock, INCONCLUSIVE (not
FAIL, not PASS, not an exception) when the bound fires, and unchanged
verdicts for patterns that finish.
"""

from __future__ import annotations

import time
import unittest

from protocol_tests import community_runner as cr
from protocol_tests.http_helpers import INCONCLUSIVE_PREFIX, is_inconclusive

CATASTROPHIC_PATTERN = "(a|aa)+$"
CATASTROPHIC_INPUT = "a" * 37 + "!"
WALL_CLOCK_LIMIT_S = 2.0


def _evaluate(pattern: str, text: str) -> tuple[bool, str]:
    evaluator = cr.AssertionEvaluator({"field": text}, [])
    return evaluator.evaluate({"type": "field_matches", "field": "field", "value": pattern})


class TestCatastrophicPatternIsBounded(unittest.TestCase):

    def test_ambiguous_alternation_returns_inconclusive_within_budget(self):
        start = time.monotonic()
        passed, detail = _evaluate(CATASTROPHIC_PATTERN, CATASTROPHIC_INPUT)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, WALL_CLOCK_LIMIT_S,
                        f"regex evaluation took {elapsed:.2f}s; the bound did not fire")
        self.assertFalse(passed)
        self.assertTrue(detail.startswith(INCONCLUSIVE_PREFIX), detail)
        self.assertIn(cr.REGEX_BUDGET_EXCEEDED, detail)
        self.assertTrue(is_inconclusive(detail))

    def test_budget_exceeded_is_never_pass_and_never_plain_fail(self):
        passed, detail = _evaluate(CATASTROPHIC_PATTERN, CATASTROPHIC_INPUT)
        self.assertIs(passed, False)
        self.assertTrue(is_inconclusive(detail),
                        "a pattern the runner could not evaluate must not read as a target failure")

    def test_bounded_evaluator_kills_child_and_reports_timeout(self):
        start = time.monotonic()
        outcome, message = cr.evaluate_regex_bounded(
            CATASTROPHIC_PATTERN, CATASTROPHIC_INPUT, budget_s=0.2)
        elapsed = time.monotonic() - start
        self.assertEqual(outcome, "timeout", message)
        self.assertLess(elapsed, 1.5)
        self.assertIn("did not finish", message)

    def test_default_budget_is_under_the_wall_clock_limit(self):
        # Spawn overhead sits on top of the budget; both must fit in the limit.
        self.assertLess(cr.MAX_REGEX_EVAL_SECONDS, WALL_CLOCK_LIMIT_S)


class TestBenignPatternsKeepTheirVerdicts(unittest.TestCase):

    def test_benign_match_still_passes(self):
        passed, detail = _evaluate(r"role=adm.n", "role=admin")
        self.assertTrue(passed, detail)
        self.assertFalse(is_inconclusive(detail))

    def test_benign_non_match_still_fails_not_inconclusive(self):
        passed, detail = _evaluate(r"^nothing here$", "role=admin")
        self.assertFalse(passed)
        self.assertFalse(is_inconclusive(detail), detail)
        self.assertIn("does not match", detail)

    def test_invalid_regex_is_inconclusive_not_a_crash(self):
        passed, detail = _evaluate(r"(unclosed", "anything")
        self.assertFalse(passed)
        self.assertTrue(is_inconclusive(detail), detail)

    def test_length_caps_are_kept(self):
        self.assertEqual(cr.MAX_REGEX_LENGTH, 200)
        passed, detail = _evaluate("a" * (cr.MAX_REGEX_LENGTH + 1), "a")
        self.assertFalse(passed)
        self.assertTrue(is_inconclusive(detail), detail)
        # Input truncation still applies before the bounded search.
        long_input = "x" * (cr.MAX_REGEX_INPUT_LENGTH + 500) + "needle"
        passed, detail = _evaluate("needle", long_input)
        self.assertFalse(passed, "needle beyond the input cap must not be visible")
        self.assertFalse(is_inconclusive(detail))


class TestPatternVerdictCarriesInconclusive(unittest.TestCase):
    """A pattern with an unevaluable assertion is INCONCLUSIVE, structurally."""

    def _pattern(self, regex: str) -> cr.AttackPattern:
        return cr.AttackPattern(
            id="CT-R307", version="1.0.0", name="regex budget", description="",
            framework="generic", severity="low", owasp_category="ASI01", attack_steps=[],
            evidence_schema={"field": "string"},
            assertions=[
                {"type": "field_matches", "field": "field", "value": regex,
                 "description": "regex assertion"},
                {"type": "field_equals", "field": "field", "value": "",
                 "description": "benign assertion"},
            ],
        )

    def test_budget_exceeded_pattern_is_not_evaluated_and_not_passed(self):
        pattern = self._pattern(CATASTROPHIC_PATTERN)
        executor = cr.StepExecutor(pattern)
        executor.evidence["field"] = CATASTROPHIC_INPUT
        # Drive run_pattern through its public path with the evidence injected.
        original = cr.StepExecutor
        try:
            cr.StepExecutor = lambda *a, **k: executor  # type: ignore[assignment]
            result = cr.run_pattern(pattern)
        finally:
            cr.StepExecutor = original
        self.assertFalse(result.passed)
        self.assertTrue(result.not_evaluated)
        self.assertEqual(result.assertions_inconclusive, 1)
        self.assertTrue(result.details.startswith(INCONCLUSIVE_PREFIX), result.details)
        self.assertIn("INCONCLUSIVE: regex assertion", result.details)
        self.assertTrue(is_inconclusive(result))
        self.assertTrue(is_inconclusive(result.to_dict()))

    def test_plain_failure_is_not_inconclusive(self):
        pattern = self._pattern(r"^will-not-match$")
        result = cr.run_pattern(pattern)
        self.assertFalse(result.passed)
        self.assertFalse(result.not_evaluated)
        self.assertFalse(is_inconclusive(result))


if __name__ == "__main__":
    unittest.main()
