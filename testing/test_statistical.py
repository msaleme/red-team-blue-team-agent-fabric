#!/usr/bin/env python3
"""Unit tests for protocol_tests.statistical module.

Tests the Wilson CI, bootstrap CI, and multi-trial runner —
the only module that can be fully tested without a live endpoint.
"""
import math
import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol_tests.statistical import (
    wilson_ci,
    bootstrap_ci,
    run_with_trials,
    TrialResult,
    enhance_report,
    generate_statistical_report,
)


class TestWilsonCI(unittest.TestCase):
    """Wilson score confidence interval correctness."""

    def test_zero_trials_returns_zero(self):
        lower, upper = wilson_ci(0, 0)
        self.assertEqual(lower, 0.0)
        self.assertEqual(upper, 0.0)

    def test_all_pass(self):
        lower, upper = wilson_ci(10, 10)
        self.assertGreater(lower, 0.6)
        self.assertEqual(upper, 1.0)

    def test_all_fail(self):
        lower, upper = wilson_ci(0, 10)
        self.assertEqual(lower, 0.0)
        self.assertLess(upper, 0.4)

    def test_50_50_split(self):
        lower, upper = wilson_ci(50, 100)
        self.assertAlmostEqual((lower + upper) / 2, 0.5, delta=0.05)
        self.assertGreater(upper - lower, 0.05, "CI should have nonzero width")

    def test_bounds_never_exceed_0_1(self):
        for s in range(0, 21):
            lower, upper = wilson_ci(s, 20)
            self.assertGreaterEqual(lower, 0.0)
            self.assertLessEqual(upper, 1.0)

    def test_ci_narrows_with_more_trials(self):
        _, u10 = wilson_ci(5, 10)
        l10 = wilson_ci(5, 10)[0]
        width_10 = u10 - l10

        _, u100 = wilson_ci(50, 100)
        l100 = wilson_ci(50, 100)[0]
        width_100 = u100 - l100

        self.assertLess(width_100, width_10, "More trials should give narrower CI")

    def test_single_trial_pass(self):
        lower, upper = wilson_ci(1, 1)
        self.assertGreater(lower, 0.0)
        self.assertEqual(upper, 1.0)

    def test_single_trial_fail(self):
        lower, upper = wilson_ci(0, 1)
        self.assertEqual(lower, 0.0)
        self.assertLess(upper, 1.0)

    def test_custom_z_score_90pct(self):
        """90% CI (z=1.645) should be narrower than 95% CI (z=1.96)."""
        l95, u95 = wilson_ci(50, 100, z=1.96)
        l90, u90 = wilson_ci(50, 100, z=1.645)
        self.assertLess(u90 - l90, u95 - l95)


class TestBootstrapCI(unittest.TestCase):
    """Bootstrap confidence interval tests."""

    def test_empty_input(self):
        lower, upper = bootstrap_ci([])
        self.assertEqual(lower, 0.0)
        self.assertEqual(upper, 0.0)

    def test_all_same_rate(self):
        lower, upper = bootstrap_ci([0.8] * 20)
        self.assertAlmostEqual(lower, 0.8, places=2)
        self.assertAlmostEqual(upper, 0.8, places=2)

    def test_wide_spread(self):
        lower, upper = bootstrap_ci([0.0, 0.5, 1.0])
        self.assertLess(lower, 0.5)
        self.assertGreater(upper, 0.5)

    def test_single_value(self):
        lower, upper = bootstrap_ci([0.75])
        self.assertAlmostEqual(lower, 0.75, places=2)
        self.assertAlmostEqual(upper, 0.75, places=2)


class TestRunWithTrials(unittest.TestCase):
    """Multi-trial runner logic."""

    def _make_result(self, passed=True, elapsed_s=0.1):
        r = MagicMock()
        r.passed = passed
        r.elapsed_s = elapsed_s
        return r

    def test_all_pass(self):
        fn = lambda: self._make_result(True)
        tr = run_with_trials(fn, n_trials=5, test_id="T1", test_name="AllPass")
        self.assertEqual(tr.n_trials, 5)
        self.assertEqual(tr.n_passed, 5)
        self.assertEqual(tr.pass_rate, 1.0)
        self.assertTrue(all(tr.per_trial))

    def test_all_fail(self):
        fn = lambda: self._make_result(False)
        tr = run_with_trials(fn, n_trials=5, test_id="T2", test_name="AllFail")
        self.assertEqual(tr.n_passed, 0)
        self.assertEqual(tr.pass_rate, 0.0)

    def test_exception_counts_as_fail(self):
        def exploding():
            raise RuntimeError("boom")
        tr = run_with_trials(exploding, n_trials=3, test_id="T3", test_name="Boom")
        self.assertEqual(tr.n_passed, 0)
        self.assertEqual(tr.n_trials, 3)

    def test_mixed_results(self):
        counter = {"n": 0}
        def alternating():
            counter["n"] += 1
            return self._make_result(passed=(counter["n"] % 2 == 0))
        tr = run_with_trials(alternating, n_trials=10)
        self.assertEqual(tr.n_passed, 5)
        self.assertAlmostEqual(tr.pass_rate, 0.5, places=2)

    def test_defaults_for_missing_id(self):
        fn = lambda: self._make_result(True)
        tr = run_with_trials(fn, n_trials=1)
        self.assertEqual(tr.test_id, "unknown")
        self.assertEqual(tr.test_name, "unknown")

    def test_elapsed_time_averaged(self):
        fn = lambda: self._make_result(True, elapsed_s=2.0)
        tr = run_with_trials(fn, n_trials=4)
        self.assertAlmostEqual(tr.mean_elapsed_s, 2.0, places=1)


class TestTrialResultSerialization(unittest.TestCase):
    """TrialResult.to_dict() correctness."""

    def test_to_dict_keys(self):
        tr = TrialResult(
            test_id="X-001",
            test_name="Serialization Check",
            n_trials=5,
            n_passed=3,
            pass_rate=0.6,
            ci_95=(0.3, 0.85),
            per_trial=[True, False, True, True, False],
            mean_elapsed_s=1.5,
        )
        d = tr.to_dict()
        expected_keys = {
            "test_id", "test_name", "n_trials", "n_passed",
            "pass_rate", "ci_95_lower", "ci_95_upper", "mean_elapsed_s",
        }
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(d["ci_95_lower"], 0.3)
        self.assertEqual(d["ci_95_upper"], 0.85)


class TestEnhanceReport(unittest.TestCase):
    """Report enhancement with NIST metadata."""

    def test_basic_enhancement(self):
        report = {"suite": "test", "results": []}
        enhanced = enhance_report(report)
        self.assertIn("metadata", enhanced)
        self.assertTrue(enhanced["metadata"]["nist_ai_800_2_aligned"])
        self.assertFalse(enhanced["metadata"]["statistical_mode"])
        self.assertIn("nist_practices", enhanced)

    def test_with_trial_results(self):
        tr = TrialResult(
            test_id="X-001", test_name="T", n_trials=5,
            n_passed=3, pass_rate=0.6, ci_95=(0.3, 0.85),
            per_trial=[True, False, True, True, False],
            mean_elapsed_s=1.0,
        )
        report = {"suite": "test", "results": []}
        enhanced = enhance_report(report, trial_results=[tr])
        self.assertTrue(enhanced["metadata"]["statistical_mode"])
        self.assertIn("statistical_summary", enhanced)
        self.assertEqual(enhanced["statistical_summary"]["n_tests"], 1)


class TestGenerateStatisticalReport(unittest.TestCase):
    """JSON report generation."""

    def test_generates_json_file(self):
        import tempfile
        result = MagicMock()
        result.passed = True
        result.test_id = "T-001"
        result.__dataclass_fields__ = {}  # pretend it's a dataclass

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            # This will fail on asdict since it's a mock, but let's test
            # with a real dataclass instead
            tr = TrialResult(
                test_id="T-001", test_name="Report", n_trials=1,
                n_passed=1, pass_rate=1.0, ci_95=(0.5, 1.0),
                per_trial=[True], mean_elapsed_s=0.5,
            )
            generate_statistical_report([tr], [tr], "test-suite", path)
            import json
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["suite"], "test-suite")
            self.assertIn("metadata", data)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
