#!/usr/bin/env python3
"""Unit tests for protocol_tests.statistical module."""
import os, sys, tempfile, unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol_tests.statistical import (
    wilson_ci, bootstrap_ci, run_with_trials,
    TrialResult, enhance_report, generate_statistical_report,
)


class TestWilsonCI(unittest.TestCase):
    def test_zero_trials(self):
        self.assertEqual(wilson_ci(0, 0), (0.0, 0.0))
    def test_all_pass(self):
        l, u = wilson_ci(10, 10); self.assertGreater(l, 0.6); self.assertEqual(u, 1.0)
    def test_all_fail(self):
        l, u = wilson_ci(0, 10); self.assertEqual(l, 0.0); self.assertLess(u, 0.4)
    def test_bounds(self):
        for s in range(21):
            l, u = wilson_ci(s, 20); self.assertGreaterEqual(l, 0.0); self.assertLessEqual(u, 1.0)
    def test_narrows(self):
        w10 = wilson_ci(5, 10); w100 = wilson_ci(50, 100)
        self.assertLess(w100[1]-w100[0], w10[1]-w10[0])
    def test_monotonicity(self):
        prev = -1.0
        for s in range(11):
            l, _ = wilson_ci(s, 10); self.assertGreaterEqual(l, prev); prev = l


class TestBootstrapCI(unittest.TestCase):
    def test_empty(self): self.assertEqual(bootstrap_ci([]), (0.0, 0.0))
    def test_constant(self):
        l, u = bootstrap_ci([0.8]*20); self.assertAlmostEqual(l, 0.8, places=2)
    def test_spread(self):
        l, u = bootstrap_ci([0.0, 0.5, 1.0]); self.assertLess(l, 0.5); self.assertGreater(u, 0.5)


class TestRunWithTrials(unittest.TestCase):
    def _r(self, p=True):
        r = MagicMock(); r.passed = p; r.elapsed_s = 0.1; return r
    def test_all_pass(self): self.assertEqual(run_with_trials(lambda: self._r(True), n_trials=5).n_passed, 5)
    def test_all_fail(self): self.assertEqual(run_with_trials(lambda: self._r(False), n_trials=5).n_passed, 0)
    def test_exception(self):
        self.assertEqual(run_with_trials(lambda: (_ for _ in ()).throw(RuntimeError), n_trials=3).n_passed, 0)


class TestTrialResult(unittest.TestCase):
    def test_to_dict(self):
        tr = TrialResult("X", "T", 5, 3, 0.6, (0.3, 0.85), [True]*3+[False]*2, 1.5)
        expected = {"test_id","test_name","n_trials","n_passed","pass_rate","ci_95_lower","ci_95_upper","mean_elapsed_s"}
        self.assertEqual(set(tr.to_dict().keys()), expected)


class TestEnhanceReport(unittest.TestCase):
    def test_metadata(self):
        self.assertTrue(enhance_report({"suite":"t","results":[]})["metadata"]["nist_ai_800_2_aligned"])
    def test_statistical_mode(self):
        tr = TrialResult("X","T",5,3,0.6,(0.3,0.85),[True]*3+[False]*2,1.0)
        self.assertTrue(enhance_report({"suite":"t","results":[]}, trial_results=[tr])["metadata"]["statistical_mode"])


class TestGenerateReport(unittest.TestCase):
    def test_valid_json(self):
        import json
        tr = TrialResult("T","R",1,1,1.0,(0.5,1.0),[True],0.5)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f: path = f.name
        try:
            generate_statistical_report([tr],[tr],"suite",path)
            with open(path) as f: self.assertEqual(json.load(f)["suite"], "suite")
        finally: os.unlink(path)


if __name__ == "__main__":
    unittest.main()
