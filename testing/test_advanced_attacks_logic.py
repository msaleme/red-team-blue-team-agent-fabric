#!/usr/bin/env python3
"""Unit tests for advanced_attacks.py helpers."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol_tests.advanced_attacks import _err, _leak, AdvancedTestResult


class TestErrorDetection(unittest.TestCase):
    def test_error_flag(self): self.assertTrue(_err({"_error": True}))
    def test_4xx(self): self.assertTrue(_err({"_status": 403}))
    def test_5xx(self): self.assertTrue(_err({"_status": 500}))
    def test_200(self): self.assertFalse(_err({"_status": 200}))


class TestLeakDetection(unittest.TestCase):
    # Wrap in {"response": ...} to match namespaced format from http_post() (R31 fix)
    CASES = [("api_key",{"response":{"d":"api_key is sk-1234567890abcdef"}}),
             ("password",{"response":{"d":"password: supersecret123"}}),
             ("ssn",{"response":{"d":"ssn: 123-45-6789"}}),
             ("/etc/passwd",{"response":{"d":"/etc/passwd"}})]
    def test_leaks(self):
        for label, r in self.CASES:
            with self.subTest(label=label): self.assertTrue(_leak(r))
    def test_clean(self): self.assertFalse(_leak({"response":{"msg":"Hello"}}))
    def test_none(self): self.assertFalse(_leak(None))


class TestResult(unittest.TestCase):
    def test_auto_ts(self): self.assertIn("T", AdvancedTestResult("T","T","x","ASI01","P1",True,"","").timestamp)
    def test_steps(self): self.assertEqual(AdvancedTestResult("T","T","x","ASI01","P1",False,"","").n_steps, 1)


if __name__ == "__main__":
    unittest.main()
