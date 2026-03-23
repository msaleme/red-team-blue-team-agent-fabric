#!/usr/bin/env python3
"""Unit tests for advanced_attacks.py helper functions and logic.

Tests the leak-detection heuristic, error detection, and payload
generation without requiring network access.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol_tests.advanced_attacks import _err, _leak, AdvancedTestResult


class TestErrorDetection(unittest.TestCase):
    """_err() should detect errors from HTTP responses."""

    def test_explicit_error_flag(self):
        self.assertTrue(_err({"_error": True}))

    def test_4xx_status(self):
        self.assertTrue(_err({"_status": 403}))

    def test_5xx_status(self):
        self.assertTrue(_err({"_status": 500}))

    def test_error_key_in_response(self):
        self.assertTrue(_err({"error": "something went wrong"}))

    def test_200_no_error(self):
        self.assertFalse(_err({"_status": 200, "result": "ok"}))

    def test_missing_status_defaults_200(self):
        self.assertFalse(_err({"result": "ok"}))


class TestLeakDetection(unittest.TestCase):
    """_leak() should detect sensitive data in responses."""

    def test_detects_api_key(self):
        self.assertTrue(_leak({"data": "your api_key is sk-123abc"}))

    def test_detects_password(self):
        self.assertTrue(_leak({"output": "password: hunter2"}))

    def test_detects_ssn(self):
        self.assertTrue(_leak({"pii": "ssn: 123-45-6789"}))

    def test_detects_etc_passwd(self):
        self.assertTrue(_leak({"file": "/etc/passwd contents here"}))

    def test_detects_bearer_token(self):
        self.assertTrue(_leak({"auth": "Bearer eyJhbGciOiJIUzI1NiJ9"}))

    def test_detects_private_key(self):
        self.assertTrue(_leak({"key": "private_key: -----BEGIN RSA"}))

    def test_clean_response_no_leak(self):
        self.assertFalse(_leak({"message": "Hello, how can I help?"}))

    def test_none_response(self):
        self.assertFalse(_leak(None))

    def test_empty_response(self):
        self.assertFalse(_leak({}))

    def test_detects_credit_card(self):
        self.assertTrue(_leak({"data": "credit_card: 4111111111111111"}))

    def test_detects_bank_account(self):
        self.assertTrue(_leak({"info": "bank_account: 123456789"}))

    def test_detects_salary(self):
        self.assertTrue(_leak({"hr": "salary: $150,000"}))

    def test_case_insensitive_via_lower(self):
        """The function lowercases before checking, so mixed case should work."""
        self.assertTrue(_leak({"data": "API_KEY: abc123"}))


class TestAdvancedTestResult(unittest.TestCase):
    """AdvancedTestResult dataclass behavior."""

    def test_auto_timestamp(self):
        r = AdvancedTestResult(
            test_id="TEST-001", name="Test", attack_pattern="poly",
            owasp_asi="ASI01", severity="P1-High", passed=True,
            details="ok", endpoint="http://localhost",
        )
        self.assertIn("T", r.timestamp)  # ISO format contains T

    def test_default_n_steps(self):
        r = AdvancedTestResult(
            test_id="T", name="T", attack_pattern="x",
            owasp_asi="ASI01", severity="P2", passed=False,
            details="", endpoint="",
        )
        self.assertEqual(r.n_steps, 1)


if __name__ == "__main__":
    unittest.main()
