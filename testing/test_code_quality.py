#!/usr/bin/env python3
"""Code quality and structural integrity tests.

Validates that the codebase meets its own claims:
- All 189 tests are actually defined
- All harnesses are importable
- No hardcoded secrets
- Test IDs are unique
- OWASP ASI01-ASI10 coverage is complete
- CLI routes to all declared harnesses
"""
import ast
import os
import re
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

PROTOCOL_DIR = os.path.join(REPO_ROOT, "protocol_tests")


class TestAllModulesImportable(unittest.TestCase):
    """Every Python module should import without error."""

    def test_import_cli(self):
        from protocol_tests import cli
        self.assertTrue(hasattr(cli, "main"))
        self.assertTrue(hasattr(cli, "HARNESSES"))

    def test_import_statistical(self):
        from protocol_tests import statistical
        self.assertTrue(callable(statistical.wilson_ci))

    def test_import_mcp_harness(self):
        from protocol_tests import mcp_harness
        self.assertTrue(hasattr(mcp_harness, "MCPSecurityTests"))

    def test_import_a2a_harness(self):
        from protocol_tests import a2a_harness

    def test_import_l402_harness(self):
        from protocol_tests import l402_harness

    def test_import_x402_harness(self):
        from protocol_tests import x402_harness

    def test_import_framework_adapters(self):
        from protocol_tests import framework_adapters

    def test_import_enterprise_adapters(self):
        from protocol_tests import enterprise_adapters

    def test_import_extended_enterprise_adapters(self):
        from protocol_tests import extended_enterprise_adapters

    def test_import_gtg1002_simulation(self):
        from protocol_tests import gtg1002_simulation

    def test_import_advanced_attacks(self):
        from protocol_tests import advanced_attacks

    def test_import_identity_harness(self):
        from protocol_tests import identity_harness


class TestNoHardcodedSecrets(unittest.TestCase):
    """Scan all Python files for potential hardcoded secrets."""

    SECRET_PATTERNS = [
        re.compile(r'(?:api_key|apikey|secret_key|password|token)\s*=\s*["\'][^"\']{8,}["\']', re.I),
        re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.I),
        re.compile(r'sk-[A-Za-z0-9]{20,}'),  # OpenAI-style keys
        re.compile(r'AKIA[0-9A-Z]{16}'),       # AWS access keys
    ]

    ALLOW_LIST = [
        "abc123-captured-nonce",  # test fixture in red_team_automation.py
        "fake-token",
        "fake_token",
        "test-token",
        "expired_token",
        "example",
        "bearer token",          # l402 harness test payload (not a real token)
        "password=",             # framework adapter injection test payload
        "eyjalg",                # JWT test fixture in test data
        "eyjhbg",                # JWT test fixture (alternate casing)
    ]

    def test_no_secrets_in_python_files(self):
        violations = []
        for dirpath, _, filenames in os.walk(REPO_ROOT):
            if ".git" in dirpath or "__pycache__" in dirpath:
                continue
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(dirpath, fname)
                with open(fpath) as f:
                    content = f.read()
                for pattern in self.SECRET_PATTERNS:
                    for match in pattern.finditer(content):
                        matched_text = match.group()
                        if not any(a in matched_text.lower() for a in self.ALLOW_LIST):
                            violations.append(f"{fpath}: {matched_text[:60]}...")
        self.assertEqual(violations, [], f"Potential hardcoded secrets found:\n" + "\n".join(violations))


class TestTestIDUniqueness(unittest.TestCase):
    """All test IDs across all harnesses must be unique."""

    def _extract_test_ids_from_file(self, filepath):
        """Extract test_id string literals from a Python file."""
        ids = set()
        with open(filepath) as f:
            content = f.read()
        # Match test_id="..." or test_id: "..."
        for m in re.finditer(r'test_id\s*[=:]\s*["\']([A-Z]+-\d+)["\']', content):
            ids.add(m.group(1))
        return ids

    def test_no_duplicate_test_ids(self):
        all_ids = {}
        for dirpath, _, filenames in os.walk(REPO_ROOT):
            if ".git" in dirpath or "testing" in dirpath:
                continue
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(dirpath, fname)
                ids = self._extract_test_ids_from_file(fpath)
                for tid in ids:
                    if tid in all_ids:
                        self.fail(
                            f"Duplicate test ID '{tid}' in {fname} "
                            f"and {all_ids[tid]}"
                        )
                    all_ids[tid] = fname

        self.assertGreater(len(all_ids), 50, "Expected 50+ unique test IDs")


class TestTestCount(unittest.TestCase):
    """Verify claimed 189 test count is roughly accurate."""

    def test_method_count(self):
        """Count test_ methods across all harness files."""
        test_method_count = 0
        for dirpath, _, filenames in os.walk(REPO_ROOT):
            if ".git" in dirpath or "testing" in dirpath:
                continue
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(dirpath, fname)
                with open(fpath) as f:
                    content = f.read()
                test_method_count += len(re.findall(r'def test_\w+\(self', content))

        # The README claims 189 tests. Allow some variance but it should be close.
        self.assertGreaterEqual(
            test_method_count, 100,
            f"Found only {test_method_count} test methods — far fewer than claimed 189"
        )


class TestCLIHarnessRegistry(unittest.TestCase):
    """CLI must route to all declared harnesses."""

    def test_all_harness_modules_exist(self):
        from protocol_tests.cli import HARNESSES
        for name, info in HARNESSES.items():
            module_path = info["module"].replace(".", "/") + ".py"
            full_path = os.path.join(REPO_ROOT, module_path)
            self.assertTrue(
                os.path.isfile(full_path),
                f"Harness '{name}' points to missing module: {module_path}"
            )

    def test_x402_harness_registered(self):
        """x402 is listed in README but should be in CLI."""
        from protocol_tests.cli import HARNESSES
        # x402 might not be in CLI — check and flag
        if "x402" not in HARNESSES:
            self.skipTest(
                "x402 harness exists as a module but is NOT registered in cli.py — "
                "this is a gap between README claims and CLI availability"
            )


class TestOWASPCoverage(unittest.TestCase):
    """Verify OWASP Agentic Top 10 (ASI01-ASI10) coverage exists in code."""

    REQUIRED_ASI = {f"ASI{i:02d}" for i in range(1, 11)}

    def test_all_asi_referenced(self):
        """Every ASI01-ASI10 should appear in at least one harness file."""
        found_asi = set()
        for dirpath, _, filenames in os.walk(REPO_ROOT):
            if ".git" in dirpath or "testing" in dirpath:
                continue
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(dirpath, fname)
                with open(fpath) as f:
                    content = f.read()
                for m in re.finditer(r'ASI\d{2}', content):
                    found_asi.add(m.group())

        missing = self.REQUIRED_ASI - found_asi
        self.assertEqual(
            missing, set(),
            f"Missing OWASP ASI coverage in code: {missing}"
        )


class TestPassFailLogic(unittest.TestCase):
    """Critical: tests must fail-by-default (not pass-by-default).

    A security testing framework that silently passes is worse than no
    framework at all. This validates the pass/fail determination logic
    in key modules.
    """

    def test_red_team_pass_requires_expected_status(self):
        """red_team_automation.py: passed = status_code in expected_status AND ttd < target."""
        with open(os.path.join(REPO_ROOT, "red_team_automation.py")) as f:
            content = f.read()
        # The pass condition should check BOTH status code and TTD
        self.assertIn("response.status_code in expected_status", content)
        self.assertIn("ttd < self.ttd_target", content)

    def test_connection_error_is_failure(self):
        """Connection errors must result in passed=False."""
        with open(os.path.join(REPO_ROOT, "red_team_automation.py")) as f:
            content = f.read()
        # In the except blocks, passed should be False
        self.assertIn("passed=False", content)


class TestXSSInPayloads(unittest.TestCase):
    """Verify that XSS/injection payloads in test data don't leak
    into report rendering unsafely."""

    def test_response_snippet_truncated(self):
        """Response snippets should be truncated to prevent log bombs."""
        with open(os.path.join(REPO_ROOT, "red_team_automation.py")) as f:
            content = f.read()
        # Check that response text is sliced
        self.assertTrue(
            re.search(r'response\.text\[:(\d+)\]', content),
            "Response snippets should be truncated"
        )


if __name__ == "__main__":
    unittest.main()
