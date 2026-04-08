#!/usr/bin/env python3
"""Code quality, regression, and new-feature tests — Round 5.

Round 5 change: README-only update adding AIUC-1 crosswalk.
All prior regression tests carried forward.
"""
import os
import re
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)


# ─── IMPORTS & SECRETS ───

class TestAllModulesImportable(unittest.TestCase):
    MODULES = [
        "protocol_tests.cli", "protocol_tests.statistical",
        "protocol_tests.mcp_harness", "protocol_tests.a2a_harness",
        "protocol_tests.l402_harness", "protocol_tests.x402_harness",
        "protocol_tests.framework_adapters", "protocol_tests.enterprise_adapters",
        "protocol_tests.extended_enterprise_adapters",
        "protocol_tests.gtg1002_simulation", "protocol_tests.advanced_attacks",
        "protocol_tests.identity_harness",
        "protocol_tests.capability_profile_harness",
        "protocol_tests.harmful_output_harness",
        "protocol_tests.cbrn_harness",
        "protocol_tests.incident_response_harness",
        "protocol_tests.jailbreak_harness",
        "protocol_tests.provenance_harness",
        "protocol_tests.over_refusal_harness",
        "protocol_tests.return_channel_harness",
        "protocol_tests.cve_2026_25253_harness",
        "protocol_tests.aiuc1_compliance_harness",
        "protocol_tests.cloud_agent_harness",
        "protocol_tests.memory_harness",
    ]
    def test_all(self):
        import importlib
        for m in self.MODULES:
            with self.subTest(module=m): self.assertIsNotNone(importlib.import_module(m))


class TestNoHardcodedSecrets(unittest.TestCase):
    PATTERNS = [re.compile(r'(?:api_key|secret_key)\s*=\s*["\'][^"\']{16,}["\']', re.I),
                re.compile(r'(?<!")sk-[A-Za-z0-9]{20,}'), re.compile(r'AKIA[0-9A-Z]{16}')]
    def test_clean(self):
        v = []
        for dp, _, fns in os.walk(REPO_ROOT):
            if any(s in dp for s in [".git","__pycache__","testing"]): continue
            for fn in fns:
                if not fn.endswith(".py"): continue
                with open(os.path.join(dp, fn)) as f: c = f.read()
                for p in self.PATTERNS:
                    for m in p.finditer(c): v.append(f"{fn}: {m.group()[:60]}")
        self.assertEqual(v, [], "\n".join(v))


# ─── REGRESSIONS (all previously fixed) ───

class TestRegX402(unittest.TestCase):
    def test_registered(self):
        from protocol_tests.cli import HARNESSES
        self.assertIn("x402", HARNESSES)
    def test_harness_count(self):
        from protocol_tests.cli import HARNESSES
        self.assertEqual(len(HARNESSES), 24)
    def test_modules_exist(self):
        from protocol_tests.cli import HARNESSES
        for n, i in HARNESSES.items():
            self.assertTrue(os.path.isfile(os.path.join(REPO_ROOT, i["module"].replace(".","/") + ".py")))


class TestRegTestCount(unittest.TestCase):
    def test_cli_consistent(self):
        with open(os.path.join(REPO_ROOT, "protocol_tests", "cli.py")) as f:
            c = re.findall(r'(\d+)\s+security tests', f.read())
        self.assertEqual(len(set(c)), 1)
    def test_pyproject(self):
        with open(os.path.join(REPO_ROOT, "protocol_tests", "cli.py")) as f:
            cli = re.findall(r'(\d+)\s+security tests', f.read())
        with open(os.path.join(REPO_ROOT, "pyproject.toml")) as f:
            pyp = re.findall(r'(\d+)\s+security tests', f.read())
        if cli and pyp: self.assertEqual(cli[0], pyp[0])
    def test_readme(self):
        with open(os.path.join(REPO_ROOT, "protocol_tests", "cli.py")) as f:
            cli = re.findall(r'(\d+)\s+security tests', f.read())
        with open(os.path.join(REPO_ROOT, "README.md")) as f: readme = f.read()
        badges = re.findall(r'tests-(\d+)-', readme)
        prose = re.findall(r'\*\*(\d+)\s+security tests\*\*', readme)
        if cli and badges: self.assertEqual(cli[0], badges[0])
        if cli and prose: self.assertEqual(cli[0], prose[0])


class TestRegPassFail(unittest.TestCase):
    def test_leak_check(self):
        with open(os.path.join(REPO_ROOT, "red_team_automation.py")) as f: c = f.read()
        self.assertIn("len(leak_findings) == 0", c)
        self.assertIn("def _check_response_body_for_leaks", c)
    def test_categories(self):
        with open(os.path.join(REPO_ROOT, "red_team_automation.py")) as f: c = f.read().lower()
        for cat in ["api key","bearer","password","ssn","credit card","stack trace","sql"]:
            self.assertIn(cat, c, f"Missing: {cat}")


class TestRegDatetime(unittest.TestCase):
    def test_no_utcnow(self):
        v = []
        for dp, _, fns in os.walk(REPO_ROOT):
            if any(s in dp for s in [".git","__pycache__","testing"]): continue
            for fn in fns:
                if not fn.endswith(".py"): continue
                with open(os.path.join(dp, fn)) as f:
                    if "datetime.utcnow()" in f.read(): v.append(fn)
        self.assertEqual(v, [])


class TestRegGeopy(unittest.TestCase):
    def test_not_top_level(self):
        with open(os.path.join(REPO_ROOT, "red_team_automation.py")) as f:
            for i, line in enumerate(f, 1):
                if i > 50: break
                self.assertNotIn("from geopy", line)
    def test_still_used(self):
        with open(os.path.join(REPO_ROOT, "red_team_automation.py")) as f:
            self.assertIn("from geopy", f.read())


class TestRegCI(unittest.TestCase):
    def test_exists(self):
        self.assertTrue(os.path.isfile(os.path.join(REPO_ROOT, ".github", "workflows", "ci.yml")))
    def test_per_method_id_check(self):
        with open(os.path.join(REPO_ROOT, ".github", "workflows", "ci.yml")) as f:
            self.assertIn("method", f.read().lower())


class TestMockServer(unittest.TestCase):
    def test_exists(self):
        self.assertTrue(os.path.isfile(os.path.join(REPO_ROOT, "testing", "mock_mcp_server.py")))
    def test_importable(self):
        sys.path.insert(0, os.path.join(REPO_ROOT, "testing"))
        import mock_mcp_server
        self.assertTrue(hasattr(mock_mcp_server, "MockMCPHandler"))
    def test_no_literal_secrets(self):
        with open(os.path.join(REPO_ROOT, "testing", "mock_mcp_server.py")) as f: c = f.read()
        self.assertFalse(re.search(r'sk-prod-[a-zA-Z0-9]{10,}', c))


class TestDelayFlag(unittest.TestCase):
    def test_legacy(self):
        with open(os.path.join(REPO_ROOT, "red_team_automation.py")) as f: c = f.read()
        self.assertIn("delay_ms", c); self.assertIn("time.sleep(self.delay_ms / 1000.0)", c)
    def test_cli(self):
        with open(os.path.join(REPO_ROOT, "protocol_tests", "cli.py")) as f:
            c = f.read()
        self.assertIn("--delay", c); self.assertIn("filtered_args", c)


class TestOWASP(unittest.TestCase):
    def test_all_asi(self):
        required = {f"ASI{i:02d}" for i in range(1, 11)}
        found = set()
        for dp, _, fns in os.walk(REPO_ROOT):
            if any(s in dp for s in [".git","testing"]): continue
            for fn in fns:
                if not fn.endswith(".py"): continue
                with open(os.path.join(dp, fn)) as f:
                    for m in re.finditer(r'ASI\d{2}', f.read()): found.add(m.group())
        self.assertEqual(required - found, set())


class TestTestIDUniqueness(unittest.TestCase):
    def test_no_cross_file(self):
        all_ids = {}
        for fn in os.listdir(os.path.join(REPO_ROOT, "protocol_tests")):
            if not fn.endswith(".py"): continue
            with open(os.path.join(REPO_ROOT, "protocol_tests", fn)) as f: c = f.read()
            for tid in set(re.findall(r'test_id=["\']([A-Z][A-Z0-9]*-\d{3})["\']', c)):
                if tid in all_ids: self.fail(f"Dup '{tid}' in {fn} and {all_ids[tid]}")
                all_ids[tid] = fn
        self.assertGreater(len(all_ids), 50)


# ─── NEW: AIUC-1 Crosswalk Validation (PR#31) ───

class TestAIUC1Crosswalk(unittest.TestCase):
    """Validates the AIUC-1 crosswalk claims in the README."""

    def _readme(self):
        with open(os.path.join(REPO_ROOT, "README.md")) as f:
            return f.read()

    def test_crosswalk_section_exists(self):
        self.assertIn("AIUC-1 Crosswalk", self._readme())

    def test_claims_19_of_20(self):
        """README claims 19 of 20 testable requirements covered."""
        readme = self._readme()
        self.assertIn("19 of 20", readme)

    def test_coverage_summary_exists(self):
        """Should have a summary table with category-level coverage."""
        readme = self._readme()
        self.assertIn("Coverage Summary", readme)

    def test_requirement_ids_present(self):
        """AIUC-1 requirement IDs should be referenced (e.g., B001, C010, D004)."""
        readme = self._readme()
        req_ids = re.findall(r'[A-G]\d{3}', readme)
        self.assertGreater(len(req_ids), 10,
                           "Expected 10+ AIUC-1 requirement IDs in crosswalk")

    def test_security_section_claims_100pct(self):
        """The crosswalk claims 100% coverage of Security (B) requirements."""
        readme = self._readme()
        # Check the Security section exists with coverage claim
        self.assertIn("Security", readme)
        # Find "100%" near Security heading
        self.assertTrue(
            re.search(r'Security.*?100%', readme, re.DOTALL | re.IGNORECASE),
            "Security section should claim 100% coverage"
        )

    def test_crosswalk_references_real_test_ids(self):
        """Crosswalk should reference actual test IDs or harness names that exist."""
        readme = self._readme()
        # Extract harness/test references from crosswalk section
        crosswalk_start = readme.find("AIUC-1 Crosswalk")
        if crosswalk_start == -1:
            self.fail("No crosswalk section")
        crosswalk = readme[crosswalk_start:crosswalk_start + 5000]

        # Should reference known harness names
        harness_refs = ["MCP", "A2A", "L402", "x402", "enterprise", "identity",
                        "GTG-1002", "advanced"]
        found = sum(1 for h in harness_refs if h.lower() in crosswalk.lower())
        self.assertGreater(found, 3,
                           f"Crosswalk should reference multiple harnesses, found {found}")

    def test_test_count_consistent_in_crosswalk(self):
        """If the crosswalk mentions a test count, it should match CLI."""
        readme = self._readme()
        crosswalk_start = readme.find("AIUC-1 Crosswalk")
        crosswalk = readme[crosswalk_start:crosswalk_start + 5000]

        counts_in_crosswalk = re.findall(r'(\d+)\s+(?:executable\s+)?tests', crosswalk)
        with open(os.path.join(REPO_ROOT, "protocol_tests", "cli.py")) as f:
            cli_counts = re.findall(r'(\d+)\s+security tests', f.read())

        if counts_in_crosswalk and cli_counts:
            for c in counts_in_crosswalk:
                if int(c) > 100:  # Only check large counts that should match
                    self.assertEqual(c, cli_counts[0],
                                     f"Crosswalk says {c} tests, CLI says {cli_counts[0]}")

    def test_standards_section_includes_aiuc1(self):
        """Standards alignment section should now include AIUC-1."""
        readme = self._readme()
        # Look for AIUC-1 in the standards/alignment area
        self.assertTrue(
            re.search(r'AIUC-1.*2026', readme),
            "Standards section should reference AIUC-1 (2026)"
        )


class TestReadmeCompleteness(unittest.TestCase):
    """Carried from round 4 — README should document all major features."""

    def test_x402(self):
        with open(os.path.join(REPO_ROOT, "README.md")) as f: self.assertIn("x402", f.read())
    def test_mock_server(self):
        with open(os.path.join(REPO_ROOT, "README.md")) as f: self.assertIn("mock_mcp_server", f.read())
    def test_leak_detection(self):
        with open(os.path.join(REPO_ROOT, "README.md")) as f:
            c = f.read().lower()
        self.assertTrue("leak" in c or "response body" in c)


if __name__ == "__main__":
    unittest.main()
