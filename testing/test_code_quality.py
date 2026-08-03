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
        "protocol_tests.x402_fireblocks_harness", "protocol_tests.ap2_harness",
        "protocol_tests.ucp_acp_harness", "protocol_tests.card_token_harness",
        "protocol_tests.settlement_finality_harness",
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
        "protocol_tests.mcp_tool_poisoning_harness",
        "protocol_tests.aiuc1_compliance_harness",
        "protocol_tests.cloud_agent_harness",
        "protocol_tests.memory_harness",
        "protocol_tests.multi_agent_harness",
        "protocol_tests.crewai_cve_harness",
        "protocol_tests.intent_contract_harness",
        "protocol_tests.mcp_supplychain",
        "protocol_tests.receipt_claim_harness",
        "protocol_tests.tool_search_harness",
        "protocol_tests.ptc_harness",
        "protocol_tests.prompt_caching_harness",
        "protocol_tests.extended_thinking_harness",
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
        self.assertEqual(len(HARNESSES), 44)
    def test_modules_exist(self):
        from protocol_tests.cli import HARNESSES
        for n, i in HARNESSES.items():
            self.assertTrue(os.path.isfile(os.path.join(REPO_ROOT, i["module"].replace(".","/") + ".py")))


class TestRegTestCount(unittest.TestCase):
    def _canonical_count(self):
        """Get the canonical test count from count_tests.py."""
        import subprocess
        out = subprocess.check_output(
            ["python3", os.path.join(REPO_ROOT, "scripts", "count_tests.py")],
            text=True
        )
        m = re.search(r'Definitive count:\s*(\d+)', out)
        self.assertIsNotNone(m, "count_tests.py must output a number")
        return m.group(1)
    def test_pyproject(self):
        count = self._canonical_count()
        with open(os.path.join(REPO_ROOT, "pyproject.toml")) as f:
            pyp = re.findall(r'(\d+)\s+security tests', f.read())
        self.assertTrue(pyp, "pyproject.toml must mention test count")
        self.assertEqual(pyp[0], count)
    def test_readme(self):
        count = self._canonical_count()
        with open(os.path.join(REPO_ROOT, "README.md")) as f: readme = f.read()
        badges = re.findall(r'tests-(\d+)-', readme)
        prose = re.findall(r'\*\*(\d+)\s+executable security tests\*\*', readme)
        if badges: self.assertEqual(badges[0], count)
        if prose: self.assertEqual(prose[0], count)
    def test_skill_md(self):
        count = self._canonical_count()
        with open(os.path.join(REPO_ROOT, "SKILL.md")) as f: skill = f.read()
        mentions = re.findall(r'(\d+)\s+executable security tests', skill)
        self.assertTrue(mentions, "SKILL.md must mention test count")
        for m in mentions: self.assertEqual(m, count)
    def test_cli_total_tests_matches_canonical(self):
        """cli.py's per-harness description counts (summed by _total_tests(),
        what `agent-security version` prints) must match the canonical count.
        Catches a harness module growing (e.g. mcp_harness.py 20->32 tests)
        without its cli.py HARNESSES description being updated to match --
        found via round evaluation: 'mcp' still said 20 tests when the
        module actually had 32, silently undercounting `agent-security
        version`'s headline number by 12."""
        from protocol_tests.cli import _total_tests
        self.assertEqual(str(_total_tests()), self._canonical_count())
    def _harness_count(self):
        from protocol_tests.cli import HARNESSES
        return str(len(HARNESSES))
    def test_readme_module_count(self):
        count = self._harness_count()
        with open(os.path.join(REPO_ROOT, "README.md")) as f: readme = f.read()
        m = re.search(r'security tests across (\d+) modules', readme)
        self.assertIsNotNone(m, "README.md must state a module count")
        self.assertEqual(m.group(1), count)
    def test_test_inventory_module_count(self):
        count = self._harness_count()
        with open(os.path.join(REPO_ROOT, "docs", "TEST-INVENTORY.md")) as f: inv = f.read()
        found = re.findall(r'security tests across (\d+) modules', inv)
        found += re.findall(r'test IDs across\s*>?\s*(\d+)\s+test-bearing', inv)
        found += re.findall(r'spans \*\*(\d+) test-bearing\s*>?\s*modules', inv)
        self.assertTrue(found, "docs/TEST-INVENTORY.md must state a module count")
        for f_ in found: self.assertEqual(f_, count)

    # --- repo-wide, because per-file guards missed ten files ----------------

    # Dated snapshots record what was true when written and must NOT be
    # rewritten to today's count. Everything else is a live claim.
    _HISTORICAL = (
        "CHANGELOG.md",
        "testing/CRITICAL_EVALUATION",
        "docs/v3.8-roadmap.md",
        "docs/v3.9-roadmap.md",
        "docs/AUDIT-R33-INDEPENDENT-REVIEW.md",   # dated external audit
        "docs/engagement/WEEKLY_HOOKS",           # dated engagement snapshots
        "docs/blog/",                             # dated posts, counts as-published
    )

    # Only phrasings that assert a *repository total*. Deliberately narrow:
    # a first attempt matched "x402 tests" and "Ed25519", which is how a guard
    # earns itself a permanent skip.
    # The leading lookbehind is what makes the general form safe: in "x402
    # tests", "L402 tests" and "Ed25519", the digits are preceded by a word
    # character, so they never match. Without it this has to be enumerated
    # phrase by phrase -- which is how the first version missed "(603 tests)"
    # in QUICKSTART and silently passed a planted stale count.
    # `/` is in the lookbehind for "AG-005/006/007 tests"; `(?<!of )` spares
    # "143 of 146 tests passing", which is a dated measurement of a subset and
    # not a claim about the repository total.
    _TOTAL_COUNT_PATTERNS = (
        r'(?<!of )(?<![\w.\-/])(\d{3})\s+(?:executable\s+|active\s+|security\s+)*tests?\b',
        r'tests-(\d{3})-',
        r'(?<![\w.\-/])(\d{3})-test\b',
    )

    def _live_docs(self):
        # This file states stale counts on purpose -- in the docstrings that
        # explain the drift, and in the planted string that proves the matcher
        # still fires. Scanning it would make the guard fail on its own evidence.
        own = os.path.relpath(__file__, REPO_ROOT)
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs
                       if d not in {".git", ".venv", "node_modules", "__pycache__", "dist", "build"}]
            for name in files:
                # .cff is here because the first version of this guard walked
                # only .md/.py/.toml, so CITATION.cff -- the file GitHub reads
                # for "Cite this repository" -- kept saying 595 tests / 43
                # modules while CI passed. Public metadata is exactly what a
                # count guard exists to protect.
                if not name.endswith((".md", ".py", ".toml", ".cff", ".rst")):
                    continue
                rel = os.path.relpath(os.path.join(root, name), REPO_ROOT)
                if rel == own:
                    continue
                if any(rel.startswith(h) or h in rel for h in self._HISTORICAL):
                    continue
                yield rel

    def test_no_stale_test_count_anywhere(self):
        """No live document may state a test count other than the canonical one.

        Added 2026-08-02 after `595 tests / 43 modules` was found in ten live
        files -- the AIUC-1 crosswalk, two AIUC-1 submission documents, the docs
        index, QUICKSTART, STRATEGY, CLAUDE.md, free_scan.py and the launch
        posts -- while README, SKILL.md and TEST-INVENTORY were correct at 603.
        Guarding three files did not guard the repository, and the submission
        documents are the ones that go to outside readers.
        """
        canonical = self._canonical_count()
        pats = [re.compile(p) for p in self._TOTAL_COUNT_PATTERNS]
        bad = []
        for rel in self._live_docs():
            try:
                text = open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                for pat in pats:
                    for m in pat.finditer(line):
                        if m.group(1) != canonical:
                            bad.append(
                                f"{rel}:{line_no} says {m.group(1)}, canonical is {canonical}")
        self.assertEqual(bad, [], "stale test counts:\n  " + "\n  ".join(bad))

    def test_the_count_guard_can_actually_fail(self):
        """The guard above must detect a planted stale count.

        `test_test_count_consistent_in_crosswalk` sat green for months because
        its assertion was unreachable. A guard that cannot fail is worse than
        no guard: it reports safety it never checked. This proves the matcher
        fires, and that the narrowing above did not narrow it into a no-op.
        """
        pats = [re.compile(p) for p in self._TOTAL_COUNT_PATTERNS]
        # Each of these is a real phrasing used somewhere in this repository.
        # The parenthetical form is the one the first version of this matcher
        # missed, which a planted-count check caught before it shipped.
        for planted in ("The harness ships 595 executable security tests today.",
                        "`full_security_audit` (595 tests)",
                        "595 tests across 44 modules",
                        "Show HN: 595-test adversarial harness",
                        "[![Tests](https://img.shields.io/badge/security%20tests-595-green.svg)]",
                        "Total: 595 security tests"):
            hits = [m.group(1) for p in pats for m in p.finditer(planted)]
            self.assertIn("595", hits, f"matcher missed a stale total in: {planted}")

        for benign in ("x402 tests cover settlement", "L402 tests", "Ed25519 signatures",
                       "CVE-2025-54136 tests"):
            self.assertEqual(
                [m.group(1) for p in pats for m in p.finditer(benign)], [],
                f"false positive on: {benign}")

    def test_no_stale_module_count_anywhere(self):
        """Same, for module counts. The 42->43 drift shipped one step behind once."""
        count = self._harness_count()
        pat = re.compile(r'(?<![\w.\-])(\d{2})\s+(?:test-bearing\s+|test\s+)?modules\b')
        bad = []
        for rel in self._live_docs():
            try:
                text = open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                for m in pat.finditer(line):
                    if m.group(1) != count:
                        bad.append(f"{rel}:{line_no} says {m.group(1)} modules, canonical is {count}")
        self.assertEqual(bad, [], "stale module counts:\n  " + "\n  ".join(bad))


class TestRegJailbreakVersionConsistency(unittest.TestCase):
    """jailbreak_harness.py cites its version in 4 places (docstring, run_all
    banner print, generate_report suite name, trial_runner suite_name) that
    must agree -- issue found in round evaluation after v3.0->v3.1 (--judge)."""
    def test_consistent_version(self):
        path = os.path.join(REPO_ROOT, "protocol_tests", "jailbreak_harness.py")
        with open(path) as f: src = f.read()
        patterns = {
            "docstring": r'Jailbreak Corpus Security Test Harness \(v(\d+\.\d+)\)',
            "banner": r'CORPUS TEST SUITE v(\d+\.\d+)',
            "report": r'"suite":\s*"Expanded Jailbreak Corpus Tests v(\d+\.\d+)"',
            "trial_suite_name": r'suite_name="Expanded Jailbreak Corpus Tests v(\d+\.\d+)"',
        }
        found = {}
        for name, pat in patterns.items():
            m = re.search(pat, src)
            self.assertIsNotNone(m, f"{name} version string not found (pattern may need updating)")
            found[name] = m.group(1)
        self.assertEqual(len(set(found.values())), 1,
            f"jailbreak_harness.py version strings disagree: {found}")


class TestRegExtendedThinkingET003(unittest.TestCase):
    """ET-003's simulate-mode leak check must not be a self-referential
    tautology (x == x, always true regardless of any real detection logic) --
    found in round evaluation after extended_thinking_harness.py was added."""
    def test_not_tautological(self):
        path = os.path.join(REPO_ROOT, "protocol_tests", "extended_thinking_harness.py")
        with open(path) as f: src = f.read()
        m = re.search(
            r'def test_et_003_redacted_thinking_exposed.*?(?=\n    def test_et_004)',
            src, re.DOTALL,
        )
        self.assertIsNotNone(m, "ET-003 test method not found")
        body = m.group(0)
        self.assertNotIn(
            'naive_output == redacted_block["data"]', body,
            "ET-003's naive_leaks check must not be a self-referential tautology (x == x)",
        )
        self.assertIn(
            "_exposes_raw_payload", body,
            "ET-003 should route detection through a real detector function, "
            "not a bare identity comparison",
        )


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
    """Validates the AIUC-1 crosswalk claims in docs/AIUC1-CROSSWALK.md (moved from README in v3.10)."""

    def _crosswalk(self):
        crosswalk_path = os.path.join(REPO_ROOT, "docs", "AIUC1-CROSSWALK.md")
        if os.path.exists(crosswalk_path):
            with open(crosswalk_path) as f:
                return f.read()
        # Fallback to README for backwards compatibility
        with open(os.path.join(REPO_ROOT, "README.md")) as f:
            return f.read()

    def _readme(self):
        with open(os.path.join(REPO_ROOT, "README.md")) as f:
            return f.read()

    def test_crosswalk_section_exists(self):
        self.assertIn("AIUC-1", self._crosswalk())

    def test_claims_19_of_20(self):
        """Crosswalk claims 19 of 20 testable requirements covered."""
        content = self._crosswalk()
        self.assertIn("19 of 20", content)

    def test_coverage_summary_exists(self):
        """Should have a summary table with category-level coverage."""
        content = self._crosswalk()
        self.assertIn("Coverage Summary", content)

    def test_requirement_ids_present(self):
        """AIUC-1 requirement IDs should be referenced (e.g., B001, C010, D004)."""
        content = self._crosswalk()
        req_ids = re.findall(r'[A-G]\d{3}', content)
        self.assertGreater(len(req_ids), 10,
                           "Expected 10+ AIUC-1 requirement IDs in crosswalk")

    def test_security_section_claims_100pct(self):
        """The crosswalk claims 100% coverage of Security (B) requirements."""
        content = self._crosswalk()
        self.assertIn("Security", content)
        self.assertTrue(
            re.search(r'Security.*?100%', content, re.DOTALL | re.IGNORECASE),
            "Security section should claim 100% coverage"
        )

    def test_crosswalk_references_real_test_ids(self):
        """Crosswalk should reference actual test IDs or harness names that exist."""
        content = self._crosswalk()
        crosswalk_start = content.find("AIUC-1")
        if crosswalk_start == -1:
            self.fail("No crosswalk section")
        crosswalk = content[crosswalk_start:crosswalk_start + 5000]

        harness_refs = ["MCP", "A2A", "L402", "x402", "enterprise", "identity",
                        "GTG-1002", "advanced"]
        found = sum(1 for h in harness_refs if h.lower() in crosswalk.lower())
        self.assertGreater(found, 3,
                           f"Crosswalk should reference multiple harnesses, found {found}")

    def test_test_count_consistent_in_crosswalk(self):
        """Every test count in the crosswalk must match the canonical count.

        This test was a no-op until 2026-08-02. It compared the crosswalk to
        `(\\d+) security tests` in cli.py -- a string cli.py does not contain --
        so `cli_counts` was always empty and the assertion block never ran. It
        passed while the crosswalk said 595 and the canonical count was 603.

        Two faults, both worth naming: it compared two documents to each other
        instead of to the source of truth, and it guarded the comparison behind
        a truthiness check, so the guard's own failure looked like a pass.
        """
        import subprocess
        out = subprocess.check_output(
            ["python3", os.path.join(REPO_ROOT, "scripts", "count_tests.py")], text=True)
        canonical = re.search(r'Definitive count:\s*(\d+)', out).group(1)

        content = self._crosswalk()
        counts = re.findall(r'(\d+)\s+(?:executable\s+)?tests', content)
        counts = [c for c in counts if int(c) > 100]
        self.assertTrue(counts, "AIUC-1 crosswalk must state a test count")
        for c in counts:
            self.assertEqual(c, canonical,
                             f"Crosswalk says {c} tests, canonical is {canonical}")

    def test_standards_section_includes_aiuc1(self):
        """Crosswalk or README should reference AIUC-1."""
        content = self._crosswalk()
        self.assertTrue(
            re.search(r'AIUC-1.*2026', content),
            "Should reference AIUC-1 (2026)"
        )


class TestReadmeCompleteness(unittest.TestCase):
    """Carried from round 4 — README or docs should document all major features."""

    def _read_all_docs(self):
        """Read README + all docs/ markdown files for completeness checks."""
        content = ""
        with open(os.path.join(REPO_ROOT, "README.md")) as f:
            content += f.read()
        docs_dir = os.path.join(REPO_ROOT, "docs")
        if os.path.isdir(docs_dir):
            for fname in os.listdir(docs_dir):
                if fname.endswith(".md"):
                    with open(os.path.join(docs_dir, fname)) as f:
                        content += f.read()
        return content

    def test_x402(self):
        self.assertIn("x402", self._read_all_docs())
    def test_mock_server(self):
        self.assertIn("mock_mcp_server", self._read_all_docs())
    def test_leak_detection(self):
        c = self._read_all_docs().lower()
        self.assertTrue("leak" in c or "response body" in c)


class TestRegVersionConsistency(unittest.TestCase):
    """Issue #5 (hardcoded version): CLI VERSION must track pyproject.toml, never a literal.

    Regression guard for the 4.3.0-on-4.4.2 drift: `agent-security version` reported a stale
    hardcoded string because cli.py did not use protocol_tests.version.get_harness_version().
    """
    def _pyproject_version(self):
        with open(os.path.join(REPO_ROOT, "pyproject.toml")) as f:
            m = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', f.read(), re.M)
        self.assertIsNotNone(m, "pyproject.toml must declare a version")
        return m.group(1)
    def test_cli_version_matches_pyproject(self):
        import protocol_tests.cli as cli
        self.assertEqual(cli.VERSION, self._pyproject_version())
    def test_cli_version_not_hardcoded_literal(self):
        with open(os.path.join(REPO_ROOT, "protocol_tests", "cli.py")) as f:
            src = f.read()
        self.assertNotRegex(
            src, r'VERSION\s*=\s*["\']\d+\.\d+',
            "cli.py VERSION must come from version.py, not a hardcoded literal (issue #5)",
        )


# ─── R33: Fireblocks x402 security-extension conformance ───

class TestRegFireblocks(unittest.TestCase):
    """Executable checks on the x402_fireblocks reference verifier (FB-001..017)."""

    def test_registered(self):
        from protocol_tests.cli import HARNESSES
        self.assertIn("x402-fireblocks", HARNESSES)

    def test_integrity_detects_recipient_tamper(self):
        from protocol_tests.x402_fireblocks_harness import (
            sign_integrity_envelope, verify_integrity)
        accepts = [{"scheme": "exact", "payTo": "0xMerchant", "maxAmountRequired": "1000000"}]
        env = sign_integrity_envelope(1, accepts, 1000, 2000)
        # Untampered verifies.
        ok, _ = verify_integrity(env, {"x402Version": 1, "accepts": accepts}, 1500)
        self.assertTrue(ok)
        # Recipient swap must break verification.
        tampered = [dict(accepts[0], payTo="0xAttacker")]
        bad, reason = verify_integrity(env, {"x402Version": 1, "accepts": tampered}, 1500)
        self.assertFalse(bad, reason)

    def test_integrity_freshness_window(self):
        from protocol_tests.x402_fireblocks_harness import (
            sign_integrity_envelope, verify_integrity)
        accepts = [{"payTo": "0xM"}]
        body = {"x402Version": 1, "accepts": accepts}
        expired = sign_integrity_envelope(1, accepts, 100, 200)
        self.assertFalse(verify_integrity(expired, body, 1000)[0])   # exp < now
        future = sign_integrity_envelope(1, accepts, 100000, 200000)
        self.assertFalse(verify_integrity(future, body, 1000)[0])    # iat > now+60

    def test_require_integrity_downgrade(self):
        from protocol_tests.x402_fireblocks_harness import verify_integrity
        body = {"x402Version": 1, "accepts": []}
        self.assertFalse(verify_integrity(None, body, 1000, require=True)[0])
        self.assertTrue(verify_integrity(None, body, 1000, require=False)[0])

    def test_did_web_ssrf_blocked(self):
        from protocol_tests.x402_fireblocks_harness import resolve_did_web_safe
        for hostile in ("did:web:169.254.169.254", "did:web:localhost",
                        "did:web:10.0.0.1", "did:web:metadata.google.internal"):
            self.assertFalse(resolve_did_web_safe(hostile)[0], hostile)
        self.assertTrue(resolve_did_web_safe("did:web:merchant.example.com")[0])

    def test_policy_engine_refusals(self):
        from protocol_tests.x402_fireblocks_harness import PolicyEngine, SpendPolicy
        eng = PolicyEngine(SpendPolicy(allowlist=frozenset({"0xM"}), per_tx_cap=1_000_000))
        self.assertEqual(eng.evaluate("0xAttacker", 1, 0)[0], "refuse")      # allowlist
        self.assertEqual(eng.evaluate("0xM", 9_000_000, 0)[0], "refuse")     # per-tx cap

    def test_batch_voucher_monotonicity_and_binding(self):
        from protocol_tests.x402_fireblocks_harness import BatchChannel
        ch = BatchChannel(escrow=10_000_000, resource_hash="rh")
        self.assertTrue(ch.redeem({"cumulative": 1_000_000, "nonce": "a",
                                   "resource_hash": "rh", "expiry": 999}, 0)[0])
        # Replay + non-monotonic + wrong resource + over-escrow all rejected.
        self.assertFalse(ch.redeem({"cumulative": 1_000_000, "nonce": "a",
                                    "resource_hash": "rh", "expiry": 999}, 0)[0])
        self.assertFalse(ch.redeem({"cumulative": 2_000_000, "nonce": "b",
                                    "resource_hash": "OTHER", "expiry": 999}, 0)[0])
        self.assertFalse(ch.redeem({"cumulative": 99_000_000, "nonce": "c",
                                    "resource_hash": "rh", "expiry": 999}, 0)[0])

    def test_suite_all_pass_in_simulate(self):
        from protocol_tests.x402_fireblocks_harness import X402FireblocksTests
        results = X402FireblocksTests(simulate=True).run_all()
        self.assertEqual(len(results), 17)
        self.assertTrue(all(r.passed for r in results),
                        [r.test_id for r in results if not r.passed])


# ─── R34: AP2 mandate-chain conformance ───

class TestRegAP2(unittest.TestCase):
    """Executable checks on the ap2 reference verifier (AP2-001..017)."""

    def test_registered(self):
        from protocol_tests.cli import HARNESSES
        self.assertIn("ap2", HARNESSES)

    def test_valid_chain_verifies(self):
        from protocol_tests.ap2_harness import _valid_chain, AP2Verifier
        openm, checkout, payment = _valid_chain(1000)
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"])
        self.assertTrue(v.verify_checkout(openm, checkout, 1000).ok)
        self.assertTrue(v.verify_payment(checkout, payment, 1000).ok)

    def test_checkout_hash_tamper_rejected(self):
        from protocol_tests.ap2_harness import _valid_chain, AP2Verifier
        openm, checkout, _ = _valid_chain(1000)
        checkout["checkout_jwt"]["total"] = 999999  # tamper, stale hash claim
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"]).verify_checkout(openm, checkout, 1000)
        self.assertFalse(v.ok)

    def test_amount_cap_escalation_rejected(self):
        from protocol_tests.ap2_harness import _valid_chain, AP2Verifier, canonical_hash
        openm, checkout, _ = _valid_chain(1000)
        checkout["cart"]["total"] = 10_000_000
        checkout["checkout_jwt"]["total"] = 10_000_000
        checkout["checkout_hash"] = canonical_hash(checkout["checkout_jwt"])
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"]).verify_checkout(openm, checkout, 1000)
        self.assertFalse(v.ok)
        self.assertIn("cap", v.reason)

    def test_unknown_constraint_fail_closed(self):
        from protocol_tests.ap2_harness import _eval_constraint
        ok, reason = _eval_constraint({"type": "totally.unknown"}, {"merchant": "m"})
        self.assertFalse(ok)
        self.assertIn("unknown", reason)

    def test_chain_link_and_replay(self):
        from protocol_tests.ap2_harness import _valid_chain, AP2Verifier
        openm, checkout, payment = _valid_chain(1000)
        # Unchained payment rejected.
        bad = dict(payment, transaction_id="some-other-cart")
        self.assertFalse(AP2Verifier().verify_payment(checkout, bad, 1000).ok)
        # Replay of same jti rejected.
        v = AP2Verifier()
        self.assertTrue(v.verify_payment(checkout, payment, 1000).ok)
        self.assertFalse(v.verify_payment(checkout, payment, 1000).ok)

    def test_symmetric_signature_rejected_asymmetric_accepted(self):
        # A Payment Mandate needs asymmetric, non-repudiable provenance. Symmetric
        # keyed-MAC (HMAC) is rejected; asymmetric schemes (incl. deterministic
        # EdDSA) are accepted — determinism is not the criterion.
        from protocol_tests.ap2_harness import _valid_chain, AP2Verifier
        openm, checkout, payment = _valid_chain(1000)
        payment["sig_scheme"] = "hmac"
        self.assertFalse(AP2Verifier().verify_payment(checkout, payment, 1000).ok)
        openm2, checkout2, payment2 = _valid_chain(1000)
        payment2["sig_scheme"] = "ed25519"
        self.assertTrue(AP2Verifier().verify_payment(checkout2, payment2, 1000).ok,
                        "asymmetric EdDSA must be accepted; determinism is not the criterion")

    def test_funding_scope_binding(self):
        from protocol_tests.ap2_harness import _valid_chain, AP2Verifier
        openm, checkout, payment = _valid_chain(1000)
        payment["payment_instrument"]["scope"]["merchant"] = "wrong_merchant"
        self.assertFalse(AP2Verifier().verify_payment(checkout, payment, 1000).ok)

    def test_suite_all_pass_in_simulate(self):
        from protocol_tests.ap2_harness import AP2MandateTests
        results = AP2MandateTests(simulate=True).run_all()
        self.assertEqual(len(results), 17)
        self.assertTrue(all(r.passed for r in results),
                        [r.test_id for r in results if not r.passed])


if __name__ == "__main__":
    unittest.main()
