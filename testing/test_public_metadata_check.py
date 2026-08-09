"""Offline tests for scripts/check_public_metadata.py.

The script itself talks to the GitHub API. These do not: they exercise the
parsing and the exit-code contract with no network, so the suite stays runnable
offline and a network outage cannot turn into a green check.

The contract that matters is the three-way exit code. A checker that collapses
"unreachable" into "passed" is the defect this repository has now found five
times (v4.13.1, #348, #350, #351, #355), so it is asserted here explicitly.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_public_metadata", REPO_ROOT / "scripts" / "check_public_metadata.py")
cpm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cpm)

# Split so no live file carries a literal "<count> executable tests" that is not
# the canonical one. test_no_stale_test_count_anywhere scans this file too, and
# adding an exemption for it would weaken a guard to accommodate its own test.
STALE_COUNT = "603"      # correct for v4.15.0, stale against main
FRESH_COUNT = "604"      # canonical on main at the time of writing
_TESTS = "executable tests"

REAL = (f"AI agent security harness for adversarial testing: {STALE_COUNT} {_TESTS} "
        "across MCP, A2A, x402/L402, decision governance, benchmark integrity, "
        "human-in-the-loop, skill supply chain. Commit-pinned OWASP Agentic v1.1 "
        "T1-T17 coverage (13 direct, 4 partial, 0 not evidenced), AIUC-1 "
        "2026-Q1/Q2 crosswalk 19/20 testable, NIST AI 800-2 aligned. v4.13.1")


class TestExtract(unittest.TestCase):
    def test_reads_the_real_description(self) -> None:
        self.assertEqual(cpm.extract(REAL), (STALE_COUNT, "4.13.1"))

    def test_missing_count_is_none_not_zero(self) -> None:
        """A description with no count must not silently read as 0 or pass."""
        count, version = cpm.extract("A harness. v4.15.0")
        self.assertIsNone(count)
        self.assertEqual(version, "4.15.0")

    def test_missing_version_is_none(self) -> None:
        count, version = cpm.extract(f"{FRESH_COUNT} {_TESTS}, no version stated")
        self.assertEqual(count, FRESH_COUNT)
        self.assertIsNone(version)

    def test_empty_description(self) -> None:
        self.assertEqual(cpm.extract(""), (None, None))

    def test_does_not_match_a_bare_number(self) -> None:
        """'603' alone is not a count claim; the unit has to be present."""
        self.assertIsNone(cpm.extract("603 things happened here")[0])


class TestExitCodes(unittest.TestCase):
    def _run(self, description=None, exc=None, count=None, version="4.15.0"):
        """Run main() with every outside call stubbed.

        main() reads four things beyond the description: canonical modules,
        CITATION.cff, the release date, and two remote READMEs. All are stubbed
        so this stays offline. An earlier version of this helper stubbed only
        the description, and the suite silently started making live requests.
        """
        count = count or FRESH_COUNT
        argv = ["check_public_metadata.py", "--repo", "o/r"]
        fetch = mock.Mock(side_effect=exc) if exc else mock.Mock(return_value=description)
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(cpm, "fetch_description", fetch), \
             mock.patch.object(cpm, "canonical_count", lambda: count), \
             mock.patch.object(cpm, "canonical_version", lambda: version), \
             mock.patch.object(cpm, "canonical_modules", lambda: "44"), \
             mock.patch.object(cpm, "citation_fields", lambda: (version, "2026-08-07")), \
             mock.patch.object(cpm, "fetch_release_date", lambda r, tag: "2026-08-07"), \
             mock.patch.object(cpm, "REMOTE_READMES", ()):
            return cpm.main()

    def test_agreement_exits_zero(self) -> None:
        self.assertEqual(self._run(f"{FRESH_COUNT} {_TESTS} ... v4.15.0"), 0)

    def test_stale_count_exits_one(self) -> None:
        self.assertEqual(self._run(f"{STALE_COUNT} {_TESTS} ... v4.15.0"), 1)

    def test_stale_version_exits_one(self) -> None:
        self.assertEqual(self._run(f"{FRESH_COUNT} {_TESTS} ... v4.13.1"), 1)

    def test_todays_real_drift_would_have_been_caught(self) -> None:
        """The exact 2026-08-08 state: 603/v4.13.1 against a 603/v4.15.0 tree."""
        self.assertEqual(self._run(REAL, count=STALE_COUNT, version="4.15.0"), 1)

    def test_missing_fields_exit_one(self) -> None:
        self.assertEqual(self._run("A security harness."), 1)

    def test_unreachable_exits_two_not_zero(self) -> None:
        """The whole point. Unreachable is not agreement."""
        rc = self._run(exc=urllib.error.URLError("no route to host"))
        self.assertEqual(rc, 2)
        self.assertNotEqual(rc, 0, "an unread description must never report as a pass")

    def test_http_error_exits_two(self) -> None:
        err = urllib.error.HTTPError("u", 403, "rate limited", {}, None)
        self.assertEqual(self._run(exc=err), 2)


class TestSurfaceScoping(unittest.TestCase):
    """A check that fails on a true statement gets muted, so scope matters."""

    WANT = {"count": STALE_COUNT, "modules": "44", "version": "4.15.0"}
    _OLD_COUNT = "470"     # what the profile README said
    _OLD_MODULES = "29"    # and its module count
    _MODULES = "modules"

    def test_flags_every_stale_figure(self) -> None:
        text = (f"The harness has {self._OLD_COUNT} {_TESTS} across "
                f"{self._OLD_MODULES} {self._MODULES}.")
        problems = cpm.check_surface("profile", text, self.WANT)
        self.assertEqual(len(problems), 2)
        self.assertTrue(any("test count" in p and self._OLD_COUNT in p for p in problems))
        self.assertTrue(any("module count" in p and self._OLD_MODULES in p for p in problems))

    def test_silence_is_allowed(self) -> None:
        """A page that states no figure is not required to state one."""
        self.assertEqual(cpm.check_surface("x", "No numbers here at all.", self.WANT), [])

    def test_correct_figures_pass(self) -> None:
        text = f"{self.WANT['count']} {_TESTS} across {self.WANT['modules']} {self._MODULES}."
        self.assertEqual(cpm.check_surface("x", text, self.WANT), [])

    def test_another_packages_version_is_not_flagged(self) -> None:
        """The regression this scoping exists for.

        The first live run flagged v0.7.0 on start-here. That is
        constitutional-agent on PyPI and entirely correct.
        """
        text = "[constitutional-agent](https://pypi.org/project/constitutional-agent/) (**v0.7.0**)"
        self.assertEqual(cpm.check_surface("start-here", text, self.WANT), [])

    def test_a_stale_version_on_a_harness_line_is_flagged(self) -> None:
        text = "[red-team-blue-team-agent-fabric](https://x) (v4.9.1) is the harness."
        problems = cpm.check_surface("start-here", text, self.WANT)
        self.assertEqual(len(problems), 1)
        self.assertIn("4.9.1", problems[0])

    def test_both_on_the_same_page(self) -> None:
        """Other-package version ignored, harness version flagged, same document."""
        text = ("[constitutional-agent](https://pypi.org/project/constitutional-agent/) (**v0.7.0**)\n"
                "[agent-security-harness](https://x) v4.9.1\n")
        problems = cpm.check_surface("start-here", text, self.WANT)
        self.assertEqual(len(problems), 1)
        self.assertIn("4.9.1", problems[0])
        self.assertNotIn("0.7.0", problems[0])


class TestCitationFields(unittest.TestCase):
    def test_reads_the_repo_citation(self) -> None:
        """CITATION.cff is the file GitHub reads for 'Cite this repository'."""
        version, date = cpm.citation_fields()
        self.assertIsNotNone(version, "CITATION.cff must state a version")
        self.assertIsNotNone(date, "CITATION.cff must state date-released")

    def test_citation_version_matches_the_tree(self) -> None:
        version, _ = cpm.citation_fields()
        self.assertEqual(version, cpm.canonical_version())


if __name__ == "__main__":
    unittest.main()
