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
import re
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
FRESH_COUNT = "606"      # canonical on main at the time of writing
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

    def test_prefers_the_release_count_over_the_main_count(self) -> None:
        """A description naming both counts yields the release one.

        This is the 2026-08-17 and 2026-08-24 failure. The description had
        grown to name main and the release separately, re.search took the
        FIRST match - main's - and the check compared it against the tree at
        the release tag. The description was true and the check said DRIFT.
        """
        dual = (f"AI agent security harness: {FRESH_COUNT} {_TESTS} on main, "
                f"{STALE_COUNT} in the v4.15.0 release, across MCP. v4.15.0")
        self.assertEqual(cpm.extract(dual), (STALE_COUNT, "4.15.0"))

    def test_release_count_selected_by_scope_not_by_position(self) -> None:
        """Order must not decide it, or this is the same bug facing the door."""
        dual = (f"{STALE_COUNT} in the v4.15.0 release, {FRESH_COUNT} "
                f"{_TESTS} on main. v4.15.0")
        self.assertEqual(cpm.extract(dual)[0], STALE_COUNT)

    def test_release_count_with_the_unit_spelled_out(self) -> None:
        """Both phrasings of the release figure read the same."""
        dual = (f"{FRESH_COUNT} {_TESTS} on main, {STALE_COUNT} {_TESTS} "
                f"in the v4.15.0 release. v4.15.0")
        self.assertEqual(cpm.extract(dual)[0], STALE_COUNT)


class TestRewrite(unittest.TestCase):
    """rewrite_description is the --apply path with the network removed.

    The release-event run of the workflow failed on four consecutive releases
    because the description was edited AFTER the release was published. The
    fix is to edit it BEFORE, from the releasing side, and this is the pure
    function that decides what that edit says.
    """

    WANT = {"count": FRESH_COUNT, "modules": "44", "version": "4.15.0"}

    def _ok(self, text: str) -> None:
        """Whatever the rewrite produces must satisfy the checker's own reader."""
        self.assertEqual(cpm.extract(text), (FRESH_COUNT, "4.15.0"))

    def test_release_phrase_gets_count_and_version(self) -> None:
        stale = f"harness: {STALE_COUNT} {_TESTS} in the v4.13.1 release, across MCP."
        out = cpm.rewrite_description(stale, self.WANT)
        self.assertEqual(out, f"harness: {FRESH_COUNT} {_TESTS} in the v4.15.0 release, across MCP.")
        self._ok(out)

    def test_dual_count_shape_sets_both_counts(self) -> None:
        """At release time main and the tag are one tree, so both figures agree."""
        stale = (f"{STALE_COUNT} {_TESTS} on main, {STALE_COUNT} in the "
                 f"v4.13.1 release. v4.13.1")
        out = cpm.rewrite_description(stale, self.WANT)
        self.assertEqual(out, f"{FRESH_COUNT} {_TESTS} on main, {FRESH_COUNT} in the "
                              f"v4.15.0 release. v4.15.0")
        self._ok(out)

    def test_the_real_2026_08_08_description(self) -> None:
        out = cpm.rewrite_description(REAL, self.WANT)
        self.assertIn(f"{FRESH_COUNT} {_TESTS}", out)
        self.assertTrue(out.endswith("v4.15.0"))
        self.assertNotIn(STALE_COUNT, out)
        self.assertNotIn("4.13.1", out)
        self._ok(out)

    def test_everything_else_is_untouched(self) -> None:
        """Only the figures move. The prose around them is the maintainer's."""
        stale = f"A, B, C: {STALE_COUNT} {_TESTS} in the v4.13.1 release; T1-T17 (13 direct). v4.13.1"
        out = cpm.rewrite_description(stale, self.WANT)
        self.assertTrue(out.startswith("A, B, C: "))
        self.assertIn("T1-T17 (13 direct)", out)

    def test_idempotent(self) -> None:
        once = cpm.rewrite_description(REAL, self.WANT)
        self.assertEqual(cpm.rewrite_description(once, self.WANT), once)

    def test_a_description_with_no_figures_is_returned_unchanged(self) -> None:
        """Nothing to rewrite means nothing rewritten; --apply then REFUSES,
        because extract() on the result still finds no count."""
        self.assertEqual(cpm.rewrite_description("A harness.", self.WANT), "A harness.")


class TestApply(unittest.TestCase):
    WANT = {"count": FRESH_COUNT, "modules": "44", "version": "4.15.0"}

    def _apply(self, current, patch=None, token="t"):
        patch = patch or mock.Mock()
        env = {"GITHUB_TOKEN": token} if token else {}
        with mock.patch.object(cpm, "fetch_description", lambda repo: current), \
             mock.patch.object(cpm, "_patch_description", patch), \
             mock.patch.dict(cpm.os.environ, env, clear=True):
            return cpm.apply_description("o/r", self.WANT), patch

    def test_writes_the_rewritten_description(self) -> None:
        rc, patch = self._apply(f"{STALE_COUNT} {_TESTS} in the v4.13.1 release. v4.13.1")
        self.assertEqual(rc, 0)
        patch.assert_called_once_with("o/r", f"{FRESH_COUNT} {_TESTS} in the v4.15.0 release. v4.15.0")

    def test_already_matching_writes_nothing(self) -> None:
        rc, patch = self._apply(f"{FRESH_COUNT} {_TESTS} in the v4.15.0 release. v4.15.0")
        self.assertEqual(rc, 0)
        patch.assert_not_called()

    def test_refuses_a_rewrite_the_checker_would_still_fail(self) -> None:
        """A description with no figures cannot be repaired by substitution.
        Writing it back unchanged and reporting success would be the muted
        check this file exists to prevent."""
        rc, patch = self._apply("A security harness with no figures at all.")
        self.assertEqual(rc, 1)
        patch.assert_not_called()

    def test_no_token_is_unreachable_not_success(self) -> None:
        def _raise(repo, text):
            raise PermissionError("GITHUB_TOKEN or GH_TOKEN is required")
        rc, _ = self._apply(f"{STALE_COUNT} {_TESTS} in the v4.13.1 release. v4.13.1",
                            patch=mock.Mock(side_effect=_raise), token=None)
        self.assertEqual(rc, 2)

    def test_apply_flag_runs_the_check_afterwards(self) -> None:
        """--apply is not its own verdict. main() still compares and reports."""
        argv = ["check_public_metadata.py", "--repo", "o/r", "--apply"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(cpm, "apply_description", lambda repo, want: 0) as _, \
             mock.patch.object(cpm, "fetch_description",
                               lambda repo: f"{STALE_COUNT} {_TESTS} in the v4.15.0 release. v4.15.0"), \
             mock.patch.object(cpm, "canonical_count", lambda: FRESH_COUNT), \
             mock.patch.object(cpm, "canonical_version", lambda: "4.15.0"), \
             mock.patch.object(cpm, "canonical_modules", lambda: "44"), \
             mock.patch.object(cpm, "citation_fields", lambda repo=None: ("4.15.0", "2026-08-07")), \
             mock.patch.object(cpm, "fetch_release_date", lambda r, tag: "2026-08-07"), \
             mock.patch.object(cpm, "REMOTE_READMES", ()):
            self.assertEqual(cpm.main(), 1, "a stale description after apply must still read as DRIFT")


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
             mock.patch.object(cpm, "citation_fields", lambda repo=None: (version, "2026-08-07")), \
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

    def test_dual_count_description_agrees_with_the_release_tree(self) -> None:
        """The live description shape against the release tree: exit 0.

        This returned 1 on the 2026-08-17 and 2026-08-24 scheduled runs.
        """
        dual = (f"{FRESH_COUNT} {_TESTS} on main, {STALE_COUNT} in the "
                f"v4.15.0 release. v4.15.0")
        self.assertEqual(self._run(dual, count=STALE_COUNT), 0)

    def test_a_wrong_release_count_still_exits_one(self) -> None:
        """Scoping the read must not produce a check that cannot fail.

        Here the release figure is genuinely wrong - it repeats main's count -
        and that is real drift on the claim a visitor installs against.
        """
        dual = (f"{FRESH_COUNT} {_TESTS} on main, {FRESH_COUNT} in the "
                f"v4.15.0 release. v4.15.0")
        self.assertEqual(self._run(dual, count=STALE_COUNT), 1)

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

    def test_historical_version_alongside_the_current_one_is_allowed(self) -> None:
        """The regression this presence rule exists for.

        After the profile fix merged, the check still flagged v4.4.2 on:

            ...(v4.15.0) - 97.9% pass rate measured at v4.4.2...

        That line is correct and deliberate. Pinning a measurement to the version
        it was taken at is the honesty this check protects; flagging it would
        punish the behaviour it exists to encourage.
        """
        text = ("**[red-team-blue-team-agent-fabric](https://x)** (v4.15.0) - "
                "97.9% pass rate measured at v4.4.2, not re-measured since.")
        self.assertEqual(cpm.check_surface("profile", text, self.WANT), [])

    def test_historical_version_without_the_current_one_is_flagged(self) -> None:
        """Presence is required. A line citing only old versions is still stale."""
        text = "[agent-security-harness](https://x) measured at v4.4.2 and v4.9.1."
        problems = cpm.check_surface("profile", text, self.WANT)
        self.assertEqual(len(problems), 1)
        self.assertIn("no mention of 4.15.0", problems[0])

    def test_a_stale_version_on_a_harness_line_is_flagged(self) -> None:
        text = "[red-team-blue-team-agent-fabric](https://x) (v4.9.1) is the harness."
        problems = cpm.check_surface("start-here", text, self.WANT)
        self.assertEqual(len(problems), 1)
        self.assertIn("4.9.1", problems[0])

    def test_both_on_the_same_page_alt(self) -> None:
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


class TestWorkflowRunsTheCheckerAtTheTag(unittest.TestCase):
    """The workflow checks out a release tag and runs the checker from it.

    It did not always. scripts/check_public_metadata.py was added in #360, after
    v4.15.0 was cut, and a tag is immutable, so the checker could not be present
    in the already-released tag. The first version of the workflow checked out
    the tag and ran the script from it, which would have failed with a
    file-not-found on its first scheduled run. It never surfaced because the
    workflow had not run yet, and every manual verification copied the script in
    by hand, so none of them exercised the real path.

    The fix was a copy-out-copy-back around the checkout, guarded by three tests
    here and by a fourth asserting the premise: that the checker was ABSENT from
    the latest release tag.

    v4.16.0 (2026-08-30) is the first release that contains it. The premise test
    failed the moment that shipped, the workaround was removed, and these tests
    now assert the plain shape. That is the whole point of writing a premise
    down: a workaround that outlives its reason is indistinguishable from a
    design, and nothing else in the repository would have questioned this one.
    """

    WORKFLOW = REPO_ROOT / ".github" / "workflows" / "public-metadata.yml"

    def setUp(self) -> None:
        self.text = self.WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_exists(self) -> None:
        self.assertTrue(self.WORKFLOW.is_file())

    def test_the_workflow_checks_out_a_release_tag(self) -> None:
        self.assertNotEqual(
            self.text.find('git checkout -q "$TAG"'), -1,
            "workflow must check out the release tag; a release-facing claim "
            "compared against main fails every time main is legitimately ahead")

    def test_the_preserve_workaround_is_gone(self) -> None:
        """It was needed only while the newest release predated the checker.

        Left in place it would be a copy-out-copy-back that silently shadowed
        the tag's own checker with main's, so a release could pass this check
        using a version of the checker it does not contain.
        """
        self.assertEqual(
            self.text.find("RUNNER_TEMP/check_public_metadata.py"), -1,
            "the preserve step is back. It was removed once v4.16.0 shipped "
            "carrying the checker; restoring it would run main's checker "
            "against the tag's tree.")

    def test_workflow_verifies_the_checker_survived(self) -> None:
        """A missing checker must fail with a named error, not file-not-found."""
        self.assertIn("test -f scripts/check_public_metadata.py", self.text)

    def test_the_checker_exists_at_the_latest_release_tag(self) -> None:
        """The premise, inverted 2026-08-30 when it stopped being true.

        This used to assert the checker was ABSENT from the latest release tag,
        which was the reason the workflow copied it out before checking the tag
        out and back in afterwards. The checker was added after v4.15.0, so it
        did not exist there.

        v4.16.0 is the first release that contains it. The moment that shipped,
        this test failed with "checker now exists at v4.16.0; the preserve step
        can be simplified", which is how the workaround was noticed rather than
        left in place for years. A workaround that outlives its reason is
        indistinguishable from a design.

        The assertion is now the other way round, because the workflow depends
        on it: with the preserve step gone, a release tag that does not carry
        the checker has nothing to run.
        """
        import subprocess
        tags = subprocess.run(["git", "tag", "--sort=-v:refname"],
                              capture_output=True, text=True, cwd=REPO_ROOT).stdout.split()
        tag = next((t for t in tags if re.fullmatch(r"v\d+\.\d+\.\d+", t)), None)
        if not tag:
            self.skipTest("no release tag")
        present = subprocess.run(
            ["git", "cat-file", "-e", f"{tag}:scripts/check_public_metadata.py"],
            capture_output=True, cwd=REPO_ROOT).returncode == 0
        self.assertTrue(
            present,
            f"{tag} does not carry scripts/check_public_metadata.py. The workflow "
            f"no longer preserves it across the checkout, so this tag has nothing "
            f"to run. Either the tag predates v4.16.0 or the checker was removed.")
