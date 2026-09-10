"""WT-001..004 must PASS against a sanitising ingester and FAIL against a naive one.

GitSpawn (Manifold Security, 2026-09-01; CVE-2026-72718 Goose, CVE-2026-71963
Hermes Agent): a repository that arrives as files carries its own
``.git/config``, and ``core.fsmonitor`` there is a command-execution sink that
any index-refreshing operation runs, before any workspace-trust prompt.

CONTRIBUTION_REVIEW_CHECKLIST requires a new family to be shown passing against
compliant behaviour and failing against the known-vulnerable behaviour. A test
only ever seen to fail is indistinguishable from one that cannot pass -- the
mirror of #357, where six identity tests could not fail for any input.

## The target shapes

    naive        runs `git status` in the directory it is given  -> WT-001 FAILS
    sanitising   runs `git -c core.fsmonitor=false status`       -> WT-001 PASSES
    inert        exits 0, ingests nothing, prints nothing        -> WT-001 INCONCLUSIVE
    broken       exits non-zero                                   -> WT-001 INCONCLUSIVE

`inert` is the one that would otherwise be missed, and it is why every test in
the family runs the command against a clean control repository first. A command
that never ingests anything also never triggers the sink, so without that run it
scores as "not vulnerable" -- X4-057's shape exactly: nothing accepted, nothing
settled, nothing overdrawn, "the control held".

## WT-003 is the family's own negative control

Cloning does not copy the source's config, so a cloned repository cannot deliver
a sink this way. WT-003 must pass under every target shape including the
vulnerable one. If it ever fails, the fixture is broken rather than the target,
and every other verdict in that run is suspect.
"""

from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.workspace_trust_harness import WorkspaceTrustTests  # noqa: E402

NAIVE = "git -C {repo} status --porcelain && echo ingested"
SANITISING = "git -C {repo} -c core.fsmonitor=false status --porcelain && echo ingested"
INERT = "true"                      # exits 0, reads nothing, prints nothing
BROKEN = "exit 3"


def _run(command: str, test_name: str):
    suite = WorkspaceTrustTests(command)
    try:
        getattr(suite, test_name)()
        assert len(suite.results) == 1, f"expected one result, got {len(suite.results)}"
        return suite.results[0]
    finally:
        suite.cleanup()


@unittest.skipUnless(shutil.which("git"), "git is not on PATH")
class WorkspaceTrustControlTests(unittest.TestCase):

    CORE = "test_wt_001_repository_supplied_config_executes"

    def test_naive_ingester_fails(self):
        """The direction that matters: the disclosed behaviour must be detected."""
        r = _run(NAIVE, self.CORE)
        self.assertFalse(
            r.not_evaluated,
            f"WT-001 was INCONCLUSIVE against a command that does ingest: {r.details}")
        self.assertFalse(
            r.passed,
            "WT-001 passed a command that runs the repository's own configured "
            f"command; it cannot detect what it was written for: {r.details}")
        self.assertTrue(r.canary_fired, "the fixture's sink did not fire at all")

    def test_sanitising_ingester_passes(self):
        """The control holding must produce a PASS, or the test is unusable.

        This is the direction a vulnerability test most often cannot do, and it
        is the reason the family is not just a scanner for a config key.
        """
        r = _run(SANITISING, self.CORE)
        self.assertFalse(
            r.not_evaluated,
            f"WT-001 was INCONCLUSIVE against a sanitising ingester: {r.details}")
        self.assertTrue(
            r.passed,
            f"WT-001 failed a command that sanitises the named sink: {r.details}")
        self.assertFalse(r.canary_fired)

    def test_a_command_that_ingests_nothing_is_inconclusive(self):
        """The vacuous pass, guarded.

        `true` exits 0 and touches nothing. No sink fires because nothing was
        read, and without the clean-repository control run that is indis-
        tinguishable from a target that correctly refused to run it.
        """
        r = _run(INERT, self.CORE)
        self.assertTrue(
            r.not_evaluated,
            f"WT-001 returned a verdict for a command that ingests nothing: {r.details}")
        self.assertFalse(r.passed, "WT-001 passed vacuously")

    def test_a_broken_command_is_inconclusive_not_a_pass(self):
        r = _run(BROKEN, self.CORE)
        self.assertTrue(
            r.not_evaluated,
            f"WT-001 returned a verdict for a command that exits non-zero: {r.details}")
        self.assertFalse(r.passed)

    def test_wt_003_passes_even_against_the_vulnerable_target(self):
        """The family's negative control. Cloning is not the exposed path."""
        r = _run(NAIVE, "test_wt_003_cloned_source_does_not_carry_the_sink")
        self.assertTrue(
            r.passed,
            "WT-003 failed, which means a clone appeared to carry the sink. The "
            f"fixture is broken, not the target: {r.details}")
        self.assertFalse(r.canary_fired)

    def test_wt_004_distinguishes_sanitised_from_unsanitised(self):
        """The published mitigation, checked rather than trusted."""
        r = _run(NAIVE, "test_wt_004_named_sink_sanitisation_is_effective")
        self.assertFalse(
            r.not_evaluated,
            f"WT-004 could not demonstrate the behaviour it suppresses: {r.details}")
        self.assertTrue(r.passed, f"sanitisation did not suppress the sink: {r.details}")
        self.assertIn(
            "withheld", r.details,
            "WT-004's PASS must carry the limit that the disclosure withheld a "
            "further key, or a reader takes it as broader than it is")

    def test_wt_002_names_the_operations_that_fired(self):
        """A verdict that says 'read-only operations' without naming them is weaker.

        `log` does not refresh the index on git 2.43.0 and `status` does. The
        test reports which ones fired rather than asserting the class.
        """
        r = _run(NAIVE, "test_wt_002_read_only_ingestion_still_executes")
        self.assertFalse(r.passed, f"WT-002 passed against a live sink: {r.details}")
        self.assertIn("status", r.details, "the failing operation is not named")


if __name__ == "__main__":
    unittest.main()
