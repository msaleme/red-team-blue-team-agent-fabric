"""A review finding becomes a guard, or is recorded as unguardable with a reason.

## Why

On 2026-09-10 two external reviewers returned roughly a dozen findings across
four rounds. Five became executable guards. The rest became prose corrections
with nothing stopping them recurring, which means the next review pays to find
the same class again.

That is the difference between a review as an event and a review as an asset.
This file is the ledger that forces the distinction: a finding may not sit
unclassified, and a finding claimed as GUARDED must name a test that exists.

The register may GROW, unlike the grandfather lists elsewhere in this suite.
New reviews produce new findings and that is the system working. What may not
grow is `OPEN`.

## What this does not do

It does not check that a guard is any good. A test named here could be vacuous;
`test_static_detectors_can_fire.py` is where a detector proves it can fire. This
file only asserts that the claimed guard exists and that nothing is unclassified.

It is not in that module's `DETECTORS` registry, and the registry's derivation
agrees: it reads named paths rather than globbing source for a forbidden
construction, so there is no seeded-source pair to build. The obligation to prove
it can fire does not go away with the registry, so:

## Can it fire

Seven seeded violations, 2026-09-11, each reverted after the run. Every one
failed the intended assertion and only that one:

1. a row with disposition `OPEN`                      -> nothing_is_unclassified
2. `GUARDED` naming a file that does not exist        -> names_a_test_that_exists
3. `GUARDED` naming a symbol absent from a real file  -> names_a_test_that_exists
4. `UNGUARDABLE` with "too hard" as the reason        -> unguardable_states_why
5. an emptied register                                -> register_is_not_empty
6. a doc pinned to a commit no branch or tag contains -> reachable_beyond_a_local_branch
7. a doc publishing a hash for another revision       -> hashes_match_the_pinned_revision

Seed 6 used a real dangling commit from `git commit-tree`, which is the exact
shape of the 2026-09-11 BLOCKED: an object that resolves here and nowhere else.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTING = REPO_ROOT / "testing"

GUARDED = "guarded"          #: an executable test asserts this cannot recur
UNGUARDABLE = "unguardable"  #: prose or judgement; no test can hold it
OPEN = "open"                #: not yet decided. Must always be empty.

#: (finding, source, disposition, guard-or-reason)
#: Append as reviews land. Move rows from OPEN; never delete a row to make this pass.
REVIEW_FINDINGS: list[tuple[str, str, str, str]] = [
    # --- 2026-09-10, MEM-013..016 review rounds -----------------------------
    ("MEM-013/016 queried the stored set, not the in-force set, so a store that "
     "retains revoked records for audit scored as failing to enforce",
     "external review 2026-09-10", GUARDED,
     "testing/test_memory_revocation_enforcement.py: audit_visible store mode"),
    ("the oracle was a substring check and could not tell a policy being endorsed "
     "from one named in order to disclaim it",
     "external review 2026-09-10", GUARDED,
     "testing/test_memory_revocation_enforcement.py: informative_correct store mode"),
    ("MEM-013/014/015 names claimed retrieval, ranking and action; the assertions "
     "read only the agent's response",
     "external review 2026-09-10", UNGUARDABLE,
     "a name is prose. The observation boundary is stated in the module docstring "
     "and in the control suite; no test can assert a name is honest. The nearest "
     "mechanical cousin is the WT guard below, which works only because the claim "
     "was about which methods call a specific helper."),

    # --- 2026-09-10, workspace-trust ----------------------------------------
    ("the WorkspaceTrustTests docstring said all four tests invoke the command "
     "under test; one does",
     "second-agent packet review 2026-09-10", GUARDED,
     "testing/test_workspace_trust_controls.py: WhichTestsObserveTheTargetTests"),
    ("the reading guide's 'no network calls' claim could not hold while the "
     "harness runs an arbitrary caller command through a shell",
     "second-agent packet review 2026-09-10", UNGUARDABLE,
     "a claim about what a caller's command may do is not decidable from this "
     "repository. Withdrawn from the document instead of narrowed."),
    ("the guide enumerated subprocess calls in the file and missed run_provenance, "
     "reached only via --report, which runs git against the harness checkout",
     "second-agent packet review 2026-09-10", UNGUARDABLE,
     "enumerating an executed dependency path is a reading task. Recorded here so "
     "the next reviewer of that document knows to walk imports, not just the file."),
    ("cited line ranges in the guide were off by four, written from stale offsets",
     "author self-check 2026-09-10", GUARDED,
     "testing/test_review_findings_are_ratcheted.py: PinnedProvenanceTests"),

    # --- 2026-09-10, cross-cutting ------------------------------------------
    ("twenty-nine harnesses printed INCONCLUSIVE as FAIL on the console while the "
     "JSON report was correct",
     "author, while measuring sweep poles 2026-09-10", GUARDED,
     "testing/test_console_reports_the_third_state.py"),
    ("every release tag shipped a release-claims manifest bound to the previous "
     "release, because the rebinding PR landed after the tag",
     "author 2026-09-10", GUARDED,
     "testing/test_release_claims.py: test_a_release_claim_names_the_version_the_tree_is_at"),
    ("the packet advertised commit SHAs that existed only on a local branch, so an "
     "external reviewer could not resolve them and correctly returned BLOCKED",
     "external provenance gate 2026-09-11", GUARDED,
     "testing/test_review_findings_are_ratcheted.py: PinnedProvenanceTests"),
]

#: Documents that pin themselves to a revision and publish source hashes.
PINNED_DOCS = [Path("docs/WORKSPACE-TRUST-REVIEW.md")]

_SHA256_LINE = re.compile(r"^([0-9a-f]{64})\s+(\S+)$", re.M)
_PINNED_COMMIT = re.compile(r"pinned to \|\s*`([0-9a-f]{40})`")


def _git(*args: str) -> str | None:
    out = subprocess.run(("git", *args), cwd=REPO_ROOT, capture_output=True,
                         text=True, check=False)
    return out.stdout.strip() if out.returncode == 0 else None


def _checkout_can_answer_provenance() -> bool:
    """Does this checkout hold enough history to judge a pinned revision?

    ``actions/checkout`` defaults to ``fetch-depth: 1``, which fetches no tags
    and no history. In that clone the pinned commit is not present at all, so
    every question below returns "no" for a reason that has nothing to do with
    the document. A check that fails on a correct document is a check somebody
    deletes, so it declares itself unable to decide instead. That is the same
    three-state discipline the harnesses use, applied to the suite.

    Verified 2026-09-11 against a real ``git clone --depth 1``: without this the
    three provenance tests fail on the current, correct document. Note that
    ``git branch -r`` is *not* the signal, it still prints ``origin/HEAD`` there.

    The same signal and the same reasoning already appear in
    ``tests/test_owasp_agentic_mapping.py::test_assessed_commit_is_reachable_from_head``,
    which is why the ``pinned-provenance`` CI job exists: a skip is not a pass,
    so something must run these at full depth.
    """
    return (_git("rev-parse", "--is-shallow-repository") or "true") != "true"


class ReviewFindingsRegister(unittest.TestCase):

    def test_nothing_is_unclassified(self):
        """OPEN must be empty. A finding with no disposition is a finding nobody owns."""
        unclassified = [f for f, _, d, _ in REVIEW_FINDINGS if d == OPEN]
        self.assertEqual(
            unclassified, [],
            "these review findings have no disposition. Either write a guard and "
            "mark them GUARDED, or mark them UNGUARDABLE with the reason it cannot "
            f"be tested: {unclassified}")

    def test_every_guarded_finding_names_a_test_that_exists(self):
        """A claimed guard that does not exist is worse than no guard.

        It reads as covered in the register and holds nothing in the suite.
        """
        missing = []
        for finding, _src, disp, guard in REVIEW_FINDINGS:
            if disp != GUARDED:
                continue
            rel = guard.split(":")[0].strip()
            path = REPO_ROOT / rel
            if not path.is_file():
                missing.append(f"{rel} (for: {finding[:60]})")
                continue
            symbol = guard.split(":", 1)[1].strip() if ":" in guard else ""
            symbol = symbol.split(" ")[0] if symbol else ""
            if symbol and symbol not in path.read_text(encoding="utf-8"):
                missing.append(f"{rel} lacks {symbol!r} (for: {finding[:50]})")
        self.assertEqual(missing, [], "guards named in the register but absent: " + str(missing))

    def test_every_unguardable_finding_states_why(self):
        """'Cannot be tested' is a claim, and it needs a reason a reader can dispute."""
        for finding, _src, disp, reason in REVIEW_FINDINGS:
            if disp != UNGUARDABLE:
                continue
            with self.subTest(finding=finding[:50]):
                self.assertGreater(
                    len(reason), 60,
                    "an UNGUARDABLE row needs a real reason, not a label. Say what "
                    "about the finding is prose, judgement, or outside this repo.")

    def test_the_register_is_not_empty(self):
        """Anti-vacuity: an empty register satisfies every assertion above."""
        self.assertGreater(len(REVIEW_FINDINGS), 5)
        self.assertTrue(any(d == GUARDED for _, _, d, _ in REVIEW_FINDINGS))
        self.assertTrue(any(d == UNGUARDABLE for _, _, d, _ in REVIEW_FINDINGS))


class PinnedProvenanceTests(unittest.TestCase):
    """A document that pins itself to a revision must pin to a reachable one.

    Written 2026-09-11 after an external reviewer returned BLOCKED rather than a
    review: the packet advertised two commit SHAs that existed only on an
    unpushed local branch. Every hash in the document was correct and none of it
    could be checked, which is the same as publishing no provenance at all.

    Local reachability is the strongest thing a test can assert offline. A commit
    contained by a remote-tracking branch or a tag will survive a branch deletion
    and resolve for someone else; one contained by neither will not.

    Reachability, deliberately, and not ancestry. The sibling guard on the OWASP
    report asserts the pinned commit is an ancestor of HEAD, which is right for
    permalinks into mainline history. It would be wrong here: `39fd4d2` was
    squash-merged, so it is **not** an ancestor of HEAD, and the two `wt-*` tags
    are the only reason it still resolves for a reviewer. Tagging before the
    squash is what makes the citation survive; asserting ancestry would punish
    having done that correctly.
    """

    def setUp(self):
        if not _checkout_can_answer_provenance():
            self.skipTest(
                "shallow clone - the pinned revision is not present, so this "
                "establishes nothing about the document. Not a pass; enforced "
                "by the pinned-provenance job with fetch-depth: 0")

    def _pinned_docs(self):
        return [(p, (REPO_ROOT / p).read_text(encoding="utf-8"))
                for p in PINNED_DOCS if (REPO_ROOT / p).is_file()]

    def test_a_pinned_document_names_a_commit_that_exists(self):
        docs = self._pinned_docs()
        self.assertTrue(docs, "no pinned documents found; PINNED_DOCS is stale")
        for path, text in docs:
            m = _PINNED_COMMIT.search(text)
            with self.subTest(doc=str(path)):
                self.assertIsNotNone(m, f"{path} declares no pinned commit")
                sha = m.group(1)
                self.assertIsNotNone(
                    _git("cat-file", "-e", f"{sha}^{{commit}}"),
                    f"{path} pins {sha[:12]}, which is not a commit in this repository")

    def test_the_pinned_commit_is_reachable_beyond_a_local_branch(self):
        """The BLOCKED case. A local-only SHA is unverifiable provenance."""
        for path, text in self._pinned_docs():
            m = _PINNED_COMMIT.search(text)
            if not m:
                continue
            sha = m.group(1)
            with self.subTest(doc=str(path)):
                remote = _git("branch", "-r", "--contains", sha) or ""
                tags = _git("tag", "--contains", sha) or ""
                self.assertTrue(
                    remote.strip() or tags.strip(),
                    f"{path} pins {sha[:12]}, which no remote branch or tag contains. "
                    "Nobody outside this machine can resolve it. Push the branch or "
                    "tag the commit before offering the document as evidence.")

    def test_published_source_hashes_match_the_pinned_revision(self):
        """The document's hashes must describe the revision it claims, not HEAD."""
        for path, text in self._pinned_docs():
            m = _PINNED_COMMIT.search(text)
            if not m:
                continue
            sha = m.group(1)
            pairs = _SHA256_LINE.findall(text)
            with self.subTest(doc=str(path)):
                self.assertTrue(pairs, f"{path} publishes no source hashes")
                for want, rel in pairs:
                    blob = subprocess.run(("git", "show", f"{sha}:{rel}"), cwd=REPO_ROOT,
                                          capture_output=True, check=False)
                    self.assertEqual(
                        blob.returncode, 0,
                        f"{rel} does not exist at the pinned revision {sha[:12]}")
                    got = hashlib.sha256(blob.stdout).hexdigest()
                    self.assertEqual(
                        got, want,
                        f"{path} publishes {want[:12]} for {rel}, but that file at "
                        f"{sha[:12]} hashes to {got[:12]}. The document describes a "
                        "revision it is not pinned to.")


if __name__ == "__main__":
    unittest.main()
