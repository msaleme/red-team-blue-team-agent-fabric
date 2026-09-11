"""A review finding becomes a guard, or is recorded as unguardable with a reason.

## Why

On 2026-09-10 and 2026-09-11 three outside readers returned findings across
several rounds: a content reviewer, a second agent reading the workspace-trust
packet against its source, and a provenance gate that refused to review at all.
Five findings became executable guards. The rest became prose corrections with
nothing stopping them recurring, which means the next review pays to find the
same class again.

The `source` column below is the honest version of that count, and it shows the
rest: most rows are the author, and a register that only recorded outside
findings would flatter the process.

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

Twelve seeded violations, 2026-09-11, each reverted after the run. Every one
failed the intended assertion and only that one:

1.  a row with disposition `OPEN`                      -> nothing_is_unclassified
2.  `GUARDED` naming a file that does not exist        -> names_a_test_that_exists
3.  `GUARDED` naming a symbol absent from a real file  -> names_a_test_that_exists
4.  `UNGUARDABLE` with "too hard" as the reason        -> unguardable_states_why
5.  an emptied register                                -> register_is_not_empty
6.  a doc pinned to a commit no branch or tag contains -> reachable_beyond_a_local_branch
7.  a doc publishing a hash for another revision       -> hashes_match_the_pinned_revision
8.  a doc citing a bare SHA in no repository           -> resolves_here_or_names_its_repository
9.  a doc citing a real local-only commit              -> reachable_to_someone_else
10. a SHA regex that matches nothing                   -> derivation_finds_the_documents
11. the original inverted filter, restored             -> reachability_check_examines_a_non_empty_set
12. a self-permalink to an unreachable commit          -> reachable_to_someone_else

And two that had to be ACCEPTED rather than flagged, because a guard that fails
on a correct citation is one that gets muted: the same unknown SHA inside a
`github.com/<owner>/<repo>/commit/<sha>` URL, and the `/tree/<sha>` form. Both
are legitimate citations into another repository.

Seeds 6, 9 and 12 used a real dangling commit from `git commit-tree`: an object
that resolves here and nowhere else, the exact shape of the 2026-09-11 BLOCKED.

**Seed 9 is why this section exists**, and it took three attempts to seed
correctly, which is its own lesson.

It passed the first time it was run, against a check written specifically to
catch it. `_git` returns `""` on success and `git cat-file -e` prints nothing, so
`not _git("cat-file", ...)` was true for every commit that existed and the check
skipped all of them. Green on the real corpus, and unable to fail on any corpus.
The suite did not catch that. A seeded violation did.

The first repair added a positive control that derived the population by a
*separate* path from the test it was guarding. Seeding the bug back left the
control green, because the control was measuring a different instrument than the
one that could break. Both now read `_resolvable_cited()`. With the original
filter restored there, the control fails with `[] is not true` while the
reachability test still passes on an empty set, which is exactly the division of
labour a positive control is for.

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

    # --- 2026-09-11, found by seeding this file's own guards -----------------
    ("the check on cited commits filtered on `not _git(...)`, but `_git` returns "
     "\"\" on success, so it skipped every commit that resolved and examined "
     "nothing. Green on the real corpus and unable to fail on any corpus",
     "author, seeding this file 2026-09-11", GUARDED,
     "testing/test_review_findings_are_ratcheted.py: test_the_reachability_check_examines_a_non_empty_set"),
    ("PINNED_DOCS named one document while thirteen cite a commit, so the class "
     "was guarded on a sample and would have been reported as covered",
     "author 2026-09-11", GUARDED,
     "testing/test_review_findings_are_ratcheted.py: CitedCommitsResolve"),
    ("widening the accepted link forms briefly made a permalink into THIS "
     "repository count as a foreign citation, exempting from the reachability "
     "check the exact links that 404 when a commit is unreachable",
     "author 2026-09-11, caught by the examined-subtest count dropping 28 to 24",
     GUARDED,
     "testing/test_review_findings_are_ratcheted.py: test_the_reachability_check_examines_a_non_empty_set"),
]

#: Documents that pin themselves to a revision and publish source hashes.
#: Only these get the hash check. Every *other* markdown document that cites a
#: commit is covered by CitedCommitsResolve below, which is derived rather than
#: listed, because a hand-kept list of one file is how a guard covers a sample
#: and gets reported as covering the population.
PINNED_DOCS = [Path("docs/WORKSPACE-TRUST-REVIEW.md")]

#: A bare 40-hex word. The word boundary matters: it stops a 64-char sha256
#: matching on its first 40 characters.
_ANY_SHA = re.compile(r"\b[0-9a-f]{40}\b")

#: The shape that makes a foreign commit legitimate: a URL naming the repository
#: it lives in. `/commit/<sha>`, `/pull/N/commits/<sha>`, and the `/tree/<sha>`
#: and `/blob/<sha>` forms, which pin a directory or file at a revision and name
#: the repository just as well. Widened before shipping rather than after a false
#: positive: the failure mode of a too-narrow rule here is flagging a correct
#: citation, and a check that fails on a true statement is one that gets muted.
_FOREIGN_LINK = re.compile(
    r"https?://[^\s)\]]*?/([\w.-]+/[\w.-]+)/"
    r"(?:commit|commits|tree|blob|raw)/([0-9a-f]{40})")

_SHA256_LINE = re.compile(r"^([0-9a-f]{64})\s+(\S+)$", re.M)
_PINNED_COMMIT = re.compile(r"pinned to \|\s*`([0-9a-f]{40})`")


def _git(*args: str) -> str | None:
    out = subprocess.run(("git", *args), cwd=REPO_ROOT, capture_output=True,
                         text=True, check=False)
    return out.stdout.strip() if out.returncode == 0 else None


def _this_repository() -> str:
    """`owner/name` for this checkout, so a self-link is not mistaken for foreign.

    Derived, not written down. A permalink into *this* repository must still be
    reachability-checked: `.../blob/<sha>/path` is precisely the link that 404s
    when the commit it names is unreachable, which is the whole failure being
    guarded. Treating it as a foreign citation would exempt the most important
    case, and briefly did, caught by the examined-subtest count dropping.
    """
    url = _git("remote", "get-url", "origin") or ""
    m = re.search(r"[:/]([\w.-]+/[\w.-]+?)(?:\.git)?$", url.strip())
    return m.group(1).lower() if m else ""


def _commit_exists(sha: str) -> bool:
    """Does this object resolve to a commit here?

    Keyed on the return code, deliberately, and not on `_git`'s return value.
    ``git cat-file -e`` prints nothing on success, so `_git` hands back ``""``,
    and ``not _git(...)`` is then true for a commit that *does* exist. That
    inverted a filter here and made the reachability check below unable to fire:
    it skipped every resolvable commit and examined only the ones already caught
    by its sibling. Found 2026-09-11 by a seeded violation, not by the suite,
    which is the whole argument for seeding.
    """
    return subprocess.run(("git", "cat-file", "-e", f"{sha}^{{commit}}"),
                          cwd=REPO_ROOT, capture_output=True,
                          check=False).returncode == 0


def _foreign_shas(text: str) -> set[str]:
    """SHAs excused from resolving here: linked, and into a *different* repo."""
    here = _this_repository()
    return {sha for repo, sha in _FOREIGN_LINK.findall(text)
            if repo.lower() != here}


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
                self.assertTrue(
                    _commit_exists(sha),
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


class CitedCommitsResolve(unittest.TestCase):
    """Every commit a document cites is either resolvable here or names its repo.

    `PinnedProvenanceTests` above checks one document, because one document
    publishes source hashes. Thirteen carry a commit SHA. Checking the one and
    reporting the class as guarded is the error this suite is most prone to, so
    this derives the population instead of listing it.

    The rule has two branches, and the second is not a loophole. A SHA inside a
    `github.com/<owner>/<repo>/commit/<sha>` URL is a citation into a different
    repository: `docs/VERIFICATION-DESIGN-DEFECT.md` legitimately cites
    `token-bleed-benchmark` that way. It cannot be resolved from this checkout
    without a network call, so what is enforced is that it *names where it
    lives*. A bare 40-hex with no repository attached is the unverifiable case.

    No grandfather list. When written, 2026-09-11, all four same-repo SHAs cited
    across seven documents were tag-held and ancestors of main, so there was
    nothing to grandfather. If this ever needs one, that is a finding.
    """

    def setUp(self):
        if not _checkout_can_answer_provenance():
            self.skipTest(
                "shallow clone - cited commits are not present, so this "
                "establishes nothing. Not a pass; enforced by the "
                "pinned-provenance job with fetch-depth: 0")

    def _documents(self):
        for path in sorted((REPO_ROOT / "docs").rglob("*.md")):
            yield path, path.read_text(encoding="utf-8")

    def test_a_cited_commit_resolves_here_or_names_its_repository(self):
        for path, text in self._documents():
            foreign = _foreign_shas(text)
            for sha in sorted(set(_ANY_SHA.findall(text))):
                if sha in foreign:
                    continue
                rel = path.relative_to(REPO_ROOT)
                with self.subTest(doc=str(rel), sha=sha[:12]):
                    self.assertTrue(
                        _commit_exists(sha),
                        f"{rel} cites {sha[:12]}, which is not a commit in this "
                        "repository and is not inside a URL naming the repository "
                        "it does live in. A reader cannot resolve it either way.")

    def _resolvable_cited(self):
        """The commits the reachability check examines. One derivation, shared.

        `test_a_cited_commit_is_reachable_to_someone_else` iterates this, and
        `test_the_reachability_check_examines_a_non_empty_set` asserts it is not
        empty. Both must read the same list or the control is guarding a
        different instrument than the one that can break.
        """
        found = []
        for path, text in self._documents():
            foreign = _foreign_shas(text)
            for sha in sorted(set(_ANY_SHA.findall(text))):
                if sha not in foreign and _commit_exists(sha):
                    found.append((path.relative_to(REPO_ROOT), sha))
        return found

    def test_the_reachability_check_examines_a_non_empty_set(self):
        """The positive control the reachability check shipped without.

        It had a filter that skipped every commit that resolves, so it examined
        nothing and passed. Green, and worth nothing. Asserting the population is
        non-empty is what distinguishes "checked and clean" from "checked
        nothing".

        This only works because the test above iterates the same call. A first
        version derived the population separately, which made it useless for its
        one job: the bug could come back in the test's own filter and this would
        still see a healthy population and pass.
        """
        found = self._resolvable_cited()
        self.assertTrue(
            found,
            "no document cites a commit that resolves in this repository. Either "
            "the docs stopped citing commits, or the filter feeding the "
            "reachability check is inverted again and it is examining nothing.")

    def test_a_cited_commit_is_reachable_to_someone_else(self):
        """Same reason as the pinned case: a local-only commit is not evidence.

        Iterates `_resolvable_cited()` rather than re-deriving the population
        inline. Deliberate: the control below asserts that same call is
        non-empty, so the assertion and its control share one code path. When
        they had two, the inline filter here was inverted, examined nothing, and
        the separate control kept reporting a healthy population.
        """
        for rel, sha in self._resolvable_cited():
            with self.subTest(doc=str(rel), sha=sha[:12]):
                remote = _git("branch", "-r", "--contains", sha) or ""
                tags = _git("tag", "--contains", sha) or ""
                self.assertTrue(
                    remote.strip() or tags.strip(),
                    f"{rel} cites {sha[:12]}, which no remote branch or tag "
                    "contains. It resolves on this machine and nowhere else.")

    def test_the_derivation_finds_the_documents_it_should(self):
        """Anti-vacuity: a regex that matches nothing passes both tests above."""
        seen = sum(1 for _p, t in self._documents() if _ANY_SHA.search(t))
        self.assertGreaterEqual(
            seen, 7, "the SHA derivation found almost no documents, which means "
            "it stopped working rather than that the docs stopped citing commits")


if __name__ == "__main__":
    unittest.main()
