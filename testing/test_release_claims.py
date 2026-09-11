"""The release-claims manifest must stay true to the documents it describes (#369).

`TestRegTestCount` pins main's count into the in-tree surfaces, and
`check_public_metadata.py` pins the GitHub description. The *release* count had no
owner: main is at 606, v4.15.0 carries 603, and README states the 603 twice in prose
that nothing read. When the next release ships, `count_tests.py` moves and every
main-count surface follows it automatically, while 603 stays put and quietly becomes
a false claim about a release.

## What this test does and does not cover

It runs the manifest's **surface** checks: does every document still state the value
the manifest claims for it. That is the half that works in CI.

It deliberately does **not** run regeneration. Re-deriving 603 means checking out
`v4.15.0` and running `count_tests.py` there, and `actions/checkout@v4` defaults to
depth 1 -- the test jobs in `ci.yml` do not override it, so the tag object is not in
the clone. A test that tried would either fail on every CI run or, worse, be written
to skip quietly and turn a green suite into a claim it had not checked.

Regeneration lives in `scripts/verify_release_claims.py`, which reports whether it
actually ran and offers `--require-regenerate` for callers with a full clone. Run it
before publishing anything that quotes a release-facing number.

So: this test asserts the documents and the manifest agree. It does not assert the
manifest is *correct* -- that is what regeneration is for, and a green run here must
not be read as having reproduced any value.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import verify_release_claims  # noqa: E402

MANIFEST_PATH = REPO_ROOT / "docs" / "release-claims.json"

REQUIRED_FIELDS = {
    "id", "fact", "value", "release_tag",  "command", "value_extraction",
    "generated_on", "evidence_class", "independence_level", "limitation", "surfaces",
    "resolution",
}

#: A claim is resolved against a fixed revision, or against whatever HEAD the
#: reader has. The distinction was implicit and the two were mixed: the main
#: count paired `commit: "HEAD"` with `generated_on: "2026-09-10"`, which reads
#: as a result generated on that date and cannot be substantiated as one.
PINNED, LIVE = "pinned", "live"


class TestReleaseClaimsManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_manifest_is_present_and_non_empty(self):
        """Assert a positive expected set: an empty manifest must not read as success."""
        self.assertTrue(MANIFEST_PATH.is_file(), f"{MANIFEST_PATH} is missing")
        self.assertTrue(
            self.manifest.get("claims"),
            "the manifest declares no claims. An empty manifest passes every check below "
            "while guarding nothing, which is the exact shape of a false green.")

    def test_every_claim_declares_its_provenance(self):
        for claim in self.manifest["claims"]:
            with self.subTest(claim=claim.get("id", "<no id>")):
                missing = REQUIRED_FIELDS - set(claim)
                self.assertEqual(
                    missing, set(),
                    f"claim {claim.get('id')!r} omits {sorted(missing)}. A claim without a "
                    f"command and a revision cannot be reproduced, which is the whole point.")
                self.assertTrue(
                    claim["surfaces"],
                    f"claim {claim['id']!r} declares no surface. A claim stated in no document "
                    f"is not a release-facing fact; remove it or name where it appears.")

    def test_a_release_claim_pins_a_tag_and_a_commit(self):
        """A release-facing fact bound to a moving ref is not bound to anything."""
        release_claims = [c for c in self.manifest["claims"] if c.get("release_tag")]
        self.assertTrue(
            release_claims,
            "no claim carries a release_tag. #369 exists because release-facing facts were "
            "stated against unqualified main; at least one claim must pin a tag.")
        for claim in release_claims:
            with self.subTest(claim=claim["id"]):
                commit = claim.get("commit")
                if commit is None:
                    # Deliberate, 2026-08-30. The rule's intent is "not a MOVING
                    # ref", and a release tag is not one. Requiring a literal SHA
                    # beside a tag is also self-referential: the SHA a reader
                    # needs is the SHA of the commit that contains the manifest
                    # naming it, so it can only ever be written one commit stale.
                    # That is exactly how v4.17.0 shipped a manifest naming the
                    # 4.16.0 release merge -- reproduced 608 and PASSED, because
                    # the ancestor carried the same count, so the number was
                    # right and the provenance was false.
                    #
                    # `verify_release_claims.check_tag_binds_commit` resolves the
                    # tag, and asserts equality whenever a SHA IS pinned, so the
                    # drift this test was written for still fails loudly.
                    continue
                self.assertNotIn(
                    commit, ("HEAD", "main", ""),
                    f"claim {claim['id']!r} names tag {claim['release_tag']!r} but commit "
                    f"{commit!r}. A tagged claim binds a tag or a SHA, never a moving ref.")
                self.assertRegex(
                    commit, r"^[0-9a-f]{40}$",
                    f"claim {claim['id']!r} pins a commit, so it must be a full 40-char SHA.")

    def test_a_release_claim_names_the_version_the_tree_is_at(self):
        """The manifest inside a tag must be about THAT tag.

        Four consecutive releases shipped a manifest bound to their predecessor:

            v4.21.0  pyproject 4.21.0  manifest v4.20.0   (and the previous VALUE, 611)
            v4.21.1  pyproject 4.21.1  manifest v4.21.0
            v4.21.2  pyproject 4.21.2  manifest v4.21.1
            v4.21.3  pyproject 4.21.3  manifest v4.21.2

        The cause is ordering, not carelessness. The release PR bumps the version, the
        tag is cut at that commit, and a SEPARATE later PR rebinds the claim -- so the
        tree the tag points at always names the release before it. `main` reconciles a
        few minutes later, which is why nothing noticed: every check that runs on main
        sees an agreeing pair.

        This is not cosmetic. `docs/release-claims.json` states its purpose as binding
        each release-facing fact to "the revision, command, and value that produced it",
        and inside every release it was bound to the wrong revision. It also propagates:
        an external nightly sentinel pinned at v4.21.3 was sent by this manifest to
        regenerate a value at v4.21.2, a tag its shallow clone could not contain, and
        reported the check as not reproduced (2026-09-10).

        Asserting against `pyproject.toml` rather than against `git tag` is deliberate,
        twice over. It needs no tag object, so it holds in the depth-1 clone CI uses.
        And it fires in the RELEASE COMMIT ITSELF -- the moment the version bumps and
        the manifest has not followed -- which is the only place the fix belongs. On any
        other commit the two already agree and this is silent.

        Rebind the claim in the release PR. See docs/RELEASING.md.
        """
        from protocol_tests.version import get_harness_version

        want = f"v{get_harness_version()}"
        release_claims = [c for c in self.manifest["claims"] if c.get("release_tag")]
        self.assertTrue(release_claims, "no claim carries a release_tag")

        for claim in release_claims:
            with self.subTest(claim=claim["id"]):
                self.assertEqual(
                    claim["release_tag"], want,
                    f"claim {claim['id']!r} is bound to {claim['release_tag']!r} but this "
                    f"tree is version {want}. If this is the release PR, rebind the claim "
                    f"here rather than in a follow-up -- a tag cut now would carry a "
                    f"manifest about the previous release. See docs/RELEASING.md.")

                # The prose is a surface too. v4.21.0 shipped a `fact` naming both the
                # wrong tag and the wrong value, so agreeing on release_tag alone would
                # have let half of that through.
                self.assertIn(
                    want, claim.get("fact", ""),
                    f"claim {claim['id']!r} is bound to {want} but its `fact` reads "
                    f"{claim.get('fact', '')!r}. The sentence a reader sees must name the "
                    f"same release the claim is bound to.")

    def test_every_surface_states_the_manifest_value(self):
        """The check that would have caught 603 going stale."""
        from verify_release_claims import check_surfaces

        for claim in self.manifest["claims"]:
            for status, label, detail in check_surfaces(claim):
                with self.subTest(check=label):
                    self.assertEqual(status, "PASS", f"{label}: {detail}")


if __name__ == "__main__":
    unittest.main()

class TestAnUnresolvableTagIsNotSilentlyHead(unittest.TestCase):
    """A declared tag that does not exist must SKIP, never regenerate at HEAD.

    `regenerate()` resolved `commit or (tag and tag_commit(tag)) or "HEAD"`, so
    an absent tag made the middle term falsy and the command ran against HEAD --
    while the label still read `regenerate @ <tag>`. The run then reported
    "reproduced 608 @ v4.18.0" for a tag that did not exist.

    Same defect as the one this manifest was built to catch, one level up: the
    number is right and the provenance is false.
    """

    def test_every_tagless_claim_regenerates_at_head(self):
        """The REAL manifest, not a synthetic claim -- and it runs in CI.

        REGENERATE was treated as unavailable in CI because `actions/checkout@v4`
        clones at depth 1 and a tag-pinned claim needs the tag object. That is
        true for tag-pinned claims and false for HEAD-pinned ones, which need no
        history at all. The blanket assumption switched off a check that would
        have worked, and SURFACE alone cannot catch a stale value: it only asks
        whether the document agrees with the manifest, so a manifest and a
        sentence that are stale in the same direction confirm each other.

        That is exactly what happened on 2026-09-01. `main-test-count` said 608
        after main moved to 611, README said "`main` is at **608**", SURFACE
        reported PASS, and the stale-count guard in `test_code_quality.py` could
        not see the sentence because its pattern requires the word "tests" after
        the number. Two guards agreeing, both wrong.
        """
        manifest = verify_release_claims._load()
        tagless = [c for c in manifest["claims"] if not c.get("release_tag")]
        self.assertTrue(tagless, "no HEAD-pinned claim to regenerate -- if the "
                                 "manifest stopped carrying one, this guard is "
                                 "now vacuous and needs rewriting, not deleting")
        for claim in tagless:
            with self.subTest(claim=claim["id"]):
                status, label, detail = verify_release_claims.regenerate(claim)
                self.assertNotEqual(
                    status, verify_release_claims.SKIP,
                    f"{label}: a HEAD-pinned claim needs no tag and must not "
                    f"skip in a shallow clone -- {detail}")
                self.assertEqual(
                    status, verify_release_claims.OK,
                    f"{label}: {detail}")

    def test_the_regenerate_guard_can_actually_fail(self):
        """Seeded. A guard over the real manifest that cannot fail is decoration."""
        claim = {"id": "seeded", "command": "python3 scripts/count_tests.py",
                 "value": "1", "value_extraction": r"Definitive count:\s*(\d+)"}
        status, label, detail = verify_release_claims.regenerate(claim)
        self.assertEqual(status, verify_release_claims.BAD,
                         f"a claim of 1 test reproduced as PASS: {label} {detail}")

    def test_a_missing_tag_skips_and_says_it_reproduced_nothing(self):
        claim = {"id": "synthetic", "release_tag": "v0.0.0-no-such-tag",
                 "command": "python3 scripts/count_tests.py",
                 "value": "608", "value_extraction": r"Definitive count:\s*(\d+)"}
        status, label, detail = verify_release_claims.regenerate(claim)
        self.assertEqual(status, verify_release_claims.SKIP, f"{label}: {detail}")
        self.assertIn("NOT reproduced", detail)
        self.assertIn("v0.0.0-no-such-tag", label)

    def test_a_claim_with_no_tag_still_regenerates_at_head(self):
        """The positive control. Main-branch claims must keep working."""
        claim = {"id": "synthetic-head",
                 "command": "python3 scripts/count_tests.py",
                 "value": None, "value_extraction": r"Definitive count:\s*(\d+)"}
        status, label, _ = verify_release_claims.regenerate(claim)
        self.assertIn("HEAD", label)
        self.assertNotEqual(status, verify_release_claims.SKIP)


class TestClaimResolutionIsHonest(unittest.TestCase):
    """A dated result must not be bound to a floating ref, and a pinned claim
    must carry the output that produced it.

    Both findings came from an outside reader grading evidence classes on
    2026-09-11 (F3 and F4). Neither was an E1-to-E2 inflation: the labels were
    right. They were provenance-boundary defects, which is a quieter failure and
    the reason they survived several careful readings.
    """

    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_every_claim_declares_how_it_resolves(self):
        for claim in self.manifest["claims"]:
            with self.subTest(claim=claim.get("id")):
                self.assertIn(
                    claim.get("resolution"), (PINNED, LIVE),
                    f"claim {claim.get('id')!r} does not say whether it resolves against a "
                    f"fixed revision or against the reader's HEAD. That is the distinction "
                    f"the two rules below depend on.")

    def test_a_live_claim_carries_no_generation_date(self):
        """F3. `commit: HEAD` plus a fixed date asserts a dated observation.

        HEAD is deliberately dynamic and the surface check regenerates tagless
        claims at current HEAD, which is right for a current-inventory statement.
        It cannot substantiate the claim as a result produced on a past date
        without an immutable resolved revision and retained output. So a live
        claim states no date; if a dated observation is wanted, pin it.
        """
        live = [c for c in self.manifest["claims"] if c.get("resolution") == LIVE]
        self.assertTrue(live, "no live claim: this rule is guarding nothing")
        for claim in live:
            with self.subTest(claim=claim["id"]):
                self.assertIsNone(
                    claim.get("generated_on"),
                    f"claim {claim['id']!r} resolves live but carries "
                    f"generated_on={claim.get('generated_on')!r}. Either drop the date, or "
                    f"make it pinned with a resolved_revision and a retained artifact.")

    def test_a_pinned_claim_retains_the_output_that_produced_it(self):
        """F4. A command plus an expected value is a recipe, not a result."""
        pinned = [c for c in self.manifest["claims"] if c.get("resolution") == PINNED]
        self.assertTrue(pinned, "no pinned claim: this rule is guarding nothing")
        for claim in pinned:
            cid = claim["id"]
            with self.subTest(claim=cid):
                rev = claim.get("resolved_revision") or ""
                self.assertRegex(
                    rev, r"^[0-9a-f]{40}$",
                    f"claim {cid!r} is pinned but names no immutable 40-character revision")

                art = claim.get("evidence_artifact")
                self.assertIsInstance(
                    art, dict,
                    f"claim {cid!r} is pinned and retains no evidence_artifact. The manifest's "
                    f"stated purpose is to bind a fact to the value that produced it; a command "
                    f"and an expected value are instructions for reproducing it, not the "
                    f"observation itself.")

                path = REPO_ROOT / art["path"]
                self.assertTrue(path.is_file(), f"{cid}: artifact {art['path']} is missing")

                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(
                    actual, art["sha256"],
                    f"{cid}: {art['path']} hashes to {actual[:12]}, manifest says "
                    f"{art['sha256'][:12]}. The retained output changed after it was recorded.")

                self.assertEqual(
                    art.get("revision"), rev,
                    f"{cid}: the artifact records revision {art.get('revision')!r} but the "
                    f"claim is pinned to {rev!r}. An artifact from a different revision is "
                    f"not evidence for this claim.")
                self.assertEqual(
                    art.get("command"), claim["command"],
                    f"{cid}: the artifact records a different command than the claim declares")

                text = path.read_text(encoding="utf-8", errors="replace")
                found = re.search(claim["value_extraction"], text)
                self.assertIsNotNone(
                    found,
                    f"{cid}: the claim's own value_extraction pattern does not match anything "
                    f"in the retained output. The artifact does not record this claim's value.")
                self.assertEqual(
                    found.group(1), claim["value"],
                    f"{cid}: the retained output says {found.group(1)!r} where the claim says "
                    f"{claim['value']!r}.")

    def test_the_artifact_is_not_a_stub(self):
        """Anti-vacuity: a one-line file satisfies every hash and regex check above."""
        for claim in self.manifest["claims"]:
            art = claim.get("evidence_artifact")
            if not art:
                continue
            with self.subTest(claim=claim["id"]):
                body = (REPO_ROOT / art["path"]).read_text(encoding="utf-8", errors="replace")
                self.assertGreater(
                    len(body.splitlines()), 10,
                    f"{claim['id']}: the retained artifact is a handful of lines. A transcript "
                    f"trimmed to just the answer is the recipe problem again, one layer down.")
