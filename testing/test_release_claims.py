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

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

MANIFEST_PATH = REPO_ROOT / "docs" / "release-claims.json"

REQUIRED_FIELDS = {
    "id", "fact", "value", "release_tag",  "command", "value_extraction",
    "generated_on", "evidence_class", "independence_level", "limitation", "surfaces",
}


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

    def test_every_surface_states_the_manifest_value(self):
        """The check that would have caught 603 going stale."""
        from verify_release_claims import check_surfaces

        for claim in self.manifest["claims"]:
            for status, label, detail in check_surfaces(claim):
                with self.subTest(check=label):
                    self.assertEqual(status, "PASS", f"{label}: {detail}")


if __name__ == "__main__":
    unittest.main()
