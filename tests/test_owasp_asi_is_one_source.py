"""OWASP ASI assignment has exactly one source, and it is well-formed.

An external review (2026-09-07) found 81 tests whose ASI primary was wrong,
three independent assignment paths (inline tags, requirement-level keys in
configs/aiuc1_mapping.yaml, the threat crosswalk), coverage tables that read
the requirement path rather than the tags, and four HITL rows whose category
changed with the OUTCOME. All were possible because nothing pinned the
properties below.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_tests.asi_inventory import VALID, by_category, corpus_asi, sites, unattributed_literals

ROOT = Path(__file__).resolve().parents[1]
#: Floor on tagged tests so a locator that stops matching fails loudly.
KNOWN_TAGGED = 400


#: Tests in the corpus (scripts/count_tests.py's definition) that carry no
#: `owasp_asi` tag at any site the inventory can see. Seeded 2026-09-07.
#: May shrink as tests are tagged; must never grow -- a new test either
#: carries a tag (`""` for no primary) or fails this suite.
SEEDED_UNTAGGED_COUNT = 22
GRANDFATHERED_UNTAGGED: frozenset[str] = frozenset({
    "AIUC-C003a",
    "AIUC-C003b",
    "AIUC-C004a",
    "AIUC-C004b",
    "AIUC-C004c",
    "AIUC-E001",
    "AIUC-E002",
    "AIUC-E003",
    "AIUC-F002a",
    "AIUC-F002b",
    "AIUC-F002c",
    "AIUC-F002d",
    "RCL-001",
    "RCL-002",
    "RCL-003",
    "RCL-004",
    "RCL-005",
    "RCL-006",
    "RCL-007",
    "RCL-009",
    "RCL-010",
    "RCL-011"
})


def _corpus_ids() -> set[str]:
    """Exactly count_tests' definition, so this and the public 623 agree."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("ct", ROOT / "scripts" / "count_tests.py")
    ct = importlib.util.module_from_spec(spec); spec.loader.exec_module(ct)
    ids: set[str] = set()
    for f in sorted((ROOT / "protocol_tests").glob("*.py")):
        src = f.read_text(encoding="utf-8")
        found = set(ct.TEST_ID_RE.findall(src)) | set(ct.ARG_ID_RE.findall(src))
        ids |= {i for i in found if not i.endswith(ct._ERR_SUFFIX) and i not in ct.EXCLUDE_IDS}
    return ids


class OneSource(unittest.TestCase):
    def test_the_inventory_found_something(self):
        self.assertGreaterEqual(len(corpus_asi()), KNOWN_TAGGED)

    def test_every_tag_is_a_published_category_or_no_primary(self):
        bad = {t: v for t, v in corpus_asi().items() if v not in VALID}
        self.assertEqual(bad, {}, "tags outside ASI01..ASI10 / ''")

    def test_no_test_is_tagged_differently_at_different_sites(self):
        """A category must not vary with the outcome. corpus_asi() raises on
        disagreement; this makes the failure name every site."""
        bad = {t: ss for t, ss in sites().items() if len({v for _, _, v in ss}) > 1}
        self.assertEqual(bad, {}, "outcome-dependent tagging")

    def test_a_helper_cannot_introduce_a_category_its_module_does_not_use(self):
        """A literal ASI on a call with a parameter test_id (a shared emitter)
        must be a value some attributed test in that module already carries.
        Otherwise a helper can move rows into a category nothing pins -- the
        HITL inconclusive path said ASI08 while every attributed HITL row
        said ASI09, and the plain sites() check could not see it."""
        attributed: dict[str, set[str]] = {}
        for tid, ss in sites().items():
            for fname, _, v in ss:
                attributed.setdefault(fname, set()).add(v)
        bad = {}
        for fname, values in unattributed_literals().items():
            extra = values - attributed.get(fname, set()) - {""}
            if extra:
                bad[fname] = sorted(extra)
        self.assertEqual(bad, {}, "helper literals outside the module's attributed set")

    def test_positive_controls_carry_no_primary(self):
        c = corpus_asi()
        over_refusal = {t for t in c if t.startswith("OR-")}
        self.assertGreaterEqual(len(over_refusal), 20, "OR-* not found; vacuous")
        self.assertEqual({t: c[t] for t in over_refusal if c[t]}, {},
                         "an over-refusal positive control claims ASI coverage")

    def test_content_safety_rows_carry_no_primary(self):
        c = corpus_asi()
        for prefix in ("CBRN-",):
            rows = {t for t in c if t.startswith(prefix)}
            self.assertGreaterEqual(len(rows), 4, f"{prefix} not found; vacuous")
            self.assertEqual({t: c[t] for t in rows if c[t]}, {})

    def test_hitl_lures_are_human_agent_trust(self):
        c = corpus_asi()
        for t in ("HITL-005", "HITL-006", "HITL-007", "HITL-008"):
            self.assertEqual(c.get(t), "ASI09", t)

    def test_the_aiuc1_mapping_carries_no_asi_assignment(self):
        text = (ROOT / "configs" / "aiuc1_mapping.yaml").read_text()
        # (?m): without MULTILINE, ^ matches only at the start of the file and
        # this assertion could never fail. An injection that re-added the key
        # left the failure count unchanged, which is how that was noticed.
        self.assertNotRegex(text, r"(?m)^\s*owasp_asi\s*:", "a second assignment path returned")

    def test_no_consumer_reads_an_asi_off_the_requirement_index(self):
        for f in ("scripts/html_report.py", "scripts/evidence_pack.py", "scripts/top10_failures.py"):
            src = (ROOT / f).read_text()
            self.assertNotRegex(src, r'req(?:_def|_data)?\.get\("owasp_asi"', f)
            self.assertIn("asi_inventory", src, f"{f} does not use the one source")

    def test_every_published_category_is_represented_in_the_inventory_keys(self):
        """The renderers iterate the ten categories; each must be a valid key
        even when its list is empty -- a thin category is a true statement,
        a missing one is a rendering gap."""
        bc = by_category()
        for asi in sorted(VALID - {""}):
            self.assertIsInstance(bc.get(asi, []), list)


if __name__ == "__main__":
    unittest.main()


class UntaggedIsARatchet(unittest.TestCase):
    def test_the_corpus_was_found(self):
        self.assertGreaterEqual(len(_corpus_ids()), 600, "count_tests regexes matched nothing")

    def test_every_corpus_test_is_tagged_or_grandfathered(self):
        untagged = _corpus_ids() - set(corpus_asi())
        new = untagged - GRANDFATHERED_UNTAGGED
        self.assertEqual(sorted(new), [], "a test entered the corpus without an "
                         "owasp_asi tag; tag it ('' for no primary) rather than adding it here")

    def test_the_grandfather_list_never_grew(self):
        self.assertLessEqual(len(GRANDFATHERED_UNTAGGED), SEEDED_UNTAGGED_COUNT)

    def test_grandfathered_names_are_still_untagged_and_still_exist(self):
        """A stale name silently shrinks the checked set; a tagged one should be removed."""
        corpus, tagged = _corpus_ids(), set(corpus_asi())
        for t in sorted(GRANDFATHERED_UNTAGGED):
            with self.subTest(t):
                self.assertIn(t, corpus, "no longer in the corpus; remove from the list")
                self.assertNotIn(t, tagged, "now tagged; remove from the list")
