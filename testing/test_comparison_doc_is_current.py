"""`docs/COMPARISON.md` must not present a frozen table and a live one as one snapshot.

R5-09 (fifth external review, 2026-09-09): the document was headed April 2026
and said MCP had 18 tests and behavioural profiling was "Planned (v3.10)", while
its ASI section described the September remap and the README described the
current, much broader MCP surface. Nothing in it was fabricated. A competitor
table nobody had re-examined and self-product facts that move every release were
mixed together under one date, so a reader could not tell which cells had been
looked at.

Two claims are enforced here, and they are different claims:

    the competitor half is FROZEN, and says so, with its date
    the self-product half is DERIVED, and matches the catalog today

The second is the testable one. Every count under "This suite" is recomputed
from `scripts/count_tests.py`'s own regexes and from
`protocol_tests/asi_inventory.py`, through the derivation the document names in
its own third column -- so adding a row to the table adds a check, and a row
whose modules do not sum to its number fails.

What this file does NOT do is check the competitor cells. They cannot be
recomputed from this repository, which is exactly why they have to be dated and
declared frozen rather than quietly carried forward.
"""
from __future__ import annotations

import pathlib
import re
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "COMPARISON.md"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

#: The date the self-product half was last regenerated. Stated in the document,
#: asserted here, so the two cannot drift apart silently.
DERIVED_ON = "2026-09-08"
#: The date the competitor half was taken. It is allowed to be old. It is not
#: allowed to be undeclared.
COMPETITORS_FROZEN_ON = "April 2026"


def _catalog_counts() -> dict[str, int]:
    """{module filename: unique test IDs}, from `count_tests.module_ids()`.

    Asked, not reimplemented. An earlier draft of this file carried its own
    copy of that glob and its three exclusion rules -- a second source of truth
    for the number `count_tests.py` exists to be the only source of, which is
    the defect one level up from the one this file exists to catch. It also put
    this file into the source-scanning population of
    `test_static_detectors_can_fire.py`, which flagged it on its first full run.
    That queue was right: this test does not scan source, it reads a catalog.
    """
    import count_tests as ct

    return {name: len(ids) for name, ids in ct.module_ids().items()}


def _unique_test_ids() -> set[str]:
    import count_tests as ct

    ids: set[str] = set()
    for found in ct.module_ids().values():
        ids |= found
    return ids


def _rows(text: str, section: str) -> list[list[str]]:
    """Markdown table rows of the section beginning with heading *section*."""
    start = text.index(section)
    end = text.find("\n## ", start + 1)
    body = text[start:end if end != -1 else len(text)]
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("|") or set(line) <= set("|- "):
            continue
        out.append([c.strip() for c in line.strip("|").split("|")])
    return out


class TestTheDocumentSeparatesFrozenFromDerived(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOC.read_text(encoding="utf-8")

    def test_the_competitor_half_is_declared_frozen_with_its_date(self) -> None:
        self.assertIn(f"FROZEN, {COMPETITORS_FROZEN_ON}", self.text,
                      "the competitor table must say it is frozen and when")
        self.assertIn("Not re-examined since", self.text,
                      "the document must say no competitor was re-examined, "
                      "rather than leaving a reader to assume it was")

    def test_the_derived_half_carries_the_date_it_was_regenerated(self) -> None:
        self.assertIn(f"DERIVED, regenerated {DERIVED_ON}", self.text)
        self.assertIn("scripts/count_tests.py", self.text,
                      "the derived section must name what it was derived from")

    def test_no_headline_date_stands_for_the_whole_document(self) -> None:
        """The first line said "(April 2026)" and covered both halves.

        A single date over a document holding two ages is the R5-09 defect in
        one line, so the title carries none and each section carries its own.
        """
        first = self.text.splitlines()[0]
        self.assertNotRegex(
            first, r"\b20\d\d\b",
            f"the title dates the whole document: {first!r}. Each half is dated "
            f"in its own section, because they are not the same age.")


class TestEverySelfProductCountMatchesTheCatalog(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOC.read_text(encoding="utf-8")
        self.counts = _catalog_counts()

    def test_each_surface_row_sums_to_the_modules_it_names(self) -> None:
        rows = [r for r in _rows(self.text, "## This suite -- DERIVED")
                if len(r) == 3 and re.search(r"\d", r[1])]
        self.assertGreaterEqual(len(rows), 5, "the derived surface table is missing")
        for surface, claimed, derivation in rows:
            with self.subTest(surface=surface):
                stated = int(re.sub(r"[^0-9]", "", claimed))
                modules = re.findall(r"`([^`]+)`", derivation)
                self.assertTrue(modules, f"{surface} names no derivation")
                if modules == ["scripts/count_tests.py"]:
                    self.assertEqual(
                        stated, len(_unique_test_ids()),
                        "the total row disagrees with the catalog's unique test IDs")
                    continue
                for module in modules:
                    self.assertIn(
                        module, self.counts,
                        f"{surface} is derived from {module}, which bears no tests")
                self.assertEqual(
                    stated, sum(self.counts[m] for m in modules),
                    f"{surface} claims {stated} tests; the modules it names hold "
                    f"{sum(self.counts[m] for m in modules)}")

    def test_the_asi_table_matches_the_inventory(self) -> None:
        from protocol_tests.asi_inventory import by_category

        derived = {k: len(v) for k, v in by_category().items()}
        rows = _rows(self.text, "### OWASP Agentic Top 10")
        stated = {}
        for row in rows:
            if len(row) != 3 or not row[2].isdigit():
                continue
            key = row[0] if row[0].startswith("ASI") else ""
            stated[key] = int(row[2])
        self.assertEqual(
            stated, derived,
            "the ASI table and `asi_inventory.by_category()` disagree")

    def test_the_gap_between_the_corpus_and_the_catalog_is_stated(self) -> None:
        """Untagged is a third state, and the document has to name the number.

        The ASI rows sum to the tagged corpus, not to the test total. Leaving
        that unsaid reads as an arithmetic error in one direction, or as
        untagged tests being silently reported as "no primary" in the other.
        """
        from protocol_tests.asi_inventory import corpus_asi

        corpus = len(corpus_asi())
        self.assertIn(
            f"sum to {corpus}", self.text,
            f"the ASI rows sum to {corpus}; the document must say so, and say "
            f"why that is not the {len(_unique_test_ids())} unique test IDs")

    def test_no_capability_is_still_claimed_as_planned_after_it_shipped(self) -> None:
        """`Planned (v3.10)` outlived the script it was waiting for."""
        self.assertNotIn("Planned (v3.10)", self.text)
        for path in re.findall(r"Shipped: `([^`]+)`", self.text):
            with self.subTest(path=path):
                self.assertTrue((REPO / path).exists(),
                                f"the document says {path} shipped; it is not in the tree")


if __name__ == "__main__":
    unittest.main()
