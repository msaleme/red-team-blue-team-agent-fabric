"""The CVE pages in docs/cve/ must say only what the source says, and must not drift.

## Why

These pages are written for someone who has just searched a CVE identifier. A
test ID on one of them that does not exist, or that the source never pairs with
that CVE, is the fabricated-citation class this repository exists to argue
against, published where it is most likely to be acted on.

So the list is derived, not maintained. `scripts/generate_cve_pages.py` scans
`protocol_tests/` for every CVE identifier and the test IDs cited beside it, and
its rules fail unless `docs/cve/cve-test-mapping.yaml` accounts for all of them.
This file runs those rules and proves each one can fire.

## Two kinds of check

HEAD rules read only the working tree and run in every checkout. The pinned
rules need the pinned commit in the object store: they verify every quoted
source line verbatim at that revision and regenerate the pages to compare. In
the shallow clone the main CI job uses, they skip and say why; the
`pinned-provenance` job has full history and runs them for real.

## What it cannot check

Whether a documented test is apposite to the CVE beyond the source pairing them,
and whether the vulnerability facts are still current. The first is a reading
task; the second changes when NVD, GitHub or CISA change, and is re-retrieved
rather than edited.
"""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_cve_pages as gen  # noqa: E402


def _rules(fails: list[str]) -> set[str]:
    return {f.split("]")[0].lstrip("[") for f in fails}


class HeadRules(unittest.TestCase):
    """Run in every checkout, shallow or not."""

    @classmethod
    def setUpClass(cls):
        cls.mapping = gen.load(REPO_ROOT)
        cls.citations = gen.source_citations(REPO_ROOT)
        cls.defined = gen.defined_test_ids(REPO_ROOT)
        cls.catalog = gen.catalog_entries(REPO_ROOT)
        cls.harnesses = gen.cli_harnesses(REPO_ROOT)

    def _validate(self, mapping=None, citations=None):
        return gen.validate(mapping if mapping is not None else self.mapping, REPO_ROOT,
                            citations=citations if citations is not None else self.citations,
                            defined=self.defined, catalog=self.catalog,
                            harnesses=self.harnesses)

    def test_the_mapping_satisfies_every_head_rule(self):
        fails = self._validate()
        self.assertEqual(fails, [], "\n".join(fails))

    def test_the_derivation_sees_the_citations_it_should(self):
        """Anti-vacuity. A scan that finds nothing satisfies every rule above."""
        universe, pairs = self.citations
        self.assertGreaterEqual(len(universe), 10, "the CVE scan stopped matching")
        documented = {cve for cve in self.mapping["cves"]}
        self.assertTrue(documented <= set(pairs),
                        "a documented CVE has no source pairing at all")
        # One pairing of each derivation branch, so neither can silently stop.
        self.assertIn("MCP-021", pairs.get("CVE-2026-59822", {}),
                      "function-level pairing stopped working")
        self.assertIn("WT-001", pairs.get("CVE-2026-71963", {}),
                      "module-docstring fallback pairing stopped working")

    def test_the_helpers_read_real_populations(self):
        import count_tests
        self.assertEqual(len(self.defined),
                         sum(len(v) for v in count_tests.module_ids().values()),
                         "the defined-ID population disagrees with the canonical counter")
        self.assertGreater(len(self.defined), 600)
        self.assertGreater(len(self.catalog), 600)
        self.assertIn("crewai-cve", self.harnesses)
        self.assertEqual(self.harnesses["mcp"], "protocol_tests/mcp_harness.py")

    # -- each rule, seeded -------------------------------------------------

    def test_seeded_a_cited_cve_missing_from_the_mapping_fails(self):
        m = copy.deepcopy(self.mapping)
        del m["cves"]["CVE-2026-59822"]
        del m["tests"]["MCP-021"]
        self.assertIn("r1_unaccounted", _rules(self._validate(m)))

    def test_seeded_a_new_cve_in_the_source_fails(self):
        universe, pairs = self.citations
        seeded = (universe | {"CVE-2099-00001"}, pairs)
        self.assertIn("r1_unaccounted", _rules(self._validate(citations=seeded)))

    def test_seeded_an_invented_test_id_fails(self):
        m = copy.deepcopy(self.mapping)
        m["cves"]["CVE-2026-59822"]["documented"].append(
            {"test_id": "MCP-999", "why": "seeded"})
        rules = _rules(self._validate(m))
        self.assertIn("r3_defined", rules)
        self.assertIn("r3_catalog", rules)
        self.assertIn("r2_unpaired", rules)

    def test_seeded_a_real_test_the_source_does_not_pair_fails(self):
        m = copy.deepcopy(self.mapping)
        m["cves"]["CVE-2026-59822"]["documented"].append(
            {"test_id": "MCP-018", "why": "seeded"})
        self.assertIn("r2_unpaired", _rules(self._validate(m)))

    def test_seeded_an_unaccounted_source_pair_fails(self):
        universe, pairs = self.citations
        seeded = copy.deepcopy(pairs)
        seeded["CVE-2026-59822"]["MCP-018"] = {"protocol_tests/mcp_harness.py"}
        self.assertIn("r2_unaccounted_pair",
                      _rules(self._validate(citations=(universe, seeded))))

    def test_seeded_a_withheld_test_without_a_reason_fails(self):
        m = copy.deepcopy(self.mapping)
        # Seed whichever CVE withholds a test, not a named one: CVE-2026-2286
        # was named here until CREW-008 was documented and its withheld list
        # emptied. With none withheld, append one, so the seed never goes blind.
        with_withheld = [c for c, v in m["cves"].items() if v.get("withheld")]
        if with_withheld:
            m["cves"][with_withheld[0]]["withheld"][0]["reason"] = ""
        else:
            first = next(iter(m["cves"]))
            m["cves"][first]["withheld"] = [{"test_id": "CREW-002", "reason": ""}]
        self.assertIn("r2_reason", _rules(self._validate(m)))

    def test_seeded_an_unknown_cli_flag_fails(self):
        m = copy.deepcopy(self.mapping)
        m["tests"]["MCP-018"]["run"] += " --no-such-flag"
        self.assertIn("r5_flag", _rules(self._validate(m)))

    def test_seeded_prohibited_language_fails(self):
        m = copy.deepcopy(self.mapping)
        m["tests"]["MCP-018"]["notes"].append("This makes the server compliant.")
        self.assertIn("r6_language", _rules(self._validate(m)))

    # -- discoverability ---------------------------------------------------

    def test_the_index_is_linked_from_the_readmes(self):
        for rel, link in (("README.md", "docs/cve/README.md"),
                          ("docs/README.md", "cve/README.md")):
            with self.subTest(doc=rel):
                self.assertIn(f"({link})", (REPO_ROOT / rel).read_text(encoding="utf-8"))


class PinnedRules(unittest.TestCase):
    """Need the pinned commit. Enforced by the pinned-provenance CI job."""

    @classmethod
    def setUpClass(cls):
        cls.mapping = gen.load(REPO_ROOT)

    def setUp(self):
        if not gen.pin_available(REPO_ROOT, self.mapping["pinned_commit"]):
            if not gen.is_shallow(REPO_ROOT):
                self.fail("pinned_commit is not in this full-history repository")
            self.skipTest(
                "shallow clone - the pinned revision is not present, so this "
                "establishes nothing about the pages. Not a pass; enforced by the "
                "pinned-provenance job with fetch-depth: 0")

    def test_every_quote_is_verbatim_at_the_pinned_commit(self):
        fails = gen.validate_pinned(self.mapping, REPO_ROOT)
        self.assertEqual(fails, [], "\n".join(fails))

    def test_the_pages_match_fresh_output(self):
        fails = gen.drift(self.mapping, REPO_ROOT)
        self.assertEqual(fails, [], "\n".join(fails))

    def test_the_quote_check_examines_every_documented_test(self):
        """Positive control on the population the quote check iterates."""
        documented = {d["test_id"] for c in self.mapping["cves"].values()
                      for d in c["documented"]}
        self.assertEqual(documented, set(self.mapping["tests"]))
        self.assertTrue(all(self.mapping["tests"][t]["cites"] for t in documented))

    def test_seeded_a_paraphrased_quote_fails(self):
        m = copy.deepcopy(self.mapping)
        m["tests"]["MCP-021"]["cites"][0] = "LiteLLM's gateway returned an empty principal."
        self.assertIn("pin_quote", _rules(gen.validate_pinned(m, REPO_ROOT)))

    def test_seeded_a_paraphrased_verdict_fails(self):
        m = copy.deepcopy(self.mapping)
        m["tests"]["CREW-001"]["verdicts"][0]["quote"] = "Server blocked the attempt"
        self.assertIn("pin_quote", _rules(gen.validate_pinned(m, REPO_ROOT)))

    def test_seeded_a_page_that_differs_from_its_mapping_is_drift(self):
        m = copy.deepcopy(self.mapping)
        m["cves"]["CVE-2026-59822"]["product"] = "Seeded Product"
        self.assertTrue(any("CVE-2026-59822.md" in f for f in gen.drift(m, REPO_ROOT)),
                        "a page that no longer matches its mapping was not reported")


if __name__ == "__main__":
    unittest.main()
