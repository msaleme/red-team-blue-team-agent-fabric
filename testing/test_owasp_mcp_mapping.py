"""docs/OWASP-MCP-TOP10-MAPPING.md may cite only test IDs that exist.

The mapping is a claim about this repository. A test ID that is renamed or
removed would leave a "covers" verdict resting on nothing, which is the
fabrication the catalogs exist to prevent.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "OWASP-MCP-TOP10-MAPPING.md"
CATALOG = ROOT / "HARNESS_TEST_CATALOG.md"
ID = re.compile(r"\b(?:MCP-RC|MCP-F|MCP|CVE|MEM|PCH)-\d{3}\b")


class MappingCitesOnlyRealTests(unittest.TestCase):
    def test_every_cited_id_is_in_the_catalog(self):
        cited = set(ID.findall(DOC.read_text(encoding="utf-8")))
        known = {line.split(" | ", 1)[0] for line in CATALOG.read_text(encoding="utf-8").splitlines()
                 if " | " in line}
        self.assertTrue(cited, "the mapping cites no test IDs; the pattern is wrong")
        self.assertEqual(sorted(cited - known), [],
                         "docs/OWASP-MCP-TOP10-MAPPING.md cites test IDs not in the catalog")

    def test_the_stated_tally_matches_the_table(self):
        text = DOC.read_text(encoding="utf-8")
        rows = [r for r in text.splitlines() if r.startswith("| MCP")]
        self.assertEqual(len(rows), 10)
        count = lambda word: sum(1 for r in rows if f"**{word}" in r.split("|")[-2])
        tally = re.search(r"(\d+) of 10 entries covered, (\d+) adjacent, (\d+) not covered", text)
        self.assertIsNotNone(tally)
        self.assertEqual(tuple(map(int, tally.groups())),
                         (count("Covers"), count("Adjacent"), count("Not covered")))


if __name__ == "__main__":
    unittest.main()
