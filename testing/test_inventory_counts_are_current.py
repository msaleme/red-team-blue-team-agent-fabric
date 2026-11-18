"""Per-module counts in `docs/TEST-INVENTORY.md` must match `scripts/count_tests.py`.

Found 2026-11-18 by a coverage-gap review: the file carried three different MCP
Protocol figures at once (32 in the "reconciled" block, 31 in the module summary
table, 18 in a section heading) while `count_tests.py` said 34, and two x402
figures (54 and 52, against 66). The existing guards in `test_code_quality.py`
check the totals and the module count, so every per-module figure could drift
while the banner stayed correct. `docs/README.md` restated nine more.

The repair is in two parts, matching the two ways a restated number survives:

    tables that exist to carry a count are DERIVED, and checked here
    headings and tree comments that only repeated a count no longer carry one

A row is checked against the label `count_tests.MODULE_NAMES` gives its module,
or against an explicit sum in `COMPOSITE_ROWS`. A row that maps to neither
FAILS rather than being skipped: a guard that ignores labels it does not know
goes blind on the first rename.
"""
from __future__ import annotations

import pathlib
import re
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = REPO / "docs" / "TEST-INVENTORY.md"
DOCS_README = REPO / "docs" / "README.md"
ROOT_README = REPO / "README.md"
sys.path.insert(0, str(REPO / "scripts"))

#: Rows that report the sum of several count_tests modules.
COMPOSITE_ROWS = {
    "Enterprise Platforms": ("Enterprise Platforms (core)", "Enterprise Platforms (extended)"),
}

#: `| Module | 34 |` in the reconciled block (quoted with `>`), and
#: `| **Module** | 34 | layer | description |` in the summary table.
_ROW = re.compile(r"^>?\s*\|\s*(\*\*)?(?P<label>[^|*]+?)(\*\*)?\s*\|\s*(?P<n>\d+)\s*\|", re.M)
#: A heading that restates a test count, e.g. `### A2A (Agent-to-Agent) - 13 tests`.
_HEADING_COUNT = re.compile(r"^#{1,6} .*\b\d+ tests\b", re.M)
#: A tree comment that restates one, e.g. `# MCP (JSON-RPC 2.0) - 32 tests`.
_TREE_COUNT = re.compile(r"^[│ ]*[├└]── \S+\.py\s+#.*\b\d+ tests\b", re.M)


def catalog_by_label() -> dict[str, int]:
    """{count_tests display label: unique test IDs}. Asked, not reimplemented."""
    import count_tests as ct

    return {ct.MODULE_NAMES.get(name, name): len(ids) for name, ids in ct.module_ids().items()}


def _section(text: str, start_marker: str, end_marker: str | None) -> str:
    start = text.index(start_marker)
    end = text.index(end_marker, start) if end_marker else len(text)
    return text[start:end]


def count_tables(text: str) -> dict[str, str]:
    """The two tables in TEST-INVENTORY that exist to state per-module counts."""
    return {
        "reconciled block": _section(text, "**Per-module counts, reconciled", "Where an enumerated ID table"),
        "module summary table": _section(text, "## Test Harness Modules (representative summary)", None),
    }


def row_problems(table: str, catalog: dict[str, int]) -> list[str]:
    """Every count-bearing row that disagrees with the catalog or maps to nothing."""
    problems = []
    rows = list(_ROW.finditer(table))
    if not rows:
        return ["no count rows found; the table moved or its format changed"]
    for m in rows:
        label, stated = m.group("label").strip(), int(m.group("n"))
        if label in catalog:
            expected = catalog[label]
        elif label in COMPOSITE_ROWS:
            expected = sum(catalog[part] for part in COMPOSITE_ROWS[label])
        else:
            problems.append(f"{label!r}: not a count_tests label and not in COMPOSITE_ROWS")
            continue
        if stated != expected:
            problems.append(f"{label!r}: document says {stated}, count_tests says {expected}")
    return problems


#: README "How This Differs" table: {row label: [(pattern with one number group, count_tests labels summed)]}.
#: Found 2026-11-18 after #697: that PR derived TEST-INVENTORY but this table still said MCP
#: protocol (32) and x402 52. Every number in a row listed here is checked; a listed row or
#: pattern that is not found FAILS, so a reworded row cannot go quietly unchecked.
_MCP = ("MCP Protocol", "MCP Supply-Chain", "MCP Tool Poisoning Reproduction")
README_ROWS = {
    "MCP coverage": [(r"\*\*(\d+) tests:", _MCP),
                     (r"protocol \((\d+)\)", ("MCP Protocol",)),
                     (r"supply-chain \((\d+)\)", ("MCP Supply-Chain",)),
                     (r"tool-poisoning repro \((\d+)\)", ("MCP Tool Poisoning Reproduction",))],
    "A2A coverage": [(r"\*\*(\d+) tests\*\*", ("A2A Protocol",))],
    "L402/x402 coverage": [(r"\*\*(\d+) tests\*\*", ("L402 Payment", "x402 Payment")),
                           (r"L402 (\d+)", ("L402 Payment",)),
                           (r"x402 (\d+)\)", ("x402 Payment",))],
    "Merchant journey (UCP/ACP)": [(r"\*\*(\d+) tests:", ("UCP/ACP Merchant Journey",))],
    "Funding instrument (Visa TAP / MC Agentic Tokens)": [(r"\*\*(\d+) tests:", ("Card-Network Agentic Tokens",))],
    "Settlement finality (denial-of-settlement)": [(r"\*\*(\d+) tests:", ("Denial-of-Settlement / Finality",))],
    "Payment authz/hardening": [(r"AP2 mandate \((\d+)\)", ("AP2 Mandate Chain",)),
                                (r"Fireblocks x402 \((\d+)\)", ("x402 Fireblocks Extension",))],
    "Enterprise platforms": [(r"\*\*(\d+) cloud", ("Cloud Agent Platforms",)),
                             (r"\+ (\d+) enterprise", ("Enterprise Platforms (core)", "Enterprise Platforms (extended)")),
                             (r"core (\d+)", ("Enterprise Platforms (core)",)),
                             (r"extended (\d+)", ("Enterprise Platforms (extended)",))],
    "Human oversight (T10/T15)": [(r"\*\*(\d+) tests:", ("hitl_harness.py",))],
    "APT simulation": [(r"GTG-1002 \((\d+) tests\)", ("GTG-1002 APT Simulation",))],
    "Jailbreak/over-refusal": [(r"\*\*(\d+) tests", ("Jailbreak", "Over-Refusal")),
                               (r"\((\d+) \+", ("Jailbreak",)),
                               (r"\+ (\d+) FPR", ("Over-Refusal",))],
}


def readme_problems(text: str, catalog: dict[str, int]) -> list[str]:
    """Every listed README row whose numbers disagree with the catalog, or that is missing."""
    problems = []
    for label, checks in README_ROWS.items():
        row = re.search(r"^\|\s*\*\*" + re.escape(label) + r"\*\*\s*\|(?P<cells>.*)$", text, re.M)
        if not row:
            problems.append(f"{label!r}: row not found")
            continue
        ours = row.group("cells").rstrip().rstrip("|").rsplit("|", 1)[-1]
        for pattern, parts in checks:
            m = re.search(pattern, ours)
            if not m:
                problems.append(f"{label!r}: pattern {pattern!r} not found")
                continue
            expected = sum(catalog[p] for p in parts)
            if int(m.group(1)) != expected:
                problems.append(f"{label!r}: README says {m.group(1)} for {'+'.join(parts)}, count_tests says {expected}")
    return problems


class InventoryCountsAreCurrent(unittest.TestCase):
    def setUp(self):
        self.text = INVENTORY.read_text(encoding="utf-8")
        self.catalog = catalog_by_label()

    def test_count_tables_match_count_tests(self):
        for name, table in count_tables(self.text).items():
            with self.subTest(table=name):
                self.assertEqual(row_problems(table, self.catalog), [])

    def test_headings_do_not_restate_counts(self):
        self.assertEqual(_HEADING_COUNT.findall(self.text), [],
                         "state a module's count in a checked table, not in a heading")

    def test_docs_readme_tree_does_not_restate_counts(self):
        tree = DOCS_README.read_text(encoding="utf-8")
        self.assertEqual(_TREE_COUNT.findall(tree), [],
                         "docs/README.md tree comments must not carry per-module counts")

    def test_readme_comparison_table_matches_count_tests(self):
        text = ROOT_README.read_text(encoding="utf-8")
        self.assertEqual(readme_problems(text, self.catalog), [])


class TheGuardCanFire(unittest.TestCase):
    """Positive controls: each check fails on the defect it exists to catch."""

    catalog = {"MCP Protocol": 34, "Enterprise Platforms (core)": 31,
               "Enterprise Platforms (extended)": 27}

    def test_stale_row_is_caught(self):
        self.assertTrue(row_problems("> | MCP Protocol | 32 |\n", self.catalog))

    def test_correct_row_passes(self):
        self.assertEqual(row_problems("| **MCP Protocol** | 34 | JSON-RPC | x |\n", self.catalog), [])

    def test_composite_row_is_summed(self):
        self.assertEqual(row_problems("| **Enterprise Platforms** | 58 | APIs | x |\n", self.catalog), [])
        self.assertTrue(row_problems("| **Enterprise Platforms** | 31 | APIs | x |\n", self.catalog))

    def test_unknown_label_fails_rather_than_skips(self):
        self.assertTrue(row_problems("| **Renamed Module** | 34 | x | y |\n", self.catalog))

    def test_empty_table_fails(self):
        self.assertTrue(row_problems("no table here\n", self.catalog))

    def test_heading_and_tree_patterns_fire(self):
        self.assertTrue(_HEADING_COUNT.findall("### A2A (Agent-to-Agent) - 13 tests\n"))
        self.assertTrue(_TREE_COUNT.findall("│   ├── mcp_harness.py       # MCP (JSON-RPC 2.0) - 32 tests\n"))

    def test_readme_guard_fires_on_the_2026_11_18_text(self):
        """The row as it stood after #697 must fail; the repaired row must pass."""
        cat = catalog_by_label()
        live = ROOT_README.read_text(encoding="utf-8")
        stale = live.replace("protocol (%d)" % cat["MCP Protocol"], "protocol (32)", 1)
        self.assertNotEqual(stale, live, "control could not seed the defect")
        self.assertTrue(any("MCP Protocol" in p for p in readme_problems(stale, cat)))
        self.assertEqual(readme_problems(live, cat), [])

    def test_readme_guard_fails_on_a_missing_row(self):
        self.assertTrue(any("row not found" in p for p in readme_problems("no table\n", catalog_by_label())))


if __name__ == "__main__":
    unittest.main()
