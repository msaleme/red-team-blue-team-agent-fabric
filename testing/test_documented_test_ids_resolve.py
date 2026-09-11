"""A test ID cited in a document must be a test ID that exists.

## Why

Three documents cited 58 test IDs that did not exist:

- `docs/AIUC1-CROSSWALK.md` offered `APP-001-030` for prompt injection via
  operational data (3 exist, as `ADI-001..003`) and `ADV-001-010` for filter
  bypass (that prefix has never been used; the ten real tests in that module are
  `POLY-`, `CHAIN-`, `JAIL-`, `RECON-`, `STATE-`).
- `README.md` credited a third party's fixtures as `X4-021 through X4-030`;
  `X4-028..030` do not exist.
- `docs/aiuc1-prep.md` claimed `ID-001 to ID-018`; three exist.

Every one is a round number where a derived one belonged. The crosswalk maps this
repository onto an external certification and is publicly readable, so that is
the fabricated-citation class this repository exists to argue against.

Found 2026-09-11 by an outside reader tracing claims to code. Not by the suite.

## What it checks, and the shape of the rule

Three forms, because the first version caught only one of the three defects:

1. A **range**, `ABC-001-030`. Every ID in it must exist. A range is a structural
   claim about a block of tests and nothing innocent forms one, so this applies
   whatever the prefix. It is the only rule that catches a wholly invented
   prefix like `APP`.
2. A **prose range**, `ABC-001 through ABC-030` / `to ABC-030`. Same rule. The
   README defect used this form and rule 1 did not see it.
3. A **bare ID whose prefix the repository actually uses**, e.g. `X4-030` when
   `X4-001..057` exist. A known prefix with an unknown number is a typo or an
   invention, and this is what caught the README and `aiuc1-prep` cases.

## What it deliberately does NOT check

A bare ID under an **unknown** prefix. `SHA-256` matches the shape of a test ID
and is not one; `docs/proposals/` names tests that are proposed rather than
built; some documents cite IDs belonging to other repositories. Flagging those
would make this a check that fails on true statements, and such a check gets
muted rather than obeyed. The cost is real and is stated: a document could invent
`ZZZ-001` as a single bare ID and pass. Ranges cannot hide that way, and ranges
are how all 58 were written.

It also cannot decide whether a cited test is *apposite* to the claim beside it.
`POLY-002` exists, and a row citing it for audit logging would pass here and
still be wrong. That stays a reading task; the register in
`test_review_findings_are_ratcheted.py` records it as UNGUARDABLE.
"""

from __future__ import annotations

import pathlib
import re
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import count_tests  # noqa: E402

_RANGE = re.compile(r"\b([A-Z][A-Z0-9]*)-(\d{3})-(\d{3})\b")
_PROSE_RANGE = re.compile(
    r"\b([A-Z][A-Z0-9]*)-(\d{3})\s+(?:through|to)\s+(?:[A-Z][A-Z0-9]*-)?(\d{3})\b")
_BARE = re.compile(r"\b([A-Z][A-Z0-9]*-\d{3})\b(?!-\d)")
_ID_LITERAL = re.compile(r'"([A-Z][A-Z0-9]*-[0-9]{3}[a-z]?)"')


def _real_ids() -> set[str]:
    """Every test ID the shipped code defines.

    `count_tests.module_ids()` scans `protocol_tests/` only. `red_team_automation.py`
    sits at the repository root and defines 81 `RT-` IDs; keying on the counter
    alone made this guard fail against every document that cited them correctly.
    Widened after that, which is why the union below is not redundant.
    """
    ids: set[str] = set()
    for module_ids in count_tests.module_ids().values():
        ids |= set(module_ids)
    for path in list(REPO_ROOT.glob("*.py")) + list((REPO_ROOT / "protocol_tests").rglob("*.py")):
        ids |= set(_ID_LITERAL.findall(path.read_text(encoding="utf-8", errors="replace")))
    return ids


def _documents():
    for path in sorted((REPO_ROOT / "docs").rglob("*.md")):
        yield path, path.read_text(encoding="utf-8", errors="replace")
    readme = REPO_ROOT / "README.md"
    if readme.is_file():
        yield readme, readme.read_text(encoding="utf-8", errors="replace")


class DocumentedTestIdsResolve(unittest.TestCase):

    def setUp(self):
        self.real = _real_ids()
        self.known_prefixes = {i.split("-")[0] for i in self.real}

    def _check_range(self, rel, prefix, lo, hi, form):
        want = [f"{prefix}-{i:03d}" for i in range(int(lo), int(hi) + 1)]
        missing = [w for w in want if w not in self.real]
        if not missing:
            return
        with self.subTest(doc=str(rel), rng=f"{prefix}-{lo}-{hi}"):
            self.fail(
                f"{rel} cites {prefix}-{lo} {form} {prefix}-{hi}, and "
                f"{len(missing)} of {len(want)} do not exist "
                f"({missing[0]}..{missing[-1]}). Cite the IDs the repository "
                "defines, or describe the capability without an ID range. A "
                "round number here is how all 58 earlier phantoms were written.")

    def test_every_cited_id_range_expands_to_tests_that_exist(self):
        for path, text in _documents():
            rel = path.relative_to(REPO_ROOT)
            for prefix, lo, hi in sorted(set(_RANGE.findall(text))):
                self._check_range(rel, prefix, lo, hi, "-")

    def test_every_prose_id_range_expands_to_tests_that_exist(self):
        """`X4-021 through X4-030`. Rule 1 cannot see this form."""
        for path, text in _documents():
            rel = path.relative_to(REPO_ROOT)
            for prefix, lo, hi in sorted(set(_PROSE_RANGE.findall(text))):
                self._check_range(rel, prefix, lo, hi, "through")

    def test_a_known_prefix_with_an_unknown_number_does_not_exist(self):
        for path, text in _documents():
            rel = path.relative_to(REPO_ROOT)
            for tid in sorted(set(_BARE.findall(text))):
                if tid.split("-")[0] not in self.known_prefixes:
                    continue
                with self.subTest(doc=str(rel), id=tid):
                    self.assertIn(
                        tid, self.real,
                        f"{rel} cites {tid}. That prefix is one this repository "
                        "uses, so the number is a typo or an invention.")

    def test_the_id_population_is_real(self):
        """Anti-vacuity. An empty or tiny `real` set changes what every rule means."""
        self.assertGreater(len(self.real), 600)
        self.assertGreater(len(self.known_prefixes), 50)
        for expected in ("MCP-001", "X4-057", "ADI-001", "RT-001"):
            self.assertIn(expected, self.real,
                          f"{expected} missing: _real_ids() stopped seeing a module")

    def test_the_scanner_reads_documents_that_cite_ids(self):
        """A glob matching nothing satisfies every rule above."""
        docs = list(_documents())
        self.assertGreater(len(docs), 20)
        citing = [p for p, t in docs if _BARE.search(t) or _RANGE.search(t)]
        self.assertGreater(
            len(citing), 5,
            "almost no document cites a test ID, so the regexes stopped matching "
            "rather than the docs stopping citing tests")


if __name__ == "__main__":
    unittest.main()
