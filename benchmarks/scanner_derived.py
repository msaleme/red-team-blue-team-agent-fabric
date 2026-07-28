#!/usr/bin/env python3
"""Derived scanner visibility for the DGB corpus.

Replaces the retired hand-assigned ``BenchmarkCase.scanner_passes`` field.

Rather than asserting per case whether a metadata-only scanner would detect a
failure, this module **runs a scanner** against the tool-registry fixtures in
``benchmarks/tool_fixtures.py`` and reports what it found.

Why the field was removed
-------------------------
``scanner_passes`` produced the corpus's most-cited number ("85% undetectable")
and drove Config C, yet nothing ever validated it -- the corpus contained no
artifact a scanner could read. A value that can be computed should not be
hand-maintained; the drift that let 9 of its 52 assignments disagree with
measurement is what hand-maintenance costs.

Scanner dependence (read before citing any number from here)
------------------------------------------------------------
The result is a property of *this scanner over these fixtures*, not of metadata
scanning in general. ``scan_tool_fields()`` is pattern-based (14 regexes). It
misses signals a semantic reader would catch -- DBC-006's fixture states in
plain language that the caller's session inherits elevated scope, and the
pattern scanner does not flag it. Report the scanner alongside the number.

Usage
-----
    from benchmarks.scanner_derived import scanner_detects, scanner_misses
    scanner_detects("DBC-039")   # -> True
    scanner_misses("DBC-039")    # -> False
"""

from __future__ import annotations

from functools import lru_cache

from benchmarks.tool_fixtures import FIXTURES
from protocol_tests.mcp_tool_poisoning_harness import scan_tool_fields

SCANNER_ID = "protocol_tests.mcp_tool_poisoning_harness.scan_tool_fields"


@lru_cache(maxsize=None)
def scan_findings(case_id: str) -> tuple:
    """Return the scanner's findings for a case's tool-registry fixture."""
    fixture = FIXTURES.get(case_id)
    if fixture is None:
        raise KeyError(f"no tool fixture for {case_id}")
    findings = []
    for tool in fixture["tools"]:
        findings.extend(scan_tool_fields(tool))
    return tuple(findings)


def scanner_detects(case_id: str) -> bool:
    """True if the scanner flags this case's tool metadata."""
    return len(scan_findings(case_id)) > 0


def scanner_misses(case_id: str) -> bool:
    """True if the scanner does not flag this case's tool metadata.

    This is the direct replacement for the retired ``scanner_passes`` field.
    """
    return not scanner_detects(case_id)


def summary() -> dict:
    """Corpus-wide detection counts, for reporting."""
    ids = list(FIXTURES)
    detected = [i for i in ids if scanner_detects(i)]
    return {
        "scanner": SCANNER_ID,
        "total": len(ids),
        "detected": len(detected),
        "missed": len(ids) - len(detected),
        "detected_ids": detected,
    }


__all__ = ["scanner_detects", "scanner_misses", "scan_findings", "summary", "SCANNER_ID"]
