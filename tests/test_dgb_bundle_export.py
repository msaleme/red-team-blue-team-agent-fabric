"""Tests for the portable DGB corpus bundle.

The property that matters is that the bundle is *usable by someone who does not
have this package*. Several tests therefore read the committed JSON with plain
stdlib only, deliberately not importing anything from `benchmarks`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

BUNDLE = Path(__file__).resolve().parents[1] / "fixtures/dgb/dgb-corpus-bundle.v1.json"


@pytest.fixture(scope="module")
def bundle() -> dict:
    return json.loads(BUNDLE.read_text(encoding="utf-8"))


def test_bundle_is_committed():
    assert BUNDLE.exists(), "the exported bundle must be committed, not generated on demand"


def test_bundle_parses_without_importing_the_package(bundle):
    """A reviewer with only the JSON must be able to read it."""
    assert bundle["schema_version"]
    assert bundle["cases"]


def test_every_case_carries_grounding(bundle):
    for case in bundle["cases"]:
        g = case.get("grounding")
        assert g, f"{case['id']} has no grounding block"
        for field in ("provenance", "evidence_fit", "record_defect", "note"):
            assert g.get(field), f"{case['id']} grounding missing {field}"


def test_grounding_vocabulary_is_closed(bundle):
    """Guards against a re-coding of the audit's terms drifting in silently."""
    fits = {"full", "full (internal)", "partial", "none", "provisional", "unresolved"}
    provs = {"external", "internal", "untraceable", "untrace+ext", "untrace+int"}
    for case in bundle["cases"]:
        g = case["grounding"]
        assert g["evidence_fit"] in fits, f"{case['id']}: {g['evidence_fit']}"
        assert g["provenance"] in provs, f"{case['id']}: {g['provenance']}"


def test_distributions_match_the_cases(bundle):
    """Summary blocks must be derived, not stale copies."""
    from collections import Counter

    fit = Counter(c["grounding"]["evidence_fit"] for c in bundle["cases"])
    assert dict(fit) == bundle["evidence_fit_distribution"]

    prov = Counter(c["grounding"]["provenance"] for c in bundle["cases"])
    assert dict(prov) == bundle["provenance_distribution"]

    defect = Counter(c["grounding"]["record_defect"] for c in bundle["cases"])
    assert dict(defect) == bundle["record_defect_distribution"]


def test_counts_match_the_cases(bundle):
    assert bundle["counts"]["total"] == len(bundle["cases"])
    assert bundle["counts"]["tool_entries"] == sum(len(c["tools"]) for c in bundle["cases"])


def test_scanner_baseline_matches_per_case_verdicts(bundle):
    """The headline detection counts must be the sum of the per-case verdicts."""
    regex = sum(1 for c in bundle["cases"] if c["expected_scanner"]["regex_metadata_scanner"])
    cap = sum(1 for c in bundle["cases"] if c["expected_scanner"]["capability_rule_scanner"])
    assert regex == bundle["scanner_baseline"]["regex_metadata_scanner_detects"]
    assert cap == bundle["scanner_baseline"]["capability_rule_scanner_detects"]


def test_scanner_baseline_matches_published_figures(bundle):
    """The changelog publishes 1/52 and 17/52. Drift here is a real change."""
    assert bundle["scanner_baseline"]["regex_metadata_scanner_detects"] == 1
    assert bundle["scanner_baseline"]["capability_rule_scanner_detects"] == 17
    assert bundle["counts"]["total"] == 52
    assert bundle["counts"]["tool_entries"] == 85


def test_single_external_corroboration_is_not_overstated(bundle):
    """Exactly one case has external provenance and full fit. Do not inflate."""
    ext = [c["id"] for c in bundle["cases"] if c["grounding"]["externally_corroborated"]]
    assert ext == ["DBC-009"], ext


def test_limitations_are_declared_inline(bundle):
    """The bundle must carry its own defects, not point at another document."""
    lim = bundle["known_limitations"]
    for key in (
        "single_author",
        "evidence_fit",
        "executable_test_coverage",
        "record_defects",
        "configs_a_and_b",
        "not_exercised",
    ):
        assert lim.get(key), f"missing declared limitation: {key}"
    assert "one author" in lim["single_author"]


def test_no_case_claims_more_than_its_grounding(bundle):
    """A case with no located support must not be marked externally corroborated."""
    for case in bundle["cases"]:
        g = case["grounding"]
        if g["evidence_fit"] in ("none", "unresolved", "provisional", "partial"):
            assert not g["externally_corroborated"], case["id"]
        if g["evidence_fit"] == "full (internal)":
            assert not g["externally_corroborated"], case["id"]


def test_export_is_deterministic():
    """Re-running the exporter must reproduce the committed bytes exactly."""
    from benchmarks.dgb_bundle_export import build_bundle, serialise

    assert serialise(build_bundle()) == BUNDLE.read_text(encoding="utf-8")
