"""Tests for the portable DGB corpus bundle.

The property that matters is that the bundle is *usable by someone who does not
have this package*. Several tests therefore read the committed JSON with plain
stdlib only, deliberately not importing anything from `benchmarks`.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

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


# --- grounding currency -----------------------------------------------------
# The audit read the corpus at 6c5d617 on 2026-07-26. A remediation pass landed
# 2026-07-27 and revised many source fields. The bundle must not present the
# audited snapshot as the current state.


def test_every_case_declares_grounding_currency(bundle):
    for case in bundle["cases"]:
        g = case["grounding"]
        assert "source_revised_since_audit" in g, case["id"]
        assert isinstance(g["source_revised_since_audit"], bool), case["id"]
        assert g["verdict_currency"], case["id"]
        assert g["audited_at_commit"].startswith("6c5d617"), case["id"]


def test_currency_block_matches_per_case_flags(bundle):
    """Three disjoint states that must sum to the corpus.

    `revised` now means "changed for reasons of its own", excluding cases
    repaired because an audit finding was accepted. Collapsing those two into
    one bucket is what would let a repair read as a routine edit.
    """
    cases = bundle["cases"]
    repaired = sum(1 for c in cases if c["grounding"]["repaired_in_response_to_audit"])
    revised = sum(
        1
        for c in cases
        if c["grounding"]["source_revised_since_audit"]
        and not c["grounding"]["repaired_in_response_to_audit"]
    )
    gc = bundle["grounding_currency"]
    assert gc["cases_with_source_revised_since_audit"] == revised
    assert gc["cases_repaired_in_response_to_audit"] == repaired
    assert gc["cases_still_as_audited"] == len(cases) - revised - repaired
    assert (
        gc["cases_with_source_revised_since_audit"]
        + gc["cases_repaired_in_response_to_audit"]
        + gc["cases_still_as_audited"]
        == len(cases)
    ), "the three currency states must partition the corpus, not overlap"


def test_flagged_and_still_as_audited_is_derived(bundle):
    """The count a reader should act on: defect verdicts still describing HEAD."""
    n = sum(
        1
        for c in bundle["cases"]
        if not c["grounding"]["source_revised_since_audit"]
        and not c["grounding"]["repaired_in_response_to_audit"]
        and (c["grounding"]["evidence_fit"] == "none" or c["grounding"]["record_defect"] != "—")
    )
    assert bundle["grounding_currency"]["flagged_and_still_as_audited"] == n


def test_verdict_currency_agrees_with_the_flag(bundle):
    """Four states now. `stale` survives only for a revised case nobody re-read;
    the corpus currently has none, but the branch must stay honest if one appears."""
    for case in bundle["cases"]:
        g = case["grounding"]
        if g["repaired_in_response_to_audit"]:
            assert g["verdict_currency"].startswith("repaired"), case["id"]
        elif g["source_revised_since_audit"] and g["readjudicated"]:
            assert g["verdict_currency"].startswith("re-adjudicated"), case["id"]
        elif g["source_revised_since_audit"]:
            assert g["verdict_currency"].startswith("stale"), case["id"]
        else:
            assert g["verdict_currency"].startswith("as-audited"), case["id"]


# --- repairs must not launder the flag ---------------------------------------
# Editing a flagged case's source text flips its digest, which would silently
# reclassify it as "revised" and drop flagged_and_still_as_audited to zero. A
# zero that means "resolved" and a zero that means "edited" are different facts.

# Seven lost every form of support. DBC-026 lost only the external half of a
# compound citation and still rests on an internal run — a different outcome that
# must not be flattened into the same label.
AUTHOR_CONSTRUCTED_REPAIRS = [
    "DBC-014",
    "DBC-016",
    "DBC-031",
    "DBC-038",
    "DBC-039",
    "DBC-040",
    "DBC-044",
]
PARTIAL_CITATION_REPAIRS = ["DBC-026"]
REPAIRED = sorted(AUTHOR_CONSTRUCTED_REPAIRS + PARTIAL_CITATION_REPAIRS)


def test_repairs_are_declared_not_absorbed_into_revised(bundle):
    declared = sorted(
        c["id"] for c in bundle["cases"] if c["grounding"]["repaired_in_response_to_audit"]
    )
    assert declared == REPAIRED
    gc = bundle["grounding_currency"]
    assert gc["cases_repaired_in_response_to_audit"] == len(REPAIRED)
    # The count that dropped to zero must be accompanied by the count that explains it.
    if gc["flagged_and_still_as_audited"] == 0:
        assert gc["cases_repaired_in_response_to_audit"] > 0, (
            "zero flagged cases with no repairs recorded would read as 'nothing was "
            "ever wrong' rather than 'the findings were acted on'"
        )


def test_repaired_cases_claim_no_external_support(bundle):
    """A withdrawn citation is not a corroboration."""
    for case in bundle["cases"]:
        g = case["grounding"]
        if not g["repaired_in_response_to_audit"]:
            continue
        assert not g["externally_corroborated"], case["id"]
        assert g["provenance_after_repair"], case["id"]
        if case["id"] in AUTHOR_CONSTRUCTED_REPAIRS:
            assert "author-constructed" in g["provenance_after_repair"], case["id"]
            assert "no external source located" in case["source"], case["id"]
            assert case["source"].startswith("Author-constructed"), case["id"]
        else:
            assert "withdrawn" in g["provenance_after_repair"], case["id"]


def test_partial_citation_repair_is_not_labelled_author_constructed(bundle):
    """DBC-026 still rests on an internal run; calling it author-constructed
    would erase the one thing it does have."""
    case = next(c for c in bundle["cases"] if c["id"] == "DBC-026")
    prov = case["grounding"]["provenance_after_repair"]
    assert "author-constructed" not in prov
    assert "internal" in prov and "unpublished" in prov
    assert "HRAO-E internal run" in case["source"]


def test_repaired_cases_record_what_they_previously_claimed(bundle):
    """The withdrawn attribution stays visible; deleting it hides the defect."""
    for case in bundle["cases"]:
        if not case["grounding"]["repaired_in_response_to_audit"]:
            continue
        assert "NOTE: previously attributed" in case["source"], case["id"]
        assert "external corroboration audit v6" in case["source"], case["id"]


def test_repair_disposition_is_present_only_for_repaired_cases(bundle):
    for case in bundle["cases"]:
        g = case["grounding"]
        if g["repaired_in_response_to_audit"]:
            assert g["repair_disposition"], case["id"]
        else:
            assert g["repair_disposition"] is None, case["id"]
            assert g["provenance_after_repair"] is None, case["id"]


# --- re-adjudication ----------------------------------------------------------
# The audit's verdicts describe text that no longer exists for 25 cases. Carrying
# them as "stale" was honest but left half the corpus unknown. These guard the
# pass that closed that, and the honesty of how it is reported.

_FIT_AFTER_VOCABULARY = {
    "external — verified",
    "external — partial",
    "internal — inspectable",
    "internal — unpublished",
    "none — outstanding",
}


def test_every_revised_case_is_accounted_for(bundle):
    """No case may sit in 'text moved, nobody looked' — the state this closes."""
    stranded = [
        c["id"]
        for c in bundle["cases"]
        if c["grounding"]["source_revised_since_audit"]
        and not c["grounding"]["readjudicated"]
        and not c["grounding"]["repaired_in_response_to_audit"]
    ]
    assert stranded == [], f"revised but neither repaired nor re-adjudicated: {stranded}"
    assert bundle["readjudication"]["revised_cases_left_unadjudicated"] == 0
    assert bundle["readjudication"]["still_unadjudicated"] == []


def test_readjudication_vocabulary_is_closed(bundle):
    for case in bundle["cases"]:
        fit = case["grounding"]["fit_after_readjudication"]
        if fit is not None:
            assert fit in _FIT_AFTER_VOCABULARY, f"{case['id']}: {fit}"


def test_readjudicated_cases_carry_a_basis(bundle):
    """A verdict with no stated reason is an assertion, not an adjudication."""
    for case in bundle["cases"]:
        g = case["grounding"]
        if not g["readjudicated"]:
            assert g["fit_after_readjudication"] is None, case["id"]
            assert g["readjudication_basis"] is None, case["id"]
            continue
        assert g["fit_after_readjudication"], case["id"]
        assert g["readjudication_basis"], case["id"]
        assert len(g["readjudication_basis"]) > 60, (
            f"{case['id']}: basis is too thin to check"
        )
        assert g["readjudicated_on"], case["id"]


def test_readjudication_declares_it_is_not_independent(bundle):
    """The single-author limitation is not discharged by the author re-reading."""
    r = bundle["readjudication"]
    assert "NOT independent" in r["performed_by"]
    assert "not independent review" in r["note"].lower()
    assert "does not discharge the single-author limitation" in r["note"]
    for case in bundle["cases"]:
        by = case["grounding"]["readjudicated_by"]
        if by is not None:
            assert "NOT independent" in by, case["id"]


def test_verified_external_cases_carry_a_fetchable_locator(bundle):
    """'Verified' has to mean a reader can go and check it."""
    import re

    for case in bundle["cases"]:
        if case["grounding"]["fit_after_readjudication"] != "external — verified":
            continue
        basis = case["grounding"]["readjudication_basis"]
        has_locator = "http" in case["source"] or re.search(
            r"CVE-\d{4}-\d+", case["source"]
        )
        assert has_locator, (
            f"{case['id']} is marked externally verified but its source names no "
            f"URL or CVE a reader could follow. Basis: {basis[:80]}"
        )


def test_readjudication_summary_is_derived(bundle):
    from collections import Counter

    fits = Counter(
        c["grounding"]["fit_after_readjudication"]
        for c in bundle["cases"]
        if c["grounding"]["fit_after_readjudication"]
    )
    r = bundle["readjudication"]
    assert dict(fits) == r["fit_after_distribution"]
    assert r["cases_readjudicated"] == sum(fits.values())
    outstanding = [
        c["id"]
        for c in bundle["cases"]
        if c["grounding"]["fit_after_readjudication"] == "none — outstanding"
    ]
    assert r["outstanding"] == outstanding


def test_no_prose_field_contradicts_the_flags_it_describes(bundle):
    """The defect this whole corpus documents, committed by the corpus.

    When the re-adjudication pass landed, three prose fields still asserted the
    revised cases had "NOT been re-adjudicated" and that doing so was "still
    outstanding work" — while `readjudication` in the same document reported 25
    done and 0 remaining. Bugbot caught two; a third was in `grounding_audit`.
    A sentence restating a flag must be derived from that flag.
    """
    r = bundle["readjudication"]
    prose = [
        ("grounding_currency.note", bundle["grounding_currency"]["note"]),
        ("grounding_audit.currency_warning", bundle["grounding_audit"]["currency_warning"]),
        ("known_limitations.evidence_fit", bundle["known_limitations"]["evidence_fit"]),
        ("known_limitations.record_defects", bundle["known_limitations"]["record_defects"]),
    ]
    if r["revised_cases_left_unadjudicated"] == 0:
        for name, text in prose:
            low = text.lower()
            assert "have not been re-adjudicated" not in low, name
            assert "not been re-adjudicated" not in low, name
            assert "still outstanding work" not in low, name
            assert "is outstanding work" not in low, name

    # Every repaired case is not author-constructed; prose must not say they are.
    if PARTIAL_CITATION_REPAIRS:
        for name, text in prose:
            assert "are now declared author-constructed" not in text, (
                f"{name} calls all repaired cases author-constructed, but "
                f"{PARTIAL_CITATION_REPAIRS} rest on an internal run"
            )


def test_verdict_currency_never_contradicts_readjudicated(bundle):
    """Per-case version of the same failure."""
    for case in bundle["cases"]:
        g = case["grounding"]
        currency = g["verdict_currency"]
        if g["readjudicated"] and not g["repaired_in_response_to_audit"]:
            assert "not re-adjudicated" not in currency, case["id"]
            assert currency.startswith("re-adjudicated"), case["id"]
        if g["repaired_in_response_to_audit"]:
            rests = g["provenance_after_repair"]
            if "author-constructed" not in rests:
                assert "remains author-constructed" not in currency, (
                    f"{case['id']} rests on '{rests}' but its currency string "
                    "calls it author-constructed"
                )


def test_an_empty_outstanding_list_never_stands_alone(bundle):
    """Same failure shape as a laundered repair, one level up.

    A pass that finds a defect and fixes it inside the same commit leaves
    `outstanding` empty. Reported by itself that reads as "we looked and found
    nothing" — the opposite of what happened.
    """
    r = bundle["readjudication"]
    if not r["outstanding"]:
        assert r["found_defective_by_this_pass"], (
            "no outstanding defects AND no record of any found: a reader cannot "
            "tell a clean corpus from an unrecorded repair"
        )
    found = sorted(
        c["id"]
        for c in bundle["cases"]
        if c["grounding"]["readjudicated"]
        and c["grounding"]["repaired_in_response_to_audit"]
    )
    assert r["found_defective_by_this_pass"] == found


def test_a_repaired_case_is_not_reported_as_outstanding(bundle):
    """fit_after must describe the case now, not when the defect was spotted."""
    for case in bundle["cases"]:
        g = case["grounding"]
        if g["repaired_in_response_to_audit"] and g["readjudicated"]:
            assert g["fit_after_readjudication"] != "none — outstanding", (
                f"{case['id']} was repaired in this pass; calling it outstanding "
                "misreports the current state"
            )
            assert "Found DEFECTIVE by this pass" in g["readjudication_basis"], (
                f"{case['id']}: the finding must survive the fix"
            )


def test_dbc_026_compound_citation_defect_is_recorded(bundle):
    """Found by re-reading, not by the currency flag.

    Revising one half of a compound citation flips the case digest and moves it
    out of the flagged bucket while the other half stays disproved. The bundle
    must say this happened, or the next compound citation hides the same way.
    """
    case = next(c for c in bundle["cases"] if c["id"] == "DBC-026")
    basis = case["grounding"]["readjudication_basis"]
    assert "compound citation defeats a per-case digest" in basis
    assert "OX Security" not in case["source"].split("NOTE:")[0], (
        "the withdrawn external half must not remain an active claim"
    )
    assert "does not cover cross-agent" in case["source"]
    assert "compound citation" in bundle["readjudication"]["note"]


# --- executable_test linkage --------------------------------------------------


def test_every_case_reports_executable_test_linkage(bundle):
    for case in bundle["cases"]:
        link = case["executable_test_link"]
        assert "resolves_to_a_test" in link, case["id"]
        assert isinstance(link["resolves_to_a_test"], bool), case["id"]


def test_linkage_summary_is_derived_from_the_cases(bundle):
    cases = bundle["cases"]
    unresolved = [c["id"] for c in cases if not c["executable_test_link"]["resolves_to_a_test"]]
    disagrees = [
        c["id"] for c in cases if c["executable_test_link"]["owasp_asi_agrees"] is False
    ]
    el = bundle["executable_test_linkage"]
    assert el["not_resolvable"] == unresolved
    assert el["cases_naming_something_else"] == len(unresolved)
    assert el["owasp_asi_disagrees_cases"] == disagrees
    assert el["owasp_asi_disagrees"] == len(disagrees)
    assert el["cases_naming_a_resolvable_test"] == len(cases) - len(unresolved)


def test_linkage_resolves_against_live_source_not_the_catalog(bundle):
    """Regression: HARNESS_TEST_CATALOG.md is a dated extract.

    Resolving against it would reintroduce the staleness this check exists to
    detect — the same class of error as citing an audit against a later commit.
    """
    assert "protocol_tests/" in bundle["executable_test_linkage"]["resolved_against"]
    assert "CATALOG" in bundle["executable_test_linkage"]["resolved_against"]
    for case in bundle["cases"]:
        link = case["executable_test_link"]
        if link["resolves_to_a_test"]:
            assert link["defined_in"].startswith("protocol_tests/"), case["id"]


def test_linkage_does_not_overclaim_coverage(bundle):
    """The block must not assert that a named test exercises the case."""
    note = bundle["executable_test_linkage"]["note"]
    assert "has never asserted that" in note
    assert "not a finding on its own" in note


def test_linkage_marks_missing_asi_as_unknown_not_a_disagreement():
    from benchmarks.dgb_bundle_export import _executable_test_link

    link = _executable_test_link(
        SimpleNamespace(executable_test="MCP-999", owasp_asi="ASI01"),
        {
            "MCP-999": {
                "name": "Synthetic test without ASI metadata",
                "owasp_asi": None,
                "category": "synthetic",
                "defined_in": "protocol_tests/synthetic.py",
            }
        },
    )

    assert link["owasp_asi_agrees"] is None
    assert "unknown" in link["note"]
    assert "check the mapping" not in link["note"]


def test_limitations_do_not_present_audited_figures_as_current(bundle):
    """Regression: the first release stated the audited counts as present tense."""
    lim = bundle["known_limitations"]
    assert "AS AUDITED" in lim["evidence_fit"]
    assert "AS AUDITED" in lim["record_defects"]
    assert "currency_warning" in bundle["grounding_audit"]


# --- the README source table --------------------------------------------------
# It was maintained by hand beside a corpus maintained in code, and had drifted:
# DBC-037 was filed under OX Security though it has never cited OX, four METR
# cases were missing, and both internal-run ranges swept in a case belonging to
# another source. Prose cannot hold a mapping in sync; this test can.

README = Path(__file__).resolve().parents[1] / "benchmarks/README.md"

# Word-bounded on purpose. An unbounded `METR` matched DBC-028's "self-reported
# metrics" and filed a UC Berkeley RDI case under METR 2025 — a citation the case
# does not make. A source-attribution guard that itself over-matches is worse
# than none, so every pattern here is anchored and covered by
# test_source_patterns_do_not_match_on_substrings.
_SOURCE_PATTERNS = {
    "UC Berkeley RDI": r"\bUC Berkeley RDI\b",
    "METR": r"\bMETR\b",
    "OX Security": r"\bOX Security\b",
    "OpenClaw CVE-2026-35625": r"\b35625\b",
    "OpenClaw CVE-2026-35629": r"\b35629\b",
    "Kiro/Amazon": r"\bKiro\b|\bAmazon\b",
    "MCP cost inflation": r"\bcost inflation\b",
    "IQuest-Coder": r"\bIQuest\b",
    "AgentSeal": r"\bAgentSeal\b",
    "HRAO-E `lightningzero`": r"\blightningzero\b",
    "HRAO-E `zhuanruhu`": r"\bzhuanruhu\b",
}


def _cases_asserting(pattern: str) -> list[str]:
    """Cases whose source *claims* this source, ignoring withdrawn NOTE text."""
    import re

    from benchmarks.decision_behavior_corpus import CORPUS

    return [
        c.id
        for c in CORPUS
        if re.search(pattern, (c.source or "").split("NOTE:")[0], re.I)
    ]


def _guarded_tables() -> str:
    """Only the two tables that claim to mirror the corpus.

    Scoped by anchor so the 'Withdrawn attributions' table — which names the
    same publications in a *previously cited* column — cannot be mistaken for a
    live attribution. Without the anchors this test reads a withdrawal as a claim.
    """
    import re

    text = README.read_text(encoding="utf-8")
    blocks = re.findall(
        r"<!-- dgb:(?:source|internal)-table:start -->(.*?)<!-- dgb:(?:source|internal)-table:end -->",
        text,
        re.S,
    )
    assert len(blocks) == 2, "both guarded tables must be anchored"
    return "\n".join(blocks)


@pytest.mark.parametrize("label,pattern", sorted(_SOURCE_PATTERNS.items()))
def test_readme_source_table_matches_the_corpus(label, pattern):
    import re

    text = _guarded_tables()
    rows = [ln for ln in text.splitlines() if ln.startswith("|") and label in ln]
    assert rows, f"no README row for {label}"
    listed: set[str] = set()
    for row in rows:
        listed |= set(re.findall(r"DBC-\d{3}", row))
    expected = set(_cases_asserting(pattern))
    assert listed == expected, (
        f"{label}: README lists {sorted(listed - expected)} that do not cite it, "
        f"and omits {sorted(expected - listed)} that do"
    )


def test_readme_records_the_withdrawn_attributions():
    text = README.read_text(encoding="utf-8")
    assert "Withdrawn attributions" in text
    for case_id in REPAIRED:
        assert case_id in text, f"{case_id} repaired but not listed as withdrawn"


_EXTERNAL_SOURCE_PATTERNS = [
    r"\bUC Berkeley RDI\b",
    r"\bMETR\b",
    r"\bOX Security\b",
    r"\b35625\b",
    r"\b35629\b",
    r"\bKiro\b|\bAmazon\b",
    r"\bIQuest\b",
    r"\bAgentSeal\b",
    r"\$45M\b",
]


def test_source_patterns_do_not_match_on_substrings():
    """Every attribution match must be the source name, not a word containing it.

    Regression: unbounded `METR` matched "self-reported metrics" in DBC-028 and
    credited METR 2025 with a case that cites only UC Berkeley RDI. The bug is
    the same shape as the one this whole PR repairs — a pattern standing in for
    a claim it does not actually establish.
    """
    import re

    from benchmarks.decision_behavior_corpus import CORPUS

    known_names = [
        "UC Berkeley RDI",
        "METR",
        "OX Security",
        "35625",
        "35629",
        "Kiro",
        "Amazon",
        "cost inflation",
        "IQuest",
        "AgentSeal",
        "45M",
        "lightningzero",
        "zhuanruhu",
    ]
    for pattern in list(_SOURCE_PATTERNS.values()) + _EXTERNAL_SOURCE_PATTERNS:
        for case in CORPUS:
            claim = (case.source or "").split("NOTE:")[0]
            for hit in re.finditer(pattern, claim, re.I):
                matched = hit.group(0)
                assert any(n.lower() in matched.lower() for n in known_names), (
                    f"{case.id}: {pattern!r} matched {matched!r}, which is not a "
                    "source name"
                )
                # The match must not be the interior of a longer word.
                after = claim[hit.end() : hit.end() + 1]
                assert not after.isalpha(), (
                    f"{case.id}: {pattern!r} matched inside {matched + after!r} — "
                    "this is a substring hit, not a citation"
                )


def test_dbc_028_is_not_credited_to_metr():
    """The exact case the unbounded pattern mis-filed."""
    import re

    from benchmarks.decision_behavior_corpus import CORPUS

    case = next(c for c in CORPUS if c.id == "DBC-028")
    assert "metrics" in case.source
    assert not re.search(_SOURCE_PATTERNS["METR"], case.source, re.I), (
        "DBC-028 cites UC Berkeley RDI and says 'self-reported metrics'; it must "
        "not resolve as a METR citation"
    )
    assert re.search(_SOURCE_PATTERNS["UC Berkeley RDI"], case.source)


def test_author_grounded_count_is_derived():
    """The headline provenance figure must match the corpus, not a memory of it.

    It was published as 24 of 52 with a breakdown that double-counted the four
    cost-inflation cases. Withdrawing seven citations moved it. A number this
    load-bearing should be recomputed, not retyped.
    """
    import re

    from benchmarks.decision_behavior_corpus import CORPUS

    def claim(case) -> str:
        return (case.source or "").split("NOTE:")[0]

    external = set()
    for pattern in _EXTERNAL_SOURCE_PATTERNS:
        external |= {c.id for c in CORPUS if re.search(pattern, claim(c), re.I)}
    author_grounded = {c.id for c in CORPUS} - external

    text = README.read_text(encoding="utf-8")
    stated = re.search(r"\*\*(\d+) of the 52 cases \((\d+)%\) are grounded", text)
    assert stated, "README no longer states the author-grounded figure"
    assert int(stated.group(1)) == len(author_grounded), (
        f"README says {stated.group(1)} author-grounded cases; the corpus has "
        f"{len(author_grounded)}"
    )
    assert int(stated.group(2)) == round(len(author_grounded) / len(CORPUS) * 100)
    # Every repaired case must land on the author-grounded side.
    assert set(REPAIRED) <= author_grounded


PAPER = Path(__file__).resolve().parents[1] / "docs/paper-dgb/main.tex"


def test_paper_grounding_figure_matches_the_corpus():
    """The paper published 24/52 for a week after the corpus moved.

    It is the same drift the README had, on the surface that is hardest to
    correct once submitted. Every occurrence of the figure must agree with the
    corpus and with each other.
    """
    import re

    from benchmarks.decision_behavior_corpus import CORPUS

    def claim(case) -> str:
        return (case.source or "").split("NOTE:")[0]

    external = set()
    for pattern in _EXTERNAL_SOURCE_PATTERNS:
        external |= {c.id for c in CORPUS if re.search(pattern, claim(c), re.I)}
    author_grounded = {c.id for c in CORPUS} - external

    text = PAPER.read_text(encoding="utf-8")
    stated = re.findall(r"(\d+) of 52 cases lack\s+independent external corroboration", text)
    stated += re.findall(r"(\d+) of 52\s+cases\s+lack independent external corroboration", text)
    stated += re.findall(r"\\textbf\{(\d+) of 52 cases lack", text)
    assert stated, "the paper no longer states the grounding figure in a parseable form"
    for value in stated:
        assert int(value) == len(author_grounded), (
            f"paper says {value} of 52 lack external corroboration; the corpus has "
            f"{len(author_grounded)}"
        )
    assert len(set(stated)) == 1, f"the paper states inconsistent figures: {set(stated)}"


def test_paper_does_not_present_the_audit_figure_as_the_current_one():
    """24 was measured under different criteria and must not read as a trend."""
    text = PAPER.read_text(encoding="utf-8")
    assert "24 of 52 source records point to internal artifacts" not in text, (
        "the audit's source-provenance figure is stated as if current"
    )
    # The audit's executable_test figure is unchanged by our work and may stay,
    # but it must be attributed to the audit rather than floated as present tense.
    if "24 of 52" in text:
        assert "2026-07 audit found 24 of 52" in text or "audit found 24 of 52" in text, (
            "a bare '24 of 52' with no attribution reads as a current measurement"
        )
    assert "not comparable to the 2026-07 audit" in text, (
        "the paper must say why its figure cannot be compared with the audit's"
    )


def test_paper_declares_the_readjudication_was_not_independent():
    text = PAPER.read_text(encoding="utf-8")
    assert "performed by the corpus author" in text
    assert "not\n        independent review" in text or "not independent review" in text


def test_readme_does_not_call_the_unlocatable_source_verifiable():
    """`$45M crypto agent 2026` has no publication anywhere in this repo."""
    text = README.read_text(encoding="utf-8")
    published = text.split("**Published sources.")[1].split("**One source")[0]
    assert "45M" not in published, (
        "the $45M source sits under a heading asserting external verifiability, "
        "but no locatable publication for it exists in this repository"
    )
    assert "No locatable publication" in text


def test_paper_cross_references_all_resolve():
    """A dangling \\ref renders as '??' in the PDF.

    `sec:formalism` was dangling on main: the corpus-construction section
    pointed at the definition of $M$ in Task Formalism, which carried no label.
    Cheap to catch, embarrassing to submit.
    """
    import re

    text = PAPER.read_text(encoding="utf-8")
    labels = set(re.findall(r"\\label\{([^}]+)\}", text))
    refs = set(re.findall(r"\\ref\{([^}]+)\}", text))
    assert refs <= labels, f"undefined \\ref targets: {sorted(refs - labels)}"
    duplicates = [x for x in labels if text.count("\\label{%s}" % x) > 1]
    assert not duplicates, f"duplicate labels: {duplicates}"
