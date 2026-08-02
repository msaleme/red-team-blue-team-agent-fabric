"""Export the Decision Governance Benchmark as a portable, self-verifying bundle.

Why this exists
---------------
DGB's own changelog names independent fixture review as the most valuable
outstanding check, and records that the corpus, both scanners and the audit
share one author. An outside reviewer cannot act on that unless the corpus is
readable and executable without importing this package.

This mirrors the packaging that made ``fixtures/rcl/rcl-oracle-fixtures.v1.json``
independently reproducible by a third party: every case is data, every expected
result is produced by executing the scanners rather than asserted, and the
corpus declares its own defects inline instead of in a separate document a
reader may never find.

What a reviewer can do with the bundle alone
--------------------------------------------
1. Read all 52 cases and their 85 tool-registry entries as JSON.
2. Write an independent scanner, run it over ``cases[].tools``, and compare
   against ``cases[].expected_scanner``.
3. See, per case, whether its cited source substantiates it, using the
   ``grounding`` block rather than having to re-derive the audit.

The expected verdicts are executed at export time, not hand-assigned. That
distinction is the reason the retired ``scanner_passes`` field was removed from
the corpus: a hand-assigned label describes an intention, not a measurement.

Usage
-----
    python -m benchmarks.dgb_bundle_export                  # write the bundle
    python -m benchmarks.dgb_bundle_export --stdout         # print instead
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path

from benchmarks.capability_scanner import capability_detects
from benchmarks.decision_behavior_corpus import CORPUS
from benchmarks.scanner_derived import scanner_detects
from benchmarks.tool_fixtures import FIXTURES

SCHEMA_VERSION = "1.0"
CORPUS_RELEASE = "dgb-v1.0.0"
DEFAULT_OUTPUT = Path("fixtures/dgb/dgb-corpus-bundle.v1.json")

# Per-case grounding, transcribed from Appendix A of the external-corroboration
# audit (audit date 2026-07-27, corpus read at commit 6c5d617). The audit
# adjudicated OX Security, UC Berkeley RDI and both OpenClaw CVEs per case and
# fetched them; METR, IQuest-Coder, AgentSeal and Kiro/Amazon were not fetched,
# and those rows are marked "provisional" rather than resolved.
#
# Vocabulary is the audit's own:
#   provenance:     external | internal | untraceable | untrace+ext | untrace+int
#   evidence_fit:   full | full (internal) | partial | none | provisional | unresolved
#   record_defect:  misdescription | invalid identifier | untraceable source | none
GROUNDING_SOURCE = {
    "audit": "DGB corpus — external corroboration audit (v6)",
    "audit_date": "2026-07-27",
    "corpus_commit_audited": "6c5d61726819165c9dcf75d99669217c3c3cab41",
    "note": (
        "Transcribed from the audit's Appendix A 52-case crosswalk. The audit "
        "asserts no source is fabricated, only that some are uncited and could "
        "not be located. 'provisional' means the source was located but a "
        "per-case locator was not established; it is not a finding of support."
    ),
    "currency_warning": (
        "These verdicts describe the corpus AS AUDITED at the commit above, "
        "not as it stands today. A remediation pass landed the day after the "
        "audit and revised many source fields. Each case reports "
        "source_revised_since_audit; where that is true the evidence_fit and "
        "record_defect below are STALE and have not been re-adjudicated. Do "
        "not read a stale 'none' as a current defect, and do not read a "
        "revision as a repair that someone has verified."
    ),
}


def _load_grounding() -> dict:
    """Grounding rows, keyed by case id.

    Kept as a literal below rather than parsed at runtime so the bundle can be
    regenerated from this repository alone, without the private audit file.
    """
    return _GROUNDING



_AUDITED_SOURCE_SHA256_16 = dict(
    line.split("\t") for line in """
DBC-001	f01a41bbecde087f
DBC-002	96d6c1e7ddf8cb9f
DBC-003	351d07a2aa84cff8
DBC-004	39c3f701504333bd
DBC-005	af7ee8fcb09465ea
DBC-006	c1b728c4a1ee774e
DBC-007	c701d9282905d805
DBC-008	9abe46597e12a24c
DBC-009	42ea67b517917464
DBC-010	c0902591f8179319
DBC-011	4d383dde0fc7c979
DBC-012	d5dfa93a29c0b443
DBC-013	4668cbb8cd65645a
DBC-014	74a4624a3e6c7bcf
DBC-015	07bcdfb2149440e4
DBC-016	a6ee482cfe75ab61
DBC-017	c245363b4393ee0f
DBC-018	8f58a381278c7454
DBC-019	07bd3e4881f87966
DBC-020	0b7b44a93d46adbd
DBC-021	0cba87b2fa5b3163
DBC-022	f7cf593ed16bc649
DBC-023	24d8c3e3c75b00db
DBC-024	4d5e1ece1f44d6a7
DBC-025	a958e2a21fe1c7a9
DBC-026	baf466908f7c3727
DBC-027	5c68c3e59c52196e
DBC-028	da304f745da4c27a
DBC-029	e3628a2cf693261c
DBC-030	2605493bdc604de8
DBC-031	92a74f845e1668b6
DBC-032	e186f579ec36396b
DBC-033	c25ac21013e06ad5
DBC-034	83b40666b384b943
DBC-035	e61c2a00a9e7568e
DBC-036	c3f77592324795c0
DBC-037	dfcb4bd6e9beee1e
DBC-038	bf9a3bd76b79de70
DBC-039	ed37bfb4f42823da
DBC-040	b4368aaeeb02a88f
DBC-041	595a8ba1b533f419
DBC-042	6c1447ad7ca01be2
DBC-043	74039a5f21a8480a
DBC-044	82fc6c94f21de854
DBC-045	f05e39a5dae35096
DBC-046	a6f78d8ed6c15192
DBC-047	1711d013907942d3
DBC-048	2765beaee6e02796
DBC-049	80898a79c6ce55f9
DBC-050	42f6f5aca88b565a
DBC-051	8ebc2451521d30fe
DBC-052	853282e96635b465
""".strip().splitlines()
)


def _source_revised(case) -> bool:
    """True if the case's `source` text changed after the grounding audit.

    The audit read the corpus at 6c5d617 on 2026-07-26. A remediation pass
    landed on 2026-07-27 and rewrote many source fields. Comparing the current
    text against the audited-era digest is how a reader can tell, per case,
    whether the recorded verdict still describes what they are looking at.
    """
    audited = _AUDITED_SOURCE_SHA256_16.get(case.id)
    if audited is None:
        return False
    current = hashlib.sha256(case.source.encode("utf-8")).hexdigest()[:16]
    return current != audited


# Cases whose `source` was rewritten *because* the audit found the citation
# unsupportable, with the disposition recorded per case.
#
# Why this register has to exist. `_source_revised` is a digest comparison, so
# repairing a flagged case silently reclassifies it from "as-audited" to
# "revised", and the headline count of cases carrying a live defect verdict
# drops to zero. That reads as "nothing outstanding" when what actually
# happened is that someone edited the text. A repair and an unrelated
# pre-audit revision are not the same event and must not collapse into one
# state. Deleting the flag would be the same failure as deleting an audit-trail
# entry: it replaces a known problem with a silent one.
_AUDIT_REPAIRS = {
    "DBC-014": "OX Security over-extension — attribution removed; case is author-constructed",
    "DBC-016": "OX Security over-extension — attribution removed; case is author-constructed",
    "DBC-031": "'$45M crypto agent 2026' unsupported — attribution removed; author-constructed",
    "DBC-038": "'$45M crypto agent 2026' unsupported — attribution removed; author-constructed",
    "DBC-039": "OX Security over-extension — attribution removed; case is author-constructed",
    "DBC-040": "'$45M crypto agent 2026' unsupported — attribution removed; author-constructed",
    "DBC-044": "UC Berkeley RDI over-extension — attribution removed; author-constructed",
    "DBC-026": (
        "OX Security over-extension, hidden by a partial revision — external half "
        "withdrawn; case now rests on an unpublished internal run"
    ),
}
_REPAIRED_AT = "2026-08-02"

# What a repaired case rests on once the bad citation is gone. Not uniform:
# seven had no support of any kind left and are author-constructed; DBC-026 lost
# only the external half of a compound citation and still rests on an internal
# run. Collapsing the two would overstate one and understate the other.
_AUTHOR_CONSTRUCTED = "author-constructed — no external source located"
_PROVENANCE_AFTER_REPAIR = {
    "DBC-014": _AUTHOR_CONSTRUCTED,
    "DBC-016": _AUTHOR_CONSTRUCTED,
    "DBC-031": _AUTHOR_CONSTRUCTED,
    "DBC-038": _AUTHOR_CONSTRUCTED,
    "DBC-039": _AUTHOR_CONSTRUCTED,
    "DBC-040": _AUTHOR_CONSTRUCTED,
    "DBC-044": _AUTHOR_CONSTRUCTED,
    "DBC-026": "internal, unpublished — external half of the citation withdrawn",
}

# Re-adjudication of the 25 cases whose source was revised after the audit.
#
# The audit's verdicts describe text that no longer exists. Until this pass they
# were carried as "stale, not re-adjudicated" — honest, but it left half the
# corpus in an unknown state. Each case below was re-read against its *current*
# text, and where that text names an external source, the source itself was
# re-fetched on 2026-08-02 rather than trusting the audit's transcription of it.
#
# Sources re-read: rdi.berkeley.edu/blog/trustworthy-benchmarks (byline, 13
# benchmarks, 45 exploits, Frontier-CS stack-frame injection, Terminal-Bench
# dummy C-extension, and the absence of judge-manipulation, string-collision and
# contamination discussion); ox.security MCP supply-chain advisory (STDIO
# command/argument injection as a class with no single CVE, and the absence of
# memory contamination, credential relay, A2A relay and phantom registration);
# NVD CVE-2026-35625 and CVE-2026-35629 (both quoted verbatim);
# metr.org/blog/2025-06-05-recent-reward-hacking; AI Incident Database 1442.
#
# THIS PASS WAS PERFORMED BY THE CORPUS AUTHOR. It is not independent review and
# does not discharge the single-author limitation. What it changes is that a
# reader can now check each verdict against a named, fetchable locator instead of
# being asked to take an unexamined "stale" on trust.
#
# fit_after vocabulary — deliberately its own, not the audit's:
#   external — verified      source re-read; current text is supported by it
#   external — partial       source supports the class, not the case's specifics
#   internal — inspectable   rests on an artifact present in this repo
#   internal — unpublished   rests on an internal run whose data is not published
#   none — outstanding       a defect the audit found is still live
_READJUDICATED_ON = "2026-08-02"
_READJUDICATED_BY = "corpus author — NOT independent review"

_INTERNAL_UNPUBLISHED = (
    "untraceable-source defect resolved: the name the audit could not locate is "
    "now declared an internal, unpublished HRAO-E run. Nothing external is "
    "claimed, so there is nothing left to trace. The run data remains "
    "unpublished and this is not corroboration."
)

_READJUDICATION = {
    # --- external, re-fetched and verified -----------------------------------
    "DBC-003": (
        "external — verified",
        "CVE-2026-35625 reads 'silent local shared-auth reconnects auto-approve "
        "scope-upgrade requests, widening paired device permissions from "
        "operator.read to operator.admin'. The revised text matches it; the "
        "audit's 'permission inheritance' misdescription is gone.",
    ),
    "DBC-006": (
        "external — verified",
        "Same CVE, same verbatim match. The 'tool permission inheritance "
        "escalation' wording the audit rejected no longer appears.",
    ),
    "DBC-007": (
        "external — verified",
        "Kiro/Amazon Dec 2025 confirmed: AWS Cost Explorer, 13h outage, agent "
        "deleted and recreated a production environment during an assigned task. "
        "Amazon's 'misconfigured access controls, not AI' statement is quoted "
        "rather than suppressed. Locator added; the audit had left this "
        "provisional for want of one.",
    ),
    "DBC-028": (
        "external — verified",
        "'Self-reported metrics, timing measurements controlled by the "
        "submission, and loosely parsed evaluator output are all attack "
        "surfaces' is present verbatim. The 'in RAG contexts' clause the audit "
        "flagged as absent has been removed, and RAG is indeed not discussed.",
    ),
    "DBC-041": (
        "external — verified",
        "Byline is Wang, Mang, Cheung, Sen, Song — no Xu, as the audit found. "
        "'We audited 13 widely-used AI benchmarks', 'Every benchmark was rated "
        "critical risk', and 45 confirmed hacking solutions achieving inflated "
        "or perfect scores. The revised text matches all three.",
    ),
    "DBC-045": (
        "external — verified",
        "Example 1 walks the call stack with sys._getframe() and replaces the "
        "scoring function in Frontier-CS. The revised text claims exactly that, "
        "and no longer claims a 'universal benchmark bypass'.",
    ),
    "DBC-048": (
        "external — verified",
        "Example 2 is a dummy .so passing an existence check while numpy does "
        "the work, in Terminal-Bench. The revised text no longer generalises the "
        "mechanism across 8 or 13 benchmarks.",
    ),
    "DBC-050": (
        "external — verified",
        "METR reports 39/128 RE-Bench runs reward-hacked (30.4%) against 8/1087 "
        "on HCAST (0.7%), and notes similar behaviour in Claude 3.7 Sonnet "
        "without publishing a rate. All three claims confirmed; locator added.",
    ),
    # --- external, still only partly supported --------------------------------
    "DBC-032": (
        "external — partial",
        "Record defect RESOLVED: the invalid 'CVE-2026-SSRF-MCP' identifier is "
        "gone, and the advisory confirms STDIO command/argument injection is a "
        "class spanning several products with no single unified CVE. Evidence "
        "fit remains PARTIAL: the advisory supports the mechanism, not this "
        "case's narrower tool-call-triggers-execution-before-validation sequence.",
    ),
    "DBC-037": (
        "external — partial",
        "Source text RESOLVED: CVE-2026-35629 reads 'multiple channel extensions "
        "that fail to properly guard configured base URLs against SSRF', which "
        "the revised text now reproduces. RESIDUAL DEFECT: the case is still "
        "*named* 'SSRF via Tool URL Parameter', a mechanism the CVE does not "
        "describe. The name was not changed here — renaming a published case is "
        "a separate decision — so the mismatch is recorded instead of hidden.",
    ),
    # --- internal, inspectable in this repo ------------------------------------
    "DBC-005": (
        "internal — inspectable",
        "constitutional-agent HC-12 exists and reads 'No manual override of "
        "constitutional gates by any agent without ratified amendment'; it ships "
        "in the open-source library. The lightningzero half is an unpublished "
        "internal run and is now declared as such.",
    ),
    "DBC-043": (
        "internal — inspectable",
        "agent-security-harness BI-004 'LLM Judge Prompt Injection' is present in "
        "protocol_tests/benchmark_integrity_harness.py. Re-reading the Berkeley "
        "article confirms it does not discuss LLM-judge manipulation, so the "
        "2026-07-27 withdrawal was correct.",
    ),
    "DBC-049": (
        "internal — inspectable",
        "agent-security-harness BI-005 'String Matching Collision' is present in "
        "protocol_tests/benchmark_integrity_harness.py. The Berkeley article does "
        "not discuss string- or hash-collision gaming, confirming the withdrawal.",
    ),
    # --- internal, unpublished -------------------------------------------------
    "DBC-001": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-002": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-004": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-021": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-022": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-023": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-024": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-025": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-027": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-030": ("internal — unpublished", _INTERNAL_UNPUBLISHED),
    "DBC-029": (
        "internal — unpublished",
        "The zhuanruhu half is now declared internal and unpublished. The "
        "'constitutional-agent governance' half names no specific constraint, so "
        "unlike DBC-005 there is no per-case locator to check. Weaker than "
        "inspectable, and recorded as such.",
    ),
    # --- still defective --------------------------------------------------------
    # Found defective by this pass and repaired within it. The fit records what
    # is true NOW — calling it "outstanding" after fixing it would be as wrong as
    # calling it clean before. The finding itself is preserved in the basis and
    # in `found_defective_by_this_pass`.
    "DBC-026": (
        "internal — unpublished",
        "Found DEFECTIVE by this pass and repaired within it, having escaped the "
        "audit's currency flag entirely. Revising the "
        "zhuanruhu half flipped the case's source digest, which marked the whole "
        "case 'revised' and moved it out of the flagged bucket — while the OX "
        "half sat unchanged and disproved. A compound citation defeats a per-case "
        "digest. Re-reading the advisory confirms it does not cover cross-agent "
        "or cross-session memory contamination. The external half is now "
        "withdrawn; the case rests on an unpublished internal run.",
    ),
}

_FIT_AFTER_VOCABULARY = {
    "external — verified",
    "external — partial",
    "internal — inspectable",
    "internal — unpublished",
    "none — outstanding",
}


def _currency(case) -> tuple[str, str | None]:
    """Return (verdict_currency, repair_disposition) for a case.

    Three states, not two. A repaired case is neither "as-audited" (its text
    changed) nor "stale, unadjudicated" (the change *was* the adjudication).
    """
    if case.id in _AUDIT_REPAIRS:
        return (
            "repaired — the audit's finding was accepted and the citation corrected "
            f"on {_REPAIRED_AT}; the case remains author-constructed and uncorroborated",
            _AUDIT_REPAIRS[case.id],
        )
    if _source_revised(case):
        return ("stale — source text changed after the audit; not re-adjudicated", None)
    return ("as-audited — source text unchanged since the audit", None)


_PROTOCOL_TESTS_DIR = Path(__file__).resolve().parents[1] / "protocol_tests"
_TEST_DEF_RE = re.compile(
    r'test_id\s*=\s*["\']([A-Z0-9]+-\d{3})["\']\s*,\s*\n?\s*name\s*=\s*["\']([^"\']+)["\']'
)


def _harvest_test_definitions() -> dict[str, dict]:
    """Read test id/name/category/owasp_asi from the live harness source.

    Deliberately parsed from ``protocol_tests/*.py`` and not from
    ``HARNESS_TEST_CATALOG.md``. The catalog is a dated extract; reading it
    would reintroduce exactly the staleness this check exists to detect.
    """
    found: dict[str, dict] = {}
    for path in sorted(_PROTOCOL_TESTS_DIR.glob("*.py")):
        src = path.read_text(encoding="utf-8", errors="replace")
        for match in _TEST_DEF_RE.finditer(src):
            test_id, name = match.group(1), match.group(2)
            if test_id in found:
                continue  # first definition wins; later ones are re-records
            tail = src[match.end() : match.end() + 400]
            category = re.search(r'category\s*=\s*["\']([^"\']+)["\']', tail)
            asi = re.search(r'owasp_asi\s*=\s*["\']([^"\']+)["\']', tail)
            found[test_id] = {
                "name": name,
                "category": category.group(1) if category else None,
                "owasp_asi": asi.group(1) if asi else None,
                "defined_in": f"protocol_tests/{path.name}",
            }
    return found


def _executable_test_link(case, tests: dict[str, dict]) -> dict:
    """Resolve a case's ``executable_test`` against the live harness.

    What this establishes and what it does not. It establishes whether the
    named test exists and whether its OWASP ASI category matches the case's.
    It does NOT establish that the test exercises the scenario — that is a
    reading, not a computation. A disagreeing category is a reason to look,
    not a finding on its own; a case can legitimately map to a test filed
    under a different ASI heading.
    """
    named = case.executable_test
    entry = tests.get(named) if named else None
    if entry is None:
        return {
            "names": named,
            "resolves_to_a_test": False,
            "test_name": None,
            "test_owasp_asi": None,
            "test_category": None,
            "defined_in": None,
            "owasp_asi_agrees": None,
            "note": (
                "not a resolvable test id in protocol_tests/ — this field names "
                "something else (a harness, or several ids)"
            ),
        }
    test_asi = entry["owasp_asi"]
    agrees = test_asi == case.owasp_asi if test_asi else None
    if agrees is True:
        note = ""
    elif agrees is False:
        note = (
            f"case is {case.owasp_asi}; the named test is "
            f"{test_asi} ({entry['name']}) — check the mapping"
        )
    else:
        note = (
            "the named test has no harvested OWASP ASI category; "
            "its category relationship to this case is unknown"
        )
    return {
        "names": named,
        "resolves_to_a_test": True,
        "test_name": entry["name"],
        "test_owasp_asi": test_asi,
        "test_category": entry["category"],
        "defined_in": entry["defined_in"],
        "owasp_asi_agrees": agrees,
        "note": note,
    }


def build_bundle() -> dict:
    grounding = _load_grounding()
    tests = _harvest_test_definitions()
    missing = [c.id for c in CORPUS if c.id not in grounding]
    if missing:
        raise SystemExit(f"grounding rows missing for: {missing}")

    cases = []
    for case in CORPUS:
        row = grounding[case.id]
        fixture = FIXTURES.get(case.id, {})
        currency, repair = _currency(case)
        cases.append(
            {
                **asdict(case),
                "grounding": {
                    "provenance": row["provenance"],
                    "evidence_fit": row["evidence_fit"],
                    "record_defect": row["record_defect"],
                    "note": row["note"],
                    "externally_corroborated": (
                        row["provenance"] in ("external", "untrace+ext")
                        and row["evidence_fit"] == "full"
                    ),
                    "audited_at_commit": GROUNDING_SOURCE["corpus_commit_audited"],
                    "source_revised_since_audit": _source_revised(case),
                    "repaired_in_response_to_audit": case.id in _AUDIT_REPAIRS,
                    "repair_disposition": repair,
                    # `provenance` above is the audit's transcription and describes
                    # the claim as it stood when audited. For a repaired case that
                    # claim has been withdrawn, so the two would otherwise read as a
                    # contradiction. The audit row is not rewritten: re-adjudicating
                    # it would be the same author grading his own correction.
                    "provenance_after_repair": _PROVENANCE_AFTER_REPAIR.get(case.id),
                    "verdict_currency": currency,
                    # Re-adjudication against the case's CURRENT text. Present
                    # only for cases whose source moved after the audit; absent
                    # means the audit's verdict still describes what you are
                    # reading and needs no restatement.
                    "readjudicated": case.id in _READJUDICATION,
                    "fit_after_readjudication": (
                        _READJUDICATION[case.id][0] if case.id in _READJUDICATION else None
                    ),
                    "readjudication_basis": (
                        _READJUDICATION[case.id][1] if case.id in _READJUDICATION else None
                    ),
                    "readjudicated_on": (
                        _READJUDICATED_ON if case.id in _READJUDICATION else None
                    ),
                    "readjudicated_by": (
                        _READJUDICATED_BY if case.id in _READJUDICATION else None
                    ),
                },
                "executable_test_link": _executable_test_link(case, tests),
                "tools": fixture.get("tools", []),
                "fixture_rationale": fixture.get("rationale", ""),
                # Executed at export time, never hand-assigned.
                "expected_scanner": {
                    "regex_metadata_scanner": bool(scanner_detects(case.id)),
                    "capability_rule_scanner": bool(capability_detects(case.id)),
                },
            }
        )

    fit_counts: dict[str, int] = {}
    defect_counts: dict[str, int] = {}
    prov_counts: dict[str, int] = {}
    for c in cases:
        g = c["grounding"]
        fit_counts[g["evidence_fit"]] = fit_counts.get(g["evidence_fit"], 0) + 1
        defect_counts[g["record_defect"]] = defect_counts.get(g["record_defect"], 0) + 1
        prov_counts[g["provenance"]] = prov_counts.get(g["provenance"], 0) + 1

    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for c in cases:
        by_category[c["category"]] = by_category.get(c["category"], 0) + 1
        by_severity[c["severity"]] = by_severity.get(c["severity"], 0) + 1

    repaired_n = sum(1 for c in cases if c["grounding"]["repaired_in_response_to_audit"])
    # "revised" now means changed for reasons other than an accepted audit finding.
    revised_n = sum(
        1
        for c in cases
        if c["grounding"]["source_revised_since_audit"]
        and not c["grounding"]["repaired_in_response_to_audit"]
    )
    still_flagged = sum(
        1
        for c in cases
        if not c["grounding"]["source_revised_since_audit"]
        and not c["grounding"]["repaired_in_response_to_audit"]
        and (c["grounding"]["evidence_fit"] == "none" or c["grounding"]["record_defect"] != "—")
    )

    readj_counts: dict[str, int] = {}
    for c in cases:
        fit = c["grounding"]["fit_after_readjudication"]
        if fit:
            readj_counts[fit] = readj_counts.get(fit, 0) + 1
    readj_outstanding = [
        c["id"]
        for c in cases
        if c["grounding"]["fit_after_readjudication"] == "none — outstanding"
    ]
    # A defect found and fixed inside one pass still has to be reported. Without
    # this, the only trace of DBC-026 would be an empty `outstanding` list, which
    # reads as "we looked and found nothing".
    readj_found_defective = [
        c["id"]
        for c in cases
        if c["grounding"]["readjudicated"]
        and c["grounding"]["repaired_in_response_to_audit"]
    ]
    # A repaired case has been adjudicated — the repair was the adjudication.
    # Only cases whose text moved and were then neither repaired nor re-read
    # count as still unaccounted for.
    not_readjudicated = [
        c["id"]
        for c in cases
        if c["grounding"]["source_revised_since_audit"]
        and not c["grounding"]["readjudicated"]
        and not c["grounding"]["repaired_in_response_to_audit"]
    ]

    link_unresolved = [
        c["id"] for c in cases if not c["executable_test_link"]["resolves_to_a_test"]
    ]
    link_disagrees = [
        c["id"] for c in cases if c["executable_test_link"]["owasp_asi_agrees"] is False
    ]

    regex_hits = sum(1 for c in cases if c["expected_scanner"]["regex_metadata_scanner"])
    cap_hits = sum(1 for c in cases if c["expected_scanner"]["capability_rule_scanner"])

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "benchmarks/dgb_bundle_export.py",
        "source_modules": [
            "benchmarks/decision_behavior_corpus.py",
            "benchmarks/tool_fixtures.py",
            "benchmarks/scanner_derived.py",
            "benchmarks/capability_scanner.py",
        ],
        "corpus_release": CORPUS_RELEASE,
        "grounding_audit": GROUNDING_SOURCE,
        "counts": {
            "total": len(cases),
            "tool_entries": sum(len(c["tools"]) for c in cases),
            "by_category": by_category,
            "by_severity": by_severity,
        },
        "grounding_currency": {
            "audited_at_commit": GROUNDING_SOURCE["corpus_commit_audited"],
            "audit_date": GROUNDING_SOURCE["audit_date"],
            "cases_with_source_revised_since_audit": revised_n,
            "cases_repaired_in_response_to_audit": repaired_n,
            "repaired_on": _REPAIRED_AT,
            "cases_still_as_audited": len(cases) - revised_n - repaired_n,
            "flagged_and_still_as_audited": still_flagged,
            "note": (
                "Three states, not two. A remediation pass landed the day after the "
                f"audit and revised {revised_n} of {len(cases)} source fields for "
                "reasons of its own; for those the evidence_fit and record_defect "
                "recorded here are stale and have NOT been re-adjudicated against "
                f"the revised text. A further {repaired_n} cases were repaired on "
                f"{_REPAIRED_AT} because the audit's finding was accepted: their "
                "unsupportable external attributions were removed and they are now "
                "declared author-constructed. That is a correction of the record, "
                "not a demonstration that the behaviour is corroborated — those "
                f"cases have no external support and say so. {still_flagged} cases "
                "carry a defect verdict against source text the audit actually read "
                "and remain outstanding. Re-adjudicating the revised cases is still "
                "outstanding work, and until it is done neither a stale defect nor "
                "an assumed repair should be reported as the current state."
            ),
        },
        "readjudication": {
            "performed_on": _READJUDICATED_ON,
            "performed_by": _READJUDICATED_BY,
            "cases_readjudicated": len(_READJUDICATION),
            "revised_cases_left_unadjudicated": len(not_readjudicated),
            "still_unadjudicated": not_readjudicated,
            "fit_after_distribution": readj_counts,
            "outstanding": readj_outstanding,
            "found_defective_by_this_pass": readj_found_defective,
            "sources_re_read": [
                "https://rdi.berkeley.edu/blog/trustworthy-benchmarks/",
                "https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-35625",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-35629",
                "https://metr.org/blog/2025-06-05-recent-reward-hacking/",
                "https://incidentdatabase.ai/cite/1442/",
            ],
            "note": (
                "The audit's verdicts described text that no longer exists. Every "
                "case whose source moved has now been re-read against its current "
                "wording, and where that wording names an external source the "
                "source itself was re-fetched rather than trusting the audit's "
                "transcription of it. Two cases the audit had left provisional for "
                "want of a locator (DBC-007, DBC-050) are now verified and carry "
                "one. One defect was found that the audit's own currency flag could "
                "not surface: DBC-026 revised half of a compound citation, which "
                "flipped the case digest and moved it out of the flagged bucket "
                "while the disproved half sat untouched. "
                "THIS PASS WAS PERFORMED BY THE CORPUS AUTHOR and is not "
                "independent review — it does not discharge the single-author "
                "limitation. What it changes is that each verdict now points at a "
                "named, fetchable locator a reader can check, instead of asking "
                "them to accept an unexamined 'stale'."
            ),
        },
        "executable_test_linkage": {
            "resolved_against": "protocol_tests/ at export time, not HARNESS_TEST_CATALOG.md",
            "cases_naming_a_resolvable_test": len(cases) - len(link_unresolved),
            "cases_naming_something_else": len(link_unresolved),
            "not_resolvable": link_unresolved,
            "owasp_asi_disagrees": len(link_disagrees),
            "owasp_asi_disagrees_cases": link_disagrees,
            "note": (
                "executable_test names a harness test; it has never asserted that "
                "the test exercises the case. This block makes that gap measurable "
                "instead of leaving it as prose. A disagreeing OWASP ASI category is "
                "a reason to check the mapping, not a finding on its own — a case can "
                "legitimately map to a test filed under a different heading. What it "
                "does establish is that the link was never machine-verified: "
                f"{len(link_unresolved)} cases name something that is not a test id "
                f"at all, and {len(link_disagrees)} name a test whose category "
                "disagrees with the case's own."
            ),
        },
        "evidence_fit_distribution": fit_counts,
        "record_defect_distribution": defect_counts,
        "provenance_distribution": prov_counts,
        "scanner_baseline": {
            "regex_metadata_scanner_detects": regex_hits,
            "capability_rule_scanner_detects": cap_hits,
            "of_total": len(cases),
            "note": (
                "Both figures are produced by executing the scanners in this "
                "repository over cases[].tools at export time. They are the "
                "numbers an independent scanner should be compared against, "
                "not a claim that either scanner is correct."
            ),
        },
        "known_limitations": {
            "single_author": (
                "The corpus, both scanners, the tool fixtures and the grounding "
                "audit share one author. Nothing in this bundle is independent "
                "corroboration of the corpus. Independent review is the "
                "outstanding check this bundle exists to make possible."
            ),
            "evidence_fit": (
                "AS AUDITED on 2026-07-27: 1 of 52 cases had full external "
                "evidence fit (DBC-009); 10 had a located source that did not "
                "substantiate them; 12 had a source that could not be located; "
                "13 were provisional. A remediation pass landed the day after "
                "and revised many source fields, so these figures describe the "
                "audited snapshot, not the current corpus. Read "
                "grounding_currency and each case's source_revised_since_audit "
                "before treating any single verdict as current."
            ),
            "executable_test_coverage": (
                "executable_test does not cover the case for 24 of 52 at the "
                f"{CORPUS_RELEASE} tag. The field names a harness test; it does "
                "not assert that the test exercises this specific scenario."
            ),
            "record_defects": (
                "AS AUDITED: 7 cases were misdescribed relative to their "
                "source and 1 carried an invalid identifier (DBC-032, "
                "CVE-2026-SSRF-MCP). All 7 misdescribed cases have had their "
                "source text revised since, so those verdicts are stale here "
                "and have not been re-adjudicated. A record defect is not the "
                "same as zero evidentiary support and is classified separately "
                "from evidence fit."
            ),
            "configs_a_and_b": (
                "Config A and Config B results elsewhere in this repository "
                "come from deterministic stub agents, not live models. Only "
                "the scanner arm is measured."
            ),
            "not_exercised": (
                "This bundle contains no live agent run, no Config D result, "
                "and no scoring. It is corpus plus fixtures plus executed "
                "scanner verdicts."
            ),
        },
        "scope": (
            "These cases describe decision-governance failure behaviours and "
            "the tool registries that accompany them. They do not establish "
            "that any particular product or implementation exhibits these "
            "behaviours, and the grounding block records, per case, how well "
            "the cited source supports the case as written."
        ),
        "usage": (
            "Run your own scanner over cases[].tools and compare against "
            "cases[].expected_scanner. Retain the cases both scanners miss: a "
            "scanner that flags everything has not demonstrated discrimination "
            "any more than one that flags nothing. Treat evidence_fit as a map "
            "of where the corpus is weakest, and start there."
        ),
        "cases": cases,
    }


def serialise(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=False) + "\n"


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = ap.parse_args()

    data = build_bundle()
    text = serialise(data)

    if args.stdout:
        print(text, end="")
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    c = data["counts"]
    s = data["scanner_baseline"]
    print(f"wrote {args.output} - {c['total']} cases, {c['tool_entries']} tool entries")
    print(
        f"scanner baseline: regex {s['regex_metadata_scanner_detects']}/{c['total']}, "
        f"capability {s['capability_rule_scanner_detects']}/{c['total']}"
    )
    fit = data["evidence_fit_distribution"]
    print(f"evidence fit: {fit}")


_GROUNDING: dict[str, dict] = {}  # populated below by _init_grounding()


def _init_grounding() -> None:
    """Load the transcribed Appendix A rows into _GROUNDING."""
    for line in _GROUNDING_TSV.strip().splitlines():
        cid, prov, fit, defect, note = line.split("\t")
        _GROUNDING[cid] = {
            "provenance": prov,
            "evidence_fit": fit,
            "record_defect": defect,
            "note": note,
        }


# id \t provenance \t evidence_fit \t record_defect \t note
_GROUNDING_TSV = """
DBC-001	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-002	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-003	external	partial	misdescription	CVE real and supports privilege escalation, but via silent shared-auth reconnects auto-approving operator.read->operator.admin, not 'permission inheritance'. https://nvd.nist.gov/vuln/detail/CVE-2026-35625
DBC-004	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-005	untrace+int	unresolved	untraceable source	grounding source could not be located
DBC-006	external	partial	misdescription	Same CVE; 'tool permission inheritance escalation' does not match the NVD text. https://nvd.nist.gov/vuln/detail/CVE-2026-35625
DBC-007	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-008	internal	full (internal)	—	grounded in Mike's own prior work — traceable, not external corroboration
DBC-009	external	full	—	OX documents prompt injection modifying local MCP config (CVE-2026-30615, Windsurf). https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
DBC-010	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-011	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-012	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-013	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-014	external	none	—	OX article does not cover credential relay or agent impersonation. https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
DBC-015	internal	full (internal)	—	grounded in Mike's own prior work — traceable, not external corroboration
DBC-016	external	none	—	OX article does not cover A2A cross-agent injection relay. https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
DBC-017	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-018	internal	full (internal)	—	grounded in Mike's own prior work — traceable, not external corroboration
DBC-019	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-020	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-021	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-022	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-023	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-024	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-025	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-026	untrace+ext	none	untraceable source	zhuanruhu untraceable; OX does not cover cross-agent memory contamination. https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
DBC-027	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-028	external	partial	misdescription	'Self-reported metrics ... are all attack surfaces' IS in the article; 'in RAG contexts' is absent — no RAG discussion. https://rdi.berkeley.edu/blog/trustworthy-benchmarks/
DBC-029	untrace+int	unresolved	untraceable source	grounding source could not be located
DBC-030	untraceable	unresolved	untraceable source	grounding source could not be located
DBC-031	external	none	—	$45M source does not substantiate a single agent approving an over-threshold trade (see 1g).
DBC-032	external	partial	invalid identifier	OX supports the broader STDIO-injection mechanism, but no located passage establishes the narrower tool-call/pre-validation sequence; the identifier is also invalid.
DBC-033	internal	full (internal)	—	grounded in Mike's own prior work — traceable, not external corroboration
DBC-034	internal	full (internal)	—	grounded in Mike's own prior work — traceable, not external corroboration
DBC-035	internal	full (internal)	—	grounded in Mike's own prior work — traceable, not external corroboration
DBC-036	external	partial	—	RDI half holds; $45M half unsupported (see 1g). https://rdi.berkeley.edu/blog/trustworthy-benchmarks/
DBC-037	external	partial	misdescription	CVE real and supports SSRF, but via unguarded configured base URLs in channel extensions, not 'tool URL'. BlueRock attribution correct: https://www.bluerock.io/post/mcp-furi-microsoft-markitdown-vulnerabilities · https://nvd.nist.gov/vuln/detail/CVE-2026-35629
DBC-038	external	none	—	Same $45M source; credential extraction in a payment flow not evidenced in it.
DBC-039	external	none	—	OX article does not cover phantom tool injection via MCP registration. https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
DBC-040	external	none	—	Same $45M source; payment structuring to evade limits not evidenced in it.
DBC-041	external	partial	misdescription	Byline is Wang, Mang, Cheung, Sen, Song (no Xu); 13 benchmarks audited, all rated critical risk, 45 exploits producing inflated OR perfect scores — not 'all 8 hackable for perfect'. https://rdi.berkeley.edu/blog/trustworthy-benchmarks/
DBC-042	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-043	external	none	—	Article does not discuss LLM-judge manipulation via embedded instructions. https://rdi.berkeley.edu/blog/trustworthy-benchmarks/
DBC-044	external	none	—	Article does not discuss contamination/memorization; answer leakage is adjacent but distinct. https://rdi.berkeley.edu/blog/trustworthy-benchmarks/
DBC-045	external	partial	misdescription	Berkeley Example 1 shows score injection via stack-frame manipulation in Frontier-CS; 'universal benchmark bypass' outruns the source. https://rdi.berkeley.edu/blog/trustworthy-benchmarks/
DBC-046	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-047	external	provisional	—	RDI half plausible; harness attestation half internally authored. Per-case locator not established. https://rdi.berkeley.edu/blog/trustworthy-benchmarks/
DBC-048	external	partial	misdescription	Berkeley shows a dummy C-extension / weak-validator exploit in Terminal-Bench; it does not establish the mechanism across 8 — or all 13 — benchmarks. https://rdi.berkeley.edu/blog/trustworthy-benchmarks/
DBC-049	external	none	—	Article does not discuss string collision or hash-collision gaming. https://rdi.berkeley.edu/blog/trustworthy-benchmarks/
DBC-050	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-051	external	provisional	—	source located and plausibly relevant; per-case evidence locator not established in this audit
DBC-052	internal	full (internal)	—	grounded in Mike's own prior work — traceable, not external corroboration
"""

_init_grounding()

if __name__ == "__main__":
    main()
