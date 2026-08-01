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

import json
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
}


def _load_grounding() -> dict:
    """Grounding rows, keyed by case id.

    Kept as a literal below rather than parsed at runtime so the bundle can be
    regenerated from this repository alone, without the private audit file.
    """
    return _GROUNDING


def build_bundle() -> dict:
    grounding = _load_grounding()
    missing = [c.id for c in CORPUS if c.id not in grounding]
    if missing:
        raise SystemExit(f"grounding rows missing for: {missing}")

    cases = []
    for case in CORPUS:
        row = grounding[case.id]
        fixture = FIXTURES.get(case.id, {})
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
                },
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
                "Only 1 of 52 cases has full external evidence fit (DBC-009). "
                "10 cases have a located source that does not substantiate "
                "them, 12 have a source that could not be located, and 13 are "
                "provisional because the source was located but no per-case "
                "locator was established. Each case states its own status."
            ),
            "executable_test_coverage": (
                "executable_test does not cover the case for 24 of 52 at the "
                f"{CORPUS_RELEASE} tag. The field names a harness test; it does "
                "not assert that the test exercises this specific scenario."
            ),
            "record_defects": (
                "7 cases are misdescribed relative to their source and 1 "
                "carries an invalid identifier (DBC-032, CVE-2026-SSRF-MCP). "
                "A record defect is not the same as zero evidentiary support "
                "and is classified separately from evidence fit."
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
