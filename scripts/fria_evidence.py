#!/usr/bin/env python3
"""FRIA Evidence Collection Module

Maps harness test results to EU AI Act Article 27 FRIA (Fundamental Rights
Impact Assessment) categories, generating structured evidence for compliance.

Consumes harness JSON output and produces FRIA-categorized evidence with
gap identification.

Tracks GitHub issue #158.

Usage:
    python scripts/fria_evidence.py --report results.json
    python scripts/fria_evidence.py --report results.json --output fria.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


# FRIA categories per EU AI Act Article 27
FRIA_CATEGORIES = {
    "safety": {
        "title": "Safety and Physical Integrity",
        "description": "Impact on safety and physical integrity of natural persons",
        "test_patterns": {
            "IR-": "Incident response and cascade containment",
            "CBRN-": "CBRN content prevention",
            "MCP-": "MCP protocol security",
        },
        "test_ids": [
            "IR-001", "IR-002", "IR-005", "IR-006", "IR-008",
            "IR-009", "IR-010", "IR-011", "IR-012",
            "CBRN-001", "CBRN-002", "CBRN-003",
            "MCP-001", "MCP-002", "MCP-003", "MCP-006",
        ],
    },
    "non_discrimination": {
        "title": "Non-Discrimination and Equality",
        "description": "Impact on non-discrimination, equality, and bias",
        "test_patterns": {
            "FPR-": "Over-refusal / false positive rate (proxy for bias)",
            "HO-": "Harmful output detection",
        },
        "test_ids": [
            "HO-001", "HO-002",
        ],
        "gap_note": "No dedicated bias/fairness harness. FPR tests provide partial proxy coverage.",
    },
    "privacy": {
        "title": "Privacy and Data Protection",
        "description": "Impact on privacy and protection of personal data",
        "test_patterns": {
            "MEM-": "Memory poisoning and data exfiltration",
            "DATA-": "Data classification and provenance",
        },
        "test_ids": [
            "MEM-002", "MEM-005", "MEM-010",
            "DATA-001", "DATA-002", "DATA-003",
        ],
    },
    "human_oversight": {
        "title": "Human Oversight",
        "description": "Impact on effective human oversight and agency",
        "test_patterns": {
            "AUDIT-": "Audit trail and non-repudiation",
            "CP-": "Capability profile and logging",
            "AIUC-E": "AIUC-1 safety requirements",
        },
        "test_ids": [
            "AUDIT-001", "AUDIT-002",
            "CP-001", "CP-009",
            "AIUC-E001", "AIUC-E002", "AIUC-E003",
        ],
    },
    "transparency": {
        "title": "Transparency and Explainability",
        "description": "Impact on transparency, explainability, and information provision",
        "test_patterns": {
            "PRV-": "Provenance and attestation",
            "WM-": "Watermark compliance (Article 50)",
            "ATT-": "Attestation reports",
        },
        "test_ids": [
            "PRV-010", "PRV-011", "PRV-012",
            "WM-001", "WM-002", "WM-003", "WM-004", "WM-005",
            "ATT-001", "ATT-002", "ATT-003", "ATT-004",
        ],
    },
    "accountability": {
        "title": "Accountability and Redress",
        "description": "Impact on accountability, redress, and governance",
        "test_patterns": {
            "AUDIT-": "Audit trail completeness",
            "IR-006": "Log completeness for incident response",
            "AUTHZ-": "Authorization and delegation",
        },
        "test_ids": [
            "AUDIT-001", "AUDIT-002",
            "IR-006", "IR-007",
            "AUTHZ-001", "AUTHZ-002", "AUTHZ-003",
        ],
    },
}


def generate_fria_evidence(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Map harness test results to FRIA categories.

    Args:
        results: List of test result dicts from harness JSON output.

    Returns:
        FRIA evidence dict with per-category status and gap analysis.
    """
    result_by_id = {r.get("test_id", ""): r for r in results if r.get("test_id")}

    categories: dict[str, dict] = {}
    total_covered = 0
    total_flagged = 0
    total_gaps = 0

    for cat_id, cat_def in FRIA_CATEGORIES.items():
        mapped_ids = cat_def["test_ids"]
        matched = [tid for tid in mapped_ids if tid in result_by_id]
        passed = sum(1 for tid in matched if result_by_id[tid].get("passed", False))
        failed = len(matched) - passed

        if not matched:
            if cat_def.get("gap_note"):
                status = "gap"
                total_gaps += 1
            else:
                status = "no_results"
                total_gaps += 1
        elif failed > 0:
            status = "flagged"
            total_flagged += 1
        else:
            status = "covered"
            total_covered += 1

        # Build evidence narrative
        if status == "covered":
            narrative = (
                f"All {len(matched)} mapped tests pass. Evidence supports that "
                f"the system adequately addresses {cat_def['description'].lower()}."
            )
        elif status == "flagged":
            failing_ids = [tid for tid in matched if not result_by_id[tid].get("passed", False)]
            narrative = (
                f"{failed} of {len(matched)} tests failing ({', '.join(failing_ids)}). "
                f"Deployment may pose risks to {cat_def['description'].lower()}. "
                "Remediation required before FRIA approval."
            )
        elif status == "gap":
            narrative = (
                f"Insufficient test coverage for {cat_def['description'].lower()}. "
                f"{cat_def.get('gap_note', 'Additional tests needed.')} "
                f"Expected tests: {', '.join(mapped_ids[:5])}{'...' if len(mapped_ids) > 5 else ''}."
            )
        else:
            narrative = (
                f"No test results available for {cat_def['description'].lower()}. "
                f"Run the harness with relevant modules to generate evidence."
            )

        categories[cat_id] = {
            "title": cat_def["title"],
            "description": cat_def["description"],
            "status": status,
            "tests_mapped": len(mapped_ids),
            "tests_run": len(matched),
            "passed": passed,
            "failed": failed,
            "narrative": narrative,
            "test_coverage": {
                pattern: desc for pattern, desc in cat_def["test_patterns"].items()
            },
            "gap_note": cat_def.get("gap_note", ""),
        }

    total = len(FRIA_CATEGORIES)
    overall = "compliant" if total_flagged == 0 and total_gaps == 0 else (
        "non_compliant" if total_flagged > 0 else "incomplete"
    )

    return {
        "framework": "EU AI Act Article 27 — Fundamental Rights Impact Assessment",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall,
        "summary": {
            "total_categories": total,
            "covered": total_covered,
            "flagged": total_flagged,
            "gaps": total_gaps,
        },
        "categories": categories,
    }


def fria_narrative_report(evidence: dict[str, Any]) -> str:
    """Generate human-readable FRIA narrative from evidence.

    Args:
        evidence: Output from generate_fria_evidence().

    Returns:
        Markdown-formatted FRIA report.
    """
    lines: list[str] = []
    lines.append("# Fundamental Rights Impact Assessment (FRIA)")
    lines.append("## EU AI Act Article 27 — Compliance Evidence Report\n")
    lines.append(f"Generated: {evidence.get('generated_at', 'unknown')}\n")

    summary = evidence["summary"]
    lines.append(f"**Overall Status: {evidence['overall_status'].upper()}**")
    lines.append(f"- Categories covered: {summary['covered']}/{summary['total_categories']}")
    lines.append(f"- Categories flagged: {summary['flagged']}")
    lines.append(f"- Coverage gaps: {summary['gaps']}\n")

    status_icons = {
        "covered": "PASS",
        "flagged": "FAIL",
        "gap": "GAP",
        "no_results": "N/A",
    }

    for cat_id, cat_data in evidence["categories"].items():
        icon = status_icons.get(cat_data["status"], "?")
        lines.append(f"### [{icon}] {cat_data['title']}")
        lines.append(f"*{cat_data['description']}*\n")
        lines.append(cat_data["narrative"])
        lines.append(f"\nTests: {cat_data['passed']}/{cat_data['tests_run']} passing "
                     f"({cat_data['tests_mapped']} mapped)\n")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="FRIA Evidence Collection")
    parser.add_argument("--report", required=True, help="Harness JSON report path")
    parser.add_argument("--output", "-o", help="Output FRIA JSON path")
    parser.add_argument("--narrative", action="store_true", help="Print narrative report")
    args = parser.parse_args()

    with open(args.report) as f:
        data = json.load(f)

    results = data.get("results", [])
    evidence = generate_fria_evidence(results)

    if args.narrative:
        print(fria_narrative_report(evidence))
    elif args.output:
        with open(args.output, "w") as f:
            json.dump(evidence, f, indent=2)
        print(f"FRIA evidence written to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
