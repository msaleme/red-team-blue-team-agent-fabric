#!/usr/bin/env python3
"""Top 10 Failure Summary Generator

Analyzes one or more harness JSON reports and produces a ranked list of the
most common and severe failures across runs.

Ranking: severity (CRITICAL > HIGH > MEDIUM > LOW) then frequency.

Each entry includes: test ID, test name, category, severity, failure count,
affected modules, recommended fix, OWASP Agentic mapping, AIUC-1 mapping.

Usage:
    python scripts/top10_failures.py --reports run1.json run2.json --output top10.md
    python scripts/top10_failures.py --reports-dir ./reports/ --output top10.md
    python scripts/top10_failures.py --reports run1.json --json
    python scripts/top10_failures.py --reports-dir ./reports/ --json --output top10.json

Requires: Python 3.10+, PyYAML (for AIUC-1 mapping)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure repo root is on path so protocol_tests is importable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from protocol_tests.version import get_harness_version

HARNESS_VERSION = get_harness_version()

# ---------------------------------------------------------------------------
# Severity ranking (lower number = higher severity)
# ---------------------------------------------------------------------------

SEVERITY_RANK: dict[str, int] = {
    "P0-Critical": 0,
    "P1-High": 1,
    "P2-Medium": 2,
    "P3-Low": 3,
}

SEVERITY_LABELS: dict[str, str] = {
    "P0-Critical": "CRITICAL",
    "P1-High": "HIGH",
    "P2-Medium": "MEDIUM",
    "P3-Low": "LOW",
}


# ---------------------------------------------------------------------------
# OWASP Agentic Security Initiative categories
# ---------------------------------------------------------------------------

OWASP_AGENTIC_CATEGORIES: dict[str, str] = {
    "ASI01": "Prompt Injection & Input Manipulation",
    "ASI02": "Privilege Escalation & Authorization Bypass",
    "ASI03": "Capability & Task Hijacking",
    "ASI04": "Tool Poisoning & Supply Chain",
    "ASI05": "Data Leakage & Context Isolation",
    "ASI06": "Protocol & Transport Security",
    "ASI07": "Identity, Authentication & Trust",
    "ASI08": "Observability & Monitoring Gaps",
    "ASI09": "Unsafe Agent Autonomy",
    "ASI10": "Multi-Agent Trust & Delegation",
}


# ---------------------------------------------------------------------------
# Recommended fix lookup (category-based heuristics)
# ---------------------------------------------------------------------------

RECOMMENDED_FIXES: dict[str, str] = {
    "tool_discovery": "Validate tool manifests against an allowlist; reject unexpected tool names or descriptions.",
    "tool_poisoning": "Implement tool attestation and verify provenance before execution.",
    "capability_negotiation": "Enforce strict capability negotiation; reject unknown or elevated capabilities.",
    "capability_escalation": "Apply least-privilege defaults; audit capability grants at each protocol step.",
    "resource_traversal": "Validate resource paths server-side; deny path traversal patterns.",
    "prompt_injection": "Apply input sanitization and context-boundary enforcement on all prompts.",
    "sampling": "Restrict sampling API surface; validate sampling parameters against policy.",
    "input_validation": "Enforce strict JSON-RPC schema validation; reject malformed payloads.",
    "batch_abuse": "Rate-limit batch requests; cap batch size and validate each sub-request.",
    "cross_protocol": "Isolate protocol handlers; validate content-type boundaries.",
    "identity": "Implement mutual authentication; verify agent identity claims cryptographically.",
    "authentication": "Require authentication tokens; enforce token rotation and expiry.",
    "authorization": "Enforce RBAC/ABAC policies; audit authorization decisions.",
    "data_leakage": "Apply output filtering; enforce context isolation between sessions.",
    "context_isolation": "Separate session contexts; prevent cross-session data bleed.",
    "transport_security": "Enforce TLS 1.2+; reject downgrade attempts.",
    "observability": "Implement structured logging for all security-relevant events.",
    "monitoring": "Deploy anomaly detection on agent behavior patterns.",
    "autonomy": "Require human-in-the-loop for high-risk actions; enforce action budgets.",
    "delegation": "Validate delegation chains; enforce trust boundaries between agents.",
    "jailbreak": "Strengthen system prompt enforcement; add jailbreak detection layer.",
    "over_refusal": "Tune safety filters to reduce false positive rate on legitimate requests.",
    "harmful_output": "Implement output content filtering with category-specific classifiers.",
    "cbrn": "Block CBRN-related content with high-confidence classifiers; log attempts.",
    "incident_response": "Implement automated incident detection and response playbooks.",
    "memory": "Enforce memory isolation; sanitize stored context on session boundaries.",
    "supply_chain": "Verify tool and plugin provenance; implement SBOMs for agent dependencies.",
    "return_channel": "Sanitize all return channel outputs; prevent context manipulation via responses.",
}


def _get_recommended_fix(category: str, test_name: str) -> str:
    """Look up a recommended fix based on category, falling back to a generic message."""
    # Try exact match
    cat_lower = category.lower().replace(" ", "_").replace("-", "_")
    if cat_lower in RECOMMENDED_FIXES:
        return RECOMMENDED_FIXES[cat_lower]
    # Try partial match
    for key, fix in RECOMMENDED_FIXES.items():
        if key in cat_lower or cat_lower in key:
            return fix
    # Generic
    return "Review test details and implement appropriate security controls for this category."


# ---------------------------------------------------------------------------
# AIUC-1 mapping loader
# ---------------------------------------------------------------------------

def _load_aiuc1_index() -> dict[str, dict[str, Any]]:
    """Load AIUC-1 mapping and build {test_id: {req_id, title, owasp_asi}} index."""
    try:
        import yaml
    except ImportError:
        return {}

    mapping_path = os.path.join(REPO_ROOT, "configs", "aiuc1_mapping.yaml")
    if not os.path.exists(mapping_path):
        return {}

    try:
        with open(mapping_path) as f:
            data = yaml.safe_load(f)
    except Exception:
        return {}

    index: dict[str, dict[str, Any]] = {}
    categories = data.get("categories", {})
    for _cat_key, cat_data in categories.items():
        for req_id, req_def in cat_data.get("requirements", {}).items():
            owasp_asi = req_def.get("owasp_asi", "")
            for tid in req_def.get("test_ids", []):
                index[tid] = {
                    "req_id": req_id,
                    "title": req_def.get("title", ""),
                    "owasp_asi": owasp_asi,
                    "owasp_name": OWASP_AGENTIC_CATEGORIES.get(owasp_asi, ""),
                }
    return index


# ---------------------------------------------------------------------------
# Report loading
# ---------------------------------------------------------------------------

def load_reports(paths: list[str]) -> list[dict[str, Any]]:
    """Load multiple JSON report files."""
    reports: list[dict[str, Any]] = []
    for p in paths:
        with open(p) as f:
            reports.append(json.load(f))
    return reports


def discover_reports(directory: str) -> list[str]:
    """Find all .json files in a directory (non-recursive)."""
    d = Path(directory)
    if not d.is_dir():
        print(f"Error: not a directory: {directory}", file=sys.stderr)
        sys.exit(1)
    paths = sorted(str(p) for p in d.glob("*.json"))
    if not paths:
        print(f"Error: no JSON files found in {directory}", file=sys.stderr)
        sys.exit(1)
    return paths


# ---------------------------------------------------------------------------
# Failure analysis
# ---------------------------------------------------------------------------

def analyze_failures(
    reports: list[dict[str, Any]],
    aiuc1_index: dict[str, dict[str, Any]],
    top_n: int = 10,
) -> list[dict[str, Any]]:
    """Aggregate failures across reports and return a ranked list.

    Each failure entry contains:
        test_id, name, category, severity, failure_count, report_count,
        affected_modules, recommended_fix, owasp_mapping, aiuc1_mapping
    """
    # Collect all failures keyed by test_id
    failure_data: dict[str, dict[str, Any]] = {}

    for report in reports:
        suite_name = report.get("suite", "unknown")
        results = report.get("results", [])
        for r in results:
            if not isinstance(r, dict):
                continue
            if r.get("passed", False):
                continue

            tid = r.get("test_id", "unknown")
            if tid not in failure_data:
                failure_data[tid] = {
                    "test_id": tid,
                    "name": r.get("name", tid),
                    "category": r.get("category", "unknown"),
                    "severity": r.get("severity", "P3-Low"),
                    "failure_count": 0,
                    "affected_suites": set(),
                    "details_sample": r.get("details", ""),
                    "owasp_asi": r.get("owasp_asi", ""),
                }
            failure_data[tid]["failure_count"] += 1
            failure_data[tid]["affected_suites"].add(suite_name)

    # Enrich with AIUC-1 / OWASP data
    for tid, fd in failure_data.items():
        aiuc1 = aiuc1_index.get(tid, {})
        if aiuc1:
            fd["aiuc1_req"] = aiuc1.get("req_id", "")
            fd["aiuc1_title"] = aiuc1.get("title", "")
            if not fd["owasp_asi"] and aiuc1.get("owasp_asi"):
                fd["owasp_asi"] = aiuc1["owasp_asi"]
        else:
            fd["aiuc1_req"] = ""
            fd["aiuc1_title"] = ""

        # OWASP name lookup
        fd["owasp_name"] = OWASP_AGENTIC_CATEGORIES.get(fd["owasp_asi"], "")

        # Recommended fix
        fd["recommended_fix"] = _get_recommended_fix(fd["category"], fd["name"])

        # Convert set to sorted list
        fd["affected_suites"] = sorted(fd["affected_suites"])

    # Rank: severity (ascending rank number = higher priority), then frequency (descending)
    ranked = sorted(
        failure_data.values(),
        key=lambda f: (
            SEVERITY_RANK.get(f["severity"], 99),
            -f["failure_count"],
        ),
    )

    return ranked[:top_n]


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def generate_markdown(
    failures: list[dict[str, Any]],
    report_count: int,
    total_failures: int,
    timestamp: str,
) -> str:
    """Generate a markdown Top 10 Failures summary."""
    lines: list[str] = [
        "# Top 10 Failure Summary",
        "",
        f"**Generated:** {timestamp}",
        f"**Harness Version:** {HARNESS_VERSION}",
        f"**Reports Analyzed:** {report_count}",
        f"**Total Unique Failures:** {total_failures}",
        "",
        "---",
        "",
    ]

    if not failures:
        lines.append("No failures found across the analyzed reports.")
        return "\n".join(lines)

    lines.extend([
        "## Ranked Failures",
        "",
        "| Rank | Test ID | Name | Severity | Count | Category | OWASP | AIUC-1 |",
        "|------|---------|------|----------|-------|----------|-------|--------|",
    ])

    for i, f in enumerate(failures, 1):
        sev_label = SEVERITY_LABELS.get(f["severity"], f["severity"])
        owasp_str = f["owasp_asi"] if f["owasp_asi"] else "--"
        aiuc1_str = f["aiuc1_req"] if f["aiuc1_req"] else "--"
        lines.append(
            f"| {i} | {f['test_id']} | {f['name']} | **{sev_label}** "
            f"| {f['failure_count']} | {f['category']} | {owasp_str} | {aiuc1_str} |"
        )

    lines.extend(["", "---", ""])

    # Detailed breakdown
    lines.append("## Detailed Breakdown")
    lines.append("")

    for i, f in enumerate(failures, 1):
        sev_label = SEVERITY_LABELS.get(f["severity"], f["severity"])
        lines.extend([
            f"### {i}. {f['test_id']} -- {f['name']}",
            "",
            f"- **Severity:** {sev_label} ({f['severity']})",
            f"- **Category:** {f['category']}",
            f"- **Failure Count:** {f['failure_count']} across {len(f['affected_suites'])} suite(s)",
            f"- **Affected Suites:** {', '.join(f['affected_suites'])}",
        ])

        if f["owasp_asi"]:
            lines.append(f"- **OWASP Agentic:** {f['owasp_asi']} ({f['owasp_name']})")
        if f["aiuc1_req"]:
            lines.append(f"- **AIUC-1 Requirement:** {f['aiuc1_req']} ({f['aiuc1_title']})")

        lines.append(f"- **Recommended Fix:** {f['recommended_fix']}")

        if f.get("details_sample"):
            # Truncate long details
            details = f["details_sample"]
            if len(details) > 200:
                details = details[:200] + "..."
            lines.append(f"- **Details:** {details}")

        lines.extend(["", ""])

    lines.extend([
        "---",
        "",
        f"*Generated by Agent Security Harness v{HARNESS_VERSION} Top 10 Failure Analyzer*",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def generate_json(
    failures: list[dict[str, Any]],
    report_count: int,
    total_failures: int,
    timestamp: str,
) -> dict[str, Any]:
    """Build a structured JSON output for the Top 10 summary."""
    return {
        "schema_version": "1.0.0",
        "generated_at": timestamp,
        "harness_version": HARNESS_VERSION,
        "reports_analyzed": report_count,
        "total_unique_failures": total_failures,
        "top_failures": [
            {
                "rank": i + 1,
                "test_id": f["test_id"],
                "name": f["name"],
                "category": f["category"],
                "severity": f["severity"],
                "severity_label": SEVERITY_LABELS.get(f["severity"], f["severity"]),
                "failure_count": f["failure_count"],
                "affected_suites": f["affected_suites"],
                "owasp_mapping": {
                    "id": f["owasp_asi"],
                    "name": f["owasp_name"],
                } if f["owasp_asi"] else None,
                "aiuc1_mapping": {
                    "requirement": f["aiuc1_req"],
                    "title": f["aiuc1_title"],
                } if f["aiuc1_req"] else None,
                "recommended_fix": f["recommended_fix"],
                "details_sample": f.get("details_sample", ""),
            }
            for i, f in enumerate(failures)
        ],
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_top10(
    report_paths: list[str],
    output_path: str | None = None,
    as_json: bool = False,
    top_n: int = 10,
) -> str:
    """Analyze reports and produce the Top N failure summary.

    Returns the output content as a string.
    """
    reports = load_reports(report_paths)
    aiuc1_index = _load_aiuc1_index()

    failures = analyze_failures(reports, aiuc1_index, top_n=top_n)

    # Count total unique failures (not just top N)
    all_failures: set[str] = set()
    for report in reports:
        for r in report.get("results", []):
            if isinstance(r, dict) and not r.get("passed", False):
                all_failures.add(r.get("test_id", "unknown"))
    total_failures = len(all_failures)

    timestamp = datetime.now(timezone.utc).isoformat()

    if as_json:
        data = generate_json(failures, len(reports), total_failures, timestamp)
        content = json.dumps(data, indent=2, default=str)
    else:
        content = generate_markdown(failures, len(reports), total_failures, timestamp)

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            f.write(content)
        print(f"Top {top_n} failure summary written to {output_path}")
    else:
        print(content)

    # Print brief summary to stderr if writing to file
    if output_path:
        print(f"\n{'='*50}", file=sys.stderr)
        print("TOP FAILURES SUMMARY", file=sys.stderr)
        print(f"{'='*50}", file=sys.stderr)
        print(f"  Reports analyzed:     {len(reports)}", file=sys.stderr)
        print(f"  Unique failures:      {total_failures}", file=sys.stderr)
        print(f"  Top {top_n} shown", file=sys.stderr)
        if failures:
            print(f"  Highest severity:     {SEVERITY_LABELS.get(failures[0]['severity'], failures[0]['severity'])}", file=sys.stderr)
            print(f"  Most frequent:        {failures[0]['test_id']} ({failures[0]['failure_count']}x)", file=sys.stderr)
        print(f"{'='*50}", file=sys.stderr)

    return content


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a ranked Top 10 failure summary from harness test reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Analyze specific report files
    python scripts/top10_failures.py --reports run1.json run2.json --output top10.md

    # Scan a directory for all JSON reports
    python scripts/top10_failures.py --reports-dir ./reports/ --output top10.md

    # JSON output
    python scripts/top10_failures.py --reports run1.json --json --output top10.json

    # Print to stdout
    python scripts/top10_failures.py --reports run1.json

    # Custom top-N
    python scripts/top10_failures.py --reports run1.json --top 20
        """,
    )
    parser.add_argument(
        "--reports", nargs="+", metavar="PATH",
        help="One or more harness JSON report files",
    )
    parser.add_argument(
        "--reports-dir", metavar="DIR",
        help="Directory containing JSON report files",
    )
    parser.add_argument(
        "--output", metavar="PATH",
        help="Output file path (default: print to stdout)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON instead of markdown",
    )
    parser.add_argument(
        "--top", type=int, default=10, metavar="N",
        help="Number of top failures to include (default: 10)",
    )

    args = parser.parse_args()

    # Determine report paths
    report_paths: list[str] = []
    if args.reports:
        report_paths.extend(args.reports)
    if args.reports_dir:
        report_paths.extend(discover_reports(args.reports_dir))

    if not report_paths:
        parser.error("Provide --reports and/or --reports-dir")

    # Validate files exist
    for p in report_paths:
        if not os.path.exists(p):
            print(f"Error: file not found: {p}", file=sys.stderr)
            sys.exit(1)

    build_top10(
        report_paths=report_paths,
        output_path=args.output,
        as_json=args.json_output,
        top_n=args.top,
    )


if __name__ == "__main__":
    main()
