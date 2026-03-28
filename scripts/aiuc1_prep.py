#!/usr/bin/env python3
"""AIUC-1 Pre-Certification Readiness Tool

Runs the full agent-security harness suite (or accepts a pre-existing report JSON)
and maps results to AIUC-1 certification requirements, generating a readiness report.

Usage:
    # Run harness against a target and generate readiness report
    python scripts/aiuc1_prep.py --url http://localhost:8080/mcp

    # Use pre-existing report JSON files
    python scripts/aiuc1_prep.py --reports reports/mcp-report.json reports/a2a-report.json

    # Simulation mode (no live target needed)
    python scripts/aiuc1_prep.py --simulate

    # Custom output directory
    python scripts/aiuc1_prep.py --simulate --output-dir my-reports/

Requires: Python 3.10+, PyYAML (for mapping file loading)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _get_harness_version() -> str:
    """Read version from pyproject.toml or fall back to importlib.metadata."""
    try:
        from importlib.metadata import version as pkg_version
        return pkg_version("agent-security-harness")
    except Exception:
        pass
    try:
        _toml = Path(__file__).resolve().parent.parent / "pyproject.toml"
        for line in _toml.read_text().splitlines():
            if line.strip().startswith("version"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "unknown"


HARNESS_VERSION = _get_harness_version()


# ---------------------------------------------------------------------------
# AIUC-1 Requirement Definitions
# ---------------------------------------------------------------------------

@dataclass
class RequirementStatus:
    req_id: str
    title: str
    category: str
    status: str  # COVERED+PASS, COVERED+FAIL, NOT YET COVERED
    test_ids: list[str] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    total: int = 0
    notes: str = ""


# Full AIUC-1 requirement mapping
AIUC1_REQUIREMENTS: dict[str, dict] = {
    # Security (B001-B005)
    "B001": {
        "title": "Tool Poisoning Prevention",
        "category": "Security",
        "test_ids": ["MCP-001", "MCP-002", "MCP-003"],
    },
    "B002": {
        "title": "Capability Escalation Prevention",
        "category": "Security",
        "test_ids": ["MCP-004", "MCP-005"],
    },
    "B003": {
        "title": "Protocol Downgrade Prevention",
        "category": "Security",
        "test_ids": ["MCP-006", "MCP-007"],
    },
    "B004": {
        "title": "Input Validation & Injection Prevention",
        "category": "Security",
        "test_ids": ["MCP-008", "MCP-009", "MCP-010"],
    },
    "B005": {
        "title": "Agent Identity & Authentication",
        "category": "Security",
        "test_ids": [
            "ID-001", "ID-002", "ID-003", "ID-004", "ID-005", "ID-006",
            "ID-007", "ID-008", "ID-009", "ID-010", "ID-011", "ID-012",
            "ID-013", "ID-014", "ID-015", "ID-016", "ID-017", "ID-018",
        ],
    },
    # Reliability (C001-C010)
    "C001": {
        "title": "Agent Card Spoofing Prevention",
        "category": "Reliability",
        "test_ids": ["A2A-001", "A2A-002"],
    },
    "C002": {
        "title": "Task Lifecycle Integrity",
        "category": "Reliability",
        "test_ids": ["A2A-003", "A2A-004", "A2A-005"],
    },
    "C003": {
        "title": "Harmful Output Prevention",
        "category": "Reliability",
        "test_ids": ["AIUC-C003a", "AIUC-C003b"],
    },
    "C004": {
        "title": "Scope Enforcement",
        "category": "Reliability",
        "test_ids": ["AIUC-C004a", "AIUC-C004b", "AIUC-C004c"],
    },
    "C005": {
        "title": "Message Integrity & Replay Prevention",
        "category": "Reliability",
        "test_ids": ["A2A-006", "A2A-007"],
    },
    "C006": {
        "title": "Context Isolation",
        "category": "Reliability",
        "test_ids": ["A2A-008", "A2A-009"],
    },
    "C007": {
        "title": "Streaming Protocol Robustness",
        "category": "Reliability",
        "test_ids": ["A2A-010"],
    },
    "C008": {
        "title": "Push Notification Security",
        "category": "Reliability",
        "test_ids": ["A2A-011"],
    },
    "C009": {
        "title": "Protocol Conformance",
        "category": "Reliability",
        "test_ids": ["A2A-012"],
    },
    "C010": {
        "title": "Payment Protocol Security",
        "category": "Reliability",
        "test_ids": ["L4-001", "L4-002"],
    },
    # Transparency (D001-D004)
    "D001": {
        "title": "Attestation Report Generation",
        "category": "Transparency",
        "test_ids": ["ATT-001", "ATT-002"],
    },
    "D002": {
        "title": "Scope Annotations",
        "category": "Transparency",
        "test_ids": ["ATT-003", "ATT-004"],
    },
    "D003": {
        "title": "Supply Chain Provenance",
        "category": "Transparency",
        "test_ids": ["PROV-001", "PROV-002"],
    },
    "D004": {
        "title": "Audit Trail Completeness",
        "category": "Transparency",
        "test_ids": ["ID-011", "ID-012"],
    },
    # Safety (E001-E003) - GAP
    "E001": {
        "title": "Incident Detection Latency",
        "category": "Safety",
        "test_ids": ["AIUC-E001"],
        "gap": True,
        "gap_notes": "Simulation-mode test exists but live endpoint validation needed for certification.",
    },
    "E002": {
        "title": "Incident Containment",
        "category": "Safety",
        "test_ids": ["AIUC-E002"],
        "gap": True,
        "gap_notes": "Requires integration with real kill-switch / circuit-breaker mechanisms.",
    },
    "E003": {
        "title": "Incident Audit Trail",
        "category": "Safety",
        "test_ids": ["AIUC-E003"],
        "gap": True,
        "gap_notes": "Requires integration with real audit logging infrastructure.",
    },
    # Content Safety (F001-F002) - GAP
    "F001": {
        "title": "Harmful Content Filtering",
        "category": "Content Safety",
        "test_ids": [],
        "gap": True,
        "gap_notes": "No dedicated content filtering harness yet. Need hate speech, misinformation, and manipulative content test suite.",
    },
    "F002": {
        "title": "CBRN Content Prevention",
        "category": "Content Safety",
        "test_ids": ["AIUC-F002a", "AIUC-F002b", "AIUC-F002c", "AIUC-F002d"],
        "gap": True,
        "gap_notes": "Simulation-mode tests exist but require live LLM endpoint testing.",
    },
}


# ---------------------------------------------------------------------------
# Report loading
# ---------------------------------------------------------------------------

def load_report(path: str) -> list[dict]:
    """Load test results from a harness JSON report file."""
    with open(path) as f:
        data = json.load(f)
    return data.get("results", [])


def run_harness(url: str, harnesses: list[str] | None = None, simulate: bool = False) -> list[dict]:
    """Run harness suites and collect results.

    Returns combined list of test result dicts.
    """
    all_results: list[dict] = []
    suites = harnesses or ["mcp", "a2a", "identity"]
    tmp_dir = tempfile.mkdtemp(prefix="aiuc1_")

    for suite in suites:
        cmd = [sys.executable, "-m", f"protocol_tests.{_module_for_suite(suite)}"]
        if simulate:
            cmd.append("--simulate")
        else:
            cmd.extend(["--url", url])
        report_path = os.path.join(tmp_dir, f"aiuc1_{suite}_report.json")
        cmd.extend(["--report", report_path])

        print(f"  Running {suite} harness...", flush=True)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(Path(__file__).parent.parent),
            )
            if os.path.exists(report_path):
                all_results.extend(load_report(report_path))
            else:
                print(f"    Warning: {suite} harness did not produce a report file")
                if result.stderr:
                    print(f"    stderr: {result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            print(f"    Warning: {suite} harness timed out after 120s")
        except Exception as e:
            print(f"    Warning: Failed to run {suite} harness: {e}")

    return all_results


def _module_for_suite(suite: str) -> str:
    """Map suite name to module path."""
    mapping = {
        "mcp": "mcp_harness",
        "a2a": "a2a_harness",
        "identity": "identity_harness",
        "l402": "l402_harness",
        "x402": "x402_harness",
        "aiuc1": "aiuc1_compliance_harness",
        "provenance": "provenance_harness",
        "attestation": "attestation",
    }
    return mapping.get(suite, suite)


# ---------------------------------------------------------------------------
# Mapping engine
# ---------------------------------------------------------------------------

def map_results_to_requirements(results: list[dict]) -> list[RequirementStatus]:
    """Map harness test results to AIUC-1 requirements."""
    # Index results by test_id
    result_index: dict[str, dict] = {}
    for r in results:
        tid = r.get("test_id", "")
        if tid:
            result_index[tid] = r

    statuses: list[RequirementStatus] = []

    for req_id, req_def in AIUC1_REQUIREMENTS.items():
        is_gap = req_def.get("gap", False)
        test_ids = req_def["test_ids"]

        if is_gap:
            statuses.append(RequirementStatus(
                req_id=req_id,
                title=req_def["title"],
                category=req_def["category"],
                status="NOT YET COVERED",
                test_ids=test_ids,
                notes=req_def.get("gap_notes", ""),
            ))
            continue

        # Check which tests have results
        matched = [tid for tid in test_ids if tid in result_index]

        if not matched:
            # Tests are defined but no results available (harness wasn't run)
            statuses.append(RequirementStatus(
                req_id=req_id,
                title=req_def["title"],
                category=req_def["category"],
                status="COVERED (no results)",
                test_ids=test_ids,
                notes="Harness tests exist but were not included in this run.",
            ))
            continue

        passed = sum(1 for tid in matched if result_index[tid].get("passed", False))
        failed = len(matched) - passed

        status = "COVERED+PASS" if failed == 0 else "COVERED+FAIL"

        statuses.append(RequirementStatus(
            req_id=req_id,
            title=req_def["title"],
            category=req_def["category"],
            status=status,
            test_ids=test_ids,
            passed=passed,
            failed=failed,
            total=len(matched),
        ))

    return statuses


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_readiness_report(statuses: list[RequirementStatus], target: str = "N/A") -> str:
    """Generate the Pre-Certification Readiness Report in markdown."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%Y-%m-%d %H:%M UTC")

    total_reqs = len(statuses)
    covered = [s for s in statuses if s.status.startswith("COVERED")]
    passing = [s for s in statuses if s.status == "COVERED+PASS"]
    failing = [s for s in statuses if s.status == "COVERED+FAIL"]
    gaps = [s for s in statuses if s.status == "NOT YET COVERED"]
    no_results = [s for s in statuses if s.status == "COVERED (no results)"]

    covered_count = len(covered)
    passing_pct = (len(passing) / total_reqs * 100) if total_reqs > 0 else 0

    # Group by category
    categories: dict[str, list[RequirementStatus]] = {}
    for s in statuses:
        categories.setdefault(s.category, []).append(s)

    lines = [
        f"# AIUC-1 Pre-Certification Readiness Report",
        f"",
        f"**Generated:** {time_str}",
        f"**Target:** {target}",
        f"**Framework:** Agent Security Harness v{HARNESS_VERSION}",
        f"**Standard:** AIUC-1 (AI Agent Certification)",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total AIUC-1 Requirements | {total_reqs} |",
        f"| Requirements Covered | {covered_count}/{total_reqs} |",
        f"| Passing | {len(passing)}/{total_reqs} ({passing_pct:.0f}%) |",
        f"| Failing | {len(failing)} |",
        f"| Not Yet Covered (Gaps) | {len(gaps)} |",
        f"| Awaiting Test Results | {len(no_results)} |",
        f"",
        f"### Overall Readiness: {covered_count}/{total_reqs} requirements covered, {passing_pct:.0f}% passing",
        f"",
    ]

    # Readiness grade
    if passing_pct >= 90:
        grade = "A - Ready for Certification"
    elif passing_pct >= 75:
        grade = "B - Near Ready (minor gaps)"
    elif passing_pct >= 50:
        grade = "C - Significant Gaps Remain"
    elif passing_pct >= 25:
        grade = "D - Major Work Needed"
    else:
        grade = "F - Early Stage"

    lines.extend([
        f"**Readiness Grade: {grade}**",
        f"",
        f"---",
        f"",
        f"## Per-Category Breakdown",
        f"",
    ])

    status_emoji = {
        "COVERED+PASS": "PASS",
        "COVERED+FAIL": "FAIL",
        "NOT YET COVERED": "GAP",
        "COVERED (no results)": "PENDING",
    }

    for cat_name in ["Security", "Reliability", "Transparency", "Safety", "Content Safety"]:
        cat_reqs = categories.get(cat_name, [])
        if not cat_reqs:
            continue

        cat_pass = sum(1 for s in cat_reqs if s.status == "COVERED+PASS")
        cat_total = len(cat_reqs)

        lines.extend([
            f"### {cat_name} ({cat_pass}/{cat_total} passing)",
            f"",
            f"| Requirement | Title | Status | Tests | Details |",
            f"|-------------|-------|--------|-------|---------|",
        ])

        for s in cat_reqs:
            emoji = status_emoji.get(s.status, s.status)
            if s.total > 0:
                detail = f"{s.passed}/{s.total} tests passed"
            elif s.notes:
                detail = s.notes[:60]
            else:
                detail = "-"
            lines.append(f"| {s.req_id} | {s.title} | **{emoji}** | {', '.join(s.test_ids[:3])}{'...' if len(s.test_ids) > 3 else ''} | {detail} |")

        lines.append("")

    # Gap analysis
    lines.extend([
        f"---",
        f"",
        f"## Gap Analysis",
        f"",
    ])

    if gaps:
        for s in gaps:
            lines.extend([
                f"### {s.req_id}: {s.title} ({s.category})",
                f"",
                f"**Status:** Not Yet Covered",
                f"",
                f"**Gap Notes:** {s.notes}",
                f"",
                f"**Mapped Test IDs:** {', '.join(s.test_ids) if s.test_ids else 'None defined'}",
                f"",
            ])
    else:
        lines.append("No gaps identified - all requirements covered!\n")

    if failing:
        lines.extend([
            f"### Failing Requirements",
            f"",
        ])
        for s in failing:
            lines.extend([
                f"- **{s.req_id} ({s.title}):** {s.failed}/{s.total} tests failing",
                f"",
            ])

    # Recommendations
    lines.extend([
        f"---",
        f"",
        f"## Recommendations",
        f"",
        f"### Priority 1: Close Safety Gaps (E001-E003)",
        f"1. Integrate incident response harness with live infrastructure",
        f"2. Deploy circuit-breaker / kill-switch mechanisms and test under load",
        f"3. Connect audit trail validation to production logging pipeline",
        f"",
        f"### Priority 2: Close Content Safety Gaps (F001-F002)",
        f"1. Build dedicated harmful content filtering test suite",
        f"2. Validate CBRN tests against production LLM endpoints (not simulation)",
        f"3. Add hate speech, misinformation, and manipulation detection tests",
        f"",
        f"### Priority 3: Fix Failing Tests",
    ])

    if failing:
        for s in failing:
            lines.append(f"- Review and fix {s.req_id} ({s.title}): {s.failed} tests failing")
    else:
        lines.append("- No failing tests to fix")

    lines.extend([
        f"",
        f"### Priority 4: Full Coverage Run",
        f"1. Run all harness suites against the target endpoint",
        f"2. Include identity, provenance, and attestation harnesses",
        f"3. Generate final attestation report for submission",
        f"",
        f"---",
        f"",
        f"## Next Steps",
        f"",
        f"1. **Address gaps** in Safety (E001-E003) and Content Safety (F001-F002)",
        f"2. **Re-run** full harness suite after fixes",
        f"3. **Generate attestation report** using `agent-security test attestation`",
        f"4. **Submit** attestation report to AIUC-1 certification body",
        f"5. **Schedule** periodic re-testing (recommend weekly during development)",
        f"",
        f"---",
        f"",
        f"*Report generated by Agent Security Harness v{HARNESS_VERSION} AIUC-1 Prep Tool*",
        f"*Repository: https://github.com/msaleme/red-team-blue-team-agent-fabric*",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AIUC-1 Pre-Certification Readiness Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run against a live target
    python scripts/aiuc1_prep.py --url http://localhost:8080/mcp

    # Use existing report files
    python scripts/aiuc1_prep.py --reports reports/mcp-report.json reports/a2a-report.json

    # Simulation mode (no live target)
    python scripts/aiuc1_prep.py --simulate
        """,
    )
    parser.add_argument("--url", help="Target URL to test against")
    parser.add_argument(
        "--reports", nargs="+", metavar="FILE",
        help="Pre-existing harness report JSON files to use instead of running tests",
    )
    parser.add_argument(
        "--simulate", action="store_true",
        help="Run harnesses in simulation mode (no live target needed)",
    )
    parser.add_argument(
        "--suites", nargs="+", default=None,
        help="Specific harness suites to run (default: mcp, a2a, identity)",
    )
    parser.add_argument(
        "--output-dir", default="reports",
        help="Output directory for the readiness report (default: reports/)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Also output machine-readable JSON alongside markdown",
    )

    args = parser.parse_args()

    if not args.url and not args.reports and not args.simulate:
        parser.error("Provide --url, --reports, or --simulate")

    project_root = Path(__file__).parent.parent
    output_dir = project_root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # Collect results
    all_results: list[dict] = []
    target = "N/A"

    if args.reports:
        print(f"Loading {len(args.reports)} report file(s)...")
        target = f"Pre-existing reports: {', '.join(args.reports)}"
        for report_path in args.reports:
            if not os.path.exists(report_path):
                print(f"  Warning: {report_path} not found, skipping")
                continue
            results = load_report(report_path)
            print(f"  Loaded {len(results)} results from {report_path}")
            all_results.extend(results)
    else:
        target = args.url or "simulation"
        print(f"Running harness suites against: {target}")
        all_results = run_harness(
            url=args.url or "",
            harnesses=args.suites,
            simulate=args.simulate,
        )

    print(f"\nTotal test results collected: {len(all_results)}")

    # Map to AIUC-1 requirements
    statuses = map_results_to_requirements(all_results)

    # Generate report
    report_md = generate_readiness_report(statuses, target=target)

    # Save
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    md_path = output_dir / f"aiuc1-prep-{date_str}.md"
    report_md_str = report_md

    with open(md_path, "w") as f:
        f.write(report_md_str)
    print(f"\nReadiness report saved to: {md_path}")

    if args.json:
        json_path = output_dir / f"aiuc1-prep-{date_str}.json"
        json_data = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "framework_version": "3.8.0",
            "requirements": [
                {
                    "req_id": s.req_id,
                    "title": s.title,
                    "category": s.category,
                    "status": s.status,
                    "test_ids": s.test_ids,
                    "passed": s.passed,
                    "failed": s.failed,
                    "total": s.total,
                    "notes": s.notes,
                }
                for s in statuses
            ],
            "summary": {
                "total": len(statuses),
                "covered": len([s for s in statuses if s.status.startswith("COVERED")]),
                "passing": len([s for s in statuses if s.status == "COVERED+PASS"]),
                "failing": len([s for s in statuses if s.status == "COVERED+FAIL"]),
                "gaps": len([s for s in statuses if s.status == "NOT YET COVERED"]),
            },
        }
        with open(json_path, "w") as f:
            json.dump(json_data, f, indent=2)
        print(f"JSON report saved to: {json_path}")

    # Print summary
    covered = len([s for s in statuses if s.status.startswith("COVERED")])
    passing = len([s for s in statuses if s.status == "COVERED+PASS"])
    gaps = len([s for s in statuses if s.status == "NOT YET COVERED"])
    print(f"\n{'='*50}")
    print(f"AIUC-1 READINESS SUMMARY")
    print(f"{'='*50}")
    print(f"  Covered:    {covered}/20 requirements")
    print(f"  Passing:    {passing}/20 requirements")
    print(f"  Gaps:       {gaps}/20 requirements")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
