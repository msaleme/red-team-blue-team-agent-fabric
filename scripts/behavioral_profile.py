#!/usr/bin/env python3
"""Behavioral Profiling and Risk Scoring for Agent Security Harness

Compares test results across multiple harness runs to produce a behavioral
profile showing drift, stability, and risk scoring.  This is the "what static
scanners miss" story -- scanners check configuration at a point in time; this
tool shows behavioral change over time.

Scoring formulas (transparent and auditable):
    stability = matching_results / total_results * 100
    risk = (failure_rate * 40) + (instability_rate * 30)
         + (critical_failure_weight * 20) + (drift_velocity * 10)

Usage:
    # Compare two runs (baseline vs current)
    python scripts/behavioral_profile.py --baseline run1.json --current run2.json

    # Trend analysis over 3+ runs
    python scripts/behavioral_profile.py --history run1.json run2.json run3.json

    # Custom output directory
    python scripts/behavioral_profile.py --baseline run1.json --current run2.json --output profile/

Requires: Python 3.10+, no external dependencies.
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

# Severity weights for critical-failure scoring.
# P0-Critical and P1-High are "critical" for risk purposes.
CRITICAL_SEVERITIES = {"P0-Critical", "P1-High"}


# ---------------------------------------------------------------------------
# Report loading
# ---------------------------------------------------------------------------

def load_report(path: str) -> dict[str, Any]:
    """Load a harness JSON report and return the full dict."""
    with open(path) as f:
        return json.load(f)


def _extract_results(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the flat list of test result dicts from a report.

    Handles both single-run reports (results is a list of dicts) and
    multi-trial reports (which also have ``statistical_summary``).
    """
    results = report.get("results", [])
    # Ensure every item is a dict (dataclass objects are already serialized
    # to dicts in JSON reports).
    out: list[dict[str, Any]] = []
    for r in results:
        if isinstance(r, dict):
            out.append(r)
    return out


def _index_by_test_id(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build {test_id: result_dict} index."""
    idx: dict[str, dict[str, Any]] = {}
    for r in results:
        tid = r.get("test_id", "")
        if tid:
            idx[tid] = r
    return idx


# ---------------------------------------------------------------------------
# Stability score
# ---------------------------------------------------------------------------

def compute_stability(
    baseline_idx: dict[str, dict],
    current_idx: dict[str, dict],
) -> dict[str, Any]:
    """Compute stability score between two runs.

    stability = matching_results / total_results * 100

    A result "matches" if the passed boolean is the same in both runs.
    Tests present in only one run count as mismatches.
    """
    all_ids = sorted(set(baseline_idx) | set(current_idx))
    if not all_ids:
        return {"score": 100.0, "matching": 0, "total": 0, "details": []}

    matching = 0
    details: list[dict[str, Any]] = []

    for tid in all_ids:
        b = baseline_idx.get(tid)
        c = current_idx.get(tid)

        if b is None or c is None:
            # Test only in one run -- counts as mismatch
            details.append({
                "test_id": tid,
                "stable": False,
                "reason": "missing_in_baseline" if b is None else "missing_in_current",
            })
            continue

        b_passed = b.get("passed", False)
        c_passed = c.get("passed", False)

        if b_passed == c_passed:
            matching += 1
            details.append({"test_id": tid, "stable": True})
        else:
            details.append({
                "test_id": tid,
                "stable": False,
                "reason": "result_changed",
                "baseline": b_passed,
                "current": c_passed,
            })

    total = len(all_ids)
    score = (matching / total * 100) if total else 100.0

    return {
        "score": round(score, 2),
        "matching": matching,
        "total": total,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

def detect_drift(
    baseline_idx: dict[str, dict],
    current_idx: dict[str, dict],
) -> list[dict[str, Any]]:
    """Detect tests that changed result between baseline and current.

    Each drift event includes:
      - test_id, test_name
      - old_result, new_result (PASS / FAIL)
      - severity of the test
      - category: regression (PASS->FAIL), improvement (FAIL->PASS), flaky
    """
    drifts: list[dict[str, Any]] = []
    common_ids = sorted(set(baseline_idx) & set(current_idx))

    for tid in common_ids:
        b = baseline_idx[tid]
        c = current_idx[tid]
        b_passed = b.get("passed", False)
        c_passed = c.get("passed", False)

        if b_passed == c_passed:
            continue

        old_result = "PASS" if b_passed else "FAIL"
        new_result = "PASS" if c_passed else "FAIL"

        if b_passed and not c_passed:
            category = "regression"
        elif not b_passed and c_passed:
            category = "improvement"
        else:
            category = "flaky"

        drifts.append({
            "test_id": tid,
            "test_name": c.get("name", tid),
            "old_result": old_result,
            "new_result": new_result,
            "severity": c.get("severity", "unknown"),
            "category": category,
        })

    return drifts


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

def compute_risk_score(
    current_idx: dict[str, dict],
    stability_score: float,
    drifts: list[dict[str, Any]],
    previous_risk: float | None = None,
) -> dict[str, Any]:
    """Compute risk score (0-100) as a weighted combination.

    Formula:
        risk = (failure_rate * 40) + (instability_rate * 30)
             + (critical_failure_weight * 20) + (drift_velocity * 10)

    Components (each normalized to 0.0 - 1.0):
        failure_rate:            fraction of tests failing in the current run
        instability_rate:        1 - (stability / 100)
        critical_failure_weight: fraction of failing tests that are P0/P1
        drift_velocity:          fraction of tests that drifted between runs
    """
    total = len(current_idx)
    if total == 0:
        return {
            "score": 0.0,
            "components": {},
            "trend": None,
        }

    # failure_rate: fraction of tests that failed
    failed = sum(1 for r in current_idx.values() if not r.get("passed", False))
    failure_rate = failed / total

    # instability_rate: inverse of stability
    instability_rate = 1.0 - (stability_score / 100.0)

    # critical_failure_weight: among failures, how many are P0/P1?
    critical_failures = sum(
        1 for r in current_idx.values()
        if not r.get("passed", False) and r.get("severity", "") in CRITICAL_SEVERITIES
    )
    critical_failure_weight = critical_failures / total if total else 0.0

    # drift_velocity: fraction of tests that changed between runs
    drift_velocity = len(drifts) / total if total else 0.0

    # Weighted sum
    score = (
        (failure_rate * 40)
        + (instability_rate * 30)
        + (critical_failure_weight * 20)
        + (drift_velocity * 10)
    )
    score = min(100.0, max(0.0, score))

    # Trend compared to previous risk score
    trend = None
    if previous_risk is not None:
        diff = score - previous_risk
        if diff > 1.0:
            trend = "increasing"
        elif diff < -1.0:
            trend = "decreasing"
        else:
            trend = "stable"

    return {
        "score": round(score, 2),
        "components": {
            "failure_rate": round(failure_rate, 4),
            "instability_rate": round(instability_rate, 4),
            "critical_failure_weight": round(critical_failure_weight, 4),
            "drift_velocity": round(drift_velocity, 4),
        },
        "weights": {
            "failure_rate": 40,
            "instability_rate": 30,
            "critical_failure_weight": 20,
            "drift_velocity": 10,
        },
        "trend": trend,
    }


# ---------------------------------------------------------------------------
# Trend analysis (>2 runs)
# ---------------------------------------------------------------------------

def compute_trend(
    run_reports: list[dict[str, Any]],
) -> dict[str, Any]:
    """Analyze trends across 3+ ordered runs.

    Returns:
        - risk_over_time: list of risk scores per consecutive pair
        - persistent_failures: tests failing in ALL runs
        - intermittent: tests that flip between PASS and FAIL across runs
    """
    if len(run_reports) < 2:
        return {"error": "Need at least 2 runs for trend analysis"}

    indices = [_index_by_test_id(_extract_results(r)) for r in run_reports]

    # All test IDs seen across any run
    all_ids: set[str] = set()
    for idx in indices:
        all_ids.update(idx.keys())

    # Track per-test outcomes across runs
    test_outcomes: dict[str, list[bool | None]] = {tid: [] for tid in sorted(all_ids)}
    for idx in indices:
        for tid in sorted(all_ids):
            r = idx.get(tid)
            if r is not None:
                test_outcomes[tid].append(r.get("passed", False))
            else:
                test_outcomes[tid].append(None)

    # Persistent failures: failed in every run where present
    persistent_failures: list[str] = []
    for tid, outcomes in test_outcomes.items():
        present = [o for o in outcomes if o is not None]
        if present and all(o is False for o in present):
            persistent_failures.append(tid)

    # Intermittent: at least one PASS and one FAIL across runs
    intermittent: list[str] = []
    for tid, outcomes in test_outcomes.items():
        present = [o for o in outcomes if o is not None]
        if len(present) >= 2 and any(present) and not all(present):
            intermittent.append(tid)

    # Risk over time: compute risk score for each consecutive pair
    risk_over_time: list[dict[str, Any]] = []
    prev_risk: float | None = None
    for i in range(1, len(indices)):
        baseline_idx = indices[i - 1]
        current_idx = indices[i]

        stab = compute_stability(baseline_idx, current_idx)
        drifts = detect_drift(baseline_idx, current_idx)
        risk = compute_risk_score(current_idx, stab["score"], drifts, prev_risk)

        ts = run_reports[i].get("timestamp", f"run_{i + 1}")
        risk_over_time.append({
            "run_index": i + 1,
            "timestamp": ts,
            "risk_score": risk["score"],
            "stability_score": stab["score"],
            "drift_count": len(drifts),
            "trend": risk["trend"],
        })
        prev_risk = risk["score"]

    return {
        "runs_analyzed": len(run_reports),
        "risk_over_time": risk_over_time,
        "persistent_failures": persistent_failures,
        "persistent_failure_count": len(persistent_failures),
        "intermittent_tests": intermittent,
        "intermittent_count": len(intermittent),
    }


# ---------------------------------------------------------------------------
# Markdown generation
# ---------------------------------------------------------------------------

def _trend_arrow(trend: str | None) -> str:
    """Return a trend arrow character."""
    if trend == "increasing":
        return "^"  # risk going up
    elif trend == "decreasing":
        return "v"  # risk going down
    elif trend == "stable":
        return "->"
    return ""


def generate_markdown(
    stability: dict[str, Any],
    drifts: list[dict[str, Any]],
    risk: dict[str, Any],
    trend: dict[str, Any] | None,
    baseline_path: str,
    current_path: str,
    timestamp: str,
) -> str:
    """Generate a human-readable markdown behavioral profile report."""
    lines: list[str] = []

    # Header
    lines.extend([
        "# Behavioral Profile Report",
        "",
        f"**Generated:** {timestamp}",
        f"**Harness Version:** {HARNESS_VERSION}",
        f"**Baseline:** {baseline_path}",
        f"**Current:** {current_path}",
        "",
        "---",
        "",
    ])

    # Executive summary
    risk_score = risk["score"]
    stab_score = stability["score"]
    regression_count = sum(1 for d in drifts if d["category"] == "regression")
    improvement_count = sum(1 for d in drifts if d["category"] == "improvement")
    arrow = _trend_arrow(risk.get("trend"))

    risk_label = "LOW"
    if risk_score >= 60:
        risk_label = "CRITICAL"
    elif risk_score >= 40:
        risk_label = "HIGH"
    elif risk_score >= 20:
        risk_label = "MEDIUM"

    lines.extend([
        "## Executive Summary",
        "",
        f"Behavioral comparison of {stability['total']} tests across two harness runs "
        f"shows a stability score of {stab_score:.1f}/100 and a risk score of "
        f"{risk_score:.1f}/100 ({risk_label}). "
        f"{regression_count} regression(s) and {improvement_count} improvement(s) detected. "
        + (f"Risk trend: {arrow}" if arrow else "No prior risk data for trend."),
        "",
        "---",
        "",
    ])

    # Risk score
    lines.extend([
        "## Risk Score",
        "",
        f"**Score: {risk_score:.1f} / 100** ({risk_label})"
        + (f" {arrow}" if arrow else ""),
        "",
        "| Component | Value | Weight |",
        "|-----------|-------|--------|",
    ])
    components = risk.get("components", {})
    weights = risk.get("weights", {})
    for comp_name in ["failure_rate", "instability_rate", "critical_failure_weight", "drift_velocity"]:
        val = components.get(comp_name, 0)
        w = weights.get(comp_name, 0)
        lines.append(f"| {comp_name} | {val:.4f} | x{w} |")
    lines.extend(["", "---", ""])

    # Stability breakdown
    lines.extend([
        "## Stability",
        "",
        f"**Score: {stab_score:.1f} / 100** "
        f"({stability['matching']}/{stability['total']} tests unchanged)",
        "",
    ])

    # Category breakdown from drifts
    categories: dict[str, int] = {}
    for d in drifts:
        cat = d["category"]
        categories[cat] = categories.get(cat, 0) + 1

    if categories:
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for cat, count in sorted(categories.items()):
            lines.append(f"| {cat} | {count} |")
        lines.extend(["", ""])

    lines.extend(["---", ""])

    # Drift table
    lines.extend([
        "## Drift Events",
        "",
    ])
    if drifts:
        lines.append("| Test ID | Name | Old | New | Severity | Category |")
        lines.append("|---------|------|-----|-----|----------|----------|")
        for d in drifts:
            lines.append(
                f"| {d['test_id']} | {d['test_name']} | {d['old_result']} "
                f"| {d['new_result']} | {d['severity']} | {d['category']} |"
            )
    else:
        lines.append("No drift events detected -- all tests produced the same result.")
    lines.extend(["", "---", ""])

    # Trend analysis (if available)
    if trend and trend.get("runs_analyzed", 0) >= 2:
        lines.extend([
            "## Trend Analysis",
            "",
            f"**Runs analyzed:** {trend['runs_analyzed']}",
            "",
        ])

        if trend.get("risk_over_time"):
            lines.append("### Risk Over Time")
            lines.append("")
            lines.append("| Run | Timestamp | Risk Score | Stability | Drifts | Trend |")
            lines.append("|-----|-----------|------------|-----------|--------|-------|")
            for entry in trend["risk_over_time"]:
                t_arrow = _trend_arrow(entry.get("trend"))
                lines.append(
                    f"| {entry['run_index']} | {entry['timestamp'][:19]} "
                    f"| {entry['risk_score']:.1f} | {entry['stability_score']:.1f} "
                    f"| {entry['drift_count']} | {t_arrow} |"
                )
            lines.extend(["", ""])

        if trend.get("persistent_failures"):
            lines.append(f"### Persistent Failures ({trend['persistent_failure_count']})")
            lines.append("")
            lines.append("These tests failed in **every** run:")
            lines.append("")
            for tid in trend["persistent_failures"]:
                lines.append(f"- `{tid}`")
            lines.extend(["", ""])

        if trend.get("intermittent_tests"):
            lines.append(f"### Intermittent Tests ({trend['intermittent_count']})")
            lines.append("")
            lines.append("These tests flip between PASS and FAIL across runs "
                         "(normalization of deviance signal):")
            lines.append("")
            for tid in trend["intermittent_tests"]:
                lines.append(f"- `{tid}`")
            lines.extend(["", ""])

        lines.extend(["---", ""])

    # Recommendations
    lines.extend([
        "## Recommendations",
        "",
    ])
    recommendations: list[str] = []
    if regression_count > 0:
        recommendations.append(
            f"**Investigate {regression_count} regression(s)** -- tests that previously "
            "passed are now failing. This indicates new security gaps."
        )
    if trend and trend.get("intermittent_count", 0) > 0:
        recommendations.append(
            f"**Address {trend['intermittent_count']} intermittent test(s)** -- flaky "
            "security tests indicate unpredictable behavior, which is itself a risk."
        )
    if trend and trend.get("persistent_failure_count", 0) > 0:
        recommendations.append(
            f"**Fix {trend['persistent_failure_count']} persistent failure(s)** -- these "
            "tests have never passed across all analyzed runs."
        )
    if risk_score >= 40:
        recommendations.append(
            "**Risk score is elevated.** Review failing tests and prioritize "
            "P0-Critical and P1-High severity items."
        )
    if stab_score < 80:
        recommendations.append(
            "**Stability is below 80%.** Investigate why test results differ between runs. "
            "Non-deterministic security behavior is a risk signal."
        )
    if not recommendations:
        recommendations.append("No immediate actions required. Continue monitoring.")

    for rec in recommendations:
        lines.append(f"- {rec}")

    lines.extend([
        "",
        "---",
        "",
        f"*Generated by Agent Security Harness v{HARNESS_VERSION} Behavioral Profiler*",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Profile builder (main entry point)
# ---------------------------------------------------------------------------

def build_profile(
    baseline_path: str,
    current_path: str,
    history_paths: list[str] | None = None,
    output_dir: str = ".",
) -> str:
    """Build a behavioral profile comparing two (or more) harness runs.

    Writes JSON and markdown reports to *output_dir* and returns the
    output directory path.
    """
    baseline_report = load_report(baseline_path)
    current_report = load_report(current_path)

    baseline_results = _extract_results(baseline_report)
    current_results = _extract_results(current_report)

    baseline_idx = _index_by_test_id(baseline_results)
    current_idx = _index_by_test_id(current_results)

    # Core analyses
    stability = compute_stability(baseline_idx, current_idx)
    drifts = detect_drift(baseline_idx, current_idx)
    risk = compute_risk_score(current_idx, stability["score"], drifts)

    # Trend analysis (if history provided)
    trend: dict[str, Any] | None = None
    if history_paths and len(history_paths) >= 2:
        run_reports = [load_report(p) for p in history_paths]
        trend = compute_trend(run_reports)

        # Recompute risk with trend context (use last pair's risk as previous)
        risk_timeline = trend.get("risk_over_time", [])
        if len(risk_timeline) >= 2:
            prev_risk = risk_timeline[-2]["risk_score"]
            risk = compute_risk_score(current_idx, stability["score"], drifts, prev_risk)

    timestamp = datetime.now(timezone.utc).isoformat()

    # Build JSON profile
    profile: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": timestamp,
        "harness_version": HARNESS_VERSION,
        "baseline": baseline_path,
        "current": current_path,
        "stability": {
            "score": stability["score"],
            "matching": stability["matching"],
            "total": stability["total"],
        },
        "drift": {
            "events": drifts,
            "count": len(drifts),
            "regressions": sum(1 for d in drifts if d["category"] == "regression"),
            "improvements": sum(1 for d in drifts if d["category"] == "improvement"),
        },
        "risk": risk,
    }
    if trend:
        profile["trend"] = trend

    # Generate markdown
    markdown = generate_markdown(
        stability=stability,
        drifts=drifts,
        risk=risk,
        trend=trend,
        baseline_path=baseline_path,
        current_path=current_path,
        timestamp=timestamp,
    )

    # Write output
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    profile_json_path = out_dir / "behavioral-profile.json"
    profile_md_path = out_dir / "behavioral-profile.md"

    profile_json = json.dumps(profile, indent=2, default=str)
    with open(profile_json_path, "w") as f:
        f.write(profile_json)
    with open(profile_md_path, "w") as f:
        f.write(markdown)

    # Print summary to stdout
    print(f"\n{'='*50}")
    print("BEHAVIORAL PROFILE SUMMARY")
    print(f"{'='*50}")
    print(f"  Stability:    {stability['score']:.1f}/100 ({stability['matching']}/{stability['total']} tests stable)")
    print(f"  Drift events: {len(drifts)} ({sum(1 for d in drifts if d['category'] == 'regression')} regressions, "
          f"{sum(1 for d in drifts if d['category'] == 'improvement')} improvements)")
    print(f"  Risk score:   {risk['score']:.1f}/100", end="")
    if risk.get("trend"):
        print(f" ({risk['trend']})")
    else:
        print()
    if trend:
        print(f"  Persistent failures: {trend.get('persistent_failure_count', 0)}")
        print(f"  Intermittent tests:  {trend.get('intermittent_count', 0)}")
    print(f"{'='*50}")
    print(f"\n  JSON:     {profile_json_path}")
    print(f"  Markdown: {profile_md_path}")

    return str(out_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Behavioral profiling and risk scoring for agent security harness runs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Compare two runs
    python scripts/behavioral_profile.py --baseline report1.json --current report2.json

    # Trend analysis over multiple runs
    python scripts/behavioral_profile.py --history report1.json report2.json report3.json --output profile/

    # Baseline + current with history for trend context
    python scripts/behavioral_profile.py --baseline report1.json --current report3.json \\
        --history report1.json report2.json report3.json --output profile/
        """,
    )

    parser.add_argument(
        "--baseline", metavar="PATH",
        help="Path to the baseline harness JSON report",
    )
    parser.add_argument(
        "--current", metavar="PATH",
        help="Path to the current harness JSON report",
    )
    parser.add_argument(
        "--history", nargs="+", metavar="PATH",
        help="Ordered list of harness JSON reports for trend analysis (oldest first)",
    )
    parser.add_argument(
        "--output", default=".", metavar="DIR",
        help="Output directory for profile reports (default: current directory)",
    )

    args = parser.parse_args()

    # Determine baseline and current from arguments
    baseline = args.baseline
    current = args.current

    if args.history and len(args.history) >= 2:
        # In history mode, default baseline/current to first/last if not set
        if baseline is None:
            baseline = args.history[0]
        if current is None:
            current = args.history[-1]
    elif baseline is None or current is None:
        parser.error("Either --baseline and --current, or --history with 2+ files is required")

    # Validate files exist
    for path in [baseline, current]:
        if not os.path.exists(path):
            print(f"Error: file not found: {path}", file=sys.stderr)
            sys.exit(1)
    if args.history:
        for path in args.history:
            if not os.path.exists(path):
                print(f"Error: file not found: {path}", file=sys.stderr)
                sys.exit(1)

    build_profile(
        baseline_path=baseline,
        current_path=current,
        history_paths=args.history,
        output_dir=args.output,
    )


if __name__ == "__main__":
    main()
