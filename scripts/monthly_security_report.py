#!/usr/bin/env python3
"""Monthly Agent Security Report Pipeline.

Reads MCP server targets from configs/monthly_targets.yaml, runs the full
MCP security harness against each, and produces a combined monthly report
in markdown.

Usage:
    python scripts/monthly_security_report.py
    python scripts/monthly_security_report.py --config configs/monthly_targets.yaml
    python scripts/monthly_security_report.py --month 2026-03
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path


def _get_version() -> str:
    """Read version from pyproject.toml or importlib.metadata."""
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
from datetime import datetime, timezone
from typing import Any

# Ensure repo root is on path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

# YAML parsing - use PyYAML if available, otherwise a simple fallback
try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


def load_yaml_config(path: str) -> dict:
    """Load YAML config file."""
    with open(path, "r") as f:
        if yaml:
            return yaml.safe_load(f)
        else:
            # Minimal YAML-like parser for our simple config format
            return _simple_yaml_parse(f.read())


def _simple_yaml_parse(text: str) -> dict:
    """Bare-bones parser for the specific monthly_targets.yaml structure.
    Only handles top-level keys with list-of-dict values. Use PyYAML for
    anything more complex.
    """
    result: dict[str, Any] = {"targets": []}
    current_target: dict[str, str] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current_target:
                result["targets"].append(current_target)
            current_target = {}
            # Handle inline "- key: value"
            rest = stripped[2:].strip()
            if ":" in rest:
                k, v = rest.split(":", 1)
                current_target[k.strip()] = v.strip().strip('"').strip("'")
        elif ":" in stripped and current_target is not None:
            k, v = stripped.split(":", 1)
            current_target[k.strip()] = v.strip().strip('"').strip("'")
        elif stripped.startswith("targets:"):
            continue
        elif ":" in stripped:
            k, v = stripped.split(":", 1)
            result[k.strip()] = v.strip().strip('"').strip("'")
    if current_target:
        result["targets"].append(current_target)
    return result


# ── Harness integration ────────────────────────────────────────────────────

from protocol_tests.mcp_harness import (
    MCPSecurityTests,
    MCPTestResult,
    StreamableHTTPTransport,
)


def run_full_harness(url: str) -> list[dict]:
    """Run all MCP harness tests against a URL and return structured results."""
    transport = StreamableHTTPTransport(url)
    harness = MCPSecurityTests(transport)

    results: list[dict] = []
    # Discover all test methods
    test_methods = [m for m in dir(harness) if m.startswith("test_mcp_")]
    test_methods.sort()

    for method_name in test_methods:
        method = getattr(harness, method_name)
        try:
            result: MCPTestResult = method()
            status = result.status.value if hasattr(result.status, "value") else str(result.status)
            results.append({
                "test_id": result.test_id,
                "name": result.name,
                "status": status.upper(),
                "detail": result.detail or "",
                "category": result.category if hasattr(result, "category") else "",
            })
        except Exception as exc:
            results.append({
                "test_id": method_name,
                "name": method_name.replace("test_mcp_", "").replace("_", " ").title(),
                "status": "ERROR",
                "detail": str(exc),
                "category": "",
            })

    transport.close()
    return results


# ── Report generation ──────────────────────────────────────────────────────

def generate_monthly_report(
    all_results: dict[str, list[dict]],
    month: str,
    config: dict,
) -> str:
    """Generate the combined monthly security report in markdown."""
    total_servers = len(all_results)
    total_tests = 0
    total_passed = 0
    failure_counter: Counter = Counter()
    server_summaries: list[dict] = []

    for server_name, results in all_results.items():
        passed = sum(1 for r in results if r["status"] == "PASS")
        total = len(results)
        total_tests += total
        total_passed += passed
        pass_rate = (passed / total * 100) if total > 0 else 0

        for r in results:
            if r["status"] != "PASS":
                failure_counter[f"{r['test_id']} - {r['name']}"] += 1

        server_summaries.append({
            "name": server_name,
            "tests": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": pass_rate,
        })

    avg_pass_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
    top_failures = failure_counter.most_common(3)

    # Build markdown
    lines = [
        f"# Monthly Agent Security Report - {month}",
        "",
        f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
        "",
        "## Executive Summary",
        "",
        f"- **Servers tested:** {total_servers}",
        f"- **Total tests executed:** {total_tests}",
        f"- **Average pass rate:** {avg_pass_rate:.1f}%",
        "",
    ]

    if top_failures:
        lines.append("### Top 3 Most Common Failures")
        lines.append("")
        for i, (name, count) in enumerate(top_failures, 1):
            lines.append(f"{i}. **{name}** - failed on {count}/{total_servers} server(s)")
        lines.append("")

    # Per-server results table
    lines.extend([
        "## Per-Server Results",
        "",
        "| Server | Tests | Passed | Failed | Pass Rate |",
        "|--------|-------|--------|--------|-----------|",
    ])

    for s in server_summaries:
        lines.append(
            f"| {s['name']} | {s['tests']} | {s['passed']} | {s['failed']} | {s['pass_rate']:.0f}% |"
        )

    lines.append("")

    # Detailed per-server breakdown
    lines.extend(["## Detailed Results", ""])
    for server_name, results in all_results.items():
        lines.extend([
            f"### {server_name}",
            "",
            "| Test ID | Test Name | Status | Detail |",
            "|---------|-----------|--------|--------|",
        ])
        for r in results:
            detail = r["detail"][:60].replace("|", "/") if r["detail"] else "-"
            lines.append(f"| {r['test_id']} | {r['name']} | {r['status']} | {detail} |")
        lines.append("")

    # Trend section (stub)
    lines.extend([
        "## Trends",
        "",
        "> Previous month comparison will be added when historical data exists.",
        "> Once two or more monthly reports are available, this section will include:",
        "> - Pass rate delta per server",
        "> - New vs. resolved failures",
        "> - Overall posture trajectory",
        "",
    ])

    # Methodology
    lines.extend([
        "## Methodology",
        "",
        "This report was generated using the [agent-security-harness]"
        "(https://github.com/msaleme/red-team-blue-team-agent-fabric) MCP protocol-level",
        "test suite. Tests send real MCP JSON-RPC 2.0 messages over Streamable HTTP and",
        "validate that servers handle adversarial inputs at the wire level.",
        "",
        "Test categories include: tool discovery poisoning, capability escalation, protocol",
        "downgrade, resource path traversal, prompt injection, sampling hijack, malformed",
        "JSON-RPC, batch bombs, tool argument injection, and context displacement.",
        "",
        f"Full test suite version: v{_get_version()} (attestation branch)",
        "",
        "---",
        "",
        "*Report generated by `scripts/monthly_security_report.py`*",
    ])

    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Monthly Agent Security Report Pipeline",
    )
    parser.add_argument(
        "--config", default=os.path.join(REPO_ROOT, "configs", "monthly_targets.yaml"),
        help="Path to targets YAML config (default: configs/monthly_targets.yaml)",
    )
    parser.add_argument(
        "--month", default=None,
        help="Report month in YYYY-MM format (default: current month)",
    )
    parser.add_argument(
        "--output-dir", default=os.path.join(REPO_ROOT, "reports", "monthly"),
        help="Output directory for reports (default: reports/monthly/)",
    )

    args = parser.parse_args()

    # Determine month
    month = args.month or datetime.now(timezone.utc).strftime("%Y-%m")

    # Load config
    if not os.path.exists(args.config):
        print(f"Error: Config file not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    config = load_yaml_config(args.config)
    targets = config.get("targets", [])

    if not targets:
        print("Error: No targets found in config file.", file=sys.stderr)
        sys.exit(1)

    print(f"Monthly Agent Security Report - {month}")
    print(f"Targets: {len(targets)} servers")
    print("-" * 50)

    # Run harness against each target
    all_results: dict[str, list[dict]] = {}
    for target in targets:
        name = target.get("name", target.get("url", "unknown"))
        url = target.get("url", "")
        if not url:
            print(f"  Skipping {name}: no URL specified")
            continue

        print(f"  Scanning: {name} ({url})...")
        try:
            results = run_full_harness(url)
            all_results[name] = results
            passed = sum(1 for r in results if r["status"] == "PASS")
            print(f"    {passed}/{len(results)} tests passed")
        except Exception as exc:
            print(f"    Error: {exc}")
            all_results[name] = [{
                "test_id": "CONN",
                "name": "Connection",
                "status": "ERROR",
                "detail": str(exc),
                "category": "",
            }]

    # Generate report
    report = generate_monthly_report(all_results, month, config)

    # Save
    os.makedirs(args.output_dir, exist_ok=True)
    output_path = os.path.join(args.output_dir, f"{month}.md")
    with open(output_path, "w") as f:
        f.write(report)

    print("-" * 50)
    print(f"Report saved to: {output_path}")


if __name__ == "__main__":
    main()
