#!/usr/bin/env python3
"""Free MCP Security Scan - Quick 5-test security assessment for MCP servers.

Runs a lightweight subset of the agent-security-harness MCP tests against a
target server and produces a pass/fail report with an overall letter grade.

Designed to be wrapped by a web API. Self-contained - imports only the
existing mcp_harness module from this repo.

Usage:
    python scripts/free_scan.py --url http://server:port/mcp
    python scripts/free_scan.py --url http://server:port/mcp --format markdown
    python scripts/free_scan.py --url http://server:port/mcp --format json --email user@example.com
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

# Ensure repo root is on path so protocol_tests is importable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from protocol_tests.mcp_harness import (
    MCPSecurityTests,
    MCPTestResult,
    StreamableHTTPTransport,
)

# ── SSRF Protection ────────────────────────────────────────────────────────

def validate_url(url: str) -> str | None:
    """Validate URL for SSRF safety.

    Returns None if valid, or an error message if blocked.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return "Malformed URL"

    if parsed.scheme not in ("http", "https"):
        return f"Blocked scheme: {parsed.scheme} (only http/https allowed)"

    hostname = parsed.hostname
    if not hostname:
        return "No hostname in URL"

    try:
        resolved_ips = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return f"Cannot resolve hostname: {hostname}"

    for family, _type, _proto, _canonname, sockaddr in resolved_ips:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return f"Invalid resolved IP: {ip_str}"

        if addr.is_private:
            return f"Blocked private/internal IP: {ip_str}"
        if addr.is_loopback:
            return f"Blocked loopback IP: {ip_str}"
        if addr.is_link_local:
            return f"Blocked link-local IP: {ip_str}"
        if addr.is_reserved:
            return f"Blocked reserved IP: {ip_str}"
        if ip_str in ("169.254.169.254", "fd00:ec2::254"):
            return f"Blocked cloud metadata IP: {ip_str}"

    return None


# ── The 5 free-scan tests ─────────────────────────────────────────────────
FREE_SCAN_TESTS = [
    {
        "id": "MCP-001",
        "name": "Tool Discovery Poisoning",
        "method": "test_mcp_tool_list_injection",
        "description": "Verifies the server's tool list cannot be poisoned by a crafted client request.",
    },
    {
        "id": "MCP-003",
        "name": "Capability Escalation",
        "method": "test_mcp_capability_escalation",
        "description": "Attempts to claim capabilities the client should not have during initialization.",
    },
    {
        "id": "MCP-004",
        "name": "Protocol Downgrade",
        "method": "test_mcp_protocol_version_downgrade",
        "description": "Sends a downgrade request to an older protocol version to bypass security features.",
    },
    {
        "id": "MCP-008",
        "name": "Malformed JSON-RPC",
        "method": "test_mcp_malformed_jsonrpc",
        "description": "Sends malformed JSON-RPC messages to verify proper error handling.",
    },
    {
        "id": "MCP-010",
        "name": "Tool Argument Injection",
        "method": "test_mcp_tool_argument_injection",
        "description": "Injects malicious arguments into tool calls to test input validation.",
    },
]


# ── Grading ────────────────────────────────────────────────────────────────

def compute_grade(passed: int, total: int) -> str:
    """Return a letter grade A-F based on pass ratio."""
    if total == 0:
        return "F"
    ratio = passed / total
    if ratio >= 1.0:
        return "A"
    elif ratio >= 0.8:
        return "B"
    elif ratio >= 0.6:
        return "C"
    elif ratio >= 0.4:
        return "D"
    else:
        return "F"


def build_recommendation(results: list[dict], grade: str) -> str:
    """Generate a 1-paragraph recommendation based on scan results."""
    failed = [r for r in results if r["status"] != "PASS"]
    if not failed:
        return (
            "All five quick-scan tests passed. This MCP server demonstrates solid "
            "baseline security hygiene. We recommend running the full harness "
            "(20+ tests including DoS resilience, sampling hijack, and path traversal) "
            "for a comprehensive assessment before production deployment."
        )
    fail_names = ", ".join(r["name"] for r in failed)
    return (
        f"The scan detected {len(failed)} issue(s) in: {fail_names}. "
        f"Overall grade: {grade}. These failures indicate potential attack surface "
        f"that adversarial agents or prompt-injection payloads could exploit. "
        f"We strongly recommend remediating the failing tests and running the full "
        f"agent-security-harness suite to identify additional vulnerabilities before "
        f"exposing this server to untrusted clients."
    )


# ── Run scan ───────────────────────────────────────────────────────────────

def run_free_scan(url: str) -> dict:
    """Execute the 5 free-scan tests and return structured results."""
    transport = StreamableHTTPTransport(url)
    harness = MCPSecurityTests(transport)

    scan_results: list[dict] = []
    passed = 0
    total = len(FREE_SCAN_TESTS)

    for test_def in FREE_SCAN_TESTS:
        test_method = getattr(harness, test_def["method"], None)
        if test_method is None:
            scan_results.append({
                "id": test_def["id"],
                "name": test_def["name"],
                "status": "ERROR",
                "detail": "Test method not found in harness.",
            })
            continue

        try:
            result: MCPTestResult = test_method()
            status = result.status.value if hasattr(result.status, "value") else str(result.status)
            is_pass = status.upper() == "PASS"
            if is_pass:
                passed += 1
            scan_results.append({
                "id": test_def["id"],
                "name": test_def["name"],
                "status": status.upper(),
                "detail": result.detail or "",
            })
        except Exception as exc:
            scan_results.append({
                "id": test_def["id"],
                "name": test_def["name"],
                "status": "ERROR",
                "detail": str(exc),
            })

    transport.close()

    grade = compute_grade(passed, total)
    recommendation = build_recommendation(scan_results, grade)

    return {
        "scan_type": "free_mcp_security_scan",
        "target_url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tests_run": total,
        "tests_passed": passed,
        "tests_failed": total - passed,
        "grade": grade,
        "recommendation": recommendation,
        "results": scan_results,
    }


# ── Output formatters ─────────────────────────────────────────────────────

def format_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def format_markdown(report: dict) -> str:
    lines = [
        f"# Free MCP Security Scan Report",
        "",
        f"**Target:** `{report['target_url']}`",
        f"**Date:** {report['timestamp']}",
        f"**Grade:** {report['grade']}",
        f"**Passed:** {report['tests_passed']}/{report['tests_run']}",
        "",
        "## Results",
        "",
        "| Test ID | Test Name | Status | Detail |",
        "|---------|-----------|--------|--------|",
    ]

    for r in report["results"]:
        icon = "PASS" if r["status"] == "PASS" else "FAIL" if r["status"] == "FAIL" else "ERROR"
        detail = r["detail"][:80].replace("|", "/") if r["detail"] else "-"
        lines.append(f"| {r['id']} | {r['name']} | {icon} | {detail} |")

    lines.extend([
        "",
        "## Recommendation",
        "",
        report["recommendation"],
        "",
        "---",
        "",
        "*Generated by [agent-security-harness](https://github.com/msaleme/red-team-blue-team-agent-fabric) free scan.*",
        f"*Run the full harness for 20+ tests including DoS, sampling hijack, path traversal, and more.*",
    ])

    return "\n".join(lines)


# ── Email stub ─────────────────────────────────────────────────────────────

def send_email_stub(email: str, report_text: str) -> None:
    """Stub for email delivery. Replace with actual SMTP/SES integration."""
    print(f"\nWould email to: {email}")
    print(f"Subject: MCP Security Scan Report - Grade {json.loads(report_text)['grade'] if '{' in report_text else 'N/A'}")
    print("(Email sending is stubbed - integrate with your email provider to enable)")


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Free MCP Security Scan - Quick 5-test assessment",
        epilog="Example: python scripts/free_scan.py --url http://localhost:8080/mcp --format markdown",
    )
    parser.add_argument(
        "--url", required=True,
        help="MCP server URL (Streamable HTTP endpoint)",
    )
    parser.add_argument(
        "--format", choices=["json", "markdown"], default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--email", type=str, default=None,
        help="Email address to send the report to (stubbed)",
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Write report to file instead of stdout",
    )

    args = parser.parse_args()

    # Validate URL against SSRF before scanning
    ssrf_err = validate_url(args.url)
    if ssrf_err:
        print(f"ERROR: URL validation failed: {ssrf_err}", file=sys.stderr)
        sys.exit(2)

    # Run the scan
    report = run_free_scan(args.url)

    # Format output
    if args.format == "markdown":
        output = format_markdown(report)
    else:
        output = format_json(report)

    # Write or print
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Email stub
    if args.email:
        send_email_stub(args.email, format_json(report))

    # Exit with non-zero if any tests failed
    sys.exit(0 if report["tests_passed"] == report["tests_run"] else 1)


if __name__ == "__main__":
    main()
