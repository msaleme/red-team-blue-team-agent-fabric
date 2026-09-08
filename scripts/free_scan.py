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
import os
import socket
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

# Ensure repo root is on path so protocol_tests is importable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from protocol_tests.http_helpers import is_inconclusive
from protocol_tests.mcp_harness import (
    MCPSecurityTests,
    MCPTestResult,
    StreamableHTTPTransport,
)

#: Row status when the scanner itself could not reach a verdict. It is never
#: a failed test and never a detected issue.
INCONCLUSIVE = "INCONCLUSIVE"
COULD_NOT_EVALUATE = "the scanner could not evaluate this test"
GRADE_NOT_ESTABLISHED = "not established"

# ── SSRF Protection ────────────────────────────────────────────────────────

def validate_url(url: str) -> str | None:
    """Validate URL for SSRF safety.

    Returns None if valid, or an error message if blocked.

    NOTE: This check is vulnerable to DNS rebinding / TOCTOU attacks where the
    hostname resolves to a safe IP at validation time but to an internal IP at
    request time.  A robust mitigation would resolve DNS once, pin the IP, and
    connect directly (bypassing further resolution), but that requires
    socket-level control incompatible with urllib.  For now, accept the
    limitation and rely on network-layer controls (firewall egress rules) as a
    secondary safeguard.
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
        if addr.is_multicast:
            return f"Blocked multicast IP: {ip_str}"
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

def compute_grade(passed: int, total: int) -> str | None:
    """Return a letter grade A-F based on pass ratio.

    ``None`` when nothing was evaluated: zero tests is not an F, it is no
    grade at all (R4-06).
    """
    if total == 0:
        return None
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


def build_recommendation(results: list[dict], grade: str | None) -> str:
    """Generate a 1-paragraph recommendation based on scan results.

    Only a row the scanner actually evaluated can be a detected issue. A row
    the scanner could not evaluate is reported as exactly that, and no grade
    is claimed over it.
    """
    failed = [r for r in results if r["status"] == "FAIL"]
    unevaluated = [r for r in results if r["status"] == INCONCLUSIVE]
    if unevaluated:
        names = ", ".join(r["name"] for r in unevaluated)
        text = (
            f"The scanner could not evaluate {len(unevaluated)} of {len(results)} "
            f"tests ({names}), so no grade is established. This is not evidence "
            f"that the server is vulnerable, and it is not evidence that it is "
            f"secure. Check that the target URL is a reachable Streamable HTTP "
            f"MCP endpoint and re-run the scan."
        )
        if failed:
            fail_names = ", ".join(r["name"] for r in failed)
            text += (
                f" Of the tests that were evaluated, {len(failed)} failed: "
                f"{fail_names}. Remediate those before re-running."
            )
        return text
    if not failed:
        return (
            "All five quick-scan tests passed. This MCP server demonstrates solid "
            "baseline security hygiene. We recommend running the full harness "
            "(623 tests across 45 test-bearing modules including DoS resilience, sampling hijack, and path traversal) "
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

def _row(test_def: dict, status: str, detail: str) -> dict:
    return {
        "id": test_def["id"],
        "name": test_def["name"],
        "status": status,
        "detail": detail or "",
    }


def _status_of(result: MCPTestResult) -> str:
    if is_inconclusive(result):
        return INCONCLUSIVE
    return "PASS" if result.passed else "FAIL"


def run_free_scan(url: str, transport: str = "http") -> dict:
    """Execute the 5 free-scan tests and return structured results.

    Args:
        url: Target MCP server URL.
        transport: Transport type - 'http' (default) or 'stdio'.

    The selected ``MCPSecurityTests`` methods record their result on the
    suite and return ``None``. This wrapper used to dereference that ``None``,
    catch its own ``AttributeError`` and publish it as five failed tests,
    grade F and "The scan detected 5 issue(s)" -- against the shipped mock and
    against a closed port alike (R4-06, fourth external review, 2026-09-08).
    It now reads the recorded result back by test id, runs the MCP handshake
    the methods assume (as ``run_all`` does), and reports anything the
    scanner itself could not do as INCONCLUSIVE with no grade.
    """
    # #110 - Wire transport parameter through
    if transport == "stdio":
        from protocol_tests.mcp_harness import StdioTransport
        _transport = StdioTransport(url)
    else:
        _transport = StreamableHTTPTransport(url)
    # json_output silences the per-test console lines, which would otherwise
    # land on stdout ahead of the JSON this script prints.
    harness = MCPSecurityTests(_transport, json_output=True)

    scan_results: list[dict] = []
    total = len(FREE_SCAN_TESTS)

    try:
        # The test methods assume the handshake ran; run_all() aborts when it
        # does not. Against a closed port that is the whole verdict.
        init_error: str | None = None
        try:
            initialized = bool(harness.initialize())
        except Exception as exc:  # the transport raised rather than reporting
            initialized = False
            init_error = f"{type(exc).__name__}: {exc}"
        if not initialized:
            reason = (getattr(harness, "_connection_error", None) or init_error
                      or "MCP initialize did not succeed")
            for test_def in FREE_SCAN_TESTS:
                scan_results.append(_row(
                    test_def, INCONCLUSIVE,
                    f"INCONCLUSIVE - {COULD_NOT_EVALUATE}: {reason}"))
        else:
            for test_def in FREE_SCAN_TESTS:
                test_method = getattr(harness, test_def["method"], None)
                if test_method is None:
                    scan_results.append(_row(
                        test_def, INCONCLUSIVE,
                        f"INCONCLUSIVE - {COULD_NOT_EVALUATE}: test method "
                        f"{test_def['method']} not found in harness"))
                    continue

                before = len(harness.results)
                try:
                    test_method()
                except Exception as exc:
                    scan_results.append(_row(
                        test_def, INCONCLUSIVE,
                        f"INCONCLUSIVE - {COULD_NOT_EVALUATE}: "
                        f"{type(exc).__name__}: {exc}"))
                    continue

                recorded = [r for r in harness.results[before:]
                            if r.test_id == test_def["id"]]
                if not recorded:
                    scan_results.append(_row(
                        test_def, INCONCLUSIVE,
                        f"INCONCLUSIVE - {COULD_NOT_EVALUATE}: the harness "
                        f"recorded no result for {test_def['id']}"))
                    continue
                result = recorded[-1]
                scan_results.append(_row(test_def, _status_of(result), result.details))
    finally:
        try:
            _transport.close()
        except Exception:
            pass

    passed = sum(1 for r in scan_results if r["status"] == "PASS")
    failed = sum(1 for r in scan_results if r["status"] == "FAIL")
    inconclusive = sum(1 for r in scan_results if r["status"] == INCONCLUSIVE)

    # A grade is a claim over all five tests. If any of them was not
    # evaluated, no such claim exists.
    grade = compute_grade(passed, total) if inconclusive == 0 else None
    recommendation = build_recommendation(scan_results, grade)

    return {
        "scan_type": "free_mcp_security_scan",
        "target_url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tests_run": total,
        "tests_evaluated": total - inconclusive,
        "tests_passed": passed,
        "tests_failed": failed,
        "tests_inconclusive": inconclusive,
        "grade": grade,
        "grade_status": "established" if grade is not None else GRADE_NOT_ESTABLISHED,
        "recommendation": recommendation,
        "results": scan_results,
    }


# ── Output formatters ─────────────────────────────────────────────────────

def format_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def format_markdown(report: dict) -> str:
    lines = [
        "# Free MCP Security Scan Report",
        "",
        f"**Target:** `{report['target_url']}`",
        f"**Date:** {report['timestamp']}",
        f"**Grade:** {report['grade'] or GRADE_NOT_ESTABLISHED}",
        f"**Passed:** {report['tests_passed']}/{report['tests_run']}"
        + (f" ({report['tests_inconclusive']} not evaluated)"
           if report.get('tests_inconclusive') else ""),
        "",
        "## Results",
        "",
        "| Test ID | Test Name | Status | Detail |",
        "|---------|-----------|--------|--------|",
    ]

    for r in report["results"]:
        icon = r["status"]
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
        "*Run the full harness for 623 tests across 45 test-bearing modules including DoS, sampling hijack, path traversal, and more.*",
    ])

    return "\n".join(lines)


# ── Email stub ─────────────────────────────────────────────────────────────

def send_email_stub(email: str, report_text: str) -> None:
    """Stub for email delivery. Replace with actual SMTP/SES integration."""
    print(f"\nWould email to: {email}")
    grade = json.loads(report_text).get("grade") if "{" in report_text else None
    print(f"Subject: MCP Security Scan Report - Grade {grade or GRADE_NOT_ESTABLISHED}")
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

    # Exit code: 0 all passed, 1 a test failed, 2 the scanner could not
    # evaluate every test (no grade established).
    if report["tests_inconclusive"]:
        sys.exit(2)
    sys.exit(0 if report["tests_failed"] == 0 else 1)


if __name__ == "__main__":
    main()
