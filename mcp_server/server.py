"""Agent Security Harness MCP Server.

Exposes five tools over the Model Context Protocol:
  - scan_mcp_server     Quick 5-test scan with A-F grading
  - full_security_audit Full harness run with attestation report
  - aiuc1_readiness     AIUC-1 certification readiness assessment
  - get_test_catalog    List all available security tests
  - validate_attestation Validate an attestation report against schema

Requires: pip install mcp>=1.0.0
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging (server-side only, never exposed to clients)
# ---------------------------------------------------------------------------

_log = logging.getLogger("mcp_server")
_log_handler = logging.FileHandler(
    os.environ.get("MCP_SERVER_LOG", "/dev/null"), mode="a"
)
_log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
_log.addHandler(_log_handler)
_log.setLevel(logging.DEBUG)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------------------
# SSRF validation (reuse from free_scan)
# ---------------------------------------------------------------------------

from scripts.free_scan import validate_url  # noqa: E402

# ---------------------------------------------------------------------------
# Auth helper (#98 - enforce API key auth)
# ---------------------------------------------------------------------------

_api_key: str | None = None

# Max payload size for report_json inputs (10 MB)
_MAX_REPORT_SIZE = 10_000_000


def _check_auth(ctx: dict) -> bool:
    """Enforce API key authentication for protected tools.

    Returns True if auth passes. Raises ValueError on failure.
    If no API key is configured server-side, all requests are allowed.
    """
    if not _api_key:
        return True  # No key configured, allow all

    # Check for key in tool params or environment
    provided_key = ctx.get("api_key", "") or os.environ.get(
        "AGENT_SECURITY_CLIENT_KEY", ""
    )
    if not provided_key or not hmac.compare_digest(provided_key, _api_key):
        raise ValueError("Invalid or missing API key")
    return True


# ---------------------------------------------------------------------------
# Rate limiter - per-client (#102)
# ---------------------------------------------------------------------------

_rate_limit_store: dict[str, float] = {}
RATE_LIMIT_SECONDS = 60
_RATE_LIMIT_TTL = 300  # Clean entries older than 5 minutes


def _clean_rate_limits() -> None:
    """Remove stale rate-limit entries older than TTL."""
    now = time.time()
    stale = [k for k, v in _rate_limit_store.items() if now - v > _RATE_LIMIT_TTL]
    for k in stale:
        del _rate_limit_store[k]


def _check_rate_limit(client_id: str = "default") -> str | None:
    """Return an error message if rate-limited, else None."""
    _clean_rate_limits()
    now = time.time()
    last = _rate_limit_store.get(client_id, 0.0)
    if now - last < RATE_LIMIT_SECONDS:
        remaining = int(RATE_LIMIT_SECONDS - (now - last))
        return f"Rate limited. Try again in {remaining}s (1 scan per {RATE_LIMIT_SECONDS}s)."
    _rate_limit_store[client_id] = now
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_error(e: Exception) -> str:
    """Return error message without file paths (#106)."""
    msg = str(e)
    msg = re.sub(r"/[^\s:]+/", "<path>/", msg)
    return msg


def _run_subprocess(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run a subprocess rooted at REPO_ROOT and return (returncode, stdout, stderr).

    stderr is captured but only logged server-side, never returned to clients (#100).
    """
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(REPO_ROOT),
    )
    if result.stderr:
        _log.warning("Subprocess stderr for %s: %s", cmd[0], result.stderr)
    return result.returncode, result.stdout, result.stderr


def _validate_url_input(url: str) -> dict | None:
    """Validate a URL and return an error dict if invalid, else None."""
    if not url:
        return {"error": "URL is required."}
    err = validate_url(url)
    if err:
        return {"error": f"URL validation failed: {err}"}
    return None


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


def create_server(api_key: str | None = None) -> FastMCP:
    """Create and configure the MCP server with all tools registered."""
    global _api_key
    _api_key = api_key

    mcp = FastMCP(
        "Agent Security Harness",
        version="1.0.0",
        description=(
            "Security testing tools for AI agent systems. "
            "332 tests across MCP, A2A, L402, x402, and identity protocols."
        ),
    )

    # ------------------------------------------------------------------
    # Tool 1: scan_mcp_server (unauthenticated - free tier)
    # ------------------------------------------------------------------

    # Session counter for anonymous clients (#109)
    _session_counter = defaultdict(int)

    @mcp.tool()
    def scan_mcp_server(url: str, transport: str = "http") -> dict:
        """Quick 5-test MCP security scan with A-F grading.

        Runs the five most critical MCP protocol tests against a target server
        and returns a grade (A-F), per-test pass/fail results, a recommendation,
        and scan duration.

        Args:
            url: The MCP server URL to scan (e.g. http://host:port/mcp).
            transport: Transport type - 'http' for Streamable HTTP (default),
                       'stdio' for stdio-based servers.

        Returns:
            dict with keys: grade, tests_passed, tests_run, results,
            recommendation, scan_time, target_url, timestamp.
        """
        # Rate limit per-client (#109): key on URL as client identifier
        # since MCP tool calls don't carry a client_id in context.
        # This ensures different clients scanning different targets aren't blocked.
        client_key = f"scan:{url}"
        rate_err = _check_rate_limit(client_key)
        if rate_err:
            return {"error": rate_err}

        # Validate URL (#99 - SSRF protection)
        url_err = _validate_url_input(url)
        if url_err:
            return url_err

        # Validate transport (#110)
        valid_transports = {"http", "stdio"}
        if transport not in valid_transports:
            return {"error": f"Invalid transport '{transport}'. Choose from: {', '.join(sorted(valid_transports))}"}

        start = time.time()
        try:
            from scripts.free_scan import run_free_scan
            report = run_free_scan(url, transport=transport)
            report["scan_time"] = round(time.time() - start, 2)
            return report
        except Exception as e:
            _log.exception("scan_mcp_server failed")
            return {
                "error": "Scan failed. Check server logs for details.",
                "target_url": url,
                "scan_time": round(time.time() - start, 2),
            }

    # ------------------------------------------------------------------
    # Tool 2: full_security_audit (requires auth)
    # ------------------------------------------------------------------

    @mcp.tool()
    def full_security_audit(
        url: str,
        protocol: str = "mcp",
        categories: str = "",
        trials: int = 1,
        transport: str = "http",
        api_key: str = "",
    ) -> dict:
        """Full security audit with attestation report.

        Runs the complete agent-security-harness test suite against a target
        and returns a full attestation report in JSON format.

        Args:
            url: Target server URL.
            protocol: Protocol to test - mcp, a2a, x402, l402, or identity.
            categories: Comma-separated category filter (e.g. 'tool_poisoning,capability_escalation').
                        Empty string runs all categories.
            trials: Number of test trials (default 1). Higher values improve
                    statistical confidence for flaky tests.
            transport: Transport type - 'http' for Streamable HTTP (default),
                       'stdio' for stdio-based servers.
            api_key: API key for authentication (required when server is configured with --api-key).

        Returns:
            Full attestation report dict with summary, per-test entries,
            scope annotations, and remediation guidance.
        """
        # Auth check (#98)
        try:
            _check_auth({"api_key": api_key})
        except ValueError as e:
            return {"error": str(e)}

        # Rate limit (per-client)
        rate_err = _check_rate_limit(f"audit:{api_key or 'anon'}")
        if rate_err:
            return {"error": rate_err}

        # Validate URL (#99 - SSRF protection)
        url_err = _validate_url_input(url)
        if url_err:
            return url_err

        valid_protocols = {"mcp", "a2a", "x402", "l402", "identity"}
        if protocol not in valid_protocols:
            return {"error": f"Invalid protocol '{protocol}'. Choose from: {', '.join(sorted(valid_protocols))}"}

        if trials < 1 or trials > 10:
            return {"error": "trials must be between 1 and 10."}

        valid_transports = {"http", "stdio"}
        if transport not in valid_transports:
            return {"error": f"Invalid transport '{transport}'. Choose from: {', '.join(sorted(valid_transports))}"}

        start = time.time()
        report_path = None
        try:
            # Ensure reports/ directory exists (#104)
            os.makedirs(str(REPO_ROOT / "reports"), exist_ok=True)

            with tempfile.NamedTemporaryFile(
                suffix=".json", delete=False, dir=str(REPO_ROOT / "reports")
            ) as tmp:
                report_path = tmp.name

            cmd = [
                sys.executable, "-m", "protocol_tests.cli",
                "test", protocol,
                "--url", url,
                "--report", report_path,
                "--transport", transport,
            ]
            if categories:
                cmd.extend(["--categories", categories])
            if trials > 1:
                cmd.extend(["--trials", str(trials)])

            rc, stdout, stderr = _run_subprocess(cmd, timeout=300)

            if report_path and os.path.exists(report_path):
                with open(report_path) as f:
                    report = json.load(f)
                report["scan_time"] = round(time.time() - start, 2)
                return report
            else:
                # (#100) Don't leak stderr to client
                return {
                    "error": "Audit completed but no report was generated. Check server logs for details.",
                    "returncode": rc,
                    "scan_time": round(time.time() - start, 2),
                }
        except subprocess.TimeoutExpired:
            return {"error": "Audit timed out after 300s.", "target_url": url}
        except Exception as e:
            _log.exception("full_security_audit failed")
            return {
                "error": "Audit failed. Check server logs for details.",
                "target_url": url,
            }
        finally:
            # (#103) Clean up temp file
            if report_path:
                try:
                    os.unlink(report_path)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Tool 3: aiuc1_readiness (requires auth)
    # ------------------------------------------------------------------

    @mcp.tool()
    def aiuc1_readiness(
        url: str = "", report_json: str = "", api_key: str = ""
    ) -> dict:
        """AIUC-1 certification readiness assessment.

        Evaluates readiness for AIUC-1 (AI Agent Certification) by mapping
        security test results to certification requirements. Accepts either
        a live URL to scan or a pre-existing report JSON string.

        Args:
            url: Target URL to scan (runs full harness first). Provide this
                 OR report_json, not both.
            report_json: Pre-existing attestation report as a JSON string.
                         Useful for evaluating previously-generated reports.
            api_key: API key for authentication (required when server is configured with --api-key).

        Returns:
            dict with readiness_score, per-requirement status, gap_analysis,
            grade, and recommendations.
        """
        # Auth check (#98)
        try:
            _check_auth({"api_key": api_key})
        except ValueError as e:
            return {"error": str(e)}

        if not url and not report_json:
            return {"error": "Provide either 'url' (to scan) or 'report_json' (pre-existing report)."}

        if url and report_json:
            return {"error": "Provide either 'url' or 'report_json', not both."}

        # (#101) Size limit on report_json
        if report_json and len(report_json) > _MAX_REPORT_SIZE:
            return {"error": "Report exceeds 10MB limit"}

        start = time.time()

        try:
            from scripts.aiuc1_prep import (
                map_results_to_requirements,
                AIUC1_REQUIREMENTS,
            )
            from protocol_tests.version import get_harness_version

            all_results: list[dict] = []
            target = ""

            if report_json:
                # Parse pre-existing report
                try:
                    report_data = json.loads(report_json)
                except json.JSONDecodeError as e:
                    return {"error": f"Invalid JSON in report_json: {_safe_error(e)}"}

                all_results = report_data.get("entries", report_data.get("results", []))
                target = report_data.get("target", "pre-existing report")
            else:
                # Validate URL (#99 - SSRF protection)
                url_err = _validate_url_input(url)
                if url_err:
                    return url_err

                rate_err = _check_rate_limit(f"aiuc1:{api_key or 'anon'}")
                if rate_err:
                    return {"error": rate_err}

                from scripts.aiuc1_prep import run_harness
                target = url
                all_results = run_harness(url=url)

            # Map results to AIUC-1 requirements
            statuses = map_results_to_requirements(all_results)

            total = len(statuses)
            passing = sum(1 for s in statuses if s.status == "COVERED+PASS")
            failing = sum(1 for s in statuses if s.status == "COVERED+FAIL")
            gaps = sum(1 for s in statuses if s.status == "NOT YET COVERED")
            covered = sum(1 for s in statuses if s.status.startswith("COVERED"))

            score = round((passing / total * 100) if total > 0 else 0, 1)

            # Grade
            if score >= 90:
                grade = "A"
            elif score >= 75:
                grade = "B"
            elif score >= 50:
                grade = "C"
            elif score >= 25:
                grade = "D"
            else:
                grade = "F"

            requirements = []
            for s in statuses:
                requirements.append({
                    "req_id": s.req_id,
                    "title": s.title,
                    "category": s.category,
                    "status": s.status,
                    "test_ids": s.test_ids,
                    "passed": s.passed,
                    "failed": s.failed,
                    "total": s.total,
                    "notes": s.notes,
                })

            gap_analysis = []
            for s in statuses:
                if s.status == "NOT YET COVERED":
                    gap_analysis.append({
                        "req_id": s.req_id,
                        "title": s.title,
                        "category": s.category,
                        "notes": s.notes,
                        "test_ids": s.test_ids,
                    })

            return {
                "target": target,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "readiness_score": score,
                "grade": grade,
                "summary": {
                    "total_requirements": total,
                    "covered": covered,
                    "passing": passing,
                    "failing": failing,
                    "gaps": gaps,
                },
                "requirements": requirements,
                "gap_analysis": gap_analysis,
                "scan_time": round(time.time() - start, 2),
            }

        except Exception as e:
            _log.exception("aiuc1_readiness failed")
            return {"error": "AIUC-1 readiness check failed. Check server logs for details."}

    # ------------------------------------------------------------------
    # Tool 4: get_test_catalog (unauthenticated - free tier)
    # ------------------------------------------------------------------

    @mcp.tool()
    def get_test_catalog(protocol: str = "") -> dict:
        """List all available security tests in the harness.

        Returns the full test catalog with test_id, name, category, and
        severity for each test. Optionally filter by protocol.

        Args:
            protocol: Optional protocol filter (mcp, a2a, l402, x402, identity).
                      Empty string returns all tests.

        Returns:
            dict with total count and list of test entries.
        """
        try:
            rc, stdout, stderr = _run_subprocess(
                [sys.executable, str(REPO_ROOT / "scripts" / "count_tests.py")],
                timeout=30,
            )

            # Parse the count_tests output for module info
            # Also build catalog from harness modules directly
            from scripts.count_tests import TEST_ID_RE, ARG_ID_RE, MODULE_NAMES, EXCLUDE_IDS
            harness_dir = REPO_ROOT / "protocol_tests"

            catalog: list[dict] = []
            protocol_filter = protocol.lower().strip() if protocol else ""

            # Map protocol filter to module prefixes
            protocol_prefixes = {
                "mcp": ["MCP"],
                "a2a": ["A2A"],
                "l402": ["L4"],
                "x402": ["X4"],
                "identity": ["ID"],
            }

            for pyfile in sorted(harness_dir.glob("*.py")):
                if pyfile.name.startswith("__"):
                    continue
                text = pyfile.read_text()
                ids = set(TEST_ID_RE.findall(text))
                ids |= set(ARG_ID_RE.findall(text))
                ids -= EXCLUDE_IDS

                module_name = MODULE_NAMES.get(pyfile.name, pyfile.name.replace(".py", ""))

                for tid in sorted(ids):
                    # Determine severity from ID prefix patterns
                    prefix = tid.split("-")[0] if "-" in tid else tid[:3]

                    # Apply protocol filter
                    if protocol_filter:
                        allowed = protocol_prefixes.get(protocol_filter, [])
                        if allowed and prefix not in allowed:
                            continue

                    severity = _infer_severity(prefix)
                    catalog.append({
                        "test_id": tid,
                        "name": tid,
                        "category": module_name,
                        "severity": severity,
                    })

            return {
                "total": len(catalog),
                "protocol_filter": protocol_filter or "all",
                "tests": catalog,
            }

        except Exception as e:
            _log.exception("get_test_catalog failed")
            return {"error": "Failed to load test catalog. Check server logs for details."}

    # ------------------------------------------------------------------
    # Tool 5: validate_attestation
    # ------------------------------------------------------------------

    @mcp.tool()
    def validate_attestation(report_json: str) -> dict:
        """Validate an attestation report against the JSON schema.

        Checks that a report conforms to the attestation-report.json schema
        used by the agent-security-harness for compliance reporting.

        Args:
            report_json: The attestation report as a JSON string.

        Returns:
            dict with 'valid' (bool), 'errors' (list of error strings),
            and 'schema_version'.
        """
        # (#101) Size limit on report_json
        if len(report_json) > _MAX_REPORT_SIZE:
            return {
                "valid": False,
                "errors": ["Report exceeds 10MB limit"],
                "schema_version": "1.0.0",
            }

        try:
            report = json.loads(report_json)
        except json.JSONDecodeError as e:
            return {
                "valid": False,
                "errors": [f"Invalid JSON: {_safe_error(e)}"],
                "schema_version": "1.0.0",
            }

        try:
            from protocol_tests.attestation import validate_attestation_report, SCHEMA_VERSION
            errors = validate_attestation_report(report)
            return {
                "valid": len(errors) == 0,
                "errors": errors,
                "schema_version": SCHEMA_VERSION,
            }
        except Exception as e:
            _log.exception("validate_attestation failed")
            return {
                "valid": False,
                "errors": ["Validation failed. Check server logs for details."],
                "schema_version": "1.0.0",
            }

    return mcp


# ---------------------------------------------------------------------------
# Severity inference helper
# ---------------------------------------------------------------------------

def _infer_severity(prefix: str) -> str:
    """Infer test severity from ID prefix."""
    high = {"MCP", "A2A", "CVE", "GTG", "JB"}
    medium = {"L4", "X4", "ID", "RC", "PROV"}
    if prefix in high:
        return "high"
    elif prefix in medium:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Server runner
# ---------------------------------------------------------------------------

def run_server(mcp: FastMCP, transport: str = "stdio", host: str = "127.0.0.1", port: int = 8400) -> None:
    """Start the MCP server with the specified transport."""
    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "http":
        mcp.run(transport="streamable-http", host=host, port=port)
    else:
        print(f"Unknown transport: {transport}", file=sys.stderr)
        sys.exit(1)
