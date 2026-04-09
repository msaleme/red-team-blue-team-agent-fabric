#!/usr/bin/env python3
"""Audit-Ready Evidence Pack Generator

Generates a signed evidence package from agent-security harness test results.
The evidence pack is usable in four contexts without reformatting:
  1. CI gate artifact
  2. Exception review input
  3. Procurement questionnaire attachment
  4. Audit packet exhibit

Usage:
    python scripts/evidence_pack.py --report report.json --output evidence/
    python scripts/evidence_pack.py --report report.json --output evidence/ --sign --zip

Requires: Python 3.10+, PyYAML (for AIUC-1 mapping)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure repo root is on path so protocol_tests is importable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from protocol_tests.version import get_harness_version

HARNESS_VERSION = get_harness_version()


# ---------------------------------------------------------------------------
# AIUC-1 mapping loader
# ---------------------------------------------------------------------------

def load_aiuc1_mapping(mapping_path: str | None = None) -> dict[str, Any]:
    """Load AIUC-1 requirement-to-test mapping from YAML config."""
    import yaml  # PyYAML — project dependency

    if mapping_path is None:
        mapping_path = os.path.join(REPO_ROOT, "configs", "aiuc1_mapping.yaml")

    with open(mapping_path) as f:
        data = yaml.safe_load(f)
    return data


def _build_requirement_index(mapping: dict[str, Any]) -> dict[str, dict]:
    """Build a flat {req_id: {title, category, test_ids, owasp_asi, status, ...}} index."""
    index: dict[str, dict] = {}
    categories = mapping.get("categories", {})
    for _cat_key, cat_data in categories.items():
        cat_name = cat_data.get("name", _cat_key)
        for req_id, req_def in cat_data.get("requirements", {}).items():
            index[req_id] = {
                "title": req_def.get("title", ""),
                "category": cat_name,
                "test_ids": req_def.get("test_ids", []),
                "owasp_asi": req_def.get("owasp_asi", ""),
                "nist_rmf": req_def.get("nist_rmf", ""),
                "status": req_def.get("status", "UNKNOWN"),
                "gap_notes": req_def.get("gap_notes") or "",
            }
    return index


# ---------------------------------------------------------------------------
# Report loading
# ---------------------------------------------------------------------------

def load_report(path: str) -> dict[str, Any]:
    """Load a harness JSON report file and return the full dict."""
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# AIUC-1 coverage computation
# ---------------------------------------------------------------------------

def compute_aiuc1_coverage(
    results: list[dict],
    req_index: dict[str, dict],
) -> dict[str, Any]:
    """Map test results to AIUC-1 requirements and compute coverage.

    Returns a dict keyed by requirement ID with per-requirement pass/fail info.
    """
    # Index results by test_id
    result_by_id: dict[str, dict] = {}
    for r in results:
        tid = r.get("test_id", "")
        if tid:
            result_by_id[tid] = r

    coverage: dict[str, Any] = {}
    covered_count = 0
    total_count = len(req_index)
    gap_count = 0

    for req_id, req_def in sorted(req_index.items()):
        test_ids = req_def["test_ids"]
        is_gap = req_def["status"] == "GAP"

        if is_gap or not test_ids:
            coverage[req_id] = {
                "title": req_def["title"],
                "category": req_def["category"],
                "status": "GAP",
                "test_ids": test_ids,
                "passed": 0,
                "failed": 0,
                "total": 0,
                "notes": req_def.get("gap_notes") or "Not yet covered",
            }
            gap_count += 1
            continue

        matched = [tid for tid in test_ids if tid in result_by_id]
        if not matched:
            coverage[req_id] = {
                "title": req_def["title"],
                "category": req_def["category"],
                "status": "NO_RESULTS",
                "test_ids": test_ids,
                "passed": 0,
                "failed": 0,
                "total": 0,
                "notes": "Tests defined but not present in this report.",
            }
            continue

        passed = sum(1 for tid in matched if result_by_id[tid].get("passed", False))
        failed = len(matched) - passed
        status = "PASS" if failed == 0 else "FAIL"
        covered_count += 1

        coverage[req_id] = {
            "title": req_def["title"],
            "category": req_def["category"],
            "status": status,
            "test_ids": test_ids,
            "passed": passed,
            "failed": failed,
            "total": len(matched),
        }

    return {
        "covered": covered_count,
        "total": total_count,
        "gaps": gap_count,
        "requirements": coverage,
    }


# ---------------------------------------------------------------------------
# OWASP Agentic Top 10 mapping
# ---------------------------------------------------------------------------

# OWASP Agentic Security Initiative categories
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


def compute_owasp_coverage(
    results: list[dict],
    req_index: dict[str, dict],
) -> dict[str, Any]:
    """Map test results to OWASP Agentic Security Initiative categories."""
    # Build ASI -> test_ids mapping from the requirement index
    asi_tests: dict[str, list[str]] = {}
    for _req_id, req_def in req_index.items():
        asi = req_def.get("owasp_asi", "")
        if asi:
            for tid in req_def["test_ids"]:
                if tid not in asi_tests.get(asi, []):
                    asi_tests.setdefault(asi, []).append(tid)

    # Index results
    result_by_id: dict[str, dict] = {}
    for r in results:
        tid = r.get("test_id", "")
        if tid:
            result_by_id[tid] = r

    owasp: dict[str, Any] = {}
    for asi_id, asi_name in OWASP_AGENTIC_CATEGORIES.items():
        test_ids = list(dict.fromkeys(asi_tests.get(asi_id, [])))  # deduplicate preserving order
        matched = [tid for tid in test_ids if tid in result_by_id]
        passed = sum(1 for tid in matched if result_by_id[tid].get("passed", False))
        failed = len(matched) - passed

        owasp[asi_id] = {
            "name": asi_name,
            "tests_mapped": len(test_ids),
            "tests_run": len(matched),
            "passed": passed,
            "failed": failed,
            "status": "PASS" if (matched and failed == 0) else ("FAIL" if failed > 0 else "NOT_TESTED"),
        }

    return owasp


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def compute_evidence_hash(*json_blobs: str) -> str:
    """SHA-256 hash of concatenated JSON content."""
    h = hashlib.sha256()
    for blob in json_blobs:
        h.update(blob.encode("utf-8"))
    return f"sha256:{h.hexdigest()}"


def sign_evidence(evidence_hash: str, sign_key: str) -> dict[str, Any]:
    """HMAC-SHA256 signature over the evidence hash."""
    sig = hmac.new(
        sign_key.encode("utf-8"),
        evidence_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "signed": True,
        "algorithm": "hmac-sha256",
        "signature": sig,
    }


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def generate_markdown(
    summary: dict[str, Any],
    aiuc1: dict[str, Any],
    owasp: dict[str, Any],
    target: str,
    timestamp: str,
) -> str:
    """Generate a human-readable markdown evidence summary for auditors."""
    total = summary["total_tests"]
    passed = summary["passed"]
    failed = summary["failed"]
    pass_rate = summary["pass_rate"]

    lines = [
        "# Evidence Pack Summary",
        "",
        f"**Generated:** {timestamp}",
        f"**Harness Version:** {HARNESS_VERSION}",
        f"**Target:** {target}",
        f"**Schema Version:** 1.0.0",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"The Agent Security Harness v{HARNESS_VERSION} executed {total} tests "
        f"against `{target}`. {passed} tests passed and {failed} failed, yielding "
        f"an overall pass rate of {pass_rate:.1%}. AIUC-1 requirement coverage "
        f"stands at {aiuc1['covered']}/{aiuc1['total']} requirements with "
        f"{aiuc1['gaps']} known gaps.",
        "",
        "---",
        "",
        "## Test Results",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Tests | {total} |",
        f"| Passed | {passed} |",
        f"| Failed | {failed} |",
        f"| Pass Rate | {pass_rate:.1%} |",
        "",
        "---",
        "",
        "## AIUC-1 Requirement Coverage",
        "",
        "| Requirement | Title | Category | Status | Passed | Failed |",
        "|-------------|-------|----------|--------|--------|--------|",
    ]

    for req_id, req_data in sorted(aiuc1.get("requirements", {}).items()):
        status = req_data["status"]
        lines.append(
            f"| {req_id} | {req_data['title']} | {req_data['category']} "
            f"| **{status}** | {req_data.get('passed', 0)} | {req_data.get('failed', 0)} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## OWASP Agentic Security Initiative Coverage",
        "",
        "| ID | Category | Tests Mapped | Tests Run | Passed | Failed | Status |",
        "|----|----------|-------------|-----------|--------|--------|--------|",
    ])

    for asi_id, asi_data in sorted(owasp.items()):
        lines.append(
            f"| {asi_id} | {asi_data['name']} | {asi_data['tests_mapped']} "
            f"| {asi_data['tests_run']} | {asi_data['passed']} "
            f"| {asi_data['failed']} | **{asi_data['status']}** |"
        )

    # Gaps and recommendations
    gap_reqs = {
        rid: rd for rid, rd in aiuc1.get("requirements", {}).items()
        if rd["status"] == "GAP"
    }
    fail_reqs = {
        rid: rd for rid, rd in aiuc1.get("requirements", {}).items()
        if rd["status"] == "FAIL"
    }

    lines.extend([
        "",
        "---",
        "",
        "## Gaps and Recommendations",
        "",
    ])

    if gap_reqs:
        lines.append("### Coverage Gaps")
        lines.append("")
        for req_id, req_data in sorted(gap_reqs.items()):
            notes = req_data.get("notes", "No additional notes.")
            lines.append(f"- **{req_id} ({req_data['title']}):** {notes}")
        lines.append("")

    if fail_reqs:
        lines.append("### Failing Requirements")
        lines.append("")
        for req_id, req_data in sorted(fail_reqs.items()):
            lines.append(
                f"- **{req_id} ({req_data['title']}):** "
                f"{req_data['failed']}/{req_data['total']} tests failing"
            )
        lines.append("")

    if not gap_reqs and not fail_reqs:
        lines.append("No gaps or failures identified.")
        lines.append("")

    lines.extend([
        "---",
        "",
        f"*Generated by Agent Security Harness v{HARNESS_VERSION} Evidence Pack Generator*",
        f"*Repository: https://github.com/msaleme/red-team-blue-team-agent-fabric*",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Evidence pack builder
# ---------------------------------------------------------------------------

def build_evidence_pack(
    report_path: str,
    target: str,
    output_dir: str,
    do_sign: bool = False,
    do_zip: bool = False,
    mapping_path: str | None = None,
) -> str:
    """Build the evidence pack and return the output path."""
    # Load inputs
    report_data = load_report(report_path)
    results = report_data.get("results", [])
    mapping = load_aiuc1_mapping(mapping_path)
    req_index = _build_requirement_index(mapping)

    # Compute coverage
    aiuc1_coverage = compute_aiuc1_coverage(results, req_index)
    owasp_coverage = compute_owasp_coverage(results, req_index)

    # Summary stats
    total_tests = len(results)
    passed = sum(1 for r in results if r.get("passed", False))
    failed = total_tests - passed
    pass_rate = passed / total_tests if total_tests > 0 else 0.0

    timestamp = datetime.now(timezone.utc).isoformat()

    summary = {
        "total_tests": total_tests,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(pass_rate, 4),
        "aiuc1_coverage": {
            "covered": aiuc1_coverage["covered"],
            "total": aiuc1_coverage["total"],
            "gaps": aiuc1_coverage["gaps"],
        },
    }

    # Build JSON artifacts
    test_results_json = json.dumps(report_data, indent=2, default=str)
    aiuc1_mapping_json = json.dumps(aiuc1_coverage, indent=2, default=str)

    # Compute evidence hash over the two JSON payloads
    evidence_hash = compute_evidence_hash(test_results_json, aiuc1_mapping_json)

    # Signing
    attestation: dict[str, Any] = {"signed": False}
    if do_sign:
        sign_key = os.environ.get("AGENT_SECURITY_SIGN_KEY", "")
        if not sign_key:
            sign_key = secrets.token_hex(32)
            key_path = pack_dir / "signing.key"
            with open(key_path, "w") as kf:
                kf.write(sign_key + "\n")
            os.chmod(key_path, 0o600)
            print(
                f"WARNING: Auto-generated signing key saved to {key_path}. "
                "For production use, set AGENT_SECURITY_SIGN_KEY environment variable.",
                file=sys.stderr,
            )
        attestation = sign_evidence(evidence_hash, sign_key)

    # Build evidence-summary.json
    evidence_summary = {
        "schema_version": "1.0.0",
        "generated_at": timestamp,
        "harness_version": HARNESS_VERSION,
        "target": target,
        "evidence_hash": evidence_hash,
        "summary": summary,
        "compliance_mapping": {
            "aiuc1": {
                "covered": aiuc1_coverage["covered"],
                "total": aiuc1_coverage["total"],
                "gaps": aiuc1_coverage["gaps"],
            },
            "owasp_agentic": {
                k: v["status"] for k, v in owasp_coverage.items()
            },
        },
        "attestation": attestation,
    }
    evidence_summary_json = json.dumps(evidence_summary, indent=2, default=str)

    # Generate markdown
    markdown = generate_markdown(
        summary=summary,
        aiuc1=aiuc1_coverage,
        owasp=owasp_coverage,
        target=target,
        timestamp=timestamp,
    )

    # Write output
    pack_dir = Path(output_dir)
    pack_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "evidence-summary.json": evidence_summary_json,
        "test-results.json": test_results_json,
        "aiuc1-mapping.json": aiuc1_mapping_json,
        "evidence-summary.md": markdown,
    }

    for filename, content in files.items():
        filepath = pack_dir / filename
        with open(filepath, "w") as f:
            f.write(content)

    output_path = str(pack_dir)

    if do_zip:
        zip_path = str(pack_dir) + ".zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for filename in files:
                zf.write(pack_dir / filename, filename)
        output_path = zip_path
        print(f"Evidence pack (zip): {zip_path}")
    else:
        print(f"Evidence pack directory: {pack_dir}")

    # Print summary
    print(f"\n{'='*50}")
    print("EVIDENCE PACK SUMMARY")
    print(f"{'='*50}")
    print(f"  Tests:        {total_tests} total, {passed} passed, {failed} failed")
    print(f"  Pass rate:    {pass_rate:.1%}")
    print(f"  AIUC-1:       {aiuc1_coverage['covered']}/{aiuc1_coverage['total']} covered, {aiuc1_coverage['gaps']} gaps")
    print(f"  Signed:       {'Yes' if attestation.get('signed') else 'No'}")
    print(f"  Hash:         {evidence_hash}")
    print(f"{'='*50}")

    return output_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate audit-ready evidence pack from harness test results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate evidence pack from a harness report
    python scripts/evidence_pack.py --report report.json --output evidence/

    # Generate and sign
    python scripts/evidence_pack.py --report report.json --output evidence/ --sign

    # Generate signed zip
    python scripts/evidence_pack.py --report report.json --output evidence/ --sign --zip

    # With explicit target URL
    python scripts/evidence_pack.py --report report.json --target http://localhost:8080/mcp --output evidence/
        """,
    )
    parser.add_argument(
        "--report", required=True, metavar="PATH",
        help="Path to a harness JSON report file",
    )
    parser.add_argument(
        "--target", default="unknown",
        help="Target URL that was tested (default: read from report or 'unknown')",
    )
    parser.add_argument(
        "--output", required=True, metavar="DIR",
        help="Output directory for the evidence pack",
    )
    parser.add_argument(
        "--sign", action="store_true",
        help="Sign the evidence pack with HMAC-SHA256. Uses AGENT_SECURITY_SIGN_KEY env var; "
             "if unset, auto-generates a key and saves it as signing.key in the output directory",
    )
    parser.add_argument(
        "--zip", action="store_true", dest="create_zip",
        help="Produce a .zip file in addition to the directory",
    )
    parser.add_argument(
        "--mapping", default=None, metavar="PATH",
        help="Path to AIUC-1 mapping YAML (default: configs/aiuc1_mapping.yaml)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.report):
        print(f"Error: report file not found: {args.report}", file=sys.stderr)
        sys.exit(1)

    # Try to extract target from report if not explicitly provided
    target = args.target
    if target == "unknown":
        try:
            with open(args.report) as f:
                data = json.load(f)
            target = data.get("target", "unknown")
        except (json.JSONDecodeError, OSError):
            pass

    build_evidence_pack(
        report_path=args.report,
        target=target,
        output_dir=args.output,
        do_sign=args.sign,
        do_zip=args.create_zip,
        mapping_path=args.mapping,
    )


if __name__ == "__main__":
    main()
