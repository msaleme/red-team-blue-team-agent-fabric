#!/usr/bin/env python3
"""Self-Contained HTML Report Generator for Agent Security Harness

Generates a single HTML file (no external dependencies) from harness JSON
output.  The report is audit-ready and can be shared with auditors,
stakeholders, and procurement teams without reformatting.

Includes:
    - Executive summary with pass/fail, pass rate, risk score
    - Per-module breakdown with expandable details
    - OWASP Agentic Top 10 coverage matrix
    - AIUC-1 requirement mapping status
    - Behavioral drift indicators (when profile data exists)
    - Color-coded pass/fail indicators and status badges

Usage:
    python scripts/html_report.py --report results.json --output report.html
    python scripts/html_report.py --report results.json  # writes to stdout

Requires: Python 3.10+
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

# Ensure repo root is on path so protocol_tests is importable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from protocol_tests.version import get_harness_version

HARNESS_VERSION = get_harness_version()


# ---------------------------------------------------------------------------
# OWASP Agentic Security Initiative categories (shared with evidence_pack.py)
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
# Data helpers
# ---------------------------------------------------------------------------

def _load_report(path: str) -> dict[str, Any]:
    """Load a harness JSON report file."""
    with open(path) as f:
        return json.load(f)


def _try_load_aiuc1_mapping() -> dict[str, Any] | None:
    """Attempt to load the AIUC-1 mapping; return None if unavailable."""
    try:
        import yaml
        mapping_path = os.path.join(REPO_ROOT, "configs", "aiuc1_mapping.yaml")
        with open(mapping_path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _build_requirement_index(mapping: dict[str, Any]) -> dict[str, dict]:
    """Build a flat {req_id: {...}} index from the AIUC-1 mapping."""
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
                "status": req_def.get("status", "UNKNOWN"),
                "gap_notes": req_def.get("gap_notes") or "",
            }
    return index


def _esc(text: Any) -> str:
    """HTML-escape helper."""
    return html.escape(str(text))


# ---------------------------------------------------------------------------
# Computation (mirrors evidence_pack.py logic to stay self-contained)
# ---------------------------------------------------------------------------

def _compute_aiuc1(results: list[dict], req_index: dict[str, dict]) -> dict[str, Any]:
    """Map test results to AIUC-1 requirements."""
    result_by_id = {r.get("test_id", ""): r for r in results if r.get("test_id")}
    coverage: dict[str, Any] = {}
    covered = 0
    gaps = 0

    for req_id, req_def in sorted(req_index.items()):
        test_ids = req_def["test_ids"]
        is_gap = req_def["status"] == "GAP"
        if is_gap or not test_ids:
            coverage[req_id] = {
                "title": req_def["title"], "category": req_def["category"],
                "status": "GAP", "passed": 0, "failed": 0, "total": 0,
                "notes": req_def.get("gap_notes") or "Not yet covered",
            }
            gaps += 1
            continue

        matched = [t for t in test_ids if t in result_by_id]
        if not matched:
            coverage[req_id] = {
                "title": req_def["title"], "category": req_def["category"],
                "status": "NO_RESULTS", "passed": 0, "failed": 0, "total": 0,
            }
            continue

        passed = sum(1 for t in matched if result_by_id[t].get("passed", False))
        failed = len(matched) - passed
        covered += 1
        coverage[req_id] = {
            "title": req_def["title"], "category": req_def["category"],
            "status": "PASS" if failed == 0 else "FAIL",
            "passed": passed, "failed": failed, "total": len(matched),
        }

    return {"covered": covered, "total": len(req_index), "gaps": gaps, "requirements": coverage}


def _compute_owasp(results: list[dict], req_index: dict[str, dict]) -> dict[str, Any]:
    """Map test results to OWASP Agentic categories."""
    asi_tests: dict[str, list[str]] = {}
    for req_def in req_index.values():
        asi = req_def.get("owasp_asi", "")
        if asi:
            for tid in req_def["test_ids"]:
                asi_tests.setdefault(asi, [])
                if tid not in asi_tests[asi]:
                    asi_tests[asi].append(tid)

    result_by_id = {r.get("test_id", ""): r for r in results if r.get("test_id")}
    owasp: dict[str, Any] = {}
    for asi_id, asi_name in OWASP_AGENTIC_CATEGORIES.items():
        test_ids = asi_tests.get(asi_id, [])
        matched = [t for t in test_ids if t in result_by_id]
        passed = sum(1 for t in matched if result_by_id[t].get("passed", False))
        failed = len(matched) - passed
        if matched and failed == 0:
            status = "PASS"
        elif failed > 0:
            status = "FAIL"
        else:
            status = "NOT_TESTED"
        owasp[asi_id] = {
            "name": asi_name, "tests_mapped": len(test_ids),
            "tests_run": len(matched), "passed": passed, "failed": failed,
            "status": status,
        }
    return owasp


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

_CSS = """\
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
 color:#1a1a2e;background:#f8f9fa;line-height:1.6;font-size:14px}
.container{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:24px;font-weight:700;margin-bottom:4px}
h2{font-size:18px;font-weight:600;margin:32px 0 12px;padding-bottom:8px;border-bottom:2px solid #e0e0e0}
h3{font-size:15px;font-weight:600;margin:20px 0 8px}
.meta{color:#666;font-size:13px;margin-bottom:24px}
.meta span{margin-right:18px}

/* Cards */
.card-row{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}
.card{flex:1;min-width:160px;background:#fff;border:1px solid #e0e0e0;border-radius:8px;
 padding:16px 20px;text-align:center}
.card .label{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:#888;margin-bottom:4px}
.card .value{font-size:28px;font-weight:700}
.card .value.green{color:#16a34a}
.card .value.red{color:#dc2626}
.card .value.amber{color:#d97706}
.card .value.blue{color:#2563eb}

/* Badges */
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;
 text-transform:uppercase;letter-spacing:.3px}
.badge-pass{background:#dcfce7;color:#166534}
.badge-fail{background:#fee2e2;color:#991b1b}
.badge-gap{background:#fef3c7;color:#92400e}
.badge-na{background:#f3f4f6;color:#6b7280}

/* Tables */
table{width:100%;border-collapse:collapse;margin:12px 0;background:#fff;border-radius:8px;
 overflow:hidden;border:1px solid #e0e0e0}
th{background:#f1f5f9;font-weight:600;text-align:left;padding:10px 14px;font-size:13px;
 border-bottom:2px solid #e0e0e0}
td{padding:10px 14px;border-bottom:1px solid #f0f0f0;font-size:13px}
tr:last-child td{border-bottom:none}
tr:hover{background:#f8fafc}

/* Collapsible sections */
details{margin:8px 0}
summary{cursor:pointer;padding:10px 14px;background:#f8f9fa;border:1px solid #e0e0e0;
 border-radius:6px;font-weight:600;font-size:13px;user-select:none}
summary:hover{background:#eef2f7}
details[open] summary{border-radius:6px 6px 0 0;border-bottom:none}
details .inner{border:1px solid #e0e0e0;border-top:none;border-radius:0 0 6px 6px;
 padding:12px 14px;background:#fff}

/* Risk gauge */
.risk-bar{height:10px;background:#e5e7eb;border-radius:5px;overflow:hidden;margin:6px 0}
.risk-bar .fill{height:100%;border-radius:5px;transition:width .3s}
.risk-low .fill{background:#16a34a}
.risk-med .fill{background:#d97706}
.risk-high .fill{background:#ea580c}
.risk-crit .fill{background:#dc2626}

/* Drift section */
.drift-indicator{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
.drift-regression{background:#dc2626}
.drift-improvement{background:#16a34a}
.drift-stable{background:#9ca3af}

/* Footer */
.footer{margin-top:40px;padding-top:16px;border-top:1px solid #e0e0e0;
 color:#888;font-size:12px;text-align:center}

/* Print */
@media print{
 body{background:#fff;font-size:12px}
 .container{max-width:100%;padding:0}
 details[open] summary~*{display:block!important}
 .card{border:1px solid #ccc}
}
"""

_JS = """\
// Toggle all details sections
function toggleAll(open){
  document.querySelectorAll('details').forEach(d=>d.open=open);
}
"""


def _status_badge(status: str) -> str:
    """Return an HTML badge span for a status string."""
    s = status.upper()
    if s == "PASS":
        return '<span class="badge badge-pass">PASS</span>'
    if s == "FAIL":
        return '<span class="badge badge-fail">FAIL</span>'
    if s == "GAP":
        return '<span class="badge badge-gap">GAP</span>'
    return f'<span class="badge badge-na">{_esc(s)}</span>'


def _risk_class(score: float) -> str:
    if score >= 60:
        return "risk-crit"
    if score >= 40:
        return "risk-high"
    if score >= 20:
        return "risk-med"
    return "risk-low"


def _risk_label(score: float) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def generate_html(report_data: dict[str, Any]) -> str:
    """Generate a self-contained HTML report string from harness JSON output."""
    results = report_data.get("results", [])
    total = len(results)
    passed = sum(1 for r in results if r.get("passed", False))
    failed = total - passed
    pass_rate = (passed / total * 100) if total else 0.0

    target = report_data.get("target", "unknown")
    timestamp = report_data.get("timestamp", datetime.now(timezone.utc).isoformat())

    # Risk score: use from report if present, else compute simple estimate
    risk_data = report_data.get("risk", {})
    risk_score = risk_data.get("score", round((failed / total * 40) if total else 0, 2))

    # AIUC-1 and OWASP coverage
    mapping = _try_load_aiuc1_mapping()
    req_index = _build_requirement_index(mapping) if mapping else {}
    aiuc1 = _compute_aiuc1(results, req_index) if req_index else None
    owasp = _compute_owasp(results, req_index) if req_index else None

    # Behavioral profile data (may be embedded in report)
    drift_data = report_data.get("behavioral_profile", report_data.get("drift", None))

    # Group results by module/category
    modules: dict[str, list[dict]] = {}
    for r in results:
        mod = r.get("module", r.get("category", "General"))
        modules.setdefault(mod, []).append(r)

    # --- Build HTML ---
    parts: list[str] = []

    # Head
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="UTF-8">')
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append(f"<title>Agent Security Harness Report - {_esc(timestamp[:10])}</title>")
    parts.append(f"<style>{_CSS}</style>")
    parts.append(f"<script>{_JS}</script>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append('<div class="container">')

    # Header
    parts.append("<h1>Agent Security Harness Report</h1>")
    parts.append('<div class="meta">')
    parts.append(f'<span>Generated: {_esc(timestamp)}</span>')
    parts.append(f'<span>Harness: v{_esc(HARNESS_VERSION)}</span>')
    parts.append(f'<span>Target: {_esc(target)}</span>')
    parts.append("</div>")

    # --- Executive Summary Cards ---
    parts.append("<h2>Executive Summary</h2>")
    parts.append('<div class="card-row">')

    parts.append('<div class="card">')
    parts.append('<div class="label">Total Tests</div>')
    parts.append(f'<div class="value blue">{total}</div>')
    parts.append("</div>")

    parts.append('<div class="card">')
    parts.append('<div class="label">Passed</div>')
    parts.append(f'<div class="value green">{passed}</div>')
    parts.append("</div>")

    parts.append('<div class="card">')
    parts.append('<div class="label">Failed</div>')
    parts.append(f'<div class="value {"red" if failed else "green"}">{failed}</div>')
    parts.append("</div>")

    parts.append('<div class="card">')
    parts.append('<div class="label">Pass Rate</div>')
    rate_class = "green" if pass_rate >= 90 else ("amber" if pass_rate >= 70 else "red")
    parts.append(f'<div class="value {rate_class}">{pass_rate:.1f}%</div>')
    parts.append("</div>")

    parts.append('<div class="card">')
    parts.append('<div class="label">Risk Score</div>')
    rc = "green" if risk_score < 20 else ("amber" if risk_score < 40 else "red")
    parts.append(f'<div class="value {rc}">{risk_score:.1f}</div>')
    parts.append(f'<div class="risk-bar {_risk_class(risk_score)}">')
    parts.append(f'<div class="fill" style="width:{min(risk_score, 100):.0f}%"></div>')
    parts.append("</div>")
    parts.append(f'<div class="label">{_risk_label(risk_score)}</div>')
    parts.append("</div>")

    parts.append("</div>")  # card-row

    # --- Per-Module Breakdown ---
    parts.append("<h2>Per-Module Breakdown</h2>")
    parts.append(
        '<p style="margin-bottom:8px">'
        '<button onclick="toggleAll(true)" style="margin-right:8px;cursor:pointer">Expand All</button>'
        '<button onclick="toggleAll(false)" style="cursor:pointer">Collapse All</button></p>'
    )

    for mod_name, mod_results in sorted(modules.items()):
        mod_passed = sum(1 for r in mod_results if r.get("passed", False))
        mod_failed = len(mod_results) - mod_passed
        mod_status = "PASS" if mod_failed == 0 else "FAIL"

        parts.append("<details>")
        parts.append(
            f"<summary>{_status_badge(mod_status)} "
            f"<span style='margin-left:8px'>{_esc(mod_name)}</span> "
            f"<span style='color:#888;font-weight:400;margin-left:8px'>"
            f"{mod_passed}/{len(mod_results)} passed</span></summary>"
        )
        parts.append('<div class="inner">')
        parts.append("<table>")
        parts.append("<tr><th>Test ID</th><th>Name</th><th>Severity</th><th>Status</th><th>Details</th></tr>")

        for r in mod_results:
            tid = _esc(r.get("test_id", ""))
            name = _esc(r.get("name", r.get("test_name", tid)))
            severity = _esc(r.get("severity", ""))
            is_pass = r.get("passed", False)
            status_badge = _status_badge("PASS" if is_pass else "FAIL")
            detail = _esc(r.get("details", r.get("detail", r.get("error", r.get("reason", "")))))
            parts.append(
                f"<tr><td><code>{tid}</code></td><td>{name}</td>"
                f"<td>{severity}</td><td>{status_badge}</td>"
                f"<td style='max-width:300px;word-break:break-word'>{detail}</td></tr>"
            )

        parts.append("</table>")
        parts.append("</div>")  # inner
        parts.append("</details>")

    # --- OWASP Agentic Top 10 Coverage ---
    if owasp:
        parts.append("<h2>OWASP Agentic Top 10 Coverage</h2>")
        parts.append("<table>")
        parts.append("<tr><th>ID</th><th>Category</th><th>Mapped</th>"
                     "<th>Run</th><th>Passed</th><th>Failed</th><th>Status</th></tr>")
        for asi_id, asi_data in sorted(owasp.items()):
            parts.append(
                f"<tr><td><strong>{_esc(asi_id)}</strong></td>"
                f"<td>{_esc(asi_data['name'])}</td>"
                f"<td>{asi_data['tests_mapped']}</td>"
                f"<td>{asi_data['tests_run']}</td>"
                f"<td>{asi_data['passed']}</td>"
                f"<td>{asi_data['failed']}</td>"
                f"<td>{_status_badge(asi_data['status'])}</td></tr>"
            )
        parts.append("</table>")

    # --- AIUC-1 Requirement Mapping ---
    if aiuc1:
        reqs = aiuc1.get("requirements", {})
        parts.append("<h2>AIUC-1 Requirement Mapping</h2>")
        parts.append(
            f'<p>Coverage: <strong>{aiuc1["covered"]}/{aiuc1["total"]}</strong> requirements '
            f'| Gaps: <strong>{aiuc1["gaps"]}</strong></p>'
        )
        parts.append("<table>")
        parts.append("<tr><th>Requirement</th><th>Title</th><th>Category</th>"
                     "<th>Passed</th><th>Failed</th><th>Status</th></tr>")
        for req_id, rd in sorted(reqs.items()):
            notes = rd.get("notes", "")
            title_text = _esc(rd["title"])
            if notes:
                title_text += f' <span style="color:#888;font-size:12px">({_esc(notes)})</span>'
            parts.append(
                f"<tr><td><strong>{_esc(req_id)}</strong></td>"
                f"<td>{title_text}</td>"
                f"<td>{_esc(rd['category'])}</td>"
                f"<td>{rd.get('passed', 0)}</td>"
                f"<td>{rd.get('failed', 0)}</td>"
                f"<td>{_status_badge(rd['status'])}</td></tr>"
            )
        parts.append("</table>")

    # --- Behavioral Drift Indicators ---
    if drift_data:
        parts.append("<h2>Behavioral Drift Indicators</h2>")

        # Support both profile shapes: top-level drift or nested structure
        drift_events = []
        stability_score = None
        drift_risk_score = None

        if isinstance(drift_data, dict):
            drift_events = drift_data.get("events", drift_data.get("drift", {}).get("events", []))
            stab = drift_data.get("stability", {})
            stability_score = stab.get("score") if isinstance(stab, dict) else None
            risk = drift_data.get("risk", {})
            drift_risk_score = risk.get("score") if isinstance(risk, dict) else None

        if stability_score is not None or drift_risk_score is not None:
            parts.append('<div class="card-row">')
            if stability_score is not None:
                sc = "green" if stability_score >= 90 else ("amber" if stability_score >= 70 else "red")
                parts.append(f'<div class="card"><div class="label">Stability</div>'
                             f'<div class="value {sc}">{stability_score:.1f}</div></div>')
            if drift_risk_score is not None:
                rc = "green" if drift_risk_score < 20 else ("amber" if drift_risk_score < 40 else "red")
                parts.append(f'<div class="card"><div class="label">Drift Risk</div>'
                             f'<div class="value {rc}">{drift_risk_score:.1f}</div></div>')
            parts.append("</div>")

        if drift_events:
            regressions = [d for d in drift_events if d.get("category") == "regression"]
            improvements = [d for d in drift_events if d.get("category") == "improvement"]

            parts.append(f"<p>Drift events: <strong>{len(drift_events)}</strong> "
                         f"({len(regressions)} regressions, {len(improvements)} improvements)</p>")
            parts.append("<table>")
            parts.append("<tr><th>Test</th><th>Previous</th><th>Current</th>"
                         "<th>Severity</th><th>Category</th></tr>")
            for d in drift_events:
                cat = d.get("category", "")
                indicator_class = "drift-regression" if cat == "regression" else (
                    "drift-improvement" if cat == "improvement" else "drift-stable"
                )
                parts.append(
                    f"<tr><td><span class='drift-indicator {indicator_class}'></span>"
                    f"{_esc(d.get('test_id', ''))}</td>"
                    f"<td>{_esc(d.get('old_result', ''))}</td>"
                    f"<td>{_esc(d.get('new_result', ''))}</td>"
                    f"<td>{_esc(d.get('severity', ''))}</td>"
                    f"<td>{_esc(cat)}</td></tr>"
                )
            parts.append("</table>")
        elif not (stability_score or drift_risk_score):
            parts.append('<p style="color:#888">No behavioral profile data available for this report.</p>')

    # --- AUROC Per-Module (issue #155) ---
    auroc_data = report_data.get("auroc")
    if not auroc_data:
        # Compute on the fly if not pre-embedded
        try:
            from scripts.auroc import compute_all_auroc, auroc_color, auroc_label
            auroc_data = compute_all_auroc(report_data)
        except Exception:
            auroc_data = None

    if auroc_data and auroc_data.get("modules"):
        parts.append("<h2>AUROC — Detection Effectiveness</h2>")
        overall = auroc_data.get("overall", 0.5)
        try:
            from scripts.auroc import auroc_color as _ac, auroc_label as _al
            oc = _ac(overall)
            ol = _al(overall)
        except Exception:
            oc = "blue"
            ol = ""
        parts.append(f'<p>Overall AUROC: <strong class="{oc}">{overall:.4f}</strong> ({ol})'
                     f' | Attack tests: {auroc_data.get("attack_tests_total", "?")} |'
                     f' FPR tests: {auroc_data.get("fpr_tests_total", "?")}</p>')
        parts.append("<table>")
        parts.append("<tr><th>Module</th><th>AUROC</th><th>Rating</th></tr>")
        for mod_name, score in sorted(auroc_data["modules"].items()):
            try:
                color = _ac(score)
                label = _al(score)
            except Exception:
                color, label = "blue", ""
            parts.append(
                f'<tr><td>{_esc(mod_name)}</td>'
                f'<td><strong style="color:{"#16a34a" if color == "green" else "#d97706" if color == "amber" else "#dc2626"}">'
                f'{score:.4f}</strong></td>'
                f'<td>{_esc(label)}</td></tr>'
            )
        parts.append("</table>")
        meth = auroc_data.get("methodology", "")
        if meth:
            parts.append(f'<p style="color:#888;font-size:12px;margin-top:8px">{_esc(meth)}</p>')

    # --- Statistical Summary (if multi-trial) ---
    stat_summary = report_data.get("statistical_summary")
    if stat_summary:
        parts.append("<h2>Statistical Summary</h2>")
        parts.append("<table>")
        parts.append("<tr><th>Metric</th><th>Value</th></tr>")
        for key, val in stat_summary.items():
            parts.append(f"<tr><td>{_esc(key)}</td><td>{_esc(val)}</td></tr>")
        parts.append("</table>")

    # --- Footer ---
    parts.append('<div class="footer">')
    parts.append(
        f"Generated by Agent Security Harness v{_esc(HARNESS_VERSION)} | "
        f"{_esc(timestamp)} | "
        '<a href="https://github.com/msaleme/red-team-blue-team-agent-fabric">'
        "github.com/msaleme/red-team-blue-team-agent-fabric</a>"
    )
    parts.append("</div>")

    parts.append("</div>")  # container
    parts.append("</body>")
    parts.append("</html>")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a self-contained HTML report from harness JSON output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/html_report.py --report results.json --output report.html
    python scripts/html_report.py --report results.json  # writes to stdout
        """,
    )
    parser.add_argument(
        "--report", required=True, metavar="PATH",
        help="Path to a harness JSON report file",
    )
    parser.add_argument(
        "--output", "-o", metavar="PATH",
        help="Output HTML file path (default: stdout)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.report):
        print(f"Error: report file not found: {args.report}", file=sys.stderr)
        sys.exit(1)

    report_data = _load_report(args.report)
    html_content = generate_html(report_data)

    if args.output:
        with open(args.output, "w") as f:
            f.write(html_content)
        print(f"HTML report written to {args.output}", file=sys.stderr)
    else:
        print(html_content)


if __name__ == "__main__":
    main()
