#!/usr/bin/env python3
"""Compliance Report Auto-Generation (HTML/PDF)

Generates auditor-ready compliance reports with framework-specific language,
evidence summaries, and gap analysis. Combines AUROC metrics, framework
crosswalks, and FRIA evidence into a single document.

Tracks GitHub issue #160.

Usage:
    python scripts/compliance_report.py --report results.json --output report.html
    python scripts/compliance_report.py --report results.json --output report.html --framework eu-ai-act
    python scripts/compliance_report.py --report results.json --output report.html --framework all --fria
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

# Ensure repo root is importable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)


def _esc(text: Any) -> str:
    return html.escape(str(text))


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _status_badge(status: str) -> str:
    s = status.upper()
    colors = {
        "PASS": ("#dcfce7", "#166534"), "COVERED": ("#dcfce7", "#166534"),
        "FAIL": ("#fee2e2", "#991b1b"), "FLAGGED": ("#fee2e2", "#991b1b"),
        "NON_COMPLIANT": ("#fee2e2", "#991b1b"),
        "GAP": ("#fef3c7", "#92400e"), "INCOMPLETE": ("#fef3c7", "#92400e"),
        "COMPLIANT": ("#dcfce7", "#166534"),
    }
    bg, fg = colors.get(s, ("#f3f4f6", "#6b7280"))
    return (f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;'
            f'font-size:12px;font-weight:600;background:{bg};color:{fg}">{_esc(s)}</span>')


_CSS = """\
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
 color:#1a1a2e;background:#fff;line-height:1.6;font-size:13px}
.container{max-width:900px;margin:0 auto;padding:32px 24px}
h1{font-size:22px;font-weight:700;margin-bottom:4px}
h2{font-size:17px;font-weight:600;margin:28px 0 10px;padding-bottom:6px;border-bottom:2px solid #e0e0e0}
h3{font-size:14px;font-weight:600;margin:16px 0 6px}
.meta{color:#666;font-size:12px;margin-bottom:20px}
.meta span{margin-right:16px}
.card-row{display:flex;gap:14px;flex-wrap:wrap;margin:14px 0}
.card{flex:1;min-width:140px;background:#f8f9fa;border:1px solid #e0e0e0;border-radius:8px;
 padding:14px 16px;text-align:center}
.card .label{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#888;margin-bottom:2px}
.card .value{font-size:24px;font-weight:700}
table{width:100%;border-collapse:collapse;margin:10px 0;border:1px solid #e0e0e0;font-size:12px}
th{background:#f1f5f9;font-weight:600;text-align:left;padding:8px 12px;border-bottom:2px solid #e0e0e0}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0}
tr:hover{background:#f8fafc}
.footer{margin-top:32px;padding-top:12px;border-top:1px solid #e0e0e0;color:#888;font-size:11px;text-align:center}
.narrative{background:#f8f9fa;border-left:3px solid #2563eb;padding:10px 14px;margin:8px 0;font-size:12px}
@media print{body{font-size:11px}.container{max-width:100%;padding:0}}
"""


def generate_compliance_html(
    report_data: dict[str, Any],
    frameworks: list[str] | None = None,
    include_fria: bool = False,
) -> str:
    """Generate a compliance-focused HTML report.

    Args:
        report_data: Harness JSON output.
        frameworks: List of framework IDs to include (eu-ai-act, iso-42001, aiuc-1).
        include_fria: Whether to include FRIA evidence section.

    Returns:
        HTML string.
    """
    results = report_data.get("results", [])
    total = len(results)
    passed = sum(1 for r in results if r.get("passed", False))
    timestamp = report_data.get("timestamp", datetime.now(timezone.utc).isoformat())

    parts: list[str] = []
    parts.append("<!DOCTYPE html><html lang='en'><head>")
    parts.append("<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    parts.append(f"<title>Compliance Report - {_esc(timestamp[:10])}</title>")
    parts.append(f"<style>{_CSS}</style></head><body><div class='container'>")

    # Header
    parts.append("<h1>Agent Security Compliance Report</h1>")
    parts.append(f'<div class="meta"><span>Generated: {_esc(timestamp)}</span>'
                 f'<span>Tests: {total}</span></div>')

    # Executive Summary
    parts.append("<h2>1. Executive Summary</h2>")
    parts.append('<div class="card-row">')
    parts.append(f'<div class="card"><div class="label">Total Tests</div><div class="value" style="color:#2563eb">{total}</div></div>')
    parts.append(f'<div class="card"><div class="label">Passed</div><div class="value" style="color:#16a34a">{passed}</div></div>')
    parts.append(f'<div class="card"><div class="label">Failed</div><div class="value" style="color:{"#dc2626" if total-passed else "#16a34a"}">{total-passed}</div></div>')
    rate = (passed / total * 100) if total else 0
    parts.append(f'<div class="card"><div class="label">Pass Rate</div><div class="value" style="color:{"#16a34a" if rate >= 90 else "#d97706" if rate >= 70 else "#dc2626"}">{rate:.1f}%</div></div>')
    parts.append("</div>")

    # AUROC section
    section_num = 2
    try:
        from scripts.auroc import compute_all_auroc, auroc_label
        auroc = compute_all_auroc(report_data)
        if auroc.get("modules"):
            parts.append(f"<h2>{section_num}. Detection Effectiveness (AUROC)</h2>")
            parts.append("<table><tr><th>Module</th><th>AUROC</th><th>Rating</th></tr>")
            for mod, score in sorted(auroc["modules"].items()):
                parts.append(f"<tr><td>{_esc(mod)}</td><td><strong>{score:.4f}</strong></td>"
                             f"<td>{_esc(auroc_label(score))}</td></tr>")
            parts.append("</table>")
            parts.append(f'<p style="color:#888;font-size:11px">{_esc(auroc.get("methodology", ""))}</p>')
            section_num += 1
    except Exception:
        pass

    # Framework compliance sections
    if frameworks:
        try:
            from scripts.compliance_crosswalk import load_crosswalk, apply_crosswalk
        except ImportError:
            frameworks = []
    for fw in (frameworks or []):
        try:
            crosswalk = load_crosswalk(fw)
            compliance = apply_crosswalk(crosswalk, results)

            parts.append(f"<h2>{section_num}. {_esc(compliance['framework'])} Compliance</h2>")
            parts.append(f"<p>Controls: {compliance['covered']}/{compliance['total_controls']} covered | "
                         f"Gaps: {compliance['gaps']} | Failing: {compliance['failing']} | "
                         f"Rate: {compliance['compliance_rate']*100:.0f}%</p>")

            parts.append("<table><tr><th>Control</th><th>Description</th><th>Section</th>"
                         "<th>Mapped</th><th>Run</th><th>Pass</th><th>Fail</th><th>Status</th></tr>")
            for ctrl in compliance["controls"]:
                parts.append(
                    f"<tr><td><strong>{_esc(ctrl['control_id'])}</strong></td>"
                    f"<td>{_esc(ctrl['description'])}</td>"
                    f"<td>{_esc(ctrl.get('section', ''))}</td>"
                    f"<td>{ctrl.get('tests_mapped', 0)}</td>"
                    f"<td>{ctrl.get('tests_run', 0)}</td>"
                    f"<td>{ctrl.get('passed', 0)}</td>"
                    f"<td>{ctrl.get('failed', 0)}</td>"
                    f"<td>{_status_badge(ctrl['status'])}</td></tr>"
                )
            parts.append("</table>")

            # Gap analysis
            gap_controls = [c for c in compliance["controls"] if c["status"] in ("GAP", "FAIL", "NO_RESULTS")]
            if gap_controls:
                parts.append(f"<h3>Gap Analysis — {_esc(compliance['framework'])}</h3>")
                parts.append("<table><tr><th>Control</th><th>Issue</th><th>Notes</th></tr>")
                for gc in gap_controls:
                    issue = "No tests mapped" if gc["status"] == "GAP" else (
                        "No results" if gc["status"] == "NO_RESULTS" else
                        f"{gc.get('failed', 0)} tests failing"
                    )
                    parts.append(f"<tr><td><strong>{_esc(gc['control_id'])}</strong></td>"
                                 f"<td>{_esc(issue)}</td>"
                                 f"<td>{_esc(gc.get('gap_notes', ''))}</td></tr>")
                parts.append("</table>")

            section_num += 1
        except Exception as e:
            parts.append(f"<p style='color:red'>Error loading {fw}: {_esc(str(e))}</p>")

    # FRIA section
    if include_fria:
        try:
            from scripts.fria_evidence import generate_fria_evidence
            fria = generate_fria_evidence(results)

            parts.append(f"<h2>{section_num}. Fundamental Rights Impact Assessment (FRIA)</h2>")
            parts.append(f"<p>EU AI Act Article 27 | Status: {_status_badge(fria['overall_status'])}</p>")

            summary = fria["summary"]
            parts.append('<div class="card-row">')
            parts.append(f'<div class="card"><div class="label">Covered</div><div class="value" style="color:#16a34a">{summary["covered"]}</div></div>')
            parts.append(f'<div class="card"><div class="label">Flagged</div><div class="value" style="color:#dc2626">{summary["flagged"]}</div></div>')
            parts.append(f'<div class="card"><div class="label">Gaps</div><div class="value" style="color:#d97706">{summary["gaps"]}</div></div>')
            parts.append("</div>")

            for cat_id, cat_data in fria["categories"].items():
                parts.append(f"<h3>{_status_badge(cat_data['status'])} {_esc(cat_data['title'])}</h3>")
                parts.append(f'<div class="narrative">{_esc(cat_data["narrative"])}</div>')
                parts.append(f"<p style='font-size:11px;color:#888'>Tests: {cat_data['passed']}/{cat_data['tests_run']} passing "
                             f"({cat_data['tests_mapped']} mapped)</p>")

            section_num += 1
        except Exception as e:
            parts.append(f"<p style='color:red'>FRIA error: {_esc(str(e))}</p>")

    # Methodology
    parts.append(f"<h2>{section_num}. Methodology</h2>")
    parts.append("<ul>")
    parts.append("<li>Tests are adversarial simulations against the target agent endpoint</li>")
    parts.append("<li>Pass/fail determined by agent response to attack payloads</li>")
    parts.append("<li>Statistical confidence via Wilson score intervals</li>")
    parts.append("<li>AUROC computed from attack detection rate vs. false positive rate</li>")
    parts.append("<li>Framework mappings derived from crosswalk YAML configurations</li>")
    parts.append("</ul>")

    # Footer
    parts.append('<div class="footer">')
    parts.append(f"Generated by Agent Security Harness | {_esc(timestamp)} | "
                 '<a href="https://github.com/msaleme/red-team-blue-team-agent-fabric">'
                 "github.com/msaleme/red-team-blue-team-agent-fabric</a>")
    parts.append("</div></div></body></html>")

    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(
        description="Generate auditor-ready compliance report (HTML)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/compliance_report.py --report results.json --output compliance.html
    python scripts/compliance_report.py --report results.json --output compliance.html --framework eu-ai-act --fria
    python scripts/compliance_report.py --report results.json --output compliance.html --framework all --fria
        """,
    )
    parser.add_argument("--report", required=True, help="Harness JSON report path")
    parser.add_argument("--output", "-o", required=True, help="Output HTML file path")
    parser.add_argument("--framework", action="append", default=[],
                        help="Framework(s) to include (eu-ai-act, iso-42001, aiuc-1, all)")
    parser.add_argument("--fria", action="store_true", help="Include FRIA evidence section")

    args = parser.parse_args()

    report_data = _load_json(args.report)

    # Resolve frameworks
    frameworks = []
    for fw in args.framework:
        if fw == "all":
            frameworks = ["eu-ai-act", "iso-42001", "aiuc-1"]
            break
        frameworks.append(fw)

    html_content = generate_compliance_html(
        report_data,
        frameworks=frameworks or None,
        include_fria=args.fria,
    )

    with open(args.output, "w") as f:
        f.write(html_content)
    print(f"Compliance report written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
