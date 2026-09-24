"""CI gate over a written harness report: the GitHub Action's counts and threshold.

The Action (``action.yml``) and the reusable workflow
(``.github/workflows/security-scan.yml``) used to parse the report inline and
count ``critical_failures`` as rows with ``status == "FAIL"`` and
``severity.lower() == "critical"``. No harness report row carries a ``status``
field (the outcome is ``passed`` plus ``not_evaluated`` / ``informational`` /
the ``INCONCLUSIVE - `` detail prefix), and the MCP harness writes severity as
``"P0-Critical"``. So ``fail_on: critical``, the default, could never fire.

This module is the replacement, and it does not classify anything itself:
each row goes through `http_helpers.row_outcome`, the same function
`run_summary` counts with, so the harness summary and the CI gate cannot
disagree about what a FAIL is. A row is a FAIL only when it failed and is not
INCONCLUSIVE / NOT_EXECUTED.

Usage (what the Action runs)::

    python -m protocol_tests.report_gate summarize REPORT [--summary-file F]
    python -m protocol_tests.report_gate gate REPORT --fail-on {any,critical,none}

``summarize`` appends ``total_tests``, ``passed``, ``failed``, ``inconclusive``
and ``critical_failures`` to ``$GITHUB_OUTPUT`` and a table to
``$GITHUB_STEP_SUMMARY`` (each only when the variable is set). ``gate`` exits 1
when the threshold is breached, 0 otherwise. Stdlib only, so the Action can
import it from its own checkout without installing anything.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from enum import Enum

from protocol_tests.http_helpers import (
    OUTCOME_FAIL,
    row_field,
    row_outcome,
    run_summary,
)

FAIL_ON_CHOICES = ("any", "critical", "none")


def report_rows(report: dict) -> list:
    """Every result row in a written report, whichever writer produced it.

    Single run and ``--trials`` reports keep rows under ``results``. The MCP
    ``--protocol-version differential`` report has none at top level; its rows
    are under ``legacy.results`` and ``modern.results``, and both runs count.
    """
    rows = report.get("results")
    if isinstance(rows, list):
        return rows
    combined = []
    for key in ("legacy", "modern"):
        sub = report.get(key)
        if isinstance(sub, dict) and isinstance(sub.get("results"), list):
            combined.extend(sub["results"])
    return combined


def is_critical(row) -> bool:
    """True when a row's severity is critical.

    Harnesses write severity in three spellings: ``"P0-Critical"`` (the
    `Severity` enums, most modules), ``"critical"`` and ``"CRITICAL"``. All
    three are critical here; ``P0`` is the priority those enums pair with
    critical. A row with no severity field is not critical: it still counts
    for ``fail_on: any``, never for ``fail_on: critical``.
    """
    sev = row_field(row, "severity")
    if isinstance(sev, Enum):
        sev = sev.value
    tokens = re.split(r"[^a-z0-9]+", str(sev or "").strip().lower())
    return "critical" in tokens or "p0" in tokens


def gate_counts(report: dict) -> dict:
    """The Action's counts for one report. `failed` / `inconclusive` are run_summary's."""
    rows = report_rows(report)
    # `--trials` reports are written with `json.dump(..., default=str)` over
    # result objects, so each row lands as its repr string. Such a row has no
    # readable outcome; classifying it at all would be a guess, so the gate
    # refuses the report rather than count it either way.
    bad = [i for i, r in enumerate(rows) if not isinstance(r, dict)]
    if bad:
        raise ValueError(f"{len(bad)} result row(s) are not JSON objects (first: index "
                         f"{bad[0]}); the report cannot be classified")
    summary = run_summary(rows)
    fails = [r for r in rows if row_outcome(r) == OUTCOME_FAIL]
    return {
        "total_tests": summary["total"],
        "passed": summary["passed"],
        "failed": summary["failed"],
        "inconclusive": summary["inconclusive"],
        "critical_failures": sum(1 for r in fails if is_critical(r)),
        "fail_rows": fails,
        "error": report.get("error"),
    }


def threshold_breached(counts: dict, fail_on: str) -> str | None:
    """The error message when `fail_on` is breached, else None.

    INCONCLUSIVE rows never breach any threshold: they are neither passes nor
    failures. They are reported in the ``inconclusive`` output instead.
    """
    if fail_on not in FAIL_ON_CHOICES:
        raise ValueError(f"fail_on must be one of {', '.join(FAIL_ON_CHOICES)}; got {fail_on!r}")
    if fail_on == "any" and counts["failed"] > 0:
        return f"{counts['failed']} test(s) failed (fail_on=any)"
    if fail_on == "critical" and counts["critical_failures"] > 0:
        return f"{counts['critical_failures']} critical test(s) failed (fail_on=critical)"
    return None


def _cell(value, limit: int | None = None) -> str:
    text = " ".join(str(value or "").split()).replace("|", "\\|")
    return text[:limit] if limit else text


def summary_markdown(counts: dict) -> str:
    lines = [
        "### Security Harness Results\n",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total Tests | {counts['total_tests']} |",
        f"| Passed | {counts['passed']} |",
        f"| Failed | {counts['failed']} |",
        f"| Critical Failures | {counts['critical_failures']} |",
        f"| Inconclusive (not counted as failures) | {counts['inconclusive']} |",
        "",
    ]
    if counts.get("error"):
        lines += [f"Run error: {_cell(counts['error'], 200)}", ""]
    if counts["fail_rows"]:
        lines += ["| Test | Severity | Details |", "|------|----------|---------|"]
        for r in counts["fail_rows"]:
            name = row_field(r, "test_id") or row_field(r, "name") or "unknown"
            detail = (row_field(r, "details") or row_field(r, "detail")
                      or row_field(r, "message") or "")
            lines.append(f"| {_cell(name)} | {_cell(row_field(r, 'severity') or 'unknown')} "
                         f"| {_cell(detail, 80)} |")
        lines.append("")
    return "\n".join(lines)


def _append(path: str | None, text: str) -> None:
    if path:
        with open(path, "a") as f:
            f.write(text)


def _load(path: str) -> dict:
    with open(path) as f:
        report = json.load(f)
    if not isinstance(report, dict):
        raise ValueError("report is not a JSON object")
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m protocol_tests.report_gate",
                                 description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("summarize", help="write counts to $GITHUB_OUTPUT and a step summary")
    s.add_argument("report")
    s.add_argument("--summary-file", help="also write the markdown summary to this file")
    g = sub.add_parser("gate", help="exit 1 when the fail_on threshold is breached")
    g.add_argument("report")
    g.add_argument("--fail-on", required=True)
    args = ap.parse_args(argv)

    gh_output = os.environ.get("GITHUB_OUTPUT")
    try:
        counts = gate_counts(_load(args.report))
    except (OSError, ValueError) as exc:
        print(f"::error::Security report unreadable at {args.report}: {exc}")
        if args.cmd == "summarize":
            _append(gh_output, "".join(f"{k}=0\n" for k in (
                "total_tests", "passed", "failed", "inconclusive", "critical_failures")))
        return 1

    if args.cmd == "summarize":
        _append(gh_output, "".join(f"{k}={counts[k]}\n" for k in (
            "total_tests", "passed", "failed", "inconclusive", "critical_failures")))
        md = summary_markdown(counts)
        _append(os.environ.get("GITHUB_STEP_SUMMARY"), md)
        if args.summary_file:
            with open(args.summary_file, "w") as f:
                f.write(md)
        print(md)
        return 0

    try:
        breach = threshold_breached(counts, args.fail_on)
    except ValueError as exc:
        print(f"::error::{exc}")
        return 1
    if breach:
        print(f"::error::{breach}")
        return 1
    if counts["inconclusive"]:
        print(f"::warning::{counts['inconclusive']} test(s) INCONCLUSIVE; not counted as "
              f"failures (fail_on={args.fail_on})")
    print(f"Security scan passed threshold (fail_on={args.fail_on})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
