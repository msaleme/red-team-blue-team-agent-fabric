"""Shared result type and recording base for test harnesses.

## Why this exists

This package had 45 result dataclasses in 31 distinct field signatures, and 43
separate ``_record`` implementations of one concept: *record a verdict about a
response*. That is the direct cause of #348, #350 and #351 rather than a matter
of taste. When a defect was found in the verdict logic it had 43 possible homes,
and each repair reached only the ones someone thought to open, so the same bug
was fixed in v4.13.1, again in #348, again in #350 and again in #351.

The package already knows the right shape. ``ExtAdapter``,
``EnterprisePlatformAdapter``, ``CloudAgentAdapter`` and ``FrameworkAdapter``
each give one ``_record`` to 5-11 subclasses, which is exactly why guarding
those modules was a one-line change while guarding the five standalone harnesses
in #348 took five separate edits. The pattern is right where it is applied and
absent everywhere else.

## What this does NOT do

It does not migrate the 43. Collapsing them in one change would be a large edit
to a package with roughly 705 downloads a month, and the #351 sweep is evidence
against that approach: a careful bulk application of a *one-line* guard turned 25
correct passes into failures and had to be reverted across fourteen of them.

So this is additive. New harnesses inherit it; existing ones are grandfathered in
``testing/test_harness_base_adoption.py`` and migrate when they are touched for
other reasons. The grandfather list may shrink and must never grow.

## Field selection

Not invented. Measured across all 45 existing result classes:

    test_id   44/45     elapsed_s          42/45      category  32/45
    name      43/45     request_sent       35/45      stride    16/45
    owasp_asi 43/45     response_received  35/45      protocol  14/45
    severity  43/45     timestamp          34/45
    passed    43/45
    details   43/45

The six universal fields are required. Everything a majority declares is
optional with a default, so a subclass can add its own fields without fighting
the base.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from typing import Any

from protocol_tests.http_helpers import (
    INCONCLUSIVE_PREFIX,
    REFERENCE_VERDICT_SCOPE,
    SIMULATED_ROW_SCOPE,
    inconclusive_detail,
    is_inconclusive,
    live_run_scope,
    run_summary,
)


@dataclass
class HarnessResult:
    """The result shape 43 of 45 existing result classes already converge on.

    Subclass it to add harness-specific fields rather than starting a 46th
    parallel definition::

        @dataclass
        class MyHarnessResult(HarnessResult):
            mcp_method: str = ""
    """

    test_id: str
    name: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str

    category: str = ""
    stride: str = ""
    protocol: str = ""
    endpoint: str = ""
    request_sent: dict | None = None
    response_received: dict | None = None
    elapsed_s: float = 0.0
    timestamp: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    #: INCONCLUSIVE as a field, not only as a prefix on ``details``
    #: (http_helpers.INCONCLUSIVE_FIELDS). ``asdict()`` serialises declared
    #: fields; it does not serialise English. The base result carries it so a
    #: subclass cannot be inconclusive without saying so structurally.
    not_evaluated: bool = False

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if is_inconclusive(self.details):
            self.not_evaluated = True


class RecordingHarness:
    """Base for any harness that records a verdict about a target response.

    Supplies the one behaviour that had to be retrofitted four times: a result
    whose target never serviced the request is INCONCLUSIVE, never a pass. A
    subclass cannot forget a guard it never has to call.

    Subclasses that need their own ``_record`` behaviour should call
    ``super()._record(result)`` rather than reimplementing it. Overriding it
    without that call reintroduces exactly the defect this class exists to
    prevent, and ``testing/test_harness_base_adoption.py`` checks for it.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if not hasattr(self, "results"):
            self.results: list[Any] = []

    def _record(self, result: Any) -> Any:
        """Append a result, downgrading it to INCONCLUSIVE if unserviced."""
        self.results.append(result)
        detail = inconclusive_detail(
            getattr(result, "response_received", None),
            getattr(result, "details", None),
        )
        if detail is not None:
            result.passed = False
            result.details = detail
        return result


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------
#
# Six harnesses that handle ``--simulate`` natively (the five payment
# conformance suites and aiuc1_compliance) each assembled and wrote their own
# report dict. Five of them wrote every simulated row as ``passed: true`` with a
# serviced denominator and a Wilson interval, and the sixth wrote rows marked
# INCONCLUSIVE under a summary that said ``failed: 12`` -- two answers in one
# file. The CLI facade (`cli._simulate_harness`) intercepts ``--simulate`` and
# was correct, so the tests that existed covered the facade and not the module
# entry points a consumer can run directly (fourth external review, R4-05,
# 2026-09-08). That is CLAUDE.md item 7 one layer up: six writers, one defect,
# each repair reaching only the file someone opened. This is the one writer.


def simulated_row(row: dict) -> dict:
    """The published form of one row from a simulated (fabricated-answer) run.

    A simulated row is INCONCLUSIVE by construction: the module authored the
    target's answer, so a check against it establishes nothing about a target.
    The fabricated outcome is kept apart under ``reference_verdict`` with its
    scope, ``passed`` is false, and the row carries the structural marker
    (``not_evaluated``, http_helpers.INCONCLUSIVE_FIELDS) plus the two row-level
    labels a row consumer already knows from the reference self-test modules
    (``simulated``, ``verdict_scope``). A consumer that reads only ``passed``
    sees no pass; one that reads the shared predicate sees INCONCLUSIVE; one
    that looks for the reference verdict finds it labelled.
    """
    row = dict(row)
    if row.get("reference_verdict") is None:
        row["reference_verdict"] = {
            "passed": bool(row.get("passed", False)),
            "reason": str(row.get("details", "")),
            "scope": REFERENCE_VERDICT_SCOPE,
        }
    details = str(row.get("details", "") or "")
    if not details.startswith(INCONCLUSIVE_PREFIX):
        row["details"] = (f"{INCONCLUSIVE_PREFIX}simulated run ({SIMULATED_ROW_SCOPE}): "
                          f"no target was contacted, so this control was not "
                          f"exercised. Reference-model verdict preserved under "
                          f"reference_verdict and not scored: {details}")
    row["passed"] = False
    row["not_evaluated"] = True
    row["simulated"] = True
    row["verdict_scope"] = SIMULATED_ROW_SCOPE
    return row


def report_rows(results, *, simulate: bool) -> list[dict]:
    """Serialise result objects for a report; label every row of a simulated run."""
    rows = [asdict(r) if is_dataclass(r) else dict(r) for r in results]
    if simulate:
        rows = [simulated_row(r) for r in rows]
    return rows


def build_report(results, *, simulate: bool, target: str | None,
                 head: dict, tail: dict | None = None,
                 live_scope: bool = True) -> dict:
    """Assemble a report: ``head`` keys, ``verdict_scope``, ``summary``, ``results``, ``tail``.

    ``summary`` is the shared three-state `run_summary`, computed over the rows
    exactly as written, so the summary and the rows in one file cannot disagree:
    a simulated run reports ``serviced 0``, ``pass_rate None`` and no interval.
    ``verdict_scope`` is `live_run_scope`, the report-level statement of what
    was REACHED beside ``mode``, which says what was REQUESTED; ``live_scope``
    is false for a module whose live rows carry no ``live_evidence`` verdict
    (aiuc1_compliance), which then states a scope only for a simulated run.
    """
    rows = report_rows(results, simulate=simulate)
    report = dict(head)
    if simulate or live_scope:
        report["verdict_scope"] = live_run_scope(
            rows, live_requested=not simulate, target=target)
    report["summary"] = run_summary(rows)
    report["results"] = rows
    report.update(tail or {})
    return report


def write_report(report: dict, path: str | None, *, json_stdout: bool = False,
                 quiet: bool = False) -> None:
    """Print the report to stdout when asked, and write it to ``path`` when given."""
    if json_stdout:
        print(json.dumps(report, indent=2, default=str))
    if path:
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        if not quiet:
            print(f"Report written to {path}", file=sys.stderr)


def exit_status(report: dict) -> int:
    """1 when a serviced test FAILED, else 0.

    INCONCLUSIVE is not a failure: a fail asserts the control did not hold, and
    an unserviced or simulated row asserts nothing. ap2 and x402_fireblocks used
    ``any(not r.passed ...)``, which made a wholly-inconclusive run exit 1;
    ucp_acp, card_token and settlement_finality never set an exit status at all.
    One rule now.
    """
    return 1 if report["summary"]["failed"] else 0
