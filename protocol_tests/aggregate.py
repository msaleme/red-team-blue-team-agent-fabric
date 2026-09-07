"""One aggregate-state rule for a set of test rows mapped to a requirement.

Two consumers -- `scripts/evidence_pack.py` and `scripts/html_report.py` --
each folded a requirement's mapped tests into a status with their own rule,
for AIUC-1 and again for OWASP. Four rules, and none of them had a word for
"one member passed, the other four established nothing". The evidence pack's
rule was `FAIL if failed; INCONCLUSIVE if passed == 0; PARTIAL if a mapped
test was absent; else PASS`, which called a requirement PASS on 1 PASS + 4
INCONCLUSIVE because every member was *present*. The HTML renderer had no
PARTIAL at all: 2 of 5 present and both green rendered PASS. Found by the
third external review (2026-09-07, R3-03).

The rule, in order:

  FAIL          any present member failed. Nothing masks a real failure.
  <absent>      nothing present (NOT_TESTED for OWASP, NO_RESULTS for AIUC-1;
                the consumers' existing vocabularies are kept).
  PASS          every mapped member is present AND established-passing.
  PARTIAL       at least one member passed, but at least one other is absent
                from the report OR is inconclusive. The row says which, by ID.
  INCONCLUSIVE  members are present, none passed, none failed: everything
                that ran established nothing.

A PASS therefore asserts that every test mapped to the requirement ran and
held. Anything less says so, and says what is missing.

Rows are dicts from a JSON report. INCONCLUSIVE is decided by the one
predicate (`http_helpers.is_inconclusive`), never by `passed` alone: a row
with `passed: False` and `not_evaluated: True` is inconclusive, not failed.
"""
from __future__ import annotations

from typing import Any, Mapping

from protocol_tests.http_helpers import is_inconclusive

PASS = "PASS"
FAIL = "FAIL"
PARTIAL = "PARTIAL"
INCONCLUSIVE = "INCONCLUSIVE"
NOT_TESTED = "NOT_TESTED"
NO_RESULTS = "NO_RESULTS"


def aggregate_state(
    test_ids: list[str],
    result_by_id: Mapping[str, dict],
    *,
    absent_status: str = NOT_TESTED,
) -> dict[str, Any]:
    """Fold the rows for `test_ids` into one status, with the members named.

    Returns counts (`passed`, `failed`, `inconclusive`, `tests_mapped`,
    `tests_run`) and the member IDs behind each non-PASS state
    (`tests_absent`, `tests_inconclusive`, `tests_failed`), so a renderer can
    print *which* members kept the requirement from PASS rather than a bare
    label. `absent_status` is the name for "nothing present"; the two
    consumers' vocabularies differ and neither is wrong.
    """
    mapped = list(dict.fromkeys(test_ids))  # deduplicate, keep order
    present = [t for t in mapped if t in result_by_id]
    absent = [t for t in mapped if t not in result_by_id]

    inconclusive = [t for t in present if is_inconclusive(result_by_id[t])]
    inconc_set = set(inconclusive)
    passed = [t for t in present
              if t not in inconc_set and bool(result_by_id[t].get("passed", False))]
    passed_set = set(passed)
    # Not a residual over `present`: an inconclusive row is subtracted by ID,
    # so a control that was never exercised is never counted as one that
    # failed. A FAIL asserts the control did not hold.
    failed = [t for t in present if t not in inconc_set and t not in passed_set]

    if failed:
        status = FAIL
    elif not present:
        status = absent_status
    elif passed and not absent and not inconclusive:
        status = PASS
    elif passed:
        status = PARTIAL
    else:
        status = INCONCLUSIVE

    return {
        "status": status,
        "tests_mapped": len(mapped),
        "tests_run": len(present),
        "passed": len(passed),
        "failed": len(failed),
        "inconclusive": len(inconclusive),
        "total": len(present),
        "tests_absent": absent,
        "tests_inconclusive": inconclusive,
        "tests_failed": failed,
    }


def partial_reason(state: Mapping[str, Any]) -> str:
    """One line naming why a PARTIAL row is not a PASS, for a renderer."""
    parts = []
    if state.get("tests_absent"):
        parts.append("absent from this report: " + ", ".join(state["tests_absent"]))
    if state.get("tests_inconclusive"):
        parts.append("inconclusive (not exercised): "
                     + ", ".join(state["tests_inconclusive"]))
    return "; ".join(parts) or "unrecorded"
