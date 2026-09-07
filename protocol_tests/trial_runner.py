"""Shared multi-trial runner for all harnesses.

Fixes:
  - #72: matches results by test_id, not positional index
  - #82: per-trial error handling (one failure doesn't abort the rest)
  - #523: PASS, FAIL and INCONCLUSIVE stay distinct across trials

Usage::

    from protocol_tests.trial_runner import run_with_trials

    def single_run():
        suite = MyTests(url)
        return {"results": suite.run_all()}

    report = run_with_trials(single_run, trials=5, report_key="results")

The aggregation rule is named in the report (``aggregation.rule``) rather than
left implicit in a threshold. See ``AGGREGATION_RULE_TEXT`` for what it says and
why.
"""
from __future__ import annotations

import traceback
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from protocol_tests.http_helpers import (
    INCONCLUSIVE_FIELDS,
    INCONCLUSIVE_PREFIX,
    is_inconclusive,
    run_summary,
    summary_lines,
)
from protocol_tests.statistical import TrialResult, enhance_report, wilson_ci

#: The three states one trial of one test can be in.
PASS = "pass"
FAIL = "fail"
INCONCLUSIVE = "inconclusive"

#: Machine-readable name of the rule that turns N trial states into one verdict.
AGGREGATION_RULE = "every-serviced-trial-must-pass"

AGGREGATION_RULE_TEXT = (
    "A test counts as PASSED only if every serviced trial passed. One serviced "
    "failure makes the test FAILED: a control that gave way in any trial did not "
    "hold, and re-running until it holds is not evidence that it does. A test "
    "with no serviced trial is INCONCLUSIVE, never FAILED -- a fail asserts the "
    "control did not hold, and an unserviced trial establishes nothing."
)


def _field(result: Any, name: str, default: Any = None) -> Any:
    """Read *name* off a result that may be an object or a dict.

    The previous form, ``getattr(r, name, None) or r.get(name, default)``, had
    two faults in one line: it raised ``AttributeError`` on an object that
    merely lacked the attribute (aborting the rest of that trial's results into
    ``trial_errors``), and it treated a falsy value as absent.
    """
    if isinstance(result, Mapping):
        return result.get(name, default)
    value = getattr(result, name, None)
    return default if value is None else value


def _trial_state(result: Any) -> str:
    """PASS / FAIL / INCONCLUSIVE for a single result.

    The predicate is not reimplemented here. ``is_inconclusive`` reads
    attributes, so a result that arrives as a dict is handed the same two facts
    by key; the decision about what those facts mean stays in one place.
    """
    if isinstance(result, Mapping):
        inconclusive = (any(bool(result.get(f)) for f in INCONCLUSIVE_FIELDS)
                        or is_inconclusive(result.get("details")))
    else:
        inconclusive = is_inconclusive(result)
    if inconclusive:
        return INCONCLUSIVE
    return PASS if bool(_field(result, "passed", False)) else FAIL


@dataclass
class _Verdict:
    """One test's aggregated outcome, in the shape ``run_summary`` already reads.

    Built so the counting can be delegated to ``http_helpers.run_summary``
    instead of being written a second time here. ``not_evaluated`` is the
    structural INCONCLUSIVE field that ``is_inconclusive`` looks for.
    """

    test_id: str
    test_name: str
    passed: bool
    not_evaluated: bool
    details: str

    def __post_init__(self) -> None:
        # The package invariant: a prefix in `details` implies the field, so a
        # serialised record is never readable only as English.
        # `testing/test_inconclusive_is_structural.py` enforces it here too.
        if is_inconclusive(self.details):
            self.not_evaluated = True


def run_with_trials(
    run_fn: Callable[[], dict[str, Any]],
    trials: int,
    report_key: str = "results",
    suite_name: str = "Security Tests",
) -> dict[str, Any]:
    """Run *run_fn* N times, aggregate by test_id, compute Wilson CIs.

    Args:
        run_fn: callable returning a dict whose *report_key* entry is a list
                of result objects (each must expose ``.test_id`` and ``.passed``).
        trials: number of independent runs.
        report_key: key in the dict that holds the result list.
        suite_name: human label for the report.

    Returns:
        Merged report dict with ``statistical_summary`` and per-test stats.

    The summary keeps PASS, FAIL and INCONCLUSIVE distinct and satisfies
    ``passed + failed + inconclusive == total``. ``results`` holds one
    representative result per test_id -- the evidence for that test's verdict --
    so ``len(report["results"]) == report["summary"]["total"]`` by construction.
    It used to be the final trial's list, which could disagree with the summary,
    silently fall back to an earlier trial's list, or be empty.
    """
    # {test_id: [(state, result_obj, elapsed), ...]} in trial order
    per_test: dict[str, list[tuple[str, Any, float]]] = defaultdict(list)
    # Keep first-seen metadata per test_id
    meta: dict[str, dict[str, str]] = {}
    trial_errors: list[str] = []
    unidentified = 0

    for trial_idx in range(trials):
        print(f"\n{'#'*60}")
        print(f"# TRIAL {trial_idx + 1}/{trials}")
        print(f"{'#'*60}")
        try:
            report = run_fn()
            results = report.get(report_key, [])
            for position, r in enumerate(results):
                tid = _field(r, "test_id", None)
                if not tid:
                    # A result with no id cannot be matched to the same test in
                    # another trial, and pretending otherwise is what the shared
                    # "unknown" bucket did: three unidentified results, one of
                    # them failing, collapsed into a single entry that reported
                    # 2/3 and therefore PASSED. Each gets its own entry, and the
                    # count is published so the reader knows matching was not
                    # possible -- rather than the total quietly shrinking.
                    tid = f"unidentified-t{trial_idx + 1}-{position}"
                    unidentified += 1
                elapsed = _field(r, "elapsed_s", 0.0) or 0.0
                per_test[tid].append((_trial_state(r), r, float(elapsed)))
                if tid not in meta:
                    name = _field(r, "name", None) or tid
                    meta[tid] = {"test_name": str(name)}
        except Exception:
            msg = traceback.format_exc()
            trial_errors.append(f"Trial {trial_idx + 1}: {msg}")
            print(f"  ⚠️  Trial {trial_idx + 1} FAILED:\n{msg}")

    # Build statistical results keyed by test_id (fixes #72)
    stat_results: list[TrialResult] = []
    verdicts: list[_Verdict] = []
    representative: list[Any] = []
    unstable: list[str] = []

    for tid, outcomes in per_test.items():
        states = [s for s, _, _ in outcomes]
        n = len(states)
        n_passed = states.count(PASS)
        n_failed = states.count(FAIL)
        n_inconclusive = states.count(INCONCLUSIVE)
        serviced = n_passed + n_failed
        name = meta.get(tid, {}).get("test_name", tid)

        # `None`, not 0.0, when nothing was serviced. Matching http_helpers:
        # a rate of zero is a claim, and absence is not. The Wilson interval is
        # over `serviced` for the same reason -- an interval computed over
        # unserviced observations presents an absence as a measurement.
        pass_rate = round(n_passed / serviced, 4) if serviced else None
        ci = wilson_ci(n_passed, serviced) if serviced else None
        mean_elapsed = sum(e for _, _, e in outcomes) / n if n else 0.0

        stat_results.append(TrialResult(
            test_id=tid,
            test_name=name,
            n_trials=n,
            n_passed=n_passed,
            pass_rate=pass_rate,
            ci_95=ci,
            per_trial=[s == PASS for s in states],
            mean_elapsed_s=round(mean_elapsed, 3),
            n_inconclusive=n_inconclusive,
            per_trial_state=list(states),
        ))

        if serviced == 0:
            verdict_passed = False
            not_evaluated = True
            details = (f"{INCONCLUSIVE_PREFIX}none of {n} trial(s) were serviced, "
                       f"so no trial established whether this control holds")
        else:
            verdict_passed = n_failed == 0
            not_evaluated = False
            details = (f"{n_passed}/{serviced} serviced trial(s) passed"
                       + (f"; {n_inconclusive} inconclusive" if n_inconclusive else ""))
            if n_passed and n_failed:
                unstable.append(tid)

        verdicts.append(_Verdict(test_id=tid, test_name=name, passed=verdict_passed,
                                 not_evaluated=not_evaluated, details=details))

        # The evidence for the verdict, not whichever trial happened to be last.
        want = FAIL if (serviced and n_failed) else (PASS if serviced else INCONCLUSIVE)
        for state, obj, _ in outcomes:
            if state == want:
                representative.append(obj)
                break

    # One summary implementation for the whole package (#402/#523).
    summary = run_summary(verdicts)

    report_out: dict[str, Any] = {
        "suite": suite_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "aggregation": {
            "rule": AGGREGATION_RULE,
            "description": AGGREGATION_RULE_TEXT,
            "trials_requested": trials,
            "trials_completed": trials - len(trial_errors),
            "unstable_tests": unstable,
            "unidentified_results": unidentified,
            "results_are": ("one representative result per test_id -- the trial "
                            "that carries the verdict -- not the final trial's list"),
        },
        # Return the original result objects so callers can use attribute access (#83)
        "results": representative,
    }
    if trial_errors and not stat_results:
        # `results` is legitimately empty here, and an empty result list reads as
        # "nothing failed" to anything counting failures. Say what happened.
        report_out["error"] = (
            f"all {trials} trial(s) raised before producing a result; "
            f"no control was exercised"
        )
    report_out = enhance_report(report_out, stat_results)
    if trial_errors:
        report_out["trial_errors"] = trial_errors

    for line in summary_lines(summary):
        print(line)
    print(f"AGGREGATION: {AGGREGATION_RULE} -- {AGGREGATION_RULE_TEXT}")
    if unstable:
        print(f"{len(unstable)} test(s) were not stable across trials "
              f"(passed some serviced trials, failed others): {', '.join(unstable)}")
    if unidentified:
        print(f"{unidentified} result(s) carried no test_id and could not be "
              f"matched across trials; each is reported separately.")
    if trial_errors:
        print(f"{len(trial_errors)} of {trials} trial(s) raised; see trial_errors.")

    return report_out
