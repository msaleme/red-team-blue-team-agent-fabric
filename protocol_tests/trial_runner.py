"""Shared multi-trial runner for all harnesses.

Fixes:
  - #72: matches results by test_id, not positional index
  - #82: per-trial error handling (one failure doesn't abort the rest)

Usage::

    from protocol_tests.trial_runner import run_with_trials

    def single_run():
        suite = MyTests(url)
        return {"results": suite.run_all()}

    report = run_with_trials(single_run, trials=5, report_key="results")
"""
from __future__ import annotations

import traceback
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

from protocol_tests.statistical import wilson_ci, bootstrap_ci, TrialResult, enhance_report


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
    """
    # {test_id: [(passed:bool, elapsed:float), ...]}
    per_test: dict[str, list[tuple[bool, float]]] = defaultdict(list)
    # Keep first-seen metadata per test_id
    meta: dict[str, dict[str, str]] = {}
    last_results: list[Any] = []
    trial_errors: list[str] = []

    for trial_idx in range(trials):
        print(f"\n{'#'*60}")
        print(f"# TRIAL {trial_idx + 1}/{trials}")
        print(f"{'#'*60}")
        try:
            report = run_fn()
            results = report.get(report_key, [])
            last_results = results
            for r in results:
                tid = getattr(r, "test_id", None) or r.get("test_id", "unknown")  # type: ignore[union-attr]
                passed = getattr(r, "passed", None)
                if passed is None:
                    passed = r.get("passed", False)  # type: ignore[union-attr]
                elapsed = getattr(r, "elapsed_s", 0.0)
                if elapsed == 0.0 and isinstance(r, dict):
                    elapsed = r.get("elapsed_s", 0.0)
                per_test[tid].append((bool(passed), float(elapsed)))
                if tid not in meta:
                    name = getattr(r, "name", None) or (r.get("name") if isinstance(r, dict) else None) or tid
                    meta[tid] = {"test_name": name}
        except Exception:
            msg = traceback.format_exc()
            trial_errors.append(f"Trial {trial_idx + 1}: {msg}")
            print(f"  ⚠️  Trial {trial_idx + 1} FAILED:\n{msg}")

    # Build statistical results keyed by test_id (fixes #72)
    stat_results: list[TrialResult] = []
    for tid, outcomes in per_test.items():
        n = len(outcomes)
        n_passed = sum(1 for p, _ in outcomes if p)
        pass_rate = n_passed / n if n else 0.0
        ci = wilson_ci(n_passed, n)
        mean_elapsed = sum(e for _, e in outcomes) / n if n else 0.0
        stat_results.append(TrialResult(
            test_id=tid,
            test_name=meta.get(tid, {}).get("test_name", tid),
            n_trials=n,
            n_passed=n_passed,
            pass_rate=round(pass_rate, 4),
            ci_95=ci,
            per_trial=[p for p, _ in outcomes],
            mean_elapsed_s=round(mean_elapsed, 3),
        ))

    # Build final report
    from dataclasses import asdict
    report_out: dict[str, Any] = {
        "suite": suite_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(last_results),
            "passed": sum(1 for r in last_results if (getattr(r, "passed", None) if not isinstance(r, dict) else r.get("passed", False))),
            "failed": sum(1 for r in last_results if not (getattr(r, "passed", None) if not isinstance(r, dict) else r.get("passed", True))),
        },
        "results": [asdict(r) if hasattr(r, "__dataclass_fields__") else r for r in last_results],
    }
    report_out = enhance_report(report_out, stat_results)
    if trial_errors:
        report_out["trial_errors"] = trial_errors
    return report_out
