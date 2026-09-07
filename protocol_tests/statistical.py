#!/usr/bin/env python3
"""Statistical utilities for multi-trial evaluation (NIST AI 800-2 aligned).

Provides:
- Multi-trial test runner wrapper
- Wilson score confidence intervals for binomial proportions
- Bootstrap confidence intervals for aggregate metrics
- JSON report enhancement with statistical fields

Usage:
    from protocol_tests.statistical import run_with_trials, wilson_ci

    # Run a test function N times and get statistical results
    stats = run_with_trials(test_fn, n_trials=10)
    print(f"Pass rate: {stats['pass_rate']:.2f} ({stats['ci_95']})")
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def wilson_ci(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for binomial proportion.

    More accurate than normal approximation for small samples.
    Per NIST AI 800-2 Practice 3.1.

    Args:
        successes: Number of successes (passes)
        trials: Total number of trials
        z: Z-score for confidence level (1.96 = 95%)

    Returns:
        (lower, upper) confidence interval bounds
    """
    # Input validation: clamp to valid ranges
    trials = max(0, int(trials))
    if trials == 0:
        return (0.0, 0.0)
    successes = max(0, min(int(successes), trials))

    p_hat = successes / trials
    z2 = z * z
    n = trials

    denominator = 1 + z2 / n
    center = (p_hat + z2 / (2 * n)) / denominator
    spread = z * math.sqrt(p_hat * (1 - p_hat) / n + z2 / (4 * n * n)) / denominator

    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)

    return (round(lower, 4), round(upper, 4))


def bootstrap_ci(pass_rates: list[float], n_bootstrap: int = 10000,
                 confidence: float = 0.95, seed: int = 42) -> tuple[float, float]:
    """Bootstrap confidence interval for aggregate pass rate.

    Args:
        pass_rates: List of per-test pass rates
        n_bootstrap: Number of bootstrap samples
        confidence: Confidence level
        seed: Random seed for reproducibility (default=42)

    Returns:
        (lower, upper) confidence interval bounds
    """
    import random
    if not pass_rates:
        return (0.0, 0.0)

    rng = random.Random(seed)
    n = len(pass_rates)
    means = []
    for _ in range(n_bootstrap):
        sample = [rng.choice(pass_rates) for _ in range(n)]
        means.append(sum(sample) / n)

    means.sort()
    alpha = (1 - confidence) / 2
    lower_idx = int(alpha * n_bootstrap)
    upper_idx = int((1 - alpha) * n_bootstrap) - 1

    return (round(means[lower_idx], 4), round(means[upper_idx], 4))


@dataclass
class TrialResult:
    """Result of running a test across multiple trials.

    ``pass_rate`` and ``ci_95`` are ``None`` -- not ``0.0`` and not ``(0.0, 0.0)``
    -- when no trial was serviced, for the reason ``http_helpers.run_summary``
    gives: a rate of zero is a claim, and absence is not. The denominator for
    both is ``n_serviced``, so the rate answers "of what was observed, how much
    passed" rather than "of everything attempted".

    The three-state fields are appended, with defaults, so the positional
    constructions in ``l402_harness`` and ``x402_harness`` keep working; those
    two do not track INCONCLUSIVE per trial and correctly report zero of it.
    """
    test_id: str
    test_name: str
    n_trials: int
    n_passed: int
    pass_rate: float | None
    ci_95: tuple[float, float] | None  # Wilson score CI over serviced trials
    per_trial: list[bool]  # Individual trial results
    mean_elapsed_s: float
    #: Trials that established nothing. Not failures.
    n_inconclusive: int = 0
    #: Per-trial "pass"/"fail"/"inconclusive", when the caller tracked it.
    per_trial_state: list[str] | None = None

    @property
    def n_serviced(self) -> int:
        """Trials that actually exercised the control."""
        return self.n_trials - self.n_inconclusive

    @property
    def n_failed(self) -> int:
        """Serviced trials that failed. A residual over `n_trials` would count
        the inconclusive ones as failures, which is the defect this replaces."""
        return self.n_serviced - self.n_passed

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "n_trials": self.n_trials,
            "n_passed": self.n_passed,
            "n_failed": self.n_failed,
            "n_inconclusive": self.n_inconclusive,
            "n_serviced": self.n_serviced,
            "pass_rate": self.pass_rate,
            "ci_95_lower": self.ci_95[0] if self.ci_95 else None,
            "ci_95_upper": self.ci_95[1] if self.ci_95 else None,
            "mean_elapsed_s": self.mean_elapsed_s,
            # `per_trial` was held on the dataclass but never serialised, so the
            # claim that a flaky test's failures were "recoverable from the JSON"
            # was not true of any written report. The state sequence is carried
            # here, and is `None` for callers that do not track it.
            "per_trial_state": self.per_trial_state,
        }


def run_with_trials(test_fn: Callable, n_trials: int = 10,
                    test_id: str = "", test_name: str = "") -> TrialResult:
    """Run a test function multiple times and compute statistical metrics.

    The test function should return an object with a .passed attribute (bool)
    and optionally .elapsed_s (float).

    Args:
        test_fn: Callable that runs the test and returns a result object
        n_trials: Number of times to run the test
        test_id: Test identifier for reporting
        test_name: Test name for reporting

    Returns:
        TrialResult with statistical metrics
    """
    results = []
    elapsed_times = []

    for i in range(n_trials):
        try:
            result = test_fn()
            passed = getattr(result, 'passed', False)
            elapsed = getattr(result, 'elapsed_s', 0.0)
            results.append(passed)
            elapsed_times.append(elapsed)
        except Exception:
            results.append(False)
            elapsed_times.append(0.0)

    n_passed = sum(1 for r in results if r)
    pass_rate = n_passed / n_trials if n_trials > 0 else 0.0
    ci = wilson_ci(n_passed, n_trials)
    mean_elapsed = sum(elapsed_times) / len(elapsed_times) if elapsed_times else 0.0

    return TrialResult(
        test_id=test_id or "unknown",
        test_name=test_name or "unknown",
        n_trials=n_trials,
        n_passed=n_passed,
        pass_rate=round(pass_rate, 4),
        ci_95=ci,
        per_trial=results,
        mean_elapsed_s=round(mean_elapsed, 3),
    )


def enhance_report(report: dict, trial_results: list[TrialResult] | None = None) -> dict:
    """Enhance a JSON report with NIST AI 800-2 aligned metadata.

    Adds:
    - Protocol version and git commit
    - Statistical summary with confidence intervals
    - NIST AI 800-2 compliance metadata
    """
    import subprocess

    # Add git commit hash
    try:
        git_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        git_hash = "unknown"

    report["metadata"] = {
        "nist_ai_800_2_aligned": True,
        "protocol_version": "3.0.0",
        "git_commit": git_hash,
        "evaluation_date": datetime.now(timezone.utc).isoformat(),
        "statistical_mode": trial_results is not None,
    }

    # Add statistical summary if trial results provided
    if trial_results:
        # Only tests with a serviced trial have a rate. Averaging a `None` in as
        # 0.0 would drag the aggregate down with observations that were never
        # made -- the same substitution `run_summary` refuses.
        pass_rates = [tr.pass_rate for tr in trial_results if tr.pass_rate is not None]
        trial_counts = [tr.n_trials for tr in trial_results]
        # `trial_results[0].n_trials` published the FIRST test's trial count as
        # if it were the whole run's. After a partial trial failure it is not:
        # a run where T-1 got 3 trials and T-2 got 1 reported "3". So it is
        # published only when it is actually uniform, and the observed range is
        # published alongside it either way.
        uniform = len(set(trial_counts)) == 1

        report["statistical_summary"] = {
            "aggregate_pass_rate": (round(sum(pass_rates) / len(pass_rates), 4)
                                    if pass_rates else None),
            "aggregate_ci_95": list(bootstrap_ci(pass_rates)) if pass_rates else None,
            "n_tests": len(trial_results),
            "n_tests_with_a_serviced_trial": len(pass_rates),
            "trials_per_test": trial_counts[0] if uniform else None,
            "trials_per_test_uniform": uniform,
            "trials_per_test_min": min(trial_counts),
            "trials_per_test_max": max(trial_counts),
            "per_test": [tr.to_dict() for tr in trial_results],
        }

    # Add NIST AI 800-2 practices checklist
    report["nist_practices"] = {
        "1.1_objectives_defined": True,
        "1.2_benchmarks_selected": True,
        "2.1_protocol_designed": True,
        "2.2_code_versioned": True,
        "2.3_results_tracked": True,
        "2.4_debugging_documented": True,
        "3.1_statistical_analysis": trial_results is not None,
        "3.2_details_shared": True,
        "3.3_claims_qualified": True,
    }

    return report


def generate_statistical_report(
    results: list[Any],
    trial_results: list[TrialResult] | None,
    suite_name: str,
    output_path: str,
):
    """Generate a NIST AI 800-2 compliant JSON report.

    Args:
        results: List of test result objects (must have .passed, .test_id attributes)
        trial_results: Optional trial results for statistical mode
        suite_name: Name of the test suite
        output_path: File path for JSON output
    """
    from dataclasses import asdict

    report = {
        "suite": suite_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if getattr(r, 'passed', False)),
            "failed": sum(1 for r in results if not getattr(r, 'passed', True)),
        },
        "results": [asdict(r) if hasattr(r, '__dataclass_fields__') else r for r in results],
    }

    report = enhance_report(report, trial_results)

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"NIST AI 800-2 aligned report written to {output_path}")
