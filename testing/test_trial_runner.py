"""Tests for protocol_tests.trial_runner (#88)."""
from __future__ import annotations

import pytest
from dataclasses import dataclass


@dataclass
class _MockResult:
    test_id: str
    name: str
    passed: bool
    elapsed_s: float = 0.1


def _make_run_fn(results: list[_MockResult]):
    """Return a callable that returns a report dict with the given results."""
    def run_fn():
        return {"results": list(results)}
    return run_fn


class TestRunWithTrials:
    """Unit tests for run_with_trials."""

    def test_single_trial_all_pass(self):
        from protocol_tests.trial_runner import run_with_trials

        results = [
            _MockResult("T-001", "Test One", True),
            _MockResult("T-002", "Test Two", True),
        ]
        report = run_with_trials(_make_run_fn(results), trials=1)

        assert report["summary"]["total"] == 2
        assert report["summary"]["passed"] == 2
        assert report["summary"]["failed"] == 0
        assert "statistical_summary" in report

    def test_single_trial_mixed(self):
        from protocol_tests.trial_runner import run_with_trials

        results = [
            _MockResult("T-001", "Test One", True),
            _MockResult("T-002", "Test Two", False),
        ]
        report = run_with_trials(_make_run_fn(results), trials=1)

        assert report["summary"]["total"] == 2
        assert report["summary"]["passed"] == 1
        assert report["summary"]["failed"] == 1

    def test_multi_trial_aggregation(self):
        from protocol_tests.trial_runner import run_with_trials

        call_count = 0

        def alternating_run():
            nonlocal call_count
            call_count += 1
            # First trial: T-001 passes, T-002 fails
            # Second trial: T-001 passes, T-002 passes
            if call_count % 2 == 1:
                return {"results": [
                    _MockResult("T-001", "Test One", True),
                    _MockResult("T-002", "Test Two", False),
                ]}
            else:
                return {"results": [
                    _MockResult("T-001", "Test One", True),
                    _MockResult("T-002", "Test Two", True),
                ]}

        report = run_with_trials(alternating_run, trials=2)

        # T-001 passed 2/2 (pass_rate=1.0 >= 0.5 -> counted as passed)
        # T-002 passed 1/2 (pass_rate=0.5 >= 0.5 -> counted as passed)
        assert report["summary"]["total"] == 2
        assert report["summary"]["passed"] == 2

        # Check statistical summary exists
        stat_summary = report.get("statistical_summary", {})
        per_test = stat_summary.get("per_test", [])
        assert len(per_test) == 2
        t001 = [s for s in per_test if s["test_id"] == "T-001"][0]
        assert t001["n_passed"] == 2
        assert t001["pass_rate"] == 1.0

    def test_test_id_matching(self):
        """Results are matched by test_id, not positional index (#72)."""
        from protocol_tests.trial_runner import run_with_trials

        call_count = 0

        def reordered_run():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"results": [
                    _MockResult("T-001", "Test One", True),
                    _MockResult("T-002", "Test Two", False),
                ]}
            else:
                # Different order
                return {"results": [
                    _MockResult("T-002", "Test Two", True),
                    _MockResult("T-001", "Test One", True),
                ]}

        report = run_with_trials(reordered_run, trials=2)

        per_test = report.get("statistical_summary", {}).get("per_test", [])
        t001 = [s for s in per_test if s["test_id"] == "T-001"][0]
        t002 = [s for s in per_test if s["test_id"] == "T-002"][0]
        assert t001["n_passed"] == 2
        assert t002["n_passed"] == 1  # Failed first trial, passed second

    def test_error_handling_one_trial_fails(self):
        """One trial raising an exception shouldn't abort everything (#82)."""
        from protocol_tests.trial_runner import run_with_trials

        call_count = 0

        def flaky_run():
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("Simulated network failure")
            return {"results": [_MockResult("T-001", "Test One", True)]}

        report = run_with_trials(flaky_run, trials=3)

        assert "trial_errors" in report
        assert len(report["trial_errors"]) == 1
        assert "Trial 2" in report["trial_errors"][0]
        # Should still have stats from the 2 successful trials
        per_test = report.get("statistical_summary", {}).get("per_test", [])
        assert len(per_test) == 1
        assert per_test[0]["n_trials"] == 2

    def test_results_support_attribute_access(self):
        """Results in the report should support attribute access (#83)."""
        from protocol_tests.trial_runner import run_with_trials

        results = [_MockResult("T-001", "Test One", True)]
        report = run_with_trials(_make_run_fn(results), trials=1)

        for r in report["results"]:
            # Must support attribute access (not just dict)
            assert hasattr(r, "passed")
            assert r.passed is True
            assert r.test_id == "T-001"


class TestVersion:
    """Unit tests for protocol_tests.version (#88)."""

    def test_returns_version_string(self):
        from protocol_tests.version import get_harness_version

        version = get_harness_version()
        assert isinstance(version, str)
        assert version != "unknown"
        # Should look like a version number
        parts = version.split(".")
        assert len(parts) >= 2, f"Expected semver-like version, got: {version}"

    def test_prefers_pyproject_toml(self):
        """version.py should read from pyproject.toml first (#86)."""
        from protocol_tests.version import get_harness_version

        version = get_harness_version()
        # Read pyproject.toml directly to compare
        from pathlib import Path
        toml_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
        toml_version = None
        for line in toml_path.read_text().splitlines():
            if line.strip().startswith("version"):
                toml_version = line.split("=", 1)[1].strip().strip('"').strip("'")
                break
        assert toml_version is not None
        assert version == toml_version
