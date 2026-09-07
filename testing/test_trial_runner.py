"""Tests for protocol_tests.trial_runner (#88)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class _MockResult:
    test_id: str
    name: str
    passed: bool
    elapsed_s: float = 0.1
    details: str = ""
    #: The structural INCONCLUSIVE field the shared predicate looks for.
    not_evaluated: bool = False

    def __post_init__(self):
        if self.details.startswith("INCONCLUSIVE"):
            self.not_evaluated = True


def _inconclusive(test_id: str, name: str) -> _MockResult:
    return _MockResult(test_id, name, False,
                       details="INCONCLUSIVE - target did not service the request")


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

        # T-001 passed 2/2 -> PASSED.
        # T-002 passed 1/2. Under the old `pass_rate >= 0.5` threshold that was
        # also PASSED, which made "retry until green" the silent default. One
        # serviced failure is a failure.
        assert report["summary"]["total"] == 2
        assert report["summary"]["passed"] == 1
        assert report["summary"]["failed"] == 1
        assert report["aggregation"]["unstable_tests"] == ["T-002"]

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


class TestThreeStateSummary:
    """The summary keeps PASS, FAIL and INCONCLUSIVE distinct (#523)."""

    def test_inconclusive_is_not_a_target_failure(self):
        """`failed` was a residual bucket, so an inconclusive result was
        reported as a failure. A fail asserts the control did not hold;
        inconclusive does not establish that."""
        from protocol_tests.trial_runner import run_with_trials

        results = [_MockResult("T-001", "One", True), _inconclusive("T-002", "Two")]
        report = run_with_trials(_make_run_fn(results), trials=1)
        s = report["summary"]

        assert s["total"] == 2
        assert s["passed"] == 1
        assert s["failed"] == 0
        assert s["inconclusive"] == 1
        assert s["serviced"] == 1

    def test_bucket_invariant_holds(self):
        """Existing consumers sum the buckets. `passed + failed + inconclusive
        == total` for every mix."""
        from protocol_tests.trial_runner import run_with_trials

        results = [_MockResult("T-001", "One", True),
                   _MockResult("T-002", "Two", False),
                   _inconclusive("T-003", "Three"),
                   _inconclusive("T-004", "Four")]
        report = run_with_trials(_make_run_fn(results), trials=2)
        s = report["summary"]
        assert s["passed"] + s["failed"] + s["inconclusive"] == s["total"] == 4

    def test_all_inconclusive_reports_no_rate(self):
        """A rate of zero is a claim, and absence is not."""
        from protocol_tests.trial_runner import run_with_trials

        results = [_inconclusive("T-001", "One"), _inconclusive("T-002", "Two")]
        report = run_with_trials(_make_run_fn(results), trials=3)
        s = report["summary"]

        assert s["serviced"] == 0
        assert s["failed"] == 0
        assert s["inconclusive"] == 2
        assert s["status"] == "inconclusive"
        assert s["pass_rate"] is None
        assert s["wilson_95_ci"] is None

    def test_inconclusive_trials_do_not_dilute_a_pass(self):
        """A test serviced once and inconclusive twice passed the only trial
        that exercised it. Under the old `>= 0.5` rate over ALL trials it
        scored 0.33 and was reported failed."""
        from protocol_tests.trial_runner import run_with_trials

        calls = {"n": 0}

        def run():
            calls["n"] += 1
            if calls["n"] == 1:
                return {"results": [_MockResult("T-001", "One", True)]}
            return {"results": [_inconclusive("T-001", "One")]}

        report = run_with_trials(run, trials=3)
        assert report["summary"]["passed"] == 1
        assert report["summary"]["failed"] == 0

        pt = report["statistical_summary"]["per_test"][0]
        assert pt["n_trials"] == 3
        assert pt["n_inconclusive"] == 2
        assert pt["n_serviced"] == 1
        assert pt["pass_rate"] == 1.0  # over serviced, not over all trials

    def test_dict_results_carry_the_inconclusive_state(self):
        """Results arriving as dicts, not objects, are read the same way."""
        from protocol_tests.trial_runner import run_with_trials

        def run():
            return {"results": [
                {"test_id": "T-001", "name": "One", "passed": True},
                {"test_id": "T-002", "name": "Two", "passed": False,
                 "not_evaluated": True},
                {"test_id": "T-003", "name": "Three", "passed": False,
                 "details": "INCONCLUSIVE - target did not service the request"},
            ]}

        s = run_with_trials(run, trials=1)["summary"]
        assert (s["total"], s["passed"], s["failed"], s["inconclusive"]) == (3, 1, 0, 2)


class TestAggregationRuleIsExplicit:
    """The rule turning N trial states into one verdict is named in the output."""

    def test_rule_is_published(self):
        from protocol_tests.trial_runner import AGGREGATION_RULE, run_with_trials

        report = run_with_trials(
            _make_run_fn([_MockResult("T-001", "One", True)]), trials=2)
        agg = report["aggregation"]
        assert agg["rule"] == AGGREGATION_RULE
        assert agg["description"]
        assert agg["trials_requested"] == 2
        assert agg["trials_completed"] == 2

    def test_one_serviced_failure_fails_the_test(self):
        """Retried-until-green was the silent default: 3 of 5 passing landed in
        `summary.passed` and the 2 failures appeared nowhere in `summary`."""
        from protocol_tests.trial_runner import run_with_trials

        calls = {"n": 0}

        def run():
            calls["n"] += 1
            return {"results": [_MockResult("T-001", "One", calls["n"] <= 3)]}

        report = run_with_trials(run, trials=5)
        assert report["summary"]["passed"] == 0
        assert report["summary"]["failed"] == 1
        assert report["aggregation"]["unstable_tests"] == ["T-001"]

        pt = report["statistical_summary"]["per_test"][0]
        assert (pt["n_passed"], pt["n_failed"], pt["n_trials"]) == (3, 2, 5)
        # The two failures must be readable from the written report, not only
        # from a dataclass field that `to_dict` dropped on the floor.
        assert pt["per_trial_state"] == ["pass", "pass", "pass", "fail", "fail"]

    def test_stable_pass_is_not_flagged_unstable(self):
        from protocol_tests.trial_runner import run_with_trials

        report = run_with_trials(
            _make_run_fn([_MockResult("T-001", "One", True)]), trials=3)
        assert report["aggregation"]["unstable_tests"] == []
        assert report["summary"]["passed"] == 1

    def test_console_names_the_rule(self, capsys):
        from protocol_tests.trial_runner import AGGREGATION_RULE, run_with_trials

        run_with_trials(_make_run_fn([_MockResult("T-001", "One", True)]), trials=1)
        assert AGGREGATION_RULE in capsys.readouterr().out

    def test_console_refuses_a_wilson_interval_over_nothing(self, capsys):
        from protocol_tests.trial_runner import run_with_trials

        run_with_trials(_make_run_fn([_inconclusive("T-001", "One")]), trials=2)
        out = capsys.readouterr().out
        assert "WILSON" not in out
        assert "none serviced" in out


class TestResultsMatchTheSummary:
    """`results` used to be the FINAL trial's list while `summary` was the
    union across trials, with nothing marking the disagreement."""

    def test_results_length_equals_summary_total(self):
        from protocol_tests.trial_runner import run_with_trials

        calls = {"n": 0}

        def run():
            calls["n"] += 1
            if calls["n"] == 1:
                return {"results": [_MockResult("T-001", "One", True),
                                    _MockResult("T-002", "Two", True)]}
            # A later trial that sees fewer tests must not shrink `results`
            return {"results": [_MockResult("T-001", "One", True)]}

        report = run_with_trials(run, trials=2)
        assert report["summary"]["total"] == 2
        assert len(report["results"]) == 2
        assert {r.test_id for r in report["results"]} == {"T-001", "T-002"}

    def test_a_crashed_final_trial_does_not_silently_rewind(self):
        from protocol_tests.trial_runner import run_with_trials

        calls = {"n": 0}

        def run():
            calls["n"] += 1
            if calls["n"] == 1:
                return {"results": [_MockResult("T-001", "One", True),
                                    _MockResult("T-002", "Two", True)]}
            raise RuntimeError("trial blew up")

        report = run_with_trials(run, trials=3)
        assert report["summary"]["total"] == len(report["results"]) == 2
        assert len(report["trial_errors"]) == 2
        assert report["aggregation"]["trials_completed"] == 1

    def test_results_carry_the_failing_trial_not_the_last_one(self):
        """The representative result is the evidence for the verdict."""
        from protocol_tests.trial_runner import run_with_trials

        calls = {"n": 0}

        def run():
            calls["n"] += 1
            return {"results": [_MockResult("T-001", "One", calls["n"] != 1)]}

        report = run_with_trials(run, trials=3)
        assert report["summary"]["failed"] == 1
        assert [r.passed for r in report["results"]] == [False]

    def test_every_trial_crashing_is_stated_not_left_as_an_empty_list(self):
        from protocol_tests.trial_runner import run_with_trials

        def run():
            raise RuntimeError("every trial blew up")

        report = run_with_trials(run, trials=3)
        assert report["results"] == []
        assert report["summary"]["total"] == 0
        assert report["summary"]["status"] == "empty"
        assert "error" in report
        assert len(report["trial_errors"]) == 3


class TestMissingTestIdDoesNotCollapse:
    """Every result missing an id used to land in one `"unknown"` bucket,
    silently reducing `total`."""

    def test_unidentified_results_stay_separate(self):
        from protocol_tests.trial_runner import run_with_trials

        def run():
            return {"results": [{"passed": True, "name": "a"},
                                {"passed": False, "name": "b"},
                                {"passed": True, "name": "c"}]}

        report = run_with_trials(run, trials=1)
        s = report["summary"]
        # Old behaviour: total 1, passed 1 -- the failure disappeared entirely
        # because the merged bucket scored 2/3 and cleared the 0.5 threshold.
        assert s["total"] == 3
        assert s["passed"] == 2
        assert s["failed"] == 1
        assert report["aggregation"]["unidentified_results"] == 3
        assert len({p["test_id"]
                    for p in report["statistical_summary"]["per_test"]}) == 3

    def test_empty_string_id_is_treated_as_missing(self):
        from protocol_tests.trial_runner import run_with_trials

        results = [_MockResult("", "One", True), _MockResult("", "Two", False)]
        report = run_with_trials(_make_run_fn(results), trials=1)
        assert report["summary"]["total"] == 2
        assert report["summary"]["failed"] == 1

    def test_an_object_without_test_id_does_not_abort_the_trial(self):
        """`getattr(r, 'test_id', None) or r.get(...)` raised AttributeError on
        a non-dict result, dumping the rest of that trial into trial_errors."""
        from protocol_tests.trial_runner import run_with_trials

        class _NoId:
            passed = True
            name = "anonymous"

        def run():
            return {"results": [_NoId(), _MockResult("T-001", "One", True)]}

        report = run_with_trials(run, trials=1)
        assert "trial_errors" not in report
        assert report["summary"]["total"] == 2

    def test_identified_results_still_match_across_trials(self):
        """The fix must not turn matched tests into per-trial entries."""
        from protocol_tests.trial_runner import run_with_trials

        results = [_MockResult("T-001", "One", True)]
        report = run_with_trials(_make_run_fn(results), trials=4)
        per_test = report["statistical_summary"]["per_test"]
        assert len(per_test) == 1
        assert per_test[0]["n_trials"] == 4
        assert report["aggregation"]["unidentified_results"] == 0


class TestTrialsPerTest:
    """`trials_per_test` published the FIRST test's count as if it were uniform."""

    def test_partial_trial_failure_is_not_reported_as_uniform(self):
        from protocol_tests.trial_runner import run_with_trials

        calls = {"n": 0}

        def run():
            calls["n"] += 1
            if calls["n"] == 1:
                return {"results": [_MockResult("T-001", "One", True),
                                    _MockResult("T-002", "Two", True)]}
            return {"results": [_MockResult("T-001", "One", True)]}

        s = run_with_trials(run, trials=3)["statistical_summary"]
        assert s["trials_per_test"] is None
        assert s["trials_per_test_uniform"] is False
        assert (s["trials_per_test_min"], s["trials_per_test_max"]) == (1, 3)

    def test_uniform_run_still_publishes_the_count(self):
        from protocol_tests.trial_runner import run_with_trials

        results = [_MockResult("T-001", "One", True), _MockResult("T-002", "Two", True)]
        s = run_with_trials(_make_run_fn(results), trials=4)["statistical_summary"]
        assert s["trials_per_test"] == 4
        assert s["trials_per_test_uniform"] is True


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
