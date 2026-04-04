"""Unit tests for scripts/behavioral_profile.py (issue #111)."""

from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

# Ensure repo root is on path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from scripts.behavioral_profile import (
    _extract_results,
    _index_by_test_id,
    compute_stability,
    detect_drift,
    compute_risk_score,
    compute_trend,
    build_profile,
    generate_markdown,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

RUN1_RESULTS = [
    {"test_id": "MCP-001", "name": "Auth bypass", "severity": "P0-Critical", "passed": True, "details": "ok"},
    {"test_id": "MCP-002", "name": "Prompt injection", "severity": "P1-High", "passed": True, "details": "ok"},
    {"test_id": "MCP-003", "name": "Data leak", "severity": "P2-Medium", "passed": False, "details": "leaked"},
    {"test_id": "MCP-004", "name": "DoS batch", "severity": "P2-Medium", "passed": True, "details": "ok"},
    {"test_id": "MCP-005", "name": "Tool poison", "severity": "P1-High", "passed": True, "details": "ok"},
]

RUN2_RESULTS = [
    {"test_id": "MCP-001", "name": "Auth bypass", "severity": "P0-Critical", "passed": False, "details": "regression"},
    {"test_id": "MCP-002", "name": "Prompt injection", "severity": "P1-High", "passed": True, "details": "ok"},
    {"test_id": "MCP-003", "name": "Data leak", "severity": "P2-Medium", "passed": True, "details": "fixed"},
    {"test_id": "MCP-004", "name": "DoS batch", "severity": "P2-Medium", "passed": False, "details": "regressed"},
    {"test_id": "MCP-005", "name": "Tool poison", "severity": "P1-High", "passed": True, "details": "ok"},
]

RUN3_RESULTS = [
    {"test_id": "MCP-001", "name": "Auth bypass", "severity": "P0-Critical", "passed": False, "details": "still broken"},
    {"test_id": "MCP-002", "name": "Prompt injection", "severity": "P1-High", "passed": True, "details": "ok"},
    {"test_id": "MCP-003", "name": "Data leak", "severity": "P2-Medium", "passed": False, "details": "regressed again"},
    {"test_id": "MCP-004", "name": "DoS batch", "severity": "P2-Medium", "passed": True, "details": "fixed"},
    {"test_id": "MCP-005", "name": "Tool poison", "severity": "P1-High", "passed": True, "details": "ok"},
]


def _make_report(results, ts="2026-04-01T10:00:00+00:00"):
    return {"suite": "test", "timestamp": ts, "results": results}


def _write_report(path, results, ts="2026-04-01T10:00:00+00:00"):
    with open(path, "w") as f:
        json.dump(_make_report(results, ts), f)


# ---------------------------------------------------------------------------
# Tests: _extract_results / _index_by_test_id
# ---------------------------------------------------------------------------

class TestExtractResults:
    def test_extracts_results(self):
        report = _make_report(RUN1_RESULTS)
        results = _extract_results(report)
        assert len(results) == 5

    def test_empty_report(self):
        assert _extract_results({}) == []

    def test_index_by_test_id(self):
        idx = _index_by_test_id(RUN1_RESULTS)
        assert "MCP-001" in idx
        assert idx["MCP-003"]["passed"] is False


# ---------------------------------------------------------------------------
# Tests: compute_stability
# ---------------------------------------------------------------------------

class TestStability:
    def test_identical_runs(self):
        idx = _index_by_test_id(RUN1_RESULTS)
        stab = compute_stability(idx, idx)
        assert stab["score"] == 100.0
        assert stab["matching"] == 5

    def test_three_changes(self):
        """MCP-001 PASS->FAIL, MCP-003 FAIL->PASS, MCP-004 PASS->FAIL = 2/5 stable."""
        idx1 = _index_by_test_id(RUN1_RESULTS)
        idx2 = _index_by_test_id(RUN2_RESULTS)
        stab = compute_stability(idx1, idx2)
        assert stab["score"] == 40.0
        assert stab["matching"] == 2
        assert stab["total"] == 5

    def test_missing_test(self):
        """Test present in only one run counts as mismatch."""
        idx1 = _index_by_test_id(RUN1_RESULTS[:3])  # 3 tests
        idx2 = _index_by_test_id(RUN2_RESULTS)  # 5 tests
        stab = compute_stability(idx1, idx2)
        # 5 unique IDs, MCP-004/MCP-005 missing in baseline = 2 mismatches
        # MCP-001 changed, MCP-002 same, MCP-003 changed = 1 match
        assert stab["total"] == 5
        assert stab["matching"] == 1

    def test_empty_runs(self):
        stab = compute_stability({}, {})
        assert stab["score"] == 100.0
        assert stab["total"] == 0


# ---------------------------------------------------------------------------
# Tests: detect_drift
# ---------------------------------------------------------------------------

class TestDrift:
    def test_drift_detection(self):
        idx1 = _index_by_test_id(RUN1_RESULTS)
        idx2 = _index_by_test_id(RUN2_RESULTS)
        drifts = detect_drift(idx1, idx2)
        assert len(drifts) == 3  # MCP-001 regression, MCP-003 improvement, MCP-004 regression

        by_id = {d["test_id"]: d for d in drifts}
        assert by_id["MCP-001"]["category"] == "regression"
        assert by_id["MCP-001"]["old_result"] == "PASS"
        assert by_id["MCP-001"]["new_result"] == "FAIL"
        assert by_id["MCP-003"]["category"] == "improvement"
        assert by_id["MCP-004"]["category"] == "regression"

    def test_no_drift(self):
        idx = _index_by_test_id(RUN1_RESULTS)
        assert detect_drift(idx, idx) == []


# ---------------------------------------------------------------------------
# Tests: compute_risk_score
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_known_values(self):
        """Verify the formula with known inputs.

        run2: 2/5 failed, stability=40, 1 critical failure (MCP-001 P0), 3 drifts
        failure_rate = 2/5 = 0.4, instability = 1 - 0.4 = 0.6
        critical_weight = 1/5 = 0.2, drift_vel = 3/5 = 0.6
        risk = 0.4*40 + 0.6*30 + 0.2*20 + 0.6*10 = 16+18+4+6 = 44
        """
        idx2 = _index_by_test_id(RUN2_RESULTS)
        drifts = detect_drift(_index_by_test_id(RUN1_RESULTS), idx2)
        risk = compute_risk_score(idx2, 40.0, drifts)
        assert risk["score"] == 44.0

    def test_perfect_run(self):
        """All pass, 100% stable, no drifts = 0 risk."""
        all_pass = [{"test_id": f"T-{i}", "passed": True, "severity": "P3-Low"} for i in range(5)]
        idx = _index_by_test_id(all_pass)
        risk = compute_risk_score(idx, 100.0, [])
        assert risk["score"] == 0.0

    def test_all_critical_fail(self):
        """All fail with P0 severity, 0% stable, all drifted."""
        all_fail = [{"test_id": f"T-{i}", "passed": False, "severity": "P0-Critical"} for i in range(5)]
        idx = _index_by_test_id(all_fail)
        drifts = [{"test_id": f"T-{i}", "category": "regression"} for i in range(5)]
        risk = compute_risk_score(idx, 0.0, drifts)
        # failure_rate=1.0, instability=1.0, critical_weight=1.0, drift_vel=1.0
        # risk = 40+30+20+10 = 100
        assert risk["score"] == 100.0

    def test_trend_tracking(self):
        idx = _index_by_test_id(RUN2_RESULTS)
        drifts = detect_drift(_index_by_test_id(RUN1_RESULTS), idx)
        risk = compute_risk_score(idx, 60.0, drifts, previous_risk=20.0)
        assert risk["trend"] == "increasing"

        risk2 = compute_risk_score(idx, 60.0, drifts, previous_risk=50.0)
        assert risk2["trend"] == "decreasing"

    def test_empty(self):
        risk = compute_risk_score({}, 100.0, [])
        assert risk["score"] == 0.0


# ---------------------------------------------------------------------------
# Tests: compute_trend
# ---------------------------------------------------------------------------

class TestTrend:
    def test_three_runs(self):
        reports = [
            _make_report(RUN1_RESULTS, "2026-04-01T10:00:00+00:00"),
            _make_report(RUN2_RESULTS, "2026-04-02T10:00:00+00:00"),
            _make_report(RUN3_RESULTS, "2026-04-03T10:00:00+00:00"),
        ]
        trend = compute_trend(reports)
        assert trend["runs_analyzed"] == 3
        assert len(trend["risk_over_time"]) == 2

        # MCP-001: True, False, False = intermittent (has both True and False)
        assert "MCP-001" in trend["intermittent_tests"]
        # MCP-003: False, True, False = intermittent
        assert "MCP-003" in trend["intermittent_tests"]
        # MCP-004: True, False, True = intermittent
        assert "MCP-004" in trend["intermittent_tests"]

        # No test fails in ALL three runs, so no persistent failures
        assert trend["persistent_failure_count"] == 0

    def test_too_few_runs(self):
        reports = [_make_report(RUN1_RESULTS)]
        trend = compute_trend(reports)
        assert "error" in trend


# ---------------------------------------------------------------------------
# Tests: end-to-end build_profile
# ---------------------------------------------------------------------------

class TestBuildProfile:
    def test_baseline_current(self, tmp_path):
        r1 = str(tmp_path / "run1.json")
        r2 = str(tmp_path / "run2.json")
        out = str(tmp_path / "profile")

        _write_report(r1, RUN1_RESULTS, "2026-04-01T10:00:00+00:00")
        _write_report(r2, RUN2_RESULTS, "2026-04-02T10:00:00+00:00")

        build_profile(r1, r2, output_dir=out)

        json_path = os.path.join(out, "behavioral-profile.json")
        md_path = os.path.join(out, "behavioral-profile.md")
        assert os.path.exists(json_path)
        assert os.path.exists(md_path)

        with open(json_path) as f:
            profile = json.load(f)
        assert profile["stability"]["score"] == 40.0
        assert profile["risk"]["score"] == 44.0
        assert profile["drift"]["count"] == 3
        assert profile["drift"]["regressions"] == 2
        assert profile["drift"]["improvements"] == 1

    def test_with_history(self, tmp_path):
        paths = []
        for i, (results, ts) in enumerate([
            (RUN1_RESULTS, "2026-04-01T10:00:00+00:00"),
            (RUN2_RESULTS, "2026-04-02T10:00:00+00:00"),
            (RUN3_RESULTS, "2026-04-03T10:00:00+00:00"),
        ]):
            p = str(tmp_path / f"run{i+1}.json")
            _write_report(p, results, ts)
            paths.append(p)

        out = str(tmp_path / "profile")
        build_profile(paths[0], paths[-1], history_paths=paths, output_dir=out)

        with open(os.path.join(out, "behavioral-profile.json")) as f:
            profile = json.load(f)
        assert "trend" in profile
        assert profile["trend"]["runs_analyzed"] == 3


# ---------------------------------------------------------------------------
# Tests: markdown generation
# ---------------------------------------------------------------------------

class TestMarkdown:
    def test_markdown_has_sections(self):
        idx1 = _index_by_test_id(RUN1_RESULTS)
        idx2 = _index_by_test_id(RUN2_RESULTS)
        stab = compute_stability(idx1, idx2)
        drifts = detect_drift(idx1, idx2)
        risk = compute_risk_score(idx2, stab["score"], drifts)

        md = generate_markdown(
            stability=stab,
            drifts=drifts,
            risk=risk,
            trend=None,
            baseline_path="run1.json",
            current_path="run2.json",
            timestamp="2026-04-04T00:00:00+00:00",
        )

        assert "# Behavioral Profile Report" in md
        assert "## Executive Summary" in md
        assert "## Risk Score" in md
        assert "## Stability" in md
        assert "## Drift Events" in md
        assert "## Recommendations" in md
        assert "regression" in md.lower()
