"""Tests for FRIA evidence collection module.

Tracks GitHub issue #158.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.fria_evidence import generate_fria_evidence, fria_narrative_report, FRIA_CATEGORIES


def test_all_categories_present():
    """Output always has all 6 FRIA categories."""
    evidence = generate_fria_evidence([])
    assert len(evidence["categories"]) == 6
    for cat_id in FRIA_CATEGORIES:
        assert cat_id in evidence["categories"]


def test_passing_tests_produce_covered():
    """Tests that pass produce 'covered' status."""
    results = [
        {"test_id": "IR-001", "passed": True},
        {"test_id": "IR-002", "passed": True},
        {"test_id": "IR-005", "passed": True},
    ]
    evidence = generate_fria_evidence(results)
    safety = evidence["categories"]["safety"]
    assert safety["status"] == "covered"
    assert safety["passed"] >= 3


def test_failing_tests_produce_flagged():
    """Failing tests produce 'flagged' status."""
    results = [
        {"test_id": "IR-001", "passed": True},
        {"test_id": "IR-002", "passed": False},
    ]
    evidence = generate_fria_evidence(results)
    safety = evidence["categories"]["safety"]
    assert safety["status"] == "flagged"
    assert safety["failed"] >= 1


def test_no_results_produce_gap():
    """No matching results produce 'gap' or 'no_results'."""
    evidence = generate_fria_evidence([])
    for cat_data in evidence["categories"].values():
        assert cat_data["status"] in ("gap", "no_results")


def test_overall_status_compliant():
    """All passing → compliant."""
    results = []
    for cat_def in FRIA_CATEGORIES.values():
        for tid in cat_def["test_ids"]:
            results.append({"test_id": tid, "passed": True})
    evidence = generate_fria_evidence(results)
    assert evidence["overall_status"] == "compliant"


def test_overall_status_non_compliant():
    """Any flagged → non_compliant."""
    results = [{"test_id": "IR-001", "passed": False}]
    evidence = generate_fria_evidence(results)
    assert evidence["overall_status"] == "non_compliant"


def test_summary_structure():
    """Summary has expected keys."""
    evidence = generate_fria_evidence([])
    assert "framework" in evidence
    assert "overall_status" in evidence
    assert "summary" in evidence
    assert evidence["summary"]["total_categories"] == 6


def test_narrative_nonempty():
    """Narrative report produces readable output."""
    results = [
        {"test_id": "IR-001", "passed": True},
        {"test_id": "MEM-002", "passed": False},
    ]
    evidence = generate_fria_evidence(results)
    text = fria_narrative_report(evidence)
    assert len(text) > 200
    assert "FRIA" in text
    assert "Article 27" in text


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed.")
