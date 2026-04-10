"""Tests for AUROC computation module.

Tracks GitHub issue #155.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.auroc import compute_auroc, compute_module_auroc, compute_all_auroc, auroc_color, auroc_label


def test_perfect_classifier():
    """Perfect classifier: TPR=1.0 at FPR=0.0 → AUROC=1.0."""
    assert compute_auroc([0.0, 0.0, 1.0], [0.0, 1.0, 1.0]) == 1.0


def test_random_classifier():
    """Random classifier: diagonal → AUROC=0.5."""
    assert compute_auroc([0.0, 1.0], [0.0, 1.0]) == 0.5


def test_empty_inputs():
    """Empty inputs return 0.5 (random baseline)."""
    assert compute_auroc([], []) == 0.5


def test_single_point():
    """Single operating point at (0.1, 0.9)."""
    result = compute_auroc([0.1], [0.9])
    assert 0.85 < result < 0.95  # Should be high AUROC


def test_worst_classifier():
    """Worst classifier: TPR=0.0 at FPR=1.0 → AUROC near 0.0."""
    result = compute_auroc([0.0, 1.0, 1.0], [0.0, 0.0, 1.0])
    assert result < 0.1


def test_module_auroc_all_detected():
    """All attacks detected, no false positives → high AUROC."""
    attacks = [{"passed": True} for _ in range(10)]
    benign = [{"passed": True} for _ in range(10)]
    result = compute_module_auroc(attacks, benign)
    assert result >= 0.95


def test_module_auroc_none_detected():
    """No attacks detected → low AUROC."""
    attacks = [{"passed": False} for _ in range(10)]
    benign = [{"passed": True} for _ in range(10)]
    result = compute_module_auroc(attacks, benign)
    assert result <= 0.55


def test_module_auroc_empty():
    """Empty results → 0.5."""
    assert compute_module_auroc([], []) == 0.5


def test_compute_all_auroc_structure():
    """Full pipeline returns expected structure."""
    harness_json = {
        "results": [
            {"test_id": "MCP-001", "module": "mcp", "passed": True},
            {"test_id": "MCP-002", "module": "mcp", "passed": True},
            {"test_id": "MCP-003", "module": "mcp", "passed": False},
            {"test_id": "AUTH-001", "module": "identity", "passed": True},
            {"test_id": "FPR-001", "module": "fpr", "passed": True},
            {"test_id": "FPR-002", "module": "fpr", "passed": True},
        ],
    }
    result = compute_all_auroc(harness_json)
    assert "overall" in result
    assert "modules" in result
    assert "methodology" in result
    assert "mcp" in result["modules"]
    assert "identity" in result["modules"]
    assert "fpr" not in result["modules"]  # FPR is used for comparison, not scored


def test_auroc_color():
    assert auroc_color(0.95) == "green"
    assert auroc_color(0.85) == "amber"
    assert auroc_color(0.70) == "red"


def test_auroc_label():
    assert auroc_label(0.96) == "Excellent"
    assert auroc_label(0.91) == "Good"
    assert auroc_label(0.85) == "Fair"
    assert auroc_label(0.75) == "Poor"
    assert auroc_label(0.60) == "Inadequate"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests)} tests completed.")
