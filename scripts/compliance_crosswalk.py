#!/usr/bin/env python3
"""Compliance framework crosswalk loader and mapper.

Loads crosswalk YAML files and maps harness test results to framework
controls for EU AI Act, ISO 42001, and AIUC-1 compliance reporting.

Tracks GitHub issue #156.

Usage:
    from scripts.compliance_crosswalk import load_crosswalk, apply_crosswalk

    crosswalk = load_crosswalk("eu-ai-act")
    compliance = apply_crosswalk(crosswalk, harness_results)
"""

from __future__ import annotations

import os
from typing import Any

import yaml

CONFIGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "configs")

FRAMEWORK_FILES = {
    "eu-ai-act": "eu_ai_act_mapping.yaml",
    "iso-42001": "iso_42001_mapping.yaml",
    "aiuc-1": "aiuc1_mapping.yaml",
}


def load_crosswalk(framework: str) -> dict[str, Any]:
    """Load a compliance crosswalk YAML file.

    Args:
        framework: Framework identifier (eu-ai-act, iso-42001, aiuc-1).

    Returns:
        Parsed YAML dict.

    Raises:
        ValueError: If framework is unknown.
        FileNotFoundError: If YAML file is missing.
    """
    filename = FRAMEWORK_FILES.get(framework.lower())
    if not filename:
        available = ", ".join(FRAMEWORK_FILES.keys())
        raise ValueError(f"Unknown framework '{framework}'. Available: {available}")

    path = os.path.join(CONFIGS_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Crosswalk file not found: {path}")

    with open(path) as f:
        return yaml.safe_load(f)


def _extract_controls(crosswalk: dict) -> list[dict]:
    """Extract flat list of controls from crosswalk YAML (handles both formats)."""
    controls = []

    # EU AI Act / ISO 42001 format: articles/clauses → controls list
    for section_key in ("articles", "clauses"):
        sections = crosswalk.get(section_key, {})
        for _sec_id, sec_data in sections.items():
            sec_title = sec_data.get("title", _sec_id)
            for ctrl in sec_data.get("controls", []):
                # Copy to avoid mutating the original crosswalk dict
                ctrl_copy = dict(ctrl)
                ctrl_copy["_section"] = sec_title
                controls.append(ctrl_copy)

    # AIUC-1 format: categories → requirements dict
    categories = crosswalk.get("categories", {})
    for _cat_id, cat_data in categories.items():
        cat_name = cat_data.get("name", _cat_id)
        for req_id, req_def in cat_data.get("requirements", {}).items():
            controls.append({
                "id": req_id,
                "description": req_def.get("title", ""),
                "test_ids": req_def.get("test_ids", []),
                "status": req_def.get("status", "UNKNOWN"),
                "gap_notes": req_def.get("gap_notes", ""),
                "_section": cat_name,
            })

    return controls


def apply_crosswalk(
    crosswalk: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Map harness test results to framework controls.

    Args:
        crosswalk: Loaded crosswalk YAML.
        results: List of test result dicts with "test_id" and "passed" keys.

    Returns:
        Compliance summary with per-control status.
    """
    result_by_id = {r.get("test_id", ""): r for r in results if r.get("test_id")}
    controls = _extract_controls(crosswalk)

    control_results = []
    covered = 0
    gaps = 0
    failing = 0

    for ctrl in controls:
        ctrl_id = ctrl.get("id", "?")
        test_ids = ctrl.get("test_ids", [])
        is_gap = ctrl.get("status", "").upper() == "GAP" or not test_ids

        if is_gap:
            control_results.append({
                "control_id": ctrl_id,
                "description": ctrl.get("description", ""),
                "section": ctrl.get("_section", ""),
                "status": "GAP",
                "tests_mapped": 0,
                "tests_run": 0,
                "passed": 0,
                "failed": 0,
                "gap_notes": ctrl.get("gap_notes", ""),
            })
            gaps += 1
            continue

        matched = [t for t in test_ids if t in result_by_id]
        passed = sum(1 for t in matched if result_by_id[t].get("passed", False))
        failed = len(matched) - passed

        if matched and failed == 0:
            status = "PASS"
            covered += 1
        elif failed > 0:
            status = "FAIL"
            failing += 1
        else:
            status = "NO_RESULTS"

        control_results.append({
            "control_id": ctrl_id,
            "description": ctrl.get("description", ""),
            "section": ctrl.get("_section", ""),
            "status": status,
            "tests_mapped": len(test_ids),
            "tests_run": len(matched),
            "passed": passed,
            "failed": failed,
        })

    framework_name = crosswalk.get("framework", crosswalk.get("framework_id", "unknown"))
    total = len(control_results)

    return {
        "framework": framework_name,
        "total_controls": total,
        "covered": covered,
        "gaps": gaps,
        "failing": failing,
        "compliance_rate": round(covered / max(total - gaps, 1), 4),
        "controls": control_results,
    }


def identify_gaps(crosswalk: dict[str, Any], results: list[dict[str, Any]]) -> list[dict]:
    """Identify framework controls with no mapped tests or all-failing tests.

    Returns:
        List of gap dicts with control_id, description, and reason.
    """
    compliance = apply_crosswalk(crosswalk, results)
    return [
        {
            "control_id": c["control_id"],
            "description": c["description"],
            "section": c["section"],
            "reason": "No tests mapped" if c["status"] == "GAP" else (
                "No test results" if c["status"] == "NO_RESULTS" else
                f"{c['failed']} of {c['tests_run']} tests failing"
            ),
        }
        for c in compliance["controls"]
        if c["status"] in ("GAP", "NO_RESULTS", "FAIL")
    ]


def compliance_summary(crosswalk: dict[str, Any], results: list[dict[str, Any]]) -> str:
    """One-line compliance summary for CLI output."""
    c = apply_crosswalk(crosswalk, results)
    return (
        f"{c['framework']}: {c['covered']}/{c['total_controls']} controls covered, "
        f"{c['gaps']} gaps, {c['failing']} failing "
        f"({c['compliance_rate']*100:.0f}% compliance rate)"
    )


def list_frameworks() -> list[str]:
    """Return list of available framework identifiers."""
    return list(FRAMEWORK_FILES.keys())
