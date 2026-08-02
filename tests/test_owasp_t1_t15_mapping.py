"""CI guards for the OWASP Agentic T1-T15 coverage mapping and report.

Spec section 3.4 requires CI to fail when a mapped test id no longer exists, a
module path is wrong, a threat entry is missing, the generated report drifts
from the committed one, a direct entry has no executable evidence, metadata is
missing, evidence is double-counted, or the canonical test count disagrees.

These tests drive the real validator rather than reimplementing its rules, so
the two can never disagree.
"""

from __future__ import annotations

import collections
import pathlib
import subprocess
import sys

import pytest

yaml = pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAPPING = ROOT / "docs/coverage/owasp-agentic-t1-t15.yaml"
REPORT = ROOT / "docs/OWASP-AGENTIC-T1-T15-COVERAGE.md"
VALIDATOR = ROOT / "scripts/validate_owasp_t1_t15_mapping.py"
GENERATOR = ROOT / "scripts/generate_owasp_t1_t15_report.py"

sys.path.insert(0, str(ROOT / "scripts"))


@pytest.fixture(scope="module")
def mapping() -> dict:
    return yaml.safe_load(MAPPING.read_text(encoding="utf-8"))


def test_mapping_and_report_are_committed():
    assert MAPPING.exists(), "the canonical mapping must be committed"
    assert REPORT.exists(), "the generated report must be committed"


def test_validator_passes():
    """The whole rule set, driven through the real validator.

    If this fails, read its output: it names the rule and the offending entry.
    """
    result = subprocess.run(
        [sys.executable, str(VALIDATOR)], capture_output=True, text=True, cwd=ROOT
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_report_matches_freshly_generated_output():
    """Spec 3.4: fail when the committed report differs from generated output."""
    fresh = subprocess.run(
        [sys.executable, str(GENERATOR), "--stdout"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert fresh.returncode == 0, fresh.stderr
    assert fresh.stdout.strip() == REPORT.read_text(encoding="utf-8").strip(), (
        "docs/OWASP-AGENTIC-T1-T15-COVERAGE.md is stale. "
        "Run: python scripts/generate_owasp_t1_t15_report.py"
    )


def test_all_fifteen_threats_present_in_order(mapping):
    assert [t["id"] for t in mapping["threats"]] == [f"T{i}" for i in range(1, 16)]


def test_direct_entries_have_executable_evidence(mapping):
    for t in mapping["threats"]:
        if t["coverage"] != "direct":
            continue
        assert t["evidence"], f"{t['id']} is direct with no evidence"
        for e in t["evidence"]:
            assert e["execution"], f"{t['id']}/{e['test_id']} has no rerun command"
            assert e["attack_path"] and e["assertion"]


def test_evidence_is_not_double_counted(mapping):
    """A test may back several threats but counts once in the headline total."""
    cited = [e["test_id"] for t in mapping["threats"] for e in (t.get("evidence") or [])]
    unique = set(cited)
    assert mapping["assessment"]["unique_mapped_tests"] == len(unique)
    dupes = [k for k, v in collections.Counter(cited).items() if v > 1]
    for d in dupes:
        assert cited.count(d) >= 1  # listing under several threats is allowed


def test_snapshot_metadata_is_present(mapping):
    a = mapping["assessment"]
    assert len(a["git_commit"]) == 40, "commit must be a full 40-char SHA"
    assert a["harness_version"] and a["assessed_at"] and a["total_repository_tests"]
    assert "NOT independent" in a["adjudicated_by"]


def test_assessed_commit_is_reachable_from_head():
    """Every evidence link is pinned to the assessed commit. If that commit is
    not an ancestor of HEAD, all of them 404.

    This is not hypothetical: the first release candidate pinned a commit from a
    branch that was then squash-merged, so the SHA never existed on main. The
    report validated cleanly and every permalink in it was dead.
    """
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if shallow == "true":
        # actions/checkout defaults to fetch-depth: 1, so history does not exist
        # here and absence proves nothing. The owasp-coverage CI job checks out
        # with fetch-depth: 0 precisely so this assertion runs for real there.
        pytest.skip("shallow clone - reachability is enforced by the owasp-coverage job")

    sha = yaml.safe_load(MAPPING.read_text(encoding="utf-8"))["assessment"]["git_commit"]
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=ROOT, capture_output=True
    )
    assert exists.returncode == 0, f"assessed commit {sha} is not in this repository"
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", sha, "HEAD"], cwd=ROOT, capture_output=True
    )
    assert ancestor.returncode == 0, (
        f"assessed commit {sha[:12]} is not an ancestor of HEAD - every evidence "
        "permalink in the report would 404. Re-pin and regenerate before releasing."
    )


def test_canonical_test_count_agrees(mapping):
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts/count_tests.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
    ).stdout
    assert f"Definitive count: {mapping['assessment']['total_repository_tests']}" in out


def test_no_certification_language(mapping):
    banned = [
        "owasp certified",
        "owasp approved",
        "owasp validated",
        "fully mitigates",
        "complete coverage",
        "guarantees security",
    ]
    for path in (MAPPING, REPORT):
        low = path.read_text(encoding="utf-8").lower()
        for phrase in banned:
            assert phrase not in low, f"{path.name} contains {phrase!r}"


def test_report_carries_the_required_disclaimer():
    text = REPORT.read_text(encoding="utf-8")
    assert "does not mean a tested system mitigates the threat" in text
    assert "not a certification or mitigation guarantee" in text
    assert "test capability" in text


def test_t10_and_t15_are_not_promoted_without_a_qualifying_test(mapping):
    """Spec 11: neither may rise above not_evidenced without a real test.

    T10 needs approval-overload / attention-fatigue evidence; approval-boundary
    tests do not qualify. T15 needs agent-to-human manipulation; every candidate
    in this repo runs human-to-agent.
    """
    for tid in ("T10", "T15"):
        t = next(x for x in mapping["threats"] if x["id"] == tid)
        if t["coverage"] != "not_evidenced":
            assert t["evidence"], f"{tid} was promoted with no evidence at all"
            pytest.fail(
                f"{tid} was promoted above not_evidenced. This is allowed only with a "
                "genuinely qualifying test - re-read spec section 11 before changing "
                "this test."
            )


def test_appendix_threats_are_excluded_from_counts(mapping):
    """Guide v1.1 adds T16/T17; they must not move the T1-T15 denominator."""
    appendix = mapping.get("appendix_out_of_scope") or []
    assert [a["id"] for a in appendix] == ["T16", "T17"]
    for a in appendix:
        assert a["coverage"] == "not_assessed"
    assert len(mapping["threats"]) == 15
    report = REPORT.read_text(encoding="utf-8")
    assert "excluded from every count" in report


def test_permissive_oracle_tests_back_no_direct_verdict(mapping):
    """RT tests whose expected_status includes 200 cannot evidence blocking."""
    permissive = set(mapping["oracle_notes"]["status_permissive_tests"])
    assert permissive, "the permissive-oracle list must not be silently emptied"
    for t in mapping["threats"]:
        if t["coverage"] != "direct":
            continue
        for e in t.get("evidence") or []:
            assert e["test_id"] not in permissive, (
                f"{t['id']} is direct on {e['test_id']}, whose oracle cannot "
                "distinguish blocked from allowed"
            )
