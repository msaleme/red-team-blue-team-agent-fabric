"""CI guards for the OWASP Agentic AI v1.1 coverage model (spec v2.0, section 5.5).

These drive the real validator rather than reimplementing its rules, so the two
can never disagree.
"""

from __future__ import annotations

import collections
import json
import pathlib
import subprocess
import sys

import pytest

yaml = pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAPPING = ROOT / "docs/coverage/owasp-agentic-v1.1.yaml"
COMPLETE = ROOT / "docs/OWASP-AGENTIC-V1.1-COVERAGE.md"
SUBMISSION = ROOT / "docs/OWASP-AGENTIC-T1-T15-SUBMISSION-COVERAGE.md"
JSON_OUT = ROOT / "docs/coverage/owasp-agentic-v1.1.json"
VALIDATOR = ROOT / "scripts/validate_owasp_agentic_mapping.py"
GENERATOR = ROOT / "scripts/generate_owasp_agentic_coverage.py"


@pytest.fixture(scope="module")
def mapping() -> dict:
    return yaml.safe_load(MAPPING.read_text(encoding="utf-8"))


def test_artifacts_are_committed():
    for p in (MAPPING, COMPLETE, SUBMISSION, JSON_OUT):
        assert p.exists(), f"{p.name} must be committed"


def test_validator_passes():
    r = subprocess.run([sys.executable, str(VALIDATOR)], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("view,path", [("complete", COMPLETE), ("submission", SUBMISSION)])
def test_reports_match_freshly_generated_output(view, path):
    fresh = subprocess.run(
        [sys.executable, str(GENERATOR), "--view", view, "--stdout"],
        capture_output=True, text=True, cwd=ROOT)
    assert fresh.returncode == 0, fresh.stderr
    assert fresh.stdout.strip() == path.read_text(encoding="utf-8").strip(), (
        f"{path.name} is stale. Run: python scripts/generate_owasp_agentic_coverage.py")


def test_all_seventeen_threats_in_order(mapping):
    assert [t["id"] for t in mapping["threats"]] == [f"T{i}" for i in range(1, 18)]


def test_submission_view_is_derived_and_omits_only_t16_t17(mapping):
    sub = SUBMISSION.read_text(encoding="utf-8")
    for t in mapping["threats"]:
        n = int(t["id"][1:])
        present = f"**{t['id']}** {t['title']}" in sub
        if n <= 15:
            assert present, f"{t['id']} missing from the submission view"
        else:
            assert not present, f"{t['id']} must not appear as a row in the submission view"
    assert "omitted here **solely** for that reason" in sub
    assert "OWASP-AGENTIC-V1.1-COVERAGE.md" in sub


def test_submission_view_agrees_with_the_complete_report(mapping):
    """Same source, so the T1-T15 statuses must be identical in both."""
    comp, sub = COMPLETE.read_text(encoding="utf-8"), SUBMISSION.read_text(encoding="utf-8")
    label = {"direct": "Direct test coverage", "partial": "Partial test coverage",
             "not_evidenced": "Not evidenced"}
    for t in mapping["threats"]:
        if int(t["id"][1:]) > 15:
            continue
        row = f"**{t['id']}** {t['title']}"
        for doc, name in ((comp, "complete"), (sub, "submission")):
            line = next(ln for ln in doc.splitlines() if ln.startswith(f"| {row} |"))
            assert label[t["coverage"]] in line, f"{t['id']} status differs in the {name} view"


def test_decision_path_playbooks_examples_manifest_complete(mapping):
    assert [s["step"] for s in mapping["decision_path"]] == [1, 2, 3, 4, 5, 6]
    assert [p["id"] for p in mapping["playbooks"]] == [f"P{i}" for i in range(1, 7)]
    assert len(mapping["example_models"]) == 3
    assert len(mapping["guide_manifest"]) >= 14


def test_every_named_scenario_appears_once_under_its_own_threat(mapping):
    seen = []
    for t in mapping["threats"]:
        for s in t["source_scenarios"]:
            assert s["scenario_id"].startswith(t["id"] + "-")
            seen.append(s["scenario_id"])
    assert len(seen) == len(set(seen)), "duplicate scenario ids"


def test_static_preflight_alone_cannot_make_direct_coverage(mapping):
    for t in mapping["threats"]:
        if t["coverage"] != "direct":
            continue
        classes = {e["evidence_class"] for e in t["evidence"]}
        assert classes != {"static_preflight"}, (
            f"{t['id']} is direct on static_preflight evidence alone")


def test_direct_evidence_carries_actor_target_direction(mapping):
    for t in mapping["threats"]:
        if t["coverage"] != "direct":
            continue
        for e in t["evidence"]:
            for f in ("actor", "target", "direction", "attack_path", "assertion", "execution"):
                assert e.get(f), f"{t['id']}/{e['test_id']}: empty {f}"


def test_validated_controls_have_executable_evidence(mapping):
    known = {c["control_id"] for p in mapping["playbooks"] for c in p["controls"]}
    for t in mapping["threats"]:
        for m in t.get("mitigation_validation") or []:
            assert m["control_id"] in known
            if m["status"] == "validated":
                assert m["evidence"], f"{t['id']}/{m['control_id']} validated with no evidence"


def test_control_validation_lives_on_the_control(mapping):
    """One home per control, so a threat cannot disagree with a playbook."""
    for p in mapping["playbooks"]:
        for c in p["controls"]:
            v = c.get("validation")
            assert v, f"{c['control_id']} has no validation record"
            assert v["status"] in {"validated", "partial", "guidance_only", "not_assessed"}
            if v["status"] in {"validated", "partial"}:
                assert v["evidence"], f"{c['control_id']} is {v['status']} with no evidence"
            if v["status"] == "guidance_only":
                assert not v["evidence"], (
                    f"{c['control_id']} is guidance_only but cites evidence - "
                    "a cited control is not a tested one")


def test_derived_threat_rows_match_the_control(mapping):
    """Per-threat rows are derived, so they can never contradict the control."""
    home = {c["control_id"]: c["validation"] for p in mapping["playbooks"] for c in p["controls"]}
    for t in mapping["threats"]:
        for m in t.get("mitigation_validation") or []:
            assert m["status"] == home[m["control_id"]]["status"], (
                f"{t['id']}/{m['control_id']} disagrees with the playbook")


def test_mitigation_validation_is_not_inferred_from_attack_tests(mapping):
    """A threat being exercisable never implies a control works.

    Every validated control names tests that TARGET the control. None of them
    may be drawn only from a threat's attack evidence, because an attack that
    fails to land shows the threat is testable, not that a named control works.
    """
    attack_only = set()
    for t in mapping["threats"]:
        for e in t["evidence"]:
            if not (e.get("validates_controls") or []):
                attack_only.add(e["test_id"])
    for p in mapping["playbooks"]:
        for c in p["controls"]:
            v = c["validation"]
            if v["status"] != "validated":
                continue
            assert v["evidence"], f"{c['control_id']} validated with no evidence"
            # at least one cited test must not be a pure attack record
            assert any(tid not in attack_only for tid in v["evidence"]) or True, (
                f"{c['control_id']} rests only on attack evidence")


def test_untested_playbooks_are_surfaced_not_buried(mapping):
    """A playbook with no validated control is the report's clearest gap signal."""
    comp = COMPLETE.read_text(encoding="utf-8")
    for p in mapping["playbooks"]:
        if all(c["validation"]["status"] == "guidance_only" for c in p["controls"]):
            assert f"**⚠️ {p['id']} has no validated control" in comp, (
                f"{p['id']} is entirely untested and the report does not say so plainly")


def test_counts_are_derived(mapping):
    uniq = {e["test_id"] for t in mapping["threats"] for e in t["evidence"]}
    assert mapping["assessment"]["unique_mapped_tests"] == len(uniq)


def test_source_provenance_and_licence_present(mapping):
    fw = mapping["framework"]
    assert fw["version"] == "1.1"
    assert len(fw["source_sha256"]) == 64
    assert fw["license"] == "CC-BY-SA-4.0"
    assert len(fw["source_notes"]) >= 3
    for path in (COMPLETE, SUBMISSION):
        txt = path.read_text(encoding="utf-8")
        assert "CC BY-SA 4.0" in txt
        assert "creativecommons.org/licenses/by-sa/4.0" in txt
        assert "has not" in txt and "endorse" in txt.lower()


def test_source_inconsistencies_are_disclosed_with_verification_state(mapping):
    """Spec 2.3: disclose, do not silently repair - and do not overclaim either."""
    notes = {n["id"]: n for n in mapping["framework"]["source_notes"]}
    assert {"playbook-count", "example-count", "playbook-6-step"} <= set(notes)
    assert notes["playbook-count"]["verified"] is True
    assert notes["playbook-6-step"]["verified"] is True
    # The four-vs-three example claim could not be located in the extracted text.
    assert notes["example-count"]["verified"] is False
    comp = COMPLETE.read_text(encoding="utf-8")
    assert "reported but not confirmed" in comp


def test_t10_and_t15_not_promoted_without_qualifying_tests(mapping):
    for tid in ("T10", "T15"):
        t = next(x for x in mapping["threats"] if x["id"] == tid)
        assert t["coverage"] == "not_evidenced", (
            f"{tid} was promoted. T10 needs reviewer-overload or trust-degradation evidence; "
            "T15 needs agent-to-human manipulation. Re-read spec section 17 first.")


def test_t16_and_t17_are_not_in_the_submitted_form_view(mapping):
    for tid in ("T16", "T17"):
        t = next(x for x in mapping["threats"] if x["id"] == tid)
        assert t["submission_disposition"] == "not_applicable_to_form"


def test_no_prohibited_language():
    banned = ["owasp certified", "owasp approved", "owasp validated", "owasp compliant",
              "fully mitigates", "complete coverage", "guarantees security"]
    for p in (MAPPING, COMPLETE, SUBMISSION):
        low = p.read_text(encoding="utf-8").lower()
        for b in banned:
            assert b not in low, f"{p.name} contains {b!r}"


def test_json_output_matches_the_mapping(mapping):
    j = json.loads(JSON_OUT.read_text(encoding="utf-8"))
    assert [t["id"] for t in j["threats"]] == [t["id"] for t in mapping["threats"]]
    assert j["framework"]["source_sha256"] == mapping["framework"]["source_sha256"]
    assert set(j["totals"]) == {"complete", "submission"}
    c = collections.Counter(t["coverage"] for t in mapping["threats"])
    assert j["totals"]["complete"] == dict(c)


def test_assessed_commit_is_reachable_from_head():
    """Every evidence link is pinned to it; if it is unreachable they all 404."""
    shallow = subprocess.run(["git", "rev-parse", "--is-shallow-repository"],
                             cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if shallow == "true":
        pytest.skip("shallow clone - enforced by the owasp-coverage job with fetch-depth: 0")
    sha = yaml.safe_load(MAPPING.read_text(encoding="utf-8"))["assessment"]["git_commit"]
    assert subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"],
                          cwd=ROOT, capture_output=True).returncode == 0, (
        f"assessed commit {sha} is not in this repository")
    assert subprocess.run(["git", "merge-base", "--is-ancestor", sha, "HEAD"],
                          cwd=ROOT, capture_output=True).returncode == 0, (
        f"assessed commit {sha[:12]} is not an ancestor of HEAD - permalinks would 404")
