"""#384: a record must be able to state its own independence, inside the signature.

Before this, `generate_attestation_report()` emitted neither `independence_level`
nor `system_under_test`, the schema did not define them, and only the reference
server supplied them -- server-side, outside the signature. So a file-based record,
which is the exchange mechanism section 7 of the registry contract depends on,
reported its own independence as 'unstated'.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

# Use the shipped inference rather than a hand-written scope: a hand-written one
# drifted from the schema enums the first time this test was run.
from protocol_tests.attestation import (  # noqa: E402
    EVIDENCE_CLASSES,
    INDEPENDENCE_LEVELS,
    _infer_scope,  # noqa: E402
    generate_attestation_report,
    validate_attestation_report,
)

ENTRY = {
    "test_id": "RCL-001", "category": "receipt_claim", "result": "pass",
    "severity": "P1-High", "scope": _infer_scope("RCL-001", "receipt_claim"),
    "timestamp": "2026-08-17T00:00:00+00:00",
}


def _report(**kw):
    return generate_attestation_report([ENTRY], suite="receipt-claim",
                                       harness_version="4.15.0", **kw)


# --- the generator states the fields --------------------------------------

def test_report_states_independence_and_system_under_test():
    r = _report(independence_level="I0", system_under_test="agent-security-harness")
    assert r["independence_level"] == "I0"
    assert r["system_under_test"] == "agent-security-harness"


def test_default_states_no_claim_rather_than_defaulting_to_i0():
    """Defaulting to I0 would require inventing a system under test to attach it
    to, which is the manufactured claim this change removes from the server. An
    absence must stay an absence."""
    r = _report()
    assert "independence_level" not in r
    assert "system_under_test" not in r


def test_i_level_without_system_under_test_is_rejected():
    for lvl in INDEPENDENCE_LEVELS:
        with pytest.raises(ValueError, match="system_under_test is required"):
            _report(independence_level=lvl, system_under_test="")


def test_invalid_levels_and_classes_are_rejected():
    with pytest.raises(ValueError, match="independence_level must be one of"):
        _report(independence_level="I3", system_under_test="x")
    with pytest.raises(ValueError, match="evidence_class must be one of"):
        _report(evidence_class="E9", system_under_test="x")


def test_every_taxonomy_value_is_accepted():
    for lvl in INDEPENDENCE_LEVELS:
        assert _report(independence_level=lvl, system_under_test="x")["independence_level"] == lvl
    for ec in EVIDENCE_CLASSES:
        assert _report(evidence_class=ec, system_under_test="x")["evidence_class"] == ec


# --- the validator enforces the taxonomy rule -----------------------------

def test_validator_flags_a_bare_independence_level():
    r = _report(independence_level="I0", system_under_test="x")
    r.pop("system_under_test")
    errs = validate_attestation_report(r)
    assert any("system_under_test is missing" in e for e in errs), errs


def test_validator_flags_an_invalid_level_that_bypassed_the_generator():
    r = _report(independence_level="I0", system_under_test="x")
    r["independence_level"] = "I7"
    assert any("invalid value" in e for e in errs) if (errs := validate_attestation_report(r)) else False


def test_a_well_formed_report_validates_clean():
    r = _report(evidence_class="E2", independence_level="I0", system_under_test="x")
    errs = [e for e in validate_attestation_report(r) if "NOT SCHEMA-VALIDATED" not in e]
    assert errs == [], errs


# --- the schema carries them ----------------------------------------------

def test_schema_defines_the_fields_and_the_dependency():
    schema = json.loads((REPO / "schemas" / "attestation-report.json").read_text())
    props = schema["properties"]
    assert props["independence_level"]["enum"] == list(INDEPENDENCE_LEVELS)
    assert props["evidence_class"]["enum"] == list(EVIDENCE_CLASSES)
    assert schema["dependentRequired"]["independence_level"] == ["system_under_test"]


def test_schema_version_still_not_bumped_and_required_unchanged():
    """New fields are optional + dependentRequired, so records predating #384 stay
    valid. Adding them to `required` would need a schema_version bump."""
    schema = json.loads((REPO / "schemas" / "attestation-report.json").read_text())
    assert schema["properties"]["schema_version"]["const"] == "1.0.0"
    assert "independence_level" not in schema["required"]


# --- a record can be built with no registry -------------------------------

def test_build_record_performs_no_network_io():
    import inspect

    from protocol_tests import attestation_registry as ar
    src = inspect.getsource(ar.build_record)
    for banned in ("urlopen", "Request(", "resolve_registry_endpoint"):
        assert banned not in src, f"build_record must not do network I/O: found {banned}"


def test_build_record_round_trips_through_the_offline_verifier(tmp_path):
    from protocol_tests.attestation_registry import build_record

    report = _report(evidence_class="E2", independence_level="I0",
                     system_under_test="agent-security-harness")
    rec = build_record(report, server_name="unit test target")
    path = tmp_path / "record.json"
    path.write_text(json.dumps(rec))

    out = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "verify_attestation_record.py"), str(path)],
        capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    # the point of #384: read from the SIGNED location, not 'unstated'
    assert "unstated" not in out.stdout, out.stdout
    assert "signed payload" in out.stdout, out.stdout
    assert "agent-security-harness" in out.stdout, out.stdout


def test_verifier_rejects_a_tampered_record(tmp_path):
    """Negative control. A verifier that only ever passes proves nothing."""
    from protocol_tests.attestation_registry import build_record

    rec = build_record(_report(independence_level="I0", system_under_test="x"),
                       server_name="unit test target")
    rec["payload"]["report"]["summary"]["passed"] = 999
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(rec))

    out = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "verify_attestation_record.py"), str(path)],
        capture_output=True, text=True,
    )
    assert out.returncode == 1, out.stdout
    assert "VERIFICATION FAILED" in out.stdout


# --- the I1 case: a record about someone ELSE's system ---------------------

def _run_verifier(path):
    return subprocess.run(
        [sys.executable, str(REPO / "scripts" / "verify_attestation_record.py"), str(path)],
        capture_output=True, text=True,
    )


def test_committed_i1_record_verifies_and_names_the_other_partys_system():
    """The first I1 record: our independent recomputation of the VERITAS public
    contract. I1 is relative to THEIR system, not ours."""
    rec = REPO / "attestations" / "external" / "2026-08-17-veritas-recomputation-record.json"
    assert rec.exists(), "the I1 record must stay committed"
    report = json.loads(rec.read_text())["payload"]["report"]
    assert report["independence_level"] == "I1"
    assert "veritas-agent-trust-lab" in report["system_under_test"]
    # pinned, so the claim is checkable against a specific baseline
    assert "0f3c71fd" in report["system_under_test"]

    out = _run_verifier(rec)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "independence_level I1" in out.stdout
    assert "NOT produced by the author of that system" in out.stdout


def test_the_three_independence_states_are_distinguishable(tmp_path):
    """I0, I1 and 'no claim' must each print something different. An absence that
    reads like an I0 result is the defect this whole change removes."""
    from protocol_tests.attestation_registry import build_record

    cases = {}
    for label, kw in (
        ("none", {}),
        ("i0", {"independence_level": "I0", "system_under_test": "our own suite"}),
        ("i1", {"independence_level": "I1", "system_under_test": "someone else's system"}),
    ):
        p = tmp_path / f"{label}.json"
        p.write_text(json.dumps(build_record(_report(**kw), server_name="state test")))
        out = _run_verifier(p)
        assert out.returncode == 0, out.stdout
        cases[label] = out.stdout

    assert "makes NO independence claim" in cases["none"]
    assert "independence_level I0" in cases["i0"]
    assert "independence_level I1" in cases["i1"]
    # and the absent case must never be described as a level
    assert "independence_level 'None'" not in cases["none"]
    assert len({cases["none"], cases["i0"], cases["i1"]}) == 3
