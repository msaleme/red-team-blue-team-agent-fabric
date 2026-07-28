"""Regression tests for the exported RCL oracle fixtures.

The point of the fixture file is that somebody else can use it. These tests
check the properties that claim depends on:

1. it regenerates byte-identically (so a diff means a real change);
2. it is self-contained -- every signature verifies using only the public
   keys inside the file, with no import from the harness;
3. the accept cases survive (a fixture set of only negatives lets a
   reject-everything verifier score full marks);
4. no private seed material leaks into it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from protocol_tests import rcl_fixture_export as X

FIXTURE_PATH = Path("fixtures/rcl/rcl-oracle-fixtures.v1.json")


def test_fixture_file_is_committed():
    """The deliverable must exist. This must FAIL, never skip.

    The first version of this suite skipped when the file was absent. A
    blanket `*.json` in .gitignore then dropped the generated fixture from
    the commit, every test skipped, and CI reported green on a PR whose
    entire point was shipping that file (PR #299). A guard that passes when
    the thing it guards is missing is not a guard.
    """
    assert FIXTURE_PATH.exists(), (
        f"{FIXTURE_PATH} is missing. It is the deliverable, not a build "
        f"artifact. Regenerate with `python -m protocol_tests.rcl_fixture_export` "
        f"and ensure .gitignore does not exclude it."
    )


@pytest.fixture(scope="module")
def committed() -> dict:
    assert FIXTURE_PATH.exists(), f"{FIXTURE_PATH} is missing"
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_regenerates_byte_identically(committed):
    """A diff in the committed file must mean a real behavioural change."""
    assert X.serialise(X.build_fixture_set()) == FIXTURE_PATH.read_text(encoding="utf-8")


def test_counts_are_nine_reject_two_accept(committed):
    verdicts = [f["expected"]["verdict"] for f in committed["fixtures"]]
    assert len(verdicts) == 11
    assert verdicts.count("accept") == 2, "the positive controls must survive export"
    assert verdicts.count("reject") == 9


def test_accept_controls_present_by_id(committed):
    accepts = {f["id"] for f in committed["fixtures"]
               if f["expected"]["verdict"] == "accept"}
    assert accepts == {"RCL-008", "RCL-009"}


def test_every_envelope_signature_is_valid(committed):
    """Each vector is envelope-valid; only the substantive claims differ."""
    assert all(f["envelope_valid"] for f in committed["fixtures"])


def test_fixtures_are_self_contained_for_an_outside_verifier(committed):
    """Verify every envelope signature using ONLY the file's own public keys.

    This is the property that makes the export useful to a third party: no
    reference to the harness, its seeds, or its builders.
    """
    from protocol_tests.receipt_claim_harness import _ed25519, _jcs

    emitter_pub = bytes.fromhex(committed["public_keys"]["emitter"])
    for f in committed["fixtures"]:
        receipt = f["receipt"]
        body = {k: v for k, v in receipt.items() if k != "envelope_sig"}
        sig = bytes.fromhex(receipt["envelope_sig"])
        assert _ed25519.verify(emitter_pub, _jcs(body), sig), \
            f"{f['id']} envelope signature did not verify from the exported public key"


def test_claim_family_is_set_for_every_rejection(committed):
    for f in committed["fixtures"]:
        exp = f["expected"]
        if exp["verdict"] == "reject":
            assert exp["claim_family"] in committed["claim_families"], f["id"]
        else:
            assert exp["claim_family"] is None, f["id"]


def test_declared_coverage_gap_is_accurate(committed):
    """The file claims integrity_provenance has no negative vector. Check it."""
    exercised = {f["expected"]["claim_family"] for f in committed["fixtures"]
                 if f["expected"]["verdict"] == "reject"}
    declared = set(committed["coverage_gaps"]["families_with_no_negative_vector"])
    assert declared == set(committed["claim_families"]) - exercised


def test_no_private_key_material_exported(committed):
    """Assert the actual seeds are absent, not that the word 'secret' is.

    The first version grepped for the substring "secret", which broke as soon
    as the file gained a note explaining that these keys are not secret. A
    test that a documentation change can break was testing the wrong thing.
    This checks for the real private seed bytes.
    """
    from protocol_tests.receipt_claim_harness import _SEEDS

    raw = FIXTURE_PATH.read_text(encoding="utf-8")
    for name, seed in _SEEDS.items():
        assert seed.hex() not in raw, f"private seed for {name} leaked into the fixtures"
    assert set(committed["public_keys"]) == {"emitter", "checker", "authz", "exec"}
    for name, hex_pub in committed["public_keys"].items():
        assert hex_pub != _SEEDS[name].hex(), f"{name}: exported key equals the private seed"
