"""Conformance tests for the attestation registry server contract.

Tracks GitHub issue #333. Asserts docs/ATTESTATION-REGISTRY-SERVER-CONTRACT.md
against scripts/registry_reference_server.py and
scripts/verify_attestation_record.py.

The reference server is the executable form of the contract, so an untested
reference is a contract nothing checks. Each test names the contract section it
pins.
"""

import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.registry_reference_server import (  # noqa: E402
    CLAIM_LABEL,
    Rejected,
    Store,
    build_server,
    canonical_bytes,
    find_sensitive_keys,
    load_schema_required,
    validate_and_build,
)

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

REQUIRED = load_schema_required()


def _report():
    return {
        "schema_version": "1.0",
        "harness_version": "4.15.0",
        "suite": "mcp",
        "timestamp": "2026-08-14T12:00:00Z",
        "summary": {"total": 1, "passed": 1, "failed": 0},
        "entries": [{"id": "MCP-001", "result": "pass"}],
    }


def _keypair():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return key, pub


def _envelope(payload_overrides=None, signed=True, key=None, pub=None):
    payload = {
        "server_name": "demo-server",
        "contact": None,
        "report": _report(),
        "published_at": "2026-08-14T12:00:00Z",
    }
    payload.update(payload_overrides or {})
    raw = canonical_bytes(payload)
    envelope = {
        "payload": payload,
        "signature": "00" * 64,
        "verification_hash": hashlib.sha256(raw).hexdigest(),
    }
    if signed:
        if key is None:
            key, pub = _keypair()
        envelope["envelope_version"] = "2"
        envelope["signature"] = key.sign(raw).hex()
        envelope["public_key"] = pub
        envelope["public_key_fingerprint"] = hashlib.sha256(pub.encode()).hexdigest()[:16]
    return envelope


def _resign(envelope, key):
    raw = canonical_bytes(envelope["payload"])
    envelope["verification_hash"] = hashlib.sha256(raw).hexdigest()
    envelope["signature"] = key.sign(raw).hex()
    return envelope


# --- Contract 4.1: canonicalization -----------------------------------------

def test_canonical_bytes_use_default_separators_not_compact():
    """4.1. The pinned basis is the ONLY reason an independent reimplementation
    can verify a signature. Compact separators produce different bytes."""
    payload = {"b": 1, "a": 2}
    assert canonical_bytes(payload) == b'{"a": 2, "b": 1}'
    assert canonical_bytes(payload) != json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()


def test_canonical_bytes_sort_keys():
    assert canonical_bytes({"z": 1, "a": 2}) == canonical_bytes({"a": 2, "z": 1})


# --- Contract 5: the eight POST obligations, in order ------------------------

def test_missing_payload_is_rejected():
    """5.1 shape."""
    with pytest.raises(Rejected) as exc:
        validate_and_build({"signature": "x", "verification_hash": "y"}, REQUIRED)
    assert exc.value.status == 400


@pytest.mark.parametrize("name", ["has/slash", "semi;colon", "", "a" * 201])
def test_server_name_pattern_is_reenforced_server_side(name):
    """5.2. A server that trusts the client's validator trusts an
    unauthenticated party."""
    key, pub = _keypair()
    env = _resign(_envelope(signed=True, key=key, pub=pub) | {}, key)
    env["payload"]["server_name"] = name
    _resign(env, key)
    with pytest.raises(Rejected) as exc:
        validate_and_build(env, REQUIRED)
    assert exc.value.status == 400


def test_invalid_contact_is_rejected():
    """5.2."""
    key, pub = _keypair()
    env = _envelope({"contact": "not-an-email"}, key=key, pub=pub)
    _resign(env, key)
    with pytest.raises(Rejected) as exc:
        validate_and_build(env, REQUIRED)
    assert exc.value.status == 400


def test_tampered_payload_fails_the_hash_check():
    """5.3. Mutating the payload after signing must not survive."""
    env = _envelope()
    env["payload"]["server_name"] = "tampered-after-signing"
    with pytest.raises(Rejected) as exc:
        validate_and_build(env, REQUIRED)
    assert exc.value.status == 400
    assert "canonical payload bytes" in exc.value.reason


def test_sensitive_key_in_report_is_rejected_with_its_path():
    """5.4. Defense in depth: its presence means a non-conforming client."""
    key, pub = _keypair()
    env = _envelope(key=key, pub=pub)
    env["payload"]["report"]["entries"][0]["target_url"] = "https://internal.example"
    _resign(env, key)
    with pytest.raises(Rejected) as exc:
        validate_and_build(env, REQUIRED)
    assert exc.value.status == 422
    assert "target_url" in exc.value.reason


@pytest.mark.parametrize("key_name", ["target_url", "auth_token", "raw_response", "hostname"])
def test_sensitive_scan_covers_exact_and_substring_matches(key_name):
    """5.4. Mirrors the client's _is_sensitive_key, including substrings."""
    assert find_sensitive_keys({key_name: "x"}) == [f"report.{key_name}"]


def test_schema_required_key_missing_is_rejected():
    """5.5. Uses schemas/attestation-report.json rather than a local copy (R3)."""
    key, pub = _keypair()
    env = _envelope(key=key, pub=pub)
    del env["payload"]["report"]["entries"]
    _resign(env, key)
    with pytest.raises(Rejected) as exc:
        validate_and_build(env, REQUIRED)
    assert exc.value.status == 422
    assert "entries" in exc.value.reason


def test_required_keys_are_read_from_the_shipped_schema():
    """R3. The server must not fork the schema."""
    assert "entries" in REQUIRED and "summary" in REQUIRED


def test_valid_signature_marks_the_record_verifiable():
    """5.6."""
    record = validate_and_build(_envelope(), REQUIRED)
    assert record["signature_verifiable"] is True


def test_signature_over_different_bytes_is_rejected():
    """5.6. A signature valid for some other payload must not pass."""
    key, pub = _keypair()
    env = _envelope(key=key, pub=pub)
    env["signature"] = key.sign(b"a different message").hex()
    with pytest.raises(Rejected) as exc:
        validate_and_build(env, REQUIRED)
    assert exc.value.status == 400


def test_public_key_not_matching_its_fingerprint_is_rejected():
    """5.6."""
    _, other_pub = _keypair()
    env = _envelope()
    env["public_key"] = other_pub
    with pytest.raises(Rejected) as exc:
        validate_and_build(env, REQUIRED)
    assert exc.value.status == 400
    assert "fingerprint" in exc.value.reason


def test_unsigned_envelope_is_stored_as_not_verifiable():
    """4.2. The currently shipping client sends no public key. The record must
    say so about itself rather than omitting the question."""
    record = validate_and_build(_envelope(signed=False), REQUIRED)
    assert record["signature_verifiable"] is False
    assert record["envelope_version"] == "1"


def test_submitter_cannot_assert_an_independence_level():
    """1 and 7. Independence is not a flag an operator or submitter can set."""
    env = _envelope()
    env["independence_level"] = "I2"
    with pytest.raises(Rejected) as exc:
        validate_and_build(env, REQUIRED)
    assert exc.value.status == 422


def test_record_is_always_i0_with_a_named_system_under_test():
    """1. An I-level with no named system under test is not a claim."""
    record = validate_and_build(_envelope(), REQUIRED)
    assert record["independence_level"] == "I0"
    assert record["system_under_test"] == "demo-server"


def test_claim_label_is_not_stronger_than_tested_with():
    """1. 'Verified'/'certified' would present self-authored evidence as review."""
    record = validate_and_build(_envelope(), REQUIRED)
    assert record["claim_label"] == CLAIM_LABEL
    assert "Tested with" in CLAIM_LABEL
    for forbidden in ("verified", "certified", "approved", "confirmed"):
        assert forbidden not in CLAIM_LABEL.lower()


def test_id_is_derivable_from_the_record():
    """5.8. Matches the client's fallback when a response omits 'id'."""
    env = _envelope()
    record = validate_and_build(env, REQUIRED)
    assert record["id"] == env["verification_hash"][:12]


# --- Contract 6: GET obligations --------------------------------------------

def test_payload_is_stored_verbatim_so_the_signature_still_verifies():
    """6. A server that normalizes the payload destroys every downstream check."""
    env = _envelope()
    record = validate_and_build(env, REQUIRED)
    assert canonical_bytes(record["payload"]) == canonical_bytes(env["payload"])
    assert hashlib.sha256(canonical_bytes(record["payload"])).hexdigest() == (
        record["verification_hash"]
    )


def test_received_at_is_present_and_distinct_from_the_signed_timestamp():
    """6. received_at is an operator claim outside the signature."""
    record = validate_and_build(_envelope(), REQUIRED)
    assert record["received_at"]
    assert "received_at" not in record["payload"]


def test_store_is_idempotent_on_verification_hash():
    """5. Two identical submissions are one record."""
    store = Store()
    record = validate_and_build(_envelope(), REQUIRED)
    store.put(record)
    assert store.existing_id_for(record["verification_hash"]) == record["id"]


# --- Contract 9: verification without trusting the operator ------------------

def _verify(record):
    script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts", "verify_attestation_record.py",
    )
    return subprocess.run(
        [sys.executable, script, "-"], input=json.dumps(record),
        capture_output=True, text=True,
    )


def test_signed_record_verifies_offline():
    """9. Steps 1-4 pass with no call back to the registry."""
    result = _verify(validate_and_build(_envelope(), REQUIRED))
    assert result.returncode == 0, result.stdout
    assert "Ed25519 signature verifies" in result.stdout


def test_unsigned_record_cannot_be_verified_and_says_why():
    """4.2. The gap in the shipping client, asserted rather than described."""
    result = _verify(validate_and_build(_envelope(signed=False), REQUIRED))
    assert result.returncode == 1
    assert "CANNOT be checked" in result.stdout


def test_verifier_states_that_i0_proves_nothing_about_the_target():
    """9 step 6. The step most likely skipped after four passing checks."""
    result = _verify(validate_and_build(_envelope(), REQUIRED))
    assert "NOTHING about the target" in result.stdout


def test_verifier_rejects_a_record_whose_payload_was_swapped():
    """9. The operator-tampering case R2 exists to defeat."""
    record = validate_and_build(_envelope(), REQUIRED)
    record["payload"]["server_name"] = "operator-substituted"
    result = _verify(record)
    assert result.returncode == 1


# --- Contract 3: the wire, end to end ----------------------------------------

@pytest.fixture
def live_server():
    httpd = build_server(0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _post(base, envelope):
    req = urllib.request.Request(
        base, data=json.dumps(envelope).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_post_then_get_round_trip(live_server):
    """3. The three endpoints the shipping client already calls."""
    status, body = _post(live_server, _envelope())
    assert status == 201
    record = json.loads(urllib.request.urlopen(f"{live_server}/{body['id']}").read())
    assert record["id"] == body["id"]
    assert record["independence_level"] == "I0"
    assert _verify(record).returncode == 0


def test_repost_returns_the_same_id(live_server):
    envelope = _envelope()
    first = _post(live_server, envelope)
    second = _post(live_server, envelope)
    assert first[1]["id"] == second[1]["id"]
    assert second[0] == 200


def test_badge_is_served_and_carries_the_bounded_claim(live_server):
    _, body = _post(live_server, _envelope())
    with urllib.request.urlopen(f"{live_server}/badge/{body['id']}") as resp:
        svg = resp.read().decode()
    assert CLAIM_LABEL in svg
    assert "Verified by" not in svg


def test_registry_id_pattern_is_enforced_on_get(live_server):
    """3. Path-traversal shaped ids are rejected before lookup."""
    req = urllib.request.Request(f"{live_server}/..%2Fetc", method="GET")
    try:
        status = urllib.request.urlopen(req, timeout=10).status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status in (400, 404)


def test_unknown_id_is_404(live_server):
    try:
        status = urllib.request.urlopen(f"{live_server}/deadbeef1234", timeout=10).status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 404

# --- Contract 4.2: the client half ------------------------------------------

def test_client_emits_envelope_v2_carrying_the_public_key(monkeypatch, tmp_path):
    """#371. v1 sent only sha256(pub)[:16], so no third party could check the
    signature and the verification property the docs promise was unreachable."""
    import protocol_tests.attestation_registry as reg

    captured = {}

    class _Resp:
        @staticmethod
        def read():
            return json.dumps({"id": "abc123"}).encode()

    def _fake_urlopen(req, timeout=15):
        captured["body"] = json.loads(req.data.decode())
        return _Resp()

    monkeypatch.setenv("AGENT_SECURITY_REGISTRY_URL", "https://registry.invalid")
    monkeypatch.setattr(reg, "urlopen", _fake_urlopen)
    reg.publish_attestation(_report(), server_name="probe")

    body = captured["body"]
    assert body["envelope_version"] == "2"
    assert body["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    assert hashlib.sha256(body["public_key"].encode()).hexdigest()[:16] == (
        body["public_key_fingerprint"]
    ), "fingerprint must match the key it now travels with"


def test_a_record_from_the_real_client_verifies_offline(monkeypatch):
    """The whole point of #371: the round trip a third party actually performs."""
    import protocol_tests.attestation_registry as reg

    captured = {}

    class _Resp:
        @staticmethod
        def read():
            return json.dumps({"id": "abc123"}).encode()

    def _fake_urlopen(req, timeout=15):
        captured["body"] = json.loads(req.data.decode())
        return _Resp()

    monkeypatch.setenv("AGENT_SECURITY_REGISTRY_URL", "https://registry.invalid")
    monkeypatch.setattr(reg, "urlopen", _fake_urlopen)
    reg.publish_attestation(_report(), server_name="probe")

    record = validate_and_build(captured["body"], REQUIRED)
    assert record["signature_verifiable"] is True
    assert record["envelope_version"] == "2"
    assert _verify(record).returncode == 0
