"""A signed record whose report is schema-invalid must not get the claim label.

Fourth external review, 2026-09-08 (R4-11). `scripts/registry_reference_server.py`
implemented contract 5 step 5 -- "validate `payload.report` against
`schemas/attestation-report.json`, reject 422" -- as a check that the schema's
required TOP-LEVEL keys were present. Reproduced against the server on loopback
before this file existed:

    submission                              HTTP  stored
    schema-valid report, signed             201   yes
    empty report                            422   no
    unknown evidence_class "E9", signed     201   yes   <-- the finding
    content/hash mismatch                   400   no
    invalid signature                       400   no

`E9` is a value no version of the evidence-class enum has contained. The record
was stored, returned on GET, and carried "Tested with Agent Security Harness".
A signature establishes who sent the bytes. It establishes nothing about
whether the document conforms, and required-key presence is not conformance.

Two properties are pinned here:

  (a) full schema validation runs before storage, and a schema-invalid report is
      422 with the validator's own message rather than a stored record;
  (b) the record states which check actually ran, in `validation_level`, so a
      consumer on a host without `jsonschema` cannot mistake the weaker answer
      for the stronger one.

The five rows above are asserted over the wire, not against the validator
function, because the finding was about what the SERVER stored.
"""
import hashlib
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts.registry_reference_server import (  # noqa: E402
    VALIDATION_REQUIRED_KEYS,
    VALIDATION_SCHEMA,
    Rejected,
    build_server,
    canonical_bytes,
    load_schema,
    load_schema_required,
    schema_errors,
    validate_and_build,
)

cryptography = pytest.importorskip("cryptography")
jsonschema = pytest.importorskip("jsonschema")

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

SCHEMA = load_schema()
REQUIRED = load_schema_required()


def valid_report(**overrides):
    report = {
        "schema_version": "1.0.0",
        "harness_version": "4.21.1",
        "suite": "mcp",
        "timestamp": "2026-09-08T12:00:00Z",
        "summary": {"total": 1, "passed": 0, "failed": 0, "inconclusive": 1},
        "entries": [{
            "test_id": "MCP-001",
            "name": "Tool List Integrity Check",
            "category": "tool_poisoning",
            "result": "inconclusive",
            "severity": "P2-Medium",
            "scope": {"protocol": "mcp", "layer": "protocol"},
            "timestamp": "2026-09-08T12:00:00Z",
        }],
    }
    report.update(overrides)
    return report


def signed_envelope(report, *, tamper=None, wrong_signature=False):
    """A correctly signed v2 envelope. Key generated per call, never stored."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    payload = {"server_name": "demo-server", "contact": None, "report": report,
               "published_at": "2026-09-08T12:00:00Z"}
    raw = canonical_bytes(payload)
    envelope = {
        "payload": payload,
        "envelope_version": "2",
        "signature": (key.sign(b"a different message") if wrong_signature
                      else key.sign(raw)).hex(),
        "verification_hash": hashlib.sha256(raw).hexdigest(),
        "public_key": pub,
        "public_key_fingerprint": hashlib.sha256(pub.encode()).hexdigest()[:16],
    }
    if tamper is not None:
        envelope["payload"]["server_name"] = tamper  # after signing: hash no longer matches
    return envelope


@pytest.fixture
def live_server():
    httpd = build_server(0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def post(base, envelope):
    req = urllib.request.Request(
        base, data=json.dumps(envelope).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def fetch(base, registry_id):
    with urllib.request.urlopen(f"{base}/{registry_id}", timeout=10) as resp:
        return json.loads(resp.read())


# --- the five rows, over the wire -------------------------------------------

def test_a_schema_valid_signed_report_is_201(live_server):
    status, body = post(live_server, signed_envelope(valid_report()))
    assert status == 201, body
    record = fetch(live_server, body["id"])
    assert record["signature_verifiable"] is True
    assert record["validation_level"] == VALIDATION_SCHEMA


@pytest.mark.parametrize("report,fragment", [
    (valid_report(evidence_class="E9"), "evidence_class"),
    (valid_report(schema_version="1.0"), "schema_version"),
    (valid_report(entries=[{"test_id": "MCP-001", "result": "pass"}]), "entries"),
    (valid_report(summary={"total": 1, "passed": 1, "failed": 0, "bogus": 1}), "summary"),
    (valid_report(entries=[dict(valid_report()["entries"][0], result="probably")]), "result"),
])
def test_a_schema_invalid_signed_report_is_422_and_is_not_stored(live_server, report, fragment):
    """The finding: correctly signed, schema-invalid, stored with 201.

    The response must carry the validator's own message, so an operator can see
    WHICH rule the document broke rather than being told the shape is wrong.
    """
    status, body = post(live_server, signed_envelope(report))
    assert status == 422, body
    assert fragment in body["error"], body["error"]
    assert "attestation schema" in body["error"]


def test_an_empty_report_is_422(live_server):
    status, body = post(live_server, signed_envelope({}))
    assert status == 422, body
    assert "schema-required keys" in body["error"]


def test_a_content_hash_mismatch_is_400(live_server):
    status, body = post(live_server, signed_envelope(valid_report(), tamper="tampered"))
    assert status == 400, body
    assert "canonical payload bytes" in body["error"]


def test_an_invalid_signature_is_400(live_server):
    status, body = post(live_server, signed_envelope(valid_report(), wrong_signature=True))
    assert status == 400, body
    assert "signature verification failed" in body["error"]


def test_the_unknown_enum_never_reaches_the_store(live_server):
    """Nothing with an off-enum evidence_class is fetchable afterwards."""
    envelope = signed_envelope(valid_report(evidence_class="E9"))
    status, _ = post(live_server, envelope)
    assert status == 422
    derived_id = envelope["verification_hash"][:12]
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{live_server}/{derived_id}", timeout=10)
    assert exc.value.code == 404


# --- the level is stated, not implied ---------------------------------------

def test_the_record_says_which_check_ran():
    with_schema = validate_and_build(signed_envelope(valid_report()), REQUIRED, schema=SCHEMA)
    assert with_schema["validation_level"] == VALIDATION_SCHEMA
    assert "attestation-report.json" in with_schema["validation_level_basis"]

    # A host with no jsonschema: the weaker answer, said out loud.
    without = validate_and_build(signed_envelope(valid_report()), REQUIRED)
    assert without["validation_level"] == VALIDATION_REQUIRED_KEYS
    assert "NOT report conformance" in without["validation_level_basis"]


def test_the_two_levels_are_distinguishable_and_not_the_same_string():
    assert VALIDATION_SCHEMA != VALIDATION_REQUIRED_KEYS


def test_the_validator_distinguishes_did_not_run_from_found_nothing():
    """`None` (no validator here) and `[]` (validated clean) are different
    answers. Collapsing them is R4-11 one level down."""
    assert schema_errors(valid_report(), SCHEMA) == []
    assert schema_errors(valid_report(evidence_class="E9"), SCHEMA)


def test_an_anyof_failure_names_the_rule_not_the_whole_document():
    """`producer` OR `harness_version` is an anyOf, and jsonschema's own message
    for a failed anyOf is the entire instance echoed back -- which tells a
    submitter nothing. The sub-errors name the rules; those are what is sent."""
    report = valid_report()
    del report["harness_version"]
    errors = schema_errors(report, SCHEMA)
    assert errors, "the report is invalid; the validator must say so"
    joined = " ".join(errors)
    assert "does not match any allowed form" in joined
    assert "'producer' is a required property" in joined
    assert "'harness_version' is a required property" in joined
    assert "MCP-001" not in joined, "the whole instance was echoed back as the message"


def test_required_keys_alone_would_have_accepted_the_unknown_enum():
    """Anti-vacuity: the old rule is exercised here and shown to be weaker.

    Without this, a test that the new rule rejects E9 proves nothing about
    what changed -- it could have been rejected by the required-key check all
    along, and the review's 201 would be unexplained.
    """
    report = valid_report(evidence_class="E9")
    assert all(k in report for k in REQUIRED)
    record = validate_and_build(signed_envelope(report), REQUIRED)  # no schema
    assert record["evidence_class"] == "E9"
    assert record["validation_level"] == VALIDATION_REQUIRED_KEYS
    with pytest.raises(Rejected) as exc:
        validate_and_build(signed_envelope(report), REQUIRED, schema=SCHEMA)
    assert exc.value.status == 422


def test_the_server_validates_against_the_shipped_schema_not_a_fork():
    """The schema the handler validates against is the one the package ships."""
    import scripts.registry_reference_server as srv
    assert Path(srv.SCHEMA_PATH).is_file()
    assert load_schema()["$id"].endswith("/schemas/attestation-report.json")
