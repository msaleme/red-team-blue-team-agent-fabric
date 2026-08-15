#!/usr/bin/env python3
"""Verify an attestation registry record without trusting the registry (#333).

Implements section 9 of docs/ATTESTATION-REGISTRY-SERVER-CONTRACT.md. Steps 1-4
are checks. Steps 5 and 6 are printed as statements, because neither is something
this script -- or any registry -- can decide for you.

    # from a file
    python3 scripts/verify_attestation_record.py record.json

    # from a registry you were given a link to
    curl -s "$AGENT_SECURITY_REGISTRY_URL/<id>" | python3 scripts/verify_attestation_record.py -

Exit status is 0 only when every applicable check passes. A record with no
public_key cannot be verified at all and exits non-zero: see contract 4.2.
"""
from __future__ import annotations

import hashlib
import json
import sys

try:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    _CRYPTO = True
except ImportError:  # pragma: no cover - environment dependent
    _CRYPTO = False

OK, BAD, NOTE = "PASS", "FAIL", "NOTE"


def canonical_bytes(payload: dict) -> bytes:
    """Contract 4.1: sort_keys, DEFAULT separators. Not compact. Not JCS."""
    return json.dumps(payload, sort_keys=True).encode()


def line(status: str, text: str) -> None:
    print(f"  [{status}] {text}")


def verify(record: dict) -> bool:
    failures = 0
    payload = record.get("payload")
    if not isinstance(payload, dict):
        line(BAD, "record has no 'payload' object; nothing to verify")
        return False

    raw = canonical_bytes(payload)

    # Step 1-2: internal consistency
    digest = hashlib.sha256(raw).hexdigest()
    claimed = record.get("verification_hash")
    if digest == claimed:
        line(OK, f"verification_hash matches the canonical payload bytes ({digest[:16]}...)")
    else:
        line(BAD, f"verification_hash mismatch: computed {digest[:16]}..., record claims "
                  f"{str(claimed)[:16]}...")
        failures += 1

    # Step 3: key matches its advertised fingerprint
    public_key = record.get("public_key")
    fingerprint = record.get("public_key_fingerprint")
    if public_key and fingerprint:
        actual = hashlib.sha256(public_key.encode()).hexdigest()[:16]
        if actual == fingerprint:
            line(OK, f"public_key matches public_key_fingerprint ({fingerprint})")
        else:
            line(BAD, f"public_key_fingerprint mismatch: computed {actual}, record claims "
                      f"{fingerprint}")
            failures += 1

    # Step 4: the signature itself
    signature = record.get("signature")
    if not public_key:
        line(BAD, "record carries no 'public_key', so the signature CANNOT be checked. "
                  "Only the registry operator's word supports this record. See contract 4.2.")
        failures += 1
    elif not signature:
        line(BAD, "record carries no 'signature'")
        failures += 1
    elif not _CRYPTO:
        line(BAD, "'cryptography' is not installed, so the signature was not checked. "
                  "Install it rather than treating an unchecked signature as valid.")
        failures += 1
    else:
        try:
            load_pem_public_key(public_key.encode()).verify(bytes.fromhex(signature), raw)
            line(OK, "Ed25519 signature verifies over the canonical payload bytes")
        except (InvalidSignature, ValueError) as exc:
            line(BAD, f"Ed25519 signature verification failed: {exc}")
            failures += 1

    # Step 5: key-to-identity binding, which no registry can supply
    line(NOTE, "key-to-identity binding is OUT OF SCOPE. The checks above prove a holder of "
               "this key signed this payload. They do not prove whose key it is.")

    # Step 6: what the record actually establishes
    level = record.get("independence_level", "unstated")
    sut = record.get("system_under_test", "unstated")
    if level == "I0":
        line(NOTE, f"independence_level I0, system under test '{sut}'. The submitter authored "
                   f"the oracle. A passing signature proves the record was not altered. It "
                   f"proves NOTHING about the target.")
    else:
        line(NOTE, f"independence_level '{level}' relative to system under test '{sut}'. An "
                   f"I-level with no named system under test is not a claim.")

    if record.get("signature_verifiable") is False:
        line(NOTE, "the registry itself reports signature_verifiable: false")
    received = record.get("received_at")
    if received:
        line(NOTE, f"received_at {received} is the OPERATOR's claim and is outside the "
                   f"signature; only payload.published_at is signed")

    return failures == 0


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    source = sys.argv[1]
    try:
        text = sys.stdin.read() if source == "-" else open(source, encoding="utf-8").read()
        record = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read a JSON record from {source!r}: {exc}", file=sys.stderr)
        return 2

    print(f"Verifying record {record.get('id', '<no id>')}")
    ok = verify(record)
    print("\nRESULT:", "all applicable checks passed" if ok else "VERIFICATION FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
