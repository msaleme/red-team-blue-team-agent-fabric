#!/usr/bin/env python3
"""Reference attestation registry server (#333).

Implements docs/ATTESTATION-REGISTRY-SERVER-CONTRACT.md. Python standard library
only, except that Ed25519 verification uses `cryptography` when available -- the
same dependency the publishing client already needs to sign.

This is a CONFORMANCE REFERENCE, not a deployment target. No persistence, no
auth, no TLS, no rate limiting, in-memory store. Run it to check a client or a
second server implementation against the contract.

    python3 scripts/registry_reference_server.py --port 8787
    export AGENT_SECURITY_REGISTRY_URL="http://localhost:8787"

This project operates no registry. See rule R1 in the contract: there is no
well-known host and this server must not become one.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:  # optional: only needed to actually verify a signature
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    _CRYPTO = True
except ImportError:  # pragma: no cover - environment dependent
    _CRYPTO = False

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schemas" / "attestation-report.json"

# Mirrors protocol_tests/attestation_registry.py. Duplicated deliberately: a
# server must not import the client to decide whether the client behaved.
SENSITIVE_FIELDS = frozenset({
    "request_sent", "response_received", "raw_request", "raw_response",
    "headers", "auth_token", "api_key", "target_url", "url", "endpoint",
})
SENSITIVE_SUBSTRINGS = ("url", "endpoint", "host", "address", "path")

SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9\-\. ]+$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
REGISTRY_ID_RE = re.compile(r"^[A-Za-z0-9\-]+$")

CLAIM_LABEL = "Tested with Agent Security Harness"

# Contract section 4.1. Default separators, NOT compact. Changing this silently
# invalidates every signature ever produced by the shipping client.
def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True).encode()


def is_sensitive_key(key: str) -> bool:
    if key in SENSITIVE_FIELDS:
        return True
    lowered = key.lower()
    return any(s in lowered for s in SENSITIVE_SUBSTRINGS)


def find_sensitive_keys(obj, path="report") -> list[str]:
    found = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if is_sensitive_key(key):
                found.append(f"{path}.{key}")
            else:
                found.extend(find_sensitive_keys(value, f"{path}.{key}"))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            found.extend(find_sensitive_keys(item, f"{path}[{i}]"))
    return found


def load_schema_required() -> list[str]:
    """Required top-level keys of the attestation report.

    Deliberately a required-key check, not full JSON Schema validation: the repo
    has no jsonschema dependency and a server that claims schema validation it
    does not perform is the same class of defect as claiming a signature check it
    skipped. A production server SHOULD validate fully.
    """
    try:
        return json.loads(SCHEMA_PATH.read_text()).get("required", [])
    except (OSError, json.JSONDecodeError):
        return []


class Store:
    def __init__(self) -> None:
        self._by_id: dict[str, dict] = {}
        self._by_hash: dict[str, str] = {}

    def get(self, registry_id: str) -> dict | None:
        return self._by_id.get(registry_id)

    def existing_id_for(self, verification_hash: str) -> str | None:
        return self._by_hash.get(verification_hash)

    def put(self, record: dict) -> str:
        registry_id = record["id"]
        self._by_id[registry_id] = record
        self._by_hash[record["verification_hash"]] = registry_id
        return registry_id


class Rejected(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def validate_and_build(submission: dict, required_keys: list[str]) -> dict:
    """Contract section 5. Eight checks, in order. Raises Rejected."""
    # 1. Shape
    if not isinstance(submission, dict):
        raise Rejected(400, "submission must be a JSON object")
    payload = submission.get("payload")
    signature = submission.get("signature")
    verification_hash = submission.get("verification_hash")
    if not isinstance(payload, dict):
        raise Rejected(400, "missing or non-object 'payload'")
    if not isinstance(signature, str) or not signature:
        raise Rejected(400, "missing 'signature'")
    if not isinstance(verification_hash, str) or not verification_hash:
        raise Rejected(400, "missing 'verification_hash'")
    server_name = payload.get("server_name")
    if not isinstance(server_name, str) or not server_name:
        raise Rejected(400, "missing 'payload.server_name'")
    if not isinstance(payload.get("published_at"), str):
        raise Rejected(400, "missing 'payload.published_at'")
    report = payload.get("report")
    if not isinstance(report, dict):
        raise Rejected(400, "missing or non-object 'payload.report'")

    # 2. Field validation (re-run, never trusted from an unauthenticated party)
    if len(server_name) > 200 or not SERVER_NAME_RE.match(server_name):
        raise Rejected(400, "'server_name' fails the contract pattern or length limit")
    contact = payload.get("contact")
    if contact is not None:
        if not isinstance(contact, str) or len(contact) > 200 or not EMAIL_RE.match(contact):
            raise Rejected(400, "'contact' fails the contract pattern or length limit")

    # 3. Hash over the canonical bytes
    recomputed = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    if recomputed != verification_hash:
        raise Rejected(
            400,
            "'verification_hash' does not match the canonical payload bytes "
            "(contract 4.1: json.dumps(payload, sort_keys=True), default separators)",
        )

    # 4. Sensitive-field scan
    leaked = find_sensitive_keys(report)
    if leaked:
        raise Rejected(422, f"report contains sensitive keys: {', '.join(sorted(leaked)[:8])}")

    # 5. Schema required keys
    missing = [k for k in required_keys if k not in report]
    if missing:
        raise Rejected(422, f"report missing schema-required keys: {', '.join(missing)}")

    # 6. Signature
    public_key = submission.get("public_key")
    fingerprint = submission.get("public_key_fingerprint")
    signature_verifiable = False
    if public_key:
        if not isinstance(public_key, str):
            raise Rejected(400, "'public_key' must be a PEM string")
        pem = public_key.encode()
        if fingerprint and hashlib.sha256(pem).hexdigest()[:16] != fingerprint:
            raise Rejected(400, "'public_key_fingerprint' does not match 'public_key'")
        if not _CRYPTO:
            raise Rejected(
                501,
                "signature verification unavailable: install 'cryptography'. Accepting a "
                "signed envelope without checking it would report a verification that "
                "never happened (contract 5.6)",
            )
        try:
            key = load_pem_public_key(pem)
            key.verify(bytes.fromhex(signature), canonical_bytes(payload))
        except (InvalidSignature, ValueError) as exc:
            raise Rejected(400, f"Ed25519 signature verification failed: {exc}") from exc
        signature_verifiable = True

    # 7. Classification. I0 always; never submitter-supplied.
    if submission.get("independence_level") not in (None, "I0"):
        raise Rejected(
            422,
            "a submitted record is I0 by construction; the registry does not accept a "
            "submitter-asserted independence level (contract 1 and 7)",
        )

    # 8. Id
    registry_id = verification_hash[:12]

    return {
        "id": registry_id,
        "payload": payload,  # stored verbatim: normalizing it destroys the signature
        "signature": signature,
        "verification_hash": verification_hash,
        "public_key": public_key,
        "public_key_fingerprint": fingerprint,
        "envelope_version": submission.get("envelope_version", "1"),
        "signature_verifiable": signature_verifiable,
        # #384: prefer what the submitter SIGNED. Before this, both of these were
        # assigned here, outside the signature -- so the independence claim existed
        # only as operator metadata a verifier could not check, which is the
        # assertion contract section 7 exists to avoid. The registry classification
        # stays I0 per section 1 (a submission establishes I0 regardless of who
        # sent it), but the system under test now comes from inside the signature
        # when the report states it, and the record says which.
        "evidence_class": report.get("evidence_class", "E1"),
        "evidence_class_source": (
            "signed_payload" if report.get("evidence_class") else "server_default"
        ),
        "independence_level": "I0",
        "independence_level_basis": (
            "contract section 1: a submission establishes I0 regardless of submitter"
        ),
        "signed_independence_level": report.get("independence_level"),
        "system_under_test": report.get("system_under_test") or server_name,
        "system_under_test_source": (
            "signed_payload" if report.get("system_under_test") else "server_assigned"
        ),
        "received_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claim_label": CLAIM_LABEL,
    }


BADGE_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="260" height="20" role="img" '
    'aria-label="{label}">'
    '<rect width="260" height="20" fill="#555"/>'
    '<text x="8" y="14" fill="#fff" font-family="Verdana,sans-serif" font-size="11">'
    "{label}</text></svg>"
)


class Handler(BaseHTTPRequestHandler):
    store: Store
    required_keys: list[str]
    server_version = "agent-security-registry-reference/1.0"

    def log_message(self, fmt, *args):  # quieter default logging
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 5_000_000:
            self._json(400, {"error": "missing or oversized body"})
            return
        try:
            submission = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            self._json(400, {"error": f"invalid JSON: {exc}"})
            return

        try:
            record = validate_and_build(submission, self.required_keys)
        except Rejected as rej:
            self._json(rej.status, {"error": rej.reason})
            return

        existing = self.store.existing_id_for(record["verification_hash"])
        if existing:
            self._json(200, {"id": existing, "idempotent": True})
            return

        self._json(201, {"id": self.store.put(record)})

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/")
        segments = [s for s in path.split("/") if s]

        if len(segments) == 2 and segments[-2] == "badge":
            registry_id = segments[-1]
            if not REGISTRY_ID_RE.match(registry_id) or not self.store.get(registry_id):
                self._json(404, {"error": "unknown registry_id"})
                return
            svg = BADGE_SVG.format(label=CLAIM_LABEL).encode()
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(svg)))
            self.end_headers()
            self.wfile.write(svg)
            return

        if len(segments) >= 1:
            registry_id = segments[-1]
            if not REGISTRY_ID_RE.match(registry_id):
                self._json(400, {"error": "registry_id fails ^[A-Za-z0-9\\-]+$"})
                return
            record = self.store.get(registry_id)
            if not record:
                self._json(404, {"error": "unknown registry_id"})
                return
            self._json(200, record)
            return

        self._json(404, {"error": "not found"})


def build_server(port: int) -> ThreadingHTTPServer:
    Handler.store = Store()
    Handler.required_keys = load_schema_required()
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()

    httpd = build_server(args.port)
    base = f"http://127.0.0.1:{args.port}"
    print(f"reference registry on {base}")
    print(f"  export AGENT_SECURITY_REGISTRY_URL=\"{base}\"")
    if not _CRYPTO:
        print("  WARNING: 'cryptography' not importable; signed envelopes will be "
              "rejected with 501 rather than silently unverified")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
