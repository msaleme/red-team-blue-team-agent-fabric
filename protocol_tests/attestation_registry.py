"""Voluntary attestation registry client.

Users explicitly publish their attestation reports to prove their
server passed security testing. This is OPT-IN only.

Nothing is ever published automatically. You must call publish_attestation()
or run: agent-security publish --attestation report.json

Usage:
    from protocol_tests.attestation_registry import publish_attestation, verify_attestation

    result = publish_attestation(report, server_name="my-mcp-server")
    verification = verify_attestation(result["registry_id"])
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

# Configurable registry endpoint - override for self-hosted deployments
REGISTRY_ENDPOINT = os.environ.get(
    "AGENT_SECURITY_REGISTRY_URL",
    "https://registry.agentsecurity.dev/v1/attestation",
)

_KEY_DIR = Path.home() / ".agent-security"
_KEY_FILE = _KEY_DIR / "signing_key.pem"

# Fields stripped from reports before publishing.
# These contain request/response payloads that may include sensitive data
# like target URLs, auth tokens, or infrastructure details.
_SENSITIVE_FIELDS = frozenset({
    "request_sent",
    "response_received",
    "raw_request",
    "raw_response",
    "headers",
    "auth_token",
    "api_key",
    "target_url",
    "url",
    "endpoint",
})


def _ensure_signing_key() -> bytes:
    """Generate an Ed25519 signing key on first use. Returns PEM bytes.

    The key is stored locally at ~/.agent-security/signing_key.pem.
    It never leaves your machine unless you explicitly share it.
    """
    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes()

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
    except ImportError:
        raise RuntimeError(
            "Attestation signing requires the 'cryptography' package.\n"
            "Install it: pip install cryptography"
        )

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_bytes(pem)
    _KEY_FILE.chmod(0o600)

    # Also save the public key for verification sharing
    pub_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    pub_file = _KEY_DIR / "signing_key_pub.pem"
    pub_file.write_bytes(pub_pem)

    return pem


def _sign_payload(payload: bytes) -> str:
    """Sign the payload with the local Ed25519 key. Returns hex signature."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    pem = _ensure_signing_key()
    key = load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Signing key is not Ed25519")
    return key.sign(payload).hex()


def strip_sensitive_fields(report: dict) -> dict:
    """Deep-copy a report and remove all sensitive fields.

    This ensures request/response payloads, URLs, credentials, and other
    infrastructure details are NEVER sent to the registry.
    """
    cleaned = copy.deepcopy(report)

    def _strip(obj: dict | list) -> None:
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if key in _SENSITIVE_FIELDS:
                    del obj[key]
                elif isinstance(obj[key], (dict, list)):
                    _strip(obj[key])
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    _strip(item)

    _strip(cleaned)
    return cleaned


def publish_attestation(
    report: dict,
    server_name: str,
    contact: str | None = None,
) -> dict:
    """Publish an attestation report to the voluntary public registry.

    This is OPT-IN. You must explicitly call this function.
    Sensitive fields (request/response payloads, URLs, credentials)
    are stripped before submission.

    Args:
        report: The attestation report dict (from harness output).
        server_name: Human-readable name for the server being attested.
        contact: Optional contact email for the attestation listing.

    Returns:
        dict with keys: registry_id, registry_url, badge_markdown, verification_hash
    """
    # Strip ALL sensitive fields before the data leaves this machine
    cleaned = strip_sensitive_fields(report)

    payload_dict = {
        "server_name": server_name,
        "contact": contact,
        "report": cleaned,
        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode()

    # Sign so the registry can verify authenticity
    signature = _sign_payload(payload_bytes)
    verification_hash = hashlib.sha256(payload_bytes).hexdigest()

    submission = {
        "payload": payload_dict,
        "signature": signature,
        "verification_hash": verification_hash,
        "public_key_fingerprint": hashlib.sha256(
            (_KEY_DIR / "signing_key_pub.pem").read_bytes()
        ).hexdigest()[:16],
    }

    req = Request(
        REGISTRY_ENDPOINT,
        data=json.dumps(submission).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        resp = urlopen(req, timeout=15)  # noqa: S310
        result = json.loads(resp.read())
    except Exception as exc:
        raise RuntimeError(f"Failed to publish attestation: {exc}") from exc

    registry_id = result.get("id", verification_hash[:12])
    registry_url = f"{REGISTRY_ENDPOINT}/{registry_id}"

    return {
        "registry_id": registry_id,
        "registry_url": registry_url,
        "verification_hash": verification_hash,
        "badge_markdown": (
            f"[![Verified by Agent Security Harness]"
            f"(https://registry.agentsecurity.dev/badge/{registry_id})]"
            f"({registry_url})"
        ),
        "badge_html": (
            f'<a href="{registry_url}">'
            f'<img src="https://registry.agentsecurity.dev/badge/{registry_id}" '
            f'alt="Verified by Agent Security Harness" /></a>'
        ),
    }


def verify_attestation(registry_id: str) -> dict:
    """Verify a published attestation by its registry ID.

    Contacts the registry to confirm the attestation exists and
    returns its metadata and verification status.

    Args:
        registry_id: The ID returned from publish_attestation().

    Returns:
        dict with verification status, server name, published date, and hash.
    """
    url = f"{REGISTRY_ENDPOINT}/{registry_id}"
    req = Request(url, method="GET")

    try:
        resp = urlopen(req, timeout=15)  # noqa: S310
        return json.loads(resp.read())
    except Exception as exc:
        raise RuntimeError(f"Failed to verify attestation '{registry_id}': {exc}") from exc
