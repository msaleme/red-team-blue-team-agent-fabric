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
import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

# There is no default registry endpoint, deliberately.
#
# Until 2026-08-04 this module defaulted to https://registry.agentsecurity.dev,
# a domain this project does not own and never did. It was fabricated, along with
# the telemetry host and the privacy contact, in 6b6a64c (2026-03-28). Every
# `agent-security publish` run with no override posted a signed attestation --
# including the optional user-supplied contact email -- to a third party.
#
# A security tool must not have a silent default destination. That property is
# what turned one wrong constant into an exfiltration path, so the fix is the
# absence of a default rather than a different default.
#
# The endpoint resolves at call time, not import time, so that importing this
# module and using strip_sensitive_fields() offline still works.

_REGISTRY_ENV = "AGENT_SECURITY_REGISTRY_URL"


class RegistryNotConfigured(RuntimeError):
    """Raised when a network operation is attempted with no registry configured."""


def resolve_registry_endpoint() -> str:
    """Return the configured registry endpoint, or raise.

    Requires AGENT_SECURITY_REGISTRY_URL. There is no default: see the note above.
    """
    raw = os.environ.get(_REGISTRY_ENV, "").strip()
    if not raw:
        raise RegistryNotConfigured(
            f"No attestation registry is configured. Set {_REGISTRY_ENV} to a "
            f"registry you control.\n"
            f"This project operates no public registry. See "
            f"docs/attestation-registry.md and issue #333 for the server contract."
        )

    # Validate URL format (#124): must be https:// (or http:// for localhost only)
    from urllib.parse import urlparse as _urlparse

    parsed = _urlparse(raw)
    if not parsed.hostname:
        raise ValueError(f"{_REGISTRY_ENV} is not a valid URL: {raw!r}")
    if parsed.scheme == "https":
        return raw
    if parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        return raw  # http allowed for local development
    raise ValueError(
        f"{_REGISTRY_ENV} must use https:// (or http:// for localhost). Got: {raw!r}"
    )

_KEY_DIR = Path.home() / ".agent-security"
_KEY_FILE = _KEY_DIR / "signing_key.pem"

# Fields stripped from reports before publishing.
# These contain request/response payloads that may include sensitive data
# like target URLs, auth tokens, or infrastructure details.
#
# Defense-in-depth: This exact-match set catches known sensitive field names.
# The _is_sensitive_key() function below also catches fields containing
# common sensitive substrings (url, endpoint, host, address, path).
# This is NOT exhaustive -- it is a best-effort defense layer.
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

# Substrings that indicate a field may contain infrastructure details (#117).
_SENSITIVE_SUBSTRINGS = ("url", "endpoint", "host", "address", "path")


def _is_sensitive_key(key: str) -> bool:
    """Check if a field name is sensitive by exact match or substring match.

    This is defense-in-depth, not exhaustive. New sensitive patterns should
    be added to _SENSITIVE_FIELDS or _SENSITIVE_SUBSTRINGS as discovered.
    """
    if key in _SENSITIVE_FIELDS:
        return True
    key_lower = key.lower()
    return any(s in key_lower for s in _SENSITIVE_SUBSTRINGS)


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
                if _is_sensitive_key(key):
                    del obj[key]
                elif isinstance(obj[key], (dict, list)):
                    _strip(obj[key])
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    _strip(item)

    _strip(cleaned)
    return cleaned


_SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9\-\. ]+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_REGISTRY_ID_RE = re.compile(r"^[A-Za-z0-9\-]+$")


def _validate_server_name(server_name: str) -> None:
    """Validate server_name: max 200 chars, alphanumeric + hyphens + dots + spaces."""
    if not server_name:
        raise ValueError("server_name is required and cannot be empty.")
    if len(server_name) > 200:
        raise ValueError(f"server_name exceeds 200 character limit (got {len(server_name)}).")
    if not _SERVER_NAME_RE.match(server_name):
        raise ValueError(
            "server_name contains invalid characters. "
            "Only alphanumeric, hyphens, dots, and spaces are allowed."
        )


def _validate_contact(contact: str) -> None:
    """Validate contact: basic email format or max 200 chars."""
    if len(contact) > 200:
        raise ValueError(f"contact exceeds 200 character limit (got {len(contact)}).")
    if not _EMAIL_RE.match(contact):
        raise ValueError(
            "contact must be a valid email address (e.g. user@example.com)."
        )


def _validate_registry_id(registry_id: str) -> None:
    """Validate registry_id is alphanumeric/UUID format only. Prevents path traversal."""
    if not registry_id:
        raise ValueError("registry_id is required and cannot be empty.")
    if len(registry_id) > 200:
        raise ValueError("registry_id is too long.")
    if not _REGISTRY_ID_RE.match(registry_id):
        raise ValueError(
            "registry_id contains invalid characters. "
            "Only alphanumeric characters and hyphens are allowed."
        )


def build_record(
    report: dict,
    server_name: str,
    contact: str | None = None,
) -> dict:
    """Build a signed envelope v2 record. Performs NO network I/O.

    Split out of publish_attestation() for #384. Before this, the only code that
    produced a signed record also POSTed it, so a record could not exist without a
    registry -- while section 7 of the server contract says the link between two
    records lives in the signature, not in an operator's assertion. The file-based
    exchange the contract relies on was unreachable through the shipped API.

    Returns the submission dict. Write it to a file, commit it, hand it to someone:
    it verifies offline with scripts/verify_attestation_record.py either way.
    """
    _validate_server_name(server_name)
    if contact:
        _validate_contact(contact)

    cleaned = strip_sensitive_fields(report)

    payload_dict = {
        "server_name": server_name,
        "contact": contact,
        "report": cleaned,
        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    # Canonical bytes: sort_keys with DEFAULT separators, not compact and not
    # JCS. Pinned in docs/ATTESTATION-REGISTRY-SERVER-CONTRACT.md section 4.1,
    # because a canonicalisation that lives in one implementation is not a
    # contract and an independent verifier reproducing it wrongly gets a valid
    # signature that will not verify.
    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode()
    signature = _sign_payload(payload_bytes)
    verification_hash = hashlib.sha256(payload_bytes).hexdigest()

    pub_pem = (_KEY_DIR / "signing_key_pub.pem").read_bytes()
    return {
        "envelope_version": "2",
        "payload": payload_dict,
        "signature": signature,
        "verification_hash": verification_hash,
        "public_key_fingerprint": hashlib.sha256(pub_pem).hexdigest()[:16],
        "public_key": pub_pem.decode("utf-8"),
    }


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
            Max 200 chars, alphanumeric + hyphens + dots + spaces only.
        contact: Optional contact email for the attestation listing.
            Must be a valid email format, max 200 chars.

    Returns:
        dict with keys: registry_id, registry_url, badge_markdown, verification_hash

    Raises:
        ValueError: If server_name or contact fail validation.
    """
    submission = build_record(report, server_name, contact)
    verification_hash = submission["verification_hash"]

    endpoint = resolve_registry_endpoint()

    req = Request(
        endpoint,
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
    registry_url = f"{endpoint}/{registry_id}"

    # Badge URLs derive from the configured registry, never from a hardcoded host.
    from urllib.parse import urlparse as _urlparse

    _p = _urlparse(endpoint)
    badge_url = f"{_p.scheme}://{_p.netloc}/badge/{registry_id}"

    # "Tested with", not "Verified by". The publisher ran this harness against
    # their own target, so the result is I0 under docs/EVIDENCE-CLASS-TAXONOMY.md.
    # A badge claiming verification would present self-authored evidence as
    # third-party review.
    _label = "Tested with Agent Security Harness"

    return {
        "registry_id": registry_id,
        "registry_url": registry_url,
        "verification_hash": verification_hash,
        "badge_markdown": f"[![{_label}]({badge_url})]({registry_url})",
        "badge_html": (
            f'<a href="{html.escape(registry_url)}">'
            f'<img src="{html.escape(badge_url)}" '
            f'alt="{_label}" /></a>'
        ),
    }


def verify_attestation(registry_id: str) -> dict:
    """Verify a published attestation by its registry ID.

    Contacts the registry to confirm the attestation exists and
    returns its metadata and verification status.

    Args:
        registry_id: The ID returned from publish_attestation().
            Must be alphanumeric/UUID format only.

    Returns:
        dict with verification status, server name, published date, and hash.

    Raises:
        ValueError: If registry_id fails validation (e.g. path traversal attempt).
    """
    # Validate registry_id before URL construction (#114)
    _validate_registry_id(registry_id)

    url = f"{resolve_registry_endpoint()}/{registry_id}"
    req = Request(url, method="GET")

    try:
        resp = urlopen(req, timeout=15)  # noqa: S310
        return json.loads(resp.read())
    except Exception as exc:
        raise RuntimeError(f"Failed to verify attestation '{registry_id}': {exc}") from exc
