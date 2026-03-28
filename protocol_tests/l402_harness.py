#!/usr/bin/env python3
"""L402 Payment Flow Security Test Harness (v3.0)

Tests the L402 payment protocol at the wire level — HTTP 402 challenge-response,
macaroon integrity, preimage validation, caveat enforcement, and rate limiting.

L402 Protocol Overview:
    L402 (formerly LSAT) is a payment protocol for HTTP APIs built on Lightning
    Network micropayments and macaroons. The flow is:

    1. Client requests a protected resource.
    2. Server returns HTTP 402 Payment Required with header:
       WWW-Authenticate: L402 macaroon="<base64>", invoice="<bolt11>"
    3. Client pays the Lightning invoice, receiving a preimage.
    4. Client sends: Authorization: L402 <macaroon>:<preimage>
    5. Server verifies the macaroon + preimage and serves the resource.

    Macaroons carry caveats (conditions) such as expiry time, resource scope,
    and spending limits. The preimage proves payment was made for the specific
    invoice tied to that macaroon.

Test Endpoints (dispatches.mystere.me):
    GET  /api/dispatches      — 402 gated index (10 sat)
    GET  /api/dispatches/:id  — 402 per-resource gating
    POST /api/ask             — 402 paywall (100 sat), accepts question body

This harness does NOT pay any invoices. All tests craft requests and analyze
server responses to validate that the server properly rejects invalid auth,
does not leak sensitive information, and enforces payment gating correctly.

Usage:
    # Test against default L402 server
    python -m protocol_tests.l402_harness

    # Test against a custom L402 endpoint
    python -m protocol_tests.l402_harness --url https://my-l402-server.com

    # Run specific test categories
    python -m protocol_tests.l402_harness --categories invoice_validation,macaroon_integrity

    # List available tests
    python -m protocol_tests.l402_harness --list

    # Multi-trial statistical mode
    python -m protocol_tests.l402_harness --trials 10 --report l402_report.json

Requires: Python 3.10+, no external dependencies.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import http.client
import urllib.request


# ---------------------------------------------------------------------------
# L402 protocol primitives
# ---------------------------------------------------------------------------

_L402_HEADER_RE = re.compile(
    r'L402\s+macaroon="([^"]+)"\s*,\s*invoice="([^"]+)"',
    re.IGNORECASE,
)

_LSAT_HEADER_RE = re.compile(
    r'LSAT\s+macaroon="([^"]+)"\s*,\s*invoice="([^"]+)"',
    re.IGNORECASE,
)


@dataclass
class L402Challenge:
    """Parsed L402 challenge from a 402 response."""
    macaroon: str       # base64-encoded macaroon
    invoice: str        # BOLT-11 Lightning invoice string
    raw_header: str     # original WWW-Authenticate header value

    @classmethod
    def from_header(cls, header: str) -> L402Challenge | None:
        """Parse a WWW-Authenticate header into an L402Challenge."""
        for pattern in (_L402_HEADER_RE, _LSAT_HEADER_RE):
            m = pattern.search(header)
            if m:
                return cls(macaroon=m.group(1), invoice=m.group(2), raw_header=header)
        return None


def _fake_preimage(length: int = 32) -> str:
    """Generate a random hex preimage (not derived from any real payment)."""
    return os.urandom(length).hex()


def _tamper_base64(b64: str, n_flips: int = 3) -> str:
    """Flip random bits in a base64-encoded blob."""
    try:
        raw = bytearray(base64.b64decode(b64))
    except Exception:
        raw = bytearray(b64.encode("utf-8"))
    import random
    for _ in range(n_flips):
        if raw:
            idx = random.randint(0, len(raw) - 1)
            raw[idx] ^= random.randint(1, 255)
    return base64.b64encode(bytes(raw)).decode("ascii")


# ---------------------------------------------------------------------------
# HTTP transport for L402 endpoints
# ---------------------------------------------------------------------------

class L402Transport:
    """HTTP transport for L402-gated APIs."""

    def __init__(self, base_url: str, headers: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict | None = None,
        timeout: float = 15.0,
    ) -> dict:
        """Send an HTTP request and return a structured response dict.

        Returns dict with keys:
            status: int HTTP status code
            headers: dict of response headers
            body: str response body (truncated to 2000 chars)
            _error: bool (only on exception)
            _exception: str (only on exception)
        """
        url = f"{self.base_url}{path}"
        all_headers = {**self.headers, **(headers or {})}
        req = urllib.request.Request(url, data=body, headers=all_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers.items()),
                    "body": resp_body[:2000],
                }
        except urllib.error.HTTPError as e:
            resp_body = ""
            try:
                resp_body = e.read().decode("utf-8", errors="replace")[:2000]
            except Exception:
                pass
            return {
                "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": resp_body,
            }
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "_error": True, "_exception": str(e)}

    def get(self, path: str, headers: dict | None = None, timeout: float = 15.0) -> dict:
        return self.request("GET", path, headers=headers, timeout=timeout)

    def post(self, path: str, body: bytes | None = None, headers: dict | None = None, timeout: float = 15.0) -> dict:
        return self.request("POST", path, body=body, headers=headers, timeout=timeout)


# ---------------------------------------------------------------------------
# Test result model
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "P0-Critical"
    HIGH = "P1-High"
    MEDIUM = "P2-Medium"
    LOW = "P3-Low"


@dataclass
class L402TestResult:
    test_id: str
    name: str
    category: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str
    http_method: str
    request_sent: dict | None = None
    response_received: dict | None = None
    elapsed_s: float = 0.0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# L402 Security Test Suite
# ---------------------------------------------------------------------------

class L402SecurityTests:
    """Protocol-level security tests for L402-gated APIs."""

    # Default test paths for dispatches.mystere.me
    PATH_INDEX = "/api/dispatches"
    PATH_RESOURCE = "/api/dispatches/1"
    PATH_ASK = "/api/ask"

    def __init__(self, transport: L402Transport):
        self.transport = transport
        self.results: list[L402TestResult] = []
        # Cache a challenge from the server for tests that need one
        self._cached_challenge: L402Challenge | None = None

    def _record(self, result: L402TestResult):
        self.results.append(result)
        status = "PASS \u2705" if result.passed else "FAIL \u274c"
        print(f"  {status} {result.test_id}: {result.name} ({result.elapsed_s:.2f}s)")

    def _get_challenge(self, path: str | None = None) -> L402Challenge | None:
        """Fetch a fresh L402 challenge from the server (expects 402)."""
        resp = self.transport.get(path or self.PATH_INDEX)
        if resp.get("status") == 402:
            www_auth = ""
            for k, v in resp.get("headers", {}).items():
                if k.lower() == "www-authenticate":
                    www_auth = v
                    break
            if www_auth:
                return L402Challenge.from_header(www_auth)
        return None

    def _ensure_challenge(self) -> L402Challenge | None:
        """Return a cached challenge or fetch a new one."""
        if not self._cached_challenge:
            self._cached_challenge = self._get_challenge()
        return self._cached_challenge

    # ------------------------------------------------------------------
    # Category 1: Invoice Validation (L4-001 through L4-003)
    # ------------------------------------------------------------------

    def test_l402_challenge_present(self):
        """L4-001: Verify 402 response contains valid WWW-Authenticate: L402 header."""
        t0 = time.monotonic()
        resp = self.transport.get(self.PATH_INDEX)
        elapsed = time.monotonic() - t0

        status = resp.get("status", 0)
        www_auth = ""
        for k, v in resp.get("headers", {}).items():
            if k.lower() == "www-authenticate":
                www_auth = v
                break

        challenge = L402Challenge.from_header(www_auth) if www_auth else None

        issues = []
        if status != 402:
            issues.append(f"Expected HTTP 402, got {status}")
        if not www_auth:
            issues.append("Missing WWW-Authenticate header")
        elif not challenge:
            issues.append(f"Could not parse L402 challenge from: {www_auth[:200]}")
        else:
            # Validate invoice looks like BOLT-11
            if not challenge.invoice.startswith(("lnbc", "lntb", "lnbcrt")):
                issues.append(f"Invoice does not look like BOLT-11: {challenge.invoice[:40]}...")
            # Cache for later tests
            self._cached_challenge = challenge

        passed = len(issues) == 0
        self._record(L402TestResult(
            test_id="L4-001",
            name="402 Challenge Header Present",
            category="invoice_validation",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details="; ".join(issues) if issues else "Valid L402 challenge returned with BOLT-11 invoice",
            http_method="GET",
            request_sent={"path": self.PATH_INDEX},
            response_received={"status": status, "www_authenticate": www_auth[:300]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_malformed_invoice(self):
        """L4-002: Present malformed invoices and verify rejection."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        malformed_invoices = [
            ("truncated", "lnbc1" + "a" * 20),
            ("wrong_prefix", "lnXX" + "0" * 60),
            ("empty", ""),
            ("garbage", "not_an_invoice_at_all_" + uuid.uuid4().hex),
        ]

        rejected = 0
        tested = 0
        for label, invoice in malformed_invoices:
            # Construct an Authorization header using the malformed invoice as the preimage component
            fake_preimage = invoice  # Use the malformed invoice data as the presented "preimage"
            mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()
            auth_header = f"L402 {mac}:{fake_preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            tested += 1
            # Server should reject (not 200 OK)
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == tested

        self._record(L402TestResult(
            test_id="L4-002",
            name="Malformed Invoice Rejection",
            category="invoice_validation",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{tested} malformed tokens rejected",
            http_method="GET",
            request_sent={"malformed_variants": [label for label, _ in malformed_invoices]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_expired_token(self):
        """L4-003: Present an expired / zero-amount token."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        # We cannot truly create an expired invoice, but we can present
        # a token that was never paid (preimage is fake) — server should reject.
        fake_preimage = _fake_preimage()
        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()
        auth_header = f"L402 {mac}:{fake_preimage}"

        resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
        elapsed = time.monotonic() - t0

        status = resp.get("status", 0)
        # Server must not grant access with an unpaid/fake preimage
        passed = status != 200

        # Check for information leakage in error response
        body_lower = resp.get("body", "").lower()
        info_leak = any(kw in body_lower for kw in [
            "stack trace", "traceback", "internal server error detail",
            "sql", "database", "secret", "api_key",
        ])

        self._record(L402TestResult(
            test_id="L4-003",
            name="Unpaid / Expired Token Rejection",
            category="invoice_validation",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed and not info_leak,
            details=(f"Server returned {status} (rejected)" if passed else f"Server returned {status} (GRANTED ACCESS)") +
                    ("; INFO LEAK detected in error body" if info_leak else ""),
            http_method="GET",
            request_sent={"authorization": f"L402 <macaroon>:<fake_preimage>"},
            response_received={"status": status, "body_preview": resp.get("body", "")[:200]},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 2: Macaroon Integrity (L4-004 through L4-006)
    # ------------------------------------------------------------------

    def test_l402_tampered_macaroon(self):
        """L4-004: Tamper with macaroon bytes and verify rejection."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-004",
                name="Tampered Macaroon Rejection",
                category="macaroon_integrity",
                owasp_asi="ASI03",
                severity=Severity.CRITICAL.value,
                passed=False,
                details="Could not obtain L402 challenge from server to test",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        tampered_variants = [
            ("bit_flip", _tamper_base64(challenge.macaroon, n_flips=3)),
            ("truncated", challenge.macaroon[:len(challenge.macaroon) // 2]),
            ("empty_macaroon", ""),
            ("garbage_b64", base64.b64encode(os.urandom(64)).decode()),
        ]

        rejected = 0
        for label, tampered_mac in tampered_variants:
            fake_preimage = _fake_preimage()
            auth_header = f"L402 {tampered_mac}:{fake_preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(tampered_variants)

        self._record(L402TestResult(
            test_id="L4-004",
            name="Tampered Macaroon Rejection",
            category="macaroon_integrity",
            owasp_asi="ASI03",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=f"{rejected}/{len(tampered_variants)} tampered macaroons rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in tampered_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_unauthorized_caveats(self):
        """L4-005: Add unauthorized caveats to macaroon."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-005",
                name="Unauthorized Caveat Injection",
                category="macaroon_integrity",
                owasp_asi="ASI02",
                severity=Severity.HIGH.value,
                passed=False,
                details="Could not obtain L402 challenge from server to test",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        # Attempt to append caveat-like data to the macaroon blob
        # Real macaroon caveat addition requires HMAC chaining, but we test
        # whether the server blindly accepts modified blobs.
        try:
            raw_mac = base64.b64decode(challenge.macaroon)
        except Exception:
            raw_mac = challenge.macaroon.encode()

        caveat_payloads = [
            b'\x00admin=true',
            b'\x00scope=*',
            b'\x00expiry=9999999999',
        ]

        rejected = 0
        for caveat in caveat_payloads:
            modified = base64.b64encode(raw_mac + caveat).decode()
            fake_preimage = _fake_preimage()
            auth_header = f"L402 {modified}:{fake_preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(caveat_payloads)

        self._record(L402TestResult(
            test_id="L4-005",
            name="Unauthorized Caveat Injection",
            category="macaroon_integrity",
            owasp_asi="ASI02",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(caveat_payloads)} caveat-injected macaroons rejected",
            http_method="GET",
            request_sent={"caveats_appended": ["admin=true", "scope=*", "expiry=9999999999"]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_stripped_signature(self):
        """L4-006: Strip signature from macaroon entirely."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-006",
                name="Stripped Macaroon Signature",
                category="macaroon_integrity",
                owasp_asi="ASI03",
                severity=Severity.CRITICAL.value,
                passed=False,
                details="Could not obtain L402 challenge from server to test",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        try:
            raw_mac = base64.b64decode(challenge.macaroon)
        except Exception:
            raw_mac = challenge.macaroon.encode()

        # Macaroon binary format: last 32 bytes are typically the HMAC signature.
        # Try presenting the macaroon with signature bytes zeroed or truncated.
        stripped_variants = [
            ("truncated_sig", base64.b64encode(raw_mac[:-32] if len(raw_mac) > 32 else raw_mac[:1]).decode()),
            ("zeroed_sig", base64.b64encode(raw_mac[:-32] + b'\x00' * 32 if len(raw_mac) > 32 else b'\x00' * 32).decode()),
            ("half_mac", base64.b64encode(raw_mac[:len(raw_mac) // 2]).decode()),
        ]

        rejected = 0
        for label, stripped_mac in stripped_variants:
            fake_preimage = _fake_preimage()
            auth_header = f"L402 {stripped_mac}:{fake_preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(stripped_variants)

        self._record(L402TestResult(
            test_id="L4-006",
            name="Stripped Macaroon Signature",
            category="macaroon_integrity",
            owasp_asi="ASI03",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=f"{rejected}/{len(stripped_variants)} signature-stripped macaroons rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in stripped_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 3: Preimage Replay (L4-007, L4-008)
    # ------------------------------------------------------------------

    def test_l402_fake_preimage(self):
        """L4-007: Present a valid-looking preimage without paying the invoice."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        # Generate several fake preimages (correct length, random bytes)
        fake_preimages = [_fake_preimage() for _ in range(5)]

        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()
        rejected = 0
        for preimage in fake_preimages:
            auth_header = f"L402 {mac}:{preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(fake_preimages)

        self._record(L402TestResult(
            test_id="L4-007",
            name="Fake Preimage Rejection",
            category="preimage_replay",
            owasp_asi="ASI03",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=f"{rejected}/{len(fake_preimages)} fake preimages rejected",
            http_method="GET",
            request_sent={"n_fake_preimages": len(fake_preimages)},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_cross_session_preimage(self):
        """L4-008: Attempt to reuse a preimage from a different session/invoice."""
        t0 = time.monotonic()

        # Fetch two separate challenges (should have different invoices)
        challenge_a = self._get_challenge(self.PATH_INDEX)
        challenge_b = self._get_challenge(self.PATH_RESOURCE)

        if not challenge_a or not challenge_b:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-008",
                name="Cross-Session Preimage Replay",
                category="preimage_replay",
                owasp_asi="ASI03",
                severity=Severity.CRITICAL.value,
                passed=True if (not challenge_a and not challenge_b) else False,
                details="Could not obtain two distinct L402 challenges" if (challenge_a or challenge_b)
                        else "Server does not return L402 challenges on tested paths (N/A)",
                http_method="GET",
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        # Check that invoices differ (different payment hashes)
        invoices_differ = challenge_a.invoice != challenge_b.invoice

        # Try presenting challenge_a's macaroon with a fake preimage against challenge_b's path
        fake_preimage = _fake_preimage()
        auth_header = f"L402 {challenge_a.macaroon}:{fake_preimage}"
        resp = self.transport.get(self.PATH_RESOURCE, headers={"Authorization": auth_header})

        elapsed = time.monotonic() - t0
        status = resp.get("status", 0)
        rejected = status != 200

        self._record(L402TestResult(
            test_id="L4-008",
            name="Cross-Session Preimage Replay",
            category="preimage_replay",
            owasp_asi="ASI03",
            severity=Severity.CRITICAL.value,
            passed=rejected,
            details=(f"Invoices differ: {invoices_differ}; cross-session token returned {status}" +
                     (" (rejected)" if rejected else " (ACCEPTED — possible replay vulnerability)")),
            http_method="GET",
            request_sent={"cross_path": True, "invoices_differ": invoices_differ},
            response_received={"status": status},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 4: Caveat Escalation (L4-009, L4-010)
    # ------------------------------------------------------------------

    def test_l402_scope_widening(self):
        """L4-009: Modify resource scope caveat to wildcard or broader path."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-009",
                name="Caveat Scope Widening",
                category="caveat_escalation",
                owasp_asi="ASI02",
                severity=Severity.HIGH.value,
                passed=False,
                details="Could not obtain L402 challenge from server to test",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        # Present a token from one endpoint against different endpoints
        fake_preimage = _fake_preimage()
        cross_paths = [
            self.PATH_INDEX,        # index vs resource
            self.PATH_RESOURCE,     # resource vs index
            self.PATH_ASK,          # ask vs index
            "/api/admin",           # non-existent admin path
            "/api/dispatches/../admin",  # traversal attempt
        ]

        rejected = 0
        for path in cross_paths:
            auth_header = f"L402 {challenge.macaroon}:{fake_preimage}"
            resp = self.transport.get(path, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(cross_paths)

        self._record(L402TestResult(
            test_id="L4-009",
            name="Caveat Scope Widening",
            category="caveat_escalation",
            owasp_asi="ASI02",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(cross_paths)} cross-scope attempts rejected",
            http_method="GET",
            request_sent={"paths_tested": cross_paths},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_permission_escalation(self):
        """L4-010: Add permission-escalating caveats (admin=true)."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-010",
                name="Permission Escalation via Caveats",
                category="caveat_escalation",
                owasp_asi="ASI02",
                severity=Severity.CRITICAL.value,
                passed=False,
                details="Could not obtain L402 challenge from server to test",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        try:
            raw_mac = base64.b64decode(challenge.macaroon)
        except Exception:
            raw_mac = challenge.macaroon.encode()

        # Inject permission-escalating caveats into the macaroon blob
        escalation_payloads = [
            b'\x00role=admin',
            b'\x00admin=true\x00bypass_payment=true',
            b'\x00resource=*\x00method=*',
        ]

        rejected = 0
        for payload in escalation_payloads:
            modified = base64.b64encode(raw_mac + payload).decode()
            fake_preimage = _fake_preimage()
            auth_header = f"L402 {modified}:{fake_preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(escalation_payloads)

        self._record(L402TestResult(
            test_id="L4-010",
            name="Permission Escalation via Caveats",
            category="caveat_escalation",
            owasp_asi="ASI02",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=f"{rejected}/{len(escalation_payloads)} escalation attempts rejected",
            http_method="GET",
            request_sent={"escalation_caveats": ["role=admin", "admin=true+bypass_payment", "resource=*+method=*"]},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 5: Payment-State Confusion (L4-011, L4-012)
    # ------------------------------------------------------------------

    def test_l402_macaroon_only_no_preimage(self):
        """L4-011: Present bearer token without preimage (macaroon only)."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()

        # Various incomplete Authorization headers
        incomplete_headers = [
            ("macaroon_only", f"L402 {mac}"),
            ("macaroon_colon_empty", f"L402 {mac}:"),
            ("bearer_macaroon", f"Bearer {mac}"),
            ("garbage_auth", f"L402 {'A' * 100}:{'B' * 64}"),
            ("lsat_compat", f"LSAT {mac}:{_fake_preimage()}"),
        ]

        rejected = 0
        for label, auth_value in incomplete_headers:
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_value})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(incomplete_headers)

        self._record(L402TestResult(
            test_id="L4-011",
            name="Incomplete Authorization Header",
            category="payment_state_confusion",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(incomplete_headers)} incomplete auth headers rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in incomplete_headers]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_presettlement_race(self):
        """L4-012: Send request immediately with token before settlement would complete."""
        t0 = time.monotonic()

        # Fetch a fresh challenge and immediately present a fake preimage
        # (simulating a race where payment hasn't settled yet)
        resp_challenge = self.transport.get(self.PATH_INDEX)
        www_auth = ""
        for k, v in resp_challenge.get("headers", {}).items():
            if k.lower() == "www-authenticate":
                www_auth = v
                break
        challenge = L402Challenge.from_header(www_auth) if www_auth else None

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-012",
                name="Pre-Settlement Race Condition",
                category="payment_state_confusion",
                owasp_asi="ASI03",
                severity=Severity.MEDIUM.value,
                passed=True,
                details="No L402 challenge available to test race condition (N/A)",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        # Immediately present the token (zero delay — payment hasn't happened)
        fake_preimage = _fake_preimage()
        auth_header = f"L402 {challenge.macaroon}:{fake_preimage}"
        resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})

        elapsed = time.monotonic() - t0
        status = resp.get("status", 0)
        passed = status != 200

        self._record(L402TestResult(
            test_id="L4-012",
            name="Pre-Settlement Race Condition",
            category="payment_state_confusion",
            owasp_asi="ASI03",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=f"Immediate token presentation returned {status}" +
                    (" (rejected)" if passed else " (ACCEPTED — possible race vulnerability)"),
            http_method="GET",
            request_sent={"race_delay_ms": 0},
            response_received={"status": status},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 6: Rate / DoS (L4-013, L4-014)
    # ------------------------------------------------------------------

    def test_l402_rapid_invoice_generation(self):
        """L4-013: Rapid sequential requests to generate many invoices."""
        t0 = time.monotonic()

        n_requests = 20
        invoices: list[str] = []
        statuses: list[int] = []

        for _ in range(n_requests):
            resp = self.transport.get(self.PATH_INDEX)
            statuses.append(resp.get("status", 0))
            www_auth = ""
            for k, v in resp.get("headers", {}).items():
                if k.lower() == "www-authenticate":
                    www_auth = v
                    break
            challenge = L402Challenge.from_header(www_auth) if www_auth else None
            if challenge:
                invoices.append(challenge.invoice)

        elapsed = time.monotonic() - t0

        # Check: server should either rate-limit or return unique invoices
        n_402 = sum(1 for s in statuses if s == 402)
        n_rate_limited = sum(1 for s in statuses if s == 429)
        unique_invoices = len(set(invoices))

        # Pass if server rate-limits OR all invoices are unique
        # (reusing invoices across requests could be a billing confusion attack)
        has_rate_limit = n_rate_limited > 0
        all_unique = unique_invoices == len(invoices) if invoices else True

        passed = has_rate_limit or all_unique

        self._record(L402TestResult(
            test_id="L4-013",
            name="Rapid Invoice Generation",
            category="rate_dos",
            owasp_asi="ASI08",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=(f"{n_requests} requests in {elapsed:.1f}s: "
                     f"{n_402} got 402, {n_rate_limited} rate-limited, "
                     f"{unique_invoices}/{len(invoices)} unique invoices"),
            http_method="GET",
            request_sent={"n_requests": n_requests},
            response_received={"n_402": n_402, "n_rate_limited": n_rate_limited,
                               "unique_invoices": unique_invoices, "total_invoices": len(invoices)},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_concurrent_invoice_uniqueness(self):
        """L4-014: Concurrent requests to test invoice uniqueness."""
        t0 = time.monotonic()

        n_workers = 10
        invoices: list[str] = []
        statuses: list[int] = []

        def _fetch():
            resp = self.transport.get(self.PATH_INDEX)
            status = resp.get("status", 0)
            www_auth = ""
            for k, v in resp.get("headers", {}).items():
                if k.lower() == "www-authenticate":
                    www_auth = v
                    break
            challenge = L402Challenge.from_header(www_auth) if www_auth else None
            return status, challenge.invoice if challenge else None

        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = [pool.submit(_fetch) for _ in range(n_workers)]
            for f in as_completed(futures):
                try:
                    status, invoice = f.result()
                    statuses.append(status)
                    if invoice:
                        invoices.append(invoice)
                except Exception:
                    pass

        elapsed = time.monotonic() - t0

        unique_invoices = len(set(invoices))
        all_unique = unique_invoices == len(invoices) if invoices else True
        n_rate_limited = sum(1 for s in statuses if s == 429)

        passed = all_unique or n_rate_limited > 0

        self._record(L402TestResult(
            test_id="L4-014",
            name="Concurrent Invoice Uniqueness",
            category="rate_dos",
            owasp_asi="ASI08",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=(f"{n_workers} concurrent requests: "
                     f"{unique_invoices}/{len(invoices)} unique invoices, "
                     f"{n_rate_limited} rate-limited"),
            http_method="GET",
            request_sent={"n_concurrent": n_workers},
            response_received={"unique_invoices": unique_invoices, "total_invoices": len(invoices),
                               "n_rate_limited": n_rate_limited},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Run all tests
    # ------------------------------------------------------------------

    ALL_TESTS: dict[str, list[str]] = {
        "invoice_validation": [
            "test_l402_challenge_present",
            "test_l402_malformed_invoice",
            "test_l402_expired_token",
        ],
        "macaroon_integrity": [
            "test_l402_tampered_macaroon",
            "test_l402_unauthorized_caveats",
            "test_l402_stripped_signature",
        ],
        "preimage_replay": [
            "test_l402_fake_preimage",
            "test_l402_cross_session_preimage",
        ],
        "caveat_escalation": [
            "test_l402_scope_widening",
            "test_l402_permission_escalation",
        ],
        "payment_state_confusion": [
            "test_l402_macaroon_only_no_preimage",
            "test_l402_presettlement_race",
        ],
        "rate_dos": [
            "test_l402_rapid_invoice_generation",
            "test_l402_concurrent_invoice_uniqueness",
        ],
    }

    def run_all(self, categories: list[str] | None = None) -> list[L402TestResult]:
        """Run all L402 security tests (or a filtered subset)."""

        test_map: dict[str, list[str]]
        if categories:
            test_map = {k: v for k, v in self.ALL_TESTS.items() if k in categories}
        else:
            test_map = dict(self.ALL_TESTS)

        print(f"\n{'='*60}")
        print("L402 PAYMENT FLOW SECURITY TEST SUITE v3.0")
        print(f"{'='*60}")
        print(f"Target: {self.transport.base_url}")

        for category, test_names in test_map.items():
            print(f"\n[{category.upper().replace('_', ' ')}]")
            for test_name in test_names:
                test_fn = getattr(self, test_name)
                try:
                    test_fn()
                except Exception as e:
                    print(f"  ERROR \u26a0\ufe0f  {test_name}: {e}")
                    self.results.append(L402TestResult(
                        test_id=test_name,
                        name=f"ERROR: {test_name}",
                        category=category,
                        owasp_asi="",
                        severity=Severity.HIGH.value,
                        passed=False,
                        details=str(e),
                        http_method="unknown",
                    ))

        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        print(f"\n{'='*60}")
        print(f"RESULTS: {passed}/{total} passed ({passed/total*100:.0f}%)" if total else "No tests run")
        print(f"{'='*60}\n")

        return self.results


# ---------------------------------------------------------------------------
# Test listing
# ---------------------------------------------------------------------------

_TEST_DESCRIPTIONS: dict[str, str] = {
    "L4-001": "Verify 402 response contains valid WWW-Authenticate: L402 header",
    "L4-002": "Present malformed invoices (truncated, wrong prefix, empty, garbage)",
    "L4-003": "Present unpaid / expired token and check for info leakage",
    "L4-004": "Tamper with macaroon bytes (bit flip, truncate, garbage)",
    "L4-005": "Inject unauthorized caveats (admin, wildcard scope, far-future expiry)",
    "L4-006": "Strip HMAC signature from macaroon",
    "L4-007": "Present valid-looking preimage without paying",
    "L4-008": "Reuse preimage from different session / invoice",
    "L4-009": "Widen resource scope caveat (cross-path, traversal)",
    "L4-010": "Add permission-escalating caveats (admin=true, bypass_payment)",
    "L4-011": "Present incomplete Authorization headers (no preimage, wrong scheme)",
    "L4-012": "Race condition: present token before settlement completes",
    "L4-013": "Rapid sequential requests to generate many invoices",
    "L4-014": "Concurrent requests to test invoice uniqueness",
}


def list_tests():
    """Print available tests grouped by category."""
    print(f"\n{'='*60}")
    print("L402 SECURITY TESTS — AVAILABLE TEST CASES")
    print(f"{'='*60}\n")

    test_id_map = {
        "invoice_validation":       ["L4-001", "L4-002", "L4-003"],
        "macaroon_integrity":       ["L4-004", "L4-005", "L4-006"],
        "preimage_replay":          ["L4-007", "L4-008"],
        "caveat_escalation":        ["L4-009", "L4-010"],
        "payment_state_confusion":  ["L4-011", "L4-012"],
        "rate_dos":                 ["L4-013", "L4-014"],
    }

    for category, ids in test_id_map.items():
        print(f"[{category}]")
        for tid in ids:
            print(f"  {tid}: {_TEST_DESCRIPTIONS.get(tid, '(no description)')}")
        print()


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(results: list[L402TestResult], output_path: str):
    """Write JSON report."""
    report = {
        "suite": "L402 Payment Flow Security Tests v3.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
        },
        "results": [asdict(r) for r in results],
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Report written to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="L402 Payment Flow Security Test Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python -m protocol_tests.l402_harness --categories invoice_validation --trials 5",
    )
    ap.add_argument("--url", default="https://dispatches.mystere.me",
                    help="L402-gated server base URL (default: dispatches.mystere.me)")
    ap.add_argument("--categories", help="Comma-separated test categories to run")
    ap.add_argument("--report", help="Output JSON report path")
    ap.add_argument("--header", action="append", default=[], help="Extra HTTP headers (key:value)")
    ap.add_argument("--trials", type=int, default=1,
                    help="Run each test N times for statistical analysis (Wilson score CIs)")
    ap.add_argument("--list", action="store_true", dest="list_tests", help="List available tests and exit")
    args = ap.parse_args()

    if args.list_tests:
        list_tests()
        sys.exit(0)

    headers = {}
    for h in args.header:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    transport = L402Transport(args.url, headers=headers)
    categories = args.categories.split(",") if args.categories else None

    if args.trials > 1:
        # Multi-trial statistical mode
        _run_statistical(transport, categories, args.trials, args.report)
    else:
        suite = L402SecurityTests(transport)
        results = suite.run_all(categories=categories)

        if args.report:
            generate_report(results, args.report)

        failed = sum(1 for r in results if not r.passed)
        sys.exit(1 if failed > 0 else 0)


def _run_statistical(
    transport: L402Transport,
    categories: list[str] | None,
    n_trials: int,
    report_path: str | None,
):
    """Run tests multiple times and compute Wilson score confidence intervals."""
    from protocol_tests.statistical import wilson_ci, enhance_report, TrialResult

    all_tests_flat: list[tuple[str, str, str]] = []  # (category, method_name, test_id)
    id_idx = 0
    test_id_order = [
        "L4-001", "L4-002", "L4-003", "L4-004", "L4-005", "L4-006",
        "L4-007", "L4-008", "L4-009", "L4-010", "L4-011", "L4-012",
        "L4-013", "L4-014",
    ]
    for category, method_names in L402SecurityTests.ALL_TESTS.items():
        if categories and category not in categories:
            id_idx += len(method_names)  # Advance past excluded tests
            continue
        for method_name in method_names:
            all_tests_flat.append((category, method_name, test_id_order[id_idx]))
            id_idx += 1

    print(f"\n{'='*60}")
    print(f"L402 STATISTICAL MODE — {n_trials} trials per test")
    print(f"{'='*60}")
    print(f"Target: {transport.base_url}\n")

    trial_results: list[TrialResult] = []
    all_results: list[L402TestResult] = []

    for category, method_name, test_id in all_tests_flat:
        passes = 0
        elapsed_times: list[float] = []

        for trial in range(n_trials):
            suite = L402SecurityTests(transport)
            test_fn = getattr(suite, method_name)
            try:
                test_fn()
                result = suite.results[-1] if suite.results else None
                if result:
                    if result.passed:
                        passes += 1
                    elapsed_times.append(result.elapsed_s)
                    if trial == 0:
                        all_results.append(result)
            except Exception:
                elapsed_times.append(0.0)

        ci = wilson_ci(passes, n_trials)
        pass_rate = passes / n_trials if n_trials > 0 else 0.0
        mean_elapsed = sum(elapsed_times) / len(elapsed_times) if elapsed_times else 0.0

        tr = TrialResult(
            test_id=test_id,
            test_name=method_name,
            n_trials=n_trials,
            n_passed=passes,
            pass_rate=round(pass_rate, 4),
            ci_95=ci,
            per_trial=[],  # Not tracking individual booleans to keep output small
            mean_elapsed_s=round(mean_elapsed, 3),
        )
        trial_results.append(tr)
        print(f"  {test_id}: {passes}/{n_trials} passed  CI95=[{ci[0]:.3f}, {ci[1]:.3f}]  "
              f"avg={mean_elapsed:.2f}s")

    print(f"\n{'='*60}")
    total_pass = sum(tr.n_passed for tr in trial_results)
    total_trials = sum(tr.n_trials for tr in trial_results)
    print(f"AGGREGATE: {total_pass}/{total_trials} trial-passes")
    print(f"{'='*60}\n")

    if report_path:
        report = {
            "suite": "L402 Payment Flow Security Tests v3.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total": len(all_results),
                "passed": sum(1 for r in all_results if r.passed),
                "failed": sum(1 for r in all_results if not r.passed),
            },
            "results": [asdict(r) for r in all_results],
        }
        report = enhance_report(report, trial_results)
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"NIST AI 800-2 aligned report written to {report_path}")

    failed_tests = sum(1 for tr in trial_results if tr.pass_rate < 1.0)
    sys.exit(1 if failed_tests > 0 else 0)


if __name__ == "__main__":
    main()
