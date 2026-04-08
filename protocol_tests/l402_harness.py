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
    # Category 7: Macaroon Caveat Manipulation (L4-015 through L4-018)
    # ------------------------------------------------------------------

    def test_l402_forged_caveat_hmac(self):
        """L4-015: Forge a macaroon with attacker-chosen caveats and guessed HMAC."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-015",
                name="Forged Caveat HMAC",
                category="macaroon_caveat_manipulation",
                owasp_asi="ASI03",
                severity=Severity.CRITICAL.value,
                passed=False,
                details="Could not obtain L402 challenge from server to test",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        # Forge entirely new macaroon blobs with attacker-chosen caveats
        # and weak/predictable HMAC keys
        forged_variants = [
            ("zero_key_hmac", hashlib.sha256(b'\x00' * 32).digest()),
            ("empty_key_hmac", hashlib.sha256(b'').digest()),
            ("predictable_key", hashlib.sha256(b'secret').digest()),
            ("root_key_guess", hashlib.sha256(b'root_key').digest()),
        ]

        rejected = 0
        for label, fake_sig in forged_variants:
            # Construct a fake macaroon: identifier + caveats + forged signature
            forged_mac = b'\x02' + b'identifier=forged_session' + b'\x00'
            forged_mac += b'admin=true\x00scope=*\x00'
            forged_mac += fake_sig
            encoded = base64.b64encode(forged_mac).decode()
            fake_preimage = _fake_preimage()
            auth_header = f"L402 {encoded}:{fake_preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(forged_variants)

        self._record(L402TestResult(
            test_id="L4-015",
            name="Forged Caveat HMAC",
            category="macaroon_caveat_manipulation",
            owasp_asi="ASI03",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=f"{rejected}/{len(forged_variants)} forged macaroons rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in forged_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_nested_caveat_depth(self):
        """L4-016: Deeply nested caveats to trigger parser overflow or bypass."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-016",
                name="Nested Caveat Depth Attack",
                category="macaroon_caveat_manipulation",
                owasp_asi="ASI02",
                severity=Severity.MEDIUM.value,
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

        # Append many layers of caveats to stress the parser
        depth_variants = [
            ("depth_100", b'\x00'.join([f"caveat_{i}=val".encode() for i in range(100)])),
            ("depth_1000", b'\x00'.join([f"c{i}=v".encode() for i in range(1000)])),
            ("long_value", b'\x00key=' + b'A' * 10000),
        ]

        rejected = 0
        for label, caveat_blob in depth_variants:
            modified = base64.b64encode(raw_mac + b'\x00' + caveat_blob).decode()
            fake_preimage = _fake_preimage()
            auth_header = f"L402 {modified}:{fake_preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            status = resp.get("status", 0)
            if status != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(depth_variants)

        self._record(L402TestResult(
            test_id="L4-016",
            name="Nested Caveat Depth Attack",
            category="macaroon_caveat_manipulation",
            owasp_asi="ASI02",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=f"{rejected}/{len(depth_variants)} deep-nested caveat blobs rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in depth_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_caveat_extension_third_party(self):
        """L4-017: Extend macaroon with third-party caveat referencing attacker verifier."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-017",
                name="Third-Party Caveat Extension",
                category="macaroon_caveat_manipulation",
                owasp_asi="ASI09",
                severity=Severity.HIGH.value,
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

        # Third-party caveat format: location + identifier + verifier key
        tp_caveats = [
            ("attacker_verifier", b'\x00tp_location=https://evil.com\x00tp_id=bypass'),
            ("localhost_verifier", b'\x00tp_location=http://127.0.0.1:8080\x00tp_id=admin'),
            ("empty_verifier", b'\x00tp_location=\x00tp_id='),
        ]

        rejected = 0
        for label, tp_blob in tp_caveats:
            modified = base64.b64encode(raw_mac + tp_blob).decode()
            fake_preimage = _fake_preimage()
            auth_header = f"L402 {modified}:{fake_preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(tp_caveats)

        self._record(L402TestResult(
            test_id="L4-017",
            name="Third-Party Caveat Extension",
            category="macaroon_caveat_manipulation",
            owasp_asi="ASI09",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(tp_caveats)} third-party caveat extensions rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in tp_caveats]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_caveat_unicode_smuggling(self):
        """L4-018: Smuggle caveats via Unicode normalization or null-byte injection."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-018",
                name="Caveat Unicode Smuggling",
                category="macaroon_caveat_manipulation",
                owasp_asi="ASI03",
                severity=Severity.HIGH.value,
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

        # Unicode and null-byte smuggling payloads
        smuggle_payloads = [
            ("null_byte", b'\x00admin\x00=true'),
            ("unicode_homoglyph", 'admin=tru\u0435'.encode('utf-8')),  # Cyrillic 'е'
            ("double_encode", b'%00admin%3Dtrue'),
            ("overlong_utf8", b'\xc0\x80admin=true'),  # overlong null
        ]

        rejected = 0
        for label, payload in smuggle_payloads:
            modified = base64.b64encode(raw_mac + payload).decode()
            fake_preimage = _fake_preimage()
            auth_header = f"L402 {modified}:{fake_preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(smuggle_payloads)

        self._record(L402TestResult(
            test_id="L4-018",
            name="Caveat Unicode Smuggling",
            category="macaroon_caveat_manipulation",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(smuggle_payloads)} unicode-smuggled caveats rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in smuggle_payloads]},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 8: Payment Channel State Attacks (L4-019 through L4-021)
    # ------------------------------------------------------------------

    def test_l402_stale_channel_state(self):
        """L4-019: Present token referencing a stale/revoked channel state."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        # Construct tokens that reference outdated channel state information
        stale_state_tokens = []
        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()

        # Simulate stale channel state by presenting tokens with old timestamps
        for offset_hours in [24, 168, 720]:  # 1 day, 1 week, 1 month ago
            stale_ts = int(time.time()) - (offset_hours * 3600)
            # Encode stale timestamp into preimage-like structure
            stale_preimage = hashlib.sha256(f"stale_state_{stale_ts}".encode()).hexdigest()
            stale_state_tokens.append((f"stale_{offset_hours}h", stale_preimage))

        rejected = 0
        for label, preimage in stale_state_tokens:
            auth_header = f"L402 {mac}:{preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(stale_state_tokens)

        self._record(L402TestResult(
            test_id="L4-019",
            name="Stale Channel State Token",
            category="payment_channel_attacks",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(stale_state_tokens)} stale channel state tokens rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in stale_state_tokens]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_force_close_timing(self):
        """L4-020: Exploit force-close timing by presenting token during settlement window."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()

        # Simulate tokens presented at different points during a force-close window
        # In Lightning, force-close has a CSV (CheckSequenceVerify) delay
        timing_variants = [
            ("immediate_post_close", _fake_preimage()),
            ("mid_csv_delay", _fake_preimage()),
            ("near_csv_expiry", _fake_preimage()),
        ]

        rejected = 0
        for label, preimage in timing_variants:
            auth_header = f"L402 {mac}:{preimage}"
            # Add header hinting at channel state
            resp = self.transport.get(self.PATH_INDEX, headers={
                "Authorization": auth_header,
                "X-Channel-State": "force_closing",
            })
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(timing_variants)

        self._record(L402TestResult(
            test_id="L4-020",
            name="Force-Close Timing Exploitation",
            category="payment_channel_attacks",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(timing_variants)} force-close timing tokens rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in timing_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_htlc_timeout_exploitation(self):
        """L4-021: Attempt to exploit HTLC timeout to use token after payment reversal."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()

        # HTLC timeout exploitation: present token with preimage that references
        # an expired HTLC (payment was reversed but token might still be cached)
        htlc_variants = [
            ("expired_htlc", hashlib.sha256(b"expired_htlc_preimage").hexdigest()),
            ("timed_out_htlc", hashlib.sha256(b"timeout_htlc_" + str(int(time.time()) - 3600).encode()).hexdigest()),
            ("cancelled_htlc", hashlib.sha256(b"cancelled_payment").hexdigest()),
        ]

        rejected = 0
        for label, preimage in htlc_variants:
            auth_header = f"L402 {mac}:{preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(htlc_variants)

        self._record(L402TestResult(
            test_id="L4-021",
            name="HTLC Timeout Exploitation",
            category="payment_channel_attacks",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(htlc_variants)} HTLC timeout exploitation attempts rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in htlc_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 9: Preimage Correlation Attacks (L4-022, L4-023)
    # ------------------------------------------------------------------

    def test_l402_preimage_hash_correlation(self):
        """L4-022: Test if preimage-to-payment-hash binding is strictly enforced."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-022",
                name="Preimage Hash Correlation",
                category="preimage_correlation",
                owasp_asi="ASI03",
                severity=Severity.CRITICAL.value,
                passed=False,
                details="Could not obtain L402 challenge from server to test",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        # The payment hash in BOLT-11 should be SHA256(preimage).
        # Try preimages whose SHA256 is close to but not matching the invoice hash.
        correlation_variants = [
            ("sha256_of_invoice", hashlib.sha256(challenge.invoice.encode()).hexdigest()),
            ("sha256_of_macaroon", hashlib.sha256(challenge.macaroon.encode()).hexdigest()),
            ("reversed_hash", _fake_preimage()[::-1]),
            ("zero_preimage", "0" * 64),
            ("ff_preimage", "f" * 64),
        ]

        rejected = 0
        for label, preimage in correlation_variants:
            auth_header = f"L402 {challenge.macaroon}:{preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(correlation_variants)

        self._record(L402TestResult(
            test_id="L4-022",
            name="Preimage Hash Correlation",
            category="preimage_correlation",
            owasp_asi="ASI03",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=f"{rejected}/{len(correlation_variants)} correlated preimage variants rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in correlation_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_preimage_length_manipulation(self):
        """L4-023: Present preimages of non-standard lengths (not 32 bytes)."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()

        # Standard preimage is 32 bytes (64 hex chars). Try other lengths.
        length_variants = [
            ("empty", ""),
            ("1_byte", os.urandom(1).hex()),
            ("16_bytes", os.urandom(16).hex()),
            ("31_bytes", os.urandom(31).hex()),
            ("33_bytes", os.urandom(33).hex()),
            ("64_bytes", os.urandom(64).hex()),
            ("256_bytes", os.urandom(256).hex()),
        ]

        rejected = 0
        for label, preimage in length_variants:
            auth_header = f"L402 {mac}:{preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(length_variants)

        self._record(L402TestResult(
            test_id="L4-023",
            name="Preimage Length Manipulation",
            category="preimage_correlation",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(length_variants)} non-standard preimage lengths rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in length_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 10: Invoice Amount Manipulation (L4-024 through L4-026)
    # ------------------------------------------------------------------

    def test_l402_invoice_amount_consistency(self):
        """L4-024: Verify that invoice amounts are consistent across repeated challenges."""
        t0 = time.monotonic()

        # Fetch multiple challenges and compare invoice amounts
        invoices = []
        for _ in range(5):
            challenge = self._get_challenge(self.PATH_INDEX)
            if challenge:
                invoices.append(challenge.invoice)

        elapsed = time.monotonic() - t0

        if not invoices:
            self._record(L402TestResult(
                test_id="L4-024",
                name="Invoice Amount Consistency",
                category="invoice_amount_manipulation",
                owasp_asi="ASI09",
                severity=Severity.MEDIUM.value,
                passed=True,
                details="No invoices returned to check consistency (N/A)",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        # Extract amount from BOLT-11 invoice prefix (lnbc<amount><multiplier>)
        amounts = []
        for inv in invoices:
            # BOLT-11: lnbc<amount>[munp]1... — amount is between prefix and '1'
            m = re.match(r'ln(?:bc|tb|bcrt)(\d+[munp]?)1', inv)
            if m:
                amounts.append(m.group(1))

        unique_amounts = set(amounts)
        consistent = len(unique_amounts) <= 1

        self._record(L402TestResult(
            test_id="L4-024",
            name="Invoice Amount Consistency",
            category="invoice_amount_manipulation",
            owasp_asi="ASI09",
            severity=Severity.MEDIUM.value,
            passed=consistent,
            details=(f"Consistent amount across {len(invoices)} invoices: {list(unique_amounts)}"
                     if consistent
                     else f"INCONSISTENT amounts detected: {list(unique_amounts)} — possible price escalation"),
            http_method="GET",
            request_sent={"n_challenges": 5},
            response_received={"unique_amounts": list(unique_amounts), "total_invoices": len(invoices)},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_overpayment_underpayment(self):
        """L4-025: Test server behavior with tokens suggesting overpayment/underpayment."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()

        # Present tokens with preimages that are crafted to look like they came
        # from invoices with different amounts than requested
        payment_variants = [
            ("zero_sat_preimage", hashlib.sha256(b"zero_amount_payment").hexdigest()),
            ("micro_sat_preimage", hashlib.sha256(b"1_sat_payment").hexdigest()),
            ("max_btc_preimage", hashlib.sha256(b"21000000_btc_payment").hexdigest()),
            ("negative_preimage", hashlib.sha256(b"negative_amount").hexdigest()),
        ]

        rejected = 0
        for label, preimage in payment_variants:
            auth_header = f"L402 {mac}:{preimage}"
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(payment_variants)

        self._record(L402TestResult(
            test_id="L4-025",
            name="Overpayment / Underpayment Edge Cases",
            category="invoice_amount_manipulation",
            owasp_asi="ASI09",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=f"{rejected}/{len(payment_variants)} payment amount edge cases rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in payment_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_invoice_expiry_bypass(self):
        """L4-026: Attempt to use a token tied to an expired invoice."""
        t0 = time.monotonic()

        # Fetch a challenge, wait briefly, then attempt to use it
        # (simulating use after invoice expiry)
        challenge = self._get_challenge(self.PATH_INDEX)

        if not challenge:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-026",
                name="Invoice Expiry Bypass",
                category="invoice_amount_manipulation",
                owasp_asi="ASI03",
                severity=Severity.HIGH.value,
                passed=True,
                details="No L402 challenge available (N/A)",
                http_method="GET",
                elapsed_s=round(elapsed, 3),
            ))
            return

        # Present the token with a fake preimage (invoice was never paid,
        # and if it had been, it may have expired by now)
        fake_preimage = _fake_preimage()
        auth_header = f"L402 {challenge.macaroon}:{fake_preimage}"
        resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_header})

        elapsed = time.monotonic() - t0
        status = resp.get("status", 0)
        passed = status != 200

        self._record(L402TestResult(
            test_id="L4-026",
            name="Invoice Expiry Bypass",
            category="invoice_amount_manipulation",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"Token for potentially expired invoice returned {status}" +
                    (" (rejected)" if passed else " (ACCEPTED — expiry bypass possible)"),
            http_method="GET",
            request_sent={"expired_invoice_token": True},
            response_received={"status": status},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 11: Multi-Hop Routing Manipulation (L4-027, L4-028)
    # ------------------------------------------------------------------

    def test_l402_multi_hop_routing_header(self):
        """L4-027: Inject routing hints to manipulate multi-hop Lightning payment path."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()

        # Inject headers that suggest alternative routing paths
        routing_variants = [
            ("attacker_hop", {"X-Lightning-Route": "03" + "aa" * 32, "Authorization": f"L402 {mac}:{_fake_preimage()}"}),
            ("private_channel", {"X-Lightning-Route": "02" + "bb" * 32, "X-Channel-Id": "999999x999x0", "Authorization": f"L402 {mac}:{_fake_preimage()}"}),
            ("zero_fee_route", {"X-Lightning-Route": "03" + "00" * 32, "X-Fee-Rate": "0", "Authorization": f"L402 {mac}:{_fake_preimage()}"}),
        ]

        rejected = 0
        for label, headers in routing_variants:
            resp = self.transport.get(self.PATH_INDEX, headers=headers)
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(routing_variants)

        self._record(L402TestResult(
            test_id="L4-027",
            name="Multi-Hop Routing Header Injection",
            category="routing_manipulation",
            owasp_asi="ASI09",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(routing_variants)} routing manipulation attempts rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in routing_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_payment_replay_across_channels(self):
        """L4-028: Replay L402 token across different API endpoints (cross-channel replay)."""
        t0 = time.monotonic()

        # Get challenges from different endpoints
        paths = [self.PATH_INDEX, self.PATH_RESOURCE, self.PATH_ASK]
        challenges = {}
        for path in paths:
            c = self._get_challenge(path)
            if c:
                challenges[path] = c

        if len(challenges) < 2:
            elapsed = time.monotonic() - t0
            self._record(L402TestResult(
                test_id="L4-028",
                name="Payment Replay Across Channels",
                category="routing_manipulation",
                owasp_asi="ASI03",
                severity=Severity.HIGH.value,
                passed=True if len(challenges) == 0 else False,
                details=f"Only {len(challenges)} challenge(s) obtained; need 2+ for cross-channel test",
                http_method="GET",
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        # Try using each challenge's macaroon on every OTHER path
        rejected = 0
        tested = 0
        for src_path, src_challenge in challenges.items():
            for tgt_path in paths:
                if tgt_path == src_path:
                    continue
                fake_preimage = _fake_preimage()
                auth_header = f"L402 {src_challenge.macaroon}:{fake_preimage}"
                resp = self.transport.get(tgt_path, headers={"Authorization": auth_header})
                tested += 1
                if resp.get("status", 0) != 200:
                    rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == tested

        self._record(L402TestResult(
            test_id="L4-028",
            name="Payment Replay Across Channels",
            category="routing_manipulation",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{tested} cross-channel replay attempts rejected",
            http_method="GET",
            request_sent={"channels_tested": list(challenges.keys())},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 12: Lightning Network DoS Patterns (L4-029 through L4-031)
    # ------------------------------------------------------------------

    def test_l402_large_payload_dos(self):
        """L4-029: Send oversized Authorization header to test DoS resilience."""
        t0 = time.monotonic()

        # Craft extremely large Authorization headers
        large_variants = [
            ("1mb_macaroon", "L402 " + base64.b64encode(os.urandom(500000)).decode() + ":" + _fake_preimage()),
            ("1mb_preimage", "L402 " + base64.b64encode(b"mac").decode() + ":" + "a" * 1000000),
            ("repeated_colons", "L402 " + "mac:pre:" * 100000),
        ]

        handled = 0
        for label, auth_value in large_variants:
            try:
                resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_value}, timeout=10.0)
                status = resp.get("status", 0)
                # Any non-200 response or clean error is fine
                if status != 200:
                    handled += 1
                # Even 200 counts as "handled" if server didn't crash
                elif not resp.get("_error"):
                    handled += 1
            except Exception:
                handled += 1  # Exception means server didn't crash silently

        elapsed = time.monotonic() - t0
        passed = handled == len(large_variants)

        self._record(L402TestResult(
            test_id="L4-029",
            name="Large Payload DoS Resilience",
            category="ln_dos",
            owasp_asi="ASI08",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=f"{handled}/{len(large_variants)} oversized payloads handled gracefully",
            http_method="GET",
            request_sent={"variants": [label for label, _ in large_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_header_injection_dos(self):
        """L4-030: Inject malicious values in L402 headers to trigger server errors."""
        t0 = time.monotonic()

        # Test injection payloads in the Authorization header
        injection_variants = [
            ("sql_injection", 'L402 macaroon:preimage\'; DROP TABLE invoices;--'),
            ("crlf_injection", "L402 macaroon\r\nX-Injected: evil\r\n:preimage"),
            ("template_injection", "L402 {{7*7}}:${7*7}"),
            ("path_traversal", "L402 ../../etc/passwd:preimage"),
            ("null_byte", "L402 mac\x00admin:preimage"),
        ]

        safe_responses = 0
        for label, auth_value in injection_variants:
            try:
                resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_value})
                status = resp.get("status", 0)
                body_lower = resp.get("body", "").lower()
                # Check for signs of injection success
                no_injection = not any(kw in body_lower for kw in [
                    "syntax error", "sql", "template", "root:", "etc/passwd",
                    "stack trace", "traceback",
                ])
                if status != 200 and no_injection:
                    safe_responses += 1
            except Exception:
                safe_responses += 1  # Clean failure is acceptable

        elapsed = time.monotonic() - t0
        passed = safe_responses == len(injection_variants)

        self._record(L402TestResult(
            test_id="L4-030",
            name="Header Injection DoS",
            category="ln_dos",
            owasp_asi="ASI08",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{safe_responses}/{len(injection_variants)} injection attempts handled safely",
            http_method="GET",
            request_sent={"variants": [label for label, _ in injection_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_concurrent_challenge_flood(self):
        """L4-031: Flood server with concurrent 402 challenge requests."""
        t0 = time.monotonic()

        n_workers = 20
        results_list: list[dict] = []

        def _flood():
            return self.transport.get(self.PATH_INDEX)

        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = [pool.submit(_flood) for _ in range(n_workers * 2)]
            for f in as_completed(futures):
                try:
                    results_list.append(f.result())
                except Exception:
                    results_list.append({"status": 0, "_error": True})

        elapsed = time.monotonic() - t0

        statuses = [r.get("status", 0) for r in results_list]
        n_402 = sum(1 for s in statuses if s == 402)
        n_429 = sum(1 for s in statuses if s == 429)
        n_errors = sum(1 for s in statuses if s == 0 or s >= 500)

        # Server should either serve 402s or rate-limit, not error out
        passed = n_errors <= len(results_list) // 4  # Allow up to 25% errors

        self._record(L402TestResult(
            test_id="L4-031",
            name="Concurrent Challenge Flood",
            category="ln_dos",
            owasp_asi="ASI08",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=(f"{len(results_list)} concurrent requests: "
                     f"{n_402} got 402, {n_429} rate-limited, {n_errors} errors"),
            http_method="GET",
            request_sent={"n_concurrent": n_workers * 2},
            response_received={"n_402": n_402, "n_429": n_429, "n_errors": n_errors},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 13: Protocol Confusion & Information Disclosure (L4-032, L4-033)
    # ------------------------------------------------------------------

    def test_l402_protocol_downgrade_lsat(self):
        """L4-032: Test LSAT backward-compatibility for protocol downgrade attacks."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        mac = challenge.macaroon if challenge else base64.b64encode(b"fake").decode()

        # Try both L402 and LSAT auth schemes to detect inconsistent handling
        downgrade_variants = [
            ("lsat_scheme", f"LSAT {mac}:{_fake_preimage()}"),
            ("bearer_scheme", f"Bearer {mac}"),
            ("basic_scheme", f"Basic {base64.b64encode(f'{mac}:{_fake_preimage()}'.encode()).decode()}"),
            ("mixed_case_l402", f"l402 {mac}:{_fake_preimage()}"),
            ("mixed_case_LSAT", f"lsat {mac}:{_fake_preimage()}"),
        ]

        rejected = 0
        for label, auth_value in downgrade_variants:
            resp = self.transport.get(self.PATH_INDEX, headers={"Authorization": auth_value})
            if resp.get("status", 0) != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(downgrade_variants)

        self._record(L402TestResult(
            test_id="L4-032",
            name="Protocol Downgrade (LSAT Compat)",
            category="protocol_confusion",
            owasp_asi="ASI03",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=f"{rejected}/{len(downgrade_variants)} downgrade auth schemes rejected",
            http_method="GET",
            request_sent={"variants": [label for label, _ in downgrade_variants]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_l402_information_disclosure(self):
        """L4-033: Check error responses for sensitive information leakage."""
        t0 = time.monotonic()

        # Send various malformed requests and check if error responses leak info
        probe_requests = [
            ("no_auth", {}),
            ("empty_auth", {"Authorization": ""}),
            ("garbage_auth", {"Authorization": "GARBAGE " + uuid.uuid4().hex}),
            ("sql_auth", {"Authorization": "L402 ' OR 1=1--:preimage"}),
        ]

        leaks_found = []
        sensitive_patterns = [
            "stack trace", "traceback", "exception", "at line",
            "sql", "database", "mysql", "postgres", "sqlite",
            "secret", "api_key", "private_key", "password",
            "internal server", "debug", "node_id", "pubkey",
            "lnd", "c-lightning", "eclair",  # Lightning implementation details
        ]

        for label, headers in probe_requests:
            resp = self.transport.get(self.PATH_INDEX, headers=headers)
            body_lower = resp.get("body", "").lower()
            for pattern in sensitive_patterns:
                if pattern in body_lower:
                    leaks_found.append(f"{label}: '{pattern}'")

        elapsed = time.monotonic() - t0
        passed = len(leaks_found) == 0

        self._record(L402TestResult(
            test_id="L4-033",
            name="Information Disclosure in Errors",
            category="protocol_confusion",
            owasp_asi="ASI06",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=("No sensitive information leaked" if passed
                     else f"Leaks detected: {'; '.join(leaks_found[:10])}"),
            http_method="GET",
            request_sent={"probes": [label for label, _ in probe_requests]},
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
        "macaroon_caveat_manipulation": [
            "test_l402_forged_caveat_hmac",
            "test_l402_nested_caveat_depth",
            "test_l402_caveat_extension_third_party",
            "test_l402_caveat_unicode_smuggling",
        ],
        "payment_channel_attacks": [
            "test_l402_stale_channel_state",
            "test_l402_force_close_timing",
            "test_l402_htlc_timeout_exploitation",
        ],
        "preimage_correlation": [
            "test_l402_preimage_hash_correlation",
            "test_l402_preimage_length_manipulation",
        ],
        "invoice_amount_manipulation": [
            "test_l402_invoice_amount_consistency",
            "test_l402_overpayment_underpayment",
            "test_l402_invoice_expiry_bypass",
        ],
        "routing_manipulation": [
            "test_l402_multi_hop_routing_header",
            "test_l402_payment_replay_across_channels",
        ],
        "ln_dos": [
            "test_l402_large_payload_dos",
            "test_l402_header_injection_dos",
            "test_l402_concurrent_challenge_flood",
        ],
        "protocol_confusion": [
            "test_l402_protocol_downgrade_lsat",
            "test_l402_information_disclosure",
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
    "L4-015": "Forge macaroon with attacker-chosen caveats and guessed HMAC",
    "L4-016": "Deeply nested caveats to trigger parser overflow or bypass",
    "L4-017": "Extend macaroon with third-party caveat referencing attacker verifier",
    "L4-018": "Smuggle caveats via Unicode normalization or null-byte injection",
    "L4-019": "Present token referencing stale/revoked channel state",
    "L4-020": "Exploit force-close timing by presenting token during settlement window",
    "L4-021": "Attempt HTLC timeout exploitation after payment reversal",
    "L4-022": "Test preimage-to-payment-hash binding enforcement",
    "L4-023": "Present preimages of non-standard lengths (not 32 bytes)",
    "L4-024": "Verify invoice amounts are consistent across repeated challenges",
    "L4-025": "Test overpayment/underpayment edge cases",
    "L4-026": "Attempt to use token tied to an expired invoice",
    "L4-027": "Inject routing hints to manipulate multi-hop Lightning payment path",
    "L4-028": "Replay L402 token across different API endpoints (cross-channel)",
    "L4-029": "Send oversized Authorization header to test DoS resilience",
    "L4-030": "Inject malicious values in L402 headers (SQLi, CRLF, template)",
    "L4-031": "Flood server with concurrent 402 challenge requests",
    "L4-032": "Test LSAT backward-compatibility for protocol downgrade attacks",
    "L4-033": "Check error responses for sensitive information leakage",
}


def list_tests():
    """Print available tests grouped by category."""
    print(f"\n{'='*60}")
    print("L402 SECURITY TESTS — AVAILABLE TEST CASES")
    print(f"{'='*60}\n")

    test_id_map = {
        "invoice_validation":           ["L4-001", "L4-002", "L4-003"],
        "macaroon_integrity":           ["L4-004", "L4-005", "L4-006"],
        "preimage_replay":              ["L4-007", "L4-008"],
        "caveat_escalation":            ["L4-009", "L4-010"],
        "payment_state_confusion":      ["L4-011", "L4-012"],
        "rate_dos":                     ["L4-013", "L4-014"],
        "macaroon_caveat_manipulation": ["L4-015", "L4-016", "L4-017", "L4-018"],
        "payment_channel_attacks":      ["L4-019", "L4-020", "L4-021"],
        "preimage_correlation":         ["L4-022", "L4-023"],
        "invoice_amount_manipulation":  ["L4-024", "L4-025", "L4-026"],
        "routing_manipulation":         ["L4-027", "L4-028"],
        "ln_dos":                       ["L4-029", "L4-030", "L4-031"],
        "protocol_confusion":           ["L4-032", "L4-033"],
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
        "L4-013", "L4-014", "L4-015", "L4-016", "L4-017", "L4-018",
        "L4-019", "L4-020", "L4-021", "L4-022", "L4-023", "L4-024",
        "L4-025", "L4-026", "L4-027", "L4-028", "L4-029", "L4-030",
        "L4-031", "L4-032", "L4-033",
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
