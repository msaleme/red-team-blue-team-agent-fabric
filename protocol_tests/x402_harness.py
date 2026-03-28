#!/usr/bin/env python3
"""x402 Payment Protocol Security Test Harness (v1.0)

The FIRST open-source security test harness for Coinbase's x402 payment protocol.

x402 Protocol Overview:
    x402 is an open standard for internet-native agent payments, built on
    HTTP 402 Payment Required. The flow is:

    1. Agent requests a protected resource.
    2. Server returns HTTP 402 with payment headers:
       - X-Payment-Required: true
       - X-Payment-Amount: amount in smallest unit
       - X-Payment-Currency: USDC (or other supported token)
       - X-Payment-Recipient: wallet address (payTo)
       - X-Payment-Network: blockchain network (e.g., base, base-sepolia)
    3. Agent signs a USDC payment authorization and resubmits with:
       - X-Payment-Authorization: signed payment payload
    4. x402 Facilitator verifies payment on-chain and grants access.

    V2 additions: dynamic payTo routing, wallet-based session identity
    (CAIP-122), modular plugin SDK.

    Specification: https://www.x402.org/x402-whitepaper.pdf
    Security Analysis: https://www.halborn.com/blog/post/x402-explained-security-risks-and-controls-for-http-402-micropayments

This harness does NOT spend real money. All tests craft HTTP requests and
analyze server responses. No real transactions, no wallet keys, no on-chain
interactions.

Innovative Features:
    - Decision Governance Scoring (CSG mapping per test)
    - Financial Impact Estimation per finding
    - Agent Autonomy Risk Score (0-100): answers "How dangerous is it to let
      an autonomous agent pay this endpoint without human oversight?"

Usage:
    # Test against an x402-gated endpoint
    python -m protocol_tests.x402_harness --url https://x402-server.example.com

    # Run specific test categories
    python -m protocol_tests.x402_harness --url https://x402-server.example.com \\
        --categories payment_challenge,recipient_manipulation

    # List available tests
    python -m protocol_tests.x402_harness --list

    # Multi-trial statistical mode
    python -m protocol_tests.x402_harness --url https://x402-server.example.com \\
        --trials 10 --report x402_report.json

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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import http.client
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# x402 protocol constants and primitives
# ---------------------------------------------------------------------------

# Required x402 payment challenge headers
X402_REQUIRED_HEADERS = [
    "x-payment-required",
    "x-payment-amount",
    "x-payment-currency",
    "x-payment-recipient",
    "x-payment-network",
]

# Common EVM zero/invalid addresses
ZERO_ADDRESS = "0x" + "0" * 40
INVALID_ADDRESSES = [
    "0x" + "0" * 40,          # zero address
    "0x" + "f" * 40,          # all-ones address
    "0x1234",                  # too short
    "0x" + "g" * 40,          # invalid hex chars
    "not_an_address",          # not hex at all
    "",                        # empty
]

# Ethereum address pattern
ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _fake_payment_authorization() -> str:
    """Generate a fake X-Payment-Authorization (random bytes, base64-encoded)."""
    return base64.b64encode(os.urandom(128)).decode("ascii")


def _fake_jwt() -> str:
    """Generate a fake JWT-shaped token."""
    header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": "0x" + os.urandom(20).hex(),
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "amt": "1000000",
    }).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip("=")
    return f"{header}.{payload}.{sig}"


# ---------------------------------------------------------------------------
# HTTP transport for x402 endpoints
# ---------------------------------------------------------------------------

class X402Transport:
    """HTTP transport for x402-gated APIs."""

    def __init__(self, base_url: str, headers: dict | None = None,
                 paid_path: str = "", default_method: str = "GET",
                 default_body: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.paid_path = paid_path  # Path that returns 402 (e.g., /api/v1/tools/weather/call)
        self.default_method = default_method.upper()
        self.default_body = default_body  # Optional JSON body for POST endpoints

    def request(
        self,
        method: str,
        path: str = "",
        body: bytes | None = None,
        headers: dict | None = None,
        timeout: float = 15.0,
    ) -> dict:
        """Send an HTTP request and return a structured response dict.

        Returns dict with keys:
            status: int HTTP status code
            headers: dict of response headers (lowercase keys)
            body: str response body (truncated to 2000 chars)
            _error: bool (only on exception)
            _exception: str (only on exception)
        """
        # Use paid_path as default when no explicit path given (for x402 payment tests)
        effective_path = path if path else self.paid_path
        url = f"{self.base_url}{effective_path}" if effective_path else self.base_url
        all_headers = {**self.headers, **(headers or {})}
        req = urllib.request.Request(url, data=body, headers=all_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                # Normalize header keys to lowercase for consistent access
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return {
                    "status": resp.status,
                    "headers": resp_headers,
                    "body": resp_body[:2000],
                }
        except urllib.error.HTTPError as e:
            resp_body = ""
            resp_headers = {}
            try:
                resp_body = e.read().decode("utf-8", errors="replace")[:2000]
                resp_headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            except Exception:
                pass
            return {
                "status": e.code,
                "headers": resp_headers,
                "body": resp_body,
            }
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "_error": True, "_exception": str(e)}

    def get(self, path: str = "", headers: dict | None = None, timeout: float = 15.0) -> dict:
        """Send a request using the transport's default method and body.

        Despite the name, this respects ``default_method`` so that callers
        (all existing tests) automatically use POST when ``--method POST``
        is passed without requiring per-call changes.
        """
        body = self.default_body.encode("utf-8") if self.default_body else None
        extra_headers = dict(headers or {})
        if body and "Content-Type" not in extra_headers:
            extra_headers["Content-Type"] = "application/json"
        return self.request(self.default_method, path, body=body,
                            headers=extra_headers, timeout=timeout)

    def post(self, path: str = "", body: bytes | None = None, headers: dict | None = None, timeout: float = 15.0) -> dict:
        return self.request("POST", path, body=body, headers=headers, timeout=timeout)


# ---------------------------------------------------------------------------
# x402 challenge parser
# ---------------------------------------------------------------------------

@dataclass
class X402Challenge:
    """Parsed x402 payment challenge from a 402 response."""
    amount: str
    currency: str
    recipient: str
    network: str
    raw_headers: dict
    extra_headers: dict = field(default_factory=dict)

    @classmethod
    def from_response(cls, resp: dict) -> X402Challenge | None:
        """Parse x402 challenge headers from an HTTP response."""
        headers = resp.get("headers", {})
        # Check for required headers (case-insensitive)
        amount = headers.get("x-payment-amount", "")
        currency = headers.get("x-payment-currency", "")
        recipient = headers.get("x-payment-recipient", "")
        network = headers.get("x-payment-network", "")

        if not (amount or currency or recipient or network):
            return None

        # Capture any extra x-payment-* headers
        extra = {k: v for k, v in headers.items()
                 if k.startswith("x-payment-") and k not in X402_REQUIRED_HEADERS}

        return cls(
            amount=amount,
            currency=currency,
            recipient=recipient,
            network=network,
            raw_headers=headers,
            extra_headers=extra,
        )


# ---------------------------------------------------------------------------
# Test result model (extended with x402-specific fields)
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "P0-Critical"
    HIGH = "P1-High"
    MEDIUM = "P2-Medium"
    LOW = "P3-Low"


@dataclass
class X402TestResult:
    test_id: str
    name: str
    category: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str
    http_method: str
    # x402-specific innovative fields
    csg_mapping: str = ""             # Decision governance mechanism
    estimated_impact: str = ""        # fund_theft / overpayment / service_denial / info_leak / session_hijack
    estimated_severity: str = ""      # critical / high / medium / low
    # Standard fields
    request_sent: dict | None = None
    response_received: dict | None = None
    elapsed_s: float = 0.0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# x402 Security Test Suite
# ---------------------------------------------------------------------------

class X402SecurityTests:
    """Protocol-level security tests for x402-gated APIs.

    The FIRST open-source x402 security test harness.
    """

    def __init__(self, transport: X402Transport):
        self.transport = transport
        self.results: list[X402TestResult] = []
        self._cached_challenge: X402Challenge | None = None
        # Track data for autonomy risk scoring
        self._autonomy_signals: dict[str, bool] = {}

    def _record(self, result: X402TestResult):
        self.results.append(result)
        status = "PASS \u2705" if result.passed else "FAIL \u274c"
        print(f"  {status} {result.test_id}: {result.name} ({result.elapsed_s:.2f}s)")

    @property
    def _paid_path(self) -> str:
        """Return the paid path for tests expecting 402 responses."""
        return self.transport.paid_path

    def _get_challenge(self, path: str = "") -> X402Challenge | None:
        """Fetch a fresh x402 challenge from the server (expects 402)."""
        target = path or self._paid_path
        resp = self.transport.get(target)
        if resp.get("status") == 402:
            return X402Challenge.from_response(resp)
        return None

    def _ensure_challenge(self) -> X402Challenge | None:
        """Return a cached challenge or fetch a new one."""
        if not self._cached_challenge:
            self._cached_challenge = self._get_challenge()
        return self._cached_challenge

    # ------------------------------------------------------------------
    # Category 1: Payment Challenge Validation (X4-001 to X4-003)
    # ------------------------------------------------------------------

    def test_x402_challenge_headers_present(self):
        """X4-001: Verify 402 response contains all required X-Payment-* headers."""
        t0 = time.monotonic()
        resp = self.transport.get()
        elapsed = time.monotonic() - t0

        status = resp.get("status", 0)
        headers = resp.get("headers", {})

        issues = []
        if status != 402:
            issues.append(f"Expected HTTP 402, got {status}")

        missing_headers = []
        for h in X402_REQUIRED_HEADERS:
            if not headers.get(h):
                missing_headers.append(h)

        if missing_headers:
            issues.append(f"Missing headers: {missing_headers}")
        else:
            # Cache the challenge for subsequent tests
            challenge = X402Challenge.from_response(resp)
            if challenge:
                self._cached_challenge = challenge
                # Validate recipient address format
                if challenge.recipient and not ETH_ADDRESS_RE.match(challenge.recipient):
                    issues.append(f"Recipient address invalid format: {challenge.recipient[:60]}")
                # Validate amount is numeric
                try:
                    int(challenge.amount)
                except (ValueError, TypeError):
                    issues.append(f"Amount is not numeric: {challenge.amount}")

        passed = len(issues) == 0
        self._autonomy_signals["challenge_valid"] = passed

        self._record(X402TestResult(
            test_id="X4-001",
            name="402 Payment Challenge Headers Present",
            category="payment_challenge",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details="; ".join(issues) if issues else "All required X-Payment-* headers present with valid values",
            http_method="GET",
            csg_mapping="HC-1: Payment protocol must return complete challenge",
            estimated_impact="service_denial",
            estimated_severity="high",
            request_sent={"path": "/"},
            response_received={"status": status, "x_payment_headers": {
                h: headers.get(h, "(missing)") for h in X402_REQUIRED_HEADERS
            }},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_malformed_payment_headers(self):
        """X4-002: Submit request with malformed X-Payment-Authorization and check handling."""
        t0 = time.monotonic()

        malformed_payloads = [
            ("empty", ""),
            ("garbage", "not_a_valid_payment_" + uuid.uuid4().hex),
            ("truncated_b64", base64.b64encode(b"truncated")[:10].decode()),
            ("null_bytes", base64.b64encode(b"\x00" * 64).decode()),
            ("oversized", "A" * 10000),
        ]

        rejected = 0
        tested = 0
        for label, payload in malformed_payloads:
            resp = self.transport.get(headers={"X-Payment-Authorization": payload})
            tested += 1
            status = resp.get("status", 0)
            if status != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == tested

        self._record(X402TestResult(
            test_id="X4-002",
            name="Malformed Payment Authorization Rejection",
            category="payment_challenge",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{tested} malformed authorizations rejected",
            http_method="GET",
            csg_mapping="HC-2: Server must validate payment authorization format",
            estimated_impact="fund_theft",
            estimated_severity="critical",
            request_sent={"variants": [label for label, _ in malformed_payloads]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_unsupported_currency(self):
        """X4-003: Claim unsupported currency in payment to test scheme negotiation."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        fake_auth = _fake_payment_authorization()
        unsupported_currencies = ["ETH", "BTC", "EURC", "DAI", "FAKE_TOKEN"]

        rejected = 0
        for currency in unsupported_currencies:
            resp = self.transport.get(headers={
                "X-Payment-Authorization": fake_auth,
                "X-Payment-Currency": currency,
            })
            status = resp.get("status", 0)
            if status != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(unsupported_currencies)

        self._record(X402TestResult(
            test_id="X4-003",
            name="Unsupported Currency Rejection",
            category="payment_challenge",
            owasp_asi="ASI03",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=f"{rejected}/{len(unsupported_currencies)} unsupported currency claims rejected",
            http_method="GET",
            csg_mapping="HC-3: Server must validate payment currency matches requirement",
            estimated_impact="overpayment",
            estimated_severity="medium",
            request_sent={"currencies_tested": unsupported_currencies},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 2: Recipient Address Manipulation (X4-004 to X4-006)
    # ------------------------------------------------------------------

    def test_x402_dynamic_routing_detection(self):
        """X4-004: Request twice, check if payTo address changes (dynamic routing detection)."""
        t0 = time.monotonic()

        recipients = []
        for _ in range(5):
            resp = self.transport.get()
            if resp.get("status") == 402:
                addr = resp.get("headers", {}).get("x-payment-recipient", "")
                if addr:
                    recipients.append(addr)

        elapsed = time.monotonic() - t0

        unique_recipients = list(set(recipients))
        is_consistent = len(unique_recipients) <= 1
        self._autonomy_signals["consistent_recipient"] = is_consistent

        if not recipients:
            details = "No recipient addresses returned in 402 responses"
            passed = False
        elif is_consistent:
            details = f"Consistent recipient across {len(recipients)} requests: {unique_recipients[0][:20]}..."
            passed = True
        else:
            details = (f"DYNAMIC ROUTING DETECTED: {len(unique_recipients)} distinct recipients "
                       f"across {len(recipients)} requests — agent must verify each payTo independently")
            passed = False  # Dynamic routing is a risk for autonomous agents

        self._record(X402TestResult(
            test_id="X4-004",
            name="Recipient Address Consistency (Dynamic Routing)",
            category="recipient_manipulation",
            owasp_asi="ASI09",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=details,
            http_method="GET",
            csg_mapping="Twelve Numbers: payTo address must be stable and verifiable",
            estimated_impact="fund_theft",
            estimated_severity="critical",
            request_sent={"n_requests": 5},
            response_received={"unique_recipients": len(unique_recipients), "total": len(recipients)},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_wrong_recipient_payment(self):
        """X4-005: Send payment authorization targeting a DIFFERENT address than specified."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        # Construct a fake payment auth claiming to pay a different address
        attacker_address = "0x" + "dead" * 10  # obviously fake attacker address
        fake_auth = _fake_payment_authorization()

        resp = self.transport.get(headers={
            "X-Payment-Authorization": fake_auth,
            "X-Payment-Recipient": attacker_address,
        })
        elapsed = time.monotonic() - t0

        status = resp.get("status", 0)
        passed = status != 200

        self._record(X402TestResult(
            test_id="X4-005",
            name="Payment to Wrong Recipient Address",
            category="recipient_manipulation",
            owasp_asi="ASI09",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=(f"Server returned {status} when payment targeted wrong address"
                     + (" (rejected)" if passed else " (ACCEPTED — fund theft possible)")),
            http_method="GET",
            csg_mapping="HC-4: Server must verify payment recipient matches its own address",
            estimated_impact="fund_theft",
            estimated_severity="critical",
            request_sent={"attacker_recipient": attacker_address},
            response_received={"status": status},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_invalid_addresses(self):
        """X4-006: Test with obviously invalid addresses (zero, short, non-hex)."""
        t0 = time.monotonic()

        rejected = 0
        for addr in INVALID_ADDRESSES:
            fake_auth = _fake_payment_authorization()
            resp = self.transport.get(headers={
                "X-Payment-Authorization": fake_auth,
                "X-Payment-Recipient": addr,
            })
            status = resp.get("status", 0)
            if status != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(INVALID_ADDRESSES)
        self._autonomy_signals["rejects_invalid_addresses"] = passed

        self._record(X402TestResult(
            test_id="X4-006",
            name="Invalid Recipient Address Rejection",
            category="recipient_manipulation",
            owasp_asi="ASI09",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(INVALID_ADDRESSES)} invalid addresses rejected",
            http_method="GET",
            csg_mapping="HC-5: Server must validate recipient address format",
            estimated_impact="fund_theft",
            estimated_severity="high",
            request_sent={"addresses_tested": INVALID_ADDRESSES},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 3: Session Token Security (X4-007 to X4-010)
    # ------------------------------------------------------------------

    def test_x402_session_token_presence(self):
        """X4-007: After presenting payment auth, check if server returns session token."""
        t0 = time.monotonic()

        fake_auth = _fake_payment_authorization()
        resp = self.transport.get(headers={"X-Payment-Authorization": fake_auth})
        elapsed = time.monotonic() - t0

        headers = resp.get("headers", {})
        # Look for session indicators
        session_indicators = {}
        for k, v in headers.items():
            k_lower = k.lower()
            if any(kw in k_lower for kw in ["session", "token", "set-cookie", "authorization", "x-session"]):
                session_indicators[k] = v[:100]

        # Check cookies
        cookies = headers.get("set-cookie", "")
        has_session = bool(session_indicators) or bool(cookies)

        # If session token exists, check for secure flags
        cookie_issues = []
        if cookies:
            if "secure" not in cookies.lower():
                cookie_issues.append("Missing Secure flag")
            if "httponly" not in cookies.lower():
                cookie_issues.append("Missing HttpOnly flag")
            if "samesite" not in cookies.lower():
                cookie_issues.append("Missing SameSite attribute")

        passed = not cookie_issues if has_session else True

        details_parts = []
        if has_session:
            details_parts.append(f"Session indicators found: {list(session_indicators.keys())}")
            if cookie_issues:
                details_parts.append(f"Cookie security issues: {cookie_issues}")
        else:
            details_parts.append("No session token or cookie returned (stateless)")

        self._record(X402TestResult(
            test_id="X4-007",
            name="Session Token Security Check",
            category="session_security",
            owasp_asi="ASI03",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details="; ".join(details_parts),
            http_method="GET",
            csg_mapping="Harm Test: session tokens must not leak sensitive data",
            estimated_impact="session_hijack",
            estimated_severity="medium",
            request_sent={"authorization": "fake_payment_auth"},
            response_received={"session_indicators": session_indicators},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_fabricated_session_token(self):
        """X4-008: Present a fabricated session token (random bytes, wrong format)."""
        t0 = time.monotonic()

        fabricated_tokens = [
            ("random_bytes", base64.b64encode(os.urandom(32)).decode()),
            ("fake_jwt", _fake_jwt()),
            ("empty", ""),
            ("sql_injection", "' OR '1'='1"),
            ("zero_bytes", base64.b64encode(b"\x00" * 32).decode()),
        ]

        rejected = 0
        for label, token in fabricated_tokens:
            resp = self.transport.get(headers={
                "X-Session-Token": token,
                "Cookie": f"session={token}",
                "Authorization": f"Bearer {token}",
            })
            status = resp.get("status", 0)
            # Should not grant access with fabricated session
            if status != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(fabricated_tokens)
        self._autonomy_signals["rejects_fake_sessions"] = passed

        self._record(X402TestResult(
            test_id="X4-008",
            name="Fabricated Session Token Rejection",
            category="session_security",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(fabricated_tokens)} fabricated session tokens rejected",
            http_method="GET",
            csg_mapping="HC-6: Server must cryptographically verify session tokens",
            estimated_impact="session_hijack",
            estimated_severity="high",
            request_sent={"variants": [label for label, _ in fabricated_tokens]},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_expired_session_token(self):
        """X4-009: Present an expired session token (JWT with past exp claim)."""
        t0 = time.monotonic()

        # Build JWT with expired timestamp
        header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": "0x" + os.urandom(20).hex(),
            "iat": int(time.time()) - 86400,  # Issued yesterday
            "exp": int(time.time()) - 3600,     # Expired 1 hour ago
            "amt": "1000000",
            "paid": True,
        }).encode()).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip("=")
        expired_jwt = f"{header}.{payload}.{sig}"

        resp = self.transport.get(headers={
            "X-Session-Token": expired_jwt,
            "Authorization": f"Bearer {expired_jwt}",
        })
        elapsed = time.monotonic() - t0

        status = resp.get("status", 0)
        passed = status != 200

        self._record(X402TestResult(
            test_id="X4-009",
            name="Expired Session Token Rejection",
            category="session_security",
            owasp_asi="ASI03",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"Server returned {status} for expired JWT" +
                    (" (rejected)" if passed else " (ACCEPTED — session expiry not enforced)"),
            http_method="GET",
            csg_mapping="HC-7: Server must enforce session token expiration",
            estimated_impact="session_hijack",
            estimated_severity="high",
            request_sent={"token_type": "expired_jwt", "exp": "1 hour ago"},
            response_received={"status": status},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_session_data_leakage(self):
        """X4-010: Check if session tokens contain sensitive data (wallet addresses, amounts, keys)."""
        t0 = time.monotonic()

        # Request a 402 challenge and inspect all returned tokens/headers for leakage
        resp = self.transport.get()
        elapsed = time.monotonic() - t0

        headers = resp.get("headers", {})
        body = resp.get("body", "")
        all_content = json.dumps(headers) + " " + body

        # Decode any base64 blobs found in headers
        decoded_blobs = []
        b64_pattern = re.compile(r"[A-Za-z0-9+/=]{20,}")
        for match in b64_pattern.finditer(all_content):
            try:
                decoded = base64.b64decode(match.group()).decode("utf-8", errors="replace")
                decoded_blobs.append(decoded)
            except Exception:
                pass

        full_content = all_content + " " + " ".join(decoded_blobs)
        full_lower = full_content.lower()

        sensitive_patterns = {
            "private_key": r"(?:0x)?[0-9a-f]{64}",
            "api_key": r"(?:api[_-]?key|apikey|secret[_-]?key)",
            "password": r"(?:password|passwd|pwd)\s*[:=]",
            "internal_path": r"(?:/home/|/var/|/opt/|/usr/|C:\\)",
            "stack_trace": r"(?:traceback|at\s+\w+\.\w+\(|\.py:\d+|\.js:\d+)",
            "database": r"(?:mysql|postgres|mongodb|redis)://",
        }

        leaks_found = []
        for leak_type, pattern in sensitive_patterns.items():
            if re.search(pattern, full_lower):
                leaks_found.append(leak_type)

        passed = len(leaks_found) == 0
        self._autonomy_signals["no_info_leak"] = passed

        self._record(X402TestResult(
            test_id="X4-010",
            name="Session / Response Data Leakage Check",
            category="session_security",
            owasp_asi="ASI06",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=f"Sensitive data patterns found: {leaks_found}" if leaks_found
                    else "No sensitive data patterns detected in response",
            http_method="GET",
            csg_mapping="Harm Test: responses must not leak sensitive operational data",
            estimated_impact="info_leak",
            estimated_severity="medium",
            request_sent={"path": "/"},
            response_received={"leaks_found": leaks_found, "n_decoded_blobs": len(decoded_blobs)},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 4: Spending Limit Exploitation (X4-011 to X4-013)
    # ------------------------------------------------------------------

    def test_x402_rapid_payment_requests(self):
        """X4-011: Rapid sequential requests to test rate limiting on payment requests."""
        t0 = time.monotonic()

        n_requests = 20
        statuses: list[int] = []
        amounts: list[str] = []

        for _ in range(n_requests):
            resp = self.transport.get()
            statuses.append(resp.get("status", 0))
            amt = resp.get("headers", {}).get("x-payment-amount", "")
            if amt:
                amounts.append(amt)

        elapsed = time.monotonic() - t0

        n_402 = sum(1 for s in statuses if s == 402)
        n_rate_limited = sum(1 for s in statuses if s == 429)
        has_rate_limit = n_rate_limited > 0

        # Check for price escalation
        price_escalation = False
        if len(amounts) >= 2:
            try:
                parsed = [int(a) for a in amounts]
                if parsed[-1] > parsed[0]:
                    price_escalation = True
            except (ValueError, TypeError):
                pass

        passed = has_rate_limit or not price_escalation

        details_parts = [
            f"{n_requests} requests in {elapsed:.1f}s",
            f"{n_402} got 402, {n_rate_limited} rate-limited",
        ]
        if has_rate_limit:
            details_parts.append("Rate limiting detected")
        if price_escalation:
            details_parts.append(f"PRICE ESCALATION: {amounts[0]} -> {amounts[-1]}")

        self._record(X402TestResult(
            test_id="X4-011",
            name="Rapid Payment Request Rate Limiting",
            category="spending_limits",
            owasp_asi="ASI08",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details="; ".join(details_parts),
            http_method="GET",
            csg_mapping="Twelve Numbers: rate limits prevent budget exhaustion attacks",
            estimated_impact="overpayment",
            estimated_severity="medium",
            request_sent={"n_requests": n_requests},
            response_received={"n_402": n_402, "n_rate_limited": n_rate_limited,
                               "price_escalation": price_escalation},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_underpayment_attempt(self):
        """X4-012: Send payment authorization claiming a lower amount than requested."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        fake_auth = _fake_payment_authorization()

        # Try presenting payment with a lower amount header
        underpay_amounts = ["0", "1", "100"]
        if challenge and challenge.amount:
            try:
                requested = int(challenge.amount)
                if requested > 1:
                    underpay_amounts.append(str(requested // 2))
                    underpay_amounts.append(str(requested - 1))
            except (ValueError, TypeError):
                pass

        rejected = 0
        for amount in underpay_amounts:
            resp = self.transport.get(headers={
                "X-Payment-Authorization": fake_auth,
                "X-Payment-Amount": amount,
            })
            status = resp.get("status", 0)
            if status != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(underpay_amounts)
        self._autonomy_signals["rejects_underpayment"] = passed

        self._record(X402TestResult(
            test_id="X4-012",
            name="Underpayment Attempt Rejection",
            category="spending_limits",
            owasp_asi="ASI09",
            severity=Severity.HIGH.value,
            passed=passed,
            details=f"{rejected}/{len(underpay_amounts)} underpayment attempts rejected" +
                    (f" (server requires: {challenge.amount})" if challenge else ""),
            http_method="GET",
            csg_mapping="HC-8: Server must verify payment amount matches or exceeds requirement",
            estimated_impact="overpayment",
            estimated_severity="high",
            request_sent={"amounts_tried": underpay_amounts},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_budget_exhaustion(self):
        """X4-013: Simulate rapid small payment requests to test budget exhaustion defenses."""
        t0 = time.monotonic()

        n_burst = 50
        statuses: list[int] = []

        def _request():
            resp = self.transport.get()
            return resp.get("status", 0)

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(_request) for _ in range(n_burst)]
            for f in as_completed(futures):
                try:
                    statuses.append(f.result())
                except Exception:
                    pass

        elapsed = time.monotonic() - t0

        n_rate_limited = sum(1 for s in statuses if s == 429)
        n_402 = sum(1 for s in statuses if s == 402)
        n_errors = sum(1 for s in statuses if s >= 500)

        # Pass if server either rate-limits or handles burst gracefully (no 500s)
        passed = n_errors == 0 and (n_rate_limited > 0 or n_402 == len(statuses))

        self._record(X402TestResult(
            test_id="X4-013",
            name="Budget Exhaustion Burst Test",
            category="spending_limits",
            owasp_asi="ASI08",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=(f"{n_burst} concurrent requests: {n_402} got 402, "
                     f"{n_rate_limited} rate-limited, {n_errors} server errors"),
            http_method="GET",
            csg_mapping="Twelve Numbers: burst protection prevents agent budget exhaustion",
            estimated_impact="overpayment",
            estimated_severity="medium",
            request_sent={"n_burst": n_burst, "n_workers": 10},
            response_received={"n_402": n_402, "n_rate_limited": n_rate_limited, "n_errors": n_errors},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 5: Facilitator Trust (X4-014 to X4-016)
    # ------------------------------------------------------------------

    def test_x402_fake_facilitator(self):
        """X4-014: Send payment with a fake X-Payment-Facilitator header pointing to attacker URL."""
        t0 = time.monotonic()

        fake_facilitators = [
            "https://evil.com/verify",
            "http://localhost:9999/fake-verify",
            "https://attacker.io/x402-facilitator",
            "",
        ]

        fake_auth = _fake_payment_authorization()
        rejected = 0
        for facilitator_url in fake_facilitators:
            resp = self.transport.get(headers={
                "X-Payment-Authorization": fake_auth,
                "X-Payment-Facilitator": facilitator_url,
            })
            status = resp.get("status", 0)
            if status != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(fake_facilitators)
        self._autonomy_signals["validates_facilitator"] = passed

        self._record(X402TestResult(
            test_id="X4-014",
            name="Fake Facilitator Header Injection",
            category="facilitator_trust",
            owasp_asi="ASI09",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=f"{rejected}/{len(fake_facilitators)} fake facilitator claims rejected",
            http_method="GET",
            csg_mapping="HC-9: Server must only trust pre-configured facilitator(s)",
            estimated_impact="fund_theft",
            estimated_severity="critical",
            request_sent={"fake_facilitators": fake_facilitators},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_nonexistent_facilitator_verification(self):
        """X4-015: Present payment claiming verification from a non-existent facilitator."""
        t0 = time.monotonic()

        # Craft a payment auth that includes a fake verification claim
        fake_verification = json.dumps({
            "facilitator": "https://nonexistent-facilitator-" + uuid.uuid4().hex[:8] + ".com",
            "verified": True,
            "payment_hash": os.urandom(32).hex(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }).encode()

        resp = self.transport.get(headers={
            "X-Payment-Authorization": base64.b64encode(fake_verification).decode(),
            "X-Payment-Verified": "true",
        })
        elapsed = time.monotonic() - t0

        status = resp.get("status", 0)
        passed = status != 200

        self._record(X402TestResult(
            test_id="X4-015",
            name="Non-Existent Facilitator Verification Claim",
            category="facilitator_trust",
            owasp_asi="ASI09",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=f"Server returned {status} for non-existent facilitator claim" +
                    (" (rejected)" if passed else " (ACCEPTED — facilitator not validated)"),
            http_method="GET",
            csg_mapping="Falsification Requirement: facilitator identity must be independently verified",
            estimated_impact="fund_theft",
            estimated_severity="critical",
            request_sent={"fake_verification": True},
            response_received={"status": status},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_facilitator_timeout_handling(self):
        """X4-016: Test behavior when facilitator endpoint would be unreachable."""
        t0 = time.monotonic()

        # Send a payment that references a facilitator on a non-routable address
        fake_auth = _fake_payment_authorization()
        resp = self.transport.get(headers={
            "X-Payment-Authorization": fake_auth,
            "X-Payment-Facilitator": "https://192.0.2.1:1/verify",  # TEST-NET, non-routable
        })
        elapsed = time.monotonic() - t0

        status = resp.get("status", 0)
        body_lower = resp.get("body", "").lower()

        # Should fail gracefully (not 200, no stack traces)
        has_stack_trace = any(kw in body_lower for kw in [
            "traceback", "exception", "stack trace", "at line", "internal server error"
        ])

        passed = status != 200 and not has_stack_trace

        self._record(X402TestResult(
            test_id="X4-016",
            name="Facilitator Timeout / Unreachable Handling",
            category="facilitator_trust",
            owasp_asi="ASI08",
            severity=Severity.HIGH.value,
            passed=passed,
            details=(f"Server returned {status}" +
                     (" with stack trace leak" if has_stack_trace else " without info leak") +
                     (" (graceful)" if passed else " (ISSUE)")),
            http_method="GET",
            csg_mapping="HC-10: Server must fail-closed when facilitator is unreachable",
            estimated_impact="service_denial",
            estimated_severity="high",
            request_sent={"facilitator": "non-routable TEST-NET address"},
            response_received={"status": status, "has_stack_trace": has_stack_trace},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 6: Information Disclosure (X4-017 to X4-018)
    # ------------------------------------------------------------------

    def test_x402_challenge_info_leakage(self):
        """X4-017: Analyze 402 response for leaked sensitive information."""
        t0 = time.monotonic()
        resp = self.transport.get()
        elapsed = time.monotonic() - t0

        headers = resp.get("headers", {})
        body = resp.get("body", "")
        all_content = json.dumps(headers) + " " + body
        content_lower = all_content.lower()

        leaks = []
        # Check for overly detailed server info
        server_header = headers.get("server", "")
        if server_header and any(kw in server_header.lower() for kw in ["version", "debug", "dev"]):
            leaks.append(f"Detailed server header: {server_header}")

        # Check for internal contract addresses or chain IDs that shouldn't be exposed
        if re.search(r"chain[_-]?id\s*[:=]\s*\d+", content_lower):
            leaks.append("Chain ID exposed in response")

        # Check for API keys or tokens
        if re.search(r"(?:api[_-]?key|secret|token)\s*[:=]\s*\S+", content_lower):
            leaks.append("Possible API key/secret in response")

        # Check for internal wallet balances
        if re.search(r"balance\s*[:=]\s*\d+", content_lower):
            leaks.append("Wallet balance exposed in response")

        # Check for debug/verbose headers
        debug_headers = [k for k in headers if any(kw in k for kw in ["debug", "trace", "x-request-id"])]
        if debug_headers:
            leaks.append(f"Debug headers present: {debug_headers}")

        passed = len(leaks) == 0

        self._record(X402TestResult(
            test_id="X4-017",
            name="402 Response Information Leakage",
            category="information_disclosure",
            owasp_asi="ASI06",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=f"Info leaks found: {leaks}" if leaks else "No sensitive information leaked in 402 response",
            http_method="GET",
            csg_mapping="Harm Test: 402 responses must not expose internal infrastructure details",
            estimated_impact="info_leak",
            estimated_severity="medium",
            request_sent={"path": "/"},
            response_received={"leaks": leaks},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_error_message_disclosure(self):
        """X4-018: Send malformed payment and check error messages for sensitive details."""
        t0 = time.monotonic()

        # Send intentionally broken payloads to trigger error responses
        error_payloads = [
            {"X-Payment-Authorization": "{{" + "A" * 1000 + "}}"},
            {"X-Payment-Authorization": "<script>alert(1)</script>"},
            {"X-Payment-Authorization": "' OR '1'='1' --"},
            {"X-Payment-Amount": "-1"},
            {"X-Payment-Network": "../../../etc/passwd"},
        ]

        leaks_found = []
        for hdrs in error_payloads:
            resp = self.transport.get(headers=hdrs)
            body_lower = resp.get("body", "").lower()
            headers_str = json.dumps(resp.get("headers", {})).lower()
            combined = body_lower + headers_str

            for kw in ["traceback", "stack trace", "exception", "at line",
                        "sql", "database", "/home/", "/var/", "node_modules",
                        "secret", "private", "password"]:
                if kw in combined:
                    leaks_found.append(f"{kw} in error response for {list(hdrs.keys())[0]}")

        elapsed = time.monotonic() - t0
        passed = len(leaks_found) == 0

        self._record(X402TestResult(
            test_id="X4-018",
            name="Error Message Information Disclosure",
            category="information_disclosure",
            owasp_asi="ASI06",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=f"Sensitive info in error responses: {leaks_found}" if leaks_found
                    else "Error responses do not leak sensitive details",
            http_method="GET",
            csg_mapping="HC-11: Error responses must not expose internal details",
            estimated_impact="info_leak",
            estimated_severity="medium",
            request_sent={"n_payloads": len(error_payloads)},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 7: Cross-Chain Confusion (X4-019 to X4-020)
    # ------------------------------------------------------------------

    def test_x402_wrong_network(self):
        """X4-019: Specify wrong network in payment (e.g., Polygon when server expects Base)."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        wrong_networks = ["polygon", "ethereum", "arbitrum", "optimism", "avalanche", "solana", "bitcoin"]
        fake_auth = _fake_payment_authorization()

        rejected = 0
        for network in wrong_networks:
            resp = self.transport.get(headers={
                "X-Payment-Authorization": fake_auth,
                "X-Payment-Network": network,
            })
            status = resp.get("status", 0)
            if status != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(wrong_networks)

        server_network = challenge.network if challenge else "unknown"

        self._record(X402TestResult(
            test_id="X4-019",
            name="Wrong Network Payment Rejection",
            category="cross_chain_confusion",
            owasp_asi="ASI09",
            severity=Severity.HIGH.value,
            passed=passed,
            details=(f"{rejected}/{len(wrong_networks)} wrong-network payments rejected"
                     f" (server expects: {server_network})"),
            http_method="GET",
            csg_mapping="HC-12: Server must validate payment network matches requirement",
            estimated_impact="fund_theft",
            estimated_severity="high",
            request_sent={"networks_tested": wrong_networks, "expected_network": server_network},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_wrong_token_type(self):
        """X4-020: Specify wrong token type (e.g., EURC when server expects USDC)."""
        t0 = time.monotonic()
        challenge = self._ensure_challenge()

        wrong_tokens = ["EURC", "USDT", "DAI", "WETH", "WBTC", "FAKE_TOKEN", ""]
        fake_auth = _fake_payment_authorization()

        rejected = 0
        for token in wrong_tokens:
            resp = self.transport.get(headers={
                "X-Payment-Authorization": fake_auth,
                "X-Payment-Currency": token,
            })
            status = resp.get("status", 0)
            if status != 200:
                rejected += 1

        elapsed = time.monotonic() - t0
        passed = rejected == len(wrong_tokens)

        server_currency = challenge.currency if challenge else "unknown"

        self._record(X402TestResult(
            test_id="X4-020",
            name="Wrong Token Type Payment Rejection",
            category="cross_chain_confusion",
            owasp_asi="ASI09",
            severity=Severity.HIGH.value,
            passed=passed,
            details=(f"{rejected}/{len(wrong_tokens)} wrong-token payments rejected"
                     f" (server expects: {server_currency})"),
            http_method="GET",
            csg_mapping="HC-13: Server must validate payment currency matches requirement",
            estimated_impact="fund_theft",
            estimated_severity="high",
            request_sent={"tokens_tested": wrong_tokens, "expected_currency": server_currency},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 8: OATR Identity Verification (X4-021 to X4-025)
    # ------------------------------------------------------------------

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        """Base64url decode without padding."""
        s = s.replace("-", "+").replace("_", "/")
        pad = 4 - len(s) % 4
        if pad != 4:
            s += "=" * pad
        return base64.b64decode(s)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        """Base64url encode without padding."""
        return base64.b64encode(data).decode().rstrip("=").replace("+", "-").replace("/", "_")

    @staticmethod
    def _parse_jwt_parts(token: str) -> tuple[dict | None, dict | None]:
        """Minimally parse a JWT into (header, payload) dicts. Returns (None, None) on failure."""
        parts = token.split(".")
        if len(parts) != 3:
            return None, None
        try:
            header = json.loads(X402SecurityTests._b64url_decode(parts[0]))
            payload = json.loads(X402SecurityTests._b64url_decode(parts[1]))
            return header, payload
        except Exception:
            return None, None

    def _extract_attestation(self, resp: dict) -> str | None:
        """Extract an operator attestation JWT from response headers or body."""
        headers = resp.get("headers", {})
        # Check common header locations
        for key in ("x-operator-attestation", "x-agent-attestation", "x-oatr-attestation",
                     "authorization", "x-attestation"):
            val = headers.get(key, "")
            if val:
                # Strip "Bearer " prefix if present
                token = val.split(" ", 1)[-1] if " " in val else val
                parts = token.split(".")
                if len(parts) == 3:
                    return token
        # Check response body for JWT-shaped tokens
        body = resp.get("body", "")
        if body:
            try:
                body_json = json.loads(body)
                for field_name in ("attestation", "operator_attestation", "agent_attestation",
                                   "oatr_token", "token"):
                    if field_name in body_json and isinstance(body_json[field_name], str):
                        parts = body_json[field_name].split(".")
                        if len(parts) == 3:
                            return body_json[field_name]
            except (json.JSONDecodeError, TypeError):
                pass
        return None

    def test_x402_operator_attestation_presence(self):
        """X4-021: Check if the x402 endpoint returns a verifiable operator attestation (OATR JWT)."""
        t0 = time.monotonic()

        resp = self.transport.get()
        elapsed = time.monotonic() - t0

        attestation = self._extract_attestation(resp)
        issues = []

        if not attestation:
            issues.append("No operator attestation JWT found in response headers or body")
        else:
            header, payload = self._parse_jwt_parts(attestation)
            if header is None or payload is None:
                issues.append("Attestation present but not parseable as JWT (header.payload.signature)")
            else:
                # Verify expected type and algorithm
                typ = header.get("typ", "")
                alg = header.get("alg", "")
                if typ != "agent-attestation+jwt":
                    issues.append(f"JWT typ is '{typ}', expected 'agent-attestation+jwt'")
                if alg != "EdDSA":
                    issues.append(f"JWT alg is '{alg}', expected 'EdDSA'")
                # Check required payload fields
                for required_field in ("iss", "aud", "exp"):
                    if required_field not in payload:
                        issues.append(f"Missing required payload field: {required_field}")

        passed = len(issues) == 0
        self._autonomy_signals["has_operator_attestation"] = passed

        self._record(X402TestResult(
            test_id="X4-021",
            name="Operator Attestation Presence (OATR)",
            category="identity_verification",
            owasp_asi="ASI04",
            severity=Severity.HIGH.value,
            passed=passed,
            details="; ".join(issues) if issues else "Valid OATR operator attestation JWT present (EdDSA, agent-attestation+jwt)",
            http_method="GET",
            csg_mapping="HC-14: x402 endpoints must present verifiable operator identity via OATR attestation",
            estimated_impact="fund_theft",
            estimated_severity="high",
            request_sent={"path": "/"},
            response_received={"attestation_present": attestation is not None,
                               "parseable": attestation is not None and self._parse_jwt_parts(attestation)[0] is not None},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_attestation_domain_binding(self):
        """X4-022: Verify attestation JWT audience matches the endpoint domain."""
        t0 = time.monotonic()

        resp = self.transport.get()
        elapsed = time.monotonic() - t0

        attestation = self._extract_attestation(resp)
        issues = []

        if not attestation:
            issues.append("No attestation JWT found; cannot verify domain binding")
        else:
            header, payload = self._parse_jwt_parts(attestation)
            if payload is None:
                issues.append("Attestation not parseable; cannot check audience field")
            else:
                aud = payload.get("aud", "")
                # Extract domain from the target URL
                parsed_url = urllib.parse.urlparse(self.transport.base_url)
                target_domain = parsed_url.hostname or parsed_url.netloc
                # Extract domain from aud (may be a full URL or just a domain)
                if aud.startswith("http"):
                    aud_parsed = urllib.parse.urlparse(aud)
                    aud_domain = aud_parsed.hostname or aud_parsed.netloc
                else:
                    aud_domain = aud

                if not aud:
                    issues.append("Attestation JWT missing 'aud' (audience) field")
                elif aud_domain != target_domain:
                    issues.append(f"Audience mismatch: attestation aud='{aud_domain}', endpoint domain='{target_domain}'")

        passed = len(issues) == 0

        self._record(X402TestResult(
            test_id="X4-022",
            name="Attestation-Domain Binding (OATR)",
            category="identity_verification",
            owasp_asi="ASI04",
            severity=Severity.HIGH.value,
            passed=passed,
            details="; ".join(issues) if issues else "Attestation audience matches endpoint domain",
            http_method="GET",
            csg_mapping="HC-15: Attestation audience must bind to the serving domain to prevent replay",
            estimated_impact="fund_theft",
            estimated_severity="high",
            request_sent={"path": "/", "target_url": self.transport.base_url},
            response_received={"attestation_found": attestation is not None},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_attestation_revocation_check(self):
        """X4-023: Check if an OATR revocation mechanism exists and is functional."""
        t0 = time.monotonic()

        issues = []
        revocation_functional = False

        # Try well-known revocation endpoint
        parsed_url = urllib.parse.urlparse(self.transport.base_url)
        base_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        revocation_transport = X402Transport(base_origin)
        rev_resp = revocation_transport.get("/.well-known/oatr-revocation.json", timeout=10.0)

        if rev_resp.get("status") == 200:
            body = rev_resp.get("body", "")
            try:
                rev_data = json.loads(body)
                # Expect a list or object with revoked entries
                if isinstance(rev_data, dict) and ("revoked" in rev_data or "entries" in rev_data
                                                    or "issuers" in rev_data or "keys" in rev_data):
                    revocation_functional = True
                elif isinstance(rev_data, list):
                    revocation_functional = True
                else:
                    issues.append("Revocation endpoint returned JSON but unrecognized schema")
            except (json.JSONDecodeError, TypeError):
                issues.append("Revocation endpoint returned non-JSON body")
        else:
            # Also check if attestation itself contains a revocation URL
            resp = self.transport.get()
            attestation = self._extract_attestation(resp)
            if attestation:
                _, payload = self._parse_jwt_parts(attestation)
                if payload:
                    rev_url = payload.get("revocation_url") or payload.get("rev") or payload.get("crl")
                    if rev_url:
                        # Try fetching the revocation URL from the attestation
                        try:
                            rev_transport = X402Transport(rev_url)
                            rev_resp2 = rev_transport.get(timeout=10.0)
                            if rev_resp2.get("status") == 200:
                                revocation_functional = True
                            else:
                                issues.append(f"Attestation revocation URL returned {rev_resp2.get('status')}")
                        except Exception as e:
                            issues.append(f"Attestation revocation URL unreachable: {e}")
                    else:
                        issues.append("No revocation URL in attestation and /.well-known/oatr-revocation.json not found")
                else:
                    issues.append("Attestation not parseable; no revocation URL extractable")
            else:
                issues.append("No attestation and no /.well-known/oatr-revocation.json (no revocation mechanism)")

        elapsed = time.monotonic() - t0
        passed = revocation_functional

        self._record(X402TestResult(
            test_id="X4-023",
            name="Attestation Revocation Check (OATR)",
            category="identity_verification",
            owasp_asi="ASI04",
            severity=Severity.HIGH.value,
            passed=passed,
            details="; ".join(issues) if issues else "OATR revocation mechanism is functional",
            http_method="GET",
            csg_mapping="HC-16: Revocation checking must be available to reject compromised operator keys",
            estimated_impact="fund_theft",
            estimated_severity="high",
            request_sent={"revocation_url": f"{base_origin}/.well-known/oatr-revocation.json"},
            response_received={"revocation_functional": revocation_functional},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_stale_manifest_acceptance(self):
        """X4-024: Send a mock manifest with stale generated_at to test cache TTL enforcement."""
        t0 = time.monotonic()

        # Create a stale manifest (generated_at > 15 min ago = default CACHE_TTL_MS)
        stale_time = datetime.now(timezone.utc) - __import__('datetime').timedelta(minutes=20)
        stale_timestamp = stale_time.isoformat().replace("+00:00", "Z")
        stale_epoch_ms = int((time.time() - 1200) * 1000)  # 20 minutes ago (exceeds 15-min TTL)
        stale_manifest = json.dumps({
            "manifest_version": "1.0",
            "generated_at": stale_epoch_ms,
            "generated_at_iso": stale_timestamp,
            "issuers": [],
            "signature": self._b64url_encode(os.urandom(64)),
        })

        # Send the stale manifest as a header and in body
        resp = self.transport.post(
            body=stale_manifest.encode(),
            headers={
                "Content-Type": "application/json",
                "X-OATR-Manifest": base64.b64encode(stale_manifest.encode()).decode(),
                "X-OATR-Manifest-Generated-At": str(stale_epoch_ms),
            },
        )
        elapsed = time.monotonic() - t0

        status = resp.get("status", 0)
        body_lower = resp.get("body", "").lower()

        # PASS if the server rejects the stale manifest (non-200, or body indicates staleness)
        stale_rejected = (
            status != 200
            or "stale" in body_lower
            or "expired" in body_lower
            or "refresh" in body_lower
            or "cache" in body_lower
            or "ttl" in body_lower
        )

        passed = stale_rejected

        self._record(X402TestResult(
            test_id="X4-024",
            name="Stale Manifest Acceptance (OATR)",
            category="identity_verification",
            owasp_asi="ASI04",
            severity=Severity.MEDIUM.value,
            passed=passed,
            details=(f"Server returned {status} for manifest generated 20min ago (15min TTL)"
                     + (" (rejected/re-fetched)" if passed else " (ACCEPTED stale manifest without validation)")),
            http_method="POST",
            csg_mapping="HC-17: Clients/servers must reject manifests older than CACHE_TTL_MS (default 15min)",
            estimated_impact="fund_theft",
            estimated_severity="medium",
            request_sent={"stale_generated_at_ms": stale_epoch_ms, "ttl_exceeded_by_s": 300},
            response_received={"status": status, "stale_rejected": stale_rejected},
            elapsed_s=round(elapsed, 3),
        ))

    def test_x402_forged_attestation_injection(self):
        """X4-025: Inject a forged attestation JWT signed with a random key (not in any registry)."""
        t0 = time.monotonic()

        # Craft a forged OATR attestation JWT
        forged_header = self._b64url_encode(json.dumps({
            "alg": "EdDSA",
            "typ": "agent-attestation+jwt",
            "kid": "forged-key-" + uuid.uuid4().hex[:8],
        }).encode())
        forged_payload = self._b64url_encode(json.dumps({
            "iss": "fake-issuer-" + uuid.uuid4().hex[:8],
            "sub": "forged-agent",
            "aud": self.transport.base_url,
            "iat": int(time.time()),
            "exp": 9999999999,
            "scope": ["pay", "transfer"],
            "runtime_version": "1.0.0-forged",
        }).encode())
        # Random 64-byte signature (not a real Ed25519 signature)
        forged_sig = self._b64url_encode(os.urandom(64))
        forged_jwt = f"{forged_header}.{forged_payload}.{forged_sig}"

        # Send the forged attestation in multiple header locations
        resp = self.transport.get(headers={
            "X-Operator-Attestation": f"Bearer {forged_jwt}",
            "X-Agent-Attestation": forged_jwt,
            "X-OATR-Attestation": forged_jwt,
        })
        elapsed = time.monotonic() - t0

        status = resp.get("status", 0)
        body_lower = resp.get("body", "").lower()

        # PASS if the forged attestation is rejected
        rejection_indicators = (
            status != 200
            or "unknown_issuer" in body_lower
            or "invalid_signature" in body_lower
            or "invalid" in body_lower
            or "unauthorized" in body_lower
            or "forbidden" in body_lower
            or "rejected" in body_lower
            or "untrusted" in body_lower
        )

        passed = rejection_indicators
        self._autonomy_signals["rejects_forged_attestation"] = passed

        self._record(X402TestResult(
            test_id="X4-025",
            name="Forged Attestation Injection (OATR)",
            category="identity_verification",
            owasp_asi="ASI04",
            severity=Severity.CRITICAL.value,
            passed=passed,
            details=(f"Server returned {status} for forged OATR attestation"
                     + (" (rejected)" if passed else " (ACCEPTED forged attestation - identity spoofing possible)")),
            http_method="GET",
            csg_mapping="HC-18: Forged attestations with unknown issuers must be rejected",
            estimated_impact="fund_theft",
            estimated_severity="critical",
            request_sent={"forged_jwt_iss": "fake-issuer", "forged_jwt_alg": "EdDSA"},
            response_received={"status": status, "rejected": rejection_indicators},
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Agent Autonomy Risk Score
    # ------------------------------------------------------------------

    def compute_autonomy_risk_score(self) -> dict:
        """Compute Agent Autonomy Risk Score (0-100).

        Answers: 'How dangerous is it to let an autonomous agent pay this
        endpoint without human oversight?'

        100 = extremely dangerous (do not automate)
        0   = safe for autonomous operation
        """
        signals = self._autonomy_signals
        # Default all untested signals to False (assume risky).
        # This ensures the risk score is conservative: untested = risky.
        risk_components = {
            "challenge_invalid": 20 if not signals.get("challenge_valid", False) else 0,
            "inconsistent_recipient": 25 if not signals.get("consistent_recipient", False) else 0,
            "accepts_invalid_addresses": 15 if not signals.get("rejects_invalid_addresses", False) else 0,
            "accepts_fake_sessions": 10 if not signals.get("rejects_fake_sessions", False) else 0,
            "leaks_information": 10 if not signals.get("no_info_leak", False) else 0,
            "no_facilitator_validation": 15 if not signals.get("validates_facilitator", False) else 0,
            "accepts_underpayment": 5 if not signals.get("rejects_underpayment", False) else 0,
            "accepts_forged_attestation": 10 if not signals.get("rejects_forged_attestation", False) else 0,
            "no_operator_attestation": 5 if not signals.get("has_operator_attestation", False) else 0,
        }

        total_risk = sum(risk_components.values())
        # Clamp to 0-100
        total_risk = max(0, min(100, total_risk))

        risk_level = "LOW"
        if total_risk >= 70:
            risk_level = "CRITICAL"
        elif total_risk >= 50:
            risk_level = "HIGH"
        elif total_risk >= 30:
            risk_level = "MEDIUM"

        return {
            "score": total_risk,
            "risk_level": risk_level,
            "recommendation": (
                "SAFE for autonomous agent payments" if total_risk < 30
                else "REQUIRES human-in-the-loop approval" if total_risk < 70
                else "DO NOT automate payments to this endpoint"
            ),
            "components": risk_components,
            "signals": {k: v for k, v in signals.items()},
        }

    # ------------------------------------------------------------------
    # Run all tests
    # ------------------------------------------------------------------

    ALL_TESTS: dict[str, list[str]] = {
        "payment_challenge": [
            "test_x402_challenge_headers_present",
            "test_x402_malformed_payment_headers",
            "test_x402_unsupported_currency",
        ],
        "recipient_manipulation": [
            "test_x402_dynamic_routing_detection",
            "test_x402_wrong_recipient_payment",
            "test_x402_invalid_addresses",
        ],
        "session_security": [
            "test_x402_session_token_presence",
            "test_x402_fabricated_session_token",
            "test_x402_expired_session_token",
            "test_x402_session_data_leakage",
        ],
        "spending_limits": [
            "test_x402_rapid_payment_requests",
            "test_x402_underpayment_attempt",
            "test_x402_budget_exhaustion",
        ],
        "facilitator_trust": [
            "test_x402_fake_facilitator",
            "test_x402_nonexistent_facilitator_verification",
            "test_x402_facilitator_timeout_handling",
        ],
        "information_disclosure": [
            "test_x402_challenge_info_leakage",
            "test_x402_error_message_disclosure",
        ],
        "cross_chain_confusion": [
            "test_x402_wrong_network",
            "test_x402_wrong_token_type",
        ],
        "identity_verification": [
            "test_x402_operator_attestation_presence",
            "test_x402_attestation_domain_binding",
            "test_x402_attestation_revocation_check",
            "test_x402_stale_manifest_acceptance",
            "test_x402_forged_attestation_injection",
        ],
    }

    def run_all(self, categories: list[str] | None = None) -> list[X402TestResult]:
        """Run all x402 security tests (or a filtered subset)."""

        test_map: dict[str, list[str]]
        if categories:
            test_map = {k: v for k, v in self.ALL_TESTS.items() if k in categories}
        else:
            test_map = dict(self.ALL_TESTS)

        print(f"\n{'='*60}")
        print("x402 PAYMENT PROTOCOL SECURITY TEST SUITE v1.0")
        print(f"{'='*60}")
        print(f"Target: {self.transport.base_url}")
        print("The FIRST open-source x402 security test harness")

        for category, test_names in test_map.items():
            print(f"\n[{category.upper().replace('_', ' ')}]")
            for test_name in test_names:
                test_fn = getattr(self, test_name)
                try:
                    test_fn()
                except Exception as e:
                    print(f"  ERROR \u26a0\ufe0f  {test_name}: {e}")
                    self.results.append(X402TestResult(
                        test_id=test_name,
                        name=f"ERROR: {test_name}",
                        category=category,
                        owasp_asi="",
                        severity=Severity.HIGH.value,
                        passed=False,
                        details=str(e),
                        http_method="unknown",
                    ))

        # Compute autonomy risk score
        autonomy_risk = self.compute_autonomy_risk_score()

        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        print(f"\n{'='*60}")
        print(f"RESULTS: {passed}/{total} passed ({passed/total*100:.0f}%)" if total else "No tests run")
        print(f"\nAGENT AUTONOMY RISK SCORE: {autonomy_risk['score']}/100 ({autonomy_risk['risk_level']})")
        print(f"Recommendation: {autonomy_risk['recommendation']}")
        print(f"{'='*60}\n")

        return self.results


# ---------------------------------------------------------------------------
# Test listing
# ---------------------------------------------------------------------------

_TEST_DESCRIPTIONS: dict[str, str] = {
    "X4-001": "Verify 402 response contains all required X-Payment-* headers",
    "X4-002": "Submit malformed X-Payment-Authorization and verify rejection",
    "X4-003": "Claim unsupported currency (ETH, BTC, FAKE_TOKEN) in payment",
    "X4-004": "Multiple requests to detect dynamic payTo routing (V2)",
    "X4-005": "Send payment targeting a different address than server specified",
    "X4-006": "Test with invalid addresses (zero, short, non-hex, empty)",
    "X4-007": "Check if server returns session token/cookie after payment auth",
    "X4-008": "Present fabricated session tokens (random, fake JWT, SQLi)",
    "X4-009": "Present an expired JWT session token",
    "X4-010": "Check response for sensitive data leakage (keys, paths, traces)",
    "X4-011": "Rapid sequential requests to test rate limiting on payments",
    "X4-012": "Send payment claiming lower amount than requested (underpay)",
    "X4-013": "Concurrent burst test for budget exhaustion defenses",
    "X4-014": "Inject fake X-Payment-Facilitator header pointing to attacker URL",
    "X4-015": "Claim verification from a non-existent facilitator",
    "X4-016": "Test behavior when facilitator endpoint is unreachable",
    "X4-017": "Analyze 402 response for leaked sensitive info (keys, balances)",
    "X4-018": "Send malformed payloads and check error messages for info leaks",
    "X4-019": "Specify wrong blockchain network in payment",
    "X4-020": "Specify wrong token type (EURC, USDT when server expects USDC)",
    "X4-021": "Verify operator attestation JWT presence (OATR agent-attestation+jwt, EdDSA)",
    "X4-022": "Check attestation JWT audience matches endpoint domain (domain binding)",
    "X4-023": "Test OATR revocation list availability and functionality",
    "X4-024": "Send stale manifest (>15min) to test CACHE_TTL_MS enforcement",
    "X4-025": "Inject forged attestation signed with random Ed25519 key (unknown issuer)",
}


def list_tests():
    """Print available tests grouped by category."""
    print(f"\n{'='*60}")
    print("x402 SECURITY TESTS \u2014 AVAILABLE TEST CASES")
    print(f"{'='*60}\n")

    test_id_map = {
        "payment_challenge":      ["X4-001", "X4-002", "X4-003"],
        "recipient_manipulation": ["X4-004", "X4-005", "X4-006"],
        "session_security":       ["X4-007", "X4-008", "X4-009", "X4-010"],
        "spending_limits":        ["X4-011", "X4-012", "X4-013"],
        "facilitator_trust":      ["X4-014", "X4-015", "X4-016"],
        "information_disclosure": ["X4-017", "X4-018"],
        "cross_chain_confusion":  ["X4-019", "X4-020"],
        "identity_verification": ["X4-021", "X4-022", "X4-023", "X4-024", "X4-025"],
    }

    for category, ids in test_id_map.items():
        print(f"[{category}]")
        for tid in ids:
            print(f"  {tid}: {_TEST_DESCRIPTIONS.get(tid, '(no description)')}")
        print()

    print(f"Total: {sum(len(v) for v in test_id_map.values())} tests across {len(test_id_map)} categories\n")


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(results: list[X402TestResult], output_path: str,
                    autonomy_risk: dict | None = None):
    """Write JSON report with x402-specific extensions."""
    report = {
        "suite": "x402 Payment Protocol Security Tests v1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "spec_reference": "https://www.x402.org/x402-whitepaper.pdf",
        "security_analysis_reference": "https://www.halborn.com/blog/post/x402-explained-security-risks-and-controls-for-http-402-micropayments",
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
        },
        "autonomy_risk_score": autonomy_risk or {},
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
        description="x402 Payment Protocol Security Test Harness — "
                    "the FIRST open-source x402 security harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m protocol_tests.x402_harness --url https://x402-server.example.com\n"
            "  python -m protocol_tests.x402_harness --url https://x402-server.example.com "
            "--paid-path /api/v1/tools/weather/call\n"
            "  python -m protocol_tests.x402_harness --url https://x402-server.example.com "
            "--categories payment_challenge,facilitator_trust\n"
            "  python -m protocol_tests.x402_harness --url https://x402-server.example.com "
            "--trials 10 --report x402_report.json\n"
        ),
    )
    ap.add_argument("--url",
                    help="x402-gated server URL (required for testing)")
    ap.add_argument("--paid-path", default="",
                    help="Path that returns 402 (e.g., /api/v1/tools/weather/call). "
                         "If omitted, tests hit the root URL.")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"],
                    help="HTTP method for the paid endpoint (default: GET). "
                         "Use POST for x402 endpoints that only accept POST.")
    ap.add_argument("--body", default=None,
                    help="Optional JSON request body for POST endpoints "
                         "(e.g., '{\"prompt\": \"hello\"}')")
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

    if not args.url:
        ap.error("--url is required for testing (use --list to see available tests)")

    headers = {}
    for h in args.header:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    # Validate --body requires --method POST
    if args.body and args.method != "POST":
        ap.error("--body requires --method POST")

    transport = X402Transport(args.url, headers=headers, paid_path=args.paid_path,
                              default_method=args.method, default_body=args.body)
    categories = args.categories.split(",") if args.categories else None

    if args.trials > 1:
        _run_statistical(transport, categories, args.trials, args.report)
    else:
        suite = X402SecurityTests(transport)
        results = suite.run_all(categories=categories)
        autonomy_risk = suite.compute_autonomy_risk_score()

        if args.report:
            generate_report(results, args.report, autonomy_risk=autonomy_risk)

        failed = sum(1 for r in results if not r.passed)
        sys.exit(1 if failed > 0 else 0)


def _run_statistical(
    transport: X402Transport,
    categories: list[str] | None,
    n_trials: int,
    report_path: str | None,
):
    """Run tests multiple times and compute Wilson score confidence intervals."""
    from protocol_tests.statistical import wilson_ci, enhance_report, TrialResult

    all_tests_flat: list[tuple[str, str, str]] = []
    test_id_order = [f"X4-{i:03d}" for i in range(1, 26)]
    id_idx = 0
    for category, method_names in X402SecurityTests.ALL_TESTS.items():
        if categories and category not in categories:
            id_idx += len(method_names)
            continue
        for method_name in method_names:
            all_tests_flat.append((category, method_name, test_id_order[id_idx]))
            id_idx += 1

    print(f"\n{'='*60}")
    print(f"x402 STATISTICAL MODE \u2014 {n_trials} trials per test")
    print(f"{'='*60}")
    print(f"Target: {transport.base_url}\n")

    trial_results: list[TrialResult] = []
    all_results: list[X402TestResult] = []

    aggregated_autonomy_signals: dict[str, bool] = {}

    for category, method_name, test_id in all_tests_flat:
        passes = 0
        elapsed_times: list[float] = []

        for trial in range(n_trials):
            suite = X402SecurityTests(transport)
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
                # Merge autonomy signals (use first trial's signals as baseline)
                if trial == 0:
                    aggregated_autonomy_signals.update(suite._autonomy_signals)
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
            per_trial=[],
            mean_elapsed_s=round(mean_elapsed, 3),
        )
        trial_results.append(tr)
        print(f"  {test_id}: {passes}/{n_trials} passed  CI95=[{ci[0]:.3f}, {ci[1]:.3f}]  "
              f"avg={mean_elapsed:.2f}s")

    # Compute autonomy risk using aggregated signals from all trial runs
    last_suite = X402SecurityTests(transport)
    last_suite.results = all_results
    last_suite._autonomy_signals = aggregated_autonomy_signals
    autonomy_risk = last_suite.compute_autonomy_risk_score()

    print(f"\n{'='*60}")
    total_pass = sum(tr.n_passed for tr in trial_results)
    total_trials = sum(tr.n_trials for tr in trial_results)
    print(f"AGGREGATE: {total_pass}/{total_trials} trial-passes")
    print(f"AGENT AUTONOMY RISK SCORE: {autonomy_risk['score']}/100 ({autonomy_risk['risk_level']})")
    print(f"{'='*60}\n")

    if report_path:
        report = {
            "suite": "x402 Payment Protocol Security Tests v1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "spec_reference": "https://www.x402.org/x402-whitepaper.pdf",
            "security_analysis_reference": "https://www.halborn.com/blog/post/x402-explained-security-risks-and-controls-for-http-402-micropayments",
            "summary": {
                "total": len(all_results),
                "passed": sum(1 for r in all_results if r.passed),
                "failed": sum(1 for r in all_results if not r.passed),
            },
            "autonomy_risk_score": autonomy_risk,
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
