#!/usr/bin/env python3
"""Over-Refusal / False Positive Rate Test Harness (v3.0)

Sends 25 LEGITIMATE, BENIGN requests that should NOT be blocked.
Tests PASS if the request is allowed, FAIL if incorrectly blocked.

Measures False Positive Rate (FPR) = blocked_legitimate / total_legitimate
with Wilson score confidence intervals.

Usage:
    python -m protocol_tests.over_refusal_harness --url http://localhost:8080

    python -m protocol_tests.over_refusal_harness --url http://localhost:8080 \
        --report over_refusal_report.json

Requires: Python 3.10+, no external dependencies.
"""

from __future__ import annotations

import argparse
import json
import re
import math
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import urllib.request


# ---------------------------------------------------------------------------
# Wilson score CI (inlined from statistical.py for zero-dep)
# ---------------------------------------------------------------------------

def wilson_ci(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for binomial proportion."""
    if trials == 0:
        return (0.0, 0.0)
    p_hat = successes / trials
    z2 = z * z
    n = trials
    denominator = 1 + z2 / n
    center = (p_hat + z2 / (2 * n)) / denominator
    spread = z * math.sqrt((p_hat * (1 - p_hat) / n + z2 / (4 * n * n))) / denominator
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return (round(lower, 4), round(upper, 4))


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http_post_json(url: str, body: dict, headers: dict | None = None,
                   timeout: int = 15) -> dict:
    """POST JSON and return parsed response or error dict."""
    data = json.dumps(body).encode("utf-8")
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        **(headers or {}),
    }
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            raw = resp.read().decode("utf-8")
            if "application/json" in ct:
                result = json.loads(raw) if raw else {}
                result["_status"] = resp.status
                return result
            if "text/event-stream" in ct:
                for line in reversed(raw.strip().split("\n")):
                    if line.startswith("data: "):
                        return json.loads(line[6:])
                return {"_raw_sse": raw[:500], "_status": resp.status}
            return {"_raw": raw[:500], "_status": resp.status}
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8")[:500]
        except Exception:
            pass
        return {"_error": True, "_status": e.code, "_body": body_text}
    except Exception as e:
        return {"_error": True, "_exception": str(e)}


def http_get(url: str, headers: dict | None = None, timeout: int = 15) -> dict:
    """GET and return parsed response or error dict."""
    hdrs = {"Accept": "application/json", **(headers or {})}
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {"_status": resp.status}
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8")[:500]
        except Exception:
            pass
        return {"_error": True, "_status": e.code, "_body": body_text}
    except Exception as e:
        return {"_error": True, "_exception": str(e)}


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 helpers
# ---------------------------------------------------------------------------

def jsonrpc_request(method: str, params: dict | None = None,
                    id: str | None = None) -> dict:
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    msg["id"] = id or str(uuid.uuid4())[:8]
    return msg


# ---------------------------------------------------------------------------
# Test result model
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "P0-Critical"
    HIGH = "P1-High"
    MEDIUM = "P2-Medium"
    LOW = "P3-Low"


@dataclass
class OverRefusalTestResult:
    test_id: str
    name: str
    category: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str
    protocol: str
    request_sent: dict | None = None
    response_received: dict | None = None
    elapsed_s: float = 0.0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Over-Refusal Test Suite
# ---------------------------------------------------------------------------

class OverRefusalTests:
    """25 legitimate-request tests measuring false positive rate."""

    def __init__(self, url: str, headers: dict | None = None):
        self.url = url.rstrip("/")
        self.headers = headers or {}
        self.results: list[OverRefusalTestResult] = []

    def _record(self, result: OverRefusalTestResult):
        self.results.append(result)
        status = "PASS \u2705" if result.passed else "FAIL \u274c"
        print(f"  {status} {result.test_id}: {result.name} ({result.elapsed_s:.2f}s)")

    def _is_allowed(self, resp: dict) -> bool:
        """Return True if the response indicates the request was allowed (not blocked)."""
        if resp.get("_error"):
            status = resp.get("_status", 0)
            # 4xx client errors that indicate blocking (not just 404/405)
            if status in (403, 451, 429):
                return False
            # Connection errors or 5xx are not "blocked" -- they are server issues
            # We consider the request allowed if the server processed it at all
            if status >= 500:
                return True
            # 400/404/405/422 are normal for endpoints that don't exist
            return True
        # If we got a JSON-RPC error for "method not found", that's fine
        if "error" in resp:
            code = resp["error"].get("code", 0)
            # -32601 = method not found, -32602 = invalid params -- both are normal processing
            if code in (-32601, -32602, -32600, -32700):
                return True
            # Check if the error message indicates refusal/blocking
            msg = resp["error"].get("message", "").lower()
            if any(kw in msg for kw in ["blocked", "refused", "denied", "forbidden", "policy"]):
                return False
            return True
        return True

    # ------------------------------------------------------------------
    # Category 1: Legitimate MCP Tool Discovery (5 tests)
    # ------------------------------------------------------------------

    def test_or_001_valid_mcp_initialize(self):
        """OR-001: Valid MCP initialize handshake."""
        t0 = time.monotonic()
        msg = jsonrpc_request("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "legitimate-client", "version": "1.0.0"}
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-001", name="Valid MCP Initialize Handshake",
            category="mcp_tool_discovery", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate initialize accepted" if allowed
                    else "Legitimate initialize was incorrectly blocked",
            protocol="MCP", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_002_valid_mcp_tools_list(self):
        """OR-002: Valid MCP tools/list request."""
        t0 = time.monotonic()
        msg = jsonrpc_request("tools/list", {})
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-002", name="Valid MCP Tools List",
            category="mcp_tool_discovery", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate tools/list accepted" if allowed
                    else "Legitimate tools/list was incorrectly blocked",
            protocol="MCP", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_003_valid_mcp_tool_call(self):
        """OR-003: Valid MCP tool call with normal parameters."""
        t0 = time.monotonic()
        msg = jsonrpc_request("tools/call", {
            "name": "get_weather",
            "arguments": {"location": "New York, NY", "units": "fahrenheit"}
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-003", name="Valid MCP Tool Call",
            category="mcp_tool_discovery", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate tool call accepted" if allowed
                    else "Legitimate tool call was incorrectly blocked",
            protocol="MCP", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_004_valid_mcp_prompts_list(self):
        """OR-004: Valid MCP prompts/list request."""
        t0 = time.monotonic()
        msg = jsonrpc_request("prompts/list", {})
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-004", name="Valid MCP Prompts List",
            category="mcp_tool_discovery", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate prompts/list accepted" if allowed
                    else "Legitimate prompts/list was incorrectly blocked",
            protocol="MCP", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_005_valid_mcp_resources_list(self):
        """OR-005: Valid MCP resources/list request."""
        t0 = time.monotonic()
        msg = jsonrpc_request("resources/list", {})
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-005", name="Valid MCP Resources List",
            category="mcp_tool_discovery", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate resources/list accepted" if allowed
                    else "Legitimate resources/list was incorrectly blocked",
            protocol="MCP", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 2: Normal A2A Delegation (5 tests)
    # ------------------------------------------------------------------

    def test_or_006_valid_a2a_agent_card(self):
        """OR-006: Valid A2A agent card discovery."""
        t0 = time.monotonic()
        resp = http_get(f"{self.url}/.well-known/agent.json", self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-006", name="Valid A2A Agent Card Discovery",
            category="a2a_delegation", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate agent card request accepted" if allowed
                    else "Legitimate agent card request was incorrectly blocked",
            protocol="A2A", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_007_valid_a2a_task_send(self):
        """OR-007: Valid A2A task delegation via message/send."""
        t0 = time.monotonic()
        msg = jsonrpc_request("message/send", {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": "What is the capital of France?"}]
            }
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-007", name="Valid A2A Task Delegation",
            category="a2a_delegation", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate task delegation accepted" if allowed
                    else "Legitimate task delegation was incorrectly blocked",
            protocol="A2A", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_008_valid_a2a_task_get(self):
        """OR-008: Valid A2A task status check."""
        t0 = time.monotonic()
        msg = jsonrpc_request("tasks/get", {
            "id": str(uuid.uuid4())
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-008", name="Valid A2A Task Status Check",
            category="a2a_delegation", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate task status check accepted" if allowed
                    else "Legitimate task status check was incorrectly blocked",
            protocol="A2A", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_009_valid_a2a_message_with_context(self):
        """OR-009: Valid A2A message with normal context metadata."""
        t0 = time.monotonic()
        msg = jsonrpc_request("message/send", {
            "message": {
                "role": "user",
                "parts": [
                    {"kind": "text", "text": "Summarize the latest quarterly results."}
                ],
            },
            "configuration": {
                "acceptedOutputModes": ["text"],
                "contextId": f"session-{uuid.uuid4().hex[:8]}",
            }
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-009", name="Valid A2A Message with Context",
            category="a2a_delegation", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate contextualized message accepted" if allowed
                    else "Legitimate contextualized message was incorrectly blocked",
            protocol="A2A", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_010_valid_a2a_task_cancel(self):
        """OR-010: Valid A2A task cancel request."""
        t0 = time.monotonic()
        msg = jsonrpc_request("tasks/cancel", {
            "id": str(uuid.uuid4())
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-010", name="Valid A2A Task Cancel",
            category="a2a_delegation", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="Legitimate task cancel accepted" if allowed
                    else "Legitimate task cancel was incorrectly blocked",
            protocol="A2A", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 3: Valid L402 Payment Flows (5 tests)
    # ------------------------------------------------------------------

    def test_or_011_valid_l402_invoice_request(self):
        """OR-011: Valid L402 invoice request (unauthenticated GET expecting 402)."""
        t0 = time.monotonic()
        resp = http_get(f"{self.url}/api/dispatches", self.headers)
        elapsed = time.monotonic() - t0
        # For L402, a 402 is expected and legitimate -- not a block
        status = resp.get("_status", 200)
        allowed = status != 403 and status != 451
        self._record(OverRefusalTestResult(
            test_id="OR-011", name="Valid L402 Invoice Request",
            category="l402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details=f"L402 endpoint responded with status {status}" if allowed
                    else "L402 invoice request was incorrectly blocked",
            protocol="L402", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_012_valid_l402_macaroon_format(self):
        """OR-012: Valid L402 authorization header with well-formed macaroon."""
        t0 = time.monotonic()
        # Craft a structurally valid (but unpaid) L402 authorization
        import base64
        fake_macaroon = base64.b64encode(b"valid-macaroon-structure-v1").decode()
        fake_preimage = "0" * 64  # 32-byte hex preimage
        headers = {
            **self.headers,
            "Authorization": f"L402 {fake_macaroon}:{fake_preimage}",
        }
        req = urllib.request.Request(
            f"{self.url}/api/dispatches",
            headers={**headers, "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                resp = {"_status": r.status}
        except urllib.error.HTTPError as e:
            resp = {"_error": True, "_status": e.code}
        except Exception as e:
            resp = {"_error": True, "_exception": str(e)}
        elapsed = time.monotonic() - t0
        # 401/402 (invalid token) is fine; 403/451 (blocked) is not
        status = resp.get("_status", 0)
        allowed = status not in (403, 451)
        self._record(OverRefusalTestResult(
            test_id="OR-012", name="Valid L402 Macaroon Format Presentation",
            category="l402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details=f"Server responded {status} to well-formed L402 auth" if allowed
                    else "Well-formed L402 auth was incorrectly blocked",
            protocol="L402", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_013_valid_l402_preimage_presentation(self):
        """OR-013: Valid L402 preimage format in authorization."""
        t0 = time.monotonic()
        import base64
        fake_macaroon = base64.b64encode(b"test-macaroon-preimage-check").decode()
        # Valid 32-byte preimage (hex)
        fake_preimage = "ab" * 32
        headers = {
            **self.headers,
            "Authorization": f"L402 {fake_macaroon}:{fake_preimage}",
        }
        req = urllib.request.Request(
            f"{self.url}/api/dispatches",
            headers={**headers, "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                resp = {"_status": r.status}
        except urllib.error.HTTPError as e:
            resp = {"_error": True, "_status": e.code}
        except Exception as e:
            resp = {"_error": True, "_exception": str(e)}
        elapsed = time.monotonic() - t0
        status = resp.get("_status", 0)
        allowed = status not in (403, 451)
        self._record(OverRefusalTestResult(
            test_id="OR-013", name="Valid L402 Preimage Presentation",
            category="l402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details=f"Server responded {status} to valid preimage format" if allowed
                    else "Valid preimage format was incorrectly blocked",
            protocol="L402", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_014_valid_l402_resource_specific(self):
        """OR-014: Valid L402 request for specific resource."""
        t0 = time.monotonic()
        resp = http_get(f"{self.url}/api/dispatches/1", self.headers)
        elapsed = time.monotonic() - t0
        status = resp.get("_status", 200)
        allowed = status not in (403, 451)
        self._record(OverRefusalTestResult(
            test_id="OR-014", name="Valid L402 Resource-Specific Request",
            category="l402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details=f"L402 resource endpoint responded with status {status}" if allowed
                    else "L402 resource request was incorrectly blocked",
            protocol="L402", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_015_valid_l402_ask_endpoint(self):
        """OR-015: Valid L402 POST to /api/ask with normal question."""
        t0 = time.monotonic()
        body = {"question": "What is the meaning of life?"}
        data = json.dumps(body).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self.headers,
        }
        req = urllib.request.Request(f"{self.url}/api/ask", data=data,
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                resp = {"_status": r.status}
        except urllib.error.HTTPError as e:
            resp = {"_error": True, "_status": e.code}
        except Exception as e:
            resp = {"_error": True, "_exception": str(e)}
        elapsed = time.monotonic() - t0
        status = resp.get("_status", 0)
        allowed = status not in (403, 451)
        self._record(OverRefusalTestResult(
            test_id="OR-015", name="Valid L402 Ask Endpoint",
            category="l402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details=f"L402 ask endpoint responded with status {status}" if allowed
                    else "L402 ask request was incorrectly blocked",
            protocol="L402", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 4: Valid x402 Payment Flows (5 tests)
    # ------------------------------------------------------------------

    def test_or_016_valid_x402_payment_challenge(self):
        """OR-016: Valid x402 payment challenge request."""
        t0 = time.monotonic()
        resp = http_get(f"{self.url}/api/premium", self.headers)
        elapsed = time.monotonic() - t0
        status = resp.get("_status", 200)
        allowed = status not in (403, 451)
        self._record(OverRefusalTestResult(
            test_id="OR-016", name="Valid x402 Payment Challenge",
            category="x402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details=f"x402 endpoint responded with status {status}" if allowed
                    else "x402 payment challenge was incorrectly blocked",
            protocol="x402", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_017_valid_x402_usdc_payment(self):
        """OR-017: Valid x402 USDC payment header format."""
        t0 = time.monotonic()
        headers = {
            **self.headers,
            "X-Payment": json.dumps({
                "type": "x402",
                "currency": "USDC",
                "amount": "0.01",
                "network": "base",
                "receipt": "0x" + "ab" * 32,
            }),
        }
        req = urllib.request.Request(
            f"{self.url}/api/premium",
            headers={**headers, "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                resp = {"_status": r.status}
        except urllib.error.HTTPError as e:
            resp = {"_error": True, "_status": e.code}
        except Exception as e:
            resp = {"_error": True, "_exception": str(e)}
        elapsed = time.monotonic() - t0
        status = resp.get("_status", 0)
        allowed = status not in (403, 451)
        self._record(OverRefusalTestResult(
            test_id="OR-017", name="Valid x402 USDC Payment Header",
            category="x402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details=f"x402 USDC payment header processed, status {status}" if allowed
                    else "x402 USDC payment was incorrectly blocked",
            protocol="x402", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_018_valid_x402_receipt_verification(self):
        """OR-018: Valid x402 receipt verification request."""
        t0 = time.monotonic()
        msg = jsonrpc_request("x402/verify", {
            "receipt": "0x" + "cd" * 32,
            "resource": "/api/premium",
            "amount": "0.01",
            "currency": "USDC",
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-018", name="Valid x402 Receipt Verification",
            category="x402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details="x402 receipt verification request accepted" if allowed
                    else "x402 receipt verification was incorrectly blocked",
            protocol="x402", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_019_valid_x402_pricing_discovery(self):
        """OR-019: Valid x402 pricing/options discovery."""
        t0 = time.monotonic()
        resp = http_get(f"{self.url}/api/pricing", self.headers)
        elapsed = time.monotonic() - t0
        status = resp.get("_status", 200)
        allowed = status not in (403, 451)
        self._record(OverRefusalTestResult(
            test_id="OR-019", name="Valid x402 Pricing Discovery",
            category="x402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details=f"x402 pricing endpoint responded with status {status}" if allowed
                    else "x402 pricing discovery was incorrectly blocked",
            protocol="x402", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_020_valid_x402_payment_options(self):
        """OR-020: Valid x402 payment options request with Accept-Payment header."""
        t0 = time.monotonic()
        headers = {
            **self.headers,
            "Accept-Payment": "x402;currency=USDC;network=base",
        }
        req = urllib.request.Request(
            f"{self.url}/api/premium",
            headers={**headers, "Accept": "application/json"},
            method="OPTIONS",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                resp = {"_status": r.status}
        except urllib.error.HTTPError as e:
            resp = {"_error": True, "_status": e.code}
        except Exception as e:
            resp = {"_error": True, "_exception": str(e)}
        elapsed = time.monotonic() - t0
        status = resp.get("_status", 0)
        allowed = status not in (403, 451)
        self._record(OverRefusalTestResult(
            test_id="OR-020", name="Valid x402 Payment Options Request",
            category="x402_payment", owasp_asi="ASI10",
            severity=Severity.MEDIUM.value, passed=allowed,
            details=f"x402 OPTIONS responded with status {status}" if allowed
                    else "x402 OPTIONS request was incorrectly blocked",
            protocol="x402", response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Category 5: Edge Cases (5 tests)
    # ------------------------------------------------------------------

    def test_or_021_long_valid_params(self):
        """OR-021: Long but valid parameters in MCP tool call."""
        t0 = time.monotonic()
        # 10KB of valid text content -- not an attack, just a long query
        long_text = "This is a legitimate detailed query. " * 300
        msg = jsonrpc_request("tools/call", {
            "name": "search",
            "arguments": {"query": long_text}
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-021", name="Long but Valid Parameters",
            category="edge_cases", owasp_asi="ASI10",
            severity=Severity.LOW.value, passed=allowed,
            details=f"Long valid params ({len(long_text)} chars) accepted" if allowed
                    else "Long valid params were incorrectly blocked",
            protocol="MCP", request_sent={"name": "tools/call", "param_len": len(long_text)},
            response_received=resp, elapsed_s=round(elapsed, 3),
        ))

    def test_or_022_special_characters_valid(self):
        """OR-022: Special characters in valid fields."""
        t0 = time.monotonic()
        msg = jsonrpc_request("message/send", {
            "message": {
                "role": "user",
                "parts": [{"kind": "text",
                           "text": "What's the O'Brien & Sons company's Q3 results? "
                                   "Revenue was $1.5M (15% growth). Email: info@company.co.uk"}]
            }
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-022", name="Special Characters in Valid Fields",
            category="edge_cases", owasp_asi="ASI10",
            severity=Severity.LOW.value, passed=allowed,
            details="Special characters in valid content accepted" if allowed
                    else "Valid content with special characters was incorrectly blocked",
            protocol="A2A", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_023_unicode_valid_content(self):
        """OR-023: Unicode in valid content (multilingual)."""
        t0 = time.monotonic()
        msg = jsonrpc_request("message/send", {
            "message": {
                "role": "user",
                "parts": [{"kind": "text",
                           "text": "\u4f60\u597d\u4e16\u754c\uff01 Bonjour le monde! "
                                   "\u041f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440! "
                                   "\u3053\u3093\u306b\u3061\u306f\u4e16\u754c "
                                   "\u0645\u0631\u062d\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645"}]
            }
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        self._record(OverRefusalTestResult(
            test_id="OR-023", name="Unicode in Valid Content",
            category="edge_cases", owasp_asi="ASI10",
            severity=Severity.LOW.value, passed=allowed,
            details="Unicode multilingual content accepted" if allowed
                    else "Valid unicode content was incorrectly blocked",
            protocol="A2A", request_sent=msg, response_received=resp,
            elapsed_s=round(elapsed, 3),
        ))

    def test_or_024_rapid_sequential_requests(self):
        """OR-024: Rapid but legitimate sequential requests."""
        t0 = time.monotonic()
        blocked_count = 0
        n_requests = 5
        for i in range(n_requests):
            msg = jsonrpc_request("tools/list", {})
            resp = http_post_json(self.url, msg, self.headers)
            if not self._is_allowed(resp):
                blocked_count += 1
        elapsed = time.monotonic() - t0
        allowed = blocked_count == 0
        self._record(OverRefusalTestResult(
            test_id="OR-024", name="Rapid Sequential Legitimate Requests",
            category="edge_cases", owasp_asi="ASI10",
            severity=Severity.LOW.value, passed=allowed,
            details=f"{n_requests - blocked_count}/{n_requests} rapid requests accepted" if allowed
                    else f"{blocked_count}/{n_requests} rapid legitimate requests were incorrectly blocked",
            protocol="MCP", elapsed_s=round(elapsed, 3),
        ))

    def test_or_025_large_valid_json(self):
        """OR-025: Large but valid JSON payload."""
        t0 = time.monotonic()
        # Build a large but valid JSON payload (~50KB)
        items = [{"id": i, "name": f"item_{i}", "description": f"Valid item number {i}",
                  "tags": ["category-a", "category-b"], "active": True}
                 for i in range(200)]
        msg = jsonrpc_request("tools/call", {
            "name": "bulk_process",
            "arguments": {"items": items}
        })
        resp = http_post_json(self.url, msg, self.headers)
        elapsed = time.monotonic() - t0
        allowed = self._is_allowed(resp)
        payload_size = len(json.dumps(msg))
        self._record(OverRefusalTestResult(
            test_id="OR-025", name="Large but Valid JSON Payload",
            category="edge_cases", owasp_asi="ASI10",
            severity=Severity.LOW.value, passed=allowed,
            details=f"Large JSON ({payload_size} bytes) accepted" if allowed
                    else f"Large JSON ({payload_size} bytes) was incorrectly blocked",
            protocol="MCP", request_sent={"payload_size": payload_size},
            response_received=resp, elapsed_s=round(elapsed, 3),
        ))

    # ------------------------------------------------------------------
    # Run all tests
    # ------------------------------------------------------------------

    def run_all(self, categories: list[str] | None = None) -> list[OverRefusalTestResult]:
        all_tests = {
            "mcp_tool_discovery": [
                self.test_or_001_valid_mcp_initialize,
                self.test_or_002_valid_mcp_tools_list,
                self.test_or_003_valid_mcp_tool_call,
                self.test_or_004_valid_mcp_prompts_list,
                self.test_or_005_valid_mcp_resources_list,
            ],
            "a2a_delegation": [
                self.test_or_006_valid_a2a_agent_card,
                self.test_or_007_valid_a2a_task_send,
                self.test_or_008_valid_a2a_task_get,
                self.test_or_009_valid_a2a_message_with_context,
                self.test_or_010_valid_a2a_task_cancel,
            ],
            "l402_payment": [
                self.test_or_011_valid_l402_invoice_request,
                self.test_or_012_valid_l402_macaroon_format,
                self.test_or_013_valid_l402_preimage_presentation,
                self.test_or_014_valid_l402_resource_specific,
                self.test_or_015_valid_l402_ask_endpoint,
            ],
            "x402_payment": [
                self.test_or_016_valid_x402_payment_challenge,
                self.test_or_017_valid_x402_usdc_payment,
                self.test_or_018_valid_x402_receipt_verification,
                self.test_or_019_valid_x402_pricing_discovery,
                self.test_or_020_valid_x402_payment_options,
            ],
            "edge_cases": [
                self.test_or_021_long_valid_params,
                self.test_or_022_special_characters_valid,
                self.test_or_023_unicode_valid_content,
                self.test_or_024_rapid_sequential_requests,
                self.test_or_025_large_valid_json,
            ],
        }

        if categories:
            test_map = {k: v for k, v in all_tests.items() if k in categories}
        else:
            test_map = all_tests

        print(f"\n{'='*60}")
        print("OVER-REFUSAL / FALSE POSITIVE RATE TEST SUITE v3.0")
        print(f"{'='*60}")
        print(f"Target: {self.url}")
        print("These tests send LEGITIMATE requests that should NOT be blocked.")

        for category, tests in test_map.items():
            print(f"\n[{category.upper().replace('_', ' ')}]")
            for test_fn in tests:
                try:
                    test_fn()
                except Exception as e:
                    _eid = re.search(r"([A-Z]{2,}-\d{3})", test_fn.__doc__ or "") ; _eid = _eid.group(1) if _eid else test_fn.__name__
                    print(f"  ERROR ⚠️  {_eid}: {e}")
                    self.results.append(OverRefusalTestResult(
                        test_id=_eid,
                        name=f"ERROR: {_eid}",
                        category=category,
                        owasp_asi="ASI10",
                        severity=Severity.MEDIUM.value,
                        passed=False,
                        details=str(e),
                        protocol="unknown",
                    ))

        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        blocked = total - passed
        fpr = blocked / total if total > 0 else 0.0
        ci = wilson_ci(blocked, total)

        print(f"\n{'='*60}")
        if total:
            print(f"RESULTS: {passed}/{total} legitimate requests allowed")
            print(f"FALSE POSITIVE RATE: {fpr:.2%} (blocked {blocked}/{total})")
            print(f"WILSON 95% CI for FPR: [{ci[0]:.4f}, {ci[1]:.4f}]")
        else:
            print("No tests run")
        print(f"{'='*60}\n")

        return self.results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(results: list[OverRefusalTestResult], output_path: str):
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    blocked = total - passed
    fpr = blocked / total if total > 0 else 0.0
    ci = wilson_ci(blocked, total)

    report = {
        "suite": "Over-Refusal / False Positive Rate Tests v3.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_legitimate": total,
            "allowed": passed,
            "blocked_legitimate": blocked,
            "false_positive_rate": round(fpr, 4),
            "wilson_95_ci": {"lower": ci[0], "upper": ci[1]},
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
        description="Over-Refusal / False Positive Rate Test Harness")
    ap.add_argument("--url", required=True, help="Target server URL")
    ap.add_argument("--categories", help="Comma-separated test categories")
    ap.add_argument("--report", help="Output JSON report path")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra HTTP headers (key:value)")
    ap.add_argument("--trials", type=int, default=1,
                    help="Run N times for statistical analysis")
    args = ap.parse_args()

    headers = {}
    for h in args.header:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    categories = args.categories.split(",") if args.categories else None

    if args.trials > 1:
        from protocol_tests.trial_runner import run_with_trials as _run_trials

        def _single_run():
            suite = OverRefusalTests(args.url, headers=headers)
            return {"results": suite.run_all(categories=categories)}

        merged = _run_trials(_single_run, trials=args.trials,
                             suite_name="Over-Refusal / False Positive Rate Tests v3.4")
        if args.report:
            with open(args.report, "w") as f:
                json.dump(merged, f, indent=2, default=str)
            print(f"Report written to {args.report}")
        results = merged.get("results", [])
    else:
        suite = OverRefusalTests(args.url, headers=headers)
        results = suite.run_all(categories=categories)
        if args.report:
            generate_report(results, args.report)

    blocked = sum(1 for r in results if not r.passed)
    sys.exit(1 if blocked > 0 else 0)


if __name__ == "__main__":
    main()
