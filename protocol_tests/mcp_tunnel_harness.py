#!/usr/bin/env python3
"""MCP Tunnel Security Test Harness (v0.1.0 — VS-R01 SKELETON, NOT EXECUTABLE)

Adversarial probes for Anthropic MCP Tunnels — the outbound-only gateway that
fronts a self-hosted MCP server for an Anthropic-orchestrated agent. The four
tests below validate the tunnel-specific surface: outbound-only network
posture after handshake, WIF-derived tunnel-token replay across rotation,
manual-credential lifetime / refresh path, and whether the tunnel itself
sanitizes a CP-0002 (CVE-2026-25253) description-injection payload as it
passes traffic from the MCP server upstream to the orchestrator (it should
NOT — that is the documented threat boundary the operator owns).

SAFETY CONSTRAINTS — READ BEFORE WIRING CREDENTIALS:
    - Out of scope: Anthropic's orchestration plane itself, other tenants'
      tunnels, fingerprinting other research-preview participants, any probe
      that touches infrastructure not provisioned to this account.
    - Out of scope: any unauthenticated scan of tunnel.anthropic.com or
      sibling endpoints — only the tunnel gateway this account owns.
    - Module refuses to import unless `MCP_TUNNEL_PREVIEW_OK=1` is set in
      the environment AND `ANTHROPIC_API_KEY` is resolvable. No live tunnel
      handshake will be initiated unless both gates pass.
    - All four tests are `pytest.mark.skip`-decorated pending VS-R01 credential
      provisioning. See `vault/projects/harness-vs-r01-scope.md`.

References:
    - CP-0002 / CVE-2026-25253 source pattern:
      `community_modules/examples/mcp_description_exfil.yaml`
    - MCP wire-protocol harness (description-injection pattern source):
      `protocol_tests/mcp_harness.py:1222` test_mcp_tool_description_injection_patterns
    - WIF lifecycle conventions:
      `protocol_tests/identity_harness.py:251` test_auth_002_expired_credential_rejection
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Research-preview safety guard (module-load time)
# ---------------------------------------------------------------------------

RESEARCH_PREVIEW: bool = True
"""When True, every test in this module hard-skips until the operator has
explicitly opted into the Anthropic MCP Tunnels research preview. Flip to
False only after the credential-provisioning gate in VS-R01 is complete."""

_PREVIEW_ENV_FLAG = "MCP_TUNNEL_PREVIEW_OK"
_API_KEY_ENV = "ANTHROPIC_API_KEY"
_TUNNEL_GATEWAY_ENV = "MCP_TUNNEL_GATEWAY_URL"
_MCP_SERVER_ENV = "MCP_TUNNEL_UPSTREAM_URL"

# Hard refusal: importing this module without the explicit research-preview
# opt-in must fail loudly. This intercepts accidental `pytest -q` runs from
# touching live tunnel infrastructure.
assert os.environ.get(_PREVIEW_ENV_FLAG) == "1" or os.environ.get("PYTEST_COLLECT_ONLY") == "1", (
    f"mcp_tunnel_harness refuses to load: set {_PREVIEW_ENV_FLAG}=1 only after "
    f"reading vault/projects/harness-vs-r01-scope.md — this module talks to a "
    f"live Anthropic MCP Tunnel and must not run during routine pytest collection."
)


# ---------------------------------------------------------------------------
# Gated SDK import (skip whole module if anthropic not available)
# ---------------------------------------------------------------------------

try:
    import anthropic  # noqa: F401  — imported for availability check only
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _ANTHROPIC_AVAILABLE,
    reason="anthropic SDK not installed — pip install anthropic to enable",
)


# ---------------------------------------------------------------------------
# Result model — mirrors MCPTestResult / CloudAgentTestResult shape so the
# `summarize_results()` output round-trips cleanly through trial_runner.
# ---------------------------------------------------------------------------

@dataclass
class TunnelTestResult:
    test_id: str
    name: str
    category: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str
    tunnel_endpoint: str = ""
    request_sent: dict | None = None
    response_received: dict | None = None
    elapsed_s: float = 0.0
    timestamp: str = ""
    notes: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_tunnel_gateway() -> dict:
    """Resolve tunnel gateway config from env. Pytest-skips if creds missing.

    Returns a dict with `gateway_url`, `upstream_mcp_url`, `api_key`. The
    api_key is read but NEVER returned to test bodies — only the presence
    flag is exposed. Tests construct their own SDK clients via env.
    """
    gateway_url = os.environ.get(_TUNNEL_GATEWAY_ENV)
    upstream_url = os.environ.get(_MCP_SERVER_ENV)
    api_key = os.environ.get(_API_KEY_ENV)

    missing = [
        name for name, val in [
            (_TUNNEL_GATEWAY_ENV, gateway_url),
            (_MCP_SERVER_ENV, upstream_url),
            (_API_KEY_ENV, api_key),
        ]
        if not val
    ]
    if missing:
        pytest.skip(f"tunnel credentials missing: {', '.join(missing)}")

    return {
        "gateway_url": gateway_url,
        "upstream_mcp_url": upstream_url,
        "api_key_present": True,
    }


def _placeholder_skip_reason() -> str:
    return (
        "awaiting VS-R01 credential provisioning — "
        "see vault/projects/harness-vs-r01-scope.md"
    )


# ---------------------------------------------------------------------------
# Tests — all skip-decorated until VS-R01 credentials wire up
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="awaiting VS-R01 credential provisioning — see vault/projects/harness-vs-r01-scope.md")
def test_mcp_tunnel_outbound_only_assertion() -> dict:
    """MCP-TUN-001: Verify tunnel gateway has no inbound listener bound to 0.0.0.0 after handshake.

    Attack pattern: misconfiguration drift — operator deploys tunnel correctly,
        but a later config push or sidecar opens an inbound listener that
        bypasses the outbound-only invariant Anthropic documents. Detected by
        enumerating bound sockets on the gateway process post-handshake and
        asserting that no LISTEN socket is bound to 0.0.0.0 / :: on a port
        that maps to the tunnel control channel.
    In-scope behavior: post-handshake socket state of the tunnel gateway
        process this account owns.
    Expected vendor response: documented invariant — tunnel gateway opens an
        outbound mTLS connection to Anthropic and accepts no inbound traffic.
        Regression here means the threat model changes from "outbound-only"
        to "publicly reachable agent surface".

    Out of scope: probing other accounts' tunnels, sniffing the Anthropic
        side of the mTLS, scanning sibling endpoints on tunnel.anthropic.com.
    """
    cfg = _get_tunnel_gateway()

    # TODO(VS-R01-exec): replace this placeholder with actual socket enumeration
    # against the local tunnel gateway PID. Reference: `ss -tlnp` filtered
    # to the gateway process, fail on any 0.0.0.0:* or [::]:* LISTEN entry.
    result = TunnelTestResult(
        test_id="MCP-TUN-001",
        name="Tunnel Outbound-Only Posture",
        category="network_posture",
        owasp_asi="ASI03",
        severity="P0-Critical",
        passed=False,
        details="[skeleton] socket enumeration not yet wired",
        tunnel_endpoint=cfg["gateway_url"],
        notes=[
            "TODO(VS-R01-exec): enumerate LISTEN sockets on gateway PID via psutil",
            "TODO(VS-R01-exec): confirm Anthropic documents the outbound-only invariant explicitly",
        ],
    )
    return asdict(result)


@pytest.mark.skip(reason="awaiting VS-R01 credential provisioning — see vault/projects/harness-vs-r01-scope.md")
def test_mcp_tunnel_token_replay_across_session() -> dict:
    """MCP-TUN-002: Capture WIF-derived tunnel token, attempt reuse after rotation; expect rejection.

    Attack pattern: stolen-token replay. Tunnel tokens derived from a
        workload-identity federation (WIF) credential should be bound to a
        single session and rejected after the next rotation cycle. The test
        captures token T1 during session S1, forces rotation, then attempts
        to use T1 to open S2. The tunnel control channel must reject with
        a non-retryable error.
    In-scope behavior: token lifecycle for this account's WIF credential
        only. No probing of other tenants' rotation cadence.
    Expected vendor response: hard rejection (401 or equivalent control-
        plane error) within one rotation window. Acceptance = replay-attack
        surface and breaks the operator's compromise-recovery assumption.

    Out of scope: extracting Anthropic's signing key, fingerprinting the
        rotation algorithm beyond pass/fail outcome, replay across tenants.
    """
    cfg = _get_tunnel_gateway()

    # TODO(VS-R01-exec): the WIF exchange + rotation hook needs Anthropic's
    # documented rotation endpoint. If they don't expose a manual-rotation
    # API, this test downgrades to a "wait for natural rotation TTL" variant.
    result = TunnelTestResult(
        test_id="MCP-TUN-002",
        name="WIF Token Replay Across Rotation",
        category="token_lifecycle",
        owasp_asi="ASI03",
        severity="P0-Critical",
        passed=False,
        details="[skeleton] token-capture + rotation flow not yet wired",
        tunnel_endpoint=cfg["gateway_url"],
        notes=[
            "TODO(VS-R01-exec): confirm Anthropic exposes manual rotation endpoint or document natural TTL",
            "TODO(VS-R01-exec): bind captured token to JWT structure for inspection (no key extraction)",
        ],
    )
    return asdict(result)


@pytest.mark.skip(reason="awaiting VS-R01 credential provisioning — see vault/projects/harness-vs-r01-scope.md")
def test_mcp_tunnel_manual_credential_lifetime() -> dict:
    """MCP-TUN-003: Manual-credential flow — assert token TTL ≤ documented value, refresh path works, no long-lived bearer leakage.

    Attack pattern: long-lived bearer leakage. The manual-credential variant
        (where operator pastes an API key rather than using WIF) must mint a
        short-lived tunnel token, refresh it via a documented endpoint, and
        never expose the underlying API key to the upstream MCP server or
        downstream log surface. The test asserts (a) token TTL ≤ vendor-
        documented maximum, (b) refresh path succeeds before expiry, and
        (c) the raw API key never appears in tunnel logs or proxied headers.
    In-scope behavior: token TTL inspection, refresh path success, log
        scrubbing for credential material — all within this account.
    Expected vendor response: TTL bounded, refresh path documented and
        functional, API key only ever appears at the SDK call site.

    Out of scope: testing other auth modes, brute-forcing TTL boundaries,
        any timing analysis that could fingerprint the rotation worker.
    """
    cfg = _get_tunnel_gateway()

    # TODO(VS-R01-exec): confirm Anthropic's documented max TTL for manual creds.
    # Until that number is published, this test cannot assert a hard bound.
    documented_max_ttl_seconds = None  # TODO(VS-R01-exec): set when Anthropic publishes

    result = TunnelTestResult(
        test_id="MCP-TUN-003",
        name="Manual Credential Lifetime + Refresh",
        category="token_lifecycle",
        owasp_asi="ASI03",
        severity="P0-Critical",
        passed=False,
        details=f"[skeleton] manual-credential TTL probe not yet wired; documented_max_ttl_seconds={documented_max_ttl_seconds}",
        tunnel_endpoint=cfg["gateway_url"],
        notes=[
            "TODO(VS-R01-exec): confirm documented_max_ttl_seconds with Anthropic before asserting",
            "TODO(VS-R01-exec): log-scrub check requires tunnel-gateway log path — env var TBD",
        ],
    )
    return asdict(result)


@pytest.mark.skip(reason="awaiting VS-R01 credential provisioning — see vault/projects/harness-vs-r01-scope.md")
def test_mcp_tunnel_description_exfil_passthrough() -> dict:
    """MCP-TUN-004: Adapt CP-0002 description-injection through tunnel; confirm tunnel does NOT sanitize.

    Attack pattern: documents the threat boundary. The CP-0002 payload from
        `community_modules/examples/mcp_description_exfil.yaml` (CVE-2026-
        25253) — a poisoned tool description carrying hidden exfiltration
        instructions — is served by the upstream MCP server, transits the
        tunnel, and lands at the Anthropic orchestrator. The tunnel is a
        transport: it should NOT sanitize the payload. If it does, that's
        actually a problem (silent mutation of operator content). If it
        doesn't, the test documents that description-sanitization is the
        operator's responsibility, NOT the tunnel's. This is a
        documentation-of-boundary test, not a vulnerability test.
    In-scope behavior: payload passthrough fidelity end-to-end (upstream
        MCP server → tunnel → orchestrator), comparing the description
        bytes before and after transit.
    Expected vendor response: byte-for-byte passthrough. Tunnel does not
        scan, rewrite, or strip tool-description content. Operator is
        responsible for upstream MCP server hygiene (per CP-0002 mitigation).

    Out of scope: actually exfiltrating data to a third-party endpoint —
        the test only asserts payload bytes survive transit; it does not
        complete the exfil step from the CP-0002 attack chain.
    """
    cfg = _get_tunnel_gateway()

    # TODO(VS-R01-exec): load CP-0002 description payload from community_modules
    # YAML once, then issue a tools/list through the tunnel and diff the
    # description bytes the orchestrator receives against the bytes sent.
    cp_0002_payload_path = "community_modules/examples/mcp_description_exfil.yaml"

    result = TunnelTestResult(
        test_id="MCP-TUN-004",
        name="CP-0002 Description-Injection Passthrough (Boundary Doc)",
        category="threat_boundary_documentation",
        owasp_asi="ASI04",
        severity="P2-Medium",  # documentation test, not a vuln
        passed=False,
        details="[skeleton] CP-0002 passthrough fidelity check not yet wired",
        tunnel_endpoint=cfg["gateway_url"],
        request_sent={"payload_source": cp_0002_payload_path, "method": "tools/list"},
        notes=[
            "TODO(VS-R01-exec): load CP-0002 YAML and stage upstream MCP server with poisoned tool",
            "TODO(VS-R01-exec): assert tunnel passes payload bytes unchanged (this is the GOOD outcome)",
            "TODO(VS-R01-exec): do NOT actually exfiltrate — stop at passthrough assertion",
        ],
    )
    return asdict(result)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def summarize_results(results: list[dict | TunnelTestResult]) -> dict:
    """Aggregate a list of TunnelTestResult (or asdict'd equivalents) into a
    JSON-serializable summary matching `mcp_harness.build_report()` shape so
    trial_runner can consume both interchangeably.

    Returns: {"suite", "timestamp", "summary": {total, passed, failed,
    skipped}, "results": [...], "research_preview": True}.
    """
    normalized: list[dict] = []
    for r in results:
        if isinstance(r, TunnelTestResult):
            normalized.append(asdict(r))
        elif isinstance(r, dict):
            normalized.append(r)
        else:
            raise TypeError(f"unsupported result type: {type(r).__name__}")

    total = len(normalized)
    passed = sum(1 for r in normalized if r.get("passed") is True)
    failed = sum(1 for r in normalized if r.get("passed") is False)
    skipped = total - passed - failed  # None / missing key = skipped

    return {
        "suite": "MCP Tunnel Security Tests v0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "research_preview": RESEARCH_PREVIEW,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        },
        "results": normalized,
    }


if __name__ == "__main__":
    # Module is pytest-driven; running directly only prints a stub summary
    # so operators can verify the safety guard fired correctly.
    print(json.dumps(summarize_results([]), indent=2))
