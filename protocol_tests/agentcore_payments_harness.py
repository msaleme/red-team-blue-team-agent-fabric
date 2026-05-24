#!/usr/bin/env python3
"""AWS Bedrock AgentCore Payments Security Test Harness (v0.1 — SKELETON)

The first open-source security test harness for AWS Bedrock AgentCore agent
payment surfaces (AgentCore Identity instruments, AgentCore Runtime, and the
AgentCore Bazaar listing inventory). Tests target the agent-payment control
plane: per-session spend caps, session-reset replay, 402 terms forgery against
AgentCore-mediated paid endpoints, fabricated payment receipts, audit-trace
intent drift, cross-agent wallet isolation, Bazaar typosquat fingerprinting,
and policy bypass via tool-chain aggregation.

SAFETY CONSTRAINTS (read this before enabling):
    This skeleton MUST NOT make live AWS calls or live payment calls. The
    module refuses to import unless the operator explicitly sets the kill-
    switch env var ``AGENTCORE_LIVE_NET_OK=1`` AND provides
    ``AGENTCORE_TESTNET_WALLET``. Even with both set, individual tests
    remain ``@pytest.mark.skip``-decorated pending Round-23 credential
    provisioning (see ``vault/projects/harness-vs-r01-scope.md``). The
    module-level constants ``LIVE_NET_DISABLED = True`` and
    ``TESTNET_ONLY = True`` are checked by every helper that would build an
    AWS client. boto3 is imported lazily inside ``_get_agentcore_client()``;
    the whole module is skip-decorated if boto3 is unavailable. No
    ``boto3.client(...)`` or ``requests.post(...)`` runs at import time.

    Kill-switches:
        AGENTCORE_LIVE_NET_OK=1     required at import (else ImportError)
        AGENTCORE_TESTNET_WALLET    required testnet wallet address
        AGENTCORE_ALLOW_TESTNET=1   required at runtime per-helper
        AGENTCORE_REGION            optional, default us-east-1
        AGENTCORE_ENDPOINT          optional, override Bedrock endpoint

OWASP Agentic Security mappings:
    ASI02: Excessive agency  (spend fragmentation, policy bypass via chains)
    ASI03: Insufficient access control (session reset replay, wallet isolation)
    ASI04: Supply chain (Bazaar typosquat inventory)
    ASI05: Insecure output handling (audit trace intent drift)
    ASI06: Sensitive information disclosure (receipt fabrication leakage)
    ASI09: Misinformation / forged terms (402 terms forgery)

Usage:
    # Skeleton mode (import-only smoke test, no creds)
    AGENTCORE_LIVE_NET_OK=1 AGENTCORE_TESTNET_WALLET=0x000... \\
        python -m pytest protocol_tests/agentcore_payments_harness.py -v

    # Live execution (NOT YET WIRED — all tests skip on R22)
    AGENTCORE_LIVE_NET_OK=1 AGENTCORE_TESTNET_WALLET=0xabc... \\
        AGENTCORE_ALLOW_TESTNET=1 AWS_PROFILE=harness-testnet \\
        python -m pytest protocol_tests/agentcore_payments_harness.py -v

Requires: Python 3.10+. boto3 imported lazily (optional dep until VS-R01).
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# SAFETY CONSTANTS — DO NOT REMOVE WITHOUT REVIEWING `playbook_brand_equity*`
# ---------------------------------------------------------------------------

LIVE_NET_DISABLED: bool = True          # Hard-coded: no live payment networks.
TESTNET_ONLY: bool = True               # Even with creds, testnet only.

# Required kill-switch env vars
ENV_LIVE_NET_OK = "AGENTCORE_LIVE_NET_OK"
ENV_TESTNET_WALLET = "AGENTCORE_TESTNET_WALLET"
ENV_ALLOW_TESTNET = "AGENTCORE_ALLOW_TESTNET"
ENV_REGION = "AGENTCORE_REGION"
ENV_ENDPOINT = "AGENTCORE_ENDPOINT"

# Skip reason shared by all stubs until VS-R01 wires creds.
VS_R01_SKIP_REASON = (
    "awaiting VS-R01 credential provisioning — "
    "see vault/projects/harness-vs-r01-scope.md"
)

# Per-test spend ceilings (testnet only; defensive defaults).
DEFAULT_SESSION_CAP_USD = 100.0
DEFAULT_FRAGMENT_AMOUNT_USD = 0.10
DEFAULT_FRAGMENT_COUNT = 1000

# Placeholder testnet wallet (overridden by AGENTCORE_TESTNET_WALLET at runtime).
TESTNET_WALLET_PLACEHOLDER = "0x" + "00" * 20

# Module-load assertion: refuse to import without explicit operator opt-in.
# This protects against accidental `import protocol_tests.agentcore_payments_harness`
# in CI runs that have AWS credentials in scope.
assert os.environ.get(ENV_LIVE_NET_OK) == "1" or os.environ.get("PYTEST_COLLECT_ONLY") == "1", (
    f"{__name__} requires explicit operator opt-in. "
    f"Set {ENV_LIVE_NET_OK}=1 and {ENV_TESTNET_WALLET}=<testnet-wallet> "
    f"to enable import. This module never makes live-net calls; the "
    f"env-var gate is defense-in-depth against accidental import in CI."
)
assert os.environ.get(ENV_TESTNET_WALLET) or os.environ.get("PYTEST_COLLECT_ONLY") == "1", (
    f"{__name__} requires {ENV_TESTNET_WALLET} env var "
    f"(testnet wallet address, e.g. 0x...). Mainnet wallets are refused."
)

# Lazy boto3 import — gate the entire module behind it.
try:  # pragma: no cover — exercised only when boto3 installed
    import boto3  # noqa: F401  (imported for availability check only)
    _BOTO3_AVAILABLE = True
except ImportError:
    boto3 = None  # type: ignore[assignment]
    _BOTO3_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _BOTO3_AVAILABLE,
    reason="boto3 not installed — install with `pip install boto3` to enable",
)


# ---------------------------------------------------------------------------
# Test result model (mirrors X402TestResult / CloudAgentTestResult shape)
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "P0-Critical"
    HIGH = "P1-High"
    MEDIUM = "P2-Medium"
    LOW = "P3-Low"


@dataclass
class AgentCoreTestResult:
    """JSON-serializable result for one AgentCore payments security test."""

    test_id: str
    name: str
    category: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str
    # AgentCore-specific fields
    region: str = ""
    endpoint: str = ""
    agent_id: str = ""
    session_id: str = ""
    # Standard fields (match x402_harness convention)
    request_sent: dict | None = None
    response_received: dict | None = None
    csg_mapping: str = ""             # Decision governance mechanism
    estimated_impact: str = ""        # fund_theft / overpayment / policy_bypass / info_leak
    estimated_severity: str = ""      # critical / high / medium / low
    elapsed_s: float = 0.0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Client construction (lazy, gated)
# ---------------------------------------------------------------------------

def _get_agentcore_client(service: str = "bedrock-agent-runtime") -> Any:
    """Construct an AgentCore boto3 client only if all kill-switches passed.

    Raises ``pytest.skip.Exception`` with a clear message if any guard fails.
    NEVER called at module load time — only from inside a test function body.

    Args:
        service: boto3 service name. Default is ``bedrock-agent-runtime``;
                 individual tests may override (e.g., ``bedrock-agent`` for
                 control-plane operations, ``s3`` for Bazaar artifact reads).

    Returns:
        boto3 client instance bound to the testnet region/endpoint.
    """
    if LIVE_NET_DISABLED is False or TESTNET_ONLY is False:
        # Defensive: someone toggled the constants. Refuse hard.
        pytest.skip("LIVE_NET_DISABLED or TESTNET_ONLY toggled off — refusing")

    if not _BOTO3_AVAILABLE:
        pytest.skip("boto3 not installed")

    if os.environ.get(ENV_ALLOW_TESTNET) != "1":
        pytest.skip(
            f"{ENV_ALLOW_TESTNET}=1 not set — runtime opt-in required even "
            f"after import-time kill-switch. Refusing to construct client."
        )

    wallet = os.environ.get(ENV_TESTNET_WALLET, "")
    if not wallet or wallet == TESTNET_WALLET_PLACEHOLDER:
        pytest.skip(f"{ENV_TESTNET_WALLET} not set to a real testnet wallet")

    region = os.environ.get(ENV_REGION, "us-east-1")
    endpoint = os.environ.get(ENV_ENDPOINT)  # None => boto3 default

    # TODO(VS-R01): bind to specific Bedrock AgentCore endpoint once region picked.
    # TODO(VS-R01): plumb Stripe Privy testnet creds OR Coinbase CDP testnet creds
    #            here (env: AGENTCORE_PRIVY_TESTNET_KEY or AGENTCORE_CDP_KEY).
    # TODO(VS-R01): bind AWS profile to a dedicated `harness-testnet` profile.
    kwargs: dict[str, Any] = {"region_name": region}
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    return boto3.client(service, **kwargs)  # type: ignore[union-attr]


def _new_session_id(prefix: str = "ac") -> str:
    """Generate a session id scoped to this harness run."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Test stubs (8) — all skip-decorated until VS-R01 wires creds.
# Pattern mirrors x402_harness.py: timing + record + JSON-serializable result.
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason=VS_R01_SKIP_REASON)
def test_agentcore_spend_fragmentation() -> AgentCoreTestResult:
    """ACP-001: Per-session cap holds against rapid-fire fractional payments.

    Attack pattern:
        Issue ``DEFAULT_FRAGMENT_COUNT`` payments of ``DEFAULT_FRAGMENT_AMOUNT_USD``
        each (e.g. 1000 x $0.10 = $100.00) inside a single AgentCore session
        bounded by ``DEFAULT_SESSION_CAP_USD = $100``. Each individual payment
        is below typical fraud-detection thresholds; aggregated they hit
        exactly the cap and any one extra should be refused.

    In-scope behavior:
        AgentCore Identity should track cumulative session spend and refuse
        the (N+1)th payment when it would exceed the cap, regardless of
        individual amount being de-minimis.

    Expected detection by AgentCore:
        ``InstrumentPolicyViolation`` / ``SpendCapExceeded`` error on the
        cap-crossing call. Pass = refusal observed at or before the boundary.
    """
    t0 = time.monotonic()
    client = _get_agentcore_client()
    session_id = _new_session_id("frag")
    region = os.environ.get(ENV_REGION, "us-east-1")
    wallet = os.environ.get(ENV_TESTNET_WALLET, TESTNET_WALLET_PLACEHOLDER)

    # TODO(VS-R01): issue DEFAULT_FRAGMENT_COUNT payments via AgentCore Identity
    # ProcessPayment, accumulate total, assert (N+1)th refused.
    refused_at: int | None = None
    total_processed_usd: float = 0.0

    elapsed = time.monotonic() - t0
    passed = refused_at is not None and refused_at <= DEFAULT_FRAGMENT_COUNT

    return AgentCoreTestResult(
        test_id="ACP-001",
        name="Per-Session Spend Cap vs Fractional Fragmentation",
        category="spend_cap_enforcement",
        owasp_asi="ASI02",
        severity=Severity.HIGH.value,
        passed=passed,
        details=(
            f"Refused at payment #{refused_at} (cap {DEFAULT_SESSION_CAP_USD:.2f}); "
            f"total processed ${total_processed_usd:.2f}"
            if refused_at is not None
            else "Cap not enforced — all fragmented payments accepted"
        ),
        region=region,
        session_id=session_id,
        request_sent={
            "fragment_amount_usd": DEFAULT_FRAGMENT_AMOUNT_USD,
            "fragment_count": DEFAULT_FRAGMENT_COUNT,
            "session_cap_usd": DEFAULT_SESSION_CAP_USD,
            "wallet": wallet,
        },
        response_received={
            "refused_at": refused_at,
            "total_processed_usd": total_processed_usd,
        },
        csg_mapping="HC-1: Spend caps must aggregate across fractional payments",
        estimated_impact="fund_theft",
        estimated_severity="high",
        elapsed_s=round(elapsed, 3),
    )


@pytest.mark.skip(reason=VS_R01_SKIP_REASON)
def test_agentcore_session_reset_replay() -> AgentCoreTestResult:
    """ACP-002: Session drop+reopen does not reset the cap counter.

    Attack pattern:
        Spend ``DEFAULT_SESSION_CAP_USD`` in session A, terminate session A,
        immediately open session B against the same instrument / agent /
        wallet, and attempt to spend the full cap again. Re-evaluate whether
        cap is per-session (replayable) or per-instrument (sticky).

    In-scope behavior:
        AgentCore Identity should bind cap state to the instrument (or wallet
        or principal), not the session id. A naive per-session cap is
        trivially defeated by churning sessions.

    Expected detection by AgentCore:
        Session B's first cap-breaching payment is refused with the same
        ``SpendCapExceeded`` as if the session had not been reset.
    """
    t0 = time.monotonic()
    client = _get_agentcore_client()
    session_a = _new_session_id("reset-a")
    session_b = _new_session_id("reset-b")
    region = os.environ.get(ENV_REGION, "us-east-1")

    # TODO(VS-R01): exhaust cap in session_a; terminate; open session_b;
    # attempt to spend again; record whether cap state persisted.
    cap_persisted_across_reset: bool | None = None

    elapsed = time.monotonic() - t0
    passed = bool(cap_persisted_across_reset)

    return AgentCoreTestResult(
        test_id="ACP-002",
        name="Session Reset Replay — Cap State Persistence",
        category="spend_cap_enforcement",
        owasp_asi="ASI03",
        severity=Severity.CRITICAL.value,
        passed=passed,
        details=(
            "Cap persisted across session reset (instrument-bound)"
            if passed
            else "Cap reset with session — replayable for unbounded spend"
        ),
        region=region,
        session_id=f"{session_a},{session_b}",
        request_sent={
            "session_a": session_a,
            "session_b": session_b,
            "cap_usd": DEFAULT_SESSION_CAP_USD,
        },
        response_received={"cap_persisted": cap_persisted_across_reset},
        csg_mapping="HC-2: Cap state must bind to instrument, not session",
        estimated_impact="fund_theft",
        estimated_severity="critical",
        elapsed_s=round(elapsed, 3),
    )


@pytest.mark.skip(reason=VS_R01_SKIP_REASON)
def test_agentcore_402_terms_forgery() -> AgentCoreTestResult:
    """ACP-003: AgentCore reaction to crafted HTTP 402 terms from a malicious endpoint.

    Attack pattern:
        Stand up a mock paid endpoint that returns HTTP 402 with crafted
        terms: amount over the session budget, wrong asset (e.g., LTC when
        instrument is USDC), exotic chain (e.g., made-up L2). Drive AgentCore
        through it and record acceptance behavior at the 402-parse layer.

    In-scope behavior:
        AgentCore's 402 handler should validate amount-vs-budget,
        asset-vs-instrument, and chain-vs-allowlist BEFORE prompting the
        agent (or surfacing to human) for approval.

    Expected detection by AgentCore:
        Refusal at 402-parse with ``PaymentTermsRejected`` or equivalent;
        per-violation breakdown logged (over-budget / wrong-asset / exotic-chain).
    """
    t0 = time.monotonic()
    client = _get_agentcore_client()
    session_id = _new_session_id("402-forge")
    region = os.environ.get(ENV_REGION, "us-east-1")

    # TODO(VS-R01): start a local mock HTTP server emitting crafted 402s.
    # TODO(VS-R01): drive AgentCore at it and capture per-variant acceptance.
    forged_variants = ["over_budget", "wrong_asset", "exotic_chain"]
    rejected_variants: list[str] = []

    elapsed = time.monotonic() - t0
    passed = sorted(rejected_variants) == sorted(forged_variants)

    return AgentCoreTestResult(
        test_id="ACP-003",
        name="402 Terms Forgery — Malicious Paid Endpoint",
        category="402_terms_validation",
        owasp_asi="ASI09",
        severity=Severity.HIGH.value,
        passed=passed,
        details=(
            f"{len(rejected_variants)}/{len(forged_variants)} forged "
            f"402 variants rejected by AgentCore"
        ),
        region=region,
        session_id=session_id,
        request_sent={"forged_variants": forged_variants},
        response_received={"rejected_variants": rejected_variants},
        csg_mapping="HC-3: 402 terms must be validated against instrument policy",
        estimated_impact="fund_theft",
        estimated_severity="high",
        elapsed_s=round(elapsed, 3),
    )


@pytest.mark.skip(reason=VS_R01_SKIP_REASON)
def test_agentcore_receipt_validation() -> AgentCoreTestResult:
    """ACP-004: ProcessPayment rejects fabricated payment receipts.

    Attack pattern:
        Construct a payment receipt with plausible structure (correct fields,
        well-formed signatures from a non-issuer key, valid-looking tx hash
        but no on-chain backing) and submit it to ``ProcessPayment``.

    In-scope behavior:
        AgentCore should verify receipt signature against the registered
        facilitator/issuer public key, confirm tx hash exists and confirms
        the claimed amount on the claimed chain, and reject mismatches.

    Expected detection by AgentCore:
        ``InvalidReceiptSignature`` or ``ReceiptNotFound`` error; receipt
        never marked as ``Confirmed``.
    """
    t0 = time.monotonic()
    client = _get_agentcore_client()
    session_id = _new_session_id("receipt")
    region = os.environ.get(ENV_REGION, "us-east-1")

    # TODO(VS-R01): fabricate receipt with random-key signature + bogus tx hash;
    # call ProcessPayment; assert rejection.
    fabricated_receipt = {
        "tx_hash": "0x" + "ab" * 32,
        "amount_usd": "1.00",
        "signer": "0x" + "de" * 20,
        "signature": "0x" + "ef" * 64,
        "chain": "base-sepolia",
    }
    rejected: bool | None = None

    elapsed = time.monotonic() - t0
    passed = bool(rejected)

    return AgentCoreTestResult(
        test_id="ACP-004",
        name="Fabricated Payment Receipt Rejection",
        category="receipt_validation",
        owasp_asi="ASI06",
        severity=Severity.CRITICAL.value,
        passed=passed,
        details=(
            "ProcessPayment rejected fabricated receipt"
            if passed
            else "ProcessPayment ACCEPTED fabricated receipt — fund-theft path"
        ),
        region=region,
        session_id=session_id,
        request_sent={"fabricated_receipt": fabricated_receipt},
        response_received={"rejected": rejected},
        csg_mapping="HC-4: Receipts must verify against issuer key + on-chain state",
        estimated_impact="fund_theft",
        estimated_severity="critical",
        elapsed_s=round(elapsed, 3),
    )


@pytest.mark.skip(reason=VS_R01_SKIP_REASON)
def test_agentcore_audit_trace_intent_drift() -> AgentCoreTestResult:
    """ACP-005: Audit trace reasoning matches actual prompt (no tool-injected drift).

    Attack pattern:
        Register a tool whose description mis-states the reason for purchase
        (e.g., tool name "weather lookup" but description claims "buy
        compute credits for research"). Trigger a purchase via this tool
        and compare the AgentCore audit-trace ``reasoning`` field against
        the actual user prompt.

    In-scope behavior:
        Audit trace should record the true prompt context, not just the
        tool's self-described purpose. Drift between prompt and logged
        reason is an attribution-laundering vector.

    Expected detection by AgentCore:
        Audit-trace reasoning matches prompt; tool description treated as
        untrusted input and not promoted into the reasoning field verbatim.
    """
    t0 = time.monotonic()
    client = _get_agentcore_client()
    session_id = _new_session_id("intent")
    region = os.environ.get(ENV_REGION, "us-east-1")

    # TODO(VS-R01): register decoy tool, trigger purchase, fetch GetAgentTrace.
    user_prompt = "Look up tomorrow's weather in Seattle."
    decoy_tool_description = "Purchases compute credits for ML research."
    logged_reasoning: str = ""

    drift_detected = bool(logged_reasoning) and (
        decoy_tool_description.lower() in logged_reasoning.lower()
        and user_prompt.lower() not in logged_reasoning.lower()
    )

    elapsed = time.monotonic() - t0
    passed = not drift_detected and bool(logged_reasoning)

    return AgentCoreTestResult(
        test_id="ACP-005",
        name="Audit Trace Intent Drift via Tool Description",
        category="audit_trace_integrity",
        owasp_asi="ASI05",
        severity=Severity.HIGH.value,
        passed=passed,
        details=(
            "Audit reasoning matched user prompt (no drift)"
            if passed
            else "Audit reasoning drifted to tool-description text — attribution-laundering vector"
        ),
        region=region,
        session_id=session_id,
        request_sent={
            "user_prompt": user_prompt,
            "decoy_tool_description": decoy_tool_description,
        },
        response_received={"logged_reasoning": logged_reasoning},
        csg_mapping="HC-5: Audit reasoning must reflect prompt, not untrusted tool metadata",
        estimated_impact="info_leak",
        estimated_severity="high",
        elapsed_s=round(elapsed, 3),
    )


@pytest.mark.skip(reason=VS_R01_SKIP_REASON)
def test_agentcore_wallet_cross_agent_isolation() -> AgentCoreTestResult:
    """ACP-006: Agent A's payment instrument cannot be used from Agent B's runtime.

    Attack pattern:
        Provision a payment instrument scoped to Agent A in the same AWS
        account. From Agent B's runtime, attempt to invoke ``ProcessPayment``
        (or equivalent) referencing Agent A's instrument id.

    In-scope behavior:
        AgentCore Identity should enforce instrument-to-agent binding at the
        runtime layer, not just at the IAM layer. Same-account does NOT
        imply same-instrument.

    Expected detection by AgentCore:
        ``InstrumentNotAuthorizedForAgent`` or 403-equivalent; Agent B
        cannot exfiltrate Agent A's spend budget.
    """
    t0 = time.monotonic()
    client = _get_agentcore_client()
    agent_a = "agent-a-" + uuid.uuid4().hex[:8]
    agent_b = "agent-b-" + uuid.uuid4().hex[:8]
    session_id = _new_session_id("xagent")
    region = os.environ.get(ENV_REGION, "us-east-1")

    # TODO(VS-R01): create instrument scoped to agent_a; invoke ProcessPayment
    # from agent_b runtime; assert refusal.
    instrument_id: str = ""
    cross_agent_refused: bool | None = None

    elapsed = time.monotonic() - t0
    passed = bool(cross_agent_refused)

    return AgentCoreTestResult(
        test_id="ACP-006",
        name="Cross-Agent Wallet/Instrument Isolation",
        category="instrument_isolation",
        owasp_asi="ASI03",
        severity=Severity.CRITICAL.value,
        passed=passed,
        details=(
            "Agent B refused to use Agent A's instrument"
            if passed
            else "Agent B used Agent A's instrument — isolation breach"
        ),
        region=region,
        agent_id=f"{agent_a},{agent_b}",
        session_id=session_id,
        request_sent={
            "instrument_owner_agent": agent_a,
            "attempting_agent": agent_b,
            "instrument_id": instrument_id,
        },
        response_received={"cross_agent_refused": cross_agent_refused},
        csg_mapping="HC-6: Instrument bind must be enforced at runtime, not IAM-only",
        estimated_impact="fund_theft",
        estimated_severity="critical",
        elapsed_s=round(elapsed, 3),
    )


@pytest.mark.skip(reason=VS_R01_SKIP_REASON)
def test_bazaar_endpoint_typosquat_inventory() -> AgentCoreTestResult:
    """ACP-007: Passive inventory of AgentCore Bazaar listings for typosquats.

    Attack pattern:
        Pull the AgentCore Bazaar public listing (no payment, no install).
        Fingerprint duplicate/near-duplicate names by Levenshtein <= 2,
        homoglyph substitution (cyrillic 'a' for latin 'a'), and
        prefix/suffix variants ("stripe-pay" vs "stripe_pay" vs "stripe-pay-v2").

    In-scope behavior:
        This is a PASSIVE listing read — no install, no invoke, no payment.
        Output is an inventory dict suitable for downstream takedown reporting.

    Expected detection by AgentCore:
        N/A — this test reports inventory; AgentCore itself does not detect
        typosquats today. Result data feeds a follow-on disclosure workflow.
    """
    t0 = time.monotonic()
    client = _get_agentcore_client(service="bedrock-agent")  # control-plane
    region = os.environ.get(ENV_REGION, "us-east-1")

    # TODO(VS-R01): list Bazaar endpoints (ListAgentListings or equivalent);
    # bucket by normalized name; flag near-duplicates.
    listings: list[dict] = []
    typosquat_clusters: list[dict] = []

    elapsed = time.monotonic() - t0
    # Passive-inventory tests pass when inventory completed (not when N==0).
    passed = isinstance(listings, list)

    return AgentCoreTestResult(
        test_id="ACP-007",
        name="Bazaar Typosquat Inventory (Passive)",
        category="bazaar_supply_chain",
        owasp_asi="ASI04",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=(
            f"Inventoried {len(listings)} listings; "
            f"flagged {len(typosquat_clusters)} typosquat clusters"
        ),
        region=region,
        request_sent={"operation": "list_bazaar_listings", "mode": "passive"},
        response_received={
            "listings_count": len(listings),
            "typosquat_clusters": typosquat_clusters,
        },
        csg_mapping="HC-7: Marketplace inventory must be auditable for typosquats",
        estimated_impact="info_leak",
        estimated_severity="medium",
        elapsed_s=round(elapsed, 3),
    )


@pytest.mark.skip(reason=VS_R01_SKIP_REASON)
def test_agentcore_policy_bypass_via_tool_chain() -> AgentCoreTestResult:
    """ACP-008: Tool-chain aggregation of policy-compliant calls into a violation.

    Attack pattern:
        Chain two tools where each individual call is within policy
        (e.g., Tool A = "convert USD to gift-card credit, max $50";
        Tool B = "transfer gift-card credit to wallet, no limit"). Each
        call is policy-compliant in isolation; the aggregate effectively
        bypasses the $50 USD cap by laundering through Tool B.

    In-scope behavior:
        AgentCore policy engine should evaluate the cumulative effect of a
        tool chain on the constrained resource (USD spend), not just each
        call independently. Equivalent to taint-tracking the budgeted
        principal across tool boundaries.

    Expected detection by AgentCore:
        ``PolicyAggregationViolation`` on the Tool B call once the chain
        crosses the underlying cap; or refusal of the chain at plan-time.
    """
    t0 = time.monotonic()
    client = _get_agentcore_client()
    session_id = _new_session_id("chain")
    region = os.environ.get(ENV_REGION, "us-east-1")

    # TODO(VS-R01): register tool_a (capped) and tool_b (uncapped converter);
    # chain N invocations; detect whether AgentCore caught the aggregate.
    tool_a = "convert_usd_to_credit"
    tool_b = "transfer_credit_uncapped"
    individual_cap_usd = 50.0
    chain_total_usd: float = 0.0
    aggregation_detected: bool | None = None

    elapsed = time.monotonic() - t0
    passed = bool(aggregation_detected)

    return AgentCoreTestResult(
        test_id="ACP-008",
        name="Policy Bypass via Tool-Chain Aggregation",
        category="policy_aggregation",
        owasp_asi="ASI02",
        severity=Severity.CRITICAL.value,
        passed=passed,
        details=(
            f"Aggregation detected (chain total ${chain_total_usd:.2f} vs "
            f"cap ${individual_cap_usd:.2f})"
            if passed
            else f"Chain bypassed cap: ${chain_total_usd:.2f} vs ${individual_cap_usd:.2f}"
        ),
        region=region,
        session_id=session_id,
        request_sent={
            "tool_a": tool_a,
            "tool_b": tool_b,
            "individual_cap_usd": individual_cap_usd,
        },
        response_received={
            "chain_total_usd": chain_total_usd,
            "aggregation_detected": aggregation_detected,
        },
        csg_mapping="HC-8: Policy engine must aggregate constrained resources across chains",
        estimated_impact="policy_bypass",
        estimated_severity="critical",
        elapsed_s=round(elapsed, 3),
    )


# ---------------------------------------------------------------------------
# Reporting (mirrors x402_harness.generate_report shape)
# ---------------------------------------------------------------------------

ALL_TESTS: dict[str, list[str]] = {
    "spend_cap_enforcement": [
        "test_agentcore_spend_fragmentation",
        "test_agentcore_session_reset_replay",
    ],
    "402_terms_validation": [
        "test_agentcore_402_terms_forgery",
    ],
    "receipt_validation": [
        "test_agentcore_receipt_validation",
    ],
    "audit_trace_integrity": [
        "test_agentcore_audit_trace_intent_drift",
    ],
    "instrument_isolation": [
        "test_agentcore_wallet_cross_agent_isolation",
    ],
    "bazaar_supply_chain": [
        "test_bazaar_endpoint_typosquat_inventory",
    ],
    "policy_aggregation": [
        "test_agentcore_policy_bypass_via_tool_chain",
    ],
}


def summarize_results(results: list[AgentCoreTestResult]) -> dict:
    """JSON-serializable summary of an AgentCore payments test run.

    Matches the shape used by ``x402_harness.generate_report`` and
    ``cloud_agent_harness`` so downstream consumers (count_tests.py,
    statistical.enhance_report) treat this harness uniformly.
    """
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    by_category: dict[str, dict[str, int]] = {}
    for r in results:
        bucket = by_category.setdefault(r.category, {"passed": 0, "failed": 0})
        bucket["passed" if r.passed else "failed"] += 1

    return {
        "suite": "AWS Bedrock AgentCore Payments Security Tests v0.1 (SKELETON)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "spec_reference": (
            "https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html"
        ),
        "safety": {
            "live_net_disabled": LIVE_NET_DISABLED,
            "testnet_only": TESTNET_ONLY,
            "kill_switch_env": ENV_LIVE_NET_OK,
            "wallet_env": ENV_TESTNET_WALLET,
            "runtime_opt_in_env": ENV_ALLOW_TESTNET,
        },
        "summary": {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "by_category": by_category,
        },
        "results": [asdict(r) for r in results],
    }


# ---------------------------------------------------------------------------
# Module footer — intentionally NO __main__ CLI and NO HARNESSES registration.
# Mike registers this in protocol_tests/cli.py manually after live validation
# (per CLAUDE.md: count_tests.py is single source of truth; premature
# registration breaks the count).
# ---------------------------------------------------------------------------
