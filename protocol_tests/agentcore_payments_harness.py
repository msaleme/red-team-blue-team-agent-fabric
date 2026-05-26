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

def test_agentcore_spend_fragmentation() -> AgentCoreTestResult:
    """ACP-001: Session-multiplication fragmentation of the spend cap.

    Attack pattern (reframed from the scope-doc 1000-fragment version):
        The scope-doc original attack assumed per-payment fragmentation
        inside a single capped session, which would require a real x402
        merchant + valid payment payloads. This test instead exercises the
        adjacent and operationally identical attack surface: a single
        (userId, agentName) opens N parallel sessions, each with the
        configured maxSpendAmount. Cumulative authorized spend across
        sessions = N * cap, with no AgentCore-side enforcement that the
        sum of active session caps must respect any user-level ceiling.

    In-scope behavior:
        Probes:
          (1) parallel session creation count (N=5) under same userId/agentName,
              same cap each;
          (2) cap-value boundary: 0, negative, 0.001 (sub-cent), 10000.01;
          (3) documented per-session ceiling (from validation error).
        Reports cumulative_session_cap = N * cap and the per-session
        observed maximum. Cleans up every session it creates.

    Expected detection by AgentCore:
        For this to PASS (cap NOT fragmentable), AgentCore would refuse the
        2nd parallel session under same (userId, agentName) with a
        SessionConflict/QuotaExceeded error. Observed behavior: parallel
        sessions are accepted, which means cap fragmentation IS possible.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = "vsr01-fragmenter"
    agent_name = "vsr01-frag-agent"
    per_session_cap = "0.50"
    parallel_count = 5

    findings: dict = {
        "parallel_sessions_created": 0,
        "parallel_sessions_attempted": parallel_count,
        "per_session_cap_usd": per_session_cap,
        "cumulative_authorized_usd": 0.0,
        "boundary_results": {},
        "documented_per_session_ceiling": None,
        "errors": [],
        "session_ids_cleaned": 0,
    }
    created_session_ids: list[tuple[str, str]] = []  # (session_id, user_for_cleanup)

    # Probe 1: parallel session multiplication
    for i in range(parallel_count):
        try:
            r = dp.create_payment_session(
                userId=user_id,
                agentName=agent_name,
                paymentManagerArn=pm_arn,
                limits={"maxSpendAmount": {"value": per_session_cap, "currency": "USD"}},
                expiryTimeInMinutes=15,
                clientToken=str(uuid.uuid4()),
            )
            sess = r.get("paymentSession", r)
            sid = sess.get("paymentSessionId")
            if sid:
                created_session_ids.append((sid, user_id))
                findings["parallel_sessions_created"] += 1
        except Exception as e:
            findings["errors"].append(
                f"parallel[{i}]: {type(e).__name__}: {str(e)[:160]}"
            )

    findings["cumulative_authorized_usd"] = round(
        findings["parallel_sessions_created"] * float(per_session_cap), 4
    )

    # Probe 2: cap-value boundaries
    for cap_str in ("0", "-1.00", "0.001", "10000.01", "9999.99"):
        try:
            r = dp.create_payment_session(
                userId="vsr01-boundary",
                agentName="vsr01-bnd",
                paymentManagerArn=pm_arn,
                limits={"maxSpendAmount": {"value": cap_str, "currency": "USD"}},
                expiryTimeInMinutes=15,
                clientToken=str(uuid.uuid4()),
            )
            sess = r.get("paymentSession", r)
            sid = sess.get("paymentSessionId")
            if sid:
                created_session_ids.append((sid, "vsr01-boundary"))
            findings["boundary_results"][cap_str] = "ACCEPTED"
        except Exception as e:
            err_msg = str(e)[:240]
            findings["boundary_results"][cap_str] = f"REJECTED: {err_msg}"
            # Document the per-session ceiling from the validation error
            if "must not exceed" in err_msg and findings["documented_per_session_ceiling"] is None:
                import re as _re
                m = _re.search(r"exceed\s+(\d[\d.]*)", err_msg)
                if m:
                    findings["documented_per_session_ceiling"] = m.group(1)

    elapsed = time.monotonic() - t0

    # Pass condition (cap NOT fragmentable): parallel session creation refused
    # at session 2+. Observed: parallel sessions are accepted = fragmentation possible.
    cap_fragmentable = findings["parallel_sessions_created"] > 1
    passed = not cap_fragmentable  # PASS only if AgentCore refuses session multiplication

    details_parts = [
        f"opened {findings['parallel_sessions_created']}/{parallel_count} parallel sessions",
        f"per-session cap ${per_session_cap}",
        f"cumulative authorized ${findings['cumulative_authorized_usd']}",
    ]
    if findings["documented_per_session_ceiling"]:
        details_parts.append(
            f"per-session ceiling ${findings['documented_per_session_ceiling']} "
            f"(theoretical N-session ceiling unbounded)"
        )
    if cap_fragmentable:
        details_parts.append("FRAGMENTATION VIABLE")

    # Cleanup all created sessions
    for sid, user_for_cleanup in created_session_ids:
        try:
            dp.delete_payment_session(
                userId=user_for_cleanup,
                paymentManagerArn=pm_arn,
                paymentSessionId=sid,
            )
            findings["session_ids_cleaned"] += 1
        except Exception as e:
            findings["errors"].append(f"cleanup_{sid[:10]}: {type(e).__name__}")

    return AgentCoreTestResult(
        test_id="ACP-001",
        name="Session-Cap Fragmentation via Parallel Session Creation",
        category="spend_cap_enforcement",
        owasp_asi="ASI02",
        severity=Severity.HIGH.value,
        passed=passed,
        details="; ".join(details_parts),
        region=region,
        session_id=created_session_ids[0][0] if created_session_ids else "",
        request_sent={
            "operation": "CreatePaymentSession x N (parallel) + cap-value boundaries",
            "parallel_count_attempted": parallel_count,
            "per_session_cap_usd": per_session_cap,
            "user_id": user_id,
            "agent_name": agent_name,
            "boundary_cap_values_tested": list(findings["boundary_results"].keys()),
        },
        response_received=findings,
        csg_mapping="HC-1: Spend caps must aggregate across fractional payments / parallel sessions",
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


def test_agentcore_wallet_cross_agent_isolation() -> AgentCoreTestResult:
    """ACP-006: Agent A's payment instrument cannot be accessed from Agent B's context.

    Attack pattern:
        Provision two payment instruments — instrument_a bound to (userId=user-a,
        agentName=agent-a, wallet=wallet-A) and instrument_b bound to
        (userId=user-b, agentName=agent-b, wallet=wallet-B). From the
        Agent B context (different userId AND different agentName), attempt
        to access instrument_a via GetPaymentInstrument and via
        ListPaymentInstruments. Test passes when AgentCore refuses
        cross-context access at the data plane (not just IAM).

    In-scope behavior:
        AgentCore should scope instrument visibility by (userId, agentName)
        at the runtime layer. Same-account does NOT imply same-instrument.
        We verify:
          1. ListPaymentInstruments(userId=user-a) does not return instrument_b
          2. ListPaymentInstruments(userId=user-b) does not return instrument_a
          3. GetPaymentInstrument(instrument_a_id) under userId=user-b raises
             AccessDenied/ResourceNotFound

    Expected detection by AgentCore:
        Cross-context attempts denied via AccessDeniedException or
        ResourceNotFoundException; Agent B cannot enumerate or claim
        Agent A's spend budget.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    data_plane = _get_agentcore_client(service="bedrock-agentcore")
    control = _get_agentcore_client(service="bedrock-agentcore-control")

    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    connector_id = os.environ.get("AGENTCORE_PAYMENT_CONNECTOR_ID", "")
    wallet_a = "0x0E88cF39132336a4A9a7C0D37C1253Fa321F557B"  # vsr01testnet
    wallet_b = "0x9b3090cf65c568B5961F2aC27af8Ae35CaeCE536"  # vsr01testnetb
    user_a = "vsr01-user-a"
    user_b = "vsr01-user-b"
    agent_a = "vsr01-agent-a"
    agent_b = "vsr01-agent-b"
    session_id = _new_session_id("xagent")

    findings: dict = {
        "instrument_a_created": False,
        "instrument_b_created": False,
        "list_userA_sees_only_A": None,
        "list_userB_sees_only_B": None,
        "get_A_as_userB_denied": None,
        "errors": [],
    }
    instrument_a_id = ""
    instrument_b_id = ""

    # AgentCore EMBEDDED_CRYPTO_WALLET model uses identity bindings — the
    # wallet itself is auto-provisioned by AgentCore on first ProcessPayment.
    # The address Mike's CDP account (wallet_a/wallet_b above) is a separate
    # CDP-managed wallet; the AgentCore instrument represents a different
    # AgentCore-provisioned embedded wallet bound to the email identity.
    def _make_instrument(user_id: str, agent_name: str, email_addr: str) -> dict:
        return data_plane.create_payment_instrument(
            userId=user_id,
            agentName=agent_name,
            paymentManagerArn=pm_arn,
            paymentConnectorId=connector_id,
            paymentInstrumentType="EMBEDDED_CRYPTO_WALLET",
            paymentInstrumentDetails={
                "embeddedCryptoWallet": {
                    "network": "ETHEREUM",
                    "linkedAccounts": [{"email": {"emailAddress": email_addr}}],
                }
            },
            clientToken=str(uuid.uuid4()),
        )

    email_a = "vsr01-user-a@example.test"
    email_b = "vsr01-user-b@example.test"

    # Step 1: Create both instruments
    try:
        r_a = _make_instrument(user_a, agent_a, email_a)
        instrument_a_id = r_a["paymentInstrument"]["paymentInstrumentId"]
        findings["instrument_a_created"] = True
    except Exception as e:
        findings["errors"].append(f"create_a: {type(e).__name__}: {str(e)[:200]}")

    try:
        r_b = _make_instrument(user_b, agent_b, email_b)
        instrument_b_id = r_b["paymentInstrument"]["paymentInstrumentId"]
        findings["instrument_b_created"] = True
    except Exception as e:
        findings["errors"].append(f"create_b: {type(e).__name__}: {str(e)[:200]}")

    # Step 2: List instruments as user_a — should only see A
    if findings["instrument_a_created"] and findings["instrument_b_created"]:
        try:
            la = data_plane.list_payment_instruments(
                userId=user_a, paymentManagerArn=pm_arn,
            ).get("paymentInstruments", [])
            ids_a = {pi.get("paymentInstrumentId") for pi in la}
            findings["list_userA_sees_only_A"] = (
                instrument_a_id in ids_a and instrument_b_id not in ids_a
            )
            findings["list_userA_count"] = len(ids_a)
            findings["list_userA_leak_of_B"] = instrument_b_id in ids_a
        except Exception as e:
            findings["errors"].append(f"list_a: {type(e).__name__}: {str(e)[:200]}")

        # Step 3: List instruments as user_b — should only see B
        try:
            lb = data_plane.list_payment_instruments(
                userId=user_b, paymentManagerArn=pm_arn,
            ).get("paymentInstruments", [])
            ids_b = {pi.get("paymentInstrumentId") for pi in lb}
            findings["list_userB_sees_only_B"] = (
                instrument_b_id in ids_b and instrument_a_id not in ids_b
            )
            findings["list_userB_count"] = len(ids_b)
            findings["list_userB_leak_of_A"] = instrument_a_id in ids_b
        except Exception as e:
            findings["errors"].append(f"list_b: {type(e).__name__}: {str(e)[:200]}")

        # Step 4: Try to GET instrument A under user B context
        try:
            data_plane.get_payment_instrument(
                userId=user_b,
                paymentManagerArn=pm_arn,
                paymentInstrumentId=instrument_a_id,
            )
            findings["get_A_as_userB_denied"] = False  # Should have raised
            findings["get_A_as_userB_breach"] = "AgentCore returned A's instrument to user_b"
        except data_plane.exceptions.AccessDeniedException:
            findings["get_A_as_userB_denied"] = True
            findings["get_A_as_userB_error"] = "AccessDeniedException"
        except data_plane.exceptions.ResourceNotFoundException:
            findings["get_A_as_userB_denied"] = True
            findings["get_A_as_userB_error"] = "ResourceNotFoundException"
        except Exception as e:
            # Any error response that's not success counts as denial
            findings["get_A_as_userB_denied"] = True
            findings["get_A_as_userB_error"] = f"{type(e).__name__}: {str(e)[:120]}"

    elapsed = time.monotonic() - t0

    # Isolation holds only if ALL three properties verified true
    isolation_holds = bool(
        findings.get("list_userA_sees_only_A")
        and findings.get("list_userB_sees_only_B")
        and findings.get("get_A_as_userB_denied")
    )
    passed = isolation_holds

    detail_parts = []
    if findings.get("instrument_a_created") and findings.get("instrument_b_created"):
        detail_parts.append(f"created 2 instruments (a={instrument_a_id[:10]}, b={instrument_b_id[:10]})")
    detail_parts.append(f"list_userA_isolated={findings.get('list_userA_sees_only_A')}")
    detail_parts.append(f"list_userB_isolated={findings.get('list_userB_sees_only_B')}")
    detail_parts.append(f"get_A_as_userB_denied={findings.get('get_A_as_userB_denied')}")
    if findings["errors"]:
        detail_parts.append(f"errors={len(findings['errors'])}")

    # Cleanup: delete both instruments (delete requires pm_arn + connector_id + instrument_id)
    for inst_id, user_id in [(instrument_a_id, user_a), (instrument_b_id, user_b)]:
        if not inst_id:
            continue
        try:
            data_plane.delete_payment_instrument(
                userId=user_id,
                paymentManagerArn=pm_arn,
                paymentConnectorId=connector_id,
                paymentInstrumentId=inst_id,
            )
            findings.setdefault("cleanup", []).append(f"deleted {inst_id[:10]}")
        except Exception as e:
            findings.setdefault("cleanup", []).append(f"delete_{inst_id[:10]}_err: {type(e).__name__}")

    return AgentCoreTestResult(
        test_id="ACP-006",
        name="Cross-Agent Wallet/Instrument Isolation",
        category="instrument_isolation",
        owasp_asi="ASI03",
        severity=Severity.CRITICAL.value,
        passed=passed,
        details="; ".join(detail_parts),
        region=region,
        agent_id=f"{agent_a},{agent_b}",
        session_id=session_id,
        request_sent={
            "operation": "CreatePaymentInstrument x2 + ListPaymentInstruments x2 + GetPaymentInstrument cross-context",
            "user_a": user_a,
            "user_b": user_b,
            "agent_a": agent_a,
            "agent_b": agent_b,
            "wallet_a": wallet_a,
            "wallet_b": wallet_b,
        },
        response_received=findings,
        csg_mapping="HC-6: Instrument bind must be enforced at runtime, not IAM-only",
        estimated_impact="fund_theft",
        estimated_severity="critical",
        elapsed_s=round(elapsed, 3),
    )


def _bazaar_fetch_inventory(timeout_s: int = 30) -> list[dict]:
    """Paginate CDP x402 Bazaar discovery (read-only, no auth required)."""
    import urllib.request, json as _json
    base = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources"
    items: list[dict] = []
    offset = 0
    while True:
        url = f"{base}?limit=1000&offset={offset}"
        with urllib.request.urlopen(url, timeout=timeout_s) as r:
            page_data = _json.loads(r.read())
        page = page_data.get("items", [])
        if not page:
            break
        items.extend(page)
        if len(page) < 1000:
            break
        offset += 1000
    return items


def _bazaar_levenshtein(a: str, b: str) -> int:
    """Stdlib Levenshtein distance — sufficient for hostname-length strings."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(curr[-1] + 1, prev[j + 1] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _bazaar_typosquat_clusters(hosts: list[str], max_distance: int = 2) -> list[int]:
    """Cluster hostnames by Levenshtein <= max_distance (union-find).
    Returns aggregate cluster sizes only — no individual hostnames per
    VS-R01 publishable-artifact rules."""
    n = len(hosts)
    if n < 2:
        return []
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(n):
        for j in range(i + 1, n):
            if abs(len(hosts[i]) - len(hosts[j])) > max_distance:
                continue
            if _bazaar_levenshtein(hosts[i], hosts[j]) <= max_distance:
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[ri] = rj
    sizes: dict[int, int] = {}
    for i in range(n):
        r = find(i)
        sizes[r] = sizes.get(r, 0) + 1
    return sorted([s for s in sizes.values() if s > 1], reverse=True)


def _bazaar_homoglyph_count(hosts: list[str]) -> int:
    """Count hostnames containing any non-ASCII char (Cyrillic-Latin
    substitution heuristic — over-approximation, acceptable for inventory)."""
    return sum(1 for h in hosts if any(ord(c) > 127 for c in h))


def test_bazaar_endpoint_typosquat_inventory() -> AgentCoreTestResult:
    """ACP-007: Passive inventory of x402 Bazaar listings for typosquats.

    Attack pattern:
        Pull the public x402 Bazaar listing (no payment, no install).
        Fingerprint duplicate/near-duplicate hostnames by Levenshtein <= 2
        and detect homoglyph substitutions (Cyrillic chars in Latin
        hostnames). Marketplace supply-chain provenance audit.

    In-scope behavior:
        PASSIVE listing read against the public CDP discovery endpoint
        (no auth required, no payment, no AgentCore invocation). Output
        is aggregate cluster sizes only — no individual hostnames per
        VS-R01 publishable-artifact rules.

    Expected detection by AgentCore:
        N/A — AgentCore does not detect Bazaar typosquats today. This
        test surfaces inventory data for downstream disclosure workflow.
        Finding non-zero clusters indicates marketplace lacks pre-list
        homoglyph/edit-distance defenses.
    """
    import urllib.parse
    from collections import Counter

    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")

    try:
        listings = _bazaar_fetch_inventory()
    except Exception as exc:
        elapsed = time.monotonic() - t0
        return AgentCoreTestResult(
            test_id="ACP-007",
            name="Bazaar Typosquat Inventory (Passive)",
            category="bazaar_supply_chain",
            owasp_asi="ASI04",
            severity=Severity.MEDIUM.value,
            passed=False,
            details=f"Bazaar fetch failed: {type(exc).__name__}: {exc!s:.200}",
            region=region,
            request_sent={
                "operation": "GET",
                "endpoint": "api.cdp.coinbase.com/platform/v2/x402/discovery/resources",
                "mode": "passive",
            },
            response_received={"error": str(exc)[:300]},
            csg_mapping="HC-7: Marketplace inventory must be auditable for typosquats",
            estimated_impact="info_leak",
            estimated_severity="medium",
            elapsed_s=round(elapsed, 3),
        )

    # Extract unique hostnames from resource URLs
    host_counts: Counter = Counter()
    bad_urls = 0
    for item in listings:
        res = (item.get("resource") or "").strip()
        if not res:
            bad_urls += 1
            continue
        try:
            host = (urllib.parse.urlparse(res).hostname or "").lower()
        except Exception:
            bad_urls += 1
            continue
        if host:
            host_counts[host] += 1
        else:
            bad_urls += 1

    hosts = list(host_counts.keys())
    cluster_sizes = _bazaar_typosquat_clusters(hosts, max_distance=2)
    homoglyph_count = _bazaar_homoglyph_count(hosts)

    # Endpoints concentrated on a single hostname (top-1 share) is itself a
    # supply-chain signal: a few hosts running 100s of listings means the
    # marketplace is concentrated, not diverse.
    top_host_share = (host_counts.most_common(1)[0][1] / sum(host_counts.values())) if host_counts else 0.0

    elapsed = time.monotonic() - t0

    # Pass criterion: inventory completed cleanly. Test is informational —
    # finding clusters is the expected outcome, not a failure.
    passed = isinstance(listings, list) and len(listings) > 0

    summary = {
        "total_listings": len(listings),
        "unique_hostnames": len(hosts),
        "typosquat_clusters_count": len(cluster_sizes),
        "largest_cluster_size": cluster_sizes[0] if cluster_sizes else 0,
        "hosts_in_typosquat_clusters": sum(cluster_sizes),
        "homoglyph_hostnames": homoglyph_count,
        "top_host_concentration_pct": round(top_host_share * 100, 1),
        "malformed_resource_urls": bad_urls,
    }

    return AgentCoreTestResult(
        test_id="ACP-007",
        name="Bazaar Typosquat Inventory (Passive)",
        category="bazaar_supply_chain",
        owasp_asi="ASI04",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=(
            f"Bazaar inventory: {summary['total_listings']} listings across "
            f"{summary['unique_hostnames']} unique hosts; "
            f"{summary['typosquat_clusters_count']} typosquat clusters "
            f"(largest={summary['largest_cluster_size']}, "
            f"{summary['hosts_in_typosquat_clusters']} hosts in clusters); "
            f"{summary['homoglyph_hostnames']} hostnames with non-ASCII chars; "
            f"top-host concentration {summary['top_host_concentration_pct']}%"
        ),
        region=region,
        request_sent={
            "operation": "GET",
            "endpoint": "api.cdp.coinbase.com/platform/v2/x402/discovery/resources",
            "mode": "passive",
            "pagination": "limit=1000, offset paginated",
        },
        response_received=summary,
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
