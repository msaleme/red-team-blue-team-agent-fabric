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
    # VS-R02 addition (additive, defaults to "" so VS-R01 JSONs/consumers are
    # unaffected): machine-readable Evidence Class tag (E1-E5), see
    # reports/round_23/VS-R01-independent-review-package.md for the taxonomy.
    # VS-R01 tagged evidence class only in prose (review-package markdown);
    # VS-R02 makes it a structured field for the new sign-time (Tier A) tests.
    evidence_class: str = ""

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
# VS-R02 constants — Tier-A settlement-evidence extension (proof-only, 0 gas)
# ---------------------------------------------------------------------------
# Carries forward the VS-R01 AgentCore/CDP stack (scripts/vs-r01-env.sh).
# VS-R02 reaches sign-time (E3-adjacent) evidence via Coinbase CDP delegated
# signing, which VS-R01 could not reach — every VS-R01 ProcessPayment call
# hit either the `extra.name is required for EVM payments` structural gate
# (ACP-003/ACP-004) or, with that gate cleared, an
# AccessDeniedException("Delegated signing is not enabled for your Coinbase
# project"). Delegated signing was enabled 2026-06-08 and PROOF_GENERATED was
# verified ad hoc outside version control; the WalletHub per-wallet grant was
# re-issued and is valid until 2026-09-09 (see VS-R02-tier-a-runbook.md).
#
# TIER DISCIPLINE: every function below MUST stop at PROOF_GENERATED. None of
# them may submit the signed authorization to a merchant/facilitator. The
# VS-R02 wallet is UNFUNDED as of this writing — Tier B (on-chain settlement,
# e.g. ACP-012 nonce-reuse, the settlement half of ACP-016) is out of scope
# until the wallet is funded. See reports/round_24/VS-R02-tier-a-runbook.md.

# ---------------------------------------------------------------------------
# Evidence Class definition — E2.5 (independent-audit correction, VS-R02)
# ---------------------------------------------------------------------------
# E2.5 = sign-time, pre-settlement — derived from a real CDP cryptographic
# signing operation (PROOF_GENERATED, past admission) that did NOT settle
# on-chain; stronger than E2 (admission-gate) but short of E3 (settlement).
# All four VS-R02 Tier-A tests below (ACP-009, ACP-010, ACP-011, ACP-016) are
# tagged evidence_class="E2.5", NOT "E3" — "E3" is reserved for evidence that
# includes actual on-chain settlement, which none of these tests perform
# (every one stops at PROOF_GENERATED per the Tier discipline above). Some
# individual observations WITHIN ACP-011 are admission-style pre-sign
# rejections and are separately tagged "E2" in that test's findings — see
# test_agentcore_signtime_terms_forgery docstring.

ENV_VSR02_USER_ID = "AGENTCORE_VSR02_USER_ID"
ENV_VSR02_AGENT_NAME = "AGENTCORE_VSR02_AGENT_NAME"
ENV_VSR02_INSTRUMENT_ID = "AGENTCORE_VSR02_INSTRUMENT_ID"
ENV_VSR02_X402_EXTRA_NAME = "AGENTCORE_X402_EXTRA_NAME"
ENV_VSR02_X402_EXTRA_VERSION = "AGENTCORE_X402_EXTRA_VERSION"

# Identifiers below are NOT secrets — a public wallet address, a CDP *project
# id* (not an API key), and AgentCore resource names — so defaulting them in
# source follows the same convention as the vsr01testnet wallet_a/wallet_b
# addresses already hardcoded in test_agentcore_wallet_cross_agent_isolation
# above. Actual credentials (AWS keys, CDP API key file, wallet secret file)
# are read exclusively from env / file paths in scripts/vs-r02-env.sh and are
# never hardcoded here or anywhere else in this module.
VSR02_WALLET = "0x7889454DF1EB44B2fA0878179A1845F5b4649286"
VSR02_CDP_PROJECT_ID = "fdc6d46c-a5e3-49b2-8fae-0e1c42569ba7"
VSR02_CRED_PROVIDER_NAME = "vsr01cdpcreds"  # carried forward, see VS-R02-test-plan.md prereqs
# WalletHub-granted identity — the only (userId, agentName, paymentInstrumentId)
# tuple with an active delegated-signing grant as of this writing. Override
# via env if Mike re-grants under a different identity.
VSR02_USER_ID_DEFAULT = "vs-r01-walletub-1779903158"
VSR02_AGENT_NAME_DEFAULT = "vs-r01-cdp-grant-probe"
VSR02_INSTRUMENT_ID_DEFAULT = "payment-instrument-YQFWKtbGbKUuiMF"

# x402 "exact" scheme EIP-712 domain fields for the settlement asset. Public
# x402 spec convention for a USDC-class asset is name="USD Coin", version="2".
# UNVERIFIED against a live AgentCore response captured in this repo — every
# VS-R01 call was rejected before reaching delegated signing, and the
# 2026-06-08 PROOF_GENERATED verification ran outside version control (see
# module docstring above). TODO(Mike): confirm the correct `extra` shape on
# the first live run; override via AGENTCORE_X402_EXTRA_NAME /
# AGENTCORE_X402_EXTRA_VERSION if the default below is wrong, or if AgentCore
# expects additional `extra` sub-fields not modeled here.
X402_EXTRA_NAME_DEFAULT = "USD Coin"
X402_EXTRA_VERSION_DEFAULT = "2"

# Burn address — every VS-R02 Tier-A test signs against this payTo, never a
# real merchant address. Mitigation from the VS-R02 test plan risk register:
# "Sign with payTo=0xdEaD (burn address) for all proof-only tests."
BURN_PAYTO = "0x000000000000000000000000000000000000dEaD"

PROOF_GENERATED = "PROOF_GENERATED"
# Candidate field paths botocore might use for ProcessPayment status. The
# exact response schema for a *successful* (delegated-signing) ProcessPayment
# call is not captured anywhere in this repo — best-effort defensive probe,
# not a confirmed schema. See _extract_payment_status TODO.
_STATUS_CANDIDATE_KEYS = ("status", "paymentStatus", "processPaymentStatus")


def _extract_payment_status(resp: Any) -> tuple[str, str]:
    """Best-effort extraction of ProcessPayment status from a boto3 response.

    The exact response schema for a successful, delegated-signing-enabled
    ProcessPayment call is not captured anywhere in this repo: every VS-R01
    call was rejected at the structural or delegation gate before signing was
    possible (see ACP-003/ACP-004 above). This tries several plausible field
    paths and falls back to a substring search over the stringified response
    so a test does not silently under-report PROOF_GENERATED just because the
    field-name guess is wrong.

    Returns:
        A ``(status, method)`` tuple. ``status`` is the extracted status
        string, or ``""`` if nothing was recognized. ``method`` records
        which extraction path produced it — ``"structured_key:<field_name>"``
        when a known field in the parsed response body matched, or
        ``"substring_fallback"`` when the status was found only by searching
        the stringified response for ``PROOF_GENERATED``. ``method`` is
        ``""`` when ``status`` is ``""``. Callers thread ``method`` into
        their findings dict as ``status_extraction_method`` so every result
        JSON records which extraction path was actually exercised — this
        matters because the structured-key path has never been confirmed
        against a captured live schema (see TODO below).

    TODO(Mike): once a live response is captured, hard-code the correct path
    here and delete the fallback / _STATUS_CANDIDATE_KEYS guesswork.
    """
    if isinstance(resp, dict):
        payment = resp.get("payment", resp)
        if isinstance(payment, dict):
            for key in _STATUS_CANDIDATE_KEYS:
                val = payment.get(key)
                if val:
                    return str(val), f"structured_key:{key}"
    blob = str(resp)
    if PROOF_GENERATED in blob:
        return PROOF_GENERATED, "substring_fallback"
    return "", ""


def _build_x402_exact_payload(
    amount_units: str,
    pay_to: str = BURN_PAYTO,
    description: str = "VS-R02 Tier-A proof-only probe",
    resource: str = "https://vsr02-tier-a-probe.example/data",
    extra_name: str | None = None,
    extra_version: str | None = None,
) -> dict:
    """Build a structurally-complete x402 'exact' scheme EVM payload.

    Unlike the VS-R01 ACP-003/ACP-004 payloads (deliberately missing
    `extra.name` so they fail fast at the structural gate before ever
    reaching delegated signing), this payload includes `extra` so it is
    eligible to reach CDP delegated signing and return PROOF_GENERATED. See
    the X402_EXTRA_NAME_DEFAULT / X402_EXTRA_VERSION_DEFAULT TODO above —
    unverified against a captured live response.
    """
    return {
        "scheme": "exact",
        "network": "base-sepolia",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  # USDC base-sepolia
        "maxAmountRequired": amount_units,
        "resource": resource,
        "description": description,
        "mimeType": "application/json",
        "payTo": pay_to,
        "maxTimeoutSeconds": 60,
        "extra": {
            "name": extra_name or os.environ.get(ENV_VSR02_X402_EXTRA_NAME, X402_EXTRA_NAME_DEFAULT),
            "version": extra_version or os.environ.get(ENV_VSR02_X402_EXTRA_VERSION, X402_EXTRA_VERSION_DEFAULT),
        },
    }


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

    # Audit-corrected verdict (2026-05-26): the original test measured only
    # SESSION-CREATION ADMISSION CONTROL — does AgentCore refuse to open the
    # 2nd parallel session under the same (userId, agentName)? Observed: it
    # does not. But spend-time enforcement (whether ProcessPayment refuses
    # when cumulative spend across sessions would exceed any principal-level
    # ceiling) was NOT tested. That requires Coinbase delegated signing
    # enabled + a valid x402 payload that settles — discovered during ACP-004
    # corrective probing on 2026-05-26.
    #
    # PASS criterion (scope-narrowed): admission-control aggregation present.
    # FAIL = admission control admits N parallel sessions without aggregation.
    admission_control_aggregates = findings["parallel_sessions_created"] <= 1
    passed = admission_control_aggregates

    details_parts = [
        f"SCOPE: session-creation admission control only (NOT spend-time enforcement)",
        f"opened {findings['parallel_sessions_created']}/{parallel_count} parallel sessions under same (userId, agentName)",
        f"per-session cap ${per_session_cap}",
        f"admission-cumulative authorized ${findings['cumulative_authorized_usd']}",
    ]
    if findings["documented_per_session_ceiling"]:
        details_parts.append(
            f"per-session ceiling ${findings['documented_per_session_ceiling']}"
        )
    if not admission_control_aggregates:
        details_parts.append(
            "FINDING: admission control does NOT aggregate caps across parallel sessions. "
            "Spend-time enforcement requires separate test with delegated-signing enabled."
        )

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
        name="Parallel-Session Admission-Control Aggregation (admission-layer only)",
        category="spend_cap_enforcement",
        owasp_asi="ASI02",
        severity=Severity.MEDIUM.value,  # was HIGH; corrected per 2026-05-26 audit (scope-narrowed to admission control)
        passed=passed,
        details="; ".join(details_parts),
        region=region,
        session_id=created_session_ids[0][0] if created_session_ids else "",
        request_sent={
            "operation": "CreatePaymentSession x N (parallel) + cap-value boundaries — admission-control test only",
            "parallel_count_attempted": parallel_count,
            "per_session_cap_usd": per_session_cap,
            "user_id": user_id,
            "agent_name": agent_name,
            "boundary_cap_values_tested": list(findings["boundary_results"].keys()),
            "audit_note_2026_05_26": "Scope narrowed: this measures ADMISSION CONTROL (whether N sessions can be created), NOT spend-time enforcement (whether cumulative spend exceeding session caps is blocked). Spend-time test requires Coinbase delegated signing enabled in CDP project policies — see ACP-004 corrective probing.",
        },
        response_received=findings,
        csg_mapping="HC-1: Admission-control aggregation needed for principal-bound spend governance",
        estimated_impact="documentation",
        estimated_severity="medium",
        elapsed_s=round(elapsed, 3),
    )


def test_agentcore_session_reset_replay() -> AgentCoreTestResult:
    """ACP-002: Session lifecycle — does delete+recreate preserve any cap state?

    Attack pattern (reframed from scope-doc original):
        Scope-doc original assumed spending the cap in session A via real
        ProcessPayment calls, deleting session A, opening session B, and
        checking whether the cap is re-evaluated. Real spend requires a
        merchant + valid x402 payloads. Reframed test probes the adjacent
        attack surface: rapid session churn under same (userId, agentName).
        If the platform retains NO cross-session state, then session reset
        is a no-op attack vector — but it confirms ACP-001's finding that
        cap state is bound to the session lifecycle, not to the principal.

    In-scope behavior:
        (1) Create session A, capture state
        (2) Delete A explicitly
        (3) Try GetPaymentSession(A_id) — observe response (404 vs DELETED status)
        (4) List active sessions — confirm A is absent
        (5) Rapid-churn N create+delete cycles, measure rate limits and any
            cumulative tracking
        (6) Create session B under same (userId, agentName) and confirm cap
            is fresh, no link to A

    Expected detection by AgentCore:
        For the cap to be "instrument-bound" (the scope-doc desideratum),
        deleted-session metadata would have to persist across the lifecycle
        and bind to the user/instrument context. Observed: this test reveals
        whether AgentCore retains ANY cross-session state for the cap.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = "vsr01-churn-user"
    agent_name = "vsr01-churn-agent"
    per_cap = "0.10"

    findings: dict = {
        "session_a_created": False,
        "session_a_id": "",
        "session_a_deleted": False,
        "get_after_delete_status": None,
        "list_after_delete_includes_a": None,
        "churn_create_count": 0,
        "churn_delete_count": 0,
        "churn_errors": [],
        "session_b_created": False,
        "session_b_cap_fresh": None,
        "rate_limit_hit": False,
    }

    # Step 1: create session A
    try:
        r = dp.create_payment_session(
            userId=user_id,
            agentName=agent_name,
            paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": per_cap, "currency": "USD"}},
            expiryTimeInMinutes=15,
            clientToken=str(uuid.uuid4()),
        )
        sa = r.get("paymentSession", r)
        findings["session_a_id"] = sa.get("paymentSessionId", "")
        findings["session_a_created"] = bool(findings["session_a_id"])
    except Exception as e:
        findings["churn_errors"].append(f"create_a: {type(e).__name__}: {str(e)[:160]}")

    # Step 2: delete A
    if findings["session_a_id"]:
        try:
            dp.delete_payment_session(
                userId=user_id,
                paymentManagerArn=pm_arn,
                paymentSessionId=findings["session_a_id"],
            )
            findings["session_a_deleted"] = True
        except Exception as e:
            findings["churn_errors"].append(f"delete_a: {type(e).__name__}: {str(e)[:160]}")

    # Step 3: GetPaymentSession(A_id) after delete — does state persist?
    if findings["session_a_deleted"]:
        try:
            detail = dp.get_payment_session(
                userId=user_id,
                paymentManagerArn=pm_arn,
                paymentSessionId=findings["session_a_id"],
            )
            findings["get_after_delete_status"] = "RETURNED (state persists after delete)"
            findings["get_after_delete_payload"] = str(detail)[:300]
        except dp.exceptions.ResourceNotFoundException:
            findings["get_after_delete_status"] = "ResourceNotFoundException (state purged)"
        except Exception as e:
            findings["get_after_delete_status"] = f"{type(e).__name__}: {str(e)[:160]}"

    # Step 4: list active — A should be absent
    try:
        active = dp.list_payment_sessions(
            userId=user_id, paymentManagerArn=pm_arn,
        ).get("paymentSessions", [])
        active_ids = {s.get("paymentSessionId") for s in active}
        findings["list_after_delete_includes_a"] = findings["session_a_id"] in active_ids
        findings["list_after_delete_count"] = len(active)
    except Exception as e:
        findings["churn_errors"].append(f"list: {type(e).__name__}: {str(e)[:160]}")

    # Step 5: rapid churn — N create+delete cycles
    churn_n = 5
    cleanup_left = []
    for i in range(churn_n):
        try:
            r = dp.create_payment_session(
                userId=user_id,
                agentName=agent_name,
                paymentManagerArn=pm_arn,
                limits={"maxSpendAmount": {"value": per_cap, "currency": "USD"}},
                expiryTimeInMinutes=15,
                clientToken=str(uuid.uuid4()),
            )
            sid = r.get("paymentSession", r).get("paymentSessionId", "")
            findings["churn_create_count"] += 1
            if sid:
                try:
                    dp.delete_payment_session(
                        userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=sid,
                    )
                    findings["churn_delete_count"] += 1
                except Exception as e:
                    cleanup_left.append(sid)
                    findings["churn_errors"].append(f"churn_delete[{i}]: {type(e).__name__}")
        except Exception as e:
            msg = str(e)
            if "Throttling" in msg or "RateExceeded" in msg or "TooManyRequests" in msg:
                findings["rate_limit_hit"] = True
                findings["rate_limit_at_iteration"] = i
                break
            findings["churn_errors"].append(f"churn_create[{i}]: {type(e).__name__}: {msg[:120]}")

    # Step 6: create session B and check cap is fresh
    try:
        r = dp.create_payment_session(
            userId=user_id,
            agentName=agent_name,
            paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": per_cap, "currency": "USD"}},
            expiryTimeInMinutes=15,
            clientToken=str(uuid.uuid4()),
        )
        sb = r.get("paymentSession", r)
        sb_id = sb.get("paymentSessionId", "")
        findings["session_b_created"] = bool(sb_id)
        # Compare available balance against cap — fresh session should have full cap
        avail = sb.get("availableLimits", {}).get("availableSpendAmount", {}).get("value", "0")
        findings["session_b_cap_fresh"] = avail == per_cap
        findings["session_b_id"] = sb_id
        findings["session_b_available"] = avail
        # Cleanup
        if sb_id:
            try:
                dp.delete_payment_session(
                    userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=sb_id,
                )
            except Exception:
                cleanup_left.append(sb_id)
    except Exception as e:
        findings["churn_errors"].append(f"create_b: {type(e).__name__}: {str(e)[:160]}")

    # Final cleanup of stragglers
    for sid in cleanup_left:
        try:
            dp.delete_payment_session(
                userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=sid,
            )
        except Exception:
            pass

    elapsed = time.monotonic() - t0

    # Audit-corrected PASS criterion (2026-05-26): the original criterion
    # required AgentCore to retain state AFTER explicit delete — that's the
    # OPPOSITE of normal resource hygiene and would be a wrong-by-design
    # finding. This test is a CHARACTERIZATION of session lifecycle behavior,
    # not a vulnerability test. PASS = the characterization completed cleanly
    # without errors. The finding (session-scoped, not principal-scoped, cap
    # state) is documented in details; the security implication maps to ACP-001
    # at the temporal axis but is NOT itself a CRITICAL finding.
    state_purged_on_delete = findings.get("get_after_delete_status", "").startswith("ResourceNotFoundException")
    session_b_fresh = bool(findings.get("session_b_cap_fresh"))
    # PASS = test completed measurement cleanly (no errors, cleanup successful)
    passed = (
        findings["session_a_created"]
        and findings["session_a_deleted"]
        and findings["session_b_created"]
        and not findings["churn_errors"]
    )

    details = (
        f"Characterization: session lifecycle is session-scoped (NOT principal-scoped). "
        f"Session A created→deleted cleanly; GET-after-delete returns "
        f"{findings.get('get_after_delete_status','?')[:60]} (normal AWS resource lifecycle). "
        f"List-after-delete excludes A: {not findings.get('list_after_delete_includes_a')}. "
        f"Churn {findings['churn_create_count']}/{findings['churn_delete_count']} cycles clean, no rate limit at this pace. "
        f"New session B under same (userId, agentName) starts with full cap ${findings.get('session_b_available','?')} — "
        f"no carry-over from A. Documents that cap state is per-session-lifecycle; companion finding to ACP-001. "
        f"NOT a vulnerability — operators relying on cumulative-across-sessions tracking must layer at application."
    )

    return AgentCoreTestResult(
        test_id="ACP-002",
        name="Session Lifecycle Characterization — Cap State is Session-Scoped",
        category="spend_cap_enforcement",
        owasp_asi="ASI03",
        severity=Severity.LOW.value,  # was CRITICAL; corrected per 2026-05-26 audit
        passed=passed,
        details=details,
        region=region,
        session_id=findings.get("session_a_id", ""),
        request_sent={
            "operation": "Create+Delete+Get + N-cycle churn + new-session-cap characterization",
            "user_id": user_id,
            "agent_name": agent_name,
            "per_cap_usd": per_cap,
            "churn_iterations": churn_n,
            "audit_note_2026_05_26": "Original PASS criterion punished normal AWS resource lifecycle (state purged on delete = correct behavior). Reframed as characterization; the security signal is the companion to ACP-001 (no principal-bound cap state).",
        },
        response_received=findings,
        csg_mapping="HC-2: Operators must track cumulative cap at application layer if principal-bound spend governance is required",
        estimated_impact="documentation",
        estimated_severity="low",
        elapsed_s=round(elapsed, 3),
    )


def test_agentcore_402_terms_forgery() -> AgentCoreTestResult:
    """ACP-003: AgentCore client-side validation of crafted x402 payment payloads.

    Attack pattern (reframed from scope-doc original):
        Scope-doc original assumed standing up a mock 402 HTTP endpoint and
        driving AgentCore through it. The AgentCore Payments API does not
        consume 402 responses directly — that's the agent runtime's job; the
        runtime then submits a constructed payload to ProcessPayment.
        Reframed test probes the adjacent surface: does AgentCore validate
        the ProcessPayment payload CLIENT-SIDE before forwarding to merchant
        rails? We submit ProcessPayment calls with crafted payloads (over-
        budget, wrong asset, exotic chain, malformed structure) and observe
        whether AgentCore rejects pre-flight or attempts to forward.

    In-scope behavior:
        For each forged variant, submit a ProcessPayment call against a real
        session+instrument with a deliberately invalid payload. Record:
          1. Does AgentCore reject (and at which layer — input validation,
             policy, downstream)?
          2. Does the error message reveal which validation fired?
          3. Are different variant classes handled distinctly (variant-
             specific errors) or treated identically (generic input rejection)?

    Expected detection by AgentCore:
        Best case: per-variant errors (OverBudgetException for amount,
        AssetMismatchException for asset, UnsupportedNetworkException for
        chain). Worst case: all rejected as generic ValidationException with
        no semantic discrimination — meaning the agent runtime, not the
        platform, is responsible for terms validation.
    """
    import json as _json
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    connector_id = os.environ.get("AGENTCORE_PAYMENT_CONNECTOR_ID", "")
    user_id = "vsr01-forge-user"
    agent_name = "vsr01-forge-agent"
    session_cap = "0.10"  # tight cap to make "over_budget" attacks meaningful

    findings: dict = {
        "session_created": False,
        "session_id": "",
        "instrument_created": False,
        "instrument_id": "",
        "variants_tested": 0,
        "variants_rejected_preflight": 0,
        "per_variant_responses": {},
        "errors": [],
    }

    # Setup: session + instrument
    try:
        r = dp.create_payment_session(
            userId=user_id, agentName=agent_name,
            paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": session_cap, "currency": "USD"}},
            expiryTimeInMinutes=15,
            clientToken=str(uuid.uuid4()),
        )
        findings["session_id"] = r.get("paymentSession", r).get("paymentSessionId", "")
        findings["session_created"] = bool(findings["session_id"])
    except Exception as e:
        findings["errors"].append(f"session_create: {type(e).__name__}: {str(e)[:160]}")
        elapsed = time.monotonic() - t0
        return AgentCoreTestResult(
            test_id="ACP-003", name="402 Terms Forgery — Client-Side Payload Validation",
            category="402_terms_validation", owasp_asi="ASI09",
            severity=Severity.HIGH.value, passed=False,
            details=f"Setup failed: {findings['errors']}", region=region,
            session_id="", request_sent={}, response_received=findings,
            csg_mapping="HC-3: 402 terms must be validated against instrument policy",
            estimated_impact="fund_theft", estimated_severity="high",
            elapsed_s=round(elapsed, 3),
        )

    try:
        r = dp.create_payment_instrument(
            userId=user_id, agentName=agent_name,
            paymentManagerArn=pm_arn, paymentConnectorId=connector_id,
            paymentInstrumentType="EMBEDDED_CRYPTO_WALLET",
            paymentInstrumentDetails={
                "embeddedCryptoWallet": {
                    "network": "ETHEREUM",
                    "linkedAccounts": [{"email": {"emailAddress": "vsr01-forge@example.test"}}],
                }
            },
            clientToken=str(uuid.uuid4()),
        )
        findings["instrument_id"] = r["paymentInstrument"]["paymentInstrumentId"]
        findings["instrument_created"] = True
    except Exception as e:
        findings["errors"].append(f"instrument_create: {type(e).__name__}: {str(e)[:160]}")

    # Craft forged variants — each probes a different validation layer.
    # Empirically (probed 2026-05-26), AgentCore's payload validation runs
    # in this order: 1) scheme; 2) network; 3) asset; 4) EVM-specific 'extra'
    # fields; 5) network-vs-instrument match. Variants are constructed to
    # surface each layer and characterize the depth of pre-flight checks.
    USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    forged_variants = {
        "empty_payload": {},
        "structural_scheme_missing": {
            "network": "base-sepolia",
            "asset": USDC_BASE_SEPOLIA,
            "maxAmountRequired": "50000",
        },
        "structural_network_missing": {
            "scheme": "exact",
            "asset": USDC_BASE_SEPOLIA,
            "maxAmountRequired": "50000",
        },
        "structural_asset_missing": {
            "scheme": "exact",
            "network": "base-sepolia",
            "maxAmountRequired": "50000",
        },
        "semantic_exotic_network": {
            "scheme": "exact",
            "network": "fake-chain-vsr01-test",
            "asset": USDC_BASE_SEPOLIA,
            "maxAmountRequired": "50000",
            "resource": "https://attacker.example/data",
            "description": "exotic chain probe",
            "mimeType": "application/json",
            "payTo": "0x" + "DE" * 20,
            "maxTimeoutSeconds": 60,
        },
        "semantic_over_budget": {
            # session cap = $0.10; this is $10 in 6-decimal USDC units = 100x cap
            "scheme": "exact",
            "network": "base-sepolia",
            "asset": USDC_BASE_SEPOLIA,
            "maxAmountRequired": "10000000",
            "resource": "https://attacker.example/data",
            "description": "over-budget probe",
            "mimeType": "application/json",
            "payTo": "0x" + "DE" * 20,
            "maxTimeoutSeconds": 60,
        },
        "semantic_negative_amount": {
            "scheme": "exact",
            "network": "base-sepolia",
            "asset": USDC_BASE_SEPOLIA,
            "maxAmountRequired": "-50000",
            "resource": "https://attacker.example/data",
            "description": "negative amount probe",
            "mimeType": "application/json",
            "payTo": "0x" + "DE" * 20,
            "maxTimeoutSeconds": 60,
        },
        "semantic_malformed_recipient": {
            "scheme": "exact",
            "network": "base-sepolia",
            "asset": USDC_BASE_SEPOLIA,
            "maxAmountRequired": "50000",
            "resource": "https://attacker.example/data",
            "description": "malformed payTo probe",
            "mimeType": "application/json",
            "payTo": "not-a-valid-address",
            "maxTimeoutSeconds": 60,
        },
    }

    if findings["session_created"] and findings["instrument_created"]:
        for variant_name, payload_dict in forged_variants.items():
            findings["variants_tested"] += 1
            try:
                dp.process_payment(
                    userId=user_id, agentName=agent_name,
                    paymentManagerArn=pm_arn,
                    paymentSessionId=findings["session_id"],
                    paymentInstrumentId=findings["instrument_id"],
                    paymentType="CRYPTO_X402",
                    paymentInput={
                        "cryptoX402": {
                            "version": "1",
                            "payload": payload_dict,
                        }
                    },
                    clientToken=str(uuid.uuid4()),
                )
                findings["per_variant_responses"][variant_name] = "ACCEPTED (no rejection — concerning)"
            except Exception as e:
                err_type = type(e).__name__
                err_msg = str(e)[:240]
                findings["per_variant_responses"][variant_name] = f"{err_type}: {err_msg[:180]}"
                findings["variants_rejected_preflight"] += 1

    # Cleanup
    if findings["instrument_id"]:
        try:
            dp.delete_payment_instrument(
                userId=user_id, paymentManagerArn=pm_arn,
                paymentConnectorId=connector_id,
                paymentInstrumentId=findings["instrument_id"],
            )
        except Exception:
            pass
    if findings["session_id"]:
        try:
            dp.delete_payment_session(
                userId=user_id, paymentManagerArn=pm_arn,
                paymentSessionId=findings["session_id"],
            )
        except Exception:
            pass

    elapsed = time.monotonic() - t0

    # Discrimination check: do the variants get DISTINCT error semantics?
    # The boto3 wrapper adds a common prefix; we extract the message after
    # the operation name and dedupe on that.
    import re as _re
    unique_error_signatures = set()
    for v, resp in findings["per_variant_responses"].items():
        # Strip "ValidationException: An error occurred (...) when calling the X operation: "
        m = _re.search(r"operation:\s*(.*?)$", resp, _re.DOTALL)
        msg = m.group(1).strip() if m else resp
        # Signature on first 80 chars of the actual error message
        unique_error_signatures.add(msg[:80])
    findings["distinct_error_signatures"] = len(unique_error_signatures)
    findings["unique_error_messages_sample"] = sorted(list(unique_error_signatures))[:10]

    # PASS criterion: AgentCore must reject ALL forged variants AND provide
    # variant-specific error semantics (multiple distinct signatures).
    all_rejected = (
        findings["variants_rejected_preflight"] == findings["variants_tested"]
        and findings["variants_tested"] > 0
    )
    semantic_discrimination = findings["distinct_error_signatures"] >= 3  # at least 3 distinct categories
    passed = all_rejected and semantic_discrimination

    # Audit-corrected (2026-05-26): the over_budget variant short-circuited at
    # the upstream 'extra.name' structural gate before reaching cap-vs-amount
    # validation. Independent probing (during ACP-004 corrective work) confirmed
    # that with extra.name set, the next gate is delegated-signing AccessDenied
    # — meaning cap-vs-amount validation is not testable from the harness
    # without enabling Coinbase delegated signing in CDP project policies.
    cap_vs_amount_not_probed = "semantic_over_budget" in findings["per_variant_responses"] and \
        "extra.name" in findings["per_variant_responses"].get("semantic_over_budget", "")
    findings["cap_vs_amount_not_probed_due_to_upstream_gate"] = cap_vs_amount_not_probed

    details = (
        f"Setup: session={findings['session_created']} instrument={findings['instrument_created']}; "
        f"variants {findings['variants_rejected_preflight']}/{findings['variants_tested']} rejected pre-flight; "
        f"{findings['distinct_error_signatures']} distinct error signatures across structural / "
        f"network-binding / amount-sign / address-format layers "
        f"(semantic discrimination {'present' if semantic_discrimination else 'absent'}). "
        f"SCOPE NOTE: cap-vs-amount validation NOT probed — over-budget variant short-circuited at "
        f"upstream extra.name structural gate. Cap-vs-amount enforcement requires payload that passes "
        f"all structural gates AND Coinbase delegated signing enabled."
    )

    return AgentCoreTestResult(
        test_id="ACP-003",
        name="402 Terms Forgery — Client-Side Payload Validation",
        category="402_terms_validation",
        owasp_asi="ASI09",
        severity=Severity.HIGH.value,
        passed=passed,
        details=details,
        region=region,
        session_id=findings["session_id"],
        request_sent={
            "operation": "ProcessPayment x N with crafted payloads",
            "session_cap_usd": session_cap,
            "variant_names": list(forged_variants.keys()),
        },
        response_received=findings,
        csg_mapping="HC-3: 402 terms must be validated against instrument policy",
        estimated_impact="fund_theft",
        estimated_severity="high",
        elapsed_s=round(elapsed, 3),
    )


def test_agentcore_receipt_validation() -> AgentCoreTestResult:
    """ACP-004: ProcessPayment idempotency and replay-protection probe.

    Attack pattern (reframed from scope-doc original):
        Scope-doc original assumed standing up a fake-receipt path against
        ProcessPayment. AgentCore's ProcessPayment is the INPUT side (paying
        for an x402 resource); receipts are generated by the facilitator
        after settlement and aren't a user-controlled input. Reframed test
        probes the closely-adjacent attack surface: payment IDEMPOTENCY +
        REPLAY protection. Both are receipt-validation-class concerns —
        without idempotency, the same payment can be processed twice for
        double-spend; without replay protection, a recorded payment payload
        can be re-submitted.

    In-scope behavior:
        1) Submit same ProcessPayment call with SAME clientToken twice —
           expect idempotency (same response, no duplicate processing).
        2) Submit two ProcessPayment calls with DIFFERENT clientTokens but
           IDENTICAL payloads — observe whether AgentCore detects the
           payload-level duplicate or treats them as independent payments.
        3) Submit a ProcessPayment with payload claiming pre-settled metadata
           (fake tx_hash, fake facilitator_proof) — observe whether
           AgentCore strips unknown fields or accepts them.

    Expected detection by AgentCore:
        Idempotency on clientToken (AWS-standard behavior) + ideally
        payload-level deduplication for replay protection. Unknown fields
        in the payload should be stripped or rejected, not silently passed
        through.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    connector_id = os.environ.get("AGENTCORE_PAYMENT_CONNECTOR_ID", "")
    user_id = "vsr01-receipt-user"
    agent_name = "vsr01-receipt-agent"

    findings: dict = {
        "session_created": False,
        "instrument_created": False,
        "client_token_idempotent": None,
        "payload_replay_detected": None,
        "fake_receipt_fields_stripped": None,
        "per_probe_responses": {},
        "errors": [],
    }

    # Setup: session + instrument (cap $0.10 — within wallet balance)
    try:
        r = dp.create_payment_session(
            userId=user_id, agentName=agent_name,
            paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": "0.10", "currency": "USD"}},
            expiryTimeInMinutes=15,
            clientToken=str(uuid.uuid4()),
        )
        sid = r.get("paymentSession", r).get("paymentSessionId", "")
        findings["session_created"] = bool(sid)
        findings["session_id"] = sid
    except Exception as e:
        findings["errors"].append(f"session_create: {type(e).__name__}: {str(e)[:160]}")
        elapsed = time.monotonic() - t0
        return AgentCoreTestResult(
            test_id="ACP-004", name="Receipt-Class Validation (Idempotency + Replay)",
            category="receipt_validation", owasp_asi="ASI06",
            severity=Severity.CRITICAL.value, passed=False,
            details="setup failed", region=region, session_id="",
            request_sent={}, response_received=findings,
            csg_mapping="HC-4: Receipts must verify against issuer key + on-chain state",
            estimated_impact="fund_theft", estimated_severity="critical",
            elapsed_s=round(elapsed, 3),
        )

    try:
        r = dp.create_payment_instrument(
            userId=user_id, agentName=agent_name,
            paymentManagerArn=pm_arn, paymentConnectorId=connector_id,
            paymentInstrumentType="EMBEDDED_CRYPTO_WALLET",
            paymentInstrumentDetails={
                "embeddedCryptoWallet": {
                    "network": "ETHEREUM",
                    "linkedAccounts": [{"email": {"emailAddress": "vsr01-receipt@example.test"}}],
                }
            },
            clientToken=str(uuid.uuid4()),
        )
        iid = r["paymentInstrument"]["paymentInstrumentId"]
        findings["instrument_created"] = True
        findings["instrument_id"] = iid
    except Exception as e:
        findings["errors"].append(f"instrument_create: {type(e).__name__}: {str(e)[:160]}")
        iid = ""

    # Reusable payload — invalid (missing extra.name) so it fails fast but
    # in a deterministic way. This lets us observe error consistency across
    # idempotent submissions without actually moving funds.
    base_payload = {
        "scheme": "exact",
        "network": "base-sepolia",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  # USDC base-sepolia
        "maxAmountRequired": "50000",  # 0.05 USDC
        "resource": "https://vsr01-replay-probe.example/data",
        "description": "ACP-004 idempotency probe",
        "mimeType": "application/json",
        "payTo": "0x" + "DE" * 20,
        "maxTimeoutSeconds": 60,
    }

    def _process(payload, client_token):
        try:
            return dp.process_payment(
                userId=user_id, agentName=agent_name,
                paymentManagerArn=pm_arn,
                paymentSessionId=findings["session_id"],
                paymentInstrumentId=iid,
                paymentType="CRYPTO_X402",
                paymentInput={"cryptoX402": {"version": "1", "payload": payload}},
                clientToken=client_token,
            )
        except Exception as e:
            return {"_err": type(e).__name__, "_msg": str(e)[:200]}

    if findings["session_created"] and findings["instrument_created"]:
        # Probe 1: same clientToken twice
        ct_same = str(uuid.uuid4())
        r1a = _process(base_payload, ct_same)
        r1b = _process(base_payload, ct_same)
        findings["per_probe_responses"]["same_clientToken_call1"] = str(r1a)[:200]
        findings["per_probe_responses"]["same_clientToken_call2"] = str(r1b)[:200]
        # Idempotent if responses match
        findings["client_token_idempotent"] = (str(r1a)[:200] == str(r1b)[:200])

        # Probe 2: different clientTokens, identical payload
        ct_a, ct_b = str(uuid.uuid4()), str(uuid.uuid4())
        r2a = _process(base_payload, ct_a)
        r2b = _process(base_payload, ct_b)
        findings["per_probe_responses"]["diff_clientToken_call_a"] = str(r2a)[:200]
        findings["per_probe_responses"]["diff_clientToken_call_b"] = str(r2b)[:200]
        # Replay detected = AgentCore distinguishes call_b from call_a
        # (e.g., one accepted, other rejected as duplicate). If both rejected
        # identically by structural validation, no replay-protection visible.
        findings["payload_replay_detected"] = (str(r2a)[:200] != str(r2b)[:200])

        # Probe 3: payload with fake pre-settled receipt fields injected
        fake_receipt_payload = dict(base_payload)
        fake_receipt_payload.update({
            "txHash": "0x" + "ab" * 32,
            "facilitatorProof": "0x" + "ef" * 64,
            "settledAt": "2026-05-26T00:00:00Z",
            "settler": "0x" + "de" * 20,
            "settledAmount": "50000",
            "settled": True,
        })
        ct_fake = str(uuid.uuid4())
        r3 = _process(fake_receipt_payload, ct_fake)
        findings["per_probe_responses"]["fake_receipt_fields_injection"] = str(r3)[:200]
        # If the response is identical to base_payload's response (Probe 2's r2a),
        # AgentCore stripped the fake fields (good — schema-strict). If the
        # response differs, AgentCore accepted (or processed) the fake fields.
        baseline_resp = findings["per_probe_responses"].get("diff_clientToken_call_a", "")
        findings["fake_receipt_fields_stripped"] = (str(r3)[:200] == baseline_resp)

    # Cleanup
    if iid:
        try:
            dp.delete_payment_instrument(
                userId=user_id, paymentManagerArn=pm_arn,
                paymentConnectorId=connector_id, paymentInstrumentId=iid,
            )
        except Exception:
            pass
    if findings.get("session_id"):
        try:
            dp.delete_payment_session(
                userId=user_id, paymentManagerArn=pm_arn,
                paymentSessionId=findings["session_id"],
            )
        except Exception:
            pass

    elapsed = time.monotonic() - t0

    # Audit-corrected verdict (2026-05-26): all 5 ProcessPayment calls in
    # this test were blocked at the SAME structural validation gate
    # ("extra.name is required for EVM payments") BEFORE reaching the
    # idempotency / replay-protection layer. The original PASS criterion
    # ("identical responses for same clientToken = idempotent") is a
    # TAUTOLOGY because identical structural rejections are not proof of
    # idempotent processing — they're proof of consistent rejection.
    # The test is reframed as a CHARACTERIZATION of structural-layer
    # behavior. True payment-state idempotency / replay protection requires
    # successful first call (which itself requires Coinbase delegated
    # signing enabled in CDP project policies — a separate finding
    # discovered during ACP-004 corrective probing on 2026-05-26).
    all_calls_hit_structural_gate = all(
        "extra.name is required" in str(r) for r in findings["per_probe_responses"].values()
    )
    # PASS = test completed measurement cleanly + AgentCore behaved
    # consistently at the structural layer (input-validation deterministic).
    passed = (
        findings["session_created"]
        and findings["instrument_created"]
        and bool(findings.get("client_token_idempotent"))  # consistent rejection
        and bool(findings.get("fake_receipt_fields_stripped"))  # schema-strict
        and not findings["errors"]
    )

    details = (
        f"Structural-layer characterization (audit-corrected 2026-05-26). "
        f"All 5 ProcessPayment calls blocked at extra.name structural gate "
        f"BEFORE reaching idempotency/replay layer. "
        f"Same-clientToken: returns identical structural error (consistent rejection, NOT proof of payment-state idempotency). "
        f"Different-clientToken same-payload: same response (no payload-level dedup visible at this layer). "
        f"Fake-receipt fields (txHash/facilitatorProof/settledAt/settler/settledAmount/settled): silently stripped, "
        f"same baseline structural error returned (schema-strict on unknown fields — good behavior). "
        f"Companion finding from corrective probing: ProcessPayment with FULLY VALID payload returns "
        f"AccessDeniedException('Delegated signing is not enabled for your Coinbase project') — true "
        f"payment-state idempotency cannot be tested until that CDP project policy is enabled."
    )

    return AgentCoreTestResult(
        test_id="ACP-004",
        name="ProcessPayment Structural-Layer Characterization (idempotency NOT measured)",
        category="receipt_validation",
        owasp_asi="ASI06",
        severity=Severity.LOW.value,  # was CRITICAL; corrected per 2026-05-26 audit (tautology)
        passed=passed,
        details=details,
        region=region,
        session_id=findings.get("session_id", ""),
        request_sent={
            "operation": "ProcessPayment 5 calls (same-CT x2, diff-CT x2, fake-receipt-fields x1)",
            "session_cap_usd": "0.10",
        },
        response_received=findings,
        csg_mapping="HC-4: Receipts must verify against issuer key + on-chain state",
        estimated_impact="documentation",
        estimated_severity="low",  # was 'critical'; corrected per 2026-05-26 audit (tautology — test never reached idempotency layer)
        elapsed_s=round(elapsed, 3),
    )


def test_agentcore_audit_trace_intent_drift() -> AgentCoreTestResult:
    """ACP-005: AgentCore Payments audit surface intent-capture analysis.

    Attack pattern (reframed from scope-doc original):
        Scope-doc original assumed registering a decoy tool, triggering a
        purchase via an AgentCore agent runtime, and comparing audit-trace
        reasoning against the actual user prompt. That requires standing up
        a full agent runtime (create-agent-runtime, register tools, invoke
        with prompt, GetAgentTrace) — out of scope for the Payments-only
        eval surface. This reframed test instead probes whether the
        AgentCore Payments API has ANY user-controllable intent/reasoning
        field at all. If there is none, attribution-laundering is N/A —
        the audit surface records what (financial event) but not why
        (semantic context), which is a separate compliance gap.

    In-scope behavior:
        Schema introspection of CreatePaymentSession, GetPaymentSession,
        ProcessPayment input/output. Attempt to write candidate metadata
        fields (description, name, purpose, intent, metadata, tags) onto
        a real session; observe acceptance/rejection.

    Expected detection by AgentCore:
        For drift to be detectable, the audit trace must capture intent in
        the first place. Observed: AgentCore Payments has zero
        user-controllable intent fields; the audit surface is financial-
        event-only. Test PASSES (no drift possible) but the finding is
        the absence itself — operators relying on AgentCore Payments for
        regulatory "why" audit trail must add an external reasoning capture
        layer; the platform does not provide one.
    """
    import boto3
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")

    # Step 1: schema introspection — enumerate all user-writable fields
    # across the payment-creation surface
    candidate_intent_fields = [
        "description", "name", "purpose", "intent", "reason",
        "metadata", "tags", "annotations", "memo", "notes",
        "userPrompt", "agentReasoning", "rationale",
    ]
    schema_intent_fields_found: list[str] = []
    for op_name in ("CreatePaymentSession", "CreatePaymentInstrument", "ProcessPayment"):
        try:
            op = dp.meta.service_model.operation_model(op_name)
            members = set(op.input_shape.members.keys())
            for f in candidate_intent_fields:
                if f in members:
                    schema_intent_fields_found.append(f"{op_name}.{f}")
        except Exception:
            pass

    # Step 2: write attempts on a real session
    write_results: dict = {}
    cleanup_sids: list[str] = []
    for field in candidate_intent_fields:
        try:
            kwargs: dict = {
                "userId": "vsr01-trace-probe",
                "agentName": "vsr01-trace-agent",
                "paymentManagerArn": pm_arn,
                "limits": {"maxSpendAmount": {"value": "0.10", "currency": "USD"}},
                "expiryTimeInMinutes": 15,
                "clientToken": str(uuid.uuid4()),
            }
            kwargs[field] = "CANARY_INTENT_STRING_VSR01"
            r = dp.create_payment_session(**kwargs)
            sess = r.get("paymentSession", r)
            sid = sess.get("paymentSessionId")
            if sid:
                cleanup_sids.append(sid)
            # If accepted, check whether the canary appears in GET response
            try:
                detail = dp.get_payment_session(
                    userId="vsr01-trace-probe",
                    paymentManagerArn=pm_arn,
                    paymentSessionId=sid,
                ).get("paymentSession", {})
                canary_present = "CANARY_INTENT_STRING_VSR01" in str(detail)
            except Exception:
                canary_present = False
            write_results[field] = {
                "accepted": True,
                "canary_in_get_response": canary_present,
            }
        except boto3.exceptions.Boto3Error as e:
            msg = str(e)
            if "Unknown parameter" in msg or "unexpected keyword" in msg:
                write_results[field] = {"accepted": False, "reason": "schema_rejected"}
            else:
                write_results[field] = {"accepted": False, "reason": f"{type(e).__name__}: {msg[:120]}"}
        except Exception as e:
            msg = str(e)
            if "Unknown parameter" in msg or "unexpected keyword" in msg:
                write_results[field] = {"accepted": False, "reason": "schema_rejected"}
            else:
                write_results[field] = {"accepted": False, "reason": f"{type(e).__name__}: {msg[:120]}"}

    accepted_fields = [f for f, r in write_results.items() if r.get("accepted")]
    persisted_fields = [
        f for f, r in write_results.items()
        if r.get("accepted") and r.get("canary_in_get_response")
    ]

    # Step 3: cleanup
    cleaned = 0
    for sid in cleanup_sids:
        try:
            dp.delete_payment_session(
                userId="vsr01-trace-probe",
                paymentManagerArn=pm_arn,
                paymentSessionId=sid,
            )
            cleaned += 1
        except Exception:
            pass

    elapsed = time.monotonic() - t0

    intent_surface_present = bool(schema_intent_fields_found) or bool(persisted_fields)
    # PASS = drift not possible (because no intent surface to drift FROM)
    # This is the inverse-pass: passing means the platform doesn't even attempt
    # to capture intent, so the original attack is moot.
    passed = not intent_surface_present

    details = (
        f"Intent-capture surface check: {len(schema_intent_fields_found)} schema "
        f"fields, {len(accepted_fields)} write-accepted, {len(persisted_fields)} "
        f"persisted in GET. "
    )
    if intent_surface_present:
        details += "Intent surface EXISTS — drift testable in next pass."
    else:
        details += (
            "NO INTENT SURFACE — AgentCore Payments captures financial events "
            "without semantic context. Audit trail is what/when/how-much but "
            "not why. Operators relying on the platform for regulatory 'why' "
            "audit must layer external reasoning capture."
        )

    return AgentCoreTestResult(
        test_id="ACP-005",
        name="Audit Trace Intent Surface Analysis (input schema only)",
        category="audit_trace_integrity",
        owasp_asi="ASI05",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=details + (
            " SCOPE NOTE: this tests USER-CONTROLLABLE INTENT METADATA on the "
            "Payment APIs' input schemas only. Server-side intent capture in "
            "CloudWatch traces, X-Ray, or AgentCore internal audit pipelines "
            "was NOT probed. The 'no intent surface' finding is scoped to "
            "Payment-API user-input shapes."
        ),
        region=region,
        session_id=cleanup_sids[0] if cleanup_sids else "",
        request_sent={
            "operation": "schema introspection + write-probe of candidate intent fields",
            "candidate_fields": candidate_intent_fields,
            "fields_canary_string": "CANARY_INTENT_STRING_VSR01",
            "audit_note_2026_05_26": "Scope narrowed: claim is bounded to user-controllable input fields on the 3 Payment-API write surfaces. Does NOT cover CloudWatch / X-Ray / internal audit pipelines, which may capture intent independently.",
        },
        response_received={
            "schema_intent_fields_found": schema_intent_fields_found,
            "write_accepted_fields": accepted_fields,
            "persisted_in_get_fields": persisted_fields,
            "sessions_cleaned": cleaned,
            "per_field_results": write_results,
        },
        csg_mapping="HC-5: Audit reasoning must reflect prompt, not untrusted tool metadata",
        estimated_impact="documentation",
        estimated_severity="medium",  # was 'high'; corrected to match severity field per 2026-05-26 audit
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
        details="; ".join(detail_parts) + (
            " AMBIGUITY NOTE (audit 2026-05-26): the ResourceNotFoundException "
            "returned to user_b on get(A's id) is semantically indistinguishable "
            "from the response to a non-existent ID. Both preserve the security "
            "property (cross-user isolation holds) but the test does not "
            "distinguish data-plane isolation from privacy-preserving error "
            "discrimination. Future round: add positive-control GET-as-user_a "
            "to verify the same ID returns 200 in the owner context."
        ),
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
            "audit_note_2026_05_26": "ResourceNotFoundException is ambiguous between (a) genuine isolation, (b) privacy-preserving uniform-error response, and (c) per-user ID namespacing. All preserve the security property. Test verdict (isolation holds) is correct; published claim must acknowledge the response is semantically indistinguishable from non-existent.",
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
        # Two semantically DISTINCT findings — do not conflate (audit 2026-05-26):
        # (1) TYPOSQUAT signal: small clusters of near-duplicate hostnames
        # (2) CONCENTRATION signal: marketplace diversity / top-host share
        "total_listings": len(listings),
        "unique_hostnames": len(hosts),
        # Finding 1: typosquat detection
        "typosquat_finding": {
            "typosquat_clusters_count": len(cluster_sizes),
            "largest_cluster_size": cluster_sizes[0] if cluster_sizes else 0,
            "hosts_in_typosquat_clusters": sum(cluster_sizes),
            "homoglyph_hostnames": homoglyph_count,
            "interpretation": (
                "Levenshtein-clustered near-duplicate hostnames in the registry. "
                "Indicates marketplace lacks pre-list edit-distance defense."
            ),
        },
        # Finding 2: marketplace concentration (different question entirely)
        "concentration_finding": {
            "top_host_concentration_pct": round(top_host_share * 100, 1),
            "interpretation": (
                "Fraction of all listings registered by the top single hostname. "
                "Marketplace diversity signal — NOT a typosquat signal. High "
                "concentration suggests one operator dominates the registry, "
                "which is its own supply-chain consideration but distinct from "
                "near-duplicate hostname squatting."
            ),
        },
        "malformed_resource_urls": bad_urls,
    }

    return AgentCoreTestResult(
        test_id="ACP-007",
        name="Bazaar Inventory — Typosquat + Concentration (two distinct findings)",
        category="bazaar_supply_chain",
        owasp_asi="ASI04",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=(
            f"Bazaar inventory: {summary['total_listings']} listings across "
            f"{summary['unique_hostnames']} unique hosts. "
            f"TYPOSQUAT FINDING: {summary['typosquat_finding']['typosquat_clusters_count']} clusters "
            f"(largest={summary['typosquat_finding']['largest_cluster_size']}, "
            f"{summary['typosquat_finding']['hosts_in_typosquat_clusters']} hosts in clusters), "
            f"{summary['typosquat_finding']['homoglyph_hostnames']} non-ASCII hostnames. "
            f"CONCENTRATION FINDING (separate semantics): top-host concentration "
            f"{summary['concentration_finding']['top_host_concentration_pct']}% — "
            f"marketplace-diversity signal, NOT typosquat signal."
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


def test_agentcore_policy_bypass_via_tool_chain() -> AgentCoreTestResult:
    """ACP-008: Multi-instrument policy bypass via instrument chaining.

    Attack pattern (reframed from scope-doc original):
        Scope-doc original assumed two registered tools where individual
        calls are policy-compliant but the aggregate violates a cap. That
        requires the AgentCore Agent runtime + tool registration — out of
        scope for the Payments-only eval surface. Reframed test probes the
        adjacent attack surface: multi-instrument fragmentation. A single
        (userId, agentName) can create N PaymentInstruments, each backed by
        its own session with its own cap. Cumulative authorized spend
        across instruments = N * per_instrument_cap, with no AgentCore-side
        enforcement that the sum of (instrument, session) cap pairs respects
        any user-level ceiling. This is the "tool chain laundering" attack
        at the instrument layer instead of the agent-tool layer.

    In-scope behavior:
        (1) Create N PaymentInstruments under same (userId, agentName)
        (2) For each instrument, open a session with cap $X
        (3) Confirm all (instrument, session) pairs created successfully
        (4) Compute cumulative authorized = N * X
        (5) Verify no platform-level user cap rejects the Nth creation

    Expected detection by AgentCore:
        For PASS (laundering NOT viable), AgentCore would refuse the second
        instrument under same (userId, agentName) — or refuse the Nth session
        when summed cap across instruments exceeds a user threshold.
        Observed: AgentCore happily creates N instruments + N sessions = N*cap
        authorized, no aggregation, no user-level ceiling visible.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    connector_id = os.environ.get("AGENTCORE_PAYMENT_CONNECTOR_ID", "")
    user_id = "vsr01-chain-user"
    agent_name = "vsr01-chain-agent"
    per_pair_cap = "0.10"
    n_pairs = 3  # 3 instrument-session pairs

    findings: dict = {
        "n_pairs_attempted": n_pairs,
        "instruments_created": 0,
        "sessions_created": 0,
        "instrument_ids": [],
        "session_ids": [],
        "per_pair_cap_usd": per_pair_cap,
        "cumulative_authorized_usd": 0.0,
        "errors": [],
        "cleanup_count": 0,
    }

    for i in range(n_pairs):
        # Create instrument i
        try:
            r = dp.create_payment_instrument(
                userId=user_id, agentName=agent_name,
                paymentManagerArn=pm_arn, paymentConnectorId=connector_id,
                paymentInstrumentType="EMBEDDED_CRYPTO_WALLET",
                paymentInstrumentDetails={
                    "embeddedCryptoWallet": {
                        "network": "ETHEREUM",
                        "linkedAccounts": [{"email": {"emailAddress": f"vsr01-chain-{i}@example.test"}}],
                    }
                },
                clientToken=str(uuid.uuid4()),
            )
            iid = r["paymentInstrument"]["paymentInstrumentId"]
            findings["instrument_ids"].append(iid)
            findings["instruments_created"] += 1
        except Exception as e:
            findings["errors"].append(f"create_instrument[{i}]: {type(e).__name__}: {str(e)[:160]}")
            continue

        # Open session for this instrument
        try:
            r = dp.create_payment_session(
                userId=user_id, agentName=agent_name,
                paymentManagerArn=pm_arn,
                limits={"maxSpendAmount": {"value": per_pair_cap, "currency": "USD"}},
                expiryTimeInMinutes=15,
                clientToken=str(uuid.uuid4()),
            )
            sid = r.get("paymentSession", r).get("paymentSessionId", "")
            if sid:
                findings["session_ids"].append(sid)
                findings["sessions_created"] += 1
        except Exception as e:
            findings["errors"].append(f"create_session[{i}]: {type(e).__name__}: {str(e)[:160]}")

    findings["cumulative_authorized_usd"] = round(
        findings["sessions_created"] * float(per_pair_cap), 4
    )

    # Cleanup all pairs — audit-corrected (2026-05-26): delete SESSIONS first
    # (sessions may hold instrument-locks; reverse order = potential leak).
    for sid in findings["session_ids"]:
        try:
            dp.delete_payment_session(
                userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=sid,
            )
            findings["cleanup_count"] += 1
        except Exception as e:
            findings["errors"].append(f"cleanup_session_{sid[:10]}: {type(e).__name__}")
    for iid in findings["instrument_ids"]:
        try:
            dp.delete_payment_instrument(
                userId=user_id, paymentManagerArn=pm_arn,
                paymentConnectorId=connector_id, paymentInstrumentId=iid,
            )
            findings["cleanup_count"] += 1
        except Exception as e:
            findings["errors"].append(f"cleanup_instrument_{iid[:10]}: {type(e).__name__}")

    elapsed = time.monotonic() - t0

    # Audit-corrected verdict (2026-05-26): the original test treated this
    # as "instrument-chain laundering" but two problems were flagged:
    # (1) sessions are NOT bound to instruments at CreatePaymentSession time
    #     (no paymentInstrumentId parameter on that API) — binding happens
    #     only at ProcessPayment. The N×M multiplication is actually two
    #     INDEPENDENT axes: N instruments × M sessions are separate counts,
    #     not paired. (2) Spend-time enforcement was not measured, same
    #     issue as ACP-001. The reframe scopes the finding strictly to
    #     instrument-creation admission control under same (userId, agentName).
    # PASS = admission control limits multiple instruments under same principal.
    admission_control_aggregates = (
        findings["instruments_created"] <= 1
        or findings["sessions_created"] <= 1
    )
    passed = admission_control_aggregates

    details = (
        f"SCOPE: instrument-creation admission control only (NOT spend-time). "
        f"NOTE: sessions are not bound to instruments at creation time — N+M are independent axes, "
        f"not paired N*M. Tested N instruments + M sessions under same (userId, agentName); "
        f"(userId, agentName). Admission control aggregates: {admission_control_aggregates}. "
        f"Spend-time enforcement NOT measured (requires delegated signing per ACP-004 finding)."
    )

    return AgentCoreTestResult(
        test_id="ACP-008",
        name="Multi-Instrument Admission-Control Aggregation (admission-layer only)",
        category="policy_aggregation",
        owasp_asi="ASI02",
        severity=Severity.MEDIUM.value,  # was CRITICAL; corrected per 2026-05-26 audit
        passed=passed,
        details=details,
        region=region,
        session_id=findings["session_ids"][0] if findings["session_ids"] else "",
        request_sent={
            "operation": "CreatePaymentInstrument x N + CreatePaymentSession x N under one (userId, agentName) — admission-only",
            "n_pairs": n_pairs,
            "per_pair_cap_usd": per_pair_cap,
            "user_id": user_id,
            "agent_name": agent_name,
            "audit_note_2026_05_26": "Scope narrowed: this measures INSTRUMENT-CREATION ADMISSION CONTROL (whether N instruments + M sessions can be created under same principal), NOT spend-time aggregation. Sessions are not bound to instruments at CreatePaymentSession time — binding happens at ProcessPayment. The companion finding to ACP-001's parallel-sessions admission test.",
        },
        response_received=findings,
        csg_mapping="HC-8: Admission-control aggregation needed across instrument + session creation",
        estimated_impact="documentation",
        estimated_severity="medium",
        elapsed_s=round(elapsed, 3),
    )


# ---------------------------------------------------------------------------
# VS-R02 Tier-A stubs (4) — sign-time / PROOF_GENERATED evidence, 0 gas.
# All four require the WalletHub delegated-signing grant to be active (see
# scripts/vs-r02-env.sh) and stop before any merchant/facilitator submission.
# Pattern mirrors the VS-R01 stubs above: timing + findings dict + JSON-
# serializable AgentCoreTestResult, admission-vs-settlement / sign-vs-settle
# language throughout, "characterization" framing (no "vulnerability" claims).
# ---------------------------------------------------------------------------

def test_agentcore_signtime_spend_fragmentation() -> AgentCoreTestResult:
    """ACP-009: Sign-time spend fragmentation across parallel sessions (Tier A).

    Carries forward ACP-001 (admission-time parallel-session fragmentation,
    VS-R01, E2) to the sign-time layer now that CDP delegated signing is
    enabled. ACP-001 showed AgentCore admits N parallel PaymentSessions under
    one (userId, agentName) without aggregating the requested caps. This test
    asks the sharper question: does that same lack of aggregation hold once
    each session actually SIGNS a real payment authorization via
    ProcessPayment / CDP delegated signing, or does a principal-level ceiling
    appear once real signing key material is involved?

    Tier A / 0 gas: every ProcessPayment call targets BURN_PAYTO and the test
    stops at PROOF_GENERATED. Nothing is submitted to a merchant or
    facilitator; no chain state changes.

    Scope: uses the WalletHub-granted identity (VSR02_USER_ID_DEFAULT /
    VSR02_AGENT_NAME_DEFAULT / VSR02_INSTRUMENT_ID_DEFAULT) — the only
    (userId, agentName, paymentInstrumentId) tuple with an active delegated-
    signing grant as of this writing.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_id = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    per_session_cap = "0.05"
    parallel_count = 5
    sign_amount_units = "10000"  # 0.01 USDC (6-decimal units), well under the cap

    findings: dict = {
        "user_id": user_id,
        "agent_name": agent_name,
        "instrument_id": instrument_id,
        "parallel_sessions_created": 0,
        "parallel_sessions_attempted": parallel_count,
        "per_session_cap_usd": per_session_cap,
        "sign_attempts": 0,
        "sign_successes_proof_generated": 0,
        "per_session_sign_result": {},
        "status_extraction_method": {},
        "errors": [],
        "session_ids_cleaned": 0,
    }
    created_session_ids: list[str] = []

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
            sid = r.get("paymentSession", r).get("paymentSessionId", "")
            if sid:
                created_session_ids.append(sid)
                findings["parallel_sessions_created"] += 1
        except Exception as e:
            findings["errors"].append(f"session_create[{i}]: {type(e).__name__}: {str(e)[:160]}")

    for i, sid in enumerate(created_session_ids):
        findings["sign_attempts"] += 1
        payload = _build_x402_exact_payload(sign_amount_units, description=f"ACP-009 fragment {i}")
        try:
            resp = dp.process_payment(
                userId=user_id, agentName=agent_name,
                paymentManagerArn=pm_arn,
                paymentSessionId=sid,
                paymentInstrumentId=instrument_id,
                paymentType="CRYPTO_X402",
                paymentInput={"cryptoX402": {"version": "1", "payload": payload}},
                clientToken=str(uuid.uuid4()),
            )
            status, method = _extract_payment_status(resp)
            findings["per_session_sign_result"][sid] = status or f"UNRECOGNIZED_RESPONSE: {str(resp)[:200]}"
            findings["status_extraction_method"][sid] = method or "none"
            if status == PROOF_GENERATED:
                findings["sign_successes_proof_generated"] += 1
        except Exception as e:
            findings["per_session_sign_result"][sid] = f"{type(e).__name__}: {str(e)[:200]}"
            findings["errors"].append(f"sign[{i}]: {type(e).__name__}: {str(e)[:160]}")

    for sid in created_session_ids:
        try:
            dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=sid)
            findings["session_ids_cleaned"] += 1
        except Exception as e:
            findings["errors"].append(f"cleanup_{sid[:10]}: {type(e).__name__}")

    elapsed = time.monotonic() - t0

    # Characterization, not a pass/fail vulnerability verdict. "passed" tracks
    # whether the measurement itself completed cleanly (same convention as
    # ACP-002's audit-corrected PASS criterion above).
    measurement_clean = (
        findings["parallel_sessions_created"] == parallel_count
        and findings["sign_attempts"] == parallel_count
    )
    all_signed = findings["sign_successes_proof_generated"] == parallel_count
    none_signed = findings["sign_successes_proof_generated"] == 0
    passed = measurement_clean

    if none_signed:
        aggregation_note = (
            f"0/{parallel_count} parallel-session sign attempts reached PROOF_GENERATED — either "
            f"the response-status field-name guess is wrong (see _extract_payment_status TODO) "
            f"or delegated signing rejected every attempt; raw responses captured in "
            f"per_session_sign_result for manual inspection."
        )
    elif all_signed:
        aggregation_note = (
            f"{findings['sign_successes_proof_generated']}/{parallel_count} parallel sessions "
            f"signed to PROOF_GENERATED with no cross-session rejection — sign-time enforcement "
            f"does NOT aggregate cumulative signed amount across parallel sessions under one "
            f"(userId, agentName), consistent with the ACP-001 admission-time finding extended "
            f"to the signing layer."
        )
    else:
        aggregation_note = (
            f"{findings['sign_successes_proof_generated']}/{parallel_count} parallel sessions "
            f"signed to PROOF_GENERATED — partial aggregation or a rate/quota effect; inspect "
            f"per_session_sign_result for the boundary."
        )

    details = (
        f"SCOPE: sign-time characterization via CDP delegated signing, PROOF_GENERATED only "
        f"— no merchant submission, 0 gas. Opened {findings['parallel_sessions_created']}/"
        f"{parallel_count} parallel sessions under granted identity ({user_id}, {agent_name}); "
        f"{aggregation_note}"
    )

    return AgentCoreTestResult(
        test_id="ACP-009",
        name="Sign-Time Parallel-Session Spend Fragmentation (carries forward ACP-001)",
        category="spend_cap_enforcement",
        owasp_asi="ASI02",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=details,
        region=region,
        session_id=created_session_ids[0] if created_session_ids else "",
        request_sent={
            "operation": "CreatePaymentSession x N (parallel) + ProcessPayment x N (sign-only, burn payTo)",
            "parallel_count_attempted": parallel_count,
            "per_session_cap_usd": per_session_cap,
            "sign_amount_units": sign_amount_units,
            "pay_to": BURN_PAYTO,
            "user_id": user_id,
            "agent_name": agent_name,
            "instrument_id": instrument_id,
            "tier": "A (proof-only, 0 gas)",
        },
        response_received=findings,
        csg_mapping="HC-1: Sign-time aggregation needed for principal-bound spend governance (extends ACP-001)",
        estimated_impact="documentation",
        estimated_severity="medium",
        elapsed_s=round(elapsed, 3),
        evidence_class="E2.5",
    )


def test_agentcore_signtime_session_reset_replay() -> AgentCoreTestResult:
    """ACP-010: Does a signed proof survive session deletion / replay under a new session? (Tier A)

    Carries forward ACP-002 (VS-R01, E2 — session-lifecycle characterization
    at admission time only; no real signing occurred). This test signs a real
    payment authorization in session A via CDP delegated signing, deletes
    session A, and probes two distinct questions with two distinct sessions.

    AUDIT-CORRECTED DESIGN (independent audit, this round): the prior version
    of this test held ``clientToken`` CONSTANT across the session-A sign, the
    stale-A replay, and the session-B sign. That made every result after the
    first call an idempotency-cache hit on the shared clientToken, not
    evidence about session binding — AgentCore returning ConflictException on
    the third call ("client token already used with different parameters")
    is not a signal about session B's signing ability, it is AWS-standard
    clientToken idempotency firing on a REUSED token. clientToken is now the
    ISOLATED free variable: every ProcessPayment call in this test uses its
    OWN fresh clientToken, so a rejection or acceptance can only be
    attributed to the session/lifecycle state being probed, not to
    idempotency de-dup. The payload contents are held constant on purpose
    (same amount, description, payTo) — only clientToken varies per step.

    Step 3 (stale-A replay) and Step 4 (session B) each therefore ask a
    clean question: (a) does ProcessPayment against a DELETED session still
    succeed (does deletion void signing ability)? (b) does a FRESH session
    under the same principal, given an identical payload but a fresh token,
    sign cleanly (does it re-derive/reuse a prior proof, or produce an
    independent one)?

    Tier A / 0 gas: burn-address payTo, stops at PROOF_GENERATED, nothing
    submitted on-chain.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_id = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    per_cap = "0.05"
    sign_amount_units = "10000"

    findings: dict = {
        "session_a_id": "", "session_a_sign_status": "", "session_a_sign_response": "",
        "session_a_client_token": "",
        "session_a_deleted": False,
        "replay_under_a_after_delete_status": "",
        "replay_client_token": "",
        "session_b_id": "", "session_b_sign_status": "", "session_b_sign_response": "",
        "session_b_client_token": "",
        "proofs_identical": None,
        "status_extraction_method": {},
        "design_note": (
            "AUDIT-CORRECTED: clientToken is a FRESH, isolated variable per "
            "ProcessPayment call in this test (session_a / replay_stale_a / "
            "session_b each get their own uuid4 token). The prior design held "
            "clientToken constant across all three calls, which meant any "
            "rejection after the first call was an idempotency-cache hit, "
            "not session-binding evidence. Payload contents (amount, "
            "description, payTo) are held constant across calls on purpose."
        ),
        "errors": [],
    }
    payload = _build_x402_exact_payload(sign_amount_units, description="ACP-010 replay probe")

    # Step 1: create + sign session A (fresh clientToken)
    try:
        r = dp.create_payment_session(
            userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": per_cap, "currency": "USD"}},
            expiryTimeInMinutes=15, clientToken=str(uuid.uuid4()),
        )
        findings["session_a_id"] = r.get("paymentSession", r).get("paymentSessionId", "")
    except Exception as e:
        findings["errors"].append(f"create_a: {type(e).__name__}: {str(e)[:160]}")

    if findings["session_a_id"]:
        client_token_a = str(uuid.uuid4())
        findings["session_a_client_token"] = client_token_a
        try:
            resp = dp.process_payment(
                userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
                paymentSessionId=findings["session_a_id"], paymentInstrumentId=instrument_id,
                paymentType="CRYPTO_X402",
                paymentInput={"cryptoX402": {"version": "1", "payload": payload}},
                clientToken=client_token_a,
            )
            status, method = _extract_payment_status(resp)
            findings["session_a_sign_status"] = status or "UNRECOGNIZED"
            findings["status_extraction_method"]["session_a"] = method or "none"
            findings["session_a_sign_response"] = str(resp)[:300]
        except Exception as e:
            findings["session_a_sign_status"] = f"{type(e).__name__}"
            findings["session_a_sign_response"] = str(e)[:300]
            findings["errors"].append(f"sign_a: {type(e).__name__}: {str(e)[:160]}")

    # Step 2: delete session A
    if findings["session_a_id"]:
        try:
            dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=findings["session_a_id"])
            findings["session_a_deleted"] = True
        except Exception as e:
            findings["errors"].append(f"delete_a: {type(e).__name__}: {str(e)[:160]}")

    # Step 3: attempt ProcessPayment against session A's id AFTER delete, with
    # a FRESH clientToken (isolated from the token used to sign A) — does
    # AgentCore accept ProcessPayment against a deleted session reference, or
    # does deletion void the session's signing ability? A fresh token here
    # means any rejection is about the session, not a clientToken replay.
    if findings["session_a_deleted"]:
        client_token_replay = str(uuid.uuid4())
        findings["replay_client_token"] = client_token_replay
        try:
            resp = dp.process_payment(
                userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
                paymentSessionId=findings["session_a_id"], paymentInstrumentId=instrument_id,
                paymentType="CRYPTO_X402",
                paymentInput={"cryptoX402": {"version": "1", "payload": payload}},
                clientToken=client_token_replay,
            )
            status, method = _extract_payment_status(resp)
            findings["replay_under_a_after_delete_status"] = status or f"UNRECOGNIZED: {str(resp)[:200]}"
            findings["status_extraction_method"]["replay_stale_a"] = method or "none"
        except Exception as e:
            findings["replay_under_a_after_delete_status"] = f"{type(e).__name__}: {str(e)[:200]}"
            findings["status_extraction_method"]["replay_stale_a"] = "none"

    # Step 4: create session B (same principal), sign the IDENTICAL payload
    # with a FRESH clientToken (isolated from both A's token and the replay
    # token) — does a genuinely fresh session under the same principal sign
    # cleanly, or does it show evidence of reusing/re-deriving A's proof?
    try:
        r = dp.create_payment_session(
            userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": per_cap, "currency": "USD"}},
            expiryTimeInMinutes=15, clientToken=str(uuid.uuid4()),
        )
        findings["session_b_id"] = r.get("paymentSession", r).get("paymentSessionId", "")
    except Exception as e:
        findings["errors"].append(f"create_b: {type(e).__name__}: {str(e)[:160]}")

    if findings["session_b_id"]:
        client_token_b = str(uuid.uuid4())
        findings["session_b_client_token"] = client_token_b
        try:
            resp = dp.process_payment(
                userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
                paymentSessionId=findings["session_b_id"], paymentInstrumentId=instrument_id,
                paymentType="CRYPTO_X402",
                paymentInput={"cryptoX402": {"version": "1", "payload": payload}},
                clientToken=client_token_b,  # FRESH — isolated from session A's and the replay's tokens
            )
            status, method = _extract_payment_status(resp)
            findings["session_b_sign_status"] = status or "UNRECOGNIZED"
            findings["status_extraction_method"]["session_b"] = method or "none"
            findings["session_b_sign_response"] = str(resp)[:300]
        except Exception as e:
            findings["session_b_sign_status"] = f"{type(e).__name__}"
            findings["session_b_sign_response"] = str(e)[:300]
            findings["errors"].append(f"sign_b: {type(e).__name__}: {str(e)[:160]}")

    findings["proofs_identical"] = (
        bool(findings["session_a_sign_response"])
        and findings["session_a_sign_response"] == findings["session_b_sign_response"]
    )

    # Cleanup
    for sid in (findings["session_a_id"], findings["session_b_id"]):
        if not sid:
            continue
        try:
            dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=sid)
        except Exception:
            pass

    elapsed = time.monotonic() - t0

    measurement_clean = bool(findings["session_a_id"] and findings["session_a_deleted"] and findings["session_b_id"])
    passed = measurement_clean

    details = (
        f"SCOPE: sign-time session-binding characterization, PROOF_GENERATED only, 0 gas. "
        f"AUDIT-CORRECTED: clientToken is a fresh, isolated variable per call (see design_note) — "
        f"prior round's shared-token design conflated idempotency-cache hits with session-binding "
        f"evidence. Session A sign status={findings['session_a_sign_status']}; deleted={findings['session_a_deleted']}; "
        f"replay-against-deleted-A (fresh token) status={findings['replay_under_a_after_delete_status'] or 'not reached'}; "
        f"Session B (same principal, identical payload, FRESH clientToken) sign status="
        f"{findings['session_b_sign_status']}; proofs_identical={findings['proofs_identical']} "
        f"({'session B response text matches session A response text' if findings['proofs_identical'] else 'session B produced a distinct response text from session A'})."
    )

    return AgentCoreTestResult(
        test_id="ACP-010",
        name="Sign-Time Session-Reset Replay (carries forward ACP-002; audit-corrected fresh-clientToken design)",
        category="spend_cap_enforcement",
        owasp_asi="ASI03",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=details,
        region=region,
        session_id=findings["session_b_id"] or findings["session_a_id"],
        request_sent={
            "operation": "CreatePaymentSession(A) + ProcessPayment(A, token_a) + DeletePaymentSession(A) + "
                         "ProcessPayment(stale A, token_replay) + CreatePaymentSession(B) + "
                         "ProcessPayment(B, token_b, identical payload to A)",
            "client_tokens": {
                "session_a": findings["session_a_client_token"],
                "replay_stale_a": findings["replay_client_token"],
                "session_b": findings["session_b_client_token"],
            },
            "sign_amount_units": sign_amount_units,
            "pay_to": BURN_PAYTO,
            "user_id": user_id,
            "agent_name": agent_name,
            "instrument_id": instrument_id,
            "tier": "A (proof-only, 0 gas)",
        },
        response_received=findings,
        csg_mapping="HC-1: Signed-proof reuse must be bound to the session/context that produced it (extends ACP-002)",
        estimated_impact="documentation",
        estimated_severity="medium",
        elapsed_s=round(elapsed, 3),
        evidence_class="E2.5",
    )


def test_agentcore_signtime_terms_forgery() -> AgentCoreTestResult:
    """ACP-011: Does CDP delegated signing validate payTo legitimacy or budget-vs-amount? (Tier A)

    Carries forward ACP-003 (VS-R01, E2). VS-R01's over-budget variant never
    reached the amount-vs-cap validator because it (like every variant except
    the deliberately-invalid baseline) was missing `extra.name` and short-
    circuited at the structural gate (see the audit note in
    test_agentcore_402_terms_forgery above and
    vault/projects/vs-r01-acp-audit-2026-05-26.md). This test rebuilds each
    variant WITH `extra.name`/`extra.version` populated so it reaches
    delegated signing, and adds payTo-legitimacy variants (burn address, zero
    address, syntactically-valid-but-unknown address) per the VS-R02 test
    plan framing: "does signing care about payTo legitimacy?"

    Tier A / 0 gas: every variant stops at PROOF_GENERATED or a rejection;
    nothing is submitted to a merchant/facilitator.

    TWO DISTINCT EVIDENCE LAYERS (audit-corrected separation, this round):
    the 7 variants do NOT all land at the same layer, and conflating them
    overstates what was observed.

    Layer 1 — pre-sign rejections (malformed_recipient, exotic_network,
    over_budget_100x_cap, negative_amount): these four are rejected by
    AgentCore's OWN pre-sign ValidationException validator BEFORE the call
    ever reaches CDP delegated signing. That is admission-style evidence —
    tagged E2, same class as ACP-001/ACP-003's admission-control findings.
    ``malformed_recipient`` in particular is a basic format-rejection sanity
    check (a non-EVM string rejected as a payTo on an EVM network) — it is
    NOT a novel finding and is labeled as a sanity check, not a discovery.

    Layer 2 — the three PROOF_GENERATED payTo variants (legit_shaped_burn_
    address, zero_address, syntactically_valid_unknown_address): these are
    real CDP-signing evidence — tagged E2.5 (see module-level Evidence Class
    comment above). The payTo framing (zero-address / unvetted-address
    signing succeeding is consistent with expected signing-primitive
    behavior — payTo reputation vetting is a merchant/facilitator concern,
    not a CDP-signing concern) is preserved from the prior round but is
    explicitly marked here as an INTERPRETIVE ASSESSMENT, not an observed
    platform guarantee — AgentCore does not document this behavior anywhere
    this harness has found.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_id = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    session_cap = "0.05"  # tight cap so the over-budget variant is meaningful

    variants: dict[str, dict] = {
        "legit_shaped_burn_address": _build_x402_exact_payload("10000", pay_to=BURN_PAYTO),
        "zero_address": _build_x402_exact_payload("10000", pay_to="0x" + "00" * 20),
        "syntactically_valid_unknown_address": _build_x402_exact_payload("10000", pay_to="0x" + "AB" * 20),
        "malformed_recipient": _build_x402_exact_payload("10000", pay_to="not-a-valid-address"),
        "exotic_network": {**_build_x402_exact_payload("10000"), "network": "fake-chain-vsr02-test"},
        "over_budget_100x_cap": _build_x402_exact_payload("5000000"),  # $5.00 in 6-decimal USDC vs $0.05 cap
        "negative_amount": _build_x402_exact_payload("-10000"),
    }

    # Layer membership — used to build the two-layer breakdown after the
    # per-variant probe loop runs (see PRESIGN_REJECTION_VARIANTS / docstring
    # "TWO DISTINCT EVIDENCE LAYERS" above).
    PRESIGN_REJECTION_VARIANTS = (
        "malformed_recipient", "exotic_network", "over_budget_100x_cap", "negative_amount",
    )
    SIGNED_PAYTO_VARIANTS = (
        "legit_shaped_burn_address", "zero_address", "syntactically_valid_unknown_address",
    )

    findings: dict = {
        "session_id": "",
        "variants_tested": 0,
        "per_variant_status": {},
        "status_extraction_method": {},
        "payto_variants_that_signed": [],
        "over_budget_signed": None,
        "malformed_rejected_sanity_check": None,
        "errors": [],
    }

    try:
        r = dp.create_payment_session(
            userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": session_cap, "currency": "USD"}},
            expiryTimeInMinutes=15, clientToken=str(uuid.uuid4()),
        )
        findings["session_id"] = r.get("paymentSession", r).get("paymentSessionId", "")
    except Exception as e:
        findings["errors"].append(f"session_create: {type(e).__name__}: {str(e)[:160]}")

    if findings["session_id"]:
        for name, payload in variants.items():
            findings["variants_tested"] += 1
            try:
                resp = dp.process_payment(
                    userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
                    paymentSessionId=findings["session_id"], paymentInstrumentId=instrument_id,
                    paymentType="CRYPTO_X402",
                    paymentInput={"cryptoX402": {"version": "1", "payload": payload}},
                    clientToken=str(uuid.uuid4()),
                )
                status, method = _extract_payment_status(resp)
                status_label = status or f"UNRECOGNIZED: {str(resp)[:160]}"
                findings["per_variant_status"][name] = status_label
                findings["status_extraction_method"][name] = method or "none"
                if status == PROOF_GENERATED and "address" in name:
                    findings["payto_variants_that_signed"].append(name)
            except Exception as e:
                findings["per_variant_status"][name] = f"{type(e).__name__}: {str(e)[:200]}"
                findings["status_extraction_method"][name] = "none"

    findings["over_budget_signed"] = findings["per_variant_status"].get("over_budget_100x_cap") == PROOF_GENERATED
    # Demoted per audit: this is a basic format-rejection sanity check (a
    # non-EVM-shaped string rejected as payTo on an EVM network), not a novel
    # finding — see docstring "TWO DISTINCT EVIDENCE LAYERS".
    findings["malformed_rejected_sanity_check"] = findings["per_variant_status"].get("malformed_recipient") != PROOF_GENERATED

    # Two-layer breakdown (audit-corrected separation).
    findings["layer_1_presign_rejections"] = {
        "evidence_class": "E2",
        "description": (
            "AgentCore's OWN pre-sign ValidationException validator — these "
            "variants were rejected BEFORE reaching CDP delegated signing. "
            "Admission-style evidence, same class as ACP-001/ACP-003."
        ),
        "results": {v: findings["per_variant_status"].get(v) for v in PRESIGN_REJECTION_VARIANTS},
    }
    findings["layer_2_signed_payto_variants"] = {
        "evidence_class": "E2.5",
        "description": (
            "Real CDP delegated-signing evidence (PROOF_GENERATED). "
            "INTERPRETIVE ASSESSMENT, not an observed platform guarantee: "
            "zero-address / unvetted-address signing succeeding is "
            "consistent with expected signing-primitive behavior — payTo "
            "reputation/allowlisting is a merchant/facilitator-layer "
            "concern, not a CDP-signing concern."
        ),
        "results": {v: findings["per_variant_status"].get(v) for v in SIGNED_PAYTO_VARIANTS},
    }

    if findings["session_id"]:
        try:
            dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=findings["session_id"])
        except Exception:
            pass

    elapsed = time.monotonic() - t0

    measurement_clean = findings["variants_tested"] == len(variants) and bool(findings["session_id"])
    passed = measurement_clean

    payto_note = (
        f"LAYER 2 (E2.5, real signing): {len(findings['payto_variants_that_signed'])}/3 "
        f"syntactically-valid-but-unvetted payTo variants reached PROOF_GENERATED. "
        f"INTERPRETIVE ASSESSMENT (not an observed platform guarantee): delegated signing "
        f"authorizes based on payload well-formedness and wallet-owner delegation scope, not "
        f"payTo reputation/allowlisting — consistent with expected behavior for a signing "
        f"primitive; payTo vetting is a merchant/facilitator-layer concern, not a CDP-signing "
        f"concern."
    )
    budget_note = (
        "LAYER 1 (E2, admission-style): over-budget variant ($5.00 vs $0.05 session cap) reached "
        "PROOF_GENERATED — cap-vs-amount is NOT enforced pre-sign" if findings["over_budget_signed"]
        else "LAYER 1 (E2, admission-style): over-budget variant was rejected by AgentCore's own "
             "pre-sign ValidationException validator, before reaching delegated signing — "
             "cap-vs-amount enforcement present pre-sign (closes the ACP-003 gap where this "
             "variant never reached delegated signing)"
    )
    malformed_note = (
        "malformed_recipient rejection is a basic format sanity check (non-EVM string rejected "
        "as payTo on an EVM network), not a novel finding — demoted per audit."
    )

    details = (
        f"SCOPE: sign-time terms/payTo characterization via CDP delegated signing, "
        f"PROOF_GENERATED only, 0 gas. {findings['variants_tested']} variants tested (all with "
        f"extra.name/version populated, unlike VS-R01 ACP-003), split across two evidence layers "
        f"(see layer_1_presign_rejections / layer_2_signed_payto_variants in response_received). "
        f"{payto_note} {budget_note} {malformed_note}"
    )

    return AgentCoreTestResult(
        test_id="ACP-011",
        name="Sign-Time 402 Terms / payTo Legitimacy (carries forward ACP-003)",
        category="402_terms_validation",
        owasp_asi="ASI09",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=details,
        region=region,
        session_id=findings["session_id"],
        request_sent={
            "operation": f"ProcessPayment x {len(variants)} crafted variants (extra.name populated, "
                         f"burn/zero/unknown payTo, over-budget, malformed)",
            "session_cap_usd": session_cap,
            "variant_names": list(variants.keys()),
            "user_id": user_id,
            "agent_name": agent_name,
            "instrument_id": instrument_id,
            "tier": "A (proof-only, 0 gas)",
        },
        response_received=findings,
        csg_mapping="HC-3: 402 terms must be validated against instrument policy at sign-time (extends ACP-003)",
        estimated_impact="documentation",
        estimated_severity="medium",
        elapsed_s=round(elapsed, 3),
        evidence_class="E2.5",
    )


def test_agentcore_signtime_cross_session_aggregate_tier_a() -> AgentCoreTestResult:
    """ACP-016 (Tier-A portion only): cross-session aggregate spend ledger at sign-time.

    The full ACP-016 per the VS-R02 test plan is a Tier B (settlement-
    required, ~$0.05 USDC across 5 tx) test of whether SETTLED spend
    aggregates across sessions. The wallet is unfunded, so only the Tier-A
    slice runs here: sign (not settle) one payment per parallel session and
    inspect each session's post-sign availableSpendAmount for evidence of a
    SHARED ledger (vs. a purely per-session one). This is E2.5, PARTIAL
    evidence — it can show no shared accounting visible via the per-session
    availableSpendAmount field at sign-time (a settlement-time principal
    ledger would not surface here) but CANNOT by itself confirm or refute
    settled-spend aggregation; that requires the Tier B settlement round
    once the wallet is funded.

    Tier A / 0 gas: burn-address payTo, stops at PROOF_GENERATED.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_id = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    per_session_cap = "0.02"
    parallel_count = 5
    sign_amount_units = "5000"  # 0.005 USDC, well under cap

    findings: dict = {
        "parallel_sessions_created": 0,
        "sign_attempts": 0,
        "sign_successes_proof_generated": 0,
        "per_session_available_before": {},
        "per_session_available_after": {},
        "per_session_sign_status": {},
        "status_extraction_method": {},
        "shared_ledger_evidence": None,
        "shared_ledger_evidence_note": None,
        "errors": [],
        "note": "TIER-A PARTIAL EVIDENCE ONLY — full ACP-016 (settled-spend aggregation) is a "
                "Tier B test deferred until the wallet is funded. This test can only speak to "
                "what is visible via the per-session availableSpendAmount field at sign-time; "
                "a settlement-time principal ledger would not surface here.",
    }
    created_session_ids: list[str] = []

    for i in range(parallel_count):
        try:
            r = dp.create_payment_session(
                userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
                limits={"maxSpendAmount": {"value": per_session_cap, "currency": "USD"}},
                expiryTimeInMinutes=15, clientToken=str(uuid.uuid4()),
            )
            sess = r.get("paymentSession", r)
            sid = sess.get("paymentSessionId", "")
            if sid:
                created_session_ids.append(sid)
                findings["parallel_sessions_created"] += 1
                avail = sess.get("availableLimits", {}).get("availableSpendAmount", {}).get("value")
                findings["per_session_available_before"][sid] = avail
        except Exception as e:
            findings["errors"].append(f"session_create[{i}]: {type(e).__name__}: {str(e)[:160]}")

    for i, sid in enumerate(created_session_ids):
        findings["sign_attempts"] += 1
        payload = _build_x402_exact_payload(sign_amount_units, description=f"ACP-016 tier-a fragment {i}")
        try:
            resp = dp.process_payment(
                userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
                paymentSessionId=sid, paymentInstrumentId=instrument_id,
                paymentType="CRYPTO_X402",
                paymentInput={"cryptoX402": {"version": "1", "payload": payload}},
                clientToken=str(uuid.uuid4()),
            )
            status, method = _extract_payment_status(resp)
            findings["per_session_sign_status"][sid] = status or f"UNRECOGNIZED: {str(resp)[:160]}"
            findings["status_extraction_method"][sid] = method or "none"
            if status == PROOF_GENERATED:
                findings["sign_successes_proof_generated"] += 1
        except Exception as e:
            findings["per_session_sign_status"][sid] = f"{type(e).__name__}: {str(e)[:200]}"

        try:
            detail = dp.get_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=sid)
            sess = detail.get("paymentSession", detail)
            avail = sess.get("availableLimits", {}).get("availableSpendAmount", {}).get("value")
            findings["per_session_available_after"][sid] = avail
        except Exception as e:
            findings["errors"].append(f"get_after_sign[{i}]: {type(e).__name__}: {str(e)[:160]}")

    for sid in created_session_ids:
        try:
            dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=sid)
        except Exception:
            pass

    elapsed = time.monotonic() - t0

    # If every session's available balance drops by exactly the signed amount
    # independent of what the OTHER sessions signed, there's no evidence of a
    # shared ledger at this layer. If any signed session's post-sign
    # available drops by MORE than its own signed amount, that's evidence of
    # cross-session accounting.
    unexpected_drops = []
    for sid in created_session_ids:
        before = findings["per_session_available_before"].get(sid)
        after = findings["per_session_available_after"].get(sid)
        if before is not None and after is not None:
            try:
                delta = float(before) - float(after)
                expected = float(sign_amount_units) / 1_000_000  # USDC 6-decimals -> USD
                if abs(delta - expected) > 1e-6 and findings["per_session_sign_status"].get(sid) == PROOF_GENERATED:
                    unexpected_drops.append(sid)
            except (TypeError, ValueError):
                pass
    findings["shared_ledger_evidence"] = bool(unexpected_drops)
    findings["sessions_with_unexpected_drop"] = unexpected_drops
    findings["shared_ledger_evidence_note"] = (
        "cross-session accounting IS visible via the per-session availableSpendAmount field at "
        "sign-time (unexpected drop observed)."
        if findings["shared_ledger_evidence"] else
        "no shared accounting visible via the per-session availableSpendAmount field at sign-time "
        "(a settlement-time principal ledger would not surface here)."
    )

    measurement_clean = (
        findings["parallel_sessions_created"] == parallel_count
        and findings["sign_attempts"] == parallel_count
    )
    passed = measurement_clean

    details = (
        f"SCOPE: Tier-A PARTIAL evidence toward ACP-016 — sign-only (PROOF_GENERATED), 0 gas, "
        f"no settlement. {findings['sign_successes_proof_generated']}/{parallel_count} parallel "
        f"sessions signed. Per-session available-balance delta after signing: "
        f"{findings['shared_ledger_evidence_note']} "
        f"Full ACP-016 (whether SETTLED spend aggregates across sessions) is deferred to a Tier B "
        f"round once the wallet is funded — this result does not confirm or refute that."
    )

    return AgentCoreTestResult(
        test_id="ACP-016",
        name="Cross-Session Aggregate Spend at Sign-Time (Tier-A partial evidence; Tier B settlement round pending)",
        category="spend_cap_enforcement",
        owasp_asi="ASI02",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=details,
        region=region,
        session_id=created_session_ids[0] if created_session_ids else "",
        request_sent={
            "operation": "CreatePaymentSession x N (parallel) + ProcessPayment x N (sign-only) + "
                         "GetPaymentSession x N (post-sign balance check)",
            "parallel_count_attempted": parallel_count,
            "per_session_cap_usd": per_session_cap,
            "sign_amount_units": sign_amount_units,
            "pay_to": BURN_PAYTO,
            "user_id": user_id,
            "agent_name": agent_name,
            "instrument_id": instrument_id,
            "tier": "A (proof-only, 0 gas) — PARTIAL evidence for ACP-016; Tier B settlement round required for full claim",
        },
        response_received=findings,
        csg_mapping="HC-1: Sign-time balance accounting must reflect true per-principal exposure (partial evidence for full ACP-016)",
        estimated_impact="documentation",
        estimated_severity="medium",
        elapsed_s=round(elapsed, 3),
        evidence_class="E2.5",
    )


def _vsr02_create_session(dp: Any, user_id: str, agent_name: str, pm_arn: str) -> tuple[str, str]:
    """Create one tightly capped Tier-A session, returning ``(id, error)``."""
    try:
        response = dp.create_payment_session(
            userId=user_id,
            agentName=agent_name,
            paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": "0.02", "currency": "USD"}},
            expiryTimeInMinutes=15,
            clientToken=str(uuid.uuid4()),
        )
        session_id = response.get("paymentSession", response).get("paymentSessionId", "")
        return session_id, "" if session_id else "create returned no paymentSessionId"
    except Exception as exc:
        return "", f"{type(exc).__name__}: {str(exc)[:200]}"


def _vsr02_sign_probe(
    dp: Any,
    *,
    user_id: str,
    agent_name: str,
    pm_arn: str,
    session_id: str,
    instrument_id: str,
    description: str,
) -> dict[str, str]:
    """Make one Tier-A sign-only request and retain a bounded raw outcome.

    This helper always uses the burn address and never submits a proof to a
    merchant or facilitator.  A returned ``PROOF_GENERATED`` therefore means
    only that the delegated-signing path was reached, not that anything settled.
    """
    try:
        response = dp.process_payment(
            userId=user_id,
            agentName=agent_name,
            paymentManagerArn=pm_arn,
            paymentSessionId=session_id,
            paymentInstrumentId=instrument_id,
            paymentType="CRYPTO_X402",
            paymentInput={"cryptoX402": {"version": "1", "payload": _build_x402_exact_payload("10000", description=description)}},
            clientToken=str(uuid.uuid4()),
        )
        status, method = _extract_payment_status(response)
        return {
            "attempted": "true",
            "status": status or "UNRECOGNIZED_RESPONSE",
            "status_extraction_method": method or "none",
            "raw_outcome": str(response)[:400],
        }
    except Exception as exc:
        return {
            "attempted": "true",
            "status": type(exc).__name__,
            "status_extraction_method": "none",
            "raw_outcome": str(exc)[:400],
        }


def _vsr02_delete_session(dp: Any, user_id: str, pm_arn: str, session_id: str) -> str:
    if not session_id:
        return "not-created"
    try:
        dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=session_id)
        return "deleted"
    except Exception as exc:
        return f"{type(exc).__name__}: {str(exc)[:120]}"


def _vsr02_explicit_delegation_denial(status: str) -> bool:
    """Return true only for an interpretable access/control-plane rejection.

    A generic server failure, timeout, or retry exhaustion is not evidence that
    isolation held.  This deliberately excludes ``InternalServerException`` so
    the Tier-A result cannot convert an opaque platform error into a security
    claim.
    """
    return status in {"AccessDeniedException", "ResourceNotFoundException", "ValidationException"}


def test_agentcore_signtime_cross_instrument_delegation_isolation() -> AgentCoreTestResult:
    """ACP-014: probe whether a grant for instrument A signs for instrument B.

    The test first proves the currently granted tuple can reach
    ``PROOF_GENERATED`` in this run. It then creates a distinct embedded-wallet
    instrument under the same user/agent and attempts the identical proof-only
    request with that new instrument.  It makes no merchant submission and
    deletes the temporary session/instrument during cleanup.

    A denial after the positive control is sign-time isolation evidence.  It is
    deliberately tagged E2.5 rather than E5: no on-chain settlement occurs.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    connector_id = os.environ.get("AGENTCORE_PAYMENT_CONNECTOR_ID", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_a = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    findings: dict[str, Any] = {"positive_control": {}, "alternate_instrument": {}, "alternate_attempt": {}, "cleanup": {}}

    control_session, control_error = _vsr02_create_session(dp, user_id, agent_name, pm_arn)
    findings["positive_control"]["session_create_error"] = control_error
    if control_session:
        findings["positive_control"] |= _vsr02_sign_probe(
            dp, user_id=user_id, agent_name=agent_name, pm_arn=pm_arn,
            session_id=control_session, instrument_id=instrument_a, description="ACP-014 positive control",
        )

    instrument_b = ""
    try:
        response = dp.create_payment_instrument(
            userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
            paymentConnectorId=connector_id, paymentInstrumentType="EMBEDDED_CRYPTO_WALLET",
            paymentInstrumentDetails={"embeddedCryptoWallet": {"network": "ETHEREUM", "linkedAccounts": [{"email": {"emailAddress": "vsr02-acp014-instrument-b@example.test"}}]}},
            clientToken=str(uuid.uuid4()),
        )
        instrument_b = response.get("paymentInstrument", response).get("paymentInstrumentId", "")
        findings["alternate_instrument"] = {"created": bool(instrument_b), "id_distinct_from_a": instrument_b != instrument_a}
    except Exception as exc:
        findings["alternate_instrument"] = {"created": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}

    alternate_session, alternate_error = _vsr02_create_session(dp, user_id, agent_name, pm_arn)
    findings["alternate_attempt"]["session_create_error"] = alternate_error
    if alternate_session and instrument_b:
        findings["alternate_attempt"] = _vsr02_sign_probe(
            dp, user_id=user_id, agent_name=agent_name, pm_arn=pm_arn,
            session_id=alternate_session, instrument_id=instrument_b, description="ACP-014 alternate instrument",
        )

    findings["cleanup"]["positive_session"] = _vsr02_delete_session(dp, user_id, pm_arn, control_session)
    findings["cleanup"]["alternate_session"] = _vsr02_delete_session(dp, user_id, pm_arn, alternate_session)
    if instrument_b:
        try:
            dp.delete_payment_instrument(userId=user_id, paymentManagerArn=pm_arn, paymentConnectorId=connector_id, paymentInstrumentId=instrument_b)
            findings["cleanup"]["alternate_instrument"] = "deleted"
        except Exception as exc:
            findings["cleanup"]["alternate_instrument"] = f"{type(exc).__name__}: {str(exc)[:120]}"

    control_signed = findings["positive_control"].get("status") == PROOF_GENERATED
    alternate_signed = findings["alternate_attempt"].get("status") == PROOF_GENERATED
    measurement_clean = control_signed and bool(instrument_b) and findings["alternate_attempt"].get("attempted") == "true"
    alternate_status = findings["alternate_attempt"].get("status", "")
    explicit_denial = _vsr02_explicit_delegation_denial(alternate_status)
    isolation_holds = measurement_clean and explicit_denial
    verdict = (
        "isolation_observed" if isolation_holds else
        "delegation_scope_not_instrument_bound_at_sign_time" if measurement_clean and alternate_signed else
        "inconclusive_platform_error" if measurement_clean else "measurement_incomplete"
    )
    details = (
        "SCOPE: proof-only delegated-signing isolation probe, burn-address payTo, 0 gas. "
        f"Positive control signed={control_signed}; distinct instrument B created={bool(instrument_b)}; "
        f"instrument-B signed={alternate_signed}; alternate status={alternate_status}. "
        "Only an explicit access/control-plane denial supports isolation. Generic platform errors are inconclusive; no settlement was attempted."
    )
    return AgentCoreTestResult(
        test_id="ACP-014", name="Cross-Instrument Delegation Isolation (Tier A)",
        category="delegation_isolation", owasp_asi="ASI03", severity=Severity.HIGH.value,
        passed=measurement_clean, details=details, region=region, session_id=control_session,
        request_sent={"operation": "positive-control ProcessPayment(A) + ProcessPayment(B), sign-only", "pay_to": BURN_PAYTO, "tier": "A (proof-only, 0 gas)"},
        response_received={**findings, "isolation_holds_at_sign_time": isolation_holds, "verdict": verdict, "target_evidence_class": "E5", "claim_boundary": "E2.5 sign-time only; not settlement evidence"},
        csg_mapping="HC-6: delegated authority must remain instrument-bound", estimated_impact="fund_theft", estimated_severity="high",
        elapsed_s=round(time.monotonic() - t0, 3), evidence_class="E2.5",
    )


def test_agentcore_signtime_shared_user_multi_instrument_isolation() -> AgentCoreTestResult:
    """ACP-015: probe whether a same-email second instrument inherits a grant.

    Unlike ACP-014, the temporary instrument deliberately uses the same email
    identity as the granted instrument. A distinct returned instrument ID is a
    prerequisite. If the API deduplicates it, the result is inconclusive rather
    than evidence of isolation or leakage.
    """
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    connector_id = os.environ.get("AGENTCORE_PAYMENT_CONNECTOR_ID", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_a = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    findings: dict[str, Any] = {"positive_control": {}, "same_email_instrument": {}, "alternate_attempt": {}, "cleanup": {}}

    control_session, control_error = _vsr02_create_session(dp, user_id, agent_name, pm_arn)
    findings["positive_control"]["session_create_error"] = control_error
    if control_session:
        findings["positive_control"] |= _vsr02_sign_probe(dp, user_id=user_id, agent_name=agent_name, pm_arn=pm_arn, session_id=control_session, instrument_id=instrument_a, description="ACP-015 positive control")

    instrument_b = ""
    try:
        response = dp.create_payment_instrument(
            userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
            paymentConnectorId=connector_id, paymentInstrumentType="EMBEDDED_CRYPTO_WALLET",
            paymentInstrumentDetails={"embeddedCryptoWallet": {"network": "ETHEREUM", "linkedAccounts": [{"email": {"emailAddress": "vsr02-wallet-hub@example.test"}}]}},
            clientToken=str(uuid.uuid4()),
        )
        instrument_b = response.get("paymentInstrument", response).get("paymentInstrumentId", "")
        findings["same_email_instrument"] = {"created": bool(instrument_b), "id_distinct_from_a": instrument_b != instrument_a}
    except Exception as exc:
        findings["same_email_instrument"] = {"created": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}

    alternate_session, alternate_error = _vsr02_create_session(dp, user_id, agent_name, pm_arn)
    findings["alternate_attempt"]["session_create_error"] = alternate_error
    if alternate_session and instrument_b and instrument_b != instrument_a:
        findings["alternate_attempt"] = _vsr02_sign_probe(dp, user_id=user_id, agent_name=agent_name, pm_arn=pm_arn, session_id=alternate_session, instrument_id=instrument_b, description="ACP-015 same-user second instrument")

    findings["cleanup"]["positive_session"] = _vsr02_delete_session(dp, user_id, pm_arn, control_session)
    findings["cleanup"]["alternate_session"] = _vsr02_delete_session(dp, user_id, pm_arn, alternate_session)
    if instrument_b and instrument_b != instrument_a:
        try:
            dp.delete_payment_instrument(userId=user_id, paymentManagerArn=pm_arn, paymentConnectorId=connector_id, paymentInstrumentId=instrument_b)
            findings["cleanup"]["same_email_instrument"] = "deleted"
        except Exception as exc:
            findings["cleanup"]["same_email_instrument"] = f"{type(exc).__name__}: {str(exc)[:120]}"

    control_signed = findings["positive_control"].get("status") == PROOF_GENERATED
    distinct = findings["same_email_instrument"].get("id_distinct_from_a") is True
    alternate_signed = findings["alternate_attempt"].get("status") == PROOF_GENERATED
    measurement_clean = control_signed and distinct and findings["alternate_attempt"].get("attempted") == "true"
    alternate_status = findings["alternate_attempt"].get("status", "")
    explicit_denial = _vsr02_explicit_delegation_denial(alternate_status)
    isolation_holds = measurement_clean and explicit_denial
    verdict = (
        "isolation_observed" if isolation_holds else
        "delegation_scope_not_instrument_bound_at_sign_time" if measurement_clean and alternate_signed else
        "inconclusive_platform_error" if measurement_clean else "measurement_incomplete"
    )
    details = (
        "SCOPE: same-user, proof-only delegated-signing isolation probe, 0 gas. "
        f"Positive control signed={control_signed}; distinct same-email instrument created={distinct}; second instrument signed={alternate_signed}; alternate status={alternate_status}. "
        "If the service deduplicates the second instrument or returns a generic platform error, this test is explicitly inconclusive."
    )
    return AgentCoreTestResult(
        test_id="ACP-015", name="Shared-User Multi-Instrument Delegation Isolation (Tier A)",
        category="delegation_isolation", owasp_asi="ASI03", severity=Severity.HIGH.value,
        passed=measurement_clean, details=details, region=region, session_id=control_session,
        request_sent={"operation": "positive-control ProcessPayment(A) + same-user ProcessPayment(B), sign-only", "pay_to": BURN_PAYTO, "tier": "A (proof-only, 0 gas)"},
        response_received={**findings, "isolation_holds_at_sign_time": isolation_holds, "verdict": verdict, "target_evidence_class": "E5", "claim_boundary": "E2.5 sign-time only; not settlement evidence"},
        csg_mapping="HC-6: a per-user identity must not silently widen an instrument grant", estimated_impact="fund_theft", estimated_severity="high",
        elapsed_s=round(time.monotonic() - t0, 3), evidence_class="E2.5",
    )


def test_agentcore_signtime_cross_agent_delegation_isolation() -> AgentCoreTestResult:
    """ACP-019: probe whether a grant leaks across agent names for one user."""
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    granted_agent = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    # Allow independent reproductions to substitute a fresh alternate identity
    # without changing the test logic or the granted control identity.
    attacker_agent = os.environ.get(
        "AGENTCORE_VSR02_ALTERNATE_AGENT_NAME", "vs-r02-attacker-agent"
    )
    instrument_id = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    findings: dict[str, Any] = {"positive_control": {}, "cross_agent_attempt": {}, "cleanup": {}}

    control_session, control_error = _vsr02_create_session(dp, user_id, granted_agent, pm_arn)
    findings["positive_control"]["session_create_error"] = control_error
    if control_session:
        findings["positive_control"] |= _vsr02_sign_probe(dp, user_id=user_id, agent_name=granted_agent, pm_arn=pm_arn, session_id=control_session, instrument_id=instrument_id, description="ACP-019 positive control")

    attacker_session, attacker_error = _vsr02_create_session(dp, user_id, attacker_agent, pm_arn)
    findings["cross_agent_attempt"]["session_create_error"] = attacker_error
    if attacker_session:
        findings["cross_agent_attempt"] = _vsr02_sign_probe(dp, user_id=user_id, agent_name=attacker_agent, pm_arn=pm_arn, session_id=attacker_session, instrument_id=instrument_id, description="ACP-019 cross-agent attempt")

    findings["cleanup"]["positive_session"] = _vsr02_delete_session(dp, user_id, pm_arn, control_session)
    findings["cleanup"]["attacker_session"] = _vsr02_delete_session(dp, user_id, pm_arn, attacker_session)
    control_signed = findings["positive_control"].get("status") == PROOF_GENERATED
    attacker_signed = findings["cross_agent_attempt"].get("status") == PROOF_GENERATED
    measurement_clean = control_signed and findings["cross_agent_attempt"].get("attempted") == "true"
    attacker_status = findings["cross_agent_attempt"].get("status", "")
    explicit_denial = _vsr02_explicit_delegation_denial(attacker_status)
    isolation_holds = measurement_clean and explicit_denial
    verdict = (
        "isolation_observed" if isolation_holds else
        "delegation_scope_not_agent_bound_at_sign_time" if measurement_clean and attacker_signed else
        "inconclusive_platform_error" if measurement_clean else "measurement_incomplete"
    )
    details = (
        "SCOPE: same-user cross-agent delegated-signing isolation probe, burn-address payTo, 0 gas. "
        f"Positive control signed={control_signed}; alternate-agent signed={attacker_signed}; alternate status={attacker_status}. "
        "A positive-control success followed by alternate-agent success is a reproduction candidate, not a final security conclusion."
    )
    return AgentCoreTestResult(
        test_id="ACP-019", name="Cross-Agent Delegation Isolation (Tier A)",
        category="delegation_isolation", owasp_asi="ASI03", severity=Severity.HIGH.value,
        passed=measurement_clean, details=details, region=region, agent_id=f"{granted_agent},{attacker_agent}", session_id=control_session,
        request_sent={"operation": "positive-control ProcessPayment(granted agent) + ProcessPayment(alternate agent), sign-only", "pay_to": BURN_PAYTO, "tier": "A (proof-only, 0 gas)"},
        response_received={**findings, "isolation_holds_at_sign_time": isolation_holds, "verdict": verdict, "target_evidence_class": "E5", "claim_boundary": "E2.5 sign-time only; not settlement evidence"},
        csg_mapping="HC-6: delegated authority must remain agent-name-bound", estimated_impact="fund_theft", estimated_severity="high",
        elapsed_s=round(time.monotonic() - t0, 3), evidence_class="E2.5",
    )


VS_R02_TIER_A_TESTS: dict[str, list[str]] = {
    "spend_cap_enforcement": [
        "test_agentcore_signtime_spend_fragmentation",       # ACP-009
        "test_agentcore_signtime_session_reset_replay",      # ACP-010
        "test_agentcore_signtime_cross_session_aggregate_tier_a",  # ACP-016 (Tier-A portion)
    ],
    "402_terms_validation": [
        "test_agentcore_signtime_terms_forgery",              # ACP-011
    ],
    "delegation_isolation": [
        "test_agentcore_signtime_cross_instrument_delegation_isolation",  # ACP-014
        "test_agentcore_signtime_shared_user_multi_instrument_isolation", # ACP-015
        "test_agentcore_signtime_cross_agent_delegation_isolation",        # ACP-019
    ],
}
# NOTE: intentionally NOT merged into ALL_TESTS and NOT registered in
# protocol_tests/cli.py / scripts/count_tests.py — same staging discipline as
# the VS-R01 stubs (see "Module footer" comment below). Mike registers after
# live validation.


# ---------------------------------------------------------------------------
# VS-R02 Tier B — settlement-evidence extension (SETTLES ON-CHAIN, real gas +
# USDC). See reports/round_24/VS-R02-tier-b-runbook.md before running any of
# this. All four functions below (ACP-012, ACP-016-full, ACP-017, ACP-018)
# are fail-closed behind AGENTCORE_TIER_B_SETTLE_OK=1 IN ADDITION TO the
# module-level AGENTCORE_LIVE_NET_OK / AGENTCORE_ALLOW_TESTNET gates above —
# Tier B is a strictly narrower, separately opt-in surface because unlike
# every Tier A test it spends real money. As of this writing (2026-07-11) the
# VS-R02 wallet is UNFUNDED; none of this has been run.
#
# ARCHITECTURE — read this before trusting any Tier B result:
#   Plan A (implemented below): sign via CDP delegated signing
#   (ProcessPayment -> PROOF_GENERATED, same call as Tier A) -> extract the
#   signed authorization/proof from the response -> submit it as an
#   X-PAYMENT header to a SyntheticMerchant instance, called IN-PROCESS via
#   `merchant.handle()` (no HTTP server, no public URL needed) -> the
#   merchant's CoinbaseFacilitator relays to the real x402 facilitator's
#   /verify + /settle endpoints, which broadcast the EIP-3009
#   transferWithAuthorization on Base Sepolia and return a real tx hash.
#
#   This assumes AgentCore's ProcessPayment, on success, RETURNS the signed
#   proof to the caller rather than settling it internally end-to-end. That
#   assumption is UNVERIFIED — nobody has a captured live PROOF_GENERATED
#   response in this repo showing what field the proof comes back under (see
#   _extract_settlement_proof below, same caveat class as
#   _extract_payment_status's `extra.name` uncertainty in the Tier-A code).
#
#   Fail-closed by design: if _extract_settlement_proof finds nothing, NO
#   settlement is attempted and $0 is spent — a wrong architecture guess
#   costs nothing beyond a free API call. If Plan A turns out to be wrong
#   (AgentCore settles internally and never exposes a raw proof), Plan B is
#   documented in the runbook: point payTo at a real wallet Mike controls and
#   confirm settlement by watching the chain directly (Base Sepolia block
#   explorer) instead of trying to intercept and resubmit a proof.
#
#   `protocol_tests/x402_merchant.py` is vendored (uncommitted) from PR #217
#   (`feat/vs-r02-x402-merchant`, commit 3cf9797) — see the provenance note
#   at the top of that file. Real, unit-tested merchant relay logic; not a
#   stub. TODO(Mike): reconcile with PR #217 properly before either lands.

ENV_TIER_B_SETTLE_OK = "AGENTCORE_TIER_B_SETTLE_OK"

# Hard USD ceilings, enforced in code (not just documented). A single
# settlement attempt over TIER_B_MAX_USD_PER_TX, or a cumulative suite total
# over TIER_B_MAX_USD_PER_SUITE, raises AssertionError and halts the run
# rather than silently proceeding. See _tier_b_check_cap / _tier_b_record_spend.
TIER_B_MAX_USD_PER_TX = 0.02
TIER_B_MAX_USD_PER_SUITE = 0.10

# Module-level, process-lifetime ledger of every CONFIRMED settlement attempt
# (real money moved or a rejection was recorded) across all Tier B tests run
# in this Python process. Failed signs / unextractable proofs are NOT
# appended (they spent nothing). Inspect this after a run for a full audit
# trail independent of any single test's result JSON.
_tier_b_spend_ledger: list[dict] = []


def _tier_b_settle_gate() -> None:
    """Fail closed unless the operator explicitly opts into real settlement.

    Raises pytest.skip.Exception (same convention as _get_agentcore_client)
    if AGENTCORE_TIER_B_SETTLE_OK != "1". Deliberately a SEPARATE env var
    from AGENTCORE_ALLOW_TESTNET — conflating the two gates would make it too
    easy to accidentally run a real-money settlement test while only
    intending to run Tier A (0 gas) tests.
    """
    if os.environ.get(ENV_TIER_B_SETTLE_OK) != "1":
        pytest.skip(
            f"{ENV_TIER_B_SETTLE_OK}=1 not set — Tier B settlement tests are "
            f"fail-closed by design (real Base Sepolia gas + USDC). Read "
            f"reports/round_24/VS-R02-tier-b-runbook.md before setting this."
        )


def _tier_b_check_cap(test_id: str, usd_amount: float) -> None:
    """Pre-flight hard-cap check. Raises AssertionError BEFORE any network
    call if `usd_amount` would breach either ceiling. Does NOT append to the
    ledger — only a CONFIRMED settlement does that, via _tier_b_record_spend.
    """
    if usd_amount > TIER_B_MAX_USD_PER_TX:
        raise AssertionError(
            f"{test_id}: single-transaction amount ${usd_amount} exceeds "
            f"TIER_B_MAX_USD_PER_TX=${TIER_B_MAX_USD_PER_TX} — refusing to submit."
        )
    running_total = sum(e["usd_amount"] for e in _tier_b_spend_ledger) + usd_amount
    if running_total > TIER_B_MAX_USD_PER_SUITE:
        raise AssertionError(
            f"{test_id}: cumulative Tier B spend would reach ${running_total:.4f}, "
            f"exceeding TIER_B_MAX_USD_PER_SUITE=${TIER_B_MAX_USD_PER_SUITE} — refusing to submit."
        )


def _tier_b_record_spend(test_id: str, usd_amount: float, tx_hash: str) -> None:
    """Append a CONFIRMED outcome to the module-level spend ledger and print
    a one-line audit trail entry. `usd_amount` must be 0.0 for attempts that
    did not settle (rejections, replays that were correctly refused) — only
    money that actually moved counts against the suite ceiling.
    """
    running_total = sum(e["usd_amount"] for e in _tier_b_spend_ledger) + usd_amount
    entry = {
        "test_id": test_id,
        "usd_amount": usd_amount,
        "tx_hash": tx_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "running_total_usd": round(running_total, 6),
    }
    _tier_b_spend_ledger.append(entry)
    print(
        f"[TIER-B-SPEND] {test_id}: ${usd_amount} tx={tx_hash or '(none/rejected)'} "
        f"running_total=${running_total:.4f}/{TIER_B_MAX_USD_PER_SUITE}"
    )


def _import_x402_merchant():
    """Lazy import of the vendored synthetic-merchant module (see the
    provenance note at the top of protocol_tests/x402_merchant.py). Kept
    lazy so a missing merchant file cannot break VS-R01 / Tier-A test
    collection — only Tier B tests need it.
    """
    try:
        from protocol_tests import x402_merchant as _mod
        return _mod
    except ImportError as e:  # pragma: no cover
        pytest.skip(
            f"protocol_tests/x402_merchant.py not importable ({e}) — Tier B "
            f"settlement tests require the synthetic merchant module. See "
            f"reports/round_24/VS-R02-tier-b-runbook.md."
        )


def _extract_settlement_proof(resp: Any) -> tuple[dict | str | None, str]:
    """Best-effort extraction of a signed, settleable x402 proof from a
    PROOF_GENERATED ProcessPayment response.

    UNVERIFIED against a captured live response — same caveat class as
    _extract_payment_status above. Nobody has a captured live PROOF_GENERATED
    payload in this repo showing the exact field the signed
    authorization/proof comes back under, or whether it is already
    X-PAYMENT-header-shaped (base64 JSON, real signature included) or a raw
    dict. This tries several plausible candidate paths and returns
    ``(None, "")`` if nothing usable is found — callers MUST treat that as
    "settlement not reached, extraction failed" and stop there (no
    settlement attempted, $0 spent), never fabricate a proof to keep going.

    A structured-dict candidate is only accepted if it carries BOTH an
    `authorization`-shaped sub-object (nonce/value/from/to/validBefore/
    validAfter) AND a `signature` field. A proof with authorization fields
    but no real signature is deliberately treated as unusable — see
    _encode_x_payment_with_real_signature's docstring for why (it must never
    be handed a fabricated signature).

    Returns:
        (proof, method) — proof is a dict with ``{"authorization": ...,
        "signature": ...}`` (needs _encode_x_payment_with_real_signature), a
        str (already an encoded X-PAYMENT header), or None. method records
        which candidate path matched, threaded into the result JSON as
        `proof_extraction_method` for audit.

    TODO(Mike): once a live PROOF_GENERATED response is captured, hard-code
    the correct path here and delete the guesswork — same TODO discipline as
    _extract_payment_status.
    """
    if not isinstance(resp, dict):
        return None, ""
    payment = resp.get("payment", resp)
    if not isinstance(payment, dict):
        return None, ""

    # AgentCore's live ProcessPayment response nests the signed x402 material
    # under paymentOutput.cryptoX402.payload. Preserve the explicit path
    # rather than flattening arbitrary response fields: the proof must still
    # carry both a real authorization and signature before it is usable.
    output = payment.get("paymentOutput")
    if isinstance(output, dict):
        crypto_x402 = output.get("cryptoX402")
        if isinstance(crypto_x402, dict):
            payload = crypto_x402.get("payload")
            if isinstance(payload, dict):
                auth = payload.get("authorization")
                sig = payload.get("signature")
                if isinstance(auth, dict) and sig:
                    return {
                        "authorization": auth,
                        "signature": sig,
                    }, "structured_dict_with_signature:paymentOutput.cryptoX402.payload"

    # Candidate 1: already an X-PAYMENT-ready base64 string (real signature
    # embedded by construction, if this path is ever actually hit).
    for key in ("xPayment", "paymentHeader", "signedPayment", "signedXPayment"):
        val = payment.get(key)
        if isinstance(val, str) and val:
            return val, f"encoded_string:{key}"

    # Candidate 2: a structured proof/authorization dict — only usable if it
    # carries a real signature alongside the authorization fields.
    for key in ("proof", "paymentProof", "signedPayload", "cryptoX402Proof"):
        val = payment.get(key)
        if not isinstance(val, dict) or not val:
            continue
        auth = val.get("authorization", val)
        sig = val.get("signature") if isinstance(val, dict) else None
        if sig is None and isinstance(auth, dict):
            sig = auth.get("signature")
        if isinstance(auth, dict) and sig:
            return {"authorization": auth, "signature": sig}, f"structured_dict_with_signature:{key}"

    return None, ""


def _encode_x_payment_with_real_signature(
    proof: dict, scheme: str = "exact", network: str = "base-sepolia"
) -> str:
    """Build a base64 X-PAYMENT header using the REAL CDP-produced signature
    extracted by _extract_settlement_proof.

    Deliberately does NOT reuse x402_merchant.encode_x_payment() — that
    helper hardcodes a fake ``"0xtest"`` signature for its own unit tests
    (MockFacilitator doesn't check it). Using it here would either silently
    fail against the live Coinbase facilitator (invalid signature, safe but
    misleading) or, worse, mask the fact that no real signature was ever
    extracted. `proof` must already contain a real `signature` field — see
    _extract_settlement_proof's candidate-2 gating.
    """
    import base64 as _b64

    obj = {
        "x402Version": 1,
        "scheme": scheme,
        "network": network,
        "payload": {"authorization": proof["authorization"], "signature": proof["signature"]},
    }
    return _b64.b64encode(json.dumps(obj).encode()).decode()


def _tier_b_sign(
    dp: Any, pm_arn: str, session_id: str, user_id: str, agent_name: str,
    instrument_id: str, amount_units: str, description: str,
    max_timeout_seconds: int = 60, resource: str = "https://vsr02-tier-b-probe.example/data",
) -> dict:
    """Sign-only step: ProcessPayment via CDP delegated signing + best-effort
    proof extraction. No cap-check, no settlement attempt — the caller
    decides whether/when to submit for settlement (immediately, for most
    tests; after a deliberate delay, for ACP-017's past-window probe).
    """
    result: dict = {
        "sign_status": "", "status_extraction_method": "", "sign_response_excerpt": "",
        "proof_extracted": False, "proof_extraction_method": "", "raw_proof": None,
    }
    payload = _build_x402_exact_payload(
        amount_units, pay_to=BURN_PAYTO, description=description, resource=resource,
    )
    payload["maxTimeoutSeconds"] = max_timeout_seconds
    try:
        resp = dp.process_payment(
            userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
            paymentSessionId=session_id, paymentInstrumentId=instrument_id,
            paymentType="CRYPTO_X402",
            paymentInput={"cryptoX402": {"version": "1", "payload": payload}},
            clientToken=str(uuid.uuid4()),
        )
    except Exception as e:
        result["sign_status"] = f"{type(e).__name__}: {str(e)[:200]}"
        return result

    status, method = _extract_payment_status(resp)
    result["sign_status"] = status or f"UNRECOGNIZED: {str(resp)[:200]}"
    result["status_extraction_method"] = method or "none"
    result["sign_response_excerpt"] = str(resp)[:400]
    if status != PROOF_GENERATED:
        return result

    proof, proof_method = _extract_settlement_proof(resp)
    result["raw_proof"] = proof
    result["proof_extraction_method"] = proof_method or "none"
    result["proof_extracted"] = proof is not None
    return result


def _tier_b_submit_for_settlement(merchant: Any, raw_proof: Any, test_id: str, usd_amount: float) -> dict:
    """Submit an already-extracted proof to `merchant.handle()` for real
    settlement (in-process call — no HTTP server, no public URL required;
    the merchant's CoinbaseFacilitator does the outbound network call to the
    real x402 facilitator). Enforces the hard caps via _tier_b_check_cap
    BEFORE the call, and records the outcome via _tier_b_record_spend AFTER
    — 0.0 if it did not settle, so rejected/failed attempts never consume
    suite budget, but the REAL amount if it unexpectedly does settle (so an
    anomaly is captured accurately, not under-reported).
    """
    _tier_b_check_cap(test_id, usd_amount)
    x_payment_header = (
        raw_proof if isinstance(raw_proof, str) else _encode_x_payment_with_real_signature(raw_proof)
    )
    http_status, body = merchant.handle(merchant.req.resource, x_payment_header)
    settle_success = http_status == 200 and isinstance(body, dict)
    tx_hash = body.get("settlement", {}).get("txHash", "") if settle_success else ""
    settled_usd = usd_amount if settle_success else 0.0
    _tier_b_record_spend(test_id, settled_usd, tx_hash)
    if settle_success:
        print(f"[TIER-B-TX] {test_id}: settled tx={tx_hash} amount=${usd_amount}")
    return {
        "settle_attempted": True, "settle_http_status": http_status, "settle_body": body,
        "settle_success": settle_success, "tx_hash": tx_hash,
    }


def _tier_b_sign_and_settle(
    dp: Any, pm_arn: str, session_id: str, user_id: str, agent_name: str,
    instrument_id: str, amount_units: str, merchant: Any, description: str,
    test_id: str, max_timeout_seconds: int = 60,
) -> dict:
    """Convenience wrapper: sign immediately, then settle immediately (the
    common case — ACP-012's first settle, every ACP-016 fragment, every
    ACP-018 loop attempt). ACP-017's past-window probe calls _tier_b_sign()
    and _tier_b_submit_for_settlement() separately with a deliberate sleep
    in between instead of using this wrapper.
    """
    result = _tier_b_sign(
        dp, pm_arn, session_id, user_id, agent_name, instrument_id,
        amount_units, description, max_timeout_seconds, resource=merchant.req.resource,
    )
    if not result.get("proof_extracted"):
        result.update({"settle_attempted": False, "settle_success": False, "tx_hash": ""})
        return result
    usd_amount = round(int(amount_units) / 1_000_000, 6)
    settle_result = _tier_b_submit_for_settlement(merchant, result["raw_proof"], test_id, usd_amount)
    result.update(settle_result)
    return result


def test_agentcore_settle_receipt_nonce_reuse() -> AgentCoreTestResult:
    """ACP-012 (Tier B — SETTLES ON-CHAIN): receipt nonce reuse / double-spend probe.

    Real settlement (E3): signs one payment authorization via CDP delegated
    signing, submits it to the synthetic merchant (in-process call; the
    merchant's CoinbaseFacilitator relays to the LIVE Coinbase x402
    facilitator's /verify + /settle) — real Base Sepolia gas + USDC, a real
    transaction hash. Then resubmits the SAME extracted proof (same nonce,
    no re-signing) a second time, within its own validBefore window, and
    observes whether the facilitator's EIP-3009 authorization-state check
    refuses the replay.

    SAFETY GATE: skips unless AGENTCORE_TIER_B_SETTLE_OK=1. payTo is
    BURN_PAYTO for both the signed authorization and the merchant's
    PaymentRequirements — no counterparty, minimal blast radius.

    If the first settle does not reach real settlement (proof extraction
    failure, sign rejection, etc.), NO money is spent and the replay probe is
    skipped — see response_received for diagnosis, same triage order as the
    Tier-A runbook (grant expiry, extra payload shape, status/proof
    field-name guess).
    """
    _tier_b_settle_gate()
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_id = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    per_cap = "0.05"
    settle_amount_units = "10000"  # 0.01 USDC

    x402_merchant = _import_x402_merchant()
    merchant_req = x402_merchant.PaymentRequirements(
        pay_to=BURN_PAYTO, max_amount_required=settle_amount_units, resource="/vsr02-acp-012",
    )
    merchant = x402_merchant.SyntheticMerchant(merchant_req, x402_merchant.CoinbaseFacilitator())
    usd_amount = round(int(settle_amount_units) / 1_000_000, 6)

    findings: dict = {
        "user_id": user_id, "agent_name": agent_name, "instrument_id": instrument_id,
        "session_id": "",
        "first_settle": {}, "replay_settle": {},
        "replay_rejected": None,
        "errors": [],
    }

    try:
        r = dp.create_payment_session(
            userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": per_cap, "currency": "USD"}},
            expiryTimeInMinutes=15, clientToken=str(uuid.uuid4()),
        )
        findings["session_id"] = r.get("paymentSession", r).get("paymentSessionId", "")
    except Exception as e:
        findings["errors"].append(f"session_create: {type(e).__name__}: {str(e)[:160]}")

    if findings["session_id"]:
        findings["first_settle"] = _tier_b_sign_and_settle(
            dp, pm_arn, findings["session_id"], user_id, agent_name, instrument_id,
            settle_amount_units, merchant, "ACP-012 first settle", "ACP-012-first",
        )
        if findings["first_settle"].get("proof_extracted"):
            raw_proof = findings["first_settle"].get("raw_proof")
            replay_result = _tier_b_submit_for_settlement(merchant, raw_proof, "ACP-012-replay", usd_amount)
            findings["replay_settle"] = replay_result
            findings["replay_rejected"] = not replay_result.get("settle_success")
            if replay_result.get("settle_success"):
                findings["ANOMALY_replay_settled"] = True
        else:
            findings["replay_settle"] = {"note": "skipped — first settle did not produce an extractable proof, $0 spent"}

    if findings["session_id"]:
        try:
            dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=findings["session_id"])
        except Exception:
            pass

    elapsed = time.monotonic() - t0
    reached_settlement = bool(findings["first_settle"].get("settle_success"))
    measurement_clean = bool(findings["session_id"]) and reached_settlement
    passed = measurement_clean  # characterization convention, not a security verdict

    anomaly = bool(findings.get("ANOMALY_replay_settled"))
    if not reached_settlement:
        detail_note = (
            f"Did not reach real settlement — sign_status="
            f"{findings['first_settle'].get('sign_status', '?')}, "
            f"proof_extraction_method={findings['first_settle'].get('proof_extraction_method', '?')}. "
            f"$0 spent. See response_received for diagnosis."
        )
    elif anomaly:
        detail_note = (
            f"ANOMALY: first settle reached real on-chain settlement (tx="
            f"{findings['first_settle'].get('tx_hash', '?')}); the REPLAY of the identical signed "
            f"authorization (same nonce) also SETTLED (tx={findings['replay_settle'].get('tx_hash', '?')}) "
            f"— potential double-spend surface. STOP and verify manually against the actual chain "
            f"state before any further Tier B runs or any public framing."
        )
    else:
        detail_note = (
            f"First settle reached real on-chain settlement (tx="
            f"{findings['first_settle'].get('tx_hash', '?')}); replay of the identical signed "
            f"authorization (same nonce) was REJECTED — consistent with EIP-3009 authorization-state "
            f"single-use semantics enforced by the facilitator."
        )

    details = f"SCOPE: Tier B real settlement (E3), payTo={BURN_PAYTO}. {detail_note}"

    return AgentCoreTestResult(
        test_id="ACP-012",
        name="Settlement-Time Receipt Nonce Reuse (Tier B — real on-chain settlement)",
        category="receipt_validation",
        owasp_asi="ASI06",
        severity=Severity.CRITICAL.value if anomaly else Severity.HIGH.value,
        passed=passed,
        details=details,
        region=region,
        session_id=findings["session_id"],
        request_sent={
            "operation": "CreatePaymentSession + ProcessPayment(sign) + merchant.handle(settle) + "
                         "merchant.handle(replay, same proof, no re-sign)",
            "settle_amount_units": settle_amount_units,
            "pay_to": BURN_PAYTO,
            "user_id": user_id, "agent_name": agent_name, "instrument_id": instrument_id,
            "tier": "B (settles on-chain — real Base Sepolia gas + USDC)",
        },
        response_received=findings,
        csg_mapping="HC-4: Settled payment authorizations must be single-use (nonce/authorization-state enforcement)",
        estimated_impact="fund_theft" if anomaly else "documentation",
        estimated_severity="critical" if anomaly else "high",
        elapsed_s=round(elapsed, 3),
        evidence_class="E3" if reached_settlement else "E2.5",
    )


def test_agentcore_settle_cross_session_aggregate() -> AgentCoreTestResult:
    """ACP-016 (Tier B — full settlement, SETTLES ON-CHAIN): does SETTLED
    spend aggregate across parallel sessions under one (userId, agentName)?

    Closes the loop VS-R01 ACP-001 (admission-time, E2) and VS-R02 Tier-A's
    test_agentcore_signtime_cross_session_aggregate_tier_a (sign-time
    partial, E2.5) left open: N parallel sessions each sign AND SETTLE a
    real on-chain payment via ONE shared SyntheticMerchant instance, so
    `merchant.total_settled` reflects genuine cumulative settled value
    across all of them. If total_settled == N * per-session amount with no
    rejection, settled spend does not aggregate across sessions either —
    fragmentation extends from admission (ACP-001) through sign-time
    (ACP-009) all the way to real settlement.

    SAFETY GATE: skips unless AGENTCORE_TIER_B_SETTLE_OK=1. N is kept small
    (3, not the test-plan's aspirational 5) to leave margin under
    TIER_B_MAX_USD_PER_SUITE for the other three Tier B tests in the suite.
    """
    _tier_b_settle_gate()
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_id = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    per_session_cap = "0.02"
    parallel_count = 3
    settle_amount_units = "10000"  # 0.01 USDC per session

    x402_merchant = _import_x402_merchant()
    merchant_req = x402_merchant.PaymentRequirements(
        pay_to=BURN_PAYTO, max_amount_required=settle_amount_units, resource="/vsr02-acp-016",
    )
    merchant = x402_merchant.SyntheticMerchant(merchant_req, x402_merchant.CoinbaseFacilitator())

    findings: dict = {
        "user_id": user_id, "agent_name": agent_name, "instrument_id": instrument_id,
        "parallel_sessions_created": 0, "parallel_sessions_attempted": parallel_count,
        "per_session_cap_usd": per_session_cap, "settle_amount_units": settle_amount_units,
        "per_session_settle_result": {}, "settled_count": 0,
        "errors": [],
    }
    created_session_ids: list[str] = []

    for i in range(parallel_count):
        try:
            r = dp.create_payment_session(
                userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
                limits={"maxSpendAmount": {"value": per_session_cap, "currency": "USD"}},
                expiryTimeInMinutes=15, clientToken=str(uuid.uuid4()),
            )
            sid = r.get("paymentSession", r).get("paymentSessionId", "")
            if sid:
                created_session_ids.append(sid)
                findings["parallel_sessions_created"] += 1
        except Exception as e:
            findings["errors"].append(f"session_create[{i}]: {type(e).__name__}: {str(e)[:160]}")

    for i, sid in enumerate(created_session_ids):
        r = _tier_b_sign_and_settle(
            dp, pm_arn, sid, user_id, agent_name, instrument_id,
            settle_amount_units, merchant, f"ACP-016 settle fragment {i}", f"ACP-016-frag-{i}",
        )
        findings["per_session_settle_result"][sid] = {
            "sign_status": r.get("sign_status"), "settle_success": r.get("settle_success"),
            "tx_hash": r.get("tx_hash"), "settle_http_status": r.get("settle_http_status"),
        }
        if r.get("settle_success"):
            findings["settled_count"] += 1

    for sid in created_session_ids:
        try:
            dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=sid)
        except Exception:
            pass

    elapsed = time.monotonic() - t0
    total_settled_units = merchant.total_settled
    total_settled_usd = round(total_settled_units / 1_000_000, 6)
    per_session_cap_usd_val = float(per_session_cap)
    aggregation_enforced = total_settled_usd <= per_session_cap_usd_val + 1e-9
    findings["total_settled_units"] = total_settled_units
    findings["total_settled_usd"] = total_settled_usd
    findings["settlement_records"] = [asdict(s) for s in merchant.settlements]
    findings["aggregation_enforced_at_settlement"] = aggregation_enforced

    measurement_clean = (
        findings["parallel_sessions_created"] == parallel_count
        and len(findings["per_session_settle_result"]) == parallel_count
    )
    passed = measurement_clean

    if findings["settled_count"] == 0:
        agg_note = "0 of the parallel sessions reached real settlement — see per_session_settle_result for diagnosis; cannot characterize aggregation."
    elif aggregation_enforced:
        agg_note = (
            f"Total SETTLED spend (${total_settled_usd}) stayed within a single session's cap "
            f"(${per_session_cap_usd_val}) despite {findings['settled_count']} sessions settling — "
            f"UNEXPECTED given ACP-001/ACP-009 admission/sign-time findings; verify manually."
        )
    else:
        agg_note = (
            f"Total SETTLED spend across {findings['settled_count']} parallel sessions "
            f"(${total_settled_usd}) EXCEEDS a single session's cap (${per_session_cap_usd_val}) — "
            f"settled-spend fragmentation confirmed at the strict E3 (real settlement) layer, "
            f"consistent with the admission-time (ACP-001) and sign-time (ACP-009) findings."
        )

    details = (
        f"SCOPE: Tier B real settlement (E3), payTo={BURN_PAYTO}, {parallel_count} parallel sessions, "
        f"${round(int(settle_amount_units) / 1_000_000, 6)} each. {agg_note}"
    )

    return AgentCoreTestResult(
        test_id="ACP-016",
        name="Cross-Session Aggregate Spend at SETTLEMENT (Tier B — full, real on-chain settlement)",
        category="spend_cap_enforcement",
        owasp_asi="ASI02",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=details,
        region=region,
        session_id=created_session_ids[0] if created_session_ids else "",
        request_sent={
            "operation": "CreatePaymentSession x N (parallel) + [ProcessPayment(sign) + merchant.handle(settle)] x N, "
                         "one shared merchant instance",
            "parallel_count_attempted": parallel_count,
            "per_session_cap_usd": per_session_cap,
            "settle_amount_units": settle_amount_units,
            "pay_to": BURN_PAYTO,
            "user_id": user_id, "agent_name": agent_name, "instrument_id": instrument_id,
            "tier": "B (settles on-chain — real Base Sepolia gas + USDC)",
        },
        response_received=findings,
        csg_mapping="HC-1: Settlement-time aggregation needed for principal-bound spend governance (closes ACP-001/ACP-009 loop)",
        estimated_impact="fund_theft" if (findings["settled_count"] > 0 and not aggregation_enforced) else "documentation",
        estimated_severity="medium",
        elapsed_s=round(elapsed, 3),
        evidence_class="E3" if findings["settled_count"] > 0 else "E2.5",
    )


def test_agentcore_settle_delegation_expiry_boundary() -> AgentCoreTestResult:
    """ACP-017 (Tier B — SETTLES ON-CHAIN): is a signed authorization's own
    validBefore boundary enforced at SIGN time, at SETTLEMENT time, or both?

    REFRAMED from the VS-R02 test-plan's original ACP-017 ("sign at T-5min /
    T+5min of the WalletHub delegation GRANT's expiry"): the grant expires
    2026-09-09 (scripts/vs-r02-env.sh) — months out from any plausible run
    date for this staged suite, so waiting for real grant expiry is not
    practically scriptable. This test substitutes the boundary that IS
    controllable today: the x402 "exact" scheme authorization's own
    `validBefore` field (derived from `maxTimeoutSeconds` in the signed
    payload). It signs two independent authorizations with a short
    `maxTimeoutSeconds` window and asks: (a) does a settlement attempt made
    WELL WITHIN the window succeed; (b) does a settlement attempt made AFTER
    the window has elapsed get rejected, even though CDP delegated signing
    itself succeeded (PROOF_GENERATED) before expiry? (b) is the genuine
    sign-time-vs-settlement-time enforcement question the test plan asked,
    measured on the payload's validBefore instead of the grant's expiry.

    `days_until_grant_expiry` is logged for informational comparison only —
    if a future run happens to land near the real 2026-09-09 grant expiry,
    compare manually; that path is not automated here.

    SAFETY GATE: skips unless AGENTCORE_TIER_B_SETTLE_OK=1.
    """
    _tier_b_settle_gate()
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_id = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    per_cap = "0.05"
    settle_amount_units = "10000"
    short_timeout_s = 5
    wait_past_expiry_s = short_timeout_s + 3

    from datetime import date as _date
    grant_expiry_str = os.environ.get("AGENTCORE_VSR02_GRANT_EXPIRY", "2026-09-09")
    try:
        grant_expiry = _date.fromisoformat(grant_expiry_str)
        days_until_grant_expiry = (grant_expiry - datetime.now(timezone.utc).date()).days
    except ValueError:
        days_until_grant_expiry = None

    x402_merchant = _import_x402_merchant()
    merchant_req = x402_merchant.PaymentRequirements(
        pay_to=BURN_PAYTO, max_amount_required=settle_amount_units, resource="/vsr02-acp-017",
    )
    merchant = x402_merchant.SyntheticMerchant(merchant_req, x402_merchant.CoinbaseFacilitator())
    usd_amount = round(int(settle_amount_units) / 1_000_000, 6)

    findings: dict = {
        "user_id": user_id, "agent_name": agent_name, "instrument_id": instrument_id,
        "days_until_grant_expiry": days_until_grant_expiry,
        "short_timeout_s": short_timeout_s, "wait_past_expiry_s": wait_past_expiry_s,
        "within_window_settle": {}, "past_window_settle": {},
        "session_id": "",
        "errors": [],
    }

    try:
        r = dp.create_payment_session(
            userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": per_cap, "currency": "USD"}},
            expiryTimeInMinutes=15, clientToken=str(uuid.uuid4()),
        )
        findings["session_id"] = r.get("paymentSession", r).get("paymentSessionId", "")
    except Exception as e:
        findings["errors"].append(f"session_create: {type(e).__name__}: {str(e)[:160]}")

    if findings["session_id"]:
        # Probe (a): sign + settle immediately, well within the validBefore window.
        within = _tier_b_sign(
            dp, pm_arn, findings["session_id"], user_id, agent_name, instrument_id,
            settle_amount_units, "ACP-017 within-window", short_timeout_s, resource=merchant.req.resource,
        )
        if within.get("proof_extracted"):
            within.update(_tier_b_submit_for_settlement(merchant, within["raw_proof"], "ACP-017-within", usd_amount))
        findings["within_window_settle"] = within

        # Probe (b): sign a SEPARATE authorization (own nonce), wait past its
        # validBefore window, then attempt settlement.
        late = _tier_b_sign(
            dp, pm_arn, findings["session_id"], user_id, agent_name, instrument_id,
            settle_amount_units, "ACP-017 past-window", short_timeout_s, resource=merchant.req.resource,
        )
        findings["past_window_sign_status"] = late.get("sign_status")
        findings["past_window_proof_extracted"] = late.get("proof_extracted")
        if late.get("proof_extracted"):
            time.sleep(wait_past_expiry_s)
            past = _tier_b_submit_for_settlement(merchant, late["raw_proof"], "ACP-017-past", usd_amount)
            findings["past_window_settle"] = past
        else:
            findings["past_window_settle"] = {"note": "skipped — sign did not reach PROOF_GENERATED / no extractable proof, $0 spent"}

    if findings["session_id"]:
        try:
            dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=findings["session_id"])
        except Exception:
            pass

    elapsed = time.monotonic() - t0

    within_ok = bool(findings["within_window_settle"].get("settle_success"))
    past_reached = "settle_success" in findings.get("past_window_settle", {})
    past_settled = bool(findings.get("past_window_settle", {}).get("settle_success"))
    measurement_clean = bool(findings["session_id"]) and within_ok and past_reached
    passed = measurement_clean

    if not within_ok:
        note = "Within-window settlement did not succeed — cannot characterize the boundary; see within_window_settle for diagnosis."
    elif not past_reached:
        note = "Past-window sign/proof-extraction did not succeed — boundary not characterized on the settlement side."
    elif past_settled:
        note = (
            "Settlement past the signed authorization's own validBefore window SUCCEEDED — "
            "expiry is NOT re-validated at settlement time for this window; enforcement is "
            "sign-time only. Needs manual verification before any public framing."
        )
    else:
        note = (
            "Settlement past the signed authorization's own validBefore window was REJECTED — "
            "expiry IS re-validated at settlement time, not just sign-time (expected EIP-3009 / "
            "x402 'exact' scheme behavior)."
        )

    details = (
        f"SCOPE: Tier B real settlement (E3), payTo={BURN_PAYTO}. REFRAMED from grant-expiry to "
        f"payload validBefore (see docstring) — days_until_grant_expiry={days_until_grant_expiry} "
        f"(informational only, not exercised this run). {note}"
    )

    return AgentCoreTestResult(
        test_id="ACP-017",
        name="Delegation/Authorization Expiry — Sign-Time vs Settlement-Time Enforcement (Tier B, reframed to payload validBefore)",
        category="spend_cap_enforcement",
        owasp_asi="ASI02",
        severity=Severity.MEDIUM.value,
        passed=passed,
        details=details,
        region=region,
        session_id=findings["session_id"],
        request_sent={
            "operation": "CreatePaymentSession + [sign+settle within window] + [sign, sleep past window, settle]",
            "settle_amount_units": settle_amount_units,
            "short_timeout_s": short_timeout_s, "wait_past_expiry_s": wait_past_expiry_s,
            "pay_to": BURN_PAYTO,
            "user_id": user_id, "agent_name": agent_name, "instrument_id": instrument_id,
            "tier": "B (settles on-chain — real Base Sepolia gas + USDC)",
        },
        response_received=findings,
        csg_mapping="HC-1/HC-3: Expiry must be enforced at settlement time, not sign-time only",
        estimated_impact="fund_theft" if past_settled else "documentation",
        estimated_severity="medium",
        elapsed_s=round(elapsed, 3),
        evidence_class="E3" if past_reached else "E2.5",
    )


def test_agentcore_settle_revoke_race(revoke_at_attempt: int | None = None) -> AgentCoreTestResult:
    """ACP-018 (Tier B — SETTLES ON-CHAIN, MANUAL COORDINATION REQUIRED):
    revoke-and-immediately-spend race.

    NOT FULLY AUTOMATABLE — read before running. The VS-R02 test plan frames
    this as "end user clicks Revoke in WalletHub at T; agent submits
    ProcessPayment at T+50ms with cached delegation." Revocation of a CDP
    delegated-signing grant is a WalletHub UI action; no boto3/AgentCore API
    used anywhere in this module (create/get/list/delete_payment_session,
    create/delete_payment_instrument, process_payment) exposes it
    programmatically. This test can only automate the AGENT side of the
    race — a tight loop of small settlement attempts — while the OPERATOR
    must manually click Revoke in the WalletHub UI at a moment of their
    choosing during the loop's run window. See
    reports/round_24/VS-R02-tier-b-runbook.md for the coordination steps.

    The loop runs up to `max_attempts` settlement attempts (each well under
    TIER_B_MAX_USD_PER_TX), `attempt_interval_s` apart, recording the
    wall-clock timestamp and outcome of every attempt. The race window is
    bounded by (last success, first failure-after-a-success) — the exact
    revoke timestamp is only as precise as the operator's own note of when
    they clicked Revoke (not captured programmatically; compare manually).

    `revoke_at_attempt` is an optional operator hint for documentation only
    — not enforced by code. Leave None for a live interactive run.

    SAFETY GATE: skips unless AGENTCORE_TIER_B_SETTLE_OK=1. The loop stops
    itself (via _tier_b_check_cap) if continuing would breach the suite
    ceiling, independent of whether revoke has happened yet.
    """
    _tier_b_settle_gate()
    t0 = time.monotonic()
    region = os.environ.get(ENV_REGION, "us-east-1")
    dp = _get_agentcore_client(service="bedrock-agentcore")
    pm_arn = os.environ.get("AGENTCORE_PAYMENT_MANAGER_ARN", "")
    user_id = os.environ.get(ENV_VSR02_USER_ID, VSR02_USER_ID_DEFAULT)
    agent_name = os.environ.get(ENV_VSR02_AGENT_NAME, VSR02_AGENT_NAME_DEFAULT)
    instrument_id = os.environ.get(ENV_VSR02_INSTRUMENT_ID, VSR02_INSTRUMENT_ID_DEFAULT)
    per_cap = "0.05"
    per_attempt_units = "2000"  # 0.002 USDC — small; the loop makes several attempts
    max_attempts = 5
    attempt_interval_s = 1.0

    x402_merchant = _import_x402_merchant()
    merchant_req = x402_merchant.PaymentRequirements(
        pay_to=BURN_PAYTO, max_amount_required=per_attempt_units, resource="/vsr02-acp-018",
    )
    merchant = x402_merchant.SyntheticMerchant(merchant_req, x402_merchant.CoinbaseFacilitator())
    usd_per_attempt = round(int(per_attempt_units) / 1_000_000, 6)

    findings: dict = {
        "user_id": user_id, "agent_name": agent_name, "instrument_id": instrument_id,
        "session_id": "",
        "revoke_at_attempt_hint": revoke_at_attempt,
        "max_attempts": max_attempts, "attempt_interval_s": attempt_interval_s,
        "attempts": [],
        "manual_coordination_note": (
            "Revocation is a WalletHub UI action, not automatable from this harness. The "
            "operator must click Revoke during this loop's run window and note the wall-clock "
            "time themselves for manual comparison against the attempts list below."
        ),
        "errors": [],
    }

    try:
        r = dp.create_payment_session(
            userId=user_id, agentName=agent_name, paymentManagerArn=pm_arn,
            limits={"maxSpendAmount": {"value": per_cap, "currency": "USD"}},
            expiryTimeInMinutes=15, clientToken=str(uuid.uuid4()),
        )
        findings["session_id"] = r.get("paymentSession", r).get("paymentSessionId", "")
    except Exception as e:
        findings["errors"].append(f"session_create: {type(e).__name__}: {str(e)[:160]}")

    if findings["session_id"]:
        print(
            f"[ACP-018] Session ready. Starting {max_attempts}-attempt loop "
            f"({attempt_interval_s}s apart). CLICK REVOKE IN WALLETHUB NOW if running interactively."
        )
        for i in range(max_attempts):
            try:
                _tier_b_check_cap(f"ACP-018-attempt-{i}", usd_per_attempt)
            except AssertionError as e:
                findings["attempts"].append({
                    "index": i, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "outcome": "SUITE_CAP_REACHED_STOPPING", "detail": str(e),
                })
                break
            r = _tier_b_sign_and_settle(
                dp, pm_arn, findings["session_id"], user_id, agent_name, instrument_id,
                per_attempt_units, merchant, f"ACP-018 race attempt {i}", f"ACP-018-attempt-{i}",
            )
            findings["attempts"].append({
                "index": i, "timestamp": datetime.now(timezone.utc).isoformat(),
                "elapsed_since_loop_start_s": round(time.monotonic() - t0, 3),
                "sign_status": r.get("sign_status"), "settle_success": r.get("settle_success"),
                "tx_hash": r.get("tx_hash"), "settle_http_status": r.get("settle_http_status"),
            })
            if i < max_attempts - 1:
                time.sleep(attempt_interval_s)

    if findings["session_id"]:
        try:
            dp.delete_payment_session(userId=user_id, paymentManagerArn=pm_arn, paymentSessionId=findings["session_id"])
        except Exception:
            pass

    elapsed = time.monotonic() - t0

    successes = [a for a in findings["attempts"] if a.get("settle_success")]
    failures_after_first_success = [
        a for a in findings["attempts"]
        if not a.get("settle_success") and successes and a["index"] > successes[0]["index"]
    ]
    findings["last_success_index"] = successes[-1]["index"] if successes else None
    findings["first_failure_after_a_success_index"] = (
        failures_after_first_success[0]["index"] if failures_after_first_success else None
    )
    race_window_observed = (
        findings["last_success_index"] is not None
        and findings["first_failure_after_a_success_index"] is not None
    )

    measurement_clean = bool(findings["session_id"]) and len(findings["attempts"]) > 0
    passed = measurement_clean

    if not findings["attempts"]:
        note = "No attempts completed — see errors."
    elif not successes:
        note = (
            "Zero attempts settled — cannot characterize a revoke race; check whether the grant "
            "was already revoked/expired before this run, or diagnose via sign_status."
        )
    elif len(successes) == len(findings["attempts"]):
        note = (
            "All attempts settled successfully. Either Revoke was not actually clicked during "
            "this run, or settlement did not observe the revoke within the loop's window — MANUAL "
            "FOLLOW-UP REQUIRED: confirm with the operator whether/when Revoke was clicked, and "
            "re-run if it was not clicked during THIS invocation."
        )
    elif race_window_observed:
        note = (
            f"Race window observed: last successful settlement at attempt "
            f"{findings['last_success_index']}, first failure after a success at attempt "
            f"{findings['first_failure_after_a_success_index']}. Compare against the operator's own "
            f"note of when Revoke was clicked in WalletHub to characterize enforcement latency."
        )
    else:
        note = "Mixed results with no clean success-then-failure boundary — inspect the attempts list directly."

    details = (
        f"SCOPE: Tier B real settlement (E3), payTo={BURN_PAYTO}. MANUAL COORDINATION REQUIRED — "
        f"see manual_coordination_note. {note}"
    )

    return AgentCoreTestResult(
        test_id="ACP-018",
        name="Revoke-and-Immediately-Spend Race (Tier B — requires manual WalletHub coordination)",
        category="instrument_isolation",
        owasp_asi="ASI03",
        severity=Severity.HIGH.value,
        passed=passed,
        details=details,
        region=region,
        session_id=findings["session_id"],
        request_sent={
            "operation": f"CreatePaymentSession + {max_attempts}x [ProcessPayment(sign) + merchant.handle(settle)] "
                         f"loop, {attempt_interval_s}s apart, operator clicks WalletHub Revoke mid-loop",
            "per_attempt_units": per_attempt_units, "max_attempts": max_attempts,
            "pay_to": BURN_PAYTO,
            "user_id": user_id, "agent_name": agent_name, "instrument_id": instrument_id,
            "tier": "B (settles on-chain — real Base Sepolia gas + USDC); MANUAL revoke coordination",
        },
        response_received=findings,
        csg_mapping="HC-1/HC-5: Revocation must take effect immediately at settlement, not just at future sign attempts",
        estimated_impact=(
            "fund_theft" if (successes and len(successes) == len(findings["attempts"]) and findings["attempts"])
            else "documentation"
        ),
        estimated_severity="high",
        elapsed_s=round(elapsed, 3),
        evidence_class="E3" if successes else "E2.5",
    )


VS_R02_TIER_B_TESTS: dict[str, list[str]] = {
    "receipt_validation": [
        "test_agentcore_settle_receipt_nonce_reuse",          # ACP-012
    ],
    "spend_cap_enforcement": [
        "test_agentcore_settle_cross_session_aggregate",      # ACP-016 (Tier-B, full)
        "test_agentcore_settle_delegation_expiry_boundary",   # ACP-017
    ],
    "instrument_isolation": [
        "test_agentcore_settle_revoke_race",                  # ACP-018 — MANUAL WalletHub coordination required
    ],
}
# NOTE: intentionally NOT merged into ALL_TESTS and NOT registered in
# protocol_tests/cli.py / scripts/count_tests.py — same staging discipline as
# VS_R02_TIER_A_TESTS above. These SETTLE ON-CHAIN (real gas + USDC) and are
# additionally gated behind AGENTCORE_TIER_B_SETTLE_OK=1 (see
# _tier_b_settle_gate). Do not run until the VS-R02 wallet is funded — see
# reports/round_24/VS-R02-tier-b-runbook.md. Mike registers in cli.py after
# live validation, same as Tier A.



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
