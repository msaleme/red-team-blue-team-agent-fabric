#!/usr/bin/env bash
# VS-R02 environment setup — source this before running VS-R02 Tier-A stubs.
# Extends scripts/vs-r01-env.sh (same AWS/AgentCore/CDP stack — PaymentManager,
# PaymentConnector, CredentialProvider all carry forward unchanged) and adds
# the VS-R02-specific WalletHub-granted identity + sign-time payload knobs.
# Created 2026-07-11. See reports/round_24/VS-R02-tier-a-runbook.md.

# -- Carry forward the full VS-R01 stack (venv, AWS profile, AgentCore
#    PaymentManager/Connector/CredentialProvider, CDP credential file paths) --
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/vs-r01-env.sh"

# -- VS-R02 wallet + CDP project (WalletHub delegated-signing grant target) --
# Wallet address and CDP project id are identifiers, not secrets — safe to
# have a default here, override via env if Mike re-provisions.
export AGENTCORE_VSR02_WALLET="${AGENTCORE_VSR02_WALLET:-0x7889454DF1EB44B2fA0878179A1845F5b4649286}"
export AGENTCORE_CDP_PROJECT_ID="${AGENTCORE_CDP_PROJECT_ID:-fdc6d46c-a5e3-49b2-8fae-0e1c42569ba7}"

# -- WalletHub-granted identity (userId, agentName, paymentInstrumentId) --
# This is the ONLY (userId, agentName, paymentInstrumentId) tuple with an
# active delegated-signing grant as of 2026-07-11 (re-granted, valid until
# 2026-09-09). Carried forward from the VS-R02 test-plan prerequisites table.
export AGENTCORE_VSR02_USER_ID="${AGENTCORE_VSR02_USER_ID:-vs-r01-walletub-1779903158}"
export AGENTCORE_VSR02_AGENT_NAME="${AGENTCORE_VSR02_AGENT_NAME:-vs-r01-cdp-grant-probe}"
export AGENTCORE_VSR02_INSTRUMENT_ID="${AGENTCORE_VSR02_INSTRUMENT_ID:-payment-instrument-YQFWKtbGbKUuiMF}"

# -- x402 "exact" scheme EIP-712 domain fields (extra.name / extra.version) --
# UNVERIFIED against a captured live AgentCore response — see the TODO in
# protocol_tests/agentcore_payments_harness.py (_build_x402_exact_payload).
# Override here if the first live run shows AgentCore expects something else.
# export AGENTCORE_X402_EXTRA_NAME="USD Coin"
# export AGENTCORE_X402_EXTRA_VERSION="2"

# -- Tier discipline reminder (enforced in code via BURN_PAYTO + stopping at
#    PROOF_GENERATED for Tier A, and via the separate AGENTCORE_TIER_B_SETTLE_OK
#    gate for Tier B — this echo block is a human-readable reminder, not a
#    live balance check).
# TODO(Mike): the "UNFUNDED" string below is a static reminder written when
# the wallet genuinely held 0 ETH / 0 USDC (see
# reports/round_24/VS-R02-tier-a-runbook.md). Once you fund the wallet (see
# reports/round_24/VS-R02-tier-b-runbook.md §1), update this line — it does
# not check the real balance automatically.
echo
echo "VS-R02 environment ready (built on VS-R01 stack above)."
echo "  vsr02 wallet:        ${AGENTCORE_VSR02_WALLET:0:10}... (UNFUNDED as of 2026-07-11 — Tier A only until funded)"
echo "  cdp project:         ${AGENTCORE_CDP_PROJECT_ID}"
echo "  granted identity:    userId=${AGENTCORE_VSR02_USER_ID} agentName=${AGENTCORE_VSR02_AGENT_NAME}"
echo "  granted instrument:  ${AGENTCORE_VSR02_INSTRUMENT_ID}"
echo
echo "Reminder: every VS-R02 Tier-A test (test_agentcore_signtime_*) must stop at PROOF_GENERATED (0 gas)."
echo "Tier B (test_agentcore_settle_*) SETTLES ON-CHAIN — real gas + USDC — and is gated behind"
echo "AGENTCORE_TIER_B_SETTLE_OK=1 in addition to a funded wallet. See VS-R02-tier-b-runbook.md before setting it."
echo "Next (Tier A): pytest --collect-only -q protocol_tests/agentcore_payments_harness.py -k signtime"
echo "Next (Tier B): pytest --collect-only -q protocol_tests/agentcore_payments_harness.py -k settle"
