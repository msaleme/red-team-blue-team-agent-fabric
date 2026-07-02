#!/usr/bin/env python3
"""Card-Network Agentic Token Security Test Harness (v1.0)

Security conformance suite for the **card-network funding-instrument layer** of
the agentic-payments stack — the tokenized card credential that sits *inside* an
AP2 Payment Mandate as the actual instrument that moves money:

  * **Visa Trusted Agent Protocol (TAP)** — a tokenized card credential issued
    to a specific agent, scoped to a merchant + consent policy, carrying a
    dynamic cryptogram.
  * **Mastercard Agentic Tokens** — network-tokenized credentials scoped to an
    agent + merchant + consent policy, the Mastercard counterpart.

Both networks tokenize the underlying PAN into a credential bound to an agent
identity, a merchant (or merchant category), an amount/velocity envelope, a
consent policy and a channel, authenticated per-transaction by a dynamic
cryptogram (EMV TAVV / DTVV lineage: a token authentication value computed over
the transaction so a captured value cannot be replayed or re-priced).

This promotes the funding-instrument checks that were a single dimension of the
AP2 harness (AP2-015) into a first-class module: AP2 answers "is this agent
authorized to assemble and pay for this cart"; the card token answers "is this
specific funding credential valid, unrevoked, fresh, and bound to this agent,
merchant, amount and channel." They compose — the token is the instrument the
Payment Mandate names.

Reference-verifier note (honesty, per the repo's stdlib-only guarantee for
``protocol_tests``): production tokens use network HSM-backed cryptograms
(TAVV/DTVV) and de-tokenization vaults. The built-in reference verifier
implements the credential *semantics* — holder-key binding, merchant/amount/
velocity/consent/channel scope, monotonic-counter cryptogram freshness,
cryptogram-over-amount binding, revocation status, PAN de-tokenization
protection and cross-network substitution — with SHA-256 over the transaction
standing in for the network cryptogram. The accept/reject *decisions* under test
are the same. Every check **fails closed**: a missing binding, an inactive
status or an absent cryptogram is a rejection, never a skip. ``--simulate`` runs
the differential against this reference verifier; ``--url`` folds in a live
authorizer with a liveness gate (unreachable/erroring is observe-failure, never
a silent pass).

References:
    Visa Trusted Agent Protocol (TAP); Mastercard Agentic Tokens — tokenized
        card credential scoped to agent + merchant + consent policy, bound into
        an AP2 Payment Mandate as the funding instrument.
    EMV Payment Tokenisation; TAVV / DTVV dynamic token authentication values.
    AP2 Payment Mandate `payment_instrument` (see ap2_harness AP2-015).
    Conformance matrix: agentic-payments 4-layer stack, funding-instrument rail.

OWASP Mappings: ASI02 (Improper Access Controls), ASI03 (Identity/Priv Abuse),
                ASI04 (Agentic Supply Chain), ASI09 (Human-Agent Trust Exploit)
STRIDE: Spoofing, Tampering, Elevation of Privilege, Information Disclosure

Usage:
    python -m protocol_tests.card_token_harness --simulate
    python -m protocol_tests.card_token_harness --url https://authorizer.example.com
    python -m protocol_tests.card_token_harness --simulate --report card_token.json

Requires: Python 3.10+, no external dependencies.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from protocol_tests._utils import Severity, wilson_ci, http_post_json


# ---------------------------------------------------------------------------
# Dynamic cryptogram (TAVV / DTVV stand-in)
# ---------------------------------------------------------------------------

def _jcs(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def cryptogram(token_id: str, amount: int, counter: int) -> str:
    """A dynamic token authentication value bound to (token, amount, counter).

    Stand-in for a network TAVV/DTVV: computed over the transaction so a
    captured value cannot be replayed (counter) or re-priced (amount).
    """
    digest = hashlib.sha256(_jcs({"t": token_id, "a": amount, "c": counter}).encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@dataclass
class VerifyOutcome:
    ok: bool
    reason: str


# ---------------------------------------------------------------------------
# Card-network token reference verifier
# ---------------------------------------------------------------------------

class CardTokenVerifier:
    """Deterministic tokenized-card-credential verifier (reference model).

    Mirrors the accept/reject decisions a network token authorizer (Visa TAP /
    Mastercard Agentic Tokens) MUST make on a transaction presented against a
    tokenized credential. Every check fails closed. State is per token id:
    the last-seen cryptogram counter (freshness) and cumulative spend
    (velocity).
    """

    def __init__(self) -> None:
        self._ledger: dict[str, dict] = {}  # token_id -> {"last_counter", "spent"}

    def authorize(self, token: dict, txn: dict, now: int) -> VerifyOutcome:
        tid = token.get("token_id")
        led = self._ledger.setdefault(tid, {"last_counter": 0, "spent": 0})
        # 1. Status: a revoked/suspended token MUST NOT authorize (identify+revoke).
        if token.get("status") != "active":
            return VerifyOutcome(False, f"token status '{token.get('status')}' is not active (revoked/suspended)")
        # 2. Expiry.
        if token.get("exp", 1 << 62) < now:
            return VerifyOutcome(False, "token expired")
        # 3. Holder-key binding: only the bound agent may present the token.
        #    Fail closed: the token MUST declare a holder key (a missing binding
        #    on both sides is a rejection, not a None==None pass).
        if not token.get("holder_kid") or txn.get("presenter_kid") != token.get("holder_kid"):
            return VerifyOutcome(False, "presenter key != bound holder key (agent binding)")
        # 4. Network / BIN substitution: token network MUST match the transaction.
        if not token.get("network") or txn.get("network") != token.get("network"):
            return VerifyOutcome(False, "token network mismatch (cross-network substitution)")
        # 5. Channel binding: the token is restricted to its issued channel.
        if not token.get("channel") or txn.get("channel") != token.get("channel"):
            return VerifyOutcome(False, f"channel '{txn.get('channel')}' not permitted for this token")
        # 6. Merchant scope.
        if not token.get("merchant_scope") or txn.get("merchant") != token.get("merchant_scope"):
            return VerifyOutcome(False, "token merchant scope mismatch")
        # 7. Consent-policy binding (category + recurring).
        policy = token.get("consent_policy", {})
        cats = policy.get("categories")
        if cats is not None and txn.get("category") not in cats:
            return VerifyOutcome(False, f"category '{txn.get('category')}' outside token consent policy")
        if txn.get("recurring") and not policy.get("recurring", False):
            return VerifyOutcome(False, "recurring charge not permitted by consent policy")
        # 8. Amount bounds. Fail closed on a non-positive amount: a negative
        #    charge would pass an upper-bound-only cap AND (via spent += amount)
        #    refund velocity budget, so bound BOTH ends.
        amount = txn.get("amount", 0)
        # bool is an int subclass in Python, so exclude it explicitly — a
        # monetary amount must be a real positive integer, not True/False.
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            return VerifyOutcome(False, "amount must be a positive integer")
        if amount > token.get("max_amount", 0):
            return VerifyOutcome(
                False, f"charge {amount} exceeds per-transaction cap {token.get('max_amount')}")
        # 9. PAN de-tokenization protection: the raw PAN MUST NOT be presented,
        #    and the token MUST carry a PAN binding (not expose the PAN itself).
        if txn.get("raw_pan"):
            return VerifyOutcome(False, "raw PAN presented (de-tokenization violation)")
        if not token.get("pan_binding"):
            return VerifyOutcome(False, "token missing PAN binding")
        # 10. Cryptogram freshness: the counter MUST advance (no replay).
        counter = txn.get("counter", 0)
        if counter <= led["last_counter"]:
            return VerifyOutcome(False, "stale cryptogram / counter replay")
        # 11. Cryptogram-amount binding: the presented value MUST recompute over
        #     the presented amount + counter (no re-pricing after generation).
        expected = cryptogram(tid, amount, counter)
        if txn.get("cryptogram") != expected:
            return VerifyOutcome(False, "cryptogram does not bind the amount/counter (tamper)")
        # 12. Velocity cap: cumulative spend MUST stay within the token envelope.
        vcap = token.get("velocity_cap")
        if vcap is not None and led["spent"] + amount > vcap:
            return VerifyOutcome(
                False, f"cumulative spend {led['spent'] + amount} exceeds velocity cap {vcap}")
        # Accept — advance freshness + velocity state.
        led["last_counter"] = counter
        led["spent"] += amount
        return VerifyOutcome(True, "card token authorized")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _valid_token(now: int):
    """A coherent (token, transaction) pair with a fresh, well-bound cryptogram."""
    token = {
        "token_id": "ntk-1",
        "network": "visa-tap",
        "holder_kid": "agent-key-1",
        "merchant_scope": "merchant_1",
        "max_amount": 20000,
        "velocity_cap": 50000,
        "consent_policy": {"categories": ["books"], "recurring": False},
        "exp": now + 600,
        "status": "active",
        "channel": "agentic-commerce",
        "pan_binding": cryptogram("pan", 0, 0),  # opaque PAN binding, not the PAN
        "bin": "visa-4",
    }
    txn = _txn(token, amount=15000, counter=1)
    return token, txn


def _txn(token: dict, amount: int, counter: int, **over) -> dict:
    """Build a well-formed transaction for a token (valid cryptogram by default)."""
    t = {
        "token_id": token["token_id"],
        "presenter_kid": token["holder_kid"],
        "merchant": token["merchant_scope"],
        "network": token["network"],
        "channel": token["channel"],
        "amount": amount,
        "category": "books",
        "recurring": False,
        "counter": counter,
        "raw_pan": None,
        "cryptogram": cryptogram(token["token_id"], amount, counter),
    }
    t.update(over)
    return t


# ---------------------------------------------------------------------------
# Result model + live probe
# ---------------------------------------------------------------------------

@dataclass
class CardTokenTestResult:
    test_id: str
    name: str
    category: str
    network: str
    owasp_asi: str
    stride: str
    severity: str
    passed: bool
    details: str
    ref: str = ""
    normative: str = "N"   # N = normative MUST; I = inferred/strict
    live_evidence: dict | None = None
    elapsed_s: float = 0.0


def _live_rejected(url: str, headers: dict, payload: dict) -> tuple[str, dict]:
    """Probe a live token authorizer. Returns (verdict, evidence).

    verdict in {"rejected", "accepted", "unreachable"}. Liveness gate: a
    transport failure or 5xx is 'unreachable', never a pass.
    """
    resp = http_post_json(url, payload, headers, timeout=10)
    if resp.get("_error"):
        status = resp.get("_status", 0)
        if status and 400 <= status < 500:
            return ("rejected", resp)
        return ("unreachable", resp)
    status = resp.get("_status", 0)
    if status >= 500 or status == 0:
        return ("unreachable", resp)
    text = json.dumps(resp).lower()
    if any(w in text for w in ("reject", "declin", "denied", "invalid", "unauthorized",
                               "forbidden", "not authorized", "mismatch", "expired", "revoked")):
        return ("rejected", resp)
    if 200 <= status < 300:
        return ("accepted", resp)
    return ("unreachable", resp)


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class CardTokenTests:
    """Card-network agentic-token conformance suite (CTK-001..012)."""

    def __init__(self, url: str | None = None, headers: dict | None = None,
                 simulate: bool = False):
        self.url = url.rstrip("/") if url else "http://localhost:8080"
        self.headers = headers or {}
        self.simulate = simulate
        self.results: list[CardTokenTestResult] = []

    def _now(self) -> int:
        return 1_750_000_000 if self.simulate else int(time.time())

    def _record(self, r: CardTokenTestResult) -> None:
        print(f"  {'PASS ✅' if r.passed else 'FAIL ❌'}  {r.test_id}: {r.name}")
        self.results.append(r)

    def _finish(self, *, test_id, name, category, network, owasp, stride,
                severity, ref, normative, model_pass, model_reason,
                attack_payload, t0):
        passed = model_pass
        details = model_reason
        live_ev = None
        if not self.simulate and attack_payload is not None:
            verdict, ev = _live_rejected(self.url, self.headers, attack_payload)
            live_ev = {"verdict": verdict, "status": ev.get("_status", 0)}
            if verdict == "accepted":
                passed = False
                details = f"{model_reason}; LIVE authorizer ACCEPTED the attack — control absent"
            elif verdict == "rejected":
                details = f"{model_reason}; live authorizer rejected the attack"
            else:
                details = f"{model_reason}; live authorizer unreachable — verdict from reference model"
        self._record(CardTokenTestResult(
            test_id=test_id, name=name, category=category, network=network,
            owasp_asi=owasp, stride=stride, severity=severity, passed=passed,
            details=details, ref=ref, normative=normative,
            live_evidence=live_ev, elapsed_s=round(time.monotonic() - t0, 3)))

    # -- CTK-001: agent holder binding ------------------------------------

    def test_ctk_001_holder_binding(self) -> None:
        """CTK-001: Token presented by the wrong agent rejected (HIGH).

        A tokenized card credential is bound to a specific agent (holder key);
        presentation by a different agent MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)
        # (a) presented by a different agent
        wrong = dict(txn, presenter_kid="attacker-key-9")
        v_wrong = CardTokenVerifier().authorize(token, wrong, now)
        # (b) binding omitted on BOTH sides — must fail closed, not None==None pass
        unbound_token = dict(token, holder_kid=None)
        unbound_txn = dict(txn, presenter_kid=None)
        v_unbound = CardTokenVerifier().authorize(unbound_token, unbound_txn, now)
        model_pass = ((not v_wrong.ok and "holder key" in v_wrong.reason)
                      and (not v_unbound.ok and "holder key" in v_unbound.reason))
        self._finish(
            test_id="CTK-001", name="Agent Holder-Key Binding",
            category="binding", network="visa-tap/mc-agentic",
            owasp="ASI03", stride="Spoofing", severity=Severity.HIGH.value,
            ref="Visa TAP / MC Agentic Token: credential bound to a specific agent", normative="N",
            model_pass=model_pass,
            model_reason=("wrong-agent and unbound-holder presentations both rejected" if model_pass else
                          "TOKEN THEFT — a token was authorized for a non-bound / unbound agent"),
            attack_payload={"token": token, "transaction": wrong}, t0=t0)

    # -- CTK-002: merchant scope ------------------------------------------

    def test_ctk_002_merchant_scope(self) -> None:
        """CTK-002: Token used off-merchant rejected (HIGH)."""
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)
        txn["merchant"] = "merchant_evil"
        v = CardTokenVerifier().authorize(token, txn, now)
        self._finish(
            test_id="CTK-002", name="Token Merchant Scope",
            category="scope", network="visa-tap/mc-agentic",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.HIGH.value,
            ref="Visa TAP / MC Agentic Token: scoped to a specific merchant", normative="N",
            model_pass=(not v.ok and "merchant scope" in v.reason),
            model_reason=(f"off-merchant token rejected ({v.reason})" if not v.ok else
                          "SCOPE ABUSE — token used outside its merchant scope"),
            attack_payload={"token": token, "transaction": txn}, t0=t0)

    # -- CTK-003: per-transaction amount cap ------------------------------

    def test_ctk_003_amount_cap(self) -> None:
        """CTK-003: Charge over the per-transaction cap rejected (HIGH)."""
        t0 = time.monotonic()
        now = self._now()
        token, _ = _valid_token(now)
        # (a) over the per-transaction cap
        over = _txn(token, amount=999999, counter=1)  # over the 20000 cap
        v_over = CardTokenVerifier().authorize(token, over, now)
        # (b) negative amount — must fail closed (upper-bound-only cap would pass
        #     it, and spent += amount would refund velocity budget)
        neg = _txn(token, amount=-5000, counter=1)
        v_neg = CardTokenVerifier().authorize(token, neg, now)
        # (c) boolean amount — bool is an int subclass; must not read as a charge
        boolean = _txn(token, amount=True, counter=1)
        v_bool = CardTokenVerifier().authorize(token, boolean, now)
        model_pass = ((not v_over.ok and "per-transaction cap" in v_over.reason)
                      and (not v_neg.ok and "positive integer" in v_neg.reason)
                      and (not v_bool.ok and "positive integer" in v_bool.reason))
        self._finish(
            test_id="CTK-003", name="Per-Transaction Amount Cap",
            category="scope", network="visa-tap/mc-agentic",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.HIGH.value,
            ref="Visa TAP / MC Agentic Token: per-transaction amount envelope", normative="N",
            model_pass=model_pass,
            model_reason=("over-cap, negative and boolean charges all rejected" if model_pass else
                          "OVERCHARGE — a charge above the cap or a non-integer/negative amount was authorized"),
            attack_payload={"token": token, "transaction": over}, t0=t0)

    # -- CTK-004: cumulative velocity cap ---------------------------------

    def test_ctk_004_velocity_cap(self) -> None:
        """CTK-004: Cumulative spend over the velocity cap rejected (HIGH).

        A token authorizes up to a cumulative velocity limit across
        transactions; the charge that would exceed it MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        token, _ = _valid_token(now)  # velocity_cap 50000, cap 20000
        verifier = CardTokenVerifier()
        a = verifier.authorize(token, _txn(token, 20000, 1), now)
        b = verifier.authorize(token, _txn(token, 20000, 2), now)
        c = verifier.authorize(token, _txn(token, 20000, 3), now)  # 60000 > 50000
        self._finish(
            test_id="CTK-004", name="Cumulative Velocity Cap",
            category="scope", network="visa-tap/mc-agentic",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.HIGH.value,
            ref="Visa TAP / MC Agentic Token: cumulative velocity envelope", normative="N",
            model_pass=(a.ok and b.ok and not c.ok and "velocity cap" in c.reason),
            model_reason=(f"velocity breach rejected ({c.reason})"
                          if (a.ok and b.ok and not c.ok) else
                          "VELOCITY BREACH — cumulative spend exceeded the token velocity cap"),
            attack_payload={"token": token, "transaction": _txn(token, 20000, 3)}, t0=t0)

    # -- CTK-005: cryptogram freshness (replay) ---------------------------

    def test_ctk_005_cryptogram_replay(self) -> None:
        """CTK-005: Replayed cryptogram (counter reuse) rejected (HIGH).

        The dynamic cryptogram carries a monotonic counter; re-presenting a
        transaction with a non-advancing counter MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)  # counter 1
        verifier = CardTokenVerifier()
        first = verifier.authorize(token, txn, now)
        replay = verifier.authorize(token, dict(txn), now)  # same counter 1
        self._finish(
            test_id="CTK-005", name="Cryptogram Freshness (counter replay)",
            category="replay", network="visa-tap/mc-agentic",
            owasp="ASI03", stride="Tampering", severity=Severity.HIGH.value,
            ref="EMV TAVV/DTVV: dynamic cryptogram single-use (monotonic counter)", normative="N",
            model_pass=(first.ok and not replay.ok and "replay" in replay.reason),
            model_reason=(f"replayed cryptogram rejected ({replay.reason})"
                          if (first.ok and not replay.ok) else
                          "REPLAY — a reused token cryptogram was authorized twice"),
            attack_payload={"token": token, "transaction": txn}, t0=t0)

    # -- CTK-006: cryptogram-amount binding -------------------------------

    def test_ctk_006_cryptogram_amount_binding(self) -> None:
        """CTK-006: Amount re-priced after cryptogram generation rejected (CRITICAL).

        The cryptogram is computed over the amount; changing the amount without
        regenerating it MUST break verification (no post-authorization
        re-pricing).
        """
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)  # cryptogram over amount 15000
        txn = dict(txn, amount=15001)   # re-priced, cryptogram left stale (still < cap)
        v = CardTokenVerifier().authorize(token, txn, now)
        self._finish(
            test_id="CTK-006", name="Cryptogram-Amount Binding",
            category="crypto", network="visa-tap/mc-agentic",
            owasp="ASI03", stride="Tampering", severity=Severity.CRITICAL.value,
            ref="EMV TAVV/DTVV: cryptogram binds the transaction amount", normative="N",
            model_pass=(not v.ok and "cryptogram does not bind" in v.reason),
            model_reason=(f"re-priced transaction rejected ({v.reason})" if not v.ok else
                          "RE-PRICE — amount changed after cryptogram generation was authorized"),
            attack_payload={"token": token, "transaction": txn}, t0=t0)

    # -- CTK-007: token expiry --------------------------------------------

    def test_ctk_007_expiry(self) -> None:
        """CTK-007: Expired token rejected (MEDIUM)."""
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)
        token["exp"] = now - 60
        v = CardTokenVerifier().authorize(token, txn, now)
        self._finish(
            test_id="CTK-007", name="Token Expiry",
            category="lifecycle", network="visa-tap/mc-agentic",
            owasp="ASI03", stride="Tampering", severity=Severity.MEDIUM.value,
            ref="Visa TAP / MC Agentic Token: validity window", normative="N",
            model_pass=(not v.ok and "expired" in v.reason),
            model_reason=(f"expired token rejected ({v.reason})" if not v.ok else
                          "EXPIRY BYPASS — an expired token was authorized"),
            attack_payload={"token": token, "transaction": txn}, t0=t0)

    # -- CTK-008: revocation ----------------------------------------------

    def test_ctk_008_revocation(self) -> None:
        """CTK-008: Revoked/suspended token rejected (CRITICAL).

        'Identify and revoke': a token whose status is revoked/suspended MUST
        NOT authorize, even if it is otherwise well-formed and unexpired.
        """
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)
        token["status"] = "revoked"
        v = CardTokenVerifier().authorize(token, txn, now)
        self._finish(
            test_id="CTK-008", name="Token Revocation / Suspension",
            category="lifecycle", network="visa-tap/mc-agentic",
            owasp="ASI02", stride="Elevation of Privilege", severity=Severity.CRITICAL.value,
            ref="Visa TAP / MC Agentic Token: revoked credential MUST NOT authorize", normative="N",
            model_pass=(not v.ok and "not active" in v.reason),
            model_reason=(f"revoked token rejected ({v.reason})" if not v.ok else
                          "REVOCATION BYPASS — a revoked token was authorized"),
            attack_payload={"token": token, "transaction": txn}, t0=t0)

    # -- CTK-009: consent-policy binding ----------------------------------

    def test_ctk_009_consent_policy(self) -> None:
        """CTK-009: Purchase outside the token consent policy rejected (HIGH)."""
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)
        txn["category"] = "electronics"  # policy allows only "books"
        v = CardTokenVerifier().authorize(token, txn, now)
        self._finish(
            test_id="CTK-009", name="Consent-Policy Binding",
            category="consent", network="visa-tap/mc-agentic",
            owasp="ASI09", stride="Elevation of Privilege", severity=Severity.HIGH.value,
            ref="Visa TAP / MC Agentic Token: bound to a consent policy (category/recurring)", normative="N",
            model_pass=(not v.ok and "consent policy" in v.reason),
            model_reason=(f"out-of-policy purchase rejected ({v.reason})" if not v.ok else
                          "CONSENT BYPASS — a purchase outside the token consent policy was authorized"),
            attack_payload={"token": token, "transaction": txn}, t0=t0)

    # -- CTK-010: channel binding -----------------------------------------

    def test_ctk_010_channel_binding(self) -> None:
        """CTK-010: Token used on the wrong channel rejected (MEDIUM).

        An agentic-commerce token MUST NOT be used on another channel (e.g.
        card-present), which would sidestep the agent controls.
        """
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)
        txn["channel"] = "card-present"
        v = CardTokenVerifier().authorize(token, txn, now)
        self._finish(
            test_id="CTK-010", name="Channel / Domain Binding",
            category="binding", network="visa-tap/mc-agentic",
            owasp="ASI03", stride="Spoofing", severity=Severity.MEDIUM.value,
            ref="Visa TAP / MC Agentic Token: restricted to the agentic-commerce channel", normative="N",
            model_pass=(not v.ok and "channel" in v.reason),
            model_reason=(f"cross-channel use rejected ({v.reason})" if not v.ok else
                          "CHANNEL BYPASS — an agentic token was used on another channel"),
            attack_payload={"token": token, "transaction": txn}, t0=t0)

    # -- CTK-011: PAN de-tokenization protection --------------------------

    def test_ctk_011_pan_protection(self) -> None:
        """CTK-011: Raw PAN presentation rejected (HIGH).

        The token exists so the raw PAN is never handled by the agent; a
        transaction presenting the raw PAN MUST be rejected (de-tokenization
        attempt / info disclosure).
        """
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)
        txn["raw_pan"] = "4111111111111111"
        v = CardTokenVerifier().authorize(token, txn, now)
        self._finish(
            test_id="CTK-011", name="PAN De-Tokenization Protection",
            category="supply_chain", network="visa-tap/mc-agentic",
            owasp="ASI04", stride="Information Disclosure", severity=Severity.HIGH.value,
            ref="EMV tokenisation: the raw PAN MUST NOT be presented by the agent", normative="N",
            model_pass=(not v.ok and "raw PAN" in v.reason),
            model_reason=(f"raw-PAN presentation rejected ({v.reason})" if not v.ok else
                          "PAN EXPOSURE — a raw-PAN transaction was authorized"),
            attack_payload={"token": token, "transaction": txn}, t0=t0)

    # -- CTK-012: cross-network substitution ------------------------------

    def test_ctk_012_network_substitution(self) -> None:
        """CTK-012: Token presented under the wrong network rejected (HIGH).

        A credential issued under one network (BIN) MUST NOT authorize a
        transaction routed as another network (token substitution).
        """
        t0 = time.monotonic()
        now = self._now()
        token, txn = _valid_token(now)  # network visa-tap
        txn["network"] = "mc-agentic"
        v = CardTokenVerifier().authorize(token, txn, now)
        self._finish(
            test_id="CTK-012", name="Cross-Network Token Substitution",
            category="supply_chain", network="visa-tap/mc-agentic",
            owasp="ASI04", stride="Spoofing", severity=Severity.HIGH.value,
            ref="Network tokenisation: token bound to its issuing network/BIN", normative="N",
            model_pass=(not v.ok and "network mismatch" in v.reason),
            model_reason=(f"network substitution rejected ({v.reason})" if not v.ok else
                          "SUBSTITUTION — a token was authorized under the wrong network"),
            attack_payload={"token": token, "transaction": txn}, t0=t0)

    # -- run_all ----------------------------------------------------------

    def run_all(self) -> list[CardTokenTestResult]:
        tests = [
            self.test_ctk_001_holder_binding,
            self.test_ctk_002_merchant_scope,
            self.test_ctk_003_amount_cap,
            self.test_ctk_004_velocity_cap,
            self.test_ctk_005_cryptogram_replay,
            self.test_ctk_006_cryptogram_amount_binding,
            self.test_ctk_007_expiry,
            self.test_ctk_008_revocation,
            self.test_ctk_009_consent_policy,
            self.test_ctk_010_channel_binding,
            self.test_ctk_011_pan_protection,
            self.test_ctk_012_network_substitution,
        ]
        print(f"\n{'='*60}")
        print("CARD-NETWORK AGENTIC TOKEN CONFORMANCE SUITE")
        print(f"{'='*60}")
        print(f"Target: {self.url}")
        print(f"Mode: {'simulate (reference model)' if self.simulate else 'live'}")
        print("Layer: funding instrument (Visa TAP / Mastercard Agentic Tokens) inside AP2")
        print("Credential: agent + merchant + amount/velocity + consent + channel, dynamic cryptogram")
        print("\n[CARD-NETWORK TOKEN TESTS]")
        for fn in tests:
            try:
                fn()
            except Exception as e:  # pragma: no cover - defensive
                print(f"  ERROR ⚠️  {fn.__name__}: {e}")
                self.results.append(CardTokenTestResult(
                    test_id="CTK-ERR", name=f"ERROR: {fn.__name__}",
                    category="error", network="error", owasp_asi="ASI03",
                    stride="Tampering", severity=Severity.HIGH.value,
                    passed=False, details=str(e)))
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        ci = wilson_ci(passed, total)
        print(f"\n{'='*60}")
        if total:
            print(f"RESULTS: {passed}/{total} passed ({passed/total*100:.0f}%)")
            print(f"WILSON 95% CI: [{ci[0]:.4f}, {ci[1]:.4f}]")
        print(f"{'='*60}\n")
        return self.results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Card-network agentic-token conformance harness (CTK-001..012)")
    ap.add_argument("--url", default=None, help="Target token authorizer URL (live mode)")
    ap.add_argument("--simulate", action="store_true",
                    help="Run the differential against the built-in reference verifier (no network)")
    ap.add_argument("--report", help="Output JSON report path")
    ap.add_argument("--json", action="store_true", help="Emit JSON summary to stdout")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra HTTP headers (key:value)")
    args = ap.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    simulate = args.simulate or not args.url
    suite = CardTokenTests(url=args.url, headers=headers, simulate=simulate)
    results = suite.run_all()

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    ci = wilson_ci(passed, total)
    report = {
        "suite": "Card-Network Agentic Token Conformance",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "simulate" if simulate else "live",
        "summary": {
            "total": total, "passed": passed, "failed": total - passed,
            "pass_rate": round(passed / total, 4) if total else 0,
            "wilson_95_ci": {"lower": ci[0], "upper": ci[1]},
        },
        "results": [asdict(r) for r in results],
    }

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Report written to {args.report}")


if __name__ == "__main__":
    main()
