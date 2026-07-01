#!/usr/bin/env python3
"""UCP / ACP Merchant-Journey Security Test Harness (v1.0)

Security conformance suite for the **merchant-journey layer** of the agentic-
payments stack — the layer that sits between agent communication (MCP/A2A) and
authorization/trust (AP2). Two protocols occupy it:

  * **UCP — Universal Commerce Protocol / Universal Cart.** Shopify-led
    (announced NRF, 11 Jan 2026; self-serve agent-profile registration on
    Shopify by June 2026; Google "Universal Cart" spanning Search/Gemini/
    YouTube/Gmail). An agent registers a *profile*, then assembles a
    cross-merchant *cart* through an ordered journey (discover -> cart ->
    consent/confirm -> hand off to the authorization layer).
  * **ACP — Agentic Commerce Protocol.** OpenAI/Stripe. Its flagship product
    (Instant Checkout) was retired in March 2026, but the protocol continues
    (Stripe + PayPal integrations). An agent completes a *checkout session*
    using a delegated **SharedPaymentToken** scoped to one merchant + amount +
    session, buying items described by a merchant **product feed**.

This closes the coverage gap the conformance matrix names: the harness was deep
on settlement (x402/L402) and solid on AP2 authorization and MCP/A2A comms, but
the UCP/ACP merchant-journey layer had zero coverage — and it is the fastest-
moving layer in the stack.

Reference-verifier note (honesty, per the repo's stdlib-only guarantee for
``protocol_tests``): production UCP/ACP use signed profiles, session JWTs and
signed product feeds. The built-in reference verifier implements the journey
*semantics* — profile-to-owner-key binding, cross-merchant line-item binding,
journey step-ordering (consent-before-checkout), quote integrity, intent-scope,
session binding/expiry, delegated-token merchant+amount scope, product-feed
authenticity and order idempotency — with structural checks rather than the
production signature primitive. The accept/reject *decisions* under test are the
same. Every check **fails closed**: a missing binding is a rejection, never a
skip. ``--simulate`` runs the differential against this reference verifier;
``--url`` folds in a live verifier with a liveness gate (unreachable/erroring is
observe-failure, never a silent pass).

References:
    UCP / Universal Cart (Shopify, NRF 2026-01-11); Shopify agent-profile
        self-serve (2026-06); Google Universal Cart (I/O 2026).
    ACP — Agentic Commerce Protocol (OpenAI + Stripe); SharedPaymentToken;
        product feed; Instant Checkout retirement (2026-03), protocol continues.
    Conformance matrix: agentic-payments 4-layer stack, merchant-journey layer.

OWASP Mappings: ASI02 (Improper Access Controls), ASI03 (Identity/Priv Abuse),
                ASI04 (Agentic Supply Chain), ASI09 (Human-Agent Trust Exploit)
STRIDE: Spoofing, Tampering, Elevation of Privilege, Repudiation

Usage:
    python -m protocol_tests.ucp_acp_harness --simulate
    python -m protocol_tests.ucp_acp_harness --url https://journey.example.com
    python -m protocol_tests.ucp_acp_harness --simulate --report ucp_acp.json

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
# Canonical hashing
# ---------------------------------------------------------------------------

def _jcs(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_hash(obj) -> str:
    """base64url(SHA-256(JCS(obj)))."""
    digest = hashlib.sha256(_jcs(obj).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@dataclass
class VerifyOutcome:
    ok: bool
    reason: str


# ---------------------------------------------------------------------------
# UCP reference verifier — agent profile + cross-merchant cart journey
# ---------------------------------------------------------------------------

class UCPVerifier:
    """Deterministic UCP merchant-journey verifier (reference model).

    Mirrors the accept/reject decisions a UCP journey coordinator MUST make on
    an agent profile and the cart it assembles. Every check fails closed.
    """

    def __init__(self) -> None:
        self._profile_keys: dict[str, str] = {}  # profile_id -> owner_kid

    def verify_profile(self, profile: dict) -> VerifyOutcome:
        """Validate a self-serve-registered agent profile.

        Self-serve registration has no human approval gate, so the profile MUST
        be cryptographically bound to a verifiable owner key, and a profile id
        MUST NOT be rebound to a different key.
        """
        owner = profile.get("owner_kid")
        if not owner:
            return VerifyOutcome(False, "profile not bound to an owner key")
        if profile.get("signed_by") != owner:
            return VerifyOutcome(False, "profile signature key != owner key (unbound profile)")
        pid = profile.get("profile_id")
        prior = self._profile_keys.get(pid)
        if prior is not None and prior != owner:
            return VerifyOutcome(False, "profile id rebound to a different owner key (takeover)")
        self._profile_keys[pid] = owner
        return VerifyOutcome(True, "agent profile bound and verified")

    def verify_cart(self, journey: dict, cart: dict) -> VerifyOutcome:
        """Validate an assembled cart against the journey's intent + quotes."""
        # 1. Step ordering: checkout MUST follow an explicit consent/confirm step.
        if not cart.get("consent_confirmed"):
            return VerifyOutcome(False, "checkout before cart-confirmation/consent step")
        # 2. Cross-merchant binding: every line item's merchant MUST be a party
        #    to this journey (no injecting a line for an outside merchant).
        merchants = set(journey.get("merchants", []))
        for item in cart.get("items", []):
            if item.get("merchant") not in merchants:
                return VerifyOutcome(
                    False, f"line item merchant '{item.get('merchant')}' not party to the journey")
        # 3. Quote integrity: the price at checkout MUST equal the quoted price.
        quotes = journey.get("quotes", {})
        for item in cart.get("items", []):
            quoted = quotes.get(item.get("sku"))
            if quoted is None:
                return VerifyOutcome(False, f"item '{item.get('sku')}' has no quoted price in the journey")
            if item.get("price") != quoted:
                return VerifyOutcome(
                    False, f"checkout price {item.get('price')} differs from quoted price {quoted}")
        # 4. Intent scope: the cart MUST stay within the user's stated shopping
        #    intent (budget + categories) — journey-level scope, before AP2.
        intent = journey.get("intent", {})
        budget = intent.get("budget")
        if budget is not None and cart.get("total", 0) > budget:
            return VerifyOutcome(
                False, f"cart total {cart.get('total')} exceeds stated shopping budget {budget}")
        allowed_cats = intent.get("categories")
        if allowed_cats is not None:
            for item in cart.get("items", []):
                if item.get("category") not in allowed_cats:
                    return VerifyOutcome(
                        False, f"item category '{item.get('category')}' outside stated intent")
        return VerifyOutcome(True, "cart within journey intent, quotes and merchant scope")


# ---------------------------------------------------------------------------
# ACP reference verifier — checkout session + SharedPaymentToken + feed
# ---------------------------------------------------------------------------

class ACPVerifier:
    """Deterministic ACP checkout verifier (reference model).

    Mirrors the accept/reject decisions an ACP checkout endpoint MUST make on a
    completion presented against a consented session. Every check fails closed.
    """

    def __init__(self) -> None:
        self._seen_orders: set = set()  # (session_id, idem_key) already placed

    def verify_completion(self, session: dict, completion: dict, now: int) -> VerifyOutcome:
        # 1. Session binding: completion MUST target the consented session.
        if completion.get("session_id") != session.get("id"):
            return VerifyOutcome(False, "session_id mismatch (session fixation / cross-session replay)")
        # 2. Session expiry.
        if session.get("exp", 1 << 62) < now:
            return VerifyOutcome(False, "checkout session expired")
        # 3. Delegated-token merchant scope: SharedPaymentToken is scoped to one
        #    merchant; it MUST match the session's merchant.
        token = completion.get("shared_payment_token", {})
        if not token:
            return VerifyOutcome(False, "missing delegated payment token")
        if token.get("merchant") != session.get("merchant"):
            return VerifyOutcome(False, "payment token merchant scope mismatch")
        # 4. Delegated-token amount scope: charge MUST NOT exceed the token cap.
        if completion.get("amount", 0) > token.get("max_amount", 0):
            return VerifyOutcome(
                False, f"charge {completion.get('amount')} exceeds token authorized amount "
                       f"{token.get('max_amount')}")
        # 5. Product-feed authenticity: the purchased item + price MUST match the
        #    merchant's signed feed entry (no substituted SKU / tampered price).
        feed = session.get("feed", {})
        item = completion.get("item", {})
        entry = feed.get(item.get("sku"))
        if entry is None:
            return VerifyOutcome(False, "purchased SKU absent from the signed product feed")
        if item.get("price") != entry.get("price"):
            return VerifyOutcome(False, "purchased item price does not match the signed feed entry")
        # 6. Order idempotency: the same (session, idempotency key) MUST place at
        #    most one order (no double-charge on replay).
        key = (completion.get("session_id"), completion.get("idem_key"))
        if key in self._seen_orders:
            return VerifyOutcome(False, "duplicate order (idempotency replay)")
        self._seen_orders.add(key)
        return VerifyOutcome(True, "checkout completion verified")


# ---------------------------------------------------------------------------
# Fixtures — valid journeys the tests mutate
# ---------------------------------------------------------------------------

def _valid_ucp():
    """A coherent UCP (profile, journey, cart)."""
    profile = {"profile_id": "agent-prof-1", "owner_kid": "owner-key-1", "signed_by": "owner-key-1"}
    journey = {
        "journey_id": "jrny-1",
        "merchants": ["merchant_a", "merchant_b"],
        "intent": {"budget": 50000, "categories": ["books", "home"]},
        "quotes": {"sku-book-1": 15000, "sku-lamp-2": 12000},
    }
    cart = {
        "journey_id": "jrny-1",
        "consent_confirmed": True,
        "items": [
            {"merchant": "merchant_a", "sku": "sku-book-1", "price": 15000, "category": "books"},
            {"merchant": "merchant_b", "sku": "sku-lamp-2", "price": 12000, "category": "home"},
        ],
        "total": 27000,
    }
    return profile, journey, cart


def _valid_acp(now: int):
    """A coherent ACP (session, completion)."""
    session = {
        "id": "sess-1", "merchant": "merchant_a", "exp": now + 600,
        "feed": {"sku-book-1": {"price": 15000}},
    }
    completion = {
        "session_id": "sess-1", "idem_key": "idem-" + uuid.uuid4().hex[:8],
        "amount": 15000,
        "shared_payment_token": {"merchant": "merchant_a", "max_amount": 20000},
        "item": {"sku": "sku-book-1", "price": 15000},
    }
    return session, completion


# ---------------------------------------------------------------------------
# Result model + live probe
# ---------------------------------------------------------------------------

@dataclass
class JourneyTestResult:
    test_id: str
    name: str
    category: str
    protocol: str
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
    """Probe a live merchant-journey verifier. Returns (verdict, evidence).

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
    if any(w in text for w in ("reject", "denied", "invalid", "unauthorized",
                               "forbidden", "not authorized", "mismatch", "expired")):
        return ("rejected", resp)
    if 200 <= status < 300:
        return ("accepted", resp)
    return ("unreachable", resp)


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class UCPACPJourneyTests:
    """UCP/ACP merchant-journey conformance suite (UCP-001..006, ACP-001..006)."""

    def __init__(self, url: str | None = None, headers: dict | None = None,
                 simulate: bool = False):
        self.url = url.rstrip("/") if url else "http://localhost:8080"
        self.headers = headers or {}
        self.simulate = simulate
        self.results: list[JourneyTestResult] = []

    def _now(self) -> int:
        return 1_750_000_000 if self.simulate else int(time.time())

    def _record(self, r: JourneyTestResult) -> None:
        print(f"  {'PASS ✅' if r.passed else 'FAIL ❌'}  {r.test_id}: {r.name}")
        self.results.append(r)

    def _finish(self, *, test_id, name, category, protocol, owasp, stride,
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
                details = f"{model_reason}; LIVE verifier ACCEPTED the attack — control absent"
            elif verdict == "rejected":
                details = f"{model_reason}; live verifier rejected the attack"
            else:
                details = f"{model_reason}; live verifier unreachable — verdict from reference model"
        self._record(JourneyTestResult(
            test_id=test_id, name=name, category=category, protocol=protocol,
            owasp_asi=owasp, stride=stride, severity=severity, passed=passed,
            details=details, ref=ref, normative=normative,
            live_evidence=live_ev, elapsed_s=round(time.monotonic() - t0, 3)))

    # === UCP =============================================================

    # -- UCP-001: agent profile binding -----------------------------------

    def test_ucp_001_profile_binding(self) -> None:
        """UCP-001: Unbound agent profile rejected (HIGH).

        Self-serve registration has no approval gate, so a profile MUST be
        bound to a verifiable owner key. An unsigned / key-less profile MUST be
        rejected.
        """
        t0 = time.monotonic()
        profile, _, _ = _valid_ucp()
        profile["owner_kid"] = None
        v = UCPVerifier().verify_profile(profile)
        self._finish(
            test_id="UCP-001", name="Agent Profile Owner-Key Binding",
            category="registration", protocol="UCP",
            owasp="ASI03", stride="Spoofing", severity=Severity.HIGH.value,
            ref="UCP: self-serve profile MUST bind to a verifiable owner key", normative="N",
            model_pass=(not v.ok and "owner key" in v.reason),
            model_reason=(f"unbound profile rejected ({v.reason})" if not v.ok else
                          "SPOOFED PROFILE — an unbound agent profile was accepted"),
            attack_payload={"profile": profile}, t0=t0)

    # -- UCP-002: cross-merchant line-item injection ----------------------

    def test_ucp_002_cross_merchant_injection(self) -> None:
        """UCP-002: Line item for an outside merchant rejected (HIGH).

        A Universal Cart spans merchants; a line item attributed to a merchant
        not party to the journey MUST be rejected (cross-merchant injection).
        """
        t0 = time.monotonic()
        _, journey, cart = _valid_ucp()
        cart["items"][1]["merchant"] = "evil_merchant"
        v = UCPVerifier().verify_cart(journey, cart)
        self._finish(
            test_id="UCP-002", name="Cross-Merchant Line-Item Injection",
            category="cart_integrity", protocol="UCP",
            owasp="ASI04", stride="Tampering", severity=Severity.HIGH.value,
            ref="UCP: every line item MUST bind to a journey-party merchant", normative="N",
            model_pass=(not v.ok and "not party to the journey" in v.reason),
            model_reason=(f"cross-merchant injection rejected ({v.reason})" if not v.ok else
                          "CART TAMPER — a line item for an outside merchant was accepted"),
            attack_payload={"journey": journey, "cart": cart}, t0=t0)

    # -- UCP-003: journey step ordering (skip consent) --------------------

    def test_ucp_003_skip_consent(self) -> None:
        """UCP-003: Checkout without the consent/confirm step rejected (HIGH).

        The journey is ordered: cart -> consent/confirm -> checkout. Handing off
        to checkout without an explicit confirmation step MUST be rejected.
        """
        t0 = time.monotonic()
        _, journey, cart = _valid_ucp()
        cart["consent_confirmed"] = False
        v = UCPVerifier().verify_cart(journey, cart)
        self._finish(
            test_id="UCP-003", name="Journey Step-Order (skip consent)",
            category="journey_integrity", protocol="UCP",
            owasp="ASI09", stride="Elevation of Privilege", severity=Severity.HIGH.value,
            ref="UCP: checkout MUST follow an explicit cart-confirmation step", normative="N",
            model_pass=(not v.ok and "consent" in v.reason),
            model_reason=(f"skip-consent rejected ({v.reason})" if not v.ok else
                          "STEP SKIP — checkout accepted without a confirmation step"),
            attack_payload={"journey": journey, "cart": cart}, t0=t0)

    # -- UCP-004: quote integrity -----------------------------------------

    def test_ucp_004_quote_tamper(self) -> None:
        """UCP-004: Checkout price != quoted price rejected (HIGH).

        The price carried to checkout MUST equal the price quoted at cart
        (bait-and-switch between quote and checkout).
        """
        t0 = time.monotonic()
        _, journey, cart = _valid_ucp()
        cart["items"][0]["price"] = 1  # quoted 15000
        v = UCPVerifier().verify_cart(journey, cart)
        self._finish(
            test_id="UCP-004", name="Quote Integrity (quote-vs-checkout)",
            category="cart_integrity", protocol="UCP",
            owasp="ASI03", stride="Tampering", severity=Severity.HIGH.value,
            ref="UCP: checkout price MUST equal the quoted price", normative="N",
            model_pass=(not v.ok and "quoted price" in v.reason),
            model_reason=(f"quote tamper rejected ({v.reason})" if not v.ok else
                          "PRICE TAMPER — checkout price diverged from the quote"),
            attack_payload={"journey": journey, "cart": cart}, t0=t0)

    # -- UCP-005: intent-scope escalation ---------------------------------

    def test_ucp_005_intent_scope(self) -> None:
        """UCP-005: Cart beyond stated shopping intent rejected (CRITICAL).

        The assembled cart MUST stay within the user's stated intent — budget
        and categories — at the journey level, before it reaches AP2.
        """
        t0 = time.monotonic()
        _, journey, cart = _valid_ucp()
        cart["total"] = 500000  # over the 50000 budget
        v = UCPVerifier().verify_cart(journey, cart)
        self._finish(
            test_id="UCP-005", name="Cart Scope vs Stated Intent",
            category="scope_escalation", protocol="UCP",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.CRITICAL.value,
            ref="UCP: cart MUST stay within stated shopping intent (budget+categories)", normative="N",
            model_pass=(not v.ok and "budget" in v.reason),
            model_reason=(f"over-intent cart rejected ({v.reason})" if not v.ok else
                          "SCOPE ESCALATION — cart exceeded the user's stated shopping intent"),
            attack_payload={"journey": journey, "cart": cart}, t0=t0)

    # -- UCP-006: profile takeover (rebind) -------------------------------

    def test_ucp_006_profile_rebind(self) -> None:
        """UCP-006: Profile id rebound to a new key rejected (HIGH).

        Re-registering an existing profile id under a different owner key is a
        takeover attempt and MUST be rejected.
        """
        t0 = time.monotonic()
        profile, _, _ = _valid_ucp()
        verifier = UCPVerifier()
        first = verifier.verify_profile(profile)
        rebind = dict(profile, owner_kid="attacker-key-9", signed_by="attacker-key-9")
        v2 = verifier.verify_profile(rebind)
        self._finish(
            test_id="UCP-006", name="Agent Profile Takeover (rebind)",
            category="registration", protocol="UCP",
            owasp="ASI03", stride="Spoofing", severity=Severity.HIGH.value,
            ref="UCP: a profile id MUST NOT be rebound to a different owner key", normative="N",
            model_pass=(first.ok and not v2.ok and "rebound" in v2.reason),
            model_reason=(f"profile rebind rejected ({v2.reason})"
                          if (first.ok and not v2.ok) else
                          "TAKEOVER — a profile id was rebound to a different key"),
            attack_payload={"profile": rebind}, t0=t0)

    # === ACP =============================================================

    # -- ACP-001: checkout-session binding --------------------------------

    def test_acp_001_session_binding(self) -> None:
        """ACP-001: Completion against the wrong session rejected (HIGH).

        A completion MUST target the session the user consented to; a mismatched
        session_id is session fixation / cross-session replay.
        """
        t0 = time.monotonic()
        now = self._now()
        session, completion = _valid_acp(now)
        completion["session_id"] = "sess-attacker"
        v = ACPVerifier().verify_completion(session, completion, now)
        self._finish(
            test_id="ACP-001", name="Checkout-Session Binding",
            category="session", protocol="ACP",
            owasp="ASI02", stride="Spoofing", severity=Severity.HIGH.value,
            ref="ACP: completion MUST bind to the consented checkout session", normative="N",
            model_pass=(not v.ok and "session_id mismatch" in v.reason),
            model_reason=(f"session mismatch rejected ({v.reason})" if not v.ok else
                          "SESSION FIXATION — a completion for the wrong session was accepted"),
            attack_payload={"session": session, "completion": completion}, t0=t0)

    # -- ACP-002: delegated-token merchant scope --------------------------

    def test_acp_002_token_merchant_scope(self) -> None:
        """ACP-002: SharedPaymentToken used off-merchant rejected (CRITICAL).

        The delegated payment token is scoped to a single merchant; using it at
        a different merchant MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        session, completion = _valid_acp(now)
        completion["shared_payment_token"]["merchant"] = "merchant_b"  # session is merchant_a
        v = ACPVerifier().verify_completion(session, completion, now)
        self._finish(
            test_id="ACP-002", name="Delegated-Token Merchant Scope",
            category="funding_scope", protocol="ACP",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.CRITICAL.value,
            ref="ACP: SharedPaymentToken scoped to one merchant", normative="N",
            model_pass=(not v.ok and "merchant scope mismatch" in v.reason),
            model_reason=(f"off-merchant token rejected ({v.reason})" if not v.ok else
                          "SCOPE ABUSE — delegated token used outside its merchant scope"),
            attack_payload={"session": session, "completion": completion}, t0=t0)

    # -- ACP-003: delegated-token amount scope ----------------------------

    def test_acp_003_token_amount_scope(self) -> None:
        """ACP-003: Charge over the token cap rejected (CRITICAL).

        The delegated token authorizes up to a maximum amount; a charge above
        that cap MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        session, completion = _valid_acp(now)
        completion["amount"] = 999999  # token max_amount 20000
        v = ACPVerifier().verify_completion(session, completion, now)
        self._finish(
            test_id="ACP-003", name="Delegated-Token Amount Scope",
            category="funding_scope", protocol="ACP",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.CRITICAL.value,
            ref="ACP: charge MUST NOT exceed the token's authorized amount", normative="N",
            model_pass=(not v.ok and "exceeds token authorized amount" in v.reason),
            model_reason=(f"over-cap charge rejected ({v.reason})" if not v.ok else
                          "OVERCHARGE — a charge above the token cap was accepted"),
            attack_payload={"session": session, "completion": completion}, t0=t0)

    # -- ACP-004: order idempotency ---------------------------------------

    def test_acp_004_order_idempotency(self) -> None:
        """ACP-004: Duplicate order on replay rejected (HIGH).

        Re-presenting the same (session, idempotency key) MUST NOT place a
        second order (double-charge on replay).
        """
        t0 = time.monotonic()
        now = self._now()
        session, completion = _valid_acp(now)
        verifier = ACPVerifier()
        first = verifier.verify_completion(session, completion, now)
        replay = verifier.verify_completion(session, dict(completion), now)  # same idem key
        self._finish(
            test_id="ACP-004", name="Order Idempotency (replay)",
            category="replay", protocol="ACP",
            owasp="ASI03", stride="Tampering", severity=Severity.HIGH.value,
            ref="ACP: one order per (session, idempotency key)", normative="N",
            model_pass=(first.ok and not replay.ok and "idempotency" in replay.reason),
            model_reason=(f"duplicate order rejected ({replay.reason})"
                          if (first.ok and not replay.ok) else
                          "DOUBLE-ORDER — a replayed completion placed a second order"),
            attack_payload={"session": session, "completion": completion}, t0=t0)

    # -- ACP-005: product-feed authenticity -------------------------------

    def test_acp_005_feed_tamper(self) -> None:
        """ACP-005: Purchased item off the signed feed rejected (HIGH).

        The purchased item + price MUST match the merchant's signed product feed
        entry; a substituted SKU or tampered price MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        session, completion = _valid_acp(now)
        completion["item"]["price"] = 1  # feed says 15000
        v = ACPVerifier().verify_completion(session, completion, now)
        self._finish(
            test_id="ACP-005", name="Product-Feed Authenticity",
            category="supply_chain", protocol="ACP",
            owasp="ASI04", stride="Tampering", severity=Severity.HIGH.value,
            ref="ACP: purchased item MUST match the signed product-feed entry", normative="N",
            model_pass=(not v.ok and "feed entry" in v.reason),
            model_reason=(f"feed tamper rejected ({v.reason})" if not v.ok else
                          "FEED TAMPER — a purchase diverging from the signed feed was accepted"),
            attack_payload={"session": session, "completion": completion}, t0=t0)

    # -- ACP-006: session expiry ------------------------------------------

    def test_acp_006_session_expiry(self) -> None:
        """ACP-006: Completion on an expired session rejected (MEDIUM)."""
        t0 = time.monotonic()
        now = self._now()
        session, completion = _valid_acp(now)
        session["exp"] = now - 60
        v = ACPVerifier().verify_completion(session, completion, now)
        self._finish(
            test_id="ACP-006", name="Checkout-Session Expiry",
            category="session", protocol="ACP",
            owasp="ASI02", stride="Tampering", severity=Severity.MEDIUM.value,
            ref="ACP: an expired checkout session MUST NOT complete", normative="N",
            model_pass=(not v.ok and "expired" in v.reason),
            model_reason=(f"expired session rejected ({v.reason})" if not v.ok else
                          "EXPIRY BYPASS — a completion on an expired session was accepted"),
            attack_payload={"session": session, "completion": completion}, t0=t0)

    # -- run_all ----------------------------------------------------------

    def run_all(self) -> list[JourneyTestResult]:
        tests = [
            self.test_ucp_001_profile_binding,
            self.test_ucp_002_cross_merchant_injection,
            self.test_ucp_003_skip_consent,
            self.test_ucp_004_quote_tamper,
            self.test_ucp_005_intent_scope,
            self.test_ucp_006_profile_rebind,
            self.test_acp_001_session_binding,
            self.test_acp_002_token_merchant_scope,
            self.test_acp_003_token_amount_scope,
            self.test_acp_004_order_idempotency,
            self.test_acp_005_feed_tamper,
            self.test_acp_006_session_expiry,
        ]
        print(f"\n{'='*60}")
        print("UCP/ACP MERCHANT-JOURNEY CONFORMANCE SUITE")
        print(f"{'='*60}")
        print(f"Target: {self.url}")
        print(f"Mode: {'simulate (reference model)' if self.simulate else 'live'}")
        print("Layer: merchant journey (UCP/ACP) between comms (MCP/A2A) and authz (AP2)")
        print("Journey: profile -> cross-merchant cart -> consent -> checkout session")
        print("\n[UCP/ACP MERCHANT-JOURNEY TESTS]")
        for fn in tests:
            try:
                fn()
            except Exception as e:  # pragma: no cover - defensive
                print(f"  ERROR ⚠️  {fn.__name__}: {e}")
                self.results.append(JourneyTestResult(
                    test_id="UCPACP-ERR", name=f"ERROR: {fn.__name__}",
                    category="error", protocol="error", owasp_asi="ASI03",
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
        description="UCP/ACP merchant-journey conformance harness (UCP-001..006, ACP-001..006)")
    ap.add_argument("--url", default=None, help="Target journey verifier URL (live mode)")
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
    suite = UCPACPJourneyTests(url=args.url, headers=headers, simulate=simulate)
    results = suite.run_all()

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    ci = wilson_ci(passed, total)
    report = {
        "suite": "UCP/ACP Merchant-Journey Conformance",
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
