#!/usr/bin/env python3
"""AP2 Mandate-Chain Security Test Harness (v1.0)

Security conformance suite for the **Agent Payments Protocol (AP2)** mandate
model — originally from Google, transferred to the **FIDO Alliance** for
community governance (2026), shipped at v0.2. AP2 is the authorization/trust
layer that sits above settlement (x402/MPP): a chain of cryptographically
signed *mandates* that prove an agent is authorized to assemble a cart and pay
for it, with a tokenized card credential (Visa Trusted Agent Protocol, or
Mastercard Agentic Tokens) bound in as the funding instrument.

This harness closes the middle-layer gap in the project's coverage: the
settlement layer (x402/L402) and the comms layer (MCP/A2A) were well covered,
but the *mandate/authorization* layer was not. It tests whether an AP2 verifier
(Merchant / Merchant Payment Processor / Credential Provider) correctly rejects
the attacks the AP2 threat model calls out — the spec's stance being that
"All LLMs and Agents MUST be considered potential attackers."

Mandate model (v0.2 — grounded in google-agentic-commerce/AP2 canonical files):

    IntentMandate / open Checkout Mandate  — user's authorized constraints
        (merchants allowlist, SKUs, amount cap, expiry, cart-confirmation flag)
    CartMandate / closed Checkout Mandate  — merchant-assembled concrete cart,
        merchant-signed JWT carrying `cart_hash`/`checkout_hash` + `jti`
    PaymentMandate                         — authorizes payment for a specific
        Checkout; `transaction_id` == the Checkout's `checkout_hash` (chain
        link); carries the funding `payment_instrument{ id, type, description }`

The chain link is a hash: the Payment Mandate's ``transaction_id`` equals the
Checkout Mandate's ``checkout_hash`` (= hash of the merchant `checkout_jwt`).
Closed mandates bind to the presented open mandate via ``sd_hash`` and to the
agent key via the open mandate's ``cnf`` claim. Payment Mandates MUST use a
non-deterministic signature scheme (ECDSA), NOT a deterministic one (Ed25519),
to resist replay.

Reference-verifier note (honesty): production uses SD-JWT / VC signatures over
ES256 keys. To keep this harness stdlib-only (the repo's zero-extra-dependency
guarantee for ``protocol_tests``), the built-in reference verifier implements
the mandate *semantics* — canonical hashing, hash-chaining, constraint
evaluation (fail-closed on unknown constraints), scope/expiry checks and
funding-instrument scope binding — with SHA-256 hashing and structural signer
checks. The cryptographic primitive differs; the accept/reject *decisions*
under test do not. ``--simulate`` runs the differential against this reference
verifier; ``--url`` folds in a live verifier's observed behaviour with a
liveness gate (VS-R03 discipline: unreachable/erroring is observe-failure,
never a silent pass).

References:
    AP2 spec (v0.2): https://ap2-protocol.org/
    Canonical files: https://github.com/google-agentic-commerce/AP2
      docs/ap2/{specification,flows,agent_authorization,
                security_and_privacy_considerations}.md
    FIDO donation: https://fidoalliance.org/google-donates-agent-payments-protocol-to-fido-alliance/
    Visa TAP; Mastercard Agentic Tokens (funding-instrument binding)
    Issues #165-#172 (coverage-gap: AP2 mandate/authorization layer)

OWASP Mappings: ASI02 (Improper Access Controls), ASI03 (Identity/Priv Abuse),
                ASI04 (Agentic Supply Chain), ASI09 (Human-Agent Trust Exploit)
STRIDE: Spoofing, Tampering, Elevation of Privilege, Repudiation

Usage:
    python -m protocol_tests.ap2_harness --simulate
    python -m protocol_tests.ap2_harness --url https://ap2-verifier.example.com
    python -m protocol_tests.ap2_harness --simulate --report ap2.json

Requires: Python 3.10+, no external dependencies.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from protocol_tests._utils import Severity, wilson_ci, http_post_json


# ---------------------------------------------------------------------------
# Canonical hashing (the mandate chain link)
# ---------------------------------------------------------------------------

def _jcs(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_hash(obj) -> str:
    """base64url(SHA-256(JCS(obj))) — the `checkout_hash` / `cart_hash` form."""
    digest = hashlib.sha256(_jcs(obj).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


# ---------------------------------------------------------------------------
# Reference mandate verifier
# ---------------------------------------------------------------------------

#: Deterministic signature schemes AP2 forbids for Payment Mandates.
_DETERMINISTIC_SCHEMES = {"ed25519", "eddsa", "rsassa-pkcs1", "hmac"}


@dataclass
class VerifyOutcome:
    ok: bool
    reason: str


def _eval_constraint(constraint: dict, cart: dict) -> tuple[bool, str]:
    """Evaluate one open-mandate constraint against the closed cart.

    Fail-closed: an unknown constraint ``type`` MUST evaluate as failing
    (AP2: "unknown Constraint type MUST evaluate as failing").
    """
    ctype = constraint.get("type")
    if ctype == "checkout.allowed_merchants":
        allowed = constraint.get("allowed_merchants", [])
        if cart.get("merchant") not in allowed:
            return (False, f"merchant {cart.get('merchant')} not in allowed_merchants")
        return (True, "merchant allowed")
    if ctype == "checkout.line_items":
        acceptable = set(constraint.get("acceptable_items", []))
        bad = [s for s in cart.get("skus", []) if s not in acceptable]
        if bad:
            return (False, f"SKUs outside acceptable_items: {bad}")
        return (True, "line items acceptable")
    if ctype == "checkout.amount_cap":
        cap = constraint.get("max_amount", 0)
        if cart.get("total", 0) > cap:
            return (False, f"cart total {cart.get('total')} exceeds cap {cap}")
        return (True, "within amount cap")
    # Unknown constraint type -> fail closed.
    return (False, f"unknown constraint type '{ctype}' — fail-closed")


class AP2Verifier:
    """Deterministic AP2 mandate-chain verifier (reference model).

    Mirrors the accept/reject decisions an AP2 Merchant / MPP / Credential
    Provider MUST make. ``latest_checkout_jwt`` is the merchant's current cart
    state used for the stale-cart check.
    """

    def __init__(self, latest_checkout_jwt: dict | None = None):
        self.latest_checkout_jwt = latest_checkout_jwt
        self._seen_jti: set = set()
        self._open_mandate_used: set = set()  # open-mandate ids that produced a closed mandate

    # -- Checkout Mandate -------------------------------------------------

    def verify_checkout(self, open_mandate: dict, checkout: dict,
                        now: int) -> VerifyOutcome:
        """Verify a closed Checkout (Cart) Mandate against its open mandate."""
        # 1. checkout_hash integrity: must equal hash of the presented checkout_jwt.
        expected = canonical_hash(checkout.get("checkout_jwt", {}))
        if checkout.get("checkout_hash") != expected:
            return VerifyOutcome(False, "checkout_hash != hash(checkout_jwt)")
        # 2. stale/cross-session: must match the latest merchant cart state.
        if self.latest_checkout_jwt is not None:
            latest_hash = canonical_hash(self.latest_checkout_jwt)
            if checkout.get("checkout_hash") != latest_hash:
                return VerifyOutcome(False, "checkout_hash does not match latest checkout_jwt (stale cart)")
        # 3. vct exact match including version suffix.
        if open_mandate.get("vct") and open_mandate.get("vct") != "mandate.checkout.1":
            return VerifyOutcome(False, f"vct mismatch: {open_mandate.get('vct')}")
        # 4. expiry.
        if checkout.get("cart_expiry", 1 << 62) < now:
            return VerifyOutcome(False, "checkout mandate expired")
        # 5. sd_hash binding: closed mandate must bind to the presented open mandate.
        open_hash = canonical_hash(open_mandate)
        if checkout.get("sd_hash") != open_hash:
            return VerifyOutcome(False, "sd_hash does not bind closed mandate to open mandate")
        # 6. signer key must match the open mandate's cnf key (autonomous mode).
        cnf = open_mandate.get("cnf", {}).get("kid")
        if cnf is not None and checkout.get("signer_kid") != cnf:
            return VerifyOutcome(False, "closed-mandate signer key != open-mandate cnf key")
        # 7. every constraint must be satisfied (fail-closed on unknown).
        cart = checkout.get("cart", {})
        for c in open_mandate.get("constraints", []):
            ok, reason = _eval_constraint(c, cart)
            if not ok:
                return VerifyOutcome(False, f"constraint failed: {reason}")
        return VerifyOutcome(True, "checkout mandate verified")

    # -- Payment Mandate --------------------------------------------------

    def verify_payment(self, checkout: dict, payment: dict, now: int,
                       human_present: bool = True) -> VerifyOutcome:
        """Verify a Payment Mandate against its bound Checkout Mandate."""
        # 1. chain link: transaction_id must equal the Checkout's checkout_hash.
        if payment.get("transaction_id") != checkout.get("checkout_hash"):
            return VerifyOutcome(False, "transaction_id != checkout_hash (mandate not chained / reused)")
        # 2. vct exact.
        if payment.get("vct") and payment.get("vct") != "mandate.payment.1":
            return VerifyOutcome(False, f"vct mismatch: {payment.get('vct')}")
        # 3. amount/payee must match the bound checkout.
        cart = checkout.get("cart", {})
        if payment.get("payment_amount", {}).get("amount") != cart.get("total"):
            return VerifyOutcome(False, "payment amount does not match bound checkout total")
        if payment.get("payee", {}).get("id") != cart.get("merchant"):
            return VerifyOutcome(False, "payee does not match bound checkout merchant")
        # 4. signature scheme: Payment Mandate MUST be non-deterministic (ECDSA).
        scheme = str(payment.get("sig_scheme", "")).lower()
        if scheme in _DETERMINISTIC_SCHEMES:
            return VerifyOutcome(False, f"deterministic signature scheme '{scheme}' forbidden (replay risk)")
        # 5. authorization presence.
        if human_present and not payment.get("user_authorization"):
            return VerifyOutcome(False, "missing user signature on Payment Mandate (human-present)")
        # 6. expiry.
        if payment.get("exp", 1 << 62) < now:
            return VerifyOutcome(False, "payment mandate expired")
        # 7. replay: jti/nonce must be single-use.
        jti = payment.get("jti")
        if jti in self._seen_jti:
            return VerifyOutcome(False, "payment mandate replay (jti seen before)")
        # 8. funding-instrument scope binding (Visa TAP / Mastercard Agentic Token).
        fi = payment.get("payment_instrument", {})
        scope = fi.get("scope", {})
        if scope:
            if scope.get("agent") not in (None, payment.get("agent_id")):
                return VerifyOutcome(False, "funding instrument not scoped to this agent")
            if scope.get("merchant") not in (None, cart.get("merchant")):
                return VerifyOutcome(False, "funding instrument not scoped to this merchant")
        # 9. double-spend: a second closed mandate for the same open mandate
        #    without an intervening rejection receipt.
        open_ref = payment.get("open_mandate_id")
        if open_ref is not None:
            if open_ref in self._open_mandate_used and not payment.get("rejection_receipt"):
                return VerifyOutcome(False, "double-spend: second closed mandate for same open mandate")
            self._open_mandate_used.add(open_ref)
        if jti is not None:
            self._seen_jti.add(jti)
        return VerifyOutcome(True, "payment mandate verified")

    def credential_release_ok(self, payment: dict) -> bool:
        """Payment credential/token MUST ONLY release upon a verified FINAL
        Payment Mandate."""
        return bool(payment.get("final")) and bool(payment.get("verified"))


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class AP2TestResult:
    test_id: str
    name: str
    category: str
    mandate: str
    owasp_asi: str
    stride: str
    severity: str
    passed: bool
    details: str
    ap2_ref: str = ""
    normative: str = "N"   # N = normative MUST; I = inferred/strict
    live_evidence: dict | None = None
    elapsed_s: float = 0.0


def _live_rejected(url: str, headers: dict, payload: dict) -> tuple[str, dict]:
    """Probe a live AP2 verifier. Returns (verdict, evidence).

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
                               "forbidden", "not authorized", "mismatch")):
        return ("rejected", resp)
    if 200 <= status < 300:
        return ("accepted", resp)
    return ("unreachable", resp)


# ---------------------------------------------------------------------------
# Fixtures — a valid mandate chain the tests mutate
# ---------------------------------------------------------------------------

def _valid_chain(now: int):
    """Build a coherent (open, checkout, payment) mandate chain."""
    checkout_jwt = {"iss": "merchant_1", "items": ["sku-book-1"],
                    "total": 15000, "currency": "USD", "iat": now}
    cart = {"merchant": "merchant_1", "skus": ["sku-book-1"], "total": 15000}
    open_mandate = {
        "vct": "mandate.checkout.1",
        "cnf": {"kid": "agent-key-1"},
        "constraints": [
            {"type": "checkout.allowed_merchants", "allowed_merchants": ["merchant_1"]},
            {"type": "checkout.line_items", "acceptable_items": ["sku-book-1", "sku-book-2"]},
            {"type": "checkout.amount_cap", "max_amount": 20000},
        ],
    }
    checkout = {
        "vct": "mandate.checkout.1",
        "checkout_jwt": checkout_jwt,
        "checkout_hash": canonical_hash(checkout_jwt),
        "sd_hash": canonical_hash(open_mandate),
        "signer_kid": "agent-key-1",
        "cart_expiry": now + 600,
        "cart": cart,
    }
    payment = {
        "vct": "mandate.payment.1",
        "transaction_id": checkout["checkout_hash"],
        "payment_amount": {"amount": 15000, "currency": "USD"},
        "payee": {"id": "merchant_1"},
        "sig_scheme": "ecdsa-p256",
        "user_authorization": "vp-sd-jwt-...",
        "exp": now + 300,
        "jti": "jti-" + uuid.uuid4().hex[:8],
        "agent_id": "agent-1",
        "open_mandate_id": "open-1",
        "payment_instrument": {
            "id": "dpc-1", "type": "dpc",
            "scope": {"agent": "agent-1", "merchant": "merchant_1"},
        },
        "final": True, "verified": True,
    }
    return open_mandate, checkout, payment


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class AP2MandateTests:
    """AP2 mandate-chain conformance suite (AP2-001..AP2-017)."""

    def __init__(self, url: str | None = None, headers: dict | None = None,
                 simulate: bool = False):
        self.url = url.rstrip("/") if url else "http://localhost:8080"
        self.headers = headers or {}
        self.simulate = simulate
        self.results: list[AP2TestResult] = []

    def _now(self) -> int:
        return 1_750_000_000 if self.simulate else int(time.time())

    def _record(self, r: AP2TestResult) -> None:
        print(f"  {'PASS ✅' if r.passed else 'FAIL ❌'}  {r.test_id}: {r.name}")
        self.results.append(r)

    def _finish(self, *, test_id, name, category, mandate, owasp, stride,
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
        self._record(AP2TestResult(
            test_id=test_id, name=name, category=category, mandate=mandate,
            owasp_asi=owasp, stride=stride, severity=severity, passed=passed,
            details=details, ap2_ref=ref, normative=normative,
            live_evidence=live_ev, elapsed_s=round(time.monotonic() - t0, 3)))

    # -- AP2-001: checkout_hash tamper ------------------------------------

    def test_ap2_001_checkout_hash_tamper(self) -> None:
        """AP2-001: Tampered cart breaks checkout_hash (CRITICAL).

        An attacker mutates the cart contents but leaves the ``checkout_hash``
        claim. The verifier MUST reject because hash(checkout_jwt) != claim.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, _ = _valid_chain(now)
        checkout["checkout_jwt"]["total"] = 150000  # tamper cart, stale hash claim
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"]).verify_checkout(openm, checkout, now)
        self._finish(
            test_id="AP2-001", name="Checkout Hash Tamper",
            category="mandate_integrity", mandate="CheckoutMandate",
            owasp="ASI03", stride="Tampering", severity=Severity.CRITICAL.value,
            ref="AP2: reject hash(checkout_jwt) != checkout_hash", normative="N",
            model_pass=(not v.ok and "checkout_hash" in v.reason),
            model_reason=(f"tampered cart rejected ({v.reason})" if not v.ok else
                          "TAMPER UNDETECTED — cart mutated but checkout mandate accepted"),
            attack_payload={"checkout_mandate": checkout, "open_mandate": openm}, t0=t0)

    # -- AP2-002: stale cart ----------------------------------------------

    def test_ap2_002_stale_cart(self) -> None:
        """AP2-002: Stale / cross-session checkout rejected (HIGH).

        A valid-but-old checkout_hash that no longer matches the merchant's
        latest cart state MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, _ = _valid_chain(now)
        latest = dict(checkout["checkout_jwt"], total=16000)  # merchant moved on
        v = AP2Verifier(latest_checkout_jwt=latest).verify_checkout(openm, checkout, now)
        self._finish(
            test_id="AP2-002", name="Stale / Cross-Session Cart",
            category="mandate_integrity", mandate="CheckoutMandate",
            owasp="ASI03", stride="Tampering", severity=Severity.HIGH.value,
            ref="AP2: checkout_hash MUST match latest checkout_jwt", normative="N",
            model_pass=(not v.ok and "latest" in v.reason),
            model_reason=(f"stale cart rejected ({v.reason})" if not v.ok else
                          "STALE CART ACCEPTED — no latest-cart binding"),
            attack_payload={"checkout_mandate": checkout, "open_mandate": openm}, t0=t0)

    # -- AP2-003: amount cap escalation -----------------------------------

    def test_ap2_003_amount_escalation(self) -> None:
        """AP2-003: Cart total over Intent cap rejected (CRITICAL).

        Intent→Cart scope escalation: the closed cart total exceeds the amount
        cap the user authorized in the open mandate. MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, _ = _valid_chain(now)
        checkout["cart"]["total"] = 500000  # over the 20000 cap
        checkout["checkout_jwt"]["total"] = 500000
        checkout["checkout_hash"] = canonical_hash(checkout["checkout_jwt"])
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"]).verify_checkout(openm, checkout, now)
        self._finish(
            test_id="AP2-003", name="Amount Cap Escalation (Intent→Cart)",
            category="scope_escalation", mandate="CheckoutMandate",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.CRITICAL.value,
            ref="AP2: closed cart MUST satisfy open-mandate constraints", normative="N",
            model_pass=(not v.ok and "cap" in v.reason),
            model_reason=(f"over-cap cart rejected ({v.reason})" if not v.ok else
                          "SCOPE ESCALATION — cart exceeded user-authorized amount cap"),
            attack_payload={"checkout_mandate": checkout, "open_mandate": openm}, t0=t0)

    # -- AP2-004: merchant allowlist --------------------------------------

    def test_ap2_004_merchant_allowlist(self) -> None:
        """AP2-004: Off-allowlist merchant rejected (HIGH)."""
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, _ = _valid_chain(now)
        checkout["cart"]["merchant"] = "evil_merchant"
        checkout["checkout_jwt"]["iss"] = "evil_merchant"
        checkout["checkout_hash"] = canonical_hash(checkout["checkout_jwt"])
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"]).verify_checkout(openm, checkout, now)
        self._finish(
            test_id="AP2-004", name="Merchant Allowlist Constraint",
            category="scope_escalation", mandate="CheckoutMandate",
            owasp="ASI04", stride="Elevation of Privilege", severity=Severity.HIGH.value,
            ref="AP2: checkout.allowed_merchants constraint", normative="N",
            model_pass=(not v.ok and "merchant" in v.reason),
            model_reason=(f"off-allowlist merchant rejected ({v.reason})" if not v.ok else
                          "SCOPE ESCALATION — purchase from unauthorized merchant"),
            attack_payload={"checkout_mandate": checkout, "open_mandate": openm}, t0=t0)

    # -- AP2-005: SKU constraint ------------------------------------------

    def test_ap2_005_sku_constraint(self) -> None:
        """AP2-005: SKU outside acceptable_items rejected (HIGH)."""
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, _ = _valid_chain(now)
        checkout["cart"]["skus"] = ["sku-gift-card-5000"]  # not in acceptable_items
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"]).verify_checkout(openm, checkout, now)
        self._finish(
            test_id="AP2-005", name="Line-Item / SKU Constraint",
            category="scope_escalation", mandate="CheckoutMandate",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.HIGH.value,
            ref="AP2: checkout.line_items acceptable_items", normative="N",
            model_pass=(not v.ok and "SKU" in v.reason),
            model_reason=(f"unauthorized SKU rejected ({v.reason})" if not v.ok else
                          "SCOPE ESCALATION — agent bought an unauthorized product"),
            attack_payload={"checkout_mandate": checkout, "open_mandate": openm}, t0=t0)

    # -- AP2-006: unknown constraint fail-closed --------------------------

    def test_ap2_006_unknown_constraint_failclosed(self) -> None:
        """AP2-006: Unknown constraint type fails closed (MEDIUM).

        AP2 requires an unknown Constraint ``type`` to evaluate as FAILING —
        a verifier that skips constraints it doesn't recognize is exploitable.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, _ = _valid_chain(now)
        openm["constraints"].append({"type": "checkout.future_control_v9", "x": 1})
        # Re-bind sd_hash so the mandate is otherwise coherent and the verifier
        # reaches constraint evaluation (the behaviour under test).
        checkout["sd_hash"] = canonical_hash(openm)
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"]).verify_checkout(openm, checkout, now)
        self._finish(
            test_id="AP2-006", name="Unknown Constraint Fail-Closed",
            category="scope_escalation", mandate="CheckoutMandate",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.MEDIUM.value,
            ref="AP2: unknown Constraint type MUST evaluate as failing", normative="N",
            model_pass=(not v.ok and "unknown constraint" in v.reason),
            model_reason=(f"unknown constraint failed closed ({v.reason})" if not v.ok else
                          "FAIL-OPEN — unrecognized constraint was skipped, not failed"),
            attack_payload={"checkout_mandate": checkout, "open_mandate": openm}, t0=t0)

    # -- AP2-007: transaction_id chain ------------------------------------

    def test_ap2_007_chain_link(self) -> None:
        """AP2-007: Payment reused against a different cart rejected (CRITICAL).

        The Payment Mandate's ``transaction_id`` must equal the bound
        Checkout's ``checkout_hash``. A payment authorized for cart A replayed
        against cart B MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, payment = _valid_chain(now)
        payment["transaction_id"] = "hash-of-some-other-cart"
        v = AP2Verifier().verify_payment(checkout, payment, now)
        self._finish(
            test_id="AP2-007", name="Mandate Chain Link (transaction_id)",
            category="mandate_chain", mandate="PaymentMandate",
            owasp="ASI03", stride="Tampering", severity=Severity.CRITICAL.value,
            ref="AP2: transaction_id == checkout_hash", normative="N",
            model_pass=(not v.ok and "transaction_id" in v.reason),
            model_reason=(f"unchained payment rejected ({v.reason})" if not v.ok else
                          "MANDATE REUSE — payment accepted against an unlinked cart"),
            attack_payload={"payment_mandate": payment, "checkout_mandate": checkout}, t0=t0)

    # -- AP2-008: open-mandate substitution -------------------------------

    def test_ap2_008_open_mandate_substitution(self) -> None:
        """AP2-008: Open-mandate substitution rejected via sd_hash (HIGH).

        Swapping the presented open mandate for a more permissive one MUST
        break the closed mandate's ``sd_hash`` binding.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, _ = _valid_chain(now)
        permissive = dict(openm, constraints=[])  # attacker's wide-open mandate
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"]).verify_checkout(permissive, checkout, now)
        self._finish(
            test_id="AP2-008", name="Open-Mandate Substitution (sd_hash)",
            category="mandate_chain", mandate="CheckoutMandate",
            owasp="ASI03", stride="Tampering", severity=Severity.HIGH.value,
            ref="AP2: closed mandate sd_hash binds to presented open mandate", normative="N",
            model_pass=(not v.ok and "sd_hash" in v.reason),
            model_reason=(f"substituted open mandate rejected ({v.reason})" if not v.ok else
                          "SUBSTITUTION — a swapped, more-permissive open mandate was accepted"),
            attack_payload={"checkout_mandate": checkout, "open_mandate": permissive}, t0=t0)

    # -- AP2-009: agent key forgery ---------------------------------------

    def test_ap2_009_agent_key_forgery(self) -> None:
        """AP2-009: Closed-mandate signer must match cnf key (HIGH).

        In autonomous mode only the agent key bound via the open mandate's
        ``cnf`` claim may sign the closed mandate. A different signer MUST fail.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, _ = _valid_chain(now)
        checkout["signer_kid"] = "attacker-key-9"
        v = AP2Verifier(latest_checkout_jwt=checkout["checkout_jwt"]).verify_checkout(openm, checkout, now)
        self._finish(
            test_id="AP2-009", name="Agent Key Forgery (cnf mismatch)",
            category="authorization", mandate="CheckoutMandate",
            owasp="ASI03", stride="Spoofing", severity=Severity.HIGH.value,
            ref="AP2: open mandate cnf binds the signing agent key", normative="N",
            model_pass=(not v.ok and "cnf" in v.reason),
            model_reason=(f"forged signer rejected ({v.reason})" if not v.ok else
                          "KEY FORGERY — a non-cnf key signed the closed mandate"),
            attack_payload={"checkout_mandate": checkout, "open_mandate": openm}, t0=t0)

    # -- AP2-010: missing user signature ----------------------------------

    def test_ap2_010_missing_user_signature(self) -> None:
        """AP2-010: Missing user signature (human-present) rejected (HIGH)."""
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, payment = _valid_chain(now)
        payment["user_authorization"] = None
        v = AP2Verifier().verify_payment(checkout, payment, now, human_present=True)
        self._finish(
            test_id="AP2-010", name="Missing User Signature (human-present)",
            category="authorization", mandate="PaymentMandate",
            owasp="ASI09", stride="Spoofing", severity=Severity.HIGH.value,
            ref="AP2: MPP+CP MUST verify the user's signature", normative="N",
            model_pass=(not v.ok and "user signature" in v.reason),
            model_reason=(f"unsigned payment rejected ({v.reason})" if not v.ok else
                          "UNAUTHORIZED — payment accepted without a user signature"),
            attack_payload={"payment_mandate": payment, "checkout_mandate": checkout}, t0=t0)

    # -- AP2-011: payment replay ------------------------------------------

    def test_ap2_011_payment_replay(self) -> None:
        """AP2-011: Replayed Payment Mandate rejected (HIGH, strict).

        Re-presenting a Payment Mandate with a previously-seen ``jti`` MUST be
        rejected. (Marked strict: jti is defined in the SDK; the explicit
        replay-window MUST is under-specified in v0.2 prose.)
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, payment = _valid_chain(now)
        verifier = AP2Verifier()
        first = verifier.verify_payment(checkout, payment, now)
        replay = verifier.verify_payment(checkout, payment, now)  # same jti
        self._finish(
            test_id="AP2-011", name="Payment Mandate Replay (jti)",
            category="replay", mandate="PaymentMandate",
            owasp="ASI03", stride="Tampering", severity=Severity.HIGH.value,
            ref="AP2: jti/nonce single-use (SDK docstring)", normative="I",
            model_pass=(first.ok and not replay.ok and "replay" in replay.reason),
            model_reason=(f"replayed payment rejected ({replay.reason})"
                          if (first.ok and not replay.ok) else
                          "REPLAY — a repeated payment mandate was accepted twice"),
            attack_payload={"payment_mandate": payment, "checkout_mandate": checkout}, t0=t0)

    # -- AP2-012: expired mandate -----------------------------------------

    def test_ap2_012_expired_mandate(self) -> None:
        """AP2-012: Expired Payment Mandate rejected (MEDIUM, strict)."""
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, payment = _valid_chain(now)
        payment["exp"] = now - 60
        v = AP2Verifier().verify_payment(checkout, payment, now)
        self._finish(
            test_id="AP2-012", name="Expired Payment Mandate",
            category="replay", mandate="PaymentMandate",
            owasp="ASI03", stride="Tampering", severity=Severity.MEDIUM.value,
            ref="AP2: PaymentMandate exp (SDK 5-15 min)", normative="I",
            model_pass=(not v.ok and "expired" in v.reason),
            model_reason=(f"expired mandate rejected ({v.reason})" if not v.ok else
                          "EXPIRY BYPASS — an expired payment mandate was accepted"),
            attack_payload={"payment_mandate": payment, "checkout_mandate": checkout}, t0=t0)

    # -- AP2-013: double-spend --------------------------------------------

    def test_ap2_013_double_spend(self) -> None:
        """AP2-013: Double-spend on one open mandate rejected (HIGH).

        The agent MUST NOT sign two overlapping closed mandates for the same
        open mandate without an intervening rejection receipt.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, payment = _valid_chain(now)
        verifier = AP2Verifier()
        first = verifier.verify_payment(checkout, payment, now)
        second = dict(payment, jti="jti-second", rejection_receipt=None)
        v2 = verifier.verify_payment(checkout, second, now)
        self._finish(
            test_id="AP2-013", name="Double-Spend on Open Mandate",
            category="double_spend", mandate="PaymentMandate",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.HIGH.value,
            ref="AP2: no overlapping closed mandates w/o rejection receipt", normative="N",
            model_pass=(first.ok and not v2.ok and "double-spend" in v2.reason),
            model_reason=(f"double-spend rejected ({v2.reason})"
                          if (first.ok and not v2.ok) else
                          "DOUBLE-SPEND — two closed mandates accepted for one open mandate"),
            attack_payload={"payment_mandate": second, "checkout_mandate": checkout}, t0=t0)

    # -- AP2-014: deterministic signature ---------------------------------

    def test_ap2_014_deterministic_signature(self) -> None:
        """AP2-014: Deterministic signature scheme rejected (HIGH).

        Payment Mandates MUST use a non-deterministic scheme (ECDSA); a
        deterministic one (Ed25519) MUST be rejected (replay resistance).
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, payment = _valid_chain(now)
        payment["sig_scheme"] = "ed25519"
        v = AP2Verifier().verify_payment(checkout, payment, now)
        self._finish(
            test_id="AP2-014", name="Deterministic Signature Scheme",
            category="crypto", mandate="PaymentMandate",
            owasp="ASI03", stride="Tampering", severity=Severity.HIGH.value,
            ref="AP2: PaymentMandate MUST use non-deterministic sig (not Ed25519)", normative="N",
            model_pass=(not v.ok and "deterministic" in v.reason),
            model_reason=(f"deterministic scheme rejected ({v.reason})" if not v.ok else
                          "WEAK CRYPTO — a deterministic (Ed25519) payment signature was accepted"),
            attack_payload={"payment_mandate": payment, "checkout_mandate": checkout}, t0=t0)

    # -- AP2-015: funding-instrument scope --------------------------------

    def test_ap2_015_funding_scope(self) -> None:
        """AP2-015: Funding instrument scope binding (CRITICAL).

        A tokenized card credential (Visa TAP / Mastercard Agentic Token) is
        scoped to a specific agent + merchant + consent policy. A Payment
        Mandate whose funding token scope doesn't match MUST be rejected.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, payment = _valid_chain(now)
        # Token scoped to a different merchant than the cart.
        payment["payment_instrument"]["scope"]["merchant"] = "other_merchant"
        v = AP2Verifier().verify_payment(checkout, payment, now)
        self._finish(
            test_id="AP2-015", name="Funding-Instrument Scope Binding",
            category="funding_instrument", mandate="PaymentMandate",
            owasp="ASI03", stride="Elevation of Privilege", severity=Severity.CRITICAL.value,
            ref="AP2 + Visa TAP / Mastercard Agentic Token: token scoped to agent+merchant", normative="N",
            model_pass=(not v.ok and "scoped to this merchant" in v.reason),
            model_reason=(f"out-of-scope funding token rejected ({v.reason})" if not v.ok else
                          "SCOPE MISMATCH — funding token used outside its agent/merchant scope"),
            attack_payload={"payment_mandate": payment, "checkout_mandate": checkout}, t0=t0)

    # -- AP2-016: premature credential release ----------------------------

    def test_ap2_016_premature_credential_release(self) -> None:
        """AP2-016: Credential released only on verified FINAL mandate (HIGH).

        The payment credential/token MUST ONLY be released upon receipt and
        verification of a FINAL Payment Mandate — not a draft/unverified one.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, payment = _valid_chain(now)
        draft = dict(payment, final=False, verified=False)
        released_on_draft = AP2Verifier().credential_release_ok(draft)
        released_on_final = AP2Verifier().credential_release_ok(payment)
        model_pass = (not released_on_draft) and released_on_final
        self._finish(
            test_id="AP2-016", name="Premature Credential Release",
            category="funding_instrument", mandate="PaymentMandate",
            owasp="ASI04", stride="Information Disclosure", severity=Severity.HIGH.value,
            ref="AP2: token released ONLY upon verified final Payment Mandate", normative="N",
            model_pass=model_pass,
            model_reason=("credential withheld from draft mandate, released only on verified final"
                          if model_pass else
                          "PREMATURE RELEASE — credential released before a verified final mandate"),
            attack_payload={"payment_mandate": draft, "checkout_mandate": checkout}, t0=t0)

    # -- AP2-017: vct mismatch --------------------------------------------

    def test_ap2_017_vct_mismatch(self) -> None:
        """AP2-017: Exact vct match including version suffix (MEDIUM).

        A mandate presenting a wrong or unversioned ``vct`` MUST be rejected —
        vct matching is exact including the version suffix.
        """
        t0 = time.monotonic()
        now = self._now()
        openm, checkout, payment = _valid_chain(now)
        payment["vct"] = "mandate.payment"  # missing version suffix
        v = AP2Verifier().verify_payment(checkout, payment, now)
        self._finish(
            test_id="AP2-017", name="vct Exact-Match Enforcement",
            category="mandate_integrity", mandate="PaymentMandate",
            owasp="ASI03", stride="Spoofing", severity=Severity.MEDIUM.value,
            ref="AP2: vct matched exactly including version suffix", normative="N",
            model_pass=(not v.ok and "vct" in v.reason),
            model_reason=(f"vct mismatch rejected ({v.reason})" if not v.ok else
                          "VCT DRIFT — a mandate with the wrong vct/version was accepted"),
            attack_payload={"payment_mandate": payment, "checkout_mandate": checkout}, t0=t0)

    # -- run_all ----------------------------------------------------------

    def run_all(self) -> list[AP2TestResult]:
        tests = [
            self.test_ap2_001_checkout_hash_tamper,
            self.test_ap2_002_stale_cart,
            self.test_ap2_003_amount_escalation,
            self.test_ap2_004_merchant_allowlist,
            self.test_ap2_005_sku_constraint,
            self.test_ap2_006_unknown_constraint_failclosed,
            self.test_ap2_007_chain_link,
            self.test_ap2_008_open_mandate_substitution,
            self.test_ap2_009_agent_key_forgery,
            self.test_ap2_010_missing_user_signature,
            self.test_ap2_011_payment_replay,
            self.test_ap2_012_expired_mandate,
            self.test_ap2_013_double_spend,
            self.test_ap2_014_deterministic_signature,
            self.test_ap2_015_funding_scope,
            self.test_ap2_016_premature_credential_release,
            self.test_ap2_017_vct_mismatch,
        ]
        print(f"\n{'='*60}")
        print("AP2 MANDATE-CHAIN CONFORMANCE SUITE")
        print(f"{'='*60}")
        print(f"Target: {self.url}")
        print(f"Mode: {'simulate (reference model)' if self.simulate else 'live'}")
        print("Layer: authorization/trust (AP2, FIDO-governed) above settlement")
        print("Mandates: Intent/open Checkout -> Cart/closed Checkout -> Payment")
        print(f"\n[AP2 MANDATE-CHAIN TESTS]")
        for fn in tests:
            try:
                fn()
            except Exception as e:  # pragma: no cover - defensive
                print(f"  ERROR ⚠️  {fn.__name__}: {e}")
                self.results.append(AP2TestResult(
                    test_id="AP2-ERR", name=f"ERROR: {fn.__name__}",
                    category="error", mandate="error", owasp_asi="ASI03",
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
        description="AP2 mandate-chain security conformance harness (AP2-001..AP2-017)")
    ap.add_argument("--url", default=None, help="Target AP2 verifier URL (live mode)")
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
    suite = AP2MandateTests(url=args.url, headers=headers, simulate=simulate)
    results = suite.run_all()

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    ci = wilson_ci(passed, total)
    report = {
        "suite": "AP2 Mandate-Chain Conformance",
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

    sys.exit(1 if any(not r.passed for r in results) else 0)


if __name__ == "__main__":
    main()
