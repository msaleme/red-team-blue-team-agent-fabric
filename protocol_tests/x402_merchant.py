"""Synthetic x402 merchant — settlement-test infrastructure for VS-R02 Tier B.

PROVENANCE: this file is vendored, unmodified in logic, from commit 3cf9797
("feat(vs-r02): synthetic x402 merchant scaffold for settlement testing") on
branch `feat/vs-r02-x402-merchant` (PR #217), which is NOT merged and has
diverged from current `main` (that branch predates several file
deletions/renames on main — see the divergence note in
reports/round_24/VS-R02-tier-b-runbook.md). It is copied here, uncommitted,
so the Tier B settlement tests in agentcore_payments_harness.py have a real
merchant to import against. TODO(Mike): reconcile properly — either rebase
and merge PR #217 (preferred, keeps one history) or replace this copy with
the merged version once #217 lands. Do not let both copies drift.

The protocol/harness modules test x402 *clients* (agents constructing payment
payloads). VS-R02's settlement tests (ACP-012 receipt-nonce-reuse, ACP-016
settled-spend aggregation) need the *server* side: a merchant we control that
takes the agent's signed `X-PAYMENT`, relays it to the x402 facilitator's
verify/settle, and records what settled. This module is that merchant.

Design — two halves so the scaffold is build-and-test-able with NO live money:

  • `SyntheticMerchant`  — pure request logic (`handle()`), unit-testable in
    process, no socket. Records settled payments and seen nonces.
  • `FacilitatorClient` — abstract verify()/settle(). `MockFacilitator` (default)
    returns deterministic synthetic receipts and enforces nonce-uniqueness in
    memory, so ACP-012/016 can be exercised with zero gas. `CoinbaseFacilitator`
    (live) POSTs to the real x402 facilitator — used ONLY in Mike's live-stack
    session via `--live`, never in CI.

The on-chain settlement (EIP-3009 `transferWithAuthorization`) is the
facilitator's job; the merchant only relays and records. Run standalone with
`python -m protocol_tests.x402_merchant --pay-to 0x... [--live]`.

x402 reference: https://www.x402.org/  | EIP-3009 (transferWithAuthorization).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Base Sepolia USDC (testnet) — the asset VS-R02 settles in.
BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
DEFAULT_FACILITATOR = "https://x402.org/facilitator"
X402_VERSION = 1


# ---------------------------------------------------------------------------
# Payment requirements (what the 402 advertises)
# ---------------------------------------------------------------------------

@dataclass
class PaymentRequirements:
    """The `accepts` entry an x402 402 response advertises (exact scheme)."""
    pay_to: str
    max_amount_required: str = "10000"          # 0.01 USDC (6 decimals)
    network: str = "base-sepolia"
    asset: str = BASE_SEPOLIA_USDC
    resource: str = "/paid"
    description: str = "VS-R02 synthetic merchant resource"
    max_timeout_seconds: int = 120
    scheme: str = "exact"
    # Required to reconstruct the EIP-712 domain used for an EIP-3009 USDC
    # authorization.  AgentCore signs this domain from the original 402
    # challenge, so the relay must present the same domain to /verify.
    extra: dict = field(default_factory=lambda: {"name": "USDC", "version": "2"})

    def to_accepts(self) -> dict:
        return {
            "scheme": self.scheme,
            "network": self.network,
            "maxAmountRequired": self.max_amount_required,
            "resource": self.resource,
            "description": self.description,
            "mimeType": "application/json",
            "payTo": self.pay_to,
            "asset": self.asset,
            "maxTimeoutSeconds": self.max_timeout_seconds,
            "extra": self.extra,
        }

    def challenge_body(self) -> dict:
        return {"x402Version": X402_VERSION, "accepts": [self.to_accepts()],
                "error": "X-PAYMENT header required"}


# ---------------------------------------------------------------------------
# Payment payload parsing (the agent's X-PAYMENT header)
# ---------------------------------------------------------------------------

@dataclass
class ParsedPayment:
    raw: str
    scheme: str = ""
    network: str = ""
    nonce: str = ""
    value: str = ""
    pay_from: str = ""
    pay_to: str = ""
    valid_before: str = ""
    valid_after: str = ""
    decode_error: str = ""


def parse_x_payment(header: str) -> ParsedPayment:
    """Decode a base64(JSON) X-PAYMENT header into the fields tests assert on.

    Tolerant: an opaque/garbage header yields a ParsedPayment with decode_error
    set rather than raising, so the merchant can return a clean 402/400.
    """
    p = ParsedPayment(raw=header)
    try:
        decoded = base64.b64decode(header, validate=True)
        obj = json.loads(decoded)
    except Exception as e:
        p.decode_error = f"{type(e).__name__}: {e}"
        return p
    p.scheme = obj.get("scheme", "")
    p.network = obj.get("network", "")
    payload = obj.get("payload", obj)
    auth = payload.get("authorization", payload) if isinstance(payload, dict) else {}
    p.nonce = str(auth.get("nonce", "")) or ""
    p.value = str(auth.get("value", "")) or ""
    p.pay_from = auth.get("from", "")
    p.pay_to = auth.get("to", "")
    p.valid_before = str(auth.get("validBefore", "")) or ""
    p.valid_after = str(auth.get("validAfter", "")) or ""
    return p


def encode_x_payment(authorization: dict, scheme: str = "exact",
                     network: str = "base-sepolia") -> str:
    """Helper for tests: build a base64 X-PAYMENT header from an authorization."""
    obj = {"x402Version": X402_VERSION, "scheme": scheme, "network": network,
           "payload": {"authorization": authorization, "signature": "0xtest"}}
    return base64.b64encode(json.dumps(obj).encode()).decode()


# ---------------------------------------------------------------------------
# Facilitator clients (verify + settle)
# ---------------------------------------------------------------------------

@dataclass
class SettleResult:
    success: bool
    tx_hash: str = ""
    reason: str = ""
    network: str = ""


class FacilitatorClient:
    """Interface: verify a payment, then settle it on-chain."""

    def verify(self, payment: ParsedPayment, req: PaymentRequirements) -> SettleResult:
        raise NotImplementedError

    def settle(self, payment: ParsedPayment, req: PaymentRequirements) -> SettleResult:
        raise NotImplementedError


class MockFacilitator(FacilitatorClient):
    """In-memory facilitator: deterministic receipts, no gas, no network.

    Enforces EIP-3009-style nonce uniqueness (a settled nonce cannot settle
    again) so ACP-012 replay behavior is exercisable. `fail_verify` lets a test
    force a verify failure.
    """

    def __init__(self, fail_verify: bool = False):
        self.fail_verify = fail_verify
        self._spent_nonces: set[str] = set()
        self.calls: list[tuple[str, str]] = []  # (op, nonce)

    def verify(self, payment, req):
        self.calls.append(("verify", payment.nonce))
        if payment.decode_error:
            return SettleResult(False, reason=f"undecodable payment: {payment.decode_error}")
        if self.fail_verify:
            return SettleResult(False, reason="verify forced-fail")
        if payment.value and req.max_amount_required and \
                int(payment.value) > int(req.max_amount_required):
            return SettleResult(False, reason="amount exceeds maxAmountRequired")
        return SettleResult(True, network=req.network)

    def settle(self, payment, req):
        self.calls.append(("settle", payment.nonce))
        if payment.nonce in self._spent_nonces:
            # EIP-3009: an authorization nonce is single-use on-chain.
            return SettleResult(False, reason="nonce already used (replay)", network=req.network)
        self._spent_nonces.add(payment.nonce)
        tx = "0x" + hashlib.sha256(
            f"{payment.nonce}:{payment.value}:{req.pay_to}".encode()).hexdigest()
        return SettleResult(True, tx_hash=tx, network=req.network)


class CoinbaseFacilitator(FacilitatorClient):
    """Live facilitator — POSTs to the real x402 facilitator. Used only in the
    live-stack session (`--live`); never exercised in CI."""

    def __init__(self, base_url: str = DEFAULT_FACILITATOR, timeout: float = 20.0,
                 user_agent: str = "x402-vsr02-harness/1.0"):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.user_agent = user_agent
        # Deliberately metadata-only.  This supports the Tier-B evidence
        # manifest without retaining a reusable signed authorization.
        self.last_exchange: dict = {}

    @staticmethod
    def _decode_payment_payload(payment: ParsedPayment) -> dict:
        """Turn the wire-format X-PAYMENT header into the facilitator body.

        ``ParsedPayment.raw`` is the base64-encoded HTTP header.  The
        facilitator API expects the decoded x402 payment object under
        ``paymentPayload``; sending the header string makes the facilitator
        see ``paymentPayload.x402Version`` as undefined.  Decode locally and
        fail closed before making a live request if it is not an object.
        """
        try:
            decoded = base64.b64decode(payment.raw, validate=True)
            payload = json.loads(decoded)
        except Exception as e:
            raise ValueError(f"undecodable X-PAYMENT header: {type(e).__name__}: {e}") from e
        if not isinstance(payload, dict):
            raise ValueError("decoded X-PAYMENT header is not a JSON object")
        if payload.get("x402Version") != X402_VERSION:
            raise ValueError(
                f"decoded X-PAYMENT x402Version {payload.get('x402Version')!r} "
                f"does not match configured version {X402_VERSION}"
            )
        return payload

    def _post(self, path: str, body: dict) -> dict:
        request_url = self.base_url + path
        request_bytes = json.dumps(body, separators=(",", ":")).encode()
        req = urllib.request.Request(
            request_url, data=request_bytes,
            headers={"Content-Type": "application/json", "User-Agent": self.user_agent}, method="POST")
        self.last_exchange = {
            "url": request_url,
            "user_agent": self.user_agent,
            "request_x402_version": body.get("x402Version"),
            "payment_payload_shape": type(body.get("paymentPayload")).__name__,
            "payment_payload_sha256": hashlib.sha256(
                json.dumps(body.get("paymentPayload"), sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "payment_requirements_sha256": hashlib.sha256(
                json.dumps(body.get("paymentRequirements"), sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                self.last_exchange.update({"http_status": r.status, "response": raw.decode("utf-8", "replace")[:1000]})
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            response = e.read().decode("utf-8", "replace")[:1000]
            self.last_exchange.update({"http_status": e.code, "response": response})
            raise RuntimeError(f"HTTP {e.code}: {response}") from e

    def verify(self, payment, req):
        try:
            r = self._post("/verify", {"x402Version": X402_VERSION,
                                       "paymentPayload": self._decode_payment_payload(payment),
                                       "paymentRequirements": req.to_accepts()})
            return SettleResult(bool(r.get("isValid")), reason=r.get("invalidReason", ""))
        except Exception as e:
            return SettleResult(False, reason=f"facilitator verify error: {e}")

    def settle(self, payment, req):
        try:
            r = self._post("/settle", {"x402Version": X402_VERSION,
                                       "paymentPayload": self._decode_payment_payload(payment),
                                       "paymentRequirements": req.to_accepts()})
            return SettleResult(bool(r.get("success")), tx_hash=r.get("transaction", ""),
                                reason=r.get("errorReason", ""), network=r.get("network", ""))
        except Exception as e:
            return SettleResult(False, reason=f"facilitator settle error: {e}")


# ---------------------------------------------------------------------------
# The merchant (pure logic + HTTP wrapper)
# ---------------------------------------------------------------------------

@dataclass
class SettlementRecord:
    nonce: str
    value: str
    pay_from: str
    tx_hash: str
    success: bool
    reason: str = ""


class SyntheticMerchant:
    """x402 merchant logic. `handle()` is socket-free and unit-testable.

    Records every settlement attempt so settlement-layer tests can assert on
    them: ACP-016 sums `value` across sessions; ACP-012 checks the second
    same-nonce attempt is refused.
    """

    def __init__(self, requirements: PaymentRequirements,
                 facilitator: FacilitatorClient | None = None):
        self.req = requirements
        self.facilitator = facilitator or MockFacilitator()
        self.settlements: list[SettlementRecord] = []

    @property
    def total_settled(self) -> int:
        return sum(int(s.value or 0) for s in self.settlements if s.success)

    def handle(self, path: str, x_payment: str | None) -> tuple[int, dict]:
        """Return (http_status, body_dict) for a request to the paid resource."""
        if path.rstrip("/") != self.req.resource.rstrip("/"):
            return 404, {"error": "not found"}
        if not x_payment:
            return 402, self.req.challenge_body()

        payment = parse_x_payment(x_payment)
        verify = self.facilitator.verify(payment, self.req)
        if not verify.success:
            self.settlements.append(SettlementRecord(
                payment.nonce, payment.value, payment.pay_from, "", False,
                f"verify failed: {verify.reason}"))
            return 402, {"x402Version": X402_VERSION, "error": verify.reason,
                         "accepts": [self.req.to_accepts()]}

        settle = self.facilitator.settle(payment, self.req)
        self.settlements.append(SettlementRecord(
            payment.nonce, payment.value, payment.pay_from, settle.tx_hash,
            settle.success, settle.reason))
        if not settle.success:
            # 402 again — settlement refused (e.g. replay). The agent sees it failed.
            return 402, {"x402Version": X402_VERSION, "error": settle.reason,
                         "accepts": [self.req.to_accepts()]}
        return 200, {"resource": self.req.description, "paid": True,
                     "settlement": {"txHash": settle.tx_hash, "network": settle.network,
                                    "amount": payment.value, "nonce": payment.nonce}}


def _make_handler(merchant: SyntheticMerchant):
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            status, body = merchant.handle(self.path, self.headers.get("X-PAYMENT"))
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_POST = do_GET  # paid resources may be POSTed against too

        def log_message(self, *a):  # silence default stderr logging
            pass
    return _Handler


def serve(merchant: SyntheticMerchant, port: int = 8402) -> ThreadingHTTPServer:
    """Start the merchant on `port`. Returns the server (caller controls lifetime)."""
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(merchant))
    return httpd


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Synthetic x402 merchant (VS-R02 settlement infra)")
    ap.add_argument("--pay-to", required=True, help="Merchant receiving address (you control it)")
    ap.add_argument("--amount", default="10000", help="maxAmountRequired in smallest unit (default 0.01 USDC)")
    ap.add_argument("--network", default="base-sepolia")
    ap.add_argument("--resource", default="/paid")
    ap.add_argument("--port", type=int, default=8402)
    ap.add_argument("--live", action="store_true",
                    help="Use the real Coinbase x402 facilitator (settles on-chain). Default: mock, no gas.")
    ap.add_argument("--facilitator", default=DEFAULT_FACILITATOR)
    args = ap.parse_args()

    req = PaymentRequirements(pay_to=args.pay_to, max_amount_required=args.amount,
                              network=args.network, resource=args.resource)
    facilitator = CoinbaseFacilitator(args.facilitator) if args.live else MockFacilitator()
    merchant = SyntheticMerchant(req, facilitator)
    httpd = serve(merchant, args.port)
    mode = "LIVE (on-chain settlement)" if args.live else "MOCK (no gas)"
    print(f"x402 synthetic merchant on http://127.0.0.1:{args.port}{args.resource} "
          f"| payTo={args.pay_to} amount={args.amount} {args.network} | facilitator: {mode}",
          file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
        print(f"\nsettlements: {[asdict(s) for s in merchant.settlements]}", file=sys.stderr)
        print(f"total settled: {merchant.total_settled}", file=sys.stderr)


if __name__ == "__main__":
    main()
