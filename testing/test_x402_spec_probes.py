"""The x402 spec payment probes (X4-058..066) can pass, can fail, and say when they cannot tell.

CLAUDE.md rule 9: a new test family needs a positive control, a negative control and a truth
table. The server below is an in-process x402 v2 resource server that really verifies: it
recovers the EIP-712 signer of the `TransferWithAuthorization` with its own domain code, and
checks recipient, amount, validity window and nonce. Each flag turns one check off, which is
the bug the matching probe exists to catch.

Truth table (server shape -> verdicts):

    correct                     X4-058..066 all PASS
    accepts replays             X4-059 FAIL, X4-066 FAIL (same payload resent)
    racy nonce check            X4-066 FAIL only
    ignores recipient           X4-060 FAIL only
    ignores amount              X4-061 FAIL only
    ignores validity window     X4-062 FAIL only
    skips signature check       X4-063, X4-064, X4-065 FAIL
    accepts any of two chains   X4-065 FAIL only
    accepts nothing (10-30)     X4-058 FAIL, X4-059..066 INCONCLUSIVE
    payer not funded            X4-058..066 INCONCLUSIVE (the payer's fault, not the server's)
    500 on any bad payment      X4-058 PASS, X4-059..066 INCONCLUSIVE (not a rejection)
    no key / mainnet / over cap nothing signed, all INCONCLUSIVE with the reason
    pre-spec target             all INCONCLUSIVE ("do not apply")

Offline: no network, a fixed throwaway key, no funds.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
except ImportError:  # pragma: no cover
    # A skipped truth table is a truth table nothing checks. Locally, skip; in CI, fail.
    if os.environ.get("CI"):
        raise
    Account = None

from protocol_tests.x402_harness import X402SecurityTests, X402Transport
from protocol_tests.x402_spec_pay import SpecPayer, load_payer

PROBES = [f"X4-0{n}" for n in range(58, 67)]
TEST_KEY = "0x" + "11" * 32          # throwaway; never funded
PAY_TO = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


def _accept(network="eip155:84532"):
    return {"scheme": "exact", "network": network, "amount": "10000", "asset": USDC,
            "payTo": PAY_TO, "maxTimeoutSeconds": 60, "extra": {"name": "USDC", "version": "2"}}


def _b64(doc):
    return base64.b64encode(json.dumps(doc).encode()).decode()


def _recover(auth, signature, chain):
    """The server's own EIP-712 recovery, independent of x402_spec_pay.typed_data."""
    data = {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"},
                             {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"},
                             {"name": "verifyingContract", "type": "address"}],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {"name": "USDC", "version": "2", "chainId": chain, "verifyingContract": USDC},
        "message": {"from": auth["from"], "to": auth["to"], "value": int(auth["value"]),
                    "validAfter": int(auth["validAfter"]), "validBefore": int(auth["validBefore"]),
                    "nonce": bytes.fromhex(auth["nonce"][2:])},
    }
    try:
        return Account.recover_message(encode_typed_data(full_message=data), signature=signature)
    except Exception:  # noqa: BLE001 - any failure to recover is "no signer"
        return None


class SpecServer:
    """An x402 v2 resource server. Every check on by default; flags switch one off."""

    def __init__(self, *, replay=False, racy=False, recipient=False, amount=False,
                 window=False, signature=False, any_chain=False, accept_nothing=False,
                 crash_on_bad=False, unfunded=False, network="eip155:84532"):
        self.flags = {"replay": replay, "racy": racy, "recipient": recipient, "amount": amount,
                      "window": window, "signature": signature, "any_chain": any_chain}
        self.accept_nothing = accept_nothing
        self.crash_on_bad = crash_on_bad
        self.unfunded = unfunded
        self.accept = _accept(network)
        self.seen_nonces: set[str] = set()
        self.lock = threading.Lock()

    def _required(self, error="PAYMENT-SIGNATURE header is required"):
        doc = {"x402Version": 2, "error": error, "resource": {"url": "http://t/paid"},
               "accepts": [self.accept]}
        return {"status": 500 if (self.crash_on_bad and error != "PAYMENT-SIGNATURE header is required")
                else 402, "headers": {"payment-required": _b64(doc)}, "body": "{}"}

    def _reason(self, doc) -> str | None:
        if self.accept_nothing:
            return "PAYMENT-SIGNATURE header is required"
        if self.unfunded:   # the x402.org facilitator's code, seen live 2026-11-03
            return "invalid_exact_evm_insufficient_balance"
        auth, sig = doc["payload"]["authorization"], doc["payload"]["signature"]
        f = self.flags
        if not f["signature"]:
            chains = [84532, 11155111] if f["any_chain"] else [84532]
            if not any(_recover(auth, sig, c) == auth["from"] for c in chains):
                return "invalid_exact_evm_payload_signature"
        if not f["recipient"] and auth["to"].lower() != PAY_TO.lower():
            return "invalid_exact_evm_payload_recipient_mismatch"
        if not f["amount"] and auth["value"] != self.accept["amount"]:
            return "invalid_exact_evm_payload_authorization_value_mismatch"
        if not f["window"] and int(auth["validBefore"]) <= int(time.time()):
            return "invalid_exact_evm_payload_authorization_valid_before"
        return None

    def __call__(self, path, headers):
        raw = {k.lower(): v for k, v in headers.items()}.get("payment-signature")
        if not raw:
            return self._required()
        doc = json.loads(base64.b64decode(raw))
        reason = self._reason(doc)
        if reason:
            return self._required(reason)
        nonce = doc["payload"]["authorization"]["nonce"]
        if not self.flags["replay"]:
            if self.flags["racy"]:
                seen = nonce in self.seen_nonces       # check ...
                time.sleep(0.05)                       # ... window ...
                if seen:
                    return self._required("nonce already used")
                self.seen_nonces.add(nonce)            # ... then record
            else:
                with self.lock:
                    if nonce in self.seen_nonces:
                        return self._required("nonce already used")
                    self.seen_nonces.add(nonce)
        settle = {"success": True, "transaction": "0x" + "ab" * 32, "network": self.accept["network"],
                  "payer": doc["payload"]["authorization"]["from"]}
        return {"status": 200, "headers": {"payment-response": _b64(settle)}, "body": "{\"ok\":true}"}


class _Fake(X402Transport):
    def __init__(self, behaviour):
        super().__init__("http://target.invalid", paid_path="/paid")
        self.behaviour = behaviour

    def request(self, method, path="", body=None, headers=None, timeout=15.0):
        return self.behaviour(path, headers or {})


def _verdict(r):
    if r.not_evaluated:
        return "INCONCLUSIVE"
    return "PASS" if r.passed else "FAIL"


def _run(server, payer="default"):
    if payer == "default":
        payer = SpecPayer(TEST_KEY, max_spend_atomic=10**9)
    suite = X402SecurityTests(_Fake(server), payer=payer)
    with contextlib.redirect_stdout(io.StringIO()):
        suite.run_all(categories=["spec_payment"])
    return {r.test_id: _verdict(r) for r in suite.results}, {r.test_id: r for r in suite.results}


def _expect(fail=(), inconclusive=()):
    return {t: "FAIL" if t in fail else "INCONCLUSIVE" if t in inconclusive else "PASS"
            for t in PROBES}


@unittest.skipIf(Account is None, "eth-account not installed (x402-pay extra)")
class TruthTable(unittest.TestCase):
    def check(self, server, expected):
        verdicts, results = _run(server)
        self.assertEqual(sorted(verdicts), PROBES, "the probes did not all run")
        self.assertEqual(verdicts, expected, {t: results[t].details for t in PROBES})
        return results

    def test_correct_server_passes_everything(self):
        """Positive control for every probe."""
        results = self.check(SpecServer(), _expect())
        self.assertIn("tx 0x", results["X4-058"].details)

    def test_replay_accepted(self):
        self.check(SpecServer(replay=True), _expect(fail={"X4-059", "X4-066"}))

    def test_racy_nonce_check(self):
        self.check(SpecServer(racy=True), _expect(fail={"X4-066"}))

    def test_recipient_ignored(self):
        self.check(SpecServer(recipient=True), _expect(fail={"X4-060"}))

    def test_amount_ignored(self):
        self.check(SpecServer(amount=True), _expect(fail={"X4-061"}))

    def test_window_ignored(self):
        self.check(SpecServer(window=True), _expect(fail={"X4-062"}))

    def test_signature_not_checked(self):
        self.check(SpecServer(signature=True), _expect(fail={"X4-063", "X4-064", "X4-065"}))

    def test_any_chain_accepted(self):
        self.check(SpecServer(any_chain=True), _expect(fail={"X4-065"}))

    def test_server_that_accepts_nothing(self):
        """The 2026-10-30 shape: every rejection would have been a PASS."""
        results = self.check(SpecServer(accept_nothing=True),
                             _expect(fail={"X4-058"}, inconclusive=set(PROBES) - {"X4-058"}))
        self.assertIn("positive control did not pass", results["X4-059"].details)

    def test_an_unfunded_payer_is_not_a_server_failure(self):
        results = self.check(SpecServer(unfunded=True), _expect(inconclusive=set(PROBES)))
        self.assertIn("not funded", results["X4-058"].details)

    def test_a_crash_is_not_a_rejection(self):
        """Rule 8: a 5xx on a bad payment is not evidence the control held."""
        self.check(SpecServer(crash_on_bad=True),
                   _expect(inconclusive=set(PROBES) - {"X4-058"}))


@unittest.skipIf(Account is None, "eth-account not installed (x402-pay extra)")
class NothingIsSignedWithoutTheGuards(unittest.TestCase):
    def _all_inconclusive(self, verdicts, results, phrase):
        self.assertEqual(set(verdicts.values()), {"INCONCLUSIVE"}, verdicts)
        self.assertIn(phrase, results["X4-058"].details)

    def test_no_key(self):
        reason = load_payer(environ={})
        self.assertIsInstance(reason, str)
        self._all_inconclusive(*_run(SpecServer(), payer=reason), "no payer key")

    def test_mainnet_is_refused(self):
        self._all_inconclusive(*_run(SpecServer(network="eip155:8453")), "testnets only")

    def test_spend_cap(self):
        payer = SpecPayer(TEST_KEY, max_spend_atomic=5000)   # below one 10000 payment
        self._all_inconclusive(*_run(SpecServer(), payer=payer), "spend cap")

    def test_cap_counts_only_what_could_settle(self):
        payer = SpecPayer(TEST_KEY, max_spend_atomic=10**9)
        _run(SpecServer(), payer=payer)
        # control 10000 + wrong recipient 10000 + underpay 9999 + parallel 10000
        self.assertEqual(payer.committed_atomic, 39999)

    def test_requirement_missing_an_address(self):
        # Bugbot on #677: a challenge without payTo or asset crashed the signer with a
        # KeyError instead of grading INCONCLUSIVE.
        for field in ("payTo", "asset"):
            with self.subTest(field=field):
                server = SpecServer()
                del server.accept[field]
                self._all_inconclusive(*_run(server), f"no valid {field} address")

    def test_requirement_with_a_malformed_address(self):
        server = SpecServer()
        server.accept["payTo"] = "not-an-address"
        self._all_inconclusive(*_run(server), "no valid payTo address")

    def test_pre_spec_target(self):
        pre_spec = lambda p, h: {"status": 402, "headers": {
            "x-payment-required": "true", "x-payment-amount": "10000",
            "x-payment-recipient": PAY_TO}, "body": ""}
        self._all_inconclusive(*_run(pre_spec), "do not apply")


@unittest.skipIf(Account is None, "eth-account not installed (x402-pay extra)")
class TheSignatureIsTheSpecs(unittest.TestCase):
    def test_signer_recovers_under_the_servers_own_domain_code(self):
        payer = SpecPayer(TEST_KEY)
        p = payer.pay(2, _accept(), {"url": "http://t/paid"})
        auth = p.authorization
        self.assertEqual(_recover(auth, p.document["payload"]["signature"], 84532), payer.address)
        self.assertEqual(p.document["x402Version"], 2)
        self.assertEqual(p.document["accepted"]["payTo"], PAY_TO)
        self.assertEqual(list(p.header), ["PAYMENT-SIGNATURE"])
        self.assertEqual(len(auth["nonce"]), 66)

    def test_v1_shape(self):
        accept = {k: v for k, v in _accept("base-sepolia").items() if k != "amount"}
        accept["maxAmountRequired"] = "10000"
        p = SpecPayer(TEST_KEY).pay(1, accept)
        self.assertEqual(list(p.header), ["X-PAYMENT"])
        self.assertEqual({k for k in p.document}, {"x402Version", "scheme", "network", "payload"})
        self.assertEqual(_recover(p.authorization, p.document["payload"]["signature"], 84532),
                         p.authorization["from"])


if __name__ == "__main__":
    unittest.main()
