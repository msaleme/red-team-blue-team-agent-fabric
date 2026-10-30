"""A target that speaks the published x402 transport must not be graded by pre-spec probes.

The x402 module's probes use a pre-spec format: challenges read from `X-Payment-Amount` and
friends, payments sent as `X-Payment-Authorization`. The published HTTP transport
(x402-foundation/x402, specs/transports-v1/http.md and transports-v2/http.md) uses a JSON body
(v1) or a base64 `PAYMENT-REQUIRED` header (v2) for the challenge, and `X-PAYMENT` (v1) or
`PAYMENT-SIGNATURE` (v2) for the payment.

A spec server ignores the pre-spec headers and answers every probe with its normal 402. On
2026-10-30 the module, run against a spec v2 stub that accepts no payment at all, returned
43 PASS and 11 FAIL out of 54, and none of it was evidence. X4-045 read "Replay correctly
handled"; X4-001 FAILed the server for lacking headers the spec does not have.

Truth table (target shape -> verdicts):

    spec v2 challenge, well-formed   X4-001 PASS (positive control); every test outside
                                     SPEC_INDEPENDENT_TESTS INCONCLUSIVE
    spec v1 challenge, well-formed   same
    spec v2 challenge, no payTo      X4-001 FAIL (negative control)
    pre-spec challenge headers       the spec rule does not fire at all
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.x402_harness import (  # noqa: E402
    SPEC_INDEPENDENT_TESTS,
    X402SecurityTests,
    X402Transport,
    spec_challenge,
)

ACCEPT = {"scheme": "exact", "network": "eip155:84532", "amount": "10000",
          "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "maxTimeoutSeconds": 60}


def _v2(accept: dict):
    doc = {"x402Version": 2, "error": "PAYMENT-SIGNATURE header is required", "accepts": [accept]}
    header = base64.b64encode(json.dumps(doc).encode()).decode()
    return lambda p, h: {"status": 402, "headers": {"PAYMENT-REQUIRED": header}, "body": "{}"}


def _v1():
    accept = {k: v for k, v in ACCEPT.items() if k != "amount"} | {"maxAmountRequired": "10000"}
    body = json.dumps({"x402Version": 1, "error": "Payment required", "accepts": [accept]})
    return lambda p, h: {"status": 402, "headers": {"content-type": "application/json"}, "body": body}


SPEC_V2 = _v2(ACCEPT)
SPEC_V2_NO_PAYTO = _v2({k: v for k, v in ACCEPT.items() if k != "payTo"})
SPEC_V1 = _v1()
PRE_SPEC = lambda p, h: {"status": 402, "headers": {  # noqa: E731
    "x-payment-required": "true", "x-payment-amount": "10000", "x-payment-currency": "USDC",
    "x-payment-recipient": ACCEPT["payTo"], "x-payment-network": "base-sepolia"}, "body": ""}


class _Fake(X402Transport):
    def __init__(self, behaviour):
        super().__init__("http://target.invalid", paid_path="/paid")
        self.behaviour = behaviour

    def request(self, method, path="", body=None, headers=None, timeout=15.0):
        return self.behaviour(path, headers or {})


def _verdict(result) -> str:
    if result.not_evaluated or "INCONCLUSIVE" in result.details:
        return "INCONCLUSIVE"
    return "PASS" if result.passed else "FAIL"


def _run(behaviour, method: str | None = None) -> dict[str, str]:
    suite = X402SecurityTests(_Fake(behaviour))
    with contextlib.redirect_stdout(io.StringIO()):
        if method:
            getattr(suite, method)()
        else:
            suite.run_all()
    return {r.test_id: _verdict(r) for r in suite.results}, suite.results


class TheChallengeIsRecognised(unittest.TestCase):
    def test_v2_header(self):
        self.assertEqual(spec_challenge(SPEC_V2("/", {}))["version"], 2)

    def test_v1_body(self):
        self.assertEqual(spec_challenge(SPEC_V1("/", {}))["version"], 1)

    def test_pre_spec_headers_are_not_a_spec_challenge(self):
        self.assertIsNone(spec_challenge(PRE_SPEC("/", {})))

    def test_a_200_is_never_a_challenge(self):
        doc = base64.b64encode(json.dumps({"x402Version": 2, "accepts": [ACCEPT]}).encode()).decode()
        self.assertIsNone(spec_challenge({"status": 200, "headers": {"PAYMENT-REQUIRED": doc}}))


class ASpecTargetGetsNoPreSpecVerdicts(unittest.TestCase):
    def _check(self, behaviour):
        verdicts, results = _run(behaviour)
        self.assertGreaterEqual(len(verdicts), 50, "the suite did not run; this would pass vacuously")
        graded = sorted(t for t, v in verdicts.items() if v != "INCONCLUSIVE" and t not in SPEC_INDEPENDENT_TESTS)
        self.assertEqual(graded, [], "pre-spec probes graded a spec target")
        self.assertEqual(verdicts["X4-001"], "PASS", "positive control: a well-formed spec challenge")
        reason = next(r.details for r in results if r.test_id == "X4-045")
        self.assertIn("speaks x402 v", reason, "the INCONCLUSIVE must say why")

    def test_v2(self):
        self._check(SPEC_V2)

    def test_v1(self):
        self._check(SPEC_V1)


class TheSpecChallengeCanFail(unittest.TestCase):
    def test_a_challenge_without_pay_to_fails_x4_001(self):
        """Negative control: X4-001 must be able to fail a spec target."""
        verdicts, results = _run(SPEC_V2_NO_PAYTO, "test_x402_challenge_headers_present")
        self.assertEqual(verdicts["X4-001"], "FAIL")
        self.assertIn("no payTo", results[0].details)


class APreSpecTargetIsUnaffected(unittest.TestCase):
    def test_the_spec_rule_does_not_fire(self):
        _, results = _run(PRE_SPEC)
        fired = [r.test_id for r in results if "speaks x402 v" in r.details]
        self.assertEqual(fired, [])


if __name__ == "__main__":
    unittest.main()
