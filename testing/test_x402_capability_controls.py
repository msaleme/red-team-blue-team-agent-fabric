"""X4-056 and X4-057 must not grade a capability the target never exposed.

Both tests were added on 2026-08-29 to close gaps found in arXiv:2607.21824 and
arXiv:2605.30998. A strategic review the same day pushed back on the whole move
with a rule worth keeping:

    A gap is not permission to implement. Require an observable target
    capability, an adversarial precondition, a deterministic oracle, a positive
    control, a negative control, and PASS / FAIL / INCONCLUSIVE semantics.

Checked against that bar, both tests failed it, and X4-057 failed it in the way
this repository has spent the most effort learning to catch.

X4-057 sends three requests of 40 against a declared upto=100 allowance and
fails the target if more than 100 settles. Against a target that answers 402 to
everything -- a perfectly normal x402 endpoint that does not implement delegated
allowances at all -- nothing is accepted, nothing settles, 0 > 100 is false, and
the original version returned **PASS**. The target never exposed an allowance,
so there was nothing to overdraw, and the harness recorded that as the control
holding.

That is the #348 shape moved up a level. #348 was "the target never answered,
scored as a pass". This was "the target answered but has no such capability,
scored as a pass". The transport guard cannot catch it, because a 402 is a real
answer and x402 is excluded from the shared serviced guard for exactly that
reason (#351 precondition 3).

X4-056 failed the bar differently and less dangerously: with no control request
it could not attribute a refusal to the URL channel. A 402 on a URL-borne
credential is equally consistent with "this credential is not accepted
anywhere", so the test needed a header control to establish the differential
before a refusal means anything.

The truth table below is the fix, and it is the artifact worth keeping: four
target behaviours, three verdicts, no behaviour permitted to produce a pass
unless the capability was observably exercised.
"""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.x402_harness import X402SecurityTests, X402Transport

DEAD = lambda p, h: {"_error": True, "_exception": "conn refused", "status": 0}
NO_CAPABILITY = lambda p, h: {"status": 402}
HEADER_ONLY = lambda p, h: {"status": 200 if "X-Payment-Authorization" in h else 402}
ACCEPTS_ALL = lambda p, h: {"status": 200}


class _Fake(X402Transport):
    def __init__(self, behaviour):
        super().__init__("http://target.invalid", paid_path="/paid")
        self.behaviour = behaviour

    def request(self, method, path="", body=None, headers=None, timeout=15.0):
        return self.behaviour(path, headers or {})


def _verdict(behaviour, method_name: str) -> str:
    suite = X402SecurityTests(_Fake(behaviour))
    with contextlib.redirect_stdout(io.StringIO()):
        getattr(suite, method_name)()
    r = suite.results[0]
    if "INCONCLUSIVE" in r.details:
        return "INCONCLUSIVE"
    return "PASS" if r.passed else "FAIL"


class TestCredentialInUrl(unittest.TestCase):
    METHOD = "test_x402_credential_in_url"

    def test_dead_host_is_inconclusive(self):
        self.assertEqual(_verdict(DEAD, self.METHOD), "INCONCLUSIVE")

    def test_no_credential_accepted_anywhere_is_inconclusive(self):
        """A 402 on the URL proves nothing if the header is refused too."""
        self.assertEqual(_verdict(NO_CAPABILITY, self.METHOD), "INCONCLUSIVE")

    def test_header_accepted_url_refused_is_a_pass(self):
        """The only shape that earns a pass: the differential actually exists."""
        self.assertEqual(_verdict(HEADER_ONLY, self.METHOD), "PASS")

    def test_url_borne_credential_accepted_is_a_fail(self):
        self.assertEqual(_verdict(ACCEPTS_ALL, self.METHOD), "FAIL")


class TestAllowanceOverdraft(unittest.TestCase):
    METHOD = "test_x402_allowance_overdraft_race"

    def test_dead_host_is_inconclusive(self):
        self.assertEqual(_verdict(DEAD, self.METHOD), "INCONCLUSIVE")

    def test_absent_allowance_capability_is_inconclusive_not_pass(self):
        """The regression this file exists for.

        A target that answers 402 to everything has no delegated allowance to
        overdraw. Before the fix this returned PASS, which says the control held
        when the control was never reached.
        """
        self.assertEqual(
            _verdict(NO_CAPABILITY, self.METHOD), "INCONCLUSIVE",
            "a target with no allowance capability was graded as enforcing one")

    def test_overdraft_is_a_fail(self):
        self.assertEqual(_verdict(ACCEPTS_ALL, self.METHOD), "FAIL")


class TestNeitherTestCanPassWithoutExercisingTheCapability(unittest.TestCase):
    """The property both classes above are instances of."""

    def test_no_pass_from_a_target_that_exposes_nothing(self):
        for method in ("test_x402_credential_in_url",
                       "test_x402_allowance_overdraft_race"):
            for name, behaviour in (("dead", DEAD), ("no capability", NO_CAPABILITY)):
                with self.subTest(test=method, target=name):
                    self.assertNotEqual(
                        _verdict(behaviour, method), "PASS",
                        f"{method} passed against a target that exposed no capability")


if __name__ == "__main__":
    unittest.main()
