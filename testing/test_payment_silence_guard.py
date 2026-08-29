"""The payment protocols may treat a 402 as an answer. They may not treat silence as one.

## What this pins

`x402_harness` and `l402_harness` sat in `PROTOCOL_EXCEPTION` in
test_serviced_guard.py, on a reason that is correct:

    a 401/402 IS those protocols servicing the request, so their apparent
    exposure in any triage is inflated relative to what is actionable

The shared serviced guard would read every payment challenge as "the target did
not service the request" and invert both modules. That is real, and it is why
neither uses `inconclusive_detail`.

The bucket was doing a second job it was never given. The exception excuses one
rule -- that a non-2xx means the target did not service the request. It says
nothing about silence. Against a closed port there is no 402; there is nothing,
and both modules graded that nothing:

    x402  44 of 54 PASS      l402  4 of 33 PASS

    X4-026: No malformed payment payloads accepted
    X4-041: No SSRF via payment callback URLs
    L4-013: Preimage not leaked in error responses

"The generic instrument does not fit" had been read as "no instrument is
needed".

## Both directions, because the danger runs both ways

Over-applying a guard is how a2a_harness broke: `_serviced` turned an active
rejection into INCONCLUSIVE, a false negative introduced by the fix for false
positives. So this file asserts the silence rule fires on silence **and stays
out of the way of a target answering 402 to everything** -- the shape that is
normal operation for both protocols.

The rule is derived, not enumerated. Both modules instrument the transport, so
a test added tomorrow is covered without appearing on any list, and the
mechanism itself lives once in `http_helpers` -- `answered`, `silence_detail`,
`silence_evidence`, `instrument_transport` -- rather than twice in the two
harnesses. Convention 7 exists because a verdict defect with 44 parallel homes
had to be repaired four times.
"""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.l402_harness import L402SecurityTests, L402Transport
from protocol_tests.x402_harness import X402SecurityTests, X402Transport

CLOSED_PORT = "http://127.0.0.1:9"

#: A challenge good enough for both parsers.
_MACAROON = 'L402 macaroon="AGIAJEemVQUTEyNCR0exk7ek90Cg==", invoice="lnbc1500n1p"'
_CHALLENGE_HEADERS = {
    "www-authenticate": _MACAROON,
    "x-payment-required": "true",
    "x-payment-amount": "1000",
    "x-payment-address": "0xabc",
    "x-payment-network": "base",
    "x-payment-currency": "USDC",
}

#: What a closed port produces, in the shape both transports emit for it.
SILENCE = {"status": 0, "headers": {}, "body": "", "_error": True,
           "_exception": "[Errno 111] Connection refused"}
#: A server that is up and demanding payment for everything. Normal operation.
CHALLENGE = {"status": 402, "headers": dict(_CHALLENGE_HEADERS),
             "body": '{"error":"payment required"}'}


def _fixed(base, response):
    """A transport subclass answering every request with *response*.

    Subclassing rather than substituting keeps `base_url`, `paid_path` and
    `default_method` real, which several tests read directly.
    """
    class _Fixed(base):
        def request(self, method, path="", body=None, headers=None, timeout=15.0):
            return dict(response)
    return _Fixed


def _run(suite_cls, transport):
    suite = suite_cls(transport)
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        suite.run_all()
    return suite.results


def _passing(results):
    return [r.test_id for r in results if r.passed]


def _erroring(results):
    return [r.test_id for r in results if str(getattr(r, "name", "")).startswith("ERROR")]


class TestX402(unittest.TestCase):
    LIVE = _fixed(X402Transport, CHALLENGE)
    DEAD = _fixed(X402Transport, SILENCE)

    def test_nothing_passes_against_silence(self):
        results = _run(X402SecurityTests, self.DEAD("http://target.invalid"))
        self.assertEqual(
            _passing(results), [],
            "a verdict of the form 'nothing bad was observed' passed against a "
            "target that answered nothing")

    def test_the_suite_ran_rather_than_erroring_to_zero(self):
        """Zero passes and zero errors are the pair that means something.

        An earlier over_refusal repair appeared to reach 0 of 25 only because
        every test was raising NameError and run_all was catching it.
        """
        results = _run(X402SecurityTests, self.DEAD("http://target.invalid"))
        self.assertGreaterEqual(len(results), 54)
        self.assertEqual(_erroring(results), [])

    def test_a_402_to_everything_still_produces_real_verdicts(self):
        """The false-negative direction. A challenge is an answer.

        Two results are INCONCLUSIVE here and neither comes from the silence
        rule: X4-056 and X4-057 require an observably exercised capability
        (CLAUDE.md convention 9), and a target that challenges everything
        exposes no URL-credential channel and no delegated allowance.
        """
        results = _run(X402SecurityTests, self.LIVE("http://target.invalid"))
        self.assertEqual(_erroring(results), [])
        self.assertGreater(
            len(_passing(results)), 40,
            "the silence rule is firing against a live 402 target; it has been "
            "written too broadly and now inverts the protocol it was exempted for")
        unanswered = [r.test_id for r in results
                      if "requests were answered" in (r.details or "")]
        self.assertEqual(
            unanswered, [],
            f"the silence rule fired on a target that answered every request: "
            f"{unanswered}")


class TestL402(unittest.TestCase):
    LIVE = _fixed(L402Transport, CHALLENGE)
    DEAD = _fixed(L402Transport, SILENCE)

    def test_nothing_passes_against_silence(self):
        results = _run(L402SecurityTests, self.DEAD("http://target.invalid"))
        self.assertEqual(_passing(results), [])

    def test_the_suite_ran_rather_than_erroring_to_zero(self):
        results = _run(L402SecurityTests, self.DEAD("http://target.invalid"))
        self.assertGreaterEqual(len(results), 33)
        self.assertEqual(_erroring(results), [])

    def test_silence_uses_the_third_state_this_module_already_had(self):
        """`not_evaluated` predates #351 and was never wired to an unreachable target.

        It is excluded from `failed` in every summary this module computes, so
        setting it is what stops a run that established nothing from being
        reported as a run in which the target failed everything.
        """
        results = _run(L402SecurityTests, self.DEAD("http://target.invalid"))
        graded = [r.test_id for r in results if not r.not_evaluated]
        self.assertEqual(
            graded, [],
            f"these were graded pass or fail against a target that never "
            f"answered: {graded}")

    def test_a_402_to_everything_still_produces_real_verdicts(self):
        results = _run(L402SecurityTests, self.LIVE("http://target.invalid"))
        self.assertEqual(_erroring(results), [])
        self.assertGreater(len(_passing(results)), 25)
        unanswered = [r.test_id for r in results
                      if "requests were answered" in (r.details or "")]
        self.assertEqual(unanswered, [], f"fired on a live target: {unanswered}")


class TestTheInstrumentationItself(unittest.TestCase):
    """The mechanism the guard depends on, tested apart from any verdict."""

    def test_a_transport_that_only_implements_get_is_still_seen(self):
        """The regression. Wrapping `request` alone was not enough.

        The first version wrapped `request` only, reasoning that the real
        transports route `get` and `post` through it. True of the real ones and
        false of the doubles: three fakes in test_vsr03_verdict_correctness.py
        implement `get` and nothing else. That raised AttributeError, which was
        luck -- a double implementing `get` *and* `request` would have been
        instrumented on the path it does not use, and the guard would have gone
        quiet with every test in this file still green.
        """
        class GetOnly:
            base_url = "http://target.invalid"
            paid_path = ""
            default_method = "GET"

            def get(self, path="", headers=None, timeout=15.0):
                return dict(SILENCE)

        transport = GetOnly()
        suite = X402SecurityTests(transport)
        suite._seen.clear()
        transport.get("/x")
        self.assertEqual(
            len(suite._seen), 1,
            "a transport implementing only get() was not instrumented, so the "
            "silence guard can never fire for it")

    def test_get_delegating_to_request_counts_as_one_attempt(self):
        """Both are wrapped, so the response must be de-duplicated by identity."""
        transport = _fixed(X402Transport, CHALLENGE)("http://target.invalid")
        suite = X402SecurityTests(transport)
        suite._seen.clear()
        transport.get("/x")
        self.assertEqual(len(suite._seen), 1, f"double-counted: {suite._seen}")

    def test_a_reused_transport_feeds_the_live_suite(self):
        """Wrapping is idempotent and the sink follows the newest suite.

        The first version kept the sink in the closure, so a transport reused
        across two suites appended to the first suite's list forever while the
        second saw nothing and could never downgrade anything.
        """
        transport = _fixed(X402Transport, CHALLENGE)("http://target.invalid")
        first = X402SecurityTests(transport)
        second = X402SecurityTests(transport)
        first._seen.clear()
        second._seen.clear()
        transport.get("/x")
        self.assertEqual(len(second._seen), 1, "the live suite saw nothing")
        self.assertEqual(len(first._seen), 0, "the stale suite is still being fed")

    def test_a_test_that_makes_no_request_is_not_downgraded(self):
        """No attempts is not the same as no answers.

        A purely local verdict has nothing to be silent about, and the guard
        must not manufacture an INCONCLUSIVE for it.
        """
        from protocol_tests.x402_harness import X402TestResult
        suite = X402SecurityTests(_fixed(X402Transport, SILENCE)("http://target.invalid"))
        suite._seen.clear()
        suite._record(X402TestResult(
            test_id="LOCAL-000", name="purely local", category="c", owasp_asi="",
            severity="low", passed=True, details="decided without a target",
            http_method="none"))
        self.assertTrue(suite.results[0].passed)
        self.assertNotIn("INCONCLUSIVE", suite.results[0].details)


if __name__ == "__main__":
    unittest.main()
