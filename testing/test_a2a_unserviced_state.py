"""a2a_harness against a dead host: what is fixed, and what is still open.

This module is deliberately still in `UNREVIEWED` in test_serviced_guard.py. It
is partially repaired, and the classification says "unreviewed" rather than
"guarded" because guarded has to mean guarded. Moving it would have passed the
serviced-guard suite -- that suite feeds synthetic results which *do* carry a
response -- while six live false passes remained. Claiming protection the module
does not have, inside the very list that records protection, is the failure this
whole effort exists to prevent.

## Why the shared guard is not used here

Applying `inconclusive_detail` to `_record` broke
`test_vsr03_verdict_correctness.py::TestA2A007PushRedirect::test_active_rejection_passes`.

`http_helpers._serviced` treats a 2xx carrying a JSON-RPC error envelope as "the
target did not service the request". That is correct for "method not found" and
wrong here: in A2A-007 an error envelope is the server *refusing* an attacker
push URL, which is the control working. The guard downgraded a real rejection to
INCONCLUSIVE.

That is a false negative of exactly the kind precondition 1 exists to prevent,
reached through the response-convention door rather than the simulate-fixture
one. So this module carries a narrow local rule instead: `_record` downgrades
only on the marker `_aggregate_evidence` sets when a multi-attempt test reached
nobody, and JSON-RPC error envelopes are untouched.

## What was fixed, in two passes

**First, the counting.** Loops of the shape

    resp = self.transport.get(path)
    if resp.get("_error") or resp.get("_status", 200) >= 400:
        blocked += 1

tallied a connection refusal as a blocked attack, and reported "3/3 traversal
attempts blocked" and "8/8 unauthorized task operations blocked" against a host
that was not running. `_answered` separates an answer -- including a 4xx or an
error envelope, both of which mean the server was reached -- from silence, and
`_aggregate_evidence` retains the attempt and answer counts so the verdict is
not evidence-free.

That left six. Every one of them decided `passed = <nothing bad was found>` from
a single request, or from a shape the aggregate helper did not cover, so the
marker it sets could never reach them. A fix scoped to the mechanism rather than
to the module.

**Second, the request log.** `_record` now also reads what this test's requests
actually came back as, via `instrument_transport` on `get`/`rpc`/`rpc_raw`. That
is the general form: a test is covered whether or not it remembers to call the
aggregate helper, and whether or not it records evidence at all. Reading the log
rather than `response_received` matters because several of these convert the
failure into a boolean or an empty list before recording it.

`A2A-006` needed one more edit. It answered a failed task creation with
`passed=True` and "server may not support tasks", which is the no-probe-surface
class rather than the silence class -- convention 9's first precondition, an
observable target capability. A server with no task support has not shown it
rejects invalid state transitions.

## What is still open

Nothing, against a closed port. `STILL_FALSE_PASSING` is empty and the check
below fails if it stops being empty, in either direction. That is a statement
about one failure mode and not a clean bill of health: this module can still
mis-verdict against a live target in every other way.
"""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.a2a_harness import A2ASecurityTests, A2ATransport

CLOSED_PORT = "http://127.0.0.1:9"

# Every test in the suite. None may pass against a target that never answered.
REPAIRED = {
    "A2A-001", "A2A-003", "A2A-004", "A2A-008", "A2A-009", "A2A-010", "A2A-013",
    # Added 2026-08-29 by the request-log guard. These six survived the counting
    # repair because none of them used _aggregate_evidence.
    "A2A-002", "A2A-005", "A2A-006", "A2A-007", "A2A-011", "A2A-012",
}

# Empty, and the check below holds it empty. An entry here is a known defect
# awaiting a read, never a resting state.
STILL_FALSE_PASSING: set[str] = set()


def _dead_host_results():
    suite = A2ASecurityTests(A2ATransport(CLOSED_PORT))
    with contextlib.redirect_stdout(io.StringIO()):
        suite.run_all()
    return suite.results


class TestA2AUnservicedState(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = _dead_host_results()
        cls.passing = {r.test_id for r in cls.results if r.passed}

    def test_the_suite_actually_ran(self):
        """Assert a positive expected set, so an empty run cannot read as success."""
        self.assertGreaterEqual(
            len(self.results), 13,
            "fewer results than expected; the harness probably errored rather "
            "than the repo improving")

    def test_repaired_tests_do_not_pass_against_silence(self):
        for tid in sorted(REPAIRED):
            with self.subTest(test_id=tid):
                self.assertNotIn(
                    tid, self.passing,
                    f"{tid} was repaired to treat silence as INCONCLUSIVE and is "
                    f"passing again against a closed port")

    def test_the_open_set_does_not_grow(self):
        """The ratchet. A new false pass here is a regression, not a discovery."""
        unexpected = self.passing - STILL_FALSE_PASSING
        self.assertEqual(
            unexpected, set(),
            f"new false passes against a dead host: {sorted(unexpected)}. Either "
            f"a repair regressed or a new test was written against the pattern "
            f"#351 exists to remove.")

    def test_the_open_set_is_declared_honestly(self):
        """If one gets fixed, this fails and the declared set must shrink.

        Without this the list would rot in the optimistic direction: repairs
        would land and the file would keep claiming six, which is the same
        restated-value drift the release-claims manifest exists to stop.
        """
        self.assertEqual(
            self.passing, STILL_FALSE_PASSING,
            "STILL_FALSE_PASSING no longer matches reality; update it to the "
            "measured set and record which repair moved it")


class _RefusingTransport(A2ATransport):
    """Answers every call with a JSON-RPC error envelope.

    In this protocol that is frequently the control working, not a failure to
    service the request -- which is why the shared serviced guard cannot be
    applied here at all.
    """

    def get(self, path):
        return {"error": {"code": -32601, "message": "Method not found"}}

    def rpc(self, method, params=None):
        return {"jsonrpc": "2.0", "id": 1,
                "error": {"code": -32600, "message": "Request refused"}}

    def rpc_raw(self, *args, **kwargs):
        return {"error": {"code": -32600, "message": "Request refused"}}


class TestTheGuardStaysOutOfTheWayOfARefusal(unittest.TestCase):
    """The false-negative direction, which is the specific danger in this module.

    Applying `inconclusive_detail` here downgraded A2A-007's active rejection to
    INCONCLUSIVE and broke test_vsr03_verdict_correctness. The request-log guard
    keys on silence alone, so a server answering every call with an error
    envelope must still produce ordinary verdicts.
    """

    def test_an_error_envelope_is_not_silence(self):
        suite = A2ASecurityTests(_RefusingTransport("http://target.invalid"))
        with contextlib.redirect_stdout(io.StringIO()):
            suite.run_all()
        downgraded = [r.test_id for r in suite.results
                      if "requests were answered" in (r.details or "")]
        self.assertEqual(
            downgraded, [],
            f"the silence guard fired on a target that answered every call with "
            f"a JSON-RPC error envelope: {downgraded}")
        self.assertTrue(
            [r for r in suite.results if r.passed],
            "a refusing target produced no passing verdict; the guard has been "
            "written too broadly and now inverts the protocol")
        self.assertTrue(
            [r for r in suite.results if not r.passed],
            "a refusing target produced no failing verdict either, which would "
            "mean the suite cannot distinguish targets at all")


if __name__ == "__main__":
    unittest.main()


class TestLimitationsIsAnExtensionNotAClaim(unittest.TestCase):
    """A2A-013 failed every spec-conformant agent for lacking a non-spec field.

    The A2A AgentCard schema has no `limitations` member. Checked against the
    official a2a-sdk 1.1.2 descriptor: name, description, supported_interfaces,
    provider, version, documentation_url, capabilities, security_schemes,
    security_requirements, default_input_modes, default_output_modes, skills,
    signatures, icon_url.

    So an absent field is not the agent claiming it has no limitations. It is
    the protocol having nowhere to put them. The old detail read

        Agent Card has no 'limitations' field -- agents that claim no
        limitations are suspicious

    which attributes to the agent a claim it had no way to make, at MEDIUM, on
    every conformant implementation.

    Found by running this harness against a real A2A server built on the
    official SDK. None of the three synthetic target shapes could surface it,
    because none of them serves an agent card at all.

    A `limitations` field that IS present and trivial still fails. That is a
    real claim, deliberately made, and worth reporting.
    """

    @staticmethod
    def _card_result(card: dict):
        class _CardTransport(A2ATransport):
            def get(self_inner, path):
                return dict(card)

            def rpc(self_inner, method, params=None):
                return {"result": {}}

        suite = A2ASecurityTests(_CardTransport("http://target.invalid"))
        with contextlib.redirect_stdout(io.StringIO()):
            suite.test_a2a_agent_card_limitations()
        return suite.results[0]

    def test_absent_field_is_inconclusive_not_a_finding(self):
        r = self._card_result({"name": "conformant", "version": "1.0.0"})
        self.assertFalse(r.passed)
        self.assertIn("INCONCLUSIVE", r.details)
        self.assertIn("does not define one", r.details)
        self.assertNotIn("suspicious", r.details)

    def test_a_trivial_declared_value_still_fails(self):
        """The case where the agent did make the claim."""
        r = self._card_result({"name": "x", "limitations": "none"})
        self.assertFalse(r.passed)
        self.assertNotIn("INCONCLUSIVE", r.details)
        self.assertIn("trivial", r.details)

    def test_meaningful_limitations_pass(self):
        r = self._card_result({"name": "x", "limitations":
                               "Cannot access production data; restricted to "
                               "read-only queries within one tenant."})
        self.assertTrue(r.passed, r.details)
