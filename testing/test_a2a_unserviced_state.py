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

## What was fixed

The counting. Loops of the shape

    resp = self.transport.get(path)
    if resp.get("_error") or resp.get("_status", 200) >= 400:
        blocked += 1

tallied a connection refusal as a blocked attack, and reported "3/3 traversal
attempts blocked" and "8/8 unauthorized task operations blocked" against a host
that was not running. `_answered` now separates an answer -- including a 4xx or
an error envelope, both of which mean the server was reached -- from silence,
and `_aggregate_evidence` retains the attempt and answer counts so the verdict
is not evidence-free.

Dead-host pass count: **11 of 13 before, 6 of 13 now.**

## What is still open

The six below decide `passed = <nothing bad was found>` from a single request or
a shape the aggregate helper does not cover. Each needs its own read. They are
listed by ID rather than described loosely, so the remaining work is countable
and this file fails if the number silently grows.
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

# Repaired: these must not pass against a target that never answered.
REPAIRED = {"A2A-001", "A2A-003", "A2A-004", "A2A-008", "A2A-009", "A2A-010", "A2A-013"}

# Still open. May shrink. Must never grow.
STILL_FALSE_PASSING = {"A2A-002", "A2A-005", "A2A-006", "A2A-007", "A2A-011", "A2A-012"}


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


if __name__ == "__main__":
    unittest.main()
