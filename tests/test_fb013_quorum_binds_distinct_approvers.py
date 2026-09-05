"""FB-013: a quorum must require distinct approvers, each bound to the exact action.

Before 2026-09-05, `test_fb_013_approval_quorum` asserted one property -- that an
above-threshold spend routed to `require_approval` -- while carrying the name
"Approval Quorum Above Threshold". The test built no approver set, so there were
no identities for distinctness to be checked against and no action for an approval
to be bound to. The name claimed a control the assertion did not exercise.

Found by applying the lens VrtxOmega used on the authority-execution replay
verifier (msaleme/authority-execution-replay#1): satisfying a required-control
count must require the correct distinct identities and bindings, not merely the
correct cardinality. The replay verifier accepted three copies of one control for
a three-control requirement; FB-013 was the same defect reached from the other
side -- no identities at all.

These are the regressions. Each pins one property so that a future edit which
weakens the quorum back to a count fails here rather than in a published claim.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from protocol_tests.x402_fireblocks_harness import (  # noqa: E402
    ActionRef,
    ApprovalQuorum,
)


@pytest.fixture
def action():
    return ActionRef(pay_to="0xM", amount=5_000_000, nonce="tx-1")


def test_distinct_approvers_satisfy_the_quorum(action):
    """The positive control. A quorum that rejects everything has not enforced
    anything -- it must still accept the case it exists to allow."""
    q = ApprovalQuorum(threshold=2, action=action)
    assert q.approve("approver-a", action)[0]
    assert not q.satisfied, "one of two approvals must not satisfy a threshold of two"
    assert q.approve("approver-b", action)[0]
    assert q.satisfied


def test_one_approver_twice_is_not_a_quorum_of_two(action):
    """Cardinality is not identity. This is the defect class itself."""
    q = ApprovalQuorum(threshold=2, action=action)
    assert q.approve("approver-a", action)[0]
    accepted, reason = q.approve("approver-a", action)
    assert not accepted
    assert "duplicate" in reason
    assert not q.satisfied, "the same approver counted twice reached the threshold"


def test_approval_for_a_different_action_does_not_count(action):
    """Binding. An approval is granted for one action, not for the approver's
    general willingness to approve."""
    other = ActionRef(pay_to="0xM", amount=5_000_000, nonce="tx-2")
    q = ApprovalQuorum(threshold=1, action=action)
    accepted, reason = q.approve("approver-a", other)
    assert not accepted
    assert "not bound" in reason
    assert not q.satisfied


@pytest.mark.parametrize("field,value", [
    ("pay_to", "0xATTACKER"),
    ("amount", 50_000_000),
    ("nonce", "tx-replay"),
])
def test_binding_is_checked_on_every_field(action, field, value):
    """Each field of the action is load-bearing: an approval that differs on any
    one of destination, amount or nonce is an approval for a different action."""
    q = ApprovalQuorum(threshold=1, action=action)
    mutated = ActionRef(**{**action.__dict__, field: value})
    assert not q.approve("approver-a", mutated)[0]
    assert not q.satisfied


def test_fb013_reports_the_gap_rather_than_passing():
    """The harness test must fail loudly if the quorum stops enforcing either
    property -- the point is that FB-013 can now be wrong."""
    from protocol_tests import x402_fireblocks_harness as fb

    class CountingQuorum(fb.ApprovalQuorum):
        """A quorum that counts approvals and checks nothing else -- the pre-fix
        behaviour, injected to prove FB-013 detects it."""

        def approve(self, approver, action):
            self._approvers[f"{approver}-{len(self._approvers)}"] = action
            return (True, "counted")

    harness = fb.X402FireblocksTests(simulate=True)
    original = fb.ApprovalQuorum
    fb.ApprovalQuorum = CountingQuorum
    try:
        harness.test_fb_013_approval_quorum()
    finally:
        fb.ApprovalQuorum = original

    result = next(r for r in harness.results if r.test_id == "FB-013")
    assert not result.passed, "FB-013 passed against a quorum that only counts"
    assert "QUORUM GAP" in result.details or "BINDING GAP" in result.details
