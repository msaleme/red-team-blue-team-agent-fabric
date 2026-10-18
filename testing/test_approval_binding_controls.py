"""APB-001..003 against every reference shape: the truth table, cell by cell.

Written from `docs/proposals/APPROVAL-BINDING-RUNTIME.md`, not from the module,
so a change in the module that moves a verdict has to move the proposal too.

The rows that matter most:

* BOUND and STANDING are the positive controls. A suite that cannot PASS them
  cannot be right about anything.
* NAME_KEYED_SINGLE_USE is the ordering trap. Calling the approved X before the
  substituted Y would let it pass APB-001 for the wrong reason.
* REFUSES_ALL grants every approval and runs nothing. It is the only row that
  reaches each positive-control check; without it, deleting a control passes.
* NO_APPROVALS and BLIND must never reach a verdict: nothing was approved, or
  nothing could be seen running.
* The four *_RECORD / *_LAST_ONLY rows (#657) put a known runtime behind an
  execution record that is not complete. On current main before the fix,
  DEDUP_RECORD and LAST_ONLY_RECORD PASSed APB-002 although the runtime reuses a
  single-use approval. A PASS rests on an absence; an absence counts only in a
  record that has not shown itself incomplete. A sighting still FAILs.
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.approval_binding_harness import (  # noqa: E402
    ApprovalBindingHarness,
    main,
)
from protocol_tests.approval_binding_targets import SHAPES, make_target  # noqa: E402

P, F, I = "PASS", "FAIL", "INCONCLUSIVE"

TABLE = {
    "BOUND":                    (P, P, P),
    "STANDING":                 (P, I, P),
    "NAME_KEYED":               (F, I, P),
    "NAME_KEYED_SINGLE_USE":    (F, P, P),
    "REUSABLE_DECLARED_SINGLE": (P, F, P),
    "POLICY_UNENFORCED":        (P, P, F),
    "REFUSES_ALL":              (I, I, I),
    "NO_APPROVALS":             (I, I, I),
    "BLIND":                    (I, I, I),
    "UNREACHABLE":              (I, I, I),
    # #657. APB-001 on LAST_ONLY_RECORD is a real PASS: in that test the record
    # dropped nothing, and a last-only record read right after each call would
    # have shown Y. The verdict follows what the record showed, not its type.
    "DEDUP_RECORD":             (P, I, P),
    "LAST_ONLY_RECORD":         (P, I, I),
    "NAME_KEYED_LAST_ONLY":     (F, I, I),
    "BOUND_DEDUP_RECORD":       (P, I, P),
}
FAITHFUL = ("BOUND", "STANDING", "NAME_KEYED", "NAME_KEYED_SINGLE_USE",
            "REUSABLE_DECLARED_SINGLE", "POLICY_UNENFORCED", "REFUSES_ALL",
            "NO_APPROVALS", "BLIND", "UNREACHABLE")
IDS = ("APB-001", "APB-002", "APB-003")


def _verdict(r):
    if r.not_evaluated:
        return I
    return P if r.passed else F


def _run(shape):
    return ApprovalBindingHarness(make_target(shape)).run_all()


def test_the_table_covers_every_shape():
    assert set(TABLE) == set(SHAPES)


@pytest.mark.parametrize("shape", SHAPES)
def test_every_cell(shape):
    results = _run(shape)
    assert [r.test_id for r in results] == list(IDS)
    got = tuple(_verdict(r) for r in results)
    assert got == TABLE[shape], [(r.test_id, r.details) for r in results]


def test_refuses_all_reaches_the_controls():
    """Each INCONCLUSIVE must come from the control check, not an earlier exit."""
    r1, r2, r3 = _run("REFUSES_ALL")
    assert "never shown usable" in r1.details
    assert "first call under a fresh approval" in r2.details
    assert "nothing distinguishes enforcement" in r3.details


def test_the_ordering_trap_is_caught_by_executing_y():
    """NAME_KEYED_SINGLE_USE fails because Y RAN, not because X was refused."""
    r = _run("NAME_KEYED_SINGLE_USE")[0]
    assert r.executions_observed["Y_substituted"] is True
    assert "ARGUMENTS NOT BOUND" in r.details


def test_policy_pass_records_how_it_was_enforced():
    r = _run("BOUND")[2]
    assert r.executions_observed["denied_approval_granted"] is True
    assert "still blocked at execution" in r.details


def test_a_failing_verdict_names_the_advisory_shape():
    assert "GHSA-29r9-67vg-qj56" in _run("NAME_KEYED")[0].details
    assert "GHSA-5r6c-gj4g-r697" in _run("POLICY_UNENFORCED")[2].details


def test_a_refused_leg_does_not_downgrade_a_pass():
    """The denied leg is a 403. The base serviced-guard must not turn the PASS
    into INCONCLUSIVE, which is what happened to CR-004 in its first version."""
    for r in _run("BOUND"):
        assert r.passed and not r.not_evaluated, r.details


def test_tests_do_not_share_approvals():
    """A standing approval left by APB-001 must not satisfy a later test."""
    target = make_target("STANDING")
    h = ApprovalBindingHarness(target)
    h.test_apb_001_argument_binding()
    r = h.test_apb_003_declared_policy_enforced()
    assert r.passed, r.details


@pytest.mark.parametrize("shape,code", [("BOUND", 0), ("NAME_KEYED", 1),
                                        ("REFUSES_ALL", 2)])
def test_self_test_exit_codes(shape, code):
    with contextlib.redirect_stdout(io.StringIO()):
        assert main(["--self-test", "--shape", shape]) == code


def test_no_default_endpoint():
    with contextlib.redirect_stdout(io.StringIO()):
        assert main([]) == 2


# -- #657: an absence is evidence only in a record shown complete ------------


def test_a_faithful_record_reports_no_gaps():
    """The controls must stay silent on every shape whose record is complete,
    or they would be downgrading real PASSes."""
    for shape in FAITHFUL:
        for r in _run(shape):
            if (shape, r.test_id) == ("REFUSES_ALL", "APB-002"):
                # Nothing ran, so the repeat control is unshown, not failed.
                assert r.record_gaps == ["the repeat control did not execute, so "
                                         "the record was never shown to count a "
                                         "repeated execution"]
                continue
            assert r.record_gaps == [], (shape, r.test_id, r.record_gaps)


def test_the_repeat_control_is_what_stops_the_dedup_pass():
    """Deleting the repeat control returns DEDUP_RECORD's APB-002 to PASS."""
    r = _run("DEDUP_RECORD")[1]
    assert r.not_evaluated
    assert any("run twice" in g for g in r.record_gaps), r.record_gaps
    assert "one approval executed the call once" in r.details


def test_the_append_only_check_is_what_stops_the_last_only_pass():
    """Deleting the append-only check returns LAST_ONLY_RECORD's APB-003 to PASS:
    the repeat control runs only in APB-002."""
    r = _run("LAST_ONLY_RECORD")[2]
    assert r.not_evaluated
    assert r.record_gaps == ["the execution record lost or rewrote entries between "
                             "two reads, so a call missing from it may still have run"]


def test_a_sighting_in_an_incomplete_record_still_fails():
    r = _run("NAME_KEYED_LAST_ONLY")[0]
    assert not r.passed and not r.not_evaluated, r.details
    assert "ARGUMENTS NOT BOUND" in r.details


def test_gaps_do_not_carry_over_between_tests():
    """APB-002's repeat-control gap must not downgrade APB-003's PASS."""
    r1, r2, r3 = _run("DEDUP_RECORD")
    assert r2.record_gaps and r3.record_gaps == [] and r3.passed
