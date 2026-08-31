"""INCONCLUSIVE must be a field on a result, not only English in `details`.

#404 defined `INCONCLUSIVE_PREFIX` so the third class became countable, and said
in the same comment that a field on the result classes would be better and was
not blocked by that step. This is that step, plus the ratchet that finishes it.

Why a prefix is not enough. `asdict(result)` carries fields; it does not carry
the meaning of a sentence. A consumer reading a serialised report sees
`passed: false` for a control that failed and `passed: false` for a control that
was never exercised, and can only tell them apart by re-implementing the
substring match. That is the predicate duplication `test_no_duplicate_refusal_
predicate.py` guards against inside this repository, exported across the API
boundary where no guard can see it.

Three vocabularies existed for this, in disjoint code paths. `l402_harness` and
`x402_harness` carry `not_evaluated: bool` -- a required precondition was
missing. `identity_harness` carries `informational: bool` -- the check ran fine
and there is nothing to assert. Everything else says it in English. The first
two are a real distinction and are kept; what they are not is a distinction the
*summary* can act on, and `identity_harness` says so itself: "Both are excluded
from pass and fail counts for the same reason: an unevaluated result must not be
scored as secure."

Nothing shared knew about either field, so `run_summary` -- which counted by
prose -- would have scored a field-only result as a target failure, because
`failed` is its residual bucket. No module fed it one, so that never fired.
`test_field_only_result_is_not_counted_as_a_failure` and
`test_informational_result_is_not_counted_as_a_failure` are the negative
controls that keep it from firing later.
"""
from __future__ import annotations

import ast
import pathlib
from dataclasses import asdict, dataclass

import pytest

from protocol_tests.http_helpers import (
    INCONCLUSIVE_FIELDS,
    INCONCLUSIVE_PREFIX,
    is_inconclusive,
    run_summary,
)

PROTOCOL_TESTS = pathlib.Path(__file__).resolve().parents[1] / "protocol_tests"

#: Modules whose result dataclasses still carry INCONCLUSIVE only as a prefix on
#: `details`. **This list may shrink as modules migrate, and must never grow.**
#:
#: Adding a module here is not a way to pass this test. A new result class that
#: can be INCONCLUSIVE gets the field; the list is for the ones that predate it.
PREFIX_ONLY = {
    "a2a_harness",
    "capability_profile_harness",
    "cloud_agent_harness",
    "enterprise_adapters",
    "extended_enterprise_adapters",
    "extended_thinking_harness",
    "framework_adapters",
    "governance_modification_harness",
    "gtg1002_simulation",
    "incident_response_harness",
    "intent_contract_harness",
    "jailbreak_harness",
    "kill_switch_harness",
    "mcp_harness",
    "memory_harness",
    "multi_agent_harness",
    "over_refusal_harness",
    "provenance_harness",
    "ptc_harness",
    "tool_search_harness",
    "watermark_harness",
}


def _modules_that_can_be_inconclusive() -> dict[str, bool]:
    """Every module with a result dataclass that can report INCONCLUSIVE.

    Derived from source rather than listed, so a module added tomorrow is
    covered without anyone remembering to add it here.
    """
    found: dict[str, bool] = {}
    for path in sorted(PROTOCOL_TESTS.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "@dataclass" not in text:
            continue
        if ("INCONCLUSIVE_PREFIX" not in text
                and not any(f in text for f in INCONCLUSIVE_FIELDS)):
            continue
        tree = ast.parse(text)
        carries = any(
            isinstance(node, ast.ClassDef)
            and any(
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id in INCONCLUSIVE_FIELDS
                for stmt in node.body
            )
            for node in ast.walk(tree)
        )
        found[path.stem] = carries
    return found


def test_the_prefix_only_list_may_shrink_and_must_never_grow():
    surveyed = _modules_that_can_be_inconclusive()
    assert surveyed, "no modules surveyed -- the derivation is broken, not the repo"

    still_prefix_only = {name for name, carries in surveyed.items() if not carries}
    grew = still_prefix_only - PREFIX_ONLY
    assert not grew, (
        "these modules can report INCONCLUSIVE but carry none of "
        f"{list(INCONCLUSIVE_FIELDS)} as a field, and are not on the list: "
        f"{sorted(grew)}. "
        "A result class that can be inconclusive gets the field. Do not add the "
        "module to PREFIX_ONLY to make this pass."
    )

    stale = PREFIX_ONLY - still_prefix_only
    assert not stale, (
        f"{sorted(stale)} have migrated -- remove them from PREFIX_ONLY. The list "
        "is a debt register; leaving a paid entry on it overstates the debt."
    )


def test_modules_that_led_the_way_still_carry_the_field():
    """l402 and x402 had this right before anything shared did."""
    surveyed = _modules_that_can_be_inconclusive()
    for name in ("l402_harness", "x402_harness", "identity_harness",
                 "return_channel_harness"):
        assert surveyed.get(name) is True, (
            f"{name} lost its structural INCONCLUSIVE field. It is the "
            "home for this state, not an implementation detail of one module."
        )


@dataclass
class _FieldOnly:
    passed: bool = False
    details: str = "the control was never exercised"
    not_evaluated: bool = True


@dataclass
class _PrefixOnly:
    passed: bool = False
    details: str = INCONCLUSIVE_PREFIX + "the control was never exercised"


@dataclass
class _InformationalOnly:
    passed: bool = False
    details: str = "recorded a finding; this check has no pass/fail criterion"
    informational: bool = True


@dataclass
class _GenuineFailure:
    passed: bool = False
    details: str = "the target granted an unauthorised transfer"


def test_field_only_result_is_not_counted_as_a_failure():
    """The latent trap, closed.

    Before the shared predicate learned about the field, this result carried the
    state structurally, said nothing about it in prose, and landed in `failed`
    because `failed` is the residual bucket. A run that established nothing
    would have been reported as a target that failed everything -- the exact
    misreport #404 was written to end, arriving through the other door.
    """
    summary = run_summary([_FieldOnly()])
    assert summary["inconclusive"] == 1
    assert summary["failed"] == 0
    assert summary["serviced"] == 0
    assert summary["pass_rate"] is None, (
        "a rate over nothing serviced is a claim, and absence is not"
    )


def test_informational_result_is_not_counted_as_a_failure():
    """`identity_harness`'s word for it, honoured by the shared bucket.

    A test with no pass/fail criterion did not fail. It also did not pass --
    `passed` stays False so a consumer reading only `.passed` fails closed --
    and the field is what stops that False from being read as a target defect.
    """
    summary = run_summary([_InformationalOnly()])
    assert summary["inconclusive"] == 1
    assert summary["failed"] == 0
    assert summary["serviced"] == 0


def test_prefix_only_result_is_still_counted():
    """The 21 unmigrated modules must not regress while the ratchet runs."""
    summary = run_summary([_PrefixOnly()])
    assert summary["inconclusive"] == 1
    assert summary["failed"] == 0


def test_a_real_failure_is_still_a_failure():
    """The negative control. A predicate that cannot report FAIL is not useful."""
    summary = run_summary([_GenuineFailure()])
    assert summary["inconclusive"] == 0
    assert summary["failed"] == 1
    assert summary["serviced"] == 1


def test_the_three_states_stay_distinguishable_in_one_run():
    summary = run_summary([_FieldOnly(), _InformationalOnly(),
                           _PrefixOnly(), _GenuineFailure()])
    assert (summary["inconclusive"], summary["failed"], summary["passed"]) == (3, 1, 0)
    assert summary["total"] == summary["passed"] + summary["failed"] + summary["inconclusive"]


@pytest.mark.parametrize("subject,expected", [
    (None, False),
    ("", False),
    ("the target granted an unauthorised transfer", False),
    (INCONCLUSIVE_PREFIX + "not applicable", True),
])
def test_the_string_form_of_the_predicate_is_unchanged(subject, expected):
    """Existing callers hold a `details` string and must keep working."""
    assert is_inconclusive(subject) is expected


def test_the_state_survives_serialisation():
    """The whole point: a consumer reading JSON can see it without parsing English."""
    record = asdict(_FieldOnly())
    assert record["not_evaluated"] is True
    assert record["passed"] is False, (
        "an unexercised control is not a pass; the field distinguishes it from a "
        "failure without changing that"
    )
