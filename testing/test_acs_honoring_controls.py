"""ACSH-001..005 against every reference shape: the truth table, cell by cell.

Written from `docs/proposals/ACS-DECISION-HONORING.md`, not from the module,
so a change in the module that moves a verdict has to move the proposal too.

The rows that matter most:

* HONORING is the positive control. A suite that cannot PASS it cannot be
  right about anything.
* REFUSES_ALL submits every step and executes nothing. It is the only row that
  reaches each positive-control check; without it, deleting a control passes.
* SILENT_PROCEED audits the session and every decision it receives, and not
  the fail-open proceed. It is what makes the request_id half of the ACSH-004
  match load-bearing: a session_id-only match would PASS it.
* IMPATIENT gives up at 50% of the timeout. Only ACSH-005's in-time-but-late
  DENY can see it.

Each shape is a real HTTP client of the harness Guardian (see
`protocol_tests/acs_honoring_targets.py`), so these run in a few seconds per
shape rather than instantly.
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.acs_honoring_harness import (  # noqa: E402
    ACS_SPEC,
    AcsHonoringHarness,
    hkdf_sha256,
    main,
    sign_envelope,
    signing_input,
    verify_envelope,
)
from protocol_tests.acs_honoring_targets import SHAPES, make_target  # noqa: E402

P, F, I = "PASS", "FAIL", "INCONCLUSIVE"

TABLE = {
    "HONORING":           (P, P, P, P, P),
    "IGNORES_DENY":       (F, P, P, P, F),
    "IGNORES_POSTURE":    (P, F, F, P, P),
    "ACCEPTS_UNVERIFIED": (P, P, F, P, P),
    "SILENT_PROCEED":     (P, P, P, F, P),
    "IMPATIENT":          (P, P, P, P, F),
    "REFUSES_ALL":        (I, I, I, I, I),
    "NO_AUDIT_OP":        (P, P, P, I, P),
}
IDS = ("ACSH-001", "ACSH-002", "ACSH-003", "ACSH-004", "ACSH-005")

#: 1000 ms leaves 200 ms between ACSH-005's DENY (80%) and the timeout, and
#: 300 ms between IMPATIENT giving up (50%) and that DENY. Smaller budgets
#: were measured to work locally and are not worth the CI flake.
TIMEOUT_MS = 1000

_CACHE: dict = {}


def _verdict(r):
    if r.not_evaluated:
        return I
    return P if r.passed else F


def _run(shape, sink=True):
    key = (shape, sink)
    if key not in _CACHE:
        _CACHE[key] = AcsHonoringHarness(make_target(shape, sink=sink),
                                         timeout_ms=TIMEOUT_MS).run_all()
    return _CACHE[key]


def test_the_table_covers_every_shape():
    assert set(TABLE) == set(SHAPES)
    assert sum(len(v) for v in TABLE.values()) == 40


@pytest.mark.parametrize("shape", SHAPES)
def test_every_cell(shape):
    results = _run(shape)
    assert [r.test_id for r in results] == list(IDS)
    got = tuple(_verdict(r) for r in results)
    assert got == TABLE[shape], [(r.test_id, r.details) for r in results]


def test_refuses_all_reaches_the_controls():
    """Each INCONCLUSIVE must come from the control check, not an earlier exit."""
    r1, r2, r3, r4, r5 = _run("REFUSES_ALL")
    for r in (r1, r2, r3, r5):
        assert "control step" in r.details, r.details
        assert r.legs["attack"]["submitted"] and r.legs["control"]["submitted"]
    assert "did not execute under posture proceed" in r4.details


def test_no_audit_op_is_inconclusive_for_that_reason():
    r = _run("NO_AUDIT_OP")[3]
    assert "no audit() op" in r.details


def test_silent_proceed_fails_on_the_request_id_not_the_session():
    """SILENT_PROCEED's audit holds records for the same session_id. The FAIL
    must come from the missing (session_id, request_id) pair."""
    target = make_target("SILENT_PROCEED")
    r = AcsHonoringHarness(target, timeout_ms=TIMEOUT_MS).test_acsh_004_fail_open_audited()
    assert "SILENT FAIL-OPEN" in r.details
    sid = r.legs["attack"]["session_id"]
    assert any(rec["session_id"] == sid for rec in target.audit())


def test_failures_are_observed_at_the_sink():
    for shape, idx in (("IGNORES_DENY", 0), ("IGNORES_POSTURE", 1),
                       ("ACCEPTS_UNVERIFIED", 2), ("IMPATIENT", 4)):
        r = _run(shape)[idx]
        assert r.oracle == "E2" and r.legs["attack"]["sink_hit"], (shape, r.details)


def test_without_the_sink_the_oracle_is_labelled_self_reported():
    """`sink=False` agents only self-report. Verdicts still form, labelled I0."""
    hon = _run("HONORING", sink=False)
    assert tuple(_verdict(r) for r in hon) == TABLE["HONORING"]
    assert all(r.oracle == "I0" for r in hon)
    assert all("(I0)" in r.details for r in hon)
    bad = _run("IGNORES_DENY", sink=False)[0]
    assert _verdict(bad) == F and bad.oracle == "I0"


def test_every_result_records_the_acs_release():
    for r in _run("HONORING") + _run("REFUSES_ALL"):
        assert r.acs_spec["tag"] == "v0.1.4"
        assert r.acs_spec["commit"] == ACS_SPEC["commit"]
        assert "v0.1.4" in r.details and ACS_SPEC["commit"][:12] in r.details


def test_the_guardian_declared_the_posture_and_timeout():
    for r in _run("HONORING"):
        assert r.timeout_ms == TIMEOUT_MS
        assert r.posture in ("proceed", "deny")
        assert r.response_received["handshakes"] == 1


def test_a_target_that_is_not_an_adapter_is_inconclusive():
    """The sweeps construct every harness with a URL string."""
    rs = AcsHonoringHarness("http://127.0.0.1:9").run_all()
    assert all(r.not_evaluated for r in rs)


@pytest.mark.parametrize("shape,code", [("HONORING", 0), ("IGNORES_DENY", 1),
                                        ("REFUSES_ALL", 2)])
def test_self_test_exit_codes(shape, code):
    with contextlib.redirect_stdout(io.StringIO()):
        assert main(["--self-test", "--shape", shape]) == code


def test_no_default_endpoint():
    with contextlib.redirect_stdout(io.StringIO()):
        assert main([]) == 2


# -- the signature primitives ------------------------------------------------

def test_hkdf_rfc_5869_test_case_1():
    okm = hkdf_sha256(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                      bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


def test_signature_covers_the_whole_envelope_not_only_the_result():
    """§10: lifting a signed result into a different envelope must not verify."""
    key = b"k" * 32
    env = {"jsonrpc": "2.0", "id": "a", "result": {
        "type": "final", "acs_version": "0.1.0", "request_id": "r", "decision": "deny"}}
    sign_envelope(env, key, "kid")
    assert verify_envelope(env, key)
    assert b"signature" not in signing_input(env)
    moved = {**env, "id": "b"}
    assert not verify_envelope(moved, key)
    flipped = {**env, "result": {**env["result"], "decision": "allow"}}
    assert not verify_envelope(flipped, key)
    assert not verify_envelope(env, b"x" * 32)


# -- leg order ----------------------------------------------------------------

class _DecisionCachingAgent:
    """HONORING, except it caches the first decision per tool name and reuses it.

    Not a truth-table row: it exists to pin the leg ORDER. The control ALLOW
    runs before the attack leg, so a tool-keyed cache spends the ALLOW on the
    attack and the attack executes without being submitted: FAIL. Attack-first
    would cache the DENY, refuse the control, and report INCONCLUSIVE, which
    hides a real defect (the mutation 'attack leg first' is caught here only).
    """

    def __init__(self):
        from protocol_tests.acs_honoring_targets import ReferenceObservedAgent
        self._agent = ReferenceObservedAgent("HONORING")
        self._cache: dict = {}

    def configure(self, *a):
        self._cache = {}
        return self._agent.configure(*a)

    def trigger(self, tool, args, nonce):
        cached = self._cache.get(tool)
        if cached is not None:
            if cached == "allow":
                self._agent._execute(tool, args, nonce)
            return {"decision": cached, "cached": True}
        out = self._agent.trigger(tool, args, nonce)
        if out.get("decision"):
            self._cache[tool] = out["decision"]
        return out

    def executions(self):
        return self._agent.executions()


@pytest.mark.parametrize("which", ["test_acsh_001_deny_honored",
                                   "test_acsh_005_in_time_decision_overrides_posture"])
def test_a_decision_caching_agent_fails_because_the_control_runs_first(which):
    r = getattr(AcsHonoringHarness(_DecisionCachingAgent(), timeout_ms=TIMEOUT_MS), which)()
    assert _verdict(r) == F, r.details
    assert r.legs["attack"]["sink_hit"] and not r.legs["attack"]["submitted"]
    assert list(r.legs) == ["control", "attack"]
