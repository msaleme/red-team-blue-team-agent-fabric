"""Tests for the verdict-taint auditor (#351).

The first version of this script shipped with no tests and reported
``governance_modification_harness`` as having no response-decided verdict. It
has five, and a live false pass. The blind spot was control dependency: a flag
assigned inside an ``if`` whose condition reads the response, where the response
never appears on an assignment's right-hand side.

An instrument built to find checks that cannot fail, shipped without checks of
its own. These are the checks. Every case below is a shape taken from the
package, not an invented one.
"""

import ast
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.audit_verdict_taint import (  # noqa: E402
    RESPONSE_NAMES,
    audit,
    build_dependencies,
    candidate_modules,
    derive_response_names,
    free_names,
)


def _audit_src(src: str) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.py"
        path.write_text(src, encoding="utf-8")
        return audit(path)


def _tainted(src: str) -> list[bool]:
    return [r["tainted"] for r in _audit_src(src)]


# --- the regression that motivated this file --------------------------------

def test_flag_set_inside_a_response_conditional_is_tainted():
    """The #372 blind spot, verbatim from governance_modification_harness.

    `succeeded` never appears on a right-hand side with `resp` on it. The taint
    arrives through the condition governing the assignment.
    """
    assert _tainted('''
def t(self):
    succeeded = False
    for payload in self.payloads:
        resp = http_post(self.url, payload)
        if _response_allows_change(resp):
            succeeded = True
            break
    self._record(R(passed=not succeeded, response_received=resp))
''') == [True]


def test_the_same_shape_without_the_conditional_is_still_tainted():
    """Data dependency, which the first version did catch. Guards the fix from
    regressing the case it already handled."""
    assert _tainted('''
def t(self):
    resp = http_post(self.url, {})
    leaked = "secret" in str(resp)
    self._record(R(passed=not leaked, response_received=resp))
''') == [True]


def test_control_taint_survives_one_hop_through_another_flag():
    assert _tainted('''
def t(self):
    resp = http_post(self.url, {})
    seen = False
    if resp.get("_status") == 200:
        seen = True
    verdict = seen
    self._record(R(passed=not verdict, response_received=resp))
''') == [True]


def test_while_loop_condition_taints_its_body():
    assert _tainted('''
def t(self):
    resp = http_post(self.url, {})
    escalated = False
    while _still_open(resp):
        escalated = True
        break
    self._record(R(passed=not escalated, response_received=resp))
''') == [True]


def test_for_loop_over_a_response_taints_the_body():
    assert _tainted('''
def t(self):
    resp = http_post(self.url, {})
    bad = False
    for item in resp.get("items", []):
        bad = True
    self._record(R(passed=not bad, response_received=resp))
''') == [True]


def test_taint_through_an_except_handler_body():
    assert _tainted('''
def t(self):
    resp = http_post(self.url, {})
    ok = False
    try:
        if resp["result"]:
            ok = True
    except KeyError:
        ok = False
    self._record(R(passed=ok, response_received=resp))
''') == [True]


# --- the negative case has to stay negative ---------------------------------

def test_a_verdict_that_never_touches_a_response_is_not_tainted():
    """Over-reporting is the safe error, but not to the point of reporting
    everything. A genuinely local check must stay untainted."""
    assert _tainted('''
def t(self):
    missing = [k for k in REQUIRED if k not in self.config]
    self._record(R(passed=len(missing) == 0))
''') == [False]


def test_an_unrelated_conditional_does_not_taint():
    assert _tainted('''
def t(self):
    found = False
    if self.strict_mode:
        found = True
    self._record(R(passed=not found))
''') == [False]


# --- shape and mechanics -----------------------------------------------------

def test_false_pass_shape_flags_negations_and_emptiness():
    rows = _audit_src('''
def t(self):
    resp = http_post(self.url, {})
    self._record(R(passed=not _leak(resp)))
def u(self):
    resp = http_post(self.url, {})
    self._record(R(passed=_accepted(resp)))
''')
    assert [r["false_pass_shape"] for r in rows] == [True, False]


def test_direct_is_distinguished_from_indirect():
    rows = _audit_src('''
def t(self):
    resp = http_post(self.url, {})
    self._record(R(passed=not _leak(resp)))
def u(self):
    resp = http_post(self.url, {})
    leaked = _leak(resp)
    self._record(R(passed=not leaked))
''')
    assert rows[0]["direct"] is True
    assert rows[1]["direct"] is False and rows[1]["tainted"] is True


def test_comprehension_variables_are_not_treated_as_free_names():
    """`sum(1 for r in results if r.passed)` must not match on the loop variable
    `r`. An early version of this analyser did exactly that and reported 8
    tainted modules instead of 25."""
    expr = ast.parse("sum(1 for r in results if r.passed)", mode="eval").body
    assert "r" not in free_names(expr)


def test_build_dependencies_records_the_governing_condition():
    fn = ast.parse('''
def t(self):
    resp = http_post(self.url, {})
    flag = False
    if _check(resp):
        flag = True
''').body[0]
    deps = build_dependencies(fn)
    assert "resp" in deps["flag"]


def test_verdicts_are_found_as_keyword_and_as_assignment():
    rows = _audit_src('''
def t(self):
    resp = http_post(self.url, {})
    self._record(R(passed=not _leak(resp)))
def u(self):
    resp = http_post(self.url, {})
    passed = not _leak(resp)
    self._record(R(passed=passed))
''')
    assert len(rows) == 3  # one keyword, one assignment, one keyword re-reading it


# --- the claim the script is allowed to make ---------------------------------

def test_response_names_are_derived_not_hand_written():
    """The #372 defect one level up.

    The shipped version carried twelve hand-written names while the package binds
    responses to at least twenty-one more, so every verdict reading `resp1` or
    `ks_probe` was reported clean. Deriving per module makes a new binding
    covered the moment it lands.
    """
    tree = ast.parse(
        (Path(__file__).resolve().parents[1]
         / "protocol_tests" / "governance_modification_harness.py").read_text()
    )
    derived = derive_response_names(tree)
    for name in ("hc12_probe", "ks_probe", "readback", "rat_resp"):
        assert name in derived, f"{name} binds a response but was not derived"
        assert name not in RESPONSE_NAMES, (
            f"{name} is hand-written into the floor set; the point is that it "
            f"does not have to be"
        )


def test_a_response_under_an_unlisted_name_is_still_caught():
    """The probe that exposed the original blind spot. Two structurally identical
    verdicts differing only in variable name must classify identically."""
    unlisted = _tainted("""
def t(self):
    weird_name_9 = http_post(self.url, {})
    leaked = "secret" in str(weird_name_9)
    self._record(R(passed=not leaked, response_received=weird_name_9))
""")
    listed = _tainted("""
def t(self):
    resp = http_post(self.url, {})
    leaked = "secret" in str(resp)
    self._record(R(passed=not leaked, response_received=resp))
""")
    assert unlisted == listed == [True]


def test_every_candidate_module_parses_and_audits():
    """No module in the package should crash the auditor."""
    for path in candidate_modules():
        audit(path)
