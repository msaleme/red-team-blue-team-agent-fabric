"""MCP-021: the auth differential must tell four gateway shapes apart (#503).

CVE-2026-59822: LiteLLM's MCP Gateway returned an empty `UserAPIKeyAuth()` on the
failure branch of token validation, so `Authorization: Bearer x` granted full
access. The wire behavior of "auth fell open" and "auth was never configured" is
identical on the garbage-token request alone; only the differential against a
header-less request separates them. And two rejections alone cannot separate an
enforcing gateway from one that refuses everything, which is why the configured
credential is a required leg rather than a nicety.

Each test drives a fake transport standing in for one gateway shape. The point is
that the verdict is able to be wrong: a version of this test that graded on the
garbage rows alone would pass shapes 3 and 4.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from protocol_tests.mcp_harness import MCPSecurityTests  # noqa: E402

RESULT = {"result": {"tools": []}}
REFUSED = {"_error": True, "_status": 401, "_body": "unauthorized"}


class FakeTransport:
    """Answers by gateway shape, keyed on what the Authorization header became."""

    def __init__(self, shape, headers=None):
        self.shape = shape
        self.headers = headers if headers is not None else {"Authorization": "Bearer real"}
        self.seen = []

    def send(self, message, *, header_overrides=None):
        auth = self.headers.get("Authorization")
        if header_overrides and "Authorization" in header_overrides:
            auth = header_overrides["Authorization"]      # None means removed
        self.seen.append(auth)
        if self.shape == "holding":
            return RESULT if auth == "Bearer real" else REFUSED
        if self.shape == "fails_open":
            return REFUSED if auth is None else RESULT
        if self.shape == "no_auth":
            return RESULT
        if self.shape == "refuses_all":
            return REFUSED
        if self.shape == "unreachable":
            return {"_error": True, "_exception": "connection refused"}
        raise AssertionError(f"unknown shape {self.shape}")


def _verdict(shape, headers=None):
    t = FakeTransport(shape, headers)
    h = MCPSecurityTests(t, simulate=False)
    h.test_mcp_021_auth_fail_open()
    r = h.results[-1]
    state = ("INCONCLUSIVE" if r.details.startswith("INCONCLUSIVE")
             else "PASS" if r.passed else "FAIL")
    return state, r.details, t


def test_enforcing_gateway_passes():
    """The positive control. A verdict that never passes has enforced nothing."""
    state, details, _ = _verdict("holding")
    assert state == "PASS", details


def test_fail_open_gateway_is_caught():
    """The CVE shape: header-less refused, any bearer served."""
    state, details, _ = _verdict("fails_open")
    assert state == "FAIL", details
    assert "AUTH FAILS OPEN" in details
    assert "garbage_bearer" in details


def test_unauthenticated_endpoint_is_inconclusive_not_failed():
    """Serving the header-less request means nothing is authenticating here.

    Grading this FAIL would be the naive reading: it is a different finding."""
    state, details, _ = _verdict("no_auth")
    assert state == "INCONCLUSIVE", details
    assert "not authenticating" in details


def test_gateway_that_refuses_everything_is_inconclusive_not_passed():
    """Two rejections without the accept control are not evidence of enforcement."""
    state, details, _ = _verdict("refuses_all")
    assert state == "INCONCLUSIVE", details
    assert "configured credential was rejected" in details


def test_unreachable_target_is_inconclusive():
    state, details, _ = _verdict("unreachable")
    assert state == "INCONCLUSIVE", details


def test_missing_credential_cannot_run_the_control():
    state, details, _ = _verdict("holding", headers={})
    assert state == "INCONCLUSIVE", details
    assert "no Authorization credential is configured" in details


def test_the_header_less_leg_actually_omits_the_header():
    """The differential depends on absence, not on a blank value.

    `header_overrides` was update-only before #503; sending an empty string would
    have probed a different thing entirely."""
    _, _, t = _verdict("holding")
    assert None in t.seen, f"no leg removed the Authorization header: {t.seen}"
    assert "Bearer x" in t.seen
    assert "Bearer real" in t.seen
    assert any(s and s.startswith("Bearer eyJ") for s in t.seen), t.seen


@pytest.mark.parametrize("shape,expected", [
    ("holding", "PASS"), ("fails_open", "FAIL"), ("no_auth", "INCONCLUSIVE"),
    ("refuses_all", "INCONCLUSIVE"), ("unreachable", "INCONCLUSIVE"),
])
def test_each_shape_gets_its_own_verdict(shape, expected):
    state, details, _ = _verdict(shape)
    assert state == expected, f"{shape}: {details}"
