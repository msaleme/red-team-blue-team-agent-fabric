"""MCP-022 over a real HTTP socket: a token issued for another resource server.

## Why this file exists

GHSA-w4fh-qvv9-3v23 (Python MCP SDK, 2026-10-05): server-side bearer
authentication accepted a valid token issued for a different resource server.
The fix ships off by default, so only a test against the deployed server can
say whether audience is enforced. Gap issue #645.

Convention 9 needs a positive and a negative control before the test counts.
These stub servers are both, driven through the real transport:

==============================  =========  ==============  ========  ===========
stub                            no header  other audience  valid     verdict
==============================  =========  ==============  ========  ===========
holding (401 or 403)            rejected   rejected        served    PASS
audience-blind                  rejected   served          served    FAIL
refuses all / half-applied fix  rejected   rejected        rejected  INCONCLUSIVE
no auth on the route            served     served          served    INCONCLUSIVE
5xx on the audience leg         rejected   indeterminate   served    INCONCLUSIVE
==============================  =========  ==============  ========  ===========

plus the ill-posed runs that must never reach a verdict: no other-resource
token, a header name that does not replace the configured credential, readable
JWTs from different issuers, and a JWT that also names this server's audience.

## What this does not establish

Anything about a real product. The stubs decide by exact header value; a real
server decides by validating the token. Whether a given deployment rejects a
wrong-audience token is what the test is for.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.http_helpers import is_inconclusive  # noqa: E402
from protocol_tests.mcp_harness import (  # noqa: E402
    MCPSecurityTests,
    StreamableHTTPTransport,
    _audience_precondition,
    _jwt_claims,
)


def _jwt(claims: dict) -> str:
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"Bearer {seg({'alg': 'RS256', 'typ': 'JWT'})}.{seg(claims)}.c2ln"


VALID = "Bearer mcp022-right-audience"
OTHER = "Bearer mcp022-other-audience"
ISS = "https://auth.example.test"
VALID_JWT = _jwt({"iss": ISS, "aud": "https://mcp.example.test/mcp", "sub": "a"})
OTHER_JWT = _jwt({"iss": ISS, "aud": "https://billing.example.test", "sub": "a"})


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length) or b"{}")
        self.server.seen.append(self.headers.get("Authorization"))  # type: ignore[attr-defined]
        status = self.server.policy(self.headers.get("Authorization"))  # type: ignore[attr-defined]
        if status == 200:
            body = json.dumps({"jsonrpc": "2.0", "id": request.get("id"),
                               "result": {"tools": []}}).encode()
            ctype = "application/json"
        else:
            body, ctype = b"Unauthorized", "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _policy(*, none, other, valid=200, valid_value=VALID):
    def policy(auth):
        if auth == valid_value:
            return valid
        if auth is None:
            return none
        return other
    return policy


@contextlib.contextmanager
def _stub(policy):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.policy = policy  # type: ignore[attr-defined]
    httpd.seen = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/mcp", httpd.seen
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _verdict(result):
    if is_inconclusive(result):
        return "INCONCLUSIVE"
    return "PASS" if result.passed else "FAIL"


def _run(url, *, valid=VALID, attacker=None, configured=True):
    headers = {"Authorization": valid} if configured else {}
    transport = StreamableHTTPTransport(url, headers=headers)
    suite = MCPSecurityTests(transport, simulate=False,
                             audience_attacker_headers=attacker)
    with contextlib.redirect_stdout(io.StringIO()):
        suite.test_mcp_022_bearer_audience_binding()
    result = suite.results[-1]
    assert result.test_id == "MCP-022"
    return _verdict(result), (result.response_received or {}).get("outcomes"), result.details


def _run_stub(policy, **kw):
    with _stub(policy) as (url, seen):
        verdict, outcomes, details = _run(url, **kw)
    return verdict, outcomes, details, seen


ATTACK = {"Authorization": OTHER}


# -- positive control: a holding server must PASS ------------------------------

@pytest.mark.parametrize("status", [401, 403])
def test_holding_server_passes(status):
    verdict, outcomes, details, _ = _run_stub(
        _policy(none=status, other=status), attacker=ATTACK)
    assert outcomes == {"no_header": "rejected", "other_audience": "rejected",
                        "valid": "served"}, details
    assert verdict == "PASS", details


# -- negative control: an audience-blind server must FAIL ----------------------

def test_audience_blind_server_fails():
    verdict, outcomes, details, seen = _run_stub(
        _policy(none=401, other=200), attacker=ATTACK)
    assert outcomes == {"no_header": "rejected", "other_audience": "served",
                        "valid": "served"}, details
    assert verdict == "FAIL", details
    assert "AUDIENCE NOT ENFORCED" in details
    assert OTHER in seen, "the other-resource token must actually reach the server"


def test_audience_blind_with_readable_jwts_fails_and_reports_the_check():
    verdict, _, details, _ = _run_stub(
        _policy(none=401, other=200, valid_value=VALID_JWT),
        valid=VALID_JWT, attacker={"Authorization": OTHER_JWT})
    assert verdict == "FAIL", details
    assert "same issuer" in details


# -- the conservative states ---------------------------------------------------

def test_refuses_everything_is_inconclusive():
    """Also the advisory's half-applied fix: every request gets 401."""
    verdict, outcomes, details, _ = _run_stub(
        _policy(none=401, other=401, valid=401), attacker=ATTACK)
    assert outcomes["valid"] == "rejected", details
    assert verdict == "INCONCLUSIVE", details


def test_unauthenticated_route_is_inconclusive():
    verdict, _, details, _ = _run_stub(_policy(none=200, other=200), attacker=ATTACK)
    assert verdict == "INCONCLUSIVE", details


@pytest.mark.parametrize("status", [500, 503])
def test_5xx_on_the_audience_leg_is_inconclusive(status):
    verdict, outcomes, details, _ = _run_stub(
        _policy(none=401, other=status), attacker=ATTACK)
    assert outcomes["other_audience"] == "indeterminate", details
    assert verdict == "INCONCLUSIVE", details


def test_closed_port_is_inconclusive():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    verdict, _, details = _run(f"http://127.0.0.1:{port}/mcp", attacker=ATTACK)
    assert verdict == "INCONCLUSIVE", details


# -- ill-posed runs never reach a verdict, and send nothing --------------------

@pytest.mark.parametrize("kw", [
    {"attacker": None},
    {"attacker": {"X-Api-Key": "other"}},
    {"attacker": {"Authorization": VALID}},
    {"attacker": ATTACK, "configured": False},
    {"valid": VALID_JWT,
     "attacker": {"Authorization": _jwt({"iss": "https://other-issuer.test",
                                         "aud": "https://billing.example.test"})}},
    {"valid": VALID_JWT,
     "attacker": {"Authorization": _jwt({"iss": ISS,
                                         "aud": ["https://mcp.example.test/mcp", "x"]})}},
])
def test_ill_posed_runs_are_inconclusive_without_sending(kw):
    # A server that serves everything would turn any leak through into a verdict.
    verdict, outcomes, details, seen = _run_stub(_policy(none=200, other=200), **kw)
    assert verdict == "INCONCLUSIVE", details
    assert outcomes is None
    assert seen == []


def test_simulate_records_without_a_request():
    suite = MCPSecurityTests(StreamableHTTPTransport("http://127.0.0.1:9/mcp"),
                             simulate=True)
    with contextlib.redirect_stdout(io.StringIO()):
        suite.test_mcp_022_bearer_audience_binding()
    assert suite.results[-1].test_id == "MCP-022"
    assert "[simulate]" in suite.results[-1].details


def test_registered_under_authentication():
    suite = MCPSecurityTests(StreamableHTTPTransport("http://127.0.0.1:9/mcp"))
    names = [fn.__name__ for fn in suite.test_registry(["authentication"])["authentication"]]
    assert "test_mcp_022_bearer_audience_binding" in names


# -- the precondition helper ---------------------------------------------------

def test_jwt_claims_reads_payload_and_rejects_opaque():
    assert _jwt_claims(VALID_JWT)["iss"] == ISS
    assert _jwt_claims("Bearer opaque") is None
    assert _jwt_claims("Bearer a.!!!.c") is None


def test_precondition_never_marks_opaque_tokens_ill_posed():
    assert not _audience_precondition(VALID, OTHER).startswith("ill-posed")
    assert "operator's statement" in _audience_precondition(VALID, OTHER)
