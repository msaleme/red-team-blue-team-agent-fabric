"""MCP-021 over a real HTTP socket: a 401/403 is a rejection whatever its body.

## Why this file exists

External calibration feedback (2026-09-23) reported that MCP-021 graded a
server INCONCLUSIVE when it refused invalid credentials with a plain HTTP 401
or 403 whose body was not an MCP JSON-RPC result or error. The requested fix
was to widen what counts as an observed rejection, not to weaken the
uncertainty policy.

Checked against the source, the classifier already does this.
`_auth_outcome` returns ``rejected`` for ``_status in (401, 403)`` before it
looks at the body, and `StreamableHTTPTransport.send` records ``_status`` on
every non-2xx response (the `HTTPError` branch), including one with an empty,
HTML, plain-text or non-RPC JSON body. `tests/test_mcp021_auth_fail_open.py`
could not show this because its fake transport hands the verdict pre-shaped
dicts: the wire-to-dict step was never exercised. This file drives the real
transport against stdlib stub servers so that step is pinned.

## What this pins

1. header-less and garbage legs -> 401, valid credential -> tools/list: PASS
2. the same with 403: PASS
3. header-less -> 401, garbage bearer served: FAIL
4. every invalid leg -> 500: INCONCLUSIVE (5xx stays indeterminate)
5. the configured credential -> 401: INCONCLUSIVE (control not exercised)
6. closed port: INCONCLUSIVE

and, for 1-3, the per-leg outcome matrix, so an auth-denial leg is asserted
``rejected`` rather than merely ending in the right verdict.

## What this does not establish

Anything about a real product. Which wire shape a given gateway uses to deny
(status code, redirect, an in-band JSON-RPC error on a 200, an SSE stream) is
a property of that gateway; only a 401 or 403 is treated as a definitive
denial here. A 2xx carrying a JSON-RPC ``error``, a 3xx, and any 5xx remain
indeterminate by design.
"""

from __future__ import annotations

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
)

VALID = "Bearer mcp021-configured-credential"


class _Handler(BaseHTTPRequestHandler):
    """Answers a tools/list POST according to the server's ``policy``.

    ``policy(auth) -> (status, body_bytes, content_type)`` where ``auth`` is the
    Authorization header as received, or None when the request carried none.
    """

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length) or b"{}")
        status, body, ctype = self.server.policy(  # type: ignore[attr-defined]
            self.headers.get("Authorization"), request)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _tools_list(request):
    body = {"jsonrpc": "2.0", "id": request.get("id"), "result": {"tools": []}}
    return 200, json.dumps(body).encode(), "application/json"


def _policy(*, none, garbage, valid=None, body=b"Unauthorized", ctype="text/plain"):
    """Build a policy from one HTTP status per leg class; 200 means serve tools/list."""

    def policy(auth, request):
        if auth == VALID:
            status = 200 if valid is None else valid
        elif auth is None:
            status = none
        else:
            status = garbage
        if status == 200:
            return _tools_list(request)
        return status, body, ctype

    return policy


@contextlib.contextmanager
def _stub(policy):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.policy = policy  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/mcp"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _closed_port_url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}/mcp"


def _run(url):
    transport = StreamableHTTPTransport(url, headers={"Authorization": VALID})
    suite = MCPSecurityTests(transport, simulate=False)
    with contextlib.redirect_stdout(io.StringIO()):
        suite.test_mcp_021_auth_fail_open()
    result = suite.results[-1]
    assert result.test_id == "MCP-021"
    if is_inconclusive(result):
        verdict = "INCONCLUSIVE"
    else:
        verdict = "PASS" if result.passed else "FAIL"
    return verdict, (result.response_received or {}).get("outcomes"), result.details


def _run_stub(policy):
    with _stub(policy) as url:
        return _run(url)


ALL_DENIED = {"no_header": "rejected", "garbage_bearer": "rejected",
              "garbage_jwt": "rejected", "valid": "served"}


# -- 1 and 2: a plain HTTP denial is a rejected leg, whatever the body ---------

@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("body,ctype", [
    (b"Unauthorized", "text/plain"),
    (b"", "text/plain"),
    (b"<html><body>Forbidden</body></html>", "text/html"),
    (b'{"detail": "Not authenticated"}', "application/json"),
    (b"not json at all", "application/json"),
])
def test_http_auth_denial_is_rejected_and_enforcement_passes(status, body, ctype):
    verdict, outcomes, details = _run_stub(
        _policy(none=status, garbage=status, body=body, ctype=ctype))
    assert outcomes == ALL_DENIED, details
    assert verdict == "PASS", details


# -- 3: the fail-open differential is visible against an HTTP 401 --------------

def test_header_less_401_but_garbage_served_fails():
    verdict, outcomes, details = _run_stub(_policy(none=401, garbage=200))
    assert outcomes == {"no_header": "rejected", "garbage_bearer": "served",
                        "garbage_jwt": "served", "valid": "served"}, details
    assert verdict == "FAIL", details
    assert "AUTH FAILS OPEN" in details


def test_header_less_403_but_garbage_served_fails():
    verdict, outcomes, details = _run_stub(_policy(none=403, garbage=200))
    assert outcomes["no_header"] == "rejected", details
    assert verdict == "FAIL", details


# -- 4-6: the conservative states are unchanged --------------------------------

@pytest.mark.parametrize("status", [500, 502, 503])
def test_5xx_on_the_invalid_legs_stays_inconclusive(status):
    verdict, outcomes, details = _run_stub(_policy(none=status, garbage=status))
    assert {outcomes[k] for k in ("no_header", "garbage_bearer", "garbage_jwt")} \
        == {"indeterminate"}, details
    assert verdict == "INCONCLUSIVE", details


def test_valid_credential_refused_with_401_is_inconclusive():
    """A 401 on the control leg is a rejection too, which is exactly why it cannot pass."""
    verdict, outcomes, details = _run_stub(_policy(none=401, garbage=401, valid=401))
    assert outcomes["valid"] == "rejected", details
    assert verdict == "INCONCLUSIVE", details
    assert "configured credential was rejected" in details


def test_closed_port_is_inconclusive():
    verdict, outcomes, details = _run(_closed_port_url())
    assert set(outcomes.values()) == {"indeterminate"}, details
    assert verdict == "INCONCLUSIVE", details


def test_a_2xx_that_is_neither_result_nor_denial_stays_indeterminate():
    """Widening covers 401/403 only: a 200 with an unreadable body proves nothing."""
    def policy(auth, request):
        if auth == VALID:
            return _tools_list(request)
        return 200, b"<html>login</html>", "text/html"

    verdict, outcomes, details = _run_stub(policy)
    assert outcomes["no_header"] == "indeterminate", details
    assert verdict == "INCONCLUSIVE", details
