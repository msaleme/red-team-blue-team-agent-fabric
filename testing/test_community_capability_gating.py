"""R5-05/R5-06: an answered socket is not an exercised capability.

The fourth review's repair bound a real HTTP adapter into the community
runner, so a "live" run finally reached a target. The fifth review found the
next layer: `HttpJsonRpcAdapter.answered` accepted any dict carrying
`_status` without `_exception`, and an HTTP 403, 404, 500 or 503 carries
exactly that plus an empty body. A plugin asserting that a synthetic token is
*absent* then passed by finding nothing in an empty error envelope --
`passed: true`, `not_evaluated: false`, "one request answered" (R5-05).

Enabling real outbound requests also brought three obligations the adapter
did not carry (R5-06): a 302 from the operator's endpoint was followed to a
different host and port and the second hop's answer was counted; `resp.read()`
was unbounded and a 2,097,152-character JSON field was accepted whole; and the
pattern deadline was a post-hoc overrun check, so a 250 ms target under a
50 ms budget returned at 251 ms.

The controls this file requires of itself (CLAUDE.md item 9):

    capability            an HTTP JSON-RPC target answering a plugin's step
    precondition          the target answers, but not with an application result
    oracle                PASS / FAIL / INCONCLUSIVE from run_pattern
    positive control      a usable body without the token -> PASS
    negative control      a usable body with the token    -> FAIL
    inconclusive          error envelope, refused redirect, over-cap, deadline

Without the positive control the gate could be satisfied by never passing at
all. Both controls run against real loopback servers in this file.

The fixture plugin is synthetic, assembled at run time under a temporary
directory with a hash-bound MANIFEST.yaml the way the runner trusts any
plugin. The token is assembled from fragments at run time: it is not a
credential and it is never committed.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import textwrap
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from protocol_tests import community_runner as cr  # noqa: E402
from protocol_tests.http_helpers import (  # noqa: E402
    INCONCLUSIVE_PREFIX,
    http_post_json_bounded,
    is_inconclusive,
)

#: Assembled at run time so no token-shaped literal is committed.
TOKEN = "zq7" + "hunter2" + "wq"


# ---------------------------------------------------------------------------
# Loopback servers
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the test output readable
        pass

    def _drain(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)

    def _send(self, code: int, payload: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            # The client stopped reading at its cap; that is the point.
            pass


def _handler_for(behaviour: dict):
    """Build a request handler from a small behaviour description."""

    class H(_Handler):
        def do_POST(self):
            self._drain()
            self.server.calls.append(f"POST {self.path}:{self.server.server_port}")
            kind = behaviour["kind"]
            if kind == "status":
                self._send(behaviour["code"],
                           json.dumps({"error": "synthetic backend unavailable"}).encode())
            elif kind == "redirect":
                self.send_response(302)
                self.send_header("Location", behaviour["location"])
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif kind == "big":
                self._send(200, json.dumps(
                    {"jsonrpc": "2.0", "id": 1,
                     "result": {"filler": "A" * behaviour["chars"]}}).encode())
            elif kind == "slow":
                time.sleep(behaviour["delay_s"])
                self._send(200, json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "result": {"text": "slow"}}).encode())
            elif kind == "empty":
                self._send(200, json.dumps({}).encode())
            else:  # "usable"
                text = f"tool output: {TOKEN}" if behaviour["token"] else "tool output: none"
                self._send(200, json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "result": {"text": text}}).encode())

        def do_GET(self):
            self.server.calls.append(f"GET {self.path}:{self.server.server_port}")
            self._send(200, json.dumps(
                {"jsonrpc": "2.0", "id": 1, "result": {"text": "second hop"}}).encode())

    return H


class _Server:
    """A loopback HTTP server that records every URL path it served."""

    def __init__(self, behaviour: dict):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(behaviour))
        self.httpd.calls = []  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.httpd.server_port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/rpc"

    @property
    def calls(self) -> list[str]:
        return self.httpd.calls  # type: ignore[attr-defined]

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


# ---------------------------------------------------------------------------
# Synthetic hash-bound plugin
# ---------------------------------------------------------------------------

PLUGIN_YAML = textwrap.dedent(f"""\
    id: CP-9905
    version: "1.0.0"
    name: Synthetic absence probe (capability gating fixture)
    description: Sends one JSON-RPC request and asserts a synthetic token is absent.
    framework: generic
    severity: high
    owasp_category: OWASP-AGENT-01
    attack_steps:
      - action: send_jsonrpc
        target: http://ignored.invalid/rpc
        payload:
          method: tools/list
          params: {{}}
    assertions:
      - type: response_must_not_contain
        field: response
        value: "{TOKEN}"
        description: synthetic token must be absent
    evidence_schema:
      response_received: object
    """)


def _write_fixture(root: Path) -> tuple[str, str]:
    """A hash-bound, verified-tier plugin under *root*; returns (dir, file)."""
    cdir = root / "community_modules"
    (cdir / "contrib").mkdir(parents=True)
    pfile = cdir / "contrib" / "synthetic_absence.yaml"
    pfile.write_text(PLUGIN_YAML, encoding="utf-8")
    digest = hashlib.sha256(pfile.read_bytes()).hexdigest()
    (cdir / cr.MANIFEST_FILE).write_text(textwrap.dedent(f"""\
        spec_version: '1.0'
        patterns:
        - file: contrib/synthetic_absence.yaml
          id: CP-9905
          sha256: {digest}
          trust: verified
          reviewed_by: test-fixture
          reviewed_at: '2026-09-09'
        """), encoding="utf-8")
    return str(cdir), str(pfile)


def _pattern(**over) -> cr.AttackPattern:
    base = dict(
        id="CP-9905", version="1.0.0", name="synthetic absence probe", description="",
        framework="generic", severity="high", owasp_category="OWASP-AGENT-01",
        attack_steps=[{"action": "send_jsonrpc", "target": "server",
                       "payload": {"method": "tools/list", "params": {}}}],
        assertions=[{"type": "response_must_not_contain", "field": "response",
                     "value": TOKEN, "description": "token absent"}],
        evidence_schema={"response_received": "object"},
    )
    base.update(over)
    return cr.AttackPattern(**base)


def _run_through_the_manifest(url: str) -> dict:
    """Run the fixture the way the CLI does: discovery, manifest, execution."""
    with TemporaryDirectory() as tmp:
        cdir, pfile = _write_fixture(Path(tmp))
        with mock.patch("sys.stdout"):
            summary = cr.run_community_tests(
                community_dir=cdir, pattern_file=pfile, target_url=url)
    return summary


# ---------------------------------------------------------------------------
# R5-05: an error envelope must not satisfy an absence assertion
# ---------------------------------------------------------------------------

class TestErrorEnvelopesAreInconclusive(unittest.TestCase):
    """403, 404, 500, 503: the socket answered, the application did not."""

    def _run(self, code: int) -> cr.PatternResult:
        srv = _Server({"kind": "status", "code": code})
        try:
            return cr.run_pattern(_pattern(), target_url=srv.url)
        finally:
            srv.close()

    def test_each_error_status_is_inconclusive_never_a_pass(self):
        for code in (403, 404, 500, 503):
            with self.subTest(status=code):
                r = self._run(code)
                self.assertFalse(r.passed, r.details)
                self.assertTrue(r.not_evaluated, r.details)
                self.assertTrue(is_inconclusive(r))
                self.assertEqual(r.assertions_inconclusive, 1)
                self.assertEqual((r.requests_sent, r.requests_answered), (1, 1),
                                 "the transport did answer; that is the point")
                self.assertEqual(r.requests_with_result, 0)

    def test_the_detail_names_what_was_missing(self):
        r = self._run(500)
        self.assertIn(cr.NO_APP_RESULT, r.details)
        self.assertIn("HTTP 500", r.details)
        self.assertIn("error envelope", r.details)
        self.assertIn("response_must_not_contain", r.details)

    def test_the_serialized_row_separates_answered_from_result(self):
        row = self._run(503).to_dict()
        self.assertEqual(row["requests_answered"], 1)
        self.assertEqual(row["requests_with_result"], 0)
        self.assertTrue(row["not_evaluated"])
        self.assertFalse(row["passed"])

    def test_the_manifest_bound_plugin_reaches_the_same_verdict(self):
        srv = _Server({"kind": "status", "code": 500})
        try:
            summary = _run_through_the_manifest(srv.url)
        finally:
            srv.close()
        self.assertEqual((summary["passed"], summary["failed"], summary["inconclusive"]),
                         (0, 0, 1), summary["results"][0]["details"])

    def test_a_200_with_an_empty_body_is_also_inconclusive(self):
        srv = _Server({"kind": "empty"})
        try:
            r = cr.run_pattern(_pattern(), target_url=srv.url)
        finally:
            srv.close()
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated, r.details)
        self.assertIn("no application result body", r.details)


class TestUsableBodyControls(unittest.TestCase):
    """The two controls without which the gate above proves nothing."""

    def _run(self, token: bool) -> cr.PatternResult:
        srv = _Server({"kind": "usable", "token": token})
        try:
            return cr.run_pattern(_pattern(), target_url=srv.url)
        finally:
            srv.close()

    def test_negative_control_a_body_containing_the_token_fails(self):
        r = self._run(token=True)
        self.assertFalse(r.passed)
        self.assertFalse(r.not_evaluated, r.details)
        self.assertFalse(is_inconclusive(r))
        self.assertEqual(r.requests_with_result, 1)
        self.assertIn("Found forbidden value", r.details)

    def test_positive_control_a_body_without_the_token_passes(self):
        r = self._run(token=False)
        self.assertTrue(r.passed, r.details)
        self.assertFalse(r.not_evaluated)
        self.assertEqual(r.requests_with_result, 1)


class TestAnswerAssertionsKeepANon2xx(unittest.TestCase):
    """A refusal by status can carry protocol meaning; it is not collapsed."""

    def test_status_code_equals_is_evaluated_on_a_402(self):
        srv = _Server({"kind": "status", "code": 402})
        try:
            r = cr.run_pattern(
                _pattern(assertions=[{"type": "status_code_equals", "value": 402,
                                      "description": "payment required"}]),
                target_url=srv.url)
        finally:
            srv.close()
        self.assertTrue(r.passed, r.details)
        self.assertFalse(r.not_evaluated, r.details)
        self.assertEqual(r.requests_with_result, 0,
                         "a 402 body is not an application result, and does not need to be")

    def test_error_returned_is_evaluated_on_a_500(self):
        srv = _Server({"kind": "status", "code": 500})
        try:
            r = cr.run_pattern(
                _pattern(assertions=[{"type": "error_returned",
                                      "description": "an error is expected"}]),
                target_url=srv.url)
        finally:
            srv.close()
        self.assertTrue(r.passed, r.details)
        self.assertFalse(r.not_evaluated, r.details)

    def test_a_content_assertion_alongside_it_is_still_inconclusive(self):
        srv = _Server({"kind": "status", "code": 402})
        try:
            r = cr.run_pattern(
                _pattern(assertions=[
                    {"type": "status_code_equals", "value": 402, "description": "402"},
                    {"type": "response_must_not_contain", "field": "response",
                     "value": TOKEN, "description": "token absent"},
                ]),
                target_url=srv.url)
        finally:
            srv.close()
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated)
        self.assertEqual(r.assertions_passed, 1)
        self.assertEqual(r.assertions_inconclusive, 1)

    def test_status_code_equals_with_no_status_anywhere_is_inconclusive(self):
        evaluator = cr.AssertionEvaluator({}, [{"status": "simulated", "live": False}])
        passed, detail = evaluator.evaluate({"type": "status_code_equals", "value": 200})
        self.assertFalse(passed)
        self.assertTrue(is_inconclusive(detail), detail)


class TestTheSurfaceMapCoversEveryAssertion(unittest.TestCase):

    def test_every_assertion_type_is_classified(self):
        self.assertEqual(set(cr.ASSERTION_SURFACE), set(cr.VALID_ASSERTION_TYPES),
                         "a new assertion type must declare the surface it needs")

    def test_only_answer_shaped_assertions_are_exempt(self):
        exempt = {k for k, v in cr.ASSERTION_SURFACE.items() if v == cr.SURFACE_ANSWER}
        self.assertEqual(exempt, {"status_code_equals", "error_returned"})


# ---------------------------------------------------------------------------
# R5-06: origin, size and deadline
# ---------------------------------------------------------------------------

class TestRedirectsAreRefusedAndTheOriginIsPinned(unittest.TestCase):

    def test_a_302_is_not_followed_and_the_second_hop_is_never_fetched(self):
        hop2 = _Server({"kind": "usable", "token": False})
        hop1 = _Server({"kind": "redirect",
                        "location": f"http://127.0.0.1:{hop2.port}/second-hop"})
        try:
            r = cr.run_pattern(_pattern(), target_url=hop1.url)
            second_hop_calls = list(hop2.calls)
        finally:
            hop1.close()
            hop2.close()
        self.assertEqual(second_hop_calls, [],
                         f"the redirect target was fetched: {second_hop_calls}")
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated, r.details)
        self.assertIn(cr.REDIRECT_REFUSED, r.details)
        self.assertEqual(r.requests_with_result, 0)

    def test_the_transport_reports_the_refusal_and_the_location(self):
        hop2 = _Server({"kind": "usable", "token": False})
        hop1 = _Server({"kind": "redirect",
                        "location": f"http://127.0.0.1:{hop2.port}/second-hop"})
        try:
            resp = http_post_json_bounded(hop1.url, {"jsonrpc": "2.0", "id": 1})
        finally:
            hop1.close()
            hop2.close()
        self.assertEqual(resp["_status"], 302)
        self.assertTrue(resp["_redirect_refused"])
        self.assertIn(str(hop2.port), resp["_redirect_location"])

    def test_the_policy_constant_says_redirects_are_off(self):
        self.assertFalse(cr.FOLLOW_REDIRECTS)

    def test_an_answer_from_another_origin_is_not_a_usable_result(self):
        # The origin pin is the second half of the policy: even if a redirect
        # were followed, an answer from elsewhere is not the target's answer.
        usable, why = cr.HttpJsonRpcAdapter.usable_result({
            "_status": 200, "_error": True, "_origin_mismatch": True,
            "_final_origin": "http://127.0.0.1:2", "_expected_origin": "http://127.0.0.1:1",
            "response": {"result": {"text": "elsewhere"}},
        })
        self.assertFalse(usable)
        self.assertIn(cr.ORIGIN_MISMATCH, why)


class TestResponseSizeIsCapped(unittest.TestCase):

    def test_an_over_cap_body_is_inconclusive_not_a_crash_and_not_a_pass(self):
        srv = _Server({"kind": "big", "chars": cr.MAX_RESPONSE_BYTES * 2})
        try:
            r = cr.run_pattern(_pattern(), target_url=srv.url)
        finally:
            srv.close()
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated, r.details)
        self.assertIn(cr.RESPONSE_CAP_EXCEEDED, r.details)
        self.assertEqual(r.requests_with_result, 0)

    def test_the_body_is_capped_before_json_decoding(self):
        srv = _Server({"kind": "big", "chars": cr.MAX_RESPONSE_BYTES * 2})
        try:
            resp = cr.HttpJsonRpcAdapter(srv.url).send_jsonrpc({"jsonrpc": "2.0", "id": 1})
        finally:
            srv.close()
        self.assertTrue(resp["_truncated"])
        self.assertEqual(resp["_max_bytes"], cr.MAX_RESPONSE_BYTES)
        self.assertLessEqual(resp["_bytes_read"], cr.MAX_RESPONSE_BYTES + 1)
        self.assertEqual(resp["response"], {},
                         "nothing over the cap may reach a JSON decoder")

    def test_a_body_under_the_cap_is_still_read_whole(self):
        srv = _Server({"kind": "usable", "token": True})
        try:
            resp = cr.HttpJsonRpcAdapter(srv.url).send_jsonrpc({"jsonrpc": "2.0", "id": 1})
        finally:
            srv.close()
        self.assertNotIn("_truncated", resp)
        self.assertIn(TOKEN, resp["response"]["result"]["text"])

    def test_the_cap_is_documented_and_one_mib(self):
        self.assertEqual(cr.MAX_RESPONSE_BYTES, 1024 * 1024)


class TestTheDeadlineCancelsRatherThanReports(unittest.TestCase):

    def test_a_slow_target_is_cut_off_at_the_budget(self):
        srv = _Server({"kind": "slow", "delay_s": 0.25})
        start = time.monotonic()
        try:
            with mock.patch.object(cr, "MAX_PATTERN_EXECUTION_TIMEOUT_S", 0.05):
                r = cr.run_pattern(_pattern(), target_url=srv.url)
        finally:
            elapsed = time.monotonic() - start
            srv.close()
        self.assertLess(elapsed, 0.20,
                        f"the runner outlived its 50 ms budget by returning at "
                        f"{elapsed:.3f}s; the deadline was reported, not enforced")
        self.assertFalse(r.passed)
        self.assertTrue(r.not_evaluated, r.details)
        self.assertTrue(is_inconclusive(r))

    def test_the_adapter_refuses_to_send_once_the_deadline_has_passed(self):
        adapter = cr.HttpJsonRpcAdapter("http://127.0.0.1:9/rpc")
        adapter.set_deadline(time.monotonic() - 1.0)
        resp = adapter.send_jsonrpc({"jsonrpc": "2.0", "id": 1})
        self.assertTrue(resp["_not_sent"])
        self.assertEqual(resp["_exception"], cr.DEADLINE_PASSED)

    def test_a_request_that_was_never_sent_is_not_counted_as_sent(self):
        pat = _pattern()
        executor = cr.StepExecutor(pat, target_url="http://127.0.0.1:9/rpc",
                                   adapter=cr.HttpJsonRpcAdapter("http://127.0.0.1:9/rpc"),
                                   deadline=time.monotonic() - 1.0)
        executor.execute_step(pat.attack_steps[0])
        self.assertEqual((executor.requests_sent, executor.requests_answered), (0, 0))

    def test_a_fast_target_inside_the_budget_still_reaches_a_verdict(self):
        srv = _Server({"kind": "usable", "token": False})
        try:
            with mock.patch.object(cr, "MAX_PATTERN_EXECUTION_TIMEOUT_S", 5.0):
                r = cr.run_pattern(_pattern(), target_url=srv.url)
        finally:
            srv.close()
        self.assertTrue(r.passed, r.details)


class TestSharedTransportIsUnchangedForOtherCallers(unittest.TestCase):
    """The bounds live in a new function; http_post_json keeps its behaviour."""

    def test_the_bounded_post_is_a_separate_entry_point(self):
        from protocol_tests import http_helpers
        self.assertTrue(callable(http_helpers.http_post_json))
        self.assertTrue(callable(http_helpers.http_post_json_bounded))
        self.assertIsNot(http_helpers.http_post_json, http_helpers.http_post_json_bounded)

    def test_the_community_adapter_uses_the_bounded_one(self):
        import inspect
        src = inspect.getsource(cr.HttpJsonRpcAdapter.send_jsonrpc)
        self.assertIn("http_post_json_bounded", src)
        self.assertNotIn("http_post_json(", src)


if __name__ == "__main__":
    unittest.main()
