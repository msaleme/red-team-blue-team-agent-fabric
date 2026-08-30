"""A missing response is three different findings, and the transport knows which.

Two verdicts in mcp_harness read a missing response and asserted a cause:

    MCP-018  "No response after 5.6s -- server may have crashed or hung"
    MCP-008  "0/7 malformed messages handled gracefully"

Both were written before this harness had ever been run over stdio. The first
calibration of that transport, against the official
`@modelcontextprotocol/server-everything` on 2026-08-30, showed the two cases
are genuinely different and that the harness owns the evidence to tell them
apart:

    after seven malformed messages   process alive, still answering tools/list
    after a 10 MB body               process alive, answering nothing

Same missing response. One server survived an attack; the other was denied
service. "crashed or hung" describes neither, and "0/7 handled gracefully"
describes a server that survived all seven and kept serving.

## Why the transport and not the test

Only a transport that owns the server process can answer "is it still running".
StdioTransport launches it, so `proc.poll()` is the answer. StreamableHTTPTransport
has nothing to inspect, so `MCPTransport.is_alive` returns None and both verdicts
say so rather than picking a cause. Admitting the limit is the point: over HTTP
this reads "this transport cannot inspect the server process, so whether it
survived them is not established here."

## What did not change

A pass still requires an explicit rejection for every message, which is what the
spec asks for. Only the wording of a non-pass moved, from an asserted cause to
an observed one.
"""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.mcp_harness import MCPSecurityTests, MCPTransport


class _Silent(MCPTransport):
    """Answers nothing, and reports a liveness the test chooses."""

    def __init__(self, alive):
        self._alive = alive

    def is_alive(self):
        return self._alive

    def send(self, message, **kwargs):
        return None

    def send_raw(self, raw, mcp_method=None, **kwargs):
        return None


def _run(alive, method):
    suite = MCPSecurityTests(_Silent(alive), json_output=True)
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        getattr(suite, method)()
    return suite.results[0]


class TestTheBaseTransportAdmitsItCannotKnow(unittest.TestCase):
    def test_default_is_none_not_a_guess(self):
        self.assertIsNone(
            MCPTransport().is_alive(),
            "a transport that does not own the server process must return None; "
            "returning True or False there invents the evidence two verdicts rely on")


class TestOversizedBodyReportsWhatWasObserved(unittest.TestCase):
    METHOD = "test_mcp_unbounded_request_body_dos"

    def test_alive_is_a_wedged_session_not_a_crash(self):
        d = _run(True, self.METHOD).details
        self.assertIn("still running", d)
        self.assertIn("wedged", d)
        self.assertNotIn("crashed", d)

    def test_exited_says_the_server_terminated(self):
        d = _run(False, self.METHOD).details
        self.assertIn("exited", d)
        self.assertIn("terminated the server", d)

    def test_unknowable_says_so(self):
        d = _run(None, self.METHOD).details
        self.assertIn("cannot inspect", d)
        self.assertIn("not established", d)

    def test_no_response_is_never_a_pass(self):
        """The #351 rule still holds underneath all three wordings."""
        for alive in (True, False, None):
            with self.subTest(alive=alive):
                self.assertFalse(_run(alive, self.METHOD).passed)


class TestBatchDosRequiresAnObservedResponse(unittest.TestCase):
    """MCP-009 computed a verdict from elapsed time and ignored what came back.

        resp = self.transport.send_raw(batch_json, mcp_method="tools/list")
        passed = elapsed < 10.0
        details = f"Server responded in {elapsed:.1f}s"

    The return was discarded, so a transport answering nothing produced

        passed=True, details="Server responded in 0.0s", response_received=None

    Completing a local send call is not evidence that anything answered.

    This one is worth the extra words because of how it survived. PR #426 read
    every row of the permissive sweep, kept this one deliberately, wrote a
    comment into the source calling it "the one row that is CORRECT and stays",
    and cited it in testing/test_permissive_host_state.py as the taxonomy's
    example of a legitimate pass. The reasoning was that a batch-DoS test asks
    whether the target stayed responsive, and a fast answer is a real property.
    That is true of a fast ANSWER and the test never checked for one.

    It passed the permissive sentinel for a plausible-looking reason, which is
    exactly the case the sweep cannot separate from a real pass on its own. An
    independent review found it by reading the source. Silence is the failure
    mode a DoS test exists to detect, so silence is never a pass here.
    """

    METHOD = "test_mcp_batch_bomb"

    @staticmethod
    def _run(resp, alive=None):
        class _T(MCPTransport):
            def is_alive(self_inner): return alive
            def send(self_inner, m, **k): return None
            def send_raw(self_inner, raw, mcp_method=None, **k): return resp
        suite = MCPSecurityTests(_T(), json_output=True)
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            suite.test_mcp_batch_bomb()
        return suite.results[0]

    def test_positive_control_a_timely_answer_passes(self):
        r = self._run(b'{"jsonrpc":"2.0","id":1,"result":{}}')
        self.assertTrue(r.passed, r.details)
        self.assertIn("answered", r.details)

    def test_negative_control_immediate_silence_is_never_a_pass(self):
        """The regression. This returned PASS with response_received=None."""
        for alive in (True, False, None):
            with self.subTest(alive=alive):
                r = self._run(None, alive)
                self.assertFalse(
                    r.passed,
                    f"silence produced a PASS: {r.details!r}")
                self.assertNotIn("Server responded", r.details)

    def test_an_empty_response_is_not_a_response(self):
        self.assertFalse(self._run(b"").passed)

    def test_ignoring_the_batch_while_still_serving_is_a_pass(self):
        """The branch a blunter repair got wrong.

        The pinned reference server sends no reply to the batch and answers a
        normal request immediately afterwards. The oracle is responsiveness, so
        that is the control holding, and calling it "wedged" -- which a first
        version of this repair did, borrowing MCP-018's wording -- is the same
        overclaim MCP-009 was being repaired for, one branch over.
        """
        class _Serving(MCPTransport):
            def is_alive(self_inner): return True
            def send(self_inner, m, **k): return {"result": {"tools": []}}
            def send_raw(self_inner, raw, mcp_method=None, **k): return None

        suite = MCPSecurityTests(_Serving(), json_output=True)
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            suite.test_mcp_batch_bomb()
        r = suite.results[0]
        self.assertTrue(r.passed, r.details)
        self.assertIn("stayed responsive", r.details)
        self.assertNotIn("wedged", r.details)
        self.assertTrue(r.response_received["still_serving_after"])

    def test_silence_says_which_kind_it_was(self):
        self.assertIn("wedged", self._run(None, True).details)
        self.assertIn("exited", self._run(None, False).details)
        self.assertIn("cannot inspect", self._run(None, None).details)

    def test_the_evidence_records_what_came_back(self):
        """The detail claimed a response; the evidence recorded None.

        A reader could not check the claim against the result. Both directions
        are now recorded, so the row can be audited without rerunning it.
        """
        answered = self._run(b'{"jsonrpc":"2.0","id":1,"result":{}}')
        self.assertTrue(answered.response_received["responded"])
        self.assertGreater(answered.response_received["bytes"], 0)
        silent = self._run(None)
        self.assertFalse(silent.response_received["responded"])
        self.assertEqual(silent.response_received["bytes"], 0)


class TestMalformedHandlingSeparatesIgnoredFromDead(unittest.TestCase):
    METHOD = "test_mcp_malformed_jsonrpc"

    def test_alive_says_it_survived_them(self):
        d = _run(True, self.METHOD).details
        self.assertIn("drew no response", d)
        self.assertIn("still serving", d)

    def test_exited_says_the_process_is_gone(self):
        self.assertIn("has exited", _run(False, self.METHOD).details)

    def test_unknowable_says_so(self):
        self.assertIn("not established", _run(None, self.METHOD).details)

    def test_silence_is_still_not_graceful_handling(self):
        """The verdict did not soften, only the description.

        The spec asks for a parse error. A server that ignores malformed input
        and keeps serving has not done that, and this must keep failing.
        """
        for alive in (True, False, None):
            with self.subTest(alive=alive):
                r = _run(alive, self.METHOD)
                self.assertFalse(r.passed)
                self.assertNotIn("handled gracefully", r.details)


if __name__ == "__main__":
    unittest.main()
