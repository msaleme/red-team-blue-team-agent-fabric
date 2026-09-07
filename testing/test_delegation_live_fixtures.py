"""Live-mode verdicts against real HTTP targets, pinned response and verdict.

The existing live tests hit a closed port, and against a closed port every row
is correctly INCONCLUSIVE. That is why two defects survived them:

1. `_probe_live` searched `resp.get("_body")` for the text `"allowed": true`.
   The transport returns the PARSED body; `_body` exists only on HTTP errors.
   A target answering exactly `{"allowed": true}` was undecided. Every live
   row was INCONCLUSIVE against every target -- and a parser that treats
   everything as inconclusive passes a closed-port test.

2. DCA-005 sent ONE live request (the legitimate chain) through the generic
   reject path. Once allows were recognized, a target that correctly allowed
   that legitimate request was graded "LIVE TARGET ALLOWED — control absent".

Both found by an external review (2026-09-07) running an allow-all fixture.
These tests are that fixture, plus the ones that pin each branch of the
replay verdict, with the received response and the verdict asserted together.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_tests.delegation_chain_harness import DelegationChainTests
from protocol_tests.http_helpers import is_inconclusive

ALL_IDS = {f"DCA-{n:03d}" for n in range(1, 12)}
ACCEPT_ROWS = {"DCA-009", "DCA-010"}          # live_expect="accept"
REPLAY_ROW = "DCA-005"                        # its own live hook
REJECT_ROWS = ALL_IDS - ACCEPT_ROWS - {REPLAY_ROW}


class _Fixture:
    """A tiny HTTP target whose policy is a function of the parsed payload."""

    def __init__(self, policy):
        self.policy = policy
        self.requests: list[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(n) or b"{}")
                outer.requests.append(payload)
                body = json.dumps(outer.policy(payload, outer)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):  # quiet
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}/authorize"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# --- policies ---------------------------------------------------------------

def allow_all_fresh_receipt(payload, fx):
    return {"allowed": True, "receipt": uuid.uuid4().hex}


def allow_all_idempotent(payload, fx):
    rid = payload["request"]["request_id"]
    return {"allowed": True, "receipt": hashlib.sha256(rid.encode()).hexdigest()[:16]}


def allow_first_refuse_repeat(payload, fx):
    rid = payload["request"]["request_id"]
    seen = [r for r in fx.requests[:-1] if r["request"]["request_id"] == rid]
    if seen:
        return {"allowed": False, "reason": "replay refused"}
    return {"allowed": True, "receipt": uuid.uuid4().hex}


def deny_all(payload, fx):
    return {"allowed": False, "reason": "policy"}


def capability_attenuation_only(payload, fx):
    """Allow iff every hop's capabilities ⊆ its parent's, and the request's
    capability is held by the last hop. Checks capabilities ONLY -- resources,
    audiences, expiry and epoch are not examined, so rows attacking those
    dimensions are correctly ALLOWED by this fixture and graded FAIL. This is a
    fixture that allows the legitimate chain, not a verifier."""
    chain = payload["delegation_chain"]
    caps = [set(p["authority"]["capabilities"]) for p in chain]
    for parent, child in zip(caps, caps[1:]):
        if not child <= parent:
            return {"allowed": False, "reason": "escalation"}
    if caps and payload["request"]["capability"] not in caps[-1]:
        return {"allowed": False, "reason": "capability not held"}
    return {"allowed": True, "receipt": uuid.uuid4().hex}


def _run(fx: _Fixture):
    suite = DelegationChainTests(url=fx.url)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        suite.run_all()
    return {r.test_id: r for r in suite.results}


class AllowsAreRecognized(unittest.TestCase):
    """Fixture A. Pins defect 1: an HTTP-200 `{"allowed": true}` IS an allow."""

    @classmethod
    def setUpClass(cls):
        cls.fx = _Fixture(allow_all_fresh_receipt)
        cls.rows = _run(cls.fx)

    @classmethod
    def tearDownClass(cls):
        cls.fx.close()

    def test_the_fixture_was_actually_contacted(self):
        self.assertGreaterEqual(len(self.fx.requests), len(ALL_IDS))
        self.assertEqual({r.test_id for r in self.rows.values()}, ALL_IDS)

    def test_every_reject_row_is_a_finding_not_inconclusive(self):
        for tid in sorted(REJECT_ROWS):
            with self.subTest(tid):
                r = self.rows[tid]
                self.assertFalse(is_inconclusive(r), r.details)
                self.assertFalse(r.passed, r.details)
                self.assertIn("LIVE TARGET ALLOWED", r.details)
                self.assertIs(r.response_received.get("allowed"), True)

    def test_accept_rows_pass(self):
        for tid in sorted(ACCEPT_ROWS):
            with self.subTest(tid):
                r = self.rows[tid]
                self.assertTrue(r.passed, r.details)
                self.assertFalse(is_inconclusive(r), r.details)

    def test_replay_with_fresh_receipts_is_inconclusive_not_a_finding(self):
        """Pins defect 2: the first allow is the precondition, never the finding,
        and two allows with different receipts do not establish two effects."""
        r = self.rows[REPLAY_ROW]
        self.assertTrue(is_inconclusive(r), r.details)
        # This must be the replay hook's OWN inconclusive, not the serviced
        # guard's: the target answered 200 twice. Without this line the test
        # passed while the guard was rewriting a served response as unserviced.
        self.assertEqual(r.response_received["_status"], 200)
        self.assertNotIn("did not service", r.details)
        self.assertNotIn("control absent", r.details)
        self.assertIn("cannot be established", r.details)
        self.assertEqual(r.request_sent["sent_times"], 2)
        self.assertEqual(len([q for q in self.fx.requests
                              if q["request"]["request_id"] == "req-replay"]), 2)


class ReplayBranches(unittest.TestCase):
    def _replay_row(self, policy):
        fx = _Fixture(policy)
        try:
            return _run(fx)[REPLAY_ROW], fx
        finally:
            fx.close()

    def test_idempotent_receipt_is_a_pass(self):
        r, fx = self._replay_row(allow_all_idempotent)
        self.assertTrue(r.passed, r.details)
        self.assertIn("IDEMPOTENT", r.details)
        self.assertEqual(r.response_received["first"]["receipt"],
                         r.response_received["second"]["receipt"])

    def test_refused_second_presentation_is_a_pass(self):
        r, fx = self._replay_row(allow_first_refuse_repeat)
        self.assertTrue(r.passed, r.details)
        self.assertIn("REFUSED", r.details)
        self.assertIs(r.response_received["second"]["allowed"], False)

    def test_target_that_denies_the_legit_request_is_inconclusive(self):
        r, fx = self._replay_row(deny_all)
        self.assertTrue(is_inconclusive(r), r.details)
        self.assertIn("nothing to replay", r.details)


class DenyIsNotAPass(unittest.TestCase):
    """A real HTTP 200 `{"allowed": false}` is undecided -- refusing the authority
    claim and failing to parse the payload look the same on this wire."""

    def test_every_row_is_inconclusive_against_deny_all(self):
        fx = _Fixture(deny_all)
        try:
            rows = _run(fx)
        finally:
            fx.close()
        for tid in sorted(ALL_IDS):
            with self.subTest(tid):
                self.assertTrue(is_inconclusive(rows[tid]), rows[tid].details)
                self.assertFalse(rows[tid].passed)


class LegitimateChainAllowed(unittest.TestCase):
    """Fixture E: a target that enforces capability attenuation and nothing else."""

    def test_capability_rows_pass_and_the_legit_chain_is_allowed(self):
        fx = _Fixture(capability_attenuation_only)
        try:
            rows = _run(fx)
        finally:
            fx.close()
        # DCA-001 attacks capabilities: the fixture refuses it, so the row is
        # undecided on this wire (a refusal is not a pass) -- but it must NOT
        # be a finding.
        self.assertNotIn("LIVE TARGET ALLOWED", rows["DCA-001"].details)
        self.assertIs(rows["DCA-001"].response_received.get("allowed"), False)
        # The legitimate chain is allowed: accept rows pass.
        for tid in sorted(ACCEPT_ROWS):
            with self.subTest(tid):
                self.assertTrue(rows[tid].passed, rows[tid].details)
        # A row attacking a dimension this fixture ignores is a real finding.
        self.assertIn("LIVE TARGET ALLOWED", rows["DCA-002"].details)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Second external review, 2026-09-07: a False decision is not a refusal.
# ---------------------------------------------------------------------------

def _second_response_policy(second_body):
    def policy(payload, fx):
        rid = payload["request"]["request_id"]
        seen = [r for r in fx.requests[:-1] if r["request"]["request_id"] == rid]
        return second_body if seen else {"allowed": True, "receipt": "r-first"}
    return policy


class AFalseDecisionIsNotARefusal(unittest.TestCase):
    """The old grader read every non-True as refused. These second responses
    establish nothing about replay and must be INCONCLUSIVE, never PASS."""

    def _replay(self, second_body):
        fx = _Fixture(_second_response_policy(second_body))
        try:
            return _run(fx)[REPLAY_ROW]
        finally:
            fx.close()

    def test_empty_body_is_undecided(self):
        r = self._replay({})
        self.assertTrue(is_inconclusive(r), r.details); self.assertFalse(r.passed)

    def test_string_true_is_undecided(self):
        r = self._replay({"allowed": "true"})
        self.assertTrue(is_inconclusive(r), r.details); self.assertFalse(r.passed)

    def test_jsonrpc_error_is_undecided(self):
        r = self._replay({"error": {"code": -32601, "message": "method not found"}})
        self.assertTrue(is_inconclusive(r), r.details); self.assertFalse(r.passed)

    def test_explicit_false_is_a_refusal(self):
        r = self._replay({"allowed": False, "reason": "replay"})
        self.assertTrue(r.passed, r.details); self.assertIn("explicitly denied", r.details)

    def test_matching_empty_receipts_are_not_idempotence(self):
        fx = _Fixture(lambda p, f: {"allowed": True, "receipt": ""})
        try:
            r = _run(fx)[REPLAY_ROW]
        finally:
            fx.close()
        self.assertTrue(is_inconclusive(r), r.details); self.assertFalse(r.passed)

    def test_matching_non_string_receipts_are_not_idempotence(self):
        fx = _Fixture(lambda p, f: {"allowed": True, "receipt": {"id": 1}})
        try:
            r = _run(fx)[REPLAY_ROW]
        finally:
            fx.close()
        self.assertTrue(is_inconclusive(r), r.details); self.assertFalse(r.passed)
