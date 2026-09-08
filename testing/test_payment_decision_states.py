"""A payment probe has four outcomes, and the target's body cannot pick one.

## The defects (R4-02, R4-03; fourth external review, 2026-09-08)

R4-02. `payment_outcome` classified connection refusal, timeout and 5xx as
`unreachable` (INCONCLUSIVE, correct since #537) and a 403 as `rejected`,
but a 2xx with no rejection word as `accepted`. An empty body, non-JSON
prose, or JSON with nothing but a request id all read as the attack getting
through, so the installed AP2 suite against a loopback answering 200 ``{}``
reported 17 FAIL "LIVE verifier ACCEPTED the attack -- control absent", 17
serviced, pass_rate 0.0. Absence of a rejection word is not an acceptance
decision. The fold that stopped false PASS from unreachable targets had an
input classifier that turned absence into a positive fact the other way.

R4-03. `_utils.http_post_json` rebuilt ``_status`` from the real HTTP status
and preserved every other key the server sent, so a body
``{"allowed": true, "_error": true, "_status": 503}`` came back with its
``_error`` intact and `payment_outcome` read an affirmative decision as a
transport failure. Application JSON could downgrade the same answer to
INCONCLUSIVE.

## What this pins

- The four states, as a truth table over transport state x body shape:
  `unreachable` (no status or 5xx), `rejected` (401/402/403; a 4xx that
  states a denial; a rejection term, a decision flag set false or a reject
  state in the body), `accepted` (a RECOGNISED decision: a true flag, an
  accept state, a target-produced effect), `undecided` (answered, no
  decision).
- Over a real loopback socket, for each shape the review named: ``{}``,
  ``{"allowed": true}``, the ``_error`` forgery, 403 ``{"error":"denied"}``,
  and prose with a 200.
- The transport strips every underscore-prefixed key from a server body,
  rebuilds its own, and records what it removed under ``_stripped_keys``.
  ``status`` (an application field) and ``_status`` (the transport's) are
  not conflated in either direction.
- `fold_live_verdict("undecided")` is INCONCLUSIVE with details that say
  the request was serviced and no decision came back; `live_run_scope`
  counts it as observed and not scored.
- Through the CLI, `ap2` against the ``{}`` server: 0 PASS, 0 FAIL,
  N INCONCLUSIVE, serviced 0, no pass rate, and the scope statement says
  the rows observed a live response and none was scored.

## What this does not establish

That the acceptance vocabulary is complete for any real verifier. It is
the set of decision fields the five modules' protocols name; a verifier that
accepts in a word not listed reads as `undecided`, which is the honest
default (INCONCLUSIVE, with the answer under live_evidence), not a PASS.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests._utils import (  # noqa: E402
    RESERVED_TRANSPORT_KEYS,
    _strip_reserved,
    http_post_json,
)
from protocol_tests.http_helpers import (  # noqa: E402
    INCONCLUSIVE_PREFIX,
    PAYMENT_VERDICTS,
    fold_live_verdict,
    is_inconclusive,
    live_run_scope,
    payment_outcome,
    run_summary,
)


# ---------------------------------------------------------------------------
# A loopback server that answers one fixed (status, content-type, body) to
# every method, on a port the OS picks.
# ---------------------------------------------------------------------------

class _Fixed:
    def __init__(self, status: int, body: str, content_type: str = "application/json"):
        self.status, self.body, self.content_type = status, body, content_type
        outer = self

        class H(BaseHTTPRequestHandler):
            def _answer(self):
                n = int(self.headers.get("content-length") or 0)
                if n:
                    self.rfile.read(n)
                data = outer.body.encode("utf-8")
                self.send_response(outer.status)
                self.send_header("Content-Type", outer.content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_POST = do_GET = _answer

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


# ---------------------------------------------------------------------------
# 1. The truth table, on classifier inputs
# ---------------------------------------------------------------------------

#: Transport states as the flat `_utils` transport reports them. ``None``
#: status is a socket-level failure; the rest carry the real HTTP status.
TRANSPORT = {
    "refused": {"_error": True, "_exception": "URLError", "_message": "refused"},
    "timeout": {"_error": True, "_exception": "TimeoutError", "_message": "timed out"},
    "500": {"_error": True, "_status": 500, "_body": "{}"},
    "503": {"_error": True, "_status": 503, "_body": '{"allowed": true}'},
    "403": {"_error": True, "_status": 403, "_body": ""},
    "402": {"_error": True, "_status": 402, "_body": '{"accepts": []}'},
    "404": {"_error": True, "_status": 404, "_body": ""},
    "302": {"_status": 302},
    "200": {"_status": 200},
}

#: Body shapes the application layer can put on a 2xx (or, for the 4xx
#: rows, the parsed ``_body``).
BODY = {
    "empty": {},
    "prose": {"_raw": "hello there"},
    "no_decision": {"request_id": "abc", "echo": {"payment_mandate": {"final": True}}},
    "jsonrpc_error": {"error": {"code": -32601, "message": "method not found"}},
    "allowed": {"allowed": True},
    "nested_granted": {"result": {"granted": True, "admin": True}},
    "state_settled": {"status": "settled"},
    "effect": {"settlement_id": "stl_1"},
    "allowed_false": {"allowed": False},
    "state_rejected": {"decision": "declined"},
    "term": {"reason": "signature invalid"},
    "forged_error": {"allowed": True, "_error": True, "_status": 503},
}

#: transport -> body -> verdict. Every cell written before the code, per
#: CLAUDE.md item 9. A 5xx or no status is unreachable whatever the body;
#: 401/402/403 are rejected whatever the body; a 404 is rejected only when
#: the body states a denial; a 2xx is accepted only on a recognised decision.
EXPECTED = {
    "refused": {b: "unreachable" for b in BODY},
    "timeout": {b: "unreachable" for b in BODY},
    "500": {b: "unreachable" for b in BODY},
    "503": {b: "unreachable" for b in BODY},
    "403": {b: "rejected" for b in BODY},
    "402": {b: "rejected" for b in BODY},
    "404": {
        "empty": "undecided", "prose": "undecided", "no_decision": "undecided",
        "jsonrpc_error": "rejected", "allowed": "undecided",
        "nested_granted": "undecided", "state_settled": "undecided",
        "effect": "undecided", "allowed_false": "rejected",
        "state_rejected": "rejected", "term": "rejected",
        "forged_error": "undecided",
    },
    "302": {
        "empty": "undecided", "prose": "undecided", "no_decision": "undecided",
        "jsonrpc_error": "undecided", "allowed": "undecided",
        "nested_granted": "undecided", "state_settled": "undecided",
        "effect": "undecided", "allowed_false": "rejected",
        "state_rejected": "rejected", "term": "rejected",
        "forged_error": "undecided",
    },
    "200": {
        "empty": "undecided", "prose": "undecided", "no_decision": "undecided",
        "jsonrpc_error": "undecided", "allowed": "accepted",
        "nested_granted": "accepted", "state_settled": "accepted",
        "effect": "accepted", "allowed_false": "rejected",
        "state_rejected": "rejected", "term": "rejected",
        "forged_error": "accepted",
    },
}


def _compose(transport: str, body: str) -> dict:
    """What the transport hands the classifier for that cell. A 4xx carries
    the body as ``_body`` text; a 2xx/3xx carries it flat, with the
    transport's strip applied as `_utils.http_post_json` applies it."""
    t = dict(TRANSPORT[transport])
    b = BODY[body]
    if t.get("_error") and "_status" in t:
        t["_body"] = json.dumps({k: v for k, v in b.items() if not k.startswith("_")})
        return t
    if t.get("_error"):
        return t
    if "_raw" in b:
        return {**t, "_error": True, "_exception": "JSONDecodeError", "_raw": b["_raw"]}
    app, stripped = _strip_reserved(b)
    out = {**app, **t}
    if stripped:
        out["_stripped_keys"] = stripped
    return out


class TestTheTruthTable(unittest.TestCase):
    def test_every_cell(self):
        for transport, row in EXPECTED.items():
            for body, want in row.items():
                with self.subTest(transport=transport, body=body):
                    resp = _compose(transport, body)
                    self.assertEqual(payment_outcome(resp)[0], want, resp)

    def test_the_table_covers_every_shape_and_every_verdict_appears(self):
        self.assertEqual(set(EXPECTED), set(TRANSPORT))
        for transport, row in EXPECTED.items():
            self.assertEqual(set(row), set(BODY), transport)
        seen = {v for row in EXPECTED.values() for v in row.values()}
        self.assertEqual(seen, set(PAYMENT_VERDICTS))

    def test_an_echoed_request_is_not_a_decision(self):
        """AP2-016 sends {"final": true, "verified": true} inside a mandate;
        a verifier that echoes the payload back has decided nothing."""
        echo = {"_status": 200,
                "payment_mandate": {"final": True, "verified": True, "status": "settled"},
                "payment": {"state": "final", "receipt": {"final": True}},
                "transaction": {"approved": True}}
        self.assertEqual(payment_outcome(echo)[0], "undecided")

    def test_transport_metadata_is_never_read_as_a_rejection_word(self):
        """`_stripped_keys: ["_denied"]` is the transport's record of a
        forgery attempt, not the target saying "denied"."""
        resp = {"_status": 200, "allowed": True, "_stripped_keys": ["_denied"],
                "_body": "rejected"}
        self.assertEqual(payment_outcome(resp)[0], "accepted")

    def test_status_and_underscore_status_are_not_conflated(self):
        """`status` is the application's word; `_status` is the transport's."""
        self.assertEqual(payment_outcome({"_status": 200, "status": "settled"})[0],
                         "accepted")
        self.assertEqual(payment_outcome({"_status": 200, "status": 503})[0],
                         "undecided")
        self.assertEqual(payment_outcome({"_status": 503, "status": "settled"})[0],
                         "unreachable")
        self.assertEqual(payment_outcome({"status": 200, "allowed": True})[0],
                         "unreachable", "an application `status` is not a transport status")

    def test_a_refusal_wins_over_an_acceptance_in_the_same_answer(self):
        self.assertEqual(payment_outcome({"_status": 200, "allowed": True,
                                          "reason": "policy override"},
                                         extra=("policy",))[0], "rejected")
        self.assertEqual(payment_outcome({"_status": 200, "granted": True,
                                          "settled": False})[0], "rejected")

    def test_caller_acceptance_vocabulary_is_additive(self):
        self.assertEqual(payment_outcome({"_status": 200, "isValid": True})[0],
                         "undecided")
        self.assertEqual(payment_outcome({"_status": 200, "isValid": True},
                                         accept_flags=("isValid",))[0], "accepted")
        self.assertEqual(payment_outcome({"_status": 200, "status": "released"})[0],
                         "undecided")
        self.assertEqual(payment_outcome({"_status": 200, "status": "released"},
                                         accept_states=("released",))[0], "accepted")
        self.assertEqual(payment_outcome({"_status": 200, "order": {"id": "o1"}})[0],
                         "undecided")
        self.assertEqual(payment_outcome({"_status": 200, "order": {"id": "o1"}},
                                         accept_effects=("order",))[0], "accepted")


# ---------------------------------------------------------------------------
# 2. The transport strips what it owns
# ---------------------------------------------------------------------------

class TestReservedKeysAreTheTransports(unittest.TestCase):
    def test_the_reserved_set_names_every_key_the_transport_writes(self):
        for key in ("_status", "_error", "_exception", "_message", "_body",
                    "_raw", "_stripped_keys"):
            self.assertIn(key, RESERVED_TRANSPORT_KEYS)

    def test_every_underscore_key_is_stripped_and_recorded(self):
        app, stripped = _strip_reserved({
            "allowed": True, "_error": True, "_status": 503, "_exception": "x",
            "_transport": "forged", "_simulated": True, "_stripped_keys": [],
            "_anything_else": 1, "status": "settled"})
        self.assertEqual(app, {"allowed": True, "status": "settled"})
        self.assertEqual(stripped, sorted([
            "_error", "_status", "_exception", "_transport", "_simulated",
            "_stripped_keys", "_anything_else"]))

    def test_a_clean_body_is_returned_untouched(self):
        body = {"allowed": True, "status": "settled"}
        app, stripped = _strip_reserved(body)
        self.assertIs(app, body)
        self.assertEqual(stripped, [])


class TestOverTheWire(unittest.TestCase):
    """Each shape the review named, through a real socket and the flat
    `_utils` transport the five payment modules use."""

    def _probe(self, status, body, content_type="application/json"):
        with _Fixed(status, body, content_type) as srv:
            resp = http_post_json(srv.url, {"payment_mandate": {"id": "pm-1"}},
                                  timeout=5)
        return resp, payment_outcome(resp)

    def test_empty_object_is_undecided(self):
        resp, (verdict, _) = self._probe(200, "{}")
        self.assertEqual(resp, {"_status": 200})
        self.assertEqual(verdict, "undecided")

    def test_empty_body_is_undecided(self):
        resp, (verdict, _) = self._probe(200, "")
        self.assertEqual(resp, {"_status": 200})
        self.assertEqual(verdict, "undecided")

    def test_allowed_true_is_accepted(self):
        resp, (verdict, _) = self._probe(200, '{"allowed": true}')
        self.assertEqual(resp, {"allowed": True, "_status": 200})
        self.assertEqual(verdict, "accepted")

    def test_forged_transport_keys_are_stripped_and_the_decision_stands(self):
        """R4-03. The body says `_error: true, _status: 503`; the transport
        says 200, the body says allowed, and the classifier believes the
        transport."""
        resp, (verdict, _) = self._probe(
            200, '{"allowed": true, "_error": true, "_status": 503, '
                 '"_exception": "URLError", "_transport": "down"}')
        self.assertEqual(resp["_status"], 200)
        self.assertNotIn("_error", resp)
        self.assertNotIn("_exception", resp)
        self.assertNotIn("_transport", resp)
        self.assertEqual(resp["_stripped_keys"],
                         ["_error", "_exception", "_status", "_transport"])
        self.assertEqual(verdict, "accepted")

    def test_forged_stripped_keys_is_rebuilt_not_trusted(self):
        resp, _ = self._probe(200, '{"allowed": true, "_stripped_keys": ["nothing"]}')
        self.assertEqual(resp["_stripped_keys"], ["_stripped_keys"])

    def test_403_with_a_denial_is_rejected(self):
        resp, (verdict, _) = self._probe(403, '{"error": "denied"}')
        self.assertEqual(resp["_status"], 403)
        self.assertTrue(resp["_error"])
        self.assertEqual(verdict, "rejected")

    def test_prose_with_a_200_is_undecided(self):
        resp, (verdict, _) = self._probe(200, "hello there", "text/plain")
        self.assertEqual(resp["_status"], 200)
        self.assertEqual(resp["_raw"], "hello there")
        self.assertEqual(verdict, "undecided")

    def test_a_json_array_with_a_200_is_undecided(self):
        resp, (verdict, _) = self._probe(200, '[{"allowed": true}]')
        self.assertEqual(resp["_status"], 200)
        self.assertEqual(resp["_exception"], "NonObjectJSON")
        self.assertEqual(verdict, "undecided")

    def test_a_5xx_is_unreachable_whatever_it_says(self):
        _, (verdict, _) = self._probe(503, '{"allowed": true}')
        self.assertEqual(verdict, "unreachable")

    def test_a_closed_port_is_unreachable(self):
        resp = http_post_json("http://127.0.0.1:9", {"x": 1}, timeout=3)
        self.assertTrue(resp["_error"])
        self.assertNotIn("_status", resp)
        self.assertEqual(payment_outcome(resp)[0], "unreachable")


# ---------------------------------------------------------------------------
# 3. The fold and the scope statement
# ---------------------------------------------------------------------------

class TestTheFoldOnUndecided(unittest.TestCase):
    def test_undecided_is_inconclusive_and_says_serviced_no_decision(self):
        passed, details, ref = fold_live_verdict(
            live_requested=True, verdict="undecided",
            model_pass=True, model_reason="r", subject="live verifier")
        self.assertIs(passed, False)
        self.assertTrue(details.startswith(INCONCLUSIVE_PREFIX))
        self.assertIn("serviced the request", details)
        self.assertIn("no decision", details)
        self.assertNotIn("ACCEPTED", details)
        self.assertNotIn("unreachable", details)
        self.assertEqual(ref["passed"], True)

    def test_undecided_rows_are_observed_and_not_scored(self):
        class R:
            def __init__(self):
                self.passed, self.details, _ = fold_live_verdict(
                    live_requested=True, verdict="undecided",
                    model_pass=True, model_reason="r")
                self.not_evaluated = is_inconclusive(self.details)
                self.live_evidence = {"verdict": "undecided", "status": 200}
        rows = [R(), R(), R()]
        s = run_summary(rows)
        self.assertEqual((s["passed"], s["failed"], s["inconclusive"], s["serviced"]),
                         (0, 0, 3, 0))
        self.assertIsNone(s["pass_rate"])
        scope = live_run_scope(rows, live_requested=True, target="http://t")
        self.assertEqual(scope["rows_with_live_observation"], 3)
        self.assertEqual(scope["rows_scored"], 0)
        self.assertNotIn("NOT reached", scope["statement"])


# ---------------------------------------------------------------------------
# 4. One payment harness end to end, the way an operator runs it
# ---------------------------------------------------------------------------

class TestAP2AgainstAnEmptyAnswer(unittest.TestCase):
    """The review's reproduction: installed AP2 against 200 ``{}`` reported
    17 FAIL / 17 serviced. Every row is INCONCLUSIVE now, with the answer
    recorded and nothing scored."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="r4-02-"))
        report = cls.tmp / "ap2.json"
        env = dict(os.environ, AGENT_SECURITY_TELEMETRY="off")
        with _Fixed(200, "{}") as srv:
            cls.url = srv.url
            proc = subprocess.run(
                [sys.executable, "-m", "protocol_tests.cli", "test", "ap2",
                 "--url", srv.url, "--report", str(report)],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True,
                timeout=180, check=False)
        cls.stdout = proc.stdout
        cls.report = json.loads(report.read_text(encoding="utf-8"))

    def test_the_suite_produced_its_rows(self):
        self.assertGreaterEqual(len(self.report["results"]), 17)

    def test_zero_pass_zero_fail_n_inconclusive(self):
        s = self.report["summary"]
        n = len(self.report["results"])
        self.assertEqual((s["passed"], s["failed"], s["inconclusive"], s["serviced"]),
                         (0, 0, n, 0))
        self.assertIsNone(s["pass_rate"])
        self.assertIsNone(s["wilson_95_ci"])
        self.assertEqual(s["status"], "inconclusive")

    def test_every_row_records_the_answer_and_scores_nothing(self):
        for row in self.report["results"]:
            with self.subTest(test_id=row.get("test_id")):
                self.assertIs(row["passed"], False)
                self.assertIs(row["not_evaluated"], True)
                self.assertTrue(row["details"].startswith(INCONCLUSIVE_PREFIX))
                self.assertIn("no decision", row["details"])
                self.assertNotIn("ACCEPTED", row["details"])
                self.assertEqual(row["live_evidence"],
                                 {"verdict": "undecided", "status": 200})
                self.assertIsInstance(row["reference_verdict"], dict)

    def test_the_scope_says_observed_and_not_scored(self):
        scope = self.report["verdict_scope"]
        self.assertIs(scope["live_requested"], True)
        self.assertEqual(scope["rows_with_live_observation"], scope["rows_total"])
        self.assertEqual(scope["rows_scored"], 0)
        self.assertNotIn("NOT reached", scope["statement"])

    def test_the_console_reports_no_failure(self):
        self.assertNotIn("FAIL", self.stdout)


if __name__ == "__main__":
    unittest.main()
