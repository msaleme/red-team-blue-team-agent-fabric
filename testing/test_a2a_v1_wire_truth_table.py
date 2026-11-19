"""Truth table for speaking A2A 1.0 on the wire, written before any repair (rule 9).

Coverage-gap review 2026-11-18, gap 1: every A2A test speaks 0.3 (`message/send`,
`kind` parts, no `A2A-Version`), so a server's 1.0 handlers are never exercised.
v4.30.1 (#700) stopped that from producing false verdicts: against a 1.0-only
target the tests are INCONCLUSIVE. This file defines what speaking 1.0 must mean
before the harness is changed to do it.

Spec: a2aproject/A2A @ v1.0.1, docs/specification.md and specification/a2a.proto.

    §3.6.1   "Clients MUST send the `A2A-Version` header with each request"
    §3.6.2   "Agents MUST interpret empty value as 0.3 version."
    §5.3     JSON-RPC methods SendMessage, GetTask, ListTasks, CancelTask, ...
    App A.2  "Client Implementations SHOULD: Prefer new names immediately"
    A.2.1    Part: no `kind`; the member name (text / raw / url / data) discriminates
    proto    Role ROLE_USER / ROLE_AGENT; TaskState TASK_STATE_*; Message.message_id
             REQUIRED; SendMessageConfiguration.task_push_notification_config

MEASURED 2026-11-18 at 70588b4 against protocol_tests/mock_a2a_server.py:

    0.3 hardened     A2A-004..011 PASS                        (the mock can be passed)
    0.3 vulnerable   A2A-004..009, 011 FAIL; A2A-010 PASS     (and failed)
    1.0 hardened     A2A-004..011 INCONCLUSIVE                (the gap)
    1.0 vulnerable   A2A-004..011 INCONCLUSIVE                (the gap: an attack that
                                                               would succeed is invisible)

REPAIRED (fix/a2a-v1-wire). The transport speaks the version `select_wire` picks
from the Agent Card, translating each request with `request_to_v1` and each result
with `response_from_v1`; A2A-010 writes its raw bytes in that version. Against the
1.0-only mock the eight tests now give the 0.3 verdicts in both modes, the dual
mock is spoken to in 1.0, and the strict mock refused no translated request for
its shape (a wrong translation would otherwise read as a hardened rejection).
`--a2a-version 0.3` against a 1.0-only target is still INCONCLUSIVE.

A2A-010 does not discriminate: the vulnerable mock still parses JSON-RPC strictly.
That is a limit of the mock, recorded in NOT_DISCRIMINATED rather than hidden.

    observable capability    an A2A JSON-RPC server, its Agent Card and the version it serves
    adversarial precondition each test's attack, sent in the version the server reads
    deterministic oracle     the request's method / header / part shape, and the verdict
                             against the hardened and the vulnerable mock in each version
    positive control         hardened mock: PASS in every version it serves
    negative control         vulnerable mock: FAIL in every version it serves
    semantics                WIRE_SELECTION, REQUEST_ROWS and RESPONSE_ROWS below
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from protocol_tests import a2a_harness as harness
from protocol_tests.mock_a2a_server import (
    INVALID_PARAMS,
    VERSION_NOT_SUPPORTED,
    MockA2AState,
    handle_rpc,
    serve,
)

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
#: Wire versions the harness can speak once repaired.
SPOKEN = ("0.3", "1.0")


# --- 1. Which version to speak -----------------------------------------------------

def declared(card: dict | None) -> set[str]:
    """Major.minor versions an Agent Card declares (patch ignored, §3.6)."""
    if not card:
        return set()
    out = set()
    for iface in card.get("supportedInterfaces") or []:
        if isinstance(iface, dict) and iface.get("protocolVersion"):
            out.add(".".join(str(iface["protocolVersion"]).split(".")[:2]))
    if card.get("protocolVersion"):
        out.add(".".join(str(card["protocolVersion"]).split(".")[:2]))
    return out


def select_wire(card: dict | None, forced: str | None = None) -> str | None:
    """The version to speak, or None when the card declares none the harness speaks."""
    if forced:
        return forced
    versions = declared(card)
    if not versions:
        return "0.3"           # an undeclared server is read as 0.3 (§3.6.2)
    if "1.0" in versions:
        return "1.0"           # prefer new names (App. A.2); a dual server's 1.0 path
                               # is the one the gap says is untested
    if "0.3" in versions:
        return "0.3"
    return None                # e.g. 1.1 only: not spoken -> INCONCLUSIVE, never 0.3


WIRE_SELECTION = [
    ("no card", None, None, "0.3"),
    ("0.3 card", {"protocolVersion": "0.3.0"}, None, "0.3"),
    ("1.0-only card", {"supportedInterfaces": [{"protocolVersion": "1.0"}]}, None, "1.0"),
    ("patch version on the card", {"supportedInterfaces": [{"protocolVersion": "1.0.1"}]}, None, "1.0"),
    ("dual card", {"supportedInterfaces": [{"protocolVersion": "0.3"}, {"protocolVersion": "1.0"}]},
     None, "1.0"),
    ("only an unspoken version", {"supportedInterfaces": [{"protocolVersion": "1.1"}]}, None, None),
    ("operator forces 0.3 on a 1.0-only card",
     {"supportedInterfaces": [{"protocolVersion": "1.0"}]}, "0.3", "0.3"),
]


# --- 2. What a 1.0 request looks like ----------------------------------------------

METHOD_1_0 = {"message/send": "SendMessage", "message/stream": "SendStreamingMessage",
              "tasks/get": "GetTask", "tasks/cancel": "CancelTask", "tasks/list": "ListTasks",
              "tasks/resubscribe": "SubscribeToTask",
              "agent/getAuthenticatedExtendedCard": "GetExtendedAgentCard"}


def part_to_v1(part: dict) -> dict:
    kind = part.get("kind")
    if kind == "text":
        return {"text": part.get("text", "")}
    if kind == "data":
        return {"data": part.get("data"), "mediaType": "application/json"}
    if kind == "file":
        f = part.get("file") or {}
        out = {"url": f["uri"]} if "uri" in f else {"raw": f.get("bytes", "")}
        if f.get("mimeType"):
            out["mediaType"] = f["mimeType"]
        if f.get("name"):
            out["filename"] = f["name"]
        return out
    return dict(part)  # not a 0.3 part: an attack payload, sent as written


def request_to_v1(method: str, params) -> tuple[str, object]:
    """A 0.3 (method, params) as the same request in 1.0. Unknown methods unchanged:
    A2A-011 probes undocumented names, and renaming them would change the attack."""
    new_method = METHOD_1_0.get(method, method)
    if not isinstance(params, dict):
        return new_method, params
    params = json.loads(json.dumps(params))
    msg = params.get("message")
    if isinstance(msg, dict):
        if msg.get("role") == "user":
            msg["role"] = "ROLE_USER"
        msg.setdefault("messageId", "ash-<generated>")
        if isinstance(msg.get("parts"), list):
            msg["parts"] = [part_to_v1(p) if isinstance(p, dict) else p for p in msg["parts"]]
    config = params.get("configuration")
    if isinstance(config, dict) and "pushNotificationConfig" in config:
        config["taskPushNotificationConfig"] = config.pop("pushNotificationConfig")
    if isinstance(config, dict) and "blocking" in config:
        config["returnImmediately"] = not config.pop("blocking")
    return new_method, params


REQUEST_ROWS = [
    ("send: method, role, messageId, text part",
     ("message/send", {"message": {"role": "user", "parts": [{"kind": "text", "text": "hi"}]}}),
     ("SendMessage", {"message": {"role": "ROLE_USER", "messageId": "ash-<generated>",
                                  "parts": [{"text": "hi"}]}})),
    ("file part by URI",
     ("message/send", {"message": {"role": "user", "parts": [
         {"kind": "file", "file": {"uri": "file:///etc/passwd", "mimeType": "text/plain"}}]}}),
     ("SendMessage", {"message": {"role": "ROLE_USER", "messageId": "ash-<generated>",
                                  "parts": [{"url": "file:///etc/passwd", "mediaType": "text/plain"}]}})),
    ("data part",
     ("message/send", {"message": {"role": "user", "parts": [{"kind": "data", "data": {"a": 1}}]}}),
     ("SendMessage", {"message": {"role": "ROLE_USER", "messageId": "ash-<generated>",
                                  "parts": [{"data": {"a": 1}, "mediaType": "application/json"}]}})),
    ("push config key",
     ("message/send", {"message": {"role": "user", "parts": []},
                       "configuration": {"pushNotificationConfig": {"url": "https://evil.com/x"}}}),
     ("SendMessage", {"message": {"role": "ROLE_USER", "messageId": "ash-<generated>", "parts": []},
                      "configuration": {"taskPushNotificationConfig": {"url": "https://evil.com/x"}}})),
    ("attack-only config key is kept (A2A-008 sends skillId)",
     ("message/send", {"message": {"role": "user", "parts": []}, "configuration": {"skillId": "x"}}),
     ("SendMessage", {"message": {"role": "ROLE_USER", "messageId": "ash-<generated>", "parts": []},
                      "configuration": {"skillId": "x"}})),
    ("get and cancel", ("tasks/get", {"id": "t"}), ("GetTask", {"id": "t"})),
    ("cancel", ("tasks/cancel", {"id": "t"}), ("CancelTask", {"id": "t"})),
    ("undocumented method is not renamed (A2A-011)", ("admin/shutdown", {}), ("admin/shutdown", {})),
    ("non-object params are an attack, sent as written (A2A-010)",
     ("message/send", "string_not_object"), ("SendMessage", "string_not_object")),
]


# --- 3. Reading a 1.0 response as the tests expect it ------------------------------

STATE_0_3 = {"TASK_STATE_SUBMITTED": "submitted", "TASK_STATE_WORKING": "working",
             "TASK_STATE_COMPLETED": "completed", "TASK_STATE_FAILED": "failed",
             "TASK_STATE_CANCELED": "canceled", "TASK_STATE_INPUT_REQUIRED": "input-required",
             "TASK_STATE_REJECTED": "rejected", "TASK_STATE_AUTH_REQUIRED": "auth-required"}


def part_from_v1(part):
    if not isinstance(part, dict) or "kind" in part:
        return part
    if "text" in part:
        return {**part, "kind": "text"}
    if "data" in part:
        return {**part, "kind": "data"}
    if "url" in part or "raw" in part:
        return {**part, "kind": "file"}
    return part


def response_from_v1(result):
    """A 1.0 result in the 0.3 shape the existing oracles read. Errors untouched."""
    if not isinstance(result, dict):
        return result
    if set(result) == {"task"} or set(result) == {"message"}:
        result = next(iter(result.values()))
    out = json.loads(json.dumps(result))
    status = out.get("status")
    if isinstance(status, dict) and status.get("state") in STATE_0_3:
        status["state"] = STATE_0_3[status["state"]]
    if out.get("role") == "ROLE_AGENT":
        out["role"] = "agent"
    for holder in [out] + list(out.get("artifacts") or []) + list(out.get("history") or []):
        if isinstance(holder, dict) and isinstance(holder.get("parts"), list):
            holder["parts"] = [part_from_v1(p) for p in holder["parts"]]
    return out


RESPONSE_ROWS = [
    ("SendMessageResponse wraps the task",
     {"task": {"id": "t", "status": {"state": "TASK_STATE_COMPLETED"},
               "artifacts": [{"parts": [{"text": "ok"}]}]}},
     {"id": "t", "status": {"state": "completed"},
      "artifacts": [{"parts": [{"text": "ok", "kind": "text"}]}]}),
    ("a message reply", {"message": {"role": "ROLE_AGENT", "parts": [{"text": "x"}]}},
     {"role": "agent", "parts": [{"text": "x", "kind": "text"}]}),
    ("auth-required state", {"id": "t", "status": {"state": "TASK_STATE_AUTH_REQUIRED"}},
     {"id": "t", "status": {"state": "auth-required"}}),
    ("a 0.3-shaped reply is left alone", {"id": "t", "status": {"state": "completed"}, "kind": "task"},
     {"id": "t", "status": {"state": "completed"}, "kind": "task"}),
]


# --- 4. Verdicts against the mock ---------------------------------------------------

#: Tests the mock drives to PASS (hardened) and FAIL (vulnerable) on 0.3.
DISCRIMINATED = {"A2A-004", "A2A-005", "A2A-006", "A2A-007", "A2A-008", "A2A-009", "A2A-011"}
#: PASS against both modes: the vulnerable mock still parses JSON-RPC strictly.
NOT_DISCRIMINATED = {"A2A-010"}
#: Tests that cannot grade a 1.0-only target. Measured {A2A-004..011} at 70588b4;
#: emptied by the repair. Shrink-only, checked in both directions.
V1_UNGRADED: set[str] = set()


def measure(versions: tuple[str, ...], vulnerable: bool, *extra: str) -> dict:
    """Verdicts by test ID, plus '_shape' (the mock's shape refusals) and '_stdout'."""
    httpd = serve(0, versions, vulnerable)
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01},
                     daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            proc = subprocess.run(
                [sys.executable, "-m", "protocol_tests.a2a_harness", "--url",
                 f"http://127.0.0.1:{httpd.server_address[1]}", "--report", str(report), *extra],
                cwd=REPO, capture_output=True, text=True, timeout=240, check=False)
            results = json.loads(report.read_text())["results"]
            shape = list(httpd.state.shape_rejections)
    finally:
        httpd.shutdown()
        httpd.server_close()

    def verdict(r):
        if r.get("not_evaluated") or str(r.get("details", "")).startswith("INCONCLUSIVE"):
            return INCONCLUSIVE
        return PASS if r.get("passed") else FAIL

    out = {r["test_id"]: verdict(r) for r in results}
    out["_shape"], out["_stdout"] = shape, proc.stdout
    return out


class TruthTable(unittest.TestCase):
    def test_wire_selection(self):
        for case, card, forced, expected in WIRE_SELECTION:
            with self.subTest(case=case):
                self.assertEqual(select_wire(card, forced), expected)

    def test_request_translation(self):
        for case, (m, p), expected in REQUEST_ROWS:
            with self.subTest(case=case):
                self.assertEqual(request_to_v1(m, p), expected)

    def test_translated_requests_carry_no_kind(self):
        for case, (m, p), _ in REQUEST_ROWS:
            with self.subTest(case=case):
                self.assertNotIn('"kind"', json.dumps(request_to_v1(m, p)[1]))

    def test_response_normalisation(self):
        for case, given, expected in RESPONSE_ROWS:
            with self.subTest(case=case):
                self.assertEqual(response_from_v1(given), expected)


class TheMockIsAStrictServer(unittest.TestCase):
    """The mock's own controls: it must refuse what a 1.0 server would refuse."""

    def setUp(self):
        self.state = MockA2AState(("1.0",), vulnerable=False, port=0)

    def _call(self, method, params, header):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        return handle_rpc(self.state, body, header)

    def test_empty_header_is_0_3_and_refused_by_a_1_0_only_server(self):
        r = self._call("message/send", {}, None)
        self.assertEqual(r["error"]["code"], VERSION_NOT_SUPPORTED)

    def test_patch_version_is_ignored(self):
        r = self._call("GetTask", {"id": "nope"}, "1.0.1")
        self.assertNotEqual(r.get("error", {}).get("code"), VERSION_NOT_SUPPORTED)

    def test_a_0_3_part_under_a_1_0_header_is_refused(self):
        r = self._call("SendMessage", {"message": {"role": "ROLE_USER", "messageId": "m",
                                                   "parts": [{"kind": "text", "text": "x"}]}}, "1.0")
        self.assertEqual(r["error"]["code"], INVALID_PARAMS)

    def test_a_well_formed_1_0_request_is_served(self):
        r = self._call("SendMessage", {"message": {"role": "ROLE_USER", "messageId": "m",
                                                   "parts": [{"text": "x"}]}}, "1.0")
        self.assertEqual(r["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED")

    def test_translated_requests_are_well_formed_for_the_strict_mock(self):
        # The reference translation must produce requests the strict server reads:
        # the benign send row is accepted, with no -32602 for its shape.
        _, (m, p), _ = REQUEST_ROWS[0]
        method, params = request_to_v1(m, p)
        params["message"]["messageId"] = "m-1"
        self.assertIn("result", self._call(method, params, "1.0"))


class MeasuredAgainstTheMock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = {(v, vul): measure(v, vul)
                 for v in (("0.3",), ("1.0",)) for vul in (False, True)}

    def test_the_runs_produced_rows(self):
        for key, verdicts in self.m.items():
            with self.subTest(target=key):
                self.assertEqual(len([k for k in verdicts if not k.startswith("_")]), 13)

    def test_no_translated_request_was_refused_for_its_shape(self):
        # Positive control for the 1.0 PASSes: the hardened mock refuses a badly
        # translated request with -32602, which the tests would read as a rejection.
        for key, verdicts in self.m.items():
            with self.subTest(target=key):
                self.assertEqual(verdicts["_shape"], [])

    def test_a_1_0_target_is_spoken_to_in_1_0(self):
        self.assertIn("A2A wire version: 1.0", self.m[(("1.0",), False)]["_stdout"])
        self.assertIn("A2A wire version: 0.3", self.m[(("0.3",), False)]["_stdout"])

    def test_positive_control_hardened_0_3_passes(self):
        for t in DISCRIMINATED | NOT_DISCRIMINATED:
            with self.subTest(test_id=t):
                self.assertEqual(self.m[(("0.3",), False)][t], PASS)

    def test_negative_control_vulnerable_0_3_fails(self):
        for t in DISCRIMINATED:
            with self.subTest(test_id=t):
                self.assertEqual(self.m[(("0.3",), True)][t], FAIL)

    def test_not_discriminated_is_exact(self):
        both_pass = {t for t in DISCRIMINATED | NOT_DISCRIMINATED
                     if self.m[(("0.3",), True)][t] == PASS}
        self.assertEqual(both_pass, NOT_DISCRIMINATED)

    def test_v1_ungraded_register_is_exact(self):
        # Shrink-only, both directions: a repaired test must leave the register.
        for vul in (False, True):
            with self.subTest(vulnerable=vul):
                ungraded = {t for t, v in self.m[(("1.0",), vul)].items()
                            if v == INCONCLUSIVE and t in DISCRIMINATED | NOT_DISCRIMINATED}
                self.assertEqual(ungraded, V1_UNGRADED)

    def test_graded_on_1_0_means_the_same_verdict_as_on_0_3(self):
        # Vacuous until the repair; then it is the whole point.
        for vul in (False, True):
            for t in (DISCRIMINATED | NOT_DISCRIMINATED) - V1_UNGRADED:
                with self.subTest(test_id=t, vulnerable=vul):
                    self.assertEqual(self.m[(("1.0",), vul)][t], self.m[(("0.3",), vul)][t])


class HarnessFollowsTheTable(unittest.TestCase):
    """The harness's own functions against the rows above, not the reference copies."""

    def test_select_wire(self):
        for case, card, forced, expected in WIRE_SELECTION:
            with self.subTest(case=case):
                self.assertEqual(harness.select_wire(card, forced), expected)

    def test_request_to_v1(self):
        for case, (m, p), expected in REQUEST_ROWS:
            with self.subTest(case=case):
                self.assertEqual(harness.request_to_v1(m, p, message_id="ash-<generated>"), expected)

    def test_response_from_v1(self):
        for case, given, expected in RESPONSE_ROWS:
            with self.subTest(case=case):
                self.assertEqual(harness.response_from_v1(given), expected)

    def test_shape_counter_fires_on_a_0_3_part_under_1_0(self):
        # Control for test_no_translated_request_was_refused_for_its_shape.
        state = MockA2AState(("1.0",), vulnerable=False, port=0)
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {
            "message": {"role": "ROLE_USER", "messageId": "m",
                        "parts": [{"kind": "text", "text": "x"}]}}}).encode()
        handle_rpc(state, body, "1.0")
        self.assertEqual(len(state.shape_rejections), 1)


class OtherWireChoices(unittest.TestCase):
    def test_dual_server_is_spoken_to_in_1_0_with_the_same_verdicts(self):
        dual, v03 = measure(("0.3", "1.0"), True), measure(("0.3",), True)
        self.assertIn("A2A wire version: 1.0", dual["_stdout"])
        for t in DISCRIMINATED | NOT_DISCRIMINATED:
            with self.subTest(test_id=t):
                self.assertEqual(dual[t], v03[t])

    def test_forcing_0_3_on_a_1_0_only_target_stays_inconclusive(self):
        forced = measure(("1.0",), True, "--a2a-version", "0.3")
        for t in DISCRIMINATED | NOT_DISCRIMINATED:
            with self.subTest(test_id=t):
                self.assertEqual(forced[t], INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
