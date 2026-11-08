"""Truth table for an MCP01 probe, written before the probe exists (CLAUDE.md rule 9).

OWASP MCP Top 10 (2025) MCP01 "Token Mismanagement and Secret Exposure" is the one
server-tier entry docs/OWASP-MCP-TOP10-MAPPING.md records as not covered. Existing
credential tests look elsewhere: WXO-003 and GTG-P4-001 read an agent's or a config's
output, MCP-021/022 test token *validation* (MCP07). None asks whether an MCP server
puts the credential it holds onto the MCP wire.

Nothing here is a harness test, and no test ID is added. The table fixes which target
shapes must PASS, FAIL or be INCONCLUSIVE, and the reference grader is the oracle a
future probe must reproduce:

    observable capability    an MCP server that calls an upstream API with a credential
                             the operator configures. The operator sets that credential
                             to a harness-generated canary and points the upstream at a
                             harness-run sink.
    adversarial precondition three MCP-native paths to the wire:
                             (a) an upstream failure, whose error the server relays
                                 (error.message / error.data);
                             (b) logging/setLevel debug, then notifications/message;
                             (c) resources/list + resources/read of whatever the server
                                 exposes (config-, env- or debug-shaped URIs included).
    deterministic oracle     the canary, in any common encoding (raw, base64, hex, URL)
                             or as a contiguous run of MIN_RUN characters, in ANY message
                             the server sent. Never the server's own redaction claim.
    positive control         the sink must have received the canary from the server
                             (it holds and uses the secret), and a benign tool call must
                             have been served. Without both, a clean wire proves nothing.
    negative control         each path's leaking shape must FAIL.

Redaction is allowed: showing the last four characters ("****wxyz") is PASS. The
boundary is MIN_RUN contiguous characters.

The sink must never put the canary in its own responses. Servers routinely relay the
upstream body in their errors (github-mcp-server, mcp-grafana and mcp-atlassian all do,
checked 2026-11-08), so a sink that echoed the Authorization header would make the
server look like it leaked a secret the harness put on the wire. That result is the
harness's defect, and the grader returns INCONCLUSIVE for it, never FAIL.
"""

from __future__ import annotations

import base64
import json
import unittest
import urllib.parse

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"

CANARY = "mcp01-canary-7Qe2vN9xLr4TbZ8kWp3s"  # a probe generates a fresh one per run
MIN_RUN = 8


def encodings(secret: str) -> list[str]:
    raw = secret.encode()
    return [secret, base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
            raw.hex(), urllib.parse.quote(secret, safe=""),
            base64.b64encode(b"user:" + raw).decode()]  # HTTP Basic, the shape a relayed header takes


def leaks(text: str, secret: str = CANARY) -> str | None:
    """The first leak form found in text, or None."""
    for form in encodings(secret):
        if form in text:
            return form
    for i in range(len(secret) - MIN_RUN + 1):
        if secret[i:i + MIN_RUN] in text:
            return secret[i:i + MIN_RUN]
    return None


def grade(observed: dict) -> tuple[str, str]:
    """Reference oracle.

    observed = {
      "sink_saw_canary": bool,      # upstream sink received the canary from the server
      "benign_call_served": bool,   # a harmless tools/call returned a result
      "messages": [dict, ...],      # every JSON-RPC message the server sent, in order
      "sink_echoed_canary": bool,   # optional: the sink's own responses contained it
    }
    """
    if observed.get("sink_echoed_canary"):
        return INCONCLUSIVE, "harness sink echoed the canary; a relayed body would be our leak, not the server's"
    if not observed["messages"]:
        return INCONCLUSIVE, "server sent nothing"
    for msg in observed["messages"]:
        form = leaks(json.dumps(msg))
        if form:
            return FAIL, f"canary on the wire as {form!r} in {msg.get('method') or 'response'}"
    if not observed["sink_saw_canary"]:
        return INCONCLUSIVE, "server never used the credential; a clean wire proves nothing"
    if not observed["benign_call_served"]:
        return INCONCLUSIVE, "no benign call was served (refuses everything?)"
    return PASS, "credential used upstream; not on the wire in any checked form"


# ---------------------------------------------------------------------------
# Target shapes. Each returns what a probe would observe running paths (a)-(c).
# ---------------------------------------------------------------------------

AUTH = f"Bearer {CANARY}"
OK = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "42"}]}}


def _obs(messages, sink=True, served=True):
    return {"sink_saw_canary": sink, "benign_call_served": served, "messages": messages}


def redacting_server():
    """Positive control: uses the secret, generic errors, logs show last four only."""
    return _obs([
        OK,
        {"jsonrpc": "2.0", "id": 2, "error": {"code": -32603, "message": "upstream error (502)"}},
        {"jsonrpc": "2.0", "method": "notifications/message",
         "params": {"level": "debug", "data": {"upstream": "api.example", "auth": "Bearer ****" + CANARY[-4:]}}},
        {"jsonrpc": "2.0", "id": 3, "result": {"contents": [{"uri": "config://settings",
                                                             "text": json.dumps({"timeout": 30})}]}},
    ])


def error_relay_server():
    """(a) Relays the upstream request in error.data."""
    return _obs([OK, {"jsonrpc": "2.0", "id": 2, "error": {
        "code": -32603, "message": "upstream error (502)",
        "data": {"request": {"headers": {"Authorization": AUTH}}}}}])


def debug_log_server():
    """(b) At debug level, logs outgoing request headers."""
    return _obs([OK, {"jsonrpc": "2.0", "method": "notifications/message",
                      "params": {"level": "debug", "data": f"GET /v1/items Authorization: {AUTH}"}}])


def basic_auth_log_server():
    """(b) Same leak, base64 under HTTP Basic; a raw-string search misses it."""
    hdr = "Basic " + base64.b64encode(b"user:" + CANARY.encode()).decode()
    return _obs([OK, {"jsonrpc": "2.0", "method": "notifications/message",
                      "params": {"level": "debug", "data": {"Authorization": hdr}}}])


def config_resource_server():
    """(c) Serves its own settings, token included, as a resource."""
    return _obs([OK, {"jsonrpc": "2.0", "id": 3, "result": {"contents": [{
        "uri": "config://settings", "text": json.dumps({"api_token": CANARY})}]}}])


def partial_echo_server(run: int):
    """Shows `run` contiguous characters of the secret: the redaction boundary."""
    return _obs([OK, {"jsonrpc": "2.0", "method": "notifications/message",
                      "params": {"level": "info", "data": f"using key {CANARY[:run]}..."}}])


def refuses_everything():
    """Never serves a call. Its wire is clean, and that must not read as PASS."""
    return _obs([{"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}}],
                sink=False, served=False)


def never_uses_secret():
    """Serves calls but never contacts the upstream: it holds nothing to leak."""
    return _obs([OK], sink=False, served=True)


UPSTREAM_502 = {"message": "Bad Gateway", "documentation_url": "https://example.invalid/docs"}


def body_relay_server():
    """Relays the upstream error body verbatim. The sink's body is clean, so this is PASS."""
    return _obs([OK, {"jsonrpc": "2.0", "id": 2, "result": {"isError": True, "content": [
        {"type": "text", "text": f"upstream returned 502: {json.dumps(UPSTREAM_502)}"}]}}])


def body_relay_with_echoing_sink():
    """Same server, but the sink reflected the Authorization header into its body."""
    body = dict(UPSTREAM_502, received_auth=AUTH)
    obs = _obs([OK, {"jsonrpc": "2.0", "id": 2, "result": {"isError": True, "content": [
        {"type": "text", "text": f"upstream returned 502: {json.dumps(body)}"}]}}])
    obs["sink_echoed_canary"] = True
    return obs


def silent_server():
    return _obs([], sink=False, served=False)


TABLE = [
    ("positive control: redacting server", redacting_server, PASS),
    ("(a) error relays Authorization header", error_relay_server, FAIL),
    ("(b) debug log carries bearer token", debug_log_server, FAIL),
    ("(b) debug log carries Basic (base64) header", basic_auth_log_server, FAIL),
    ("(c) config resource carries token", config_resource_server, FAIL),
    ("redaction boundary: MIN_RUN-1 chars", lambda: partial_echo_server(MIN_RUN - 1), PASS),
    ("redaction boundary: MIN_RUN chars", lambda: partial_echo_server(MIN_RUN), FAIL),
    ("refuses everything", refuses_everything, INCONCLUSIVE),
    ("never uses the secret", never_uses_secret, INCONCLUSIVE),
    ("sends nothing", silent_server, INCONCLUSIVE),
    ("relays a clean upstream error body", body_relay_server, PASS),
    ("relays a body the harness sink polluted", body_relay_with_echoing_sink, INCONCLUSIVE),
]


class MCP01TruthTable(unittest.TestCase):
    def test_every_row(self):
        for name, shape, expected in TABLE:
            with self.subTest(name):
                verdict, why = grade(shape())
                self.assertEqual(verdict, expected, why)

    def test_the_table_has_both_controls_and_every_verdict(self):
        verdicts = [e for _, _, e in TABLE]
        self.assertIn(PASS, verdicts)
        self.assertGreaterEqual(verdicts.count(FAIL), 3, "one negative control per path (a)-(c)")
        self.assertIn(INCONCLUSIVE, verdicts)

    def test_a_raw_string_search_alone_would_miss_the_base64_row(self):
        """Why encodings() exists: the Basic header holds no raw canary run."""
        text = json.dumps(basic_auth_log_server()["messages"])
        self.assertNotIn(CANARY[:MIN_RUN], text)
        self.assertIsNotNone(leaks(text))

    def test_a_clean_wire_from_a_server_that_never_used_the_secret_is_not_pass(self):
        """Rule 9's skipped control: the X4-057 shape (no capability, so 'the control held')."""
        self.assertNotEqual(grade(never_uses_secret())[0], PASS)
        self.assertNotEqual(grade(refuses_everything())[0], PASS)

    def test_a_leak_the_harness_caused_is_never_charged_to_the_server(self):
        """Self-caught-bug attribution: the polluted relay contains the canary, and still is not FAIL."""
        obs = body_relay_with_echoing_sink()
        self.assertIsNotNone(leaks(json.dumps(obs["messages"])))
        self.assertEqual(grade(obs)[0], INCONCLUSIVE)

    def test_the_grader_is_not_vacuous(self):
        """Mutation: a grader that ignores the messages must fail the table."""
        def blind(observed):
            ok = observed["sink_saw_canary"] and observed["benign_call_served"]
            return (PASS, "") if ok else (INCONCLUSIVE, "")
        misgraded = [n for n, s, e in TABLE if blind(s())[0] != e]
        self.assertGreaterEqual(len(misgraded), 4)


if __name__ == "__main__":
    unittest.main()
