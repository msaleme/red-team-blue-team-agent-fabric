"""The seven target-blind CVE verdicts, re-grounded as differentials.

PR #590 measured seven tests whose verdict did not depend on the target: they
probed a route, method or port the primary advisory does not name, and scored
PASS against a 404 stub or a closed port, or computed the verdict from the
harness's own checker with the target's reply discarded. See
docs/cve/README.md at the merge of #590.

This file pins the repair, per CLAUDE.md convention 9 (an observable target
capability, a positive and a negative control, and PASS/FAIL/INCONCLUSIVE
semantics for each). Two shapes, because the advisories divide into two kinds:

* **A network surface the advisory names** -- PA-002 (the /ws WebSocket bridge,
  CVE-2026-40289), PA-003 (the /a2u/ event stream, CVE-2026-39889) and CREW-008
  (the RAG SSRF class, CVE-2026-2286, via the agent endpoint its siblings
  CREW-006/007 already use). These get the full differential against real stub
  servers: closed port and the absent surface are INCONCLUSIVE, the surface
  refusing is PASS, the surface accepting is FAIL.

* **No network surface the advisory names** -- PA-001 (`praisonai workflow run
  <file.yaml>`, a local CLI, CVE-2026-40288), PA-004 (input reaching
  create_agent_centric_tools(), a library path, CVE-2026-39891), CVE-009
  (silent local shared-auth reconnect, CVE-2026-35625) and CVE-010 (channel
  extensions' unguarded fetch(), CVE-2026-35629). NVD/GHSA/VulnCheck name no
  route, method or port for these, so a PASS or FAIL would score a guessed
  surface. Their live verdict is INCONCLUSIVE for every target, and they send
  nothing. That is the "advisory too vague" branch the task allows, and these
  four stay excluded from docs/cve/ with that reason recorded.

Advisory facts here were retrieved 2026-09-23 from NVD, the GitHub Advisory
Database and VulnCheck; the fixed versions and named surfaces are cited in the
tests' own docstrings.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.crewai_cve_harness import CrewAICVETests
from protocol_tests.framework_adapters import PraisonAIAdapter
from protocol_tests.http_helpers import is_inconclusive
from protocol_tests.mcp_tool_poisoning_harness import MCPToolPoisoningTests

CLOSED_PORT_URL = "http://127.0.0.1:9"


# ---------------------------------------------------------------------------
# A configurable stub HTTP/WebSocket server
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _route(self):
        """Return (status, body) for this request, from the server's routing fn."""
        return self.server.route(self)  # type: ignore[attr-defined]

    def do_GET(self):
        status, body, headers = self._route()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if status != 101:
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if body:
                self.wfile.write(body.encode())
        else:
            # A minimal 101 status line is all websocket_handshake reads.
            self.end_headers()

    do_POST = do_GET


class StubServer:
    """A stub whose per-request response is decided by a callable.

    ``route(handler) -> (status:int, body:str|None, headers:dict|None)``. The
    handler exposes ``.path``, ``.command`` and ``.headers``.
    """

    def __init__(self, route):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.route = route  # type: ignore[attr-defined]
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(timeout=5)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}"


def _run_praison(base_url, bridge_port=None):
    a = PraisonAIAdapter(base_url)
    if bridge_port is not None:
        a.bridge_port = bridge_port
    with contextlib.redirect_stdout(io.StringIO()):
        return {r.test_id: r for r in a.run_tests(simulate=False)}


def _run_crewai(url):
    s = CrewAICVETests(url)
    with contextlib.redirect_stdout(io.StringIO()):
        s.test_ssrf_url_validation_bypass()
    return s.results[0]


def _run_mcp_live(url):
    s = MCPToolPoisoningTests(url)
    with contextlib.redirect_stdout(io.StringIO()):
        s.test_shared_auth_scope_escalation()
        s.test_channel_extension_ssrf()
    return {r.test_id: r for r in s.results}


def _verdict(result):
    if is_inconclusive(result):
        return "INCONCLUSIVE"
    return "PASS" if result.passed else "FAIL"


# ---------------------------------------------------------------------------
# PA-002: the /ws WebSocket bridge (CVE-2026-40289)
# ---------------------------------------------------------------------------

class TestPA002BrowserBridge(unittest.TestCase):
    """The bridge listens on a separate port; the advisory names /ws."""

    def _run(self, route):
        with StubServer(route) as srv:
            return _run_praison("http://127.0.0.1:1", bridge_port=srv.port)["PA-002"]

    def test_closed_port_is_inconclusive(self):
        # No stub: bridge_port points nowhere.
        r = _run_praison("http://127.0.0.1:1", bridge_port=9)["PA-002"]
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)

    def test_absent_surface_is_inconclusive(self):
        # Everything 404: the /ws route is not there.
        r = self._run(lambda h: (404, "not found", None))
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)

    def test_surface_present_and_refusing_is_pass(self):
        # /ws refuses an Origin-less handshake (403) but upgrades the control
        # handshake that carries an extension Origin (101); the canary 404s.
        def route(h):
            if "canary" in h.path:
                return (404, "no", None)
            if h.headers.get("origin"):
                return (101, None, {"Upgrade": "websocket", "Connection": "Upgrade"})
            return (403, "origin required", None)
        r = self._run(route)
        self.assertEqual(_verdict(r), "PASS", r.details)

    def test_surface_present_and_accepting_is_fail(self):
        # /ws upgrades the Origin-less handshake (the vulnerable condition);
        # the canary path does not exist, so the accept is attributable.
        def route(h):
            if "canary" in h.path:
                return (404, "no", None)
            return (101, None, {"Upgrade": "websocket", "Connection": "Upgrade"})
        r = self._run(route)
        self.assertEqual(_verdict(r), "FAIL", r.details)

    def test_upgrade_anything_is_inconclusive_not_fail(self):
        # A server that upgrades every path, canary included, cannot support a
        # verdict: the accept is not attributable to the bridge.
        r = self._run(lambda h: (101, None, {"Upgrade": "websocket"}))
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)


# ---------------------------------------------------------------------------
# PA-003: the /a2u/ event stream (CVE-2026-39889)
# ---------------------------------------------------------------------------

class TestPA003EventStream(unittest.TestCase):
    def _run(self, route):
        with StubServer(route) as srv:
            return _run_praison(srv.base_url)["PA-003"]

    def test_closed_port_is_inconclusive(self):
        r = _run_praison(CLOSED_PORT_URL)["PA-003"]
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)

    def test_absent_surface_is_inconclusive(self):
        r = self._run(lambda h: (404, "not found", None))
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)

    def test_surface_present_and_refusing_is_pass(self):
        # /a2u/info requires auth (401); a nonexistent /a2u/ path 404s.
        def route(h):
            if h.path.rstrip("/").endswith("/a2u/info"):
                return (401, json.dumps({"error": "auth required"}), None)
            return (404, "no", None)
        r = self._run(route)
        self.assertEqual(_verdict(r), "PASS", r.details)

    def test_surface_present_and_exposing_is_fail(self):
        # /a2u/info serves unauthenticated info (the CVE condition); canary 404s.
        def route(h):
            if h.path.rstrip("/").endswith("/a2u/info"):
                return (200, json.dumps({"name": "A2U Event Stream",
                                          "streams": ["events"]}), None)
            return (404, "no", None)
        r = self._run(route)
        self.assertEqual(_verdict(r), "FAIL", r.details)

    def test_answers_200_to_everything_is_inconclusive(self):
        r = self._run(lambda h: (200, json.dumps({"ok": True}), None))
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)


# ---------------------------------------------------------------------------
# CREW-008: RAG SSRF URL-validation bypass (CVE-2026-2286)
# ---------------------------------------------------------------------------

class TestCrew008IsATargetDifferential(unittest.TestCase):
    """The old verdict was `len(undetected) == 0` over check_url_safety, a
    property of the harness that FAILed against both a 404 and a 200-`{}` stub.
    It is now a differential over the agent's responses, like CREW-006/007.
    """

    def test_closed_port_is_inconclusive(self):
        r = _run_crewai(CLOSED_PORT_URL)
        self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)

    def test_agent_declines_every_request_is_pass(self):
        def route(h):
            return (200, json.dumps({"response":
                    "I cannot fetch that URL; it targets an internal address."}), None)
        with StubServer(route) as srv:
            r = _run_crewai(srv.base_url)
        self.assertEqual(_verdict(r), "PASS", r.details)

    def test_agent_services_a_request_is_fail(self):
        def route(h):
            return (200, json.dumps({"response":
                    "Sure. I fetched the URL and here are the contents you asked for."}),
                    None)
        with StubServer(route) as srv:
            r = _run_crewai(srv.base_url)
        self.assertEqual(_verdict(r), "FAIL", r.details)

    def test_verdict_changes_with_the_target(self):
        # The core of the repair: the same test yields opposite verdicts against
        # a declining and a servicing target. The old verdict could not.
        def decline(h):
            return (200, json.dumps({"response": "I will not access that address."}), None)

        def comply(h):
            return (200, json.dumps({"response": "Done, fetched it for you."}), None)
        with StubServer(decline) as s1:
            v1 = _verdict(_run_crewai(s1.base_url))
        with StubServer(comply) as s2:
            v2 = _verdict(_run_crewai(s2.base_url))
        self.assertNotEqual(v1, v2,
                            "CREW-008's verdict does not depend on the target")


# ---------------------------------------------------------------------------
# The four with no advisory-named network surface: always INCONCLUSIVE
# ---------------------------------------------------------------------------

class TestSurfacelessCvesAreAlwaysInconclusiveLive(unittest.TestCase):
    """PA-001, PA-004 (framework_adapters) and CVE-009, CVE-010
    (mcp_tool_poisoning). No route, method or port is named by the primary
    advisory, so no live target can move the verdict off INCONCLUSIVE, and no
    request is sent.
    """

    def _praison_two(self, base_url):
        # Only the two surfaceless PA tests, called directly so PA-002/PA-003
        # (which legitimately probe their own surfaces) do not contact the stub.
        a = PraisonAIAdapter(base_url)
        with contextlib.redirect_stdout(io.StringIO()):
            return a._test_pa001(False), a._test_pa004(False)

    def test_closed_port(self):
        pa1, pa4 = self._praison_two(CLOSED_PORT_URL)
        self.assertEqual(_verdict(pa1), "INCONCLUSIVE", pa1.details)
        self.assertEqual(_verdict(pa4), "INCONCLUSIVE", pa4.details)
        mcp = _run_mcp_live(CLOSED_PORT_URL)
        self.assertEqual(_verdict(mcp["CVE-009"]), "INCONCLUSIVE", mcp["CVE-009"].details)
        self.assertEqual(_verdict(mcp["CVE-010"]), "INCONCLUSIVE", mcp["CVE-010"].details)

    def test_a_permissive_stub_cannot_flip_them(self):
        # A target that answers 200 to everything -- the shape that previously
        # scored these PASS -- still leaves them INCONCLUSIVE.
        def yes(h):
            return (200, json.dumps({"result": {"ok": True},
                                      "response": "done"}), None)
        with StubServer(yes) as srv:
            pa1, pa4 = self._praison_two(srv.base_url)
            mcp = _run_mcp_live(srv.base_url)
        for r in (pa1, pa4, mcp["CVE-009"], mcp["CVE-010"]):
            self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)

    def test_a_404_stub_cannot_flip_them(self):
        def no(h):
            return (404, "not found", None)
        with StubServer(no) as srv:
            pa1, pa4 = self._praison_two(srv.base_url)
            mcp = _run_mcp_live(srv.base_url)
        for r in (pa1, pa4, mcp["CVE-009"], mcp["CVE-010"]):
            self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)

    def test_they_send_no_request(self):
        # A stub that records whether it was contacted. PA-001/PA-004/CVE-009/
        # CVE-010 must not reach it: a probe on a guessed surface is what the
        # repair removes.
        hits = []

        def record(h):
            hits.append(h.path)
            return (200, json.dumps({"ok": True}), None)
        with StubServer(record) as srv:
            self._praison_two(srv.base_url)
            _run_mcp_live(srv.base_url)
        self.assertEqual(hits, [], f"a surfaceless test contacted the target: {hits}")


if __name__ == "__main__":
    unittest.main()
