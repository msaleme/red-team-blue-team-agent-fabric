"""A2A: an answer with nothing in it is no Agent Card and no JSON-RPC surface.

VrtxOmega (#622) drove a2a_harness against four contentless poles and found
twelve verdicts (measured at b06aa33, `VERDICT_ON_A_CONTENTLESS_ANSWER`):

    A2A-001  FAIL on a redirect loop and an empty 500 ("Could not fetch Agent
             Card"), and on an empty 200 / 204 ("Missing fields")
    A2A-004/007/008/009  FAIL on an empty 200 / 204: `_shows_a2a_surface`
             counted any 2xx as a served JSON-RPC endpoint, so the empty
             answer to each attack was read as the attack being served

Owner decision 2026-09-26 (decision 5): A2A-001 stays FAIL only on a 404, the
#594 contract (a served "not here"). On a redirect loop, an empty 500, an empty
200 or an empty 204 there is no Agent Card to judge, so A2A-001 is
INCONCLUSIVE; every other A2A cell on those poles is INCONCLUSIVE too.

The rule: `http_helpers.contentless_answer` (a 3xx the transport could not
follow, an empty 5xx, or an empty 2xx) is neither a surface
(`_shows_a2a_surface`) nor a served card (`_served_agent_card`), and A2A-001
reads it as no card (`_no_card_to_judge`). The transport keeps the status on
an empty body, which it used to return as a bare `{}` that the predicate could
not see.

Every pole is a real stdlib server on loopback. The four #622 poles are the
sweep's own (`no_surface_sweep.status_everywhere_target`), so this file and the
register measure the same shapes; the JSON-typed empty 200 and the served
controls use the #594 stub.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from no_surface_sweep import CONTENTLESS_POLES, status_everywhere_target  # noqa: E402
from protocol_tests.a2a_harness import (  # noqa: E402
    _no_card_to_judge,
    _served_agent_card,
    _shows_a2a_surface,
)
from testing.test_a2a_verdicts_need_an_a2a_surface import (  # noqa: E402
    _CARD,
    _METHODS,
    SURFACE_GATED,
    _against,
    _rpc_error,
    _run,
    _verdict,
    accepting_dispatcher,
    card_then_forbidding,
    not_found_everywhere,
    refusing_dispatcher,
)

#: Every A2A test this file can drive, A2A-001 first.
ALL_IDS = tuple(_METHODS)

#: The four #622 poles owner decision 5 covers.
DECISION_5_POLES = ("redirect-loop", "empty-500", "empty-200", "empty-204")


def _on_pole(pole, ids=ALL_IDS):
    with status_everywhere_target(**CONTENTLESS_POLES[pole]) as url:
        return _run(url, ids)


class TestContentlessPolesAreInconclusive(unittest.TestCase):
    """The twelve registered cells, and every other A2A row on these poles."""

    def test_every_row_on_every_pole(self):
        for pole in DECISION_5_POLES:
            rs = _on_pole(pole)
            for tid in ALL_IDS:
                with self.subTest(pole=pole, test_id=tid):
                    self.assertEqual(_verdict(rs[tid]), "INCONCLUSIVE", rs[tid].details)
                    self.assertTrue(rs[tid].not_evaluated)

    def test_a2a_001_names_why_there_is_no_card(self):
        expected = {
            "redirect-loop": "redirect loop",
            "empty-500": "an empty HTTP 500",
            "empty-200": "an empty HTTP 200",
            "empty-204": "an empty HTTP 204",
        }
        for pole, text in expected.items():
            with self.subTest(pole=pole):
                r = _on_pole(pole, ("A2A-001",))["A2A-001"]
                self.assertIn(text, r.details)
                self.assertIn("no Agent Card to judge", r.details)

    def test_empty_200_typed_as_json(self):
        """A real server may label the empty body application/json. The
        transport returned `{}` for it, with no status, which `empty_2xx`
        cannot recognise; it now keeps the status."""
        rs = _against(lambda *a: (200, None), ALL_IDS)
        for tid in ALL_IDS:
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(rs[tid]), "INCONCLUSIVE", rs[tid].details)

    def test_whitespace_only_200(self):
        rs = _against(lambda *a: (200, "  \n"), ("A2A-001",) + SURFACE_GATED)
        for tid, r in rs.items():
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)


class TestServedAnswersAreUnchanged(unittest.TestCase):
    """What the decision keeps: A2A-001 FAILs on a 404, a served card with the
    attack refused PASSes, a served compliance FAILs, bare 401/403 (#601)."""

    def test_a2a_001_fails_on_404(self):
        r = _against(not_found_everywhere, ("A2A-001",))["A2A-001"]
        self.assertEqual(_verdict(r), "FAIL", r.details)
        self.assertIn("Could not fetch Agent Card", r.details)

    def test_a2a_001_fails_on_a_404_with_an_empty_body(self):
        """The 404 rule is the status, not the body: an empty 404 is still a
        served "not here"."""
        r = _against(lambda *a: (404, None), ("A2A-001",))["A2A-001"]
        self.assertEqual(_verdict(r), "FAIL", r.details)

    def test_served_card_and_refused_attack_passes(self):
        rs = _against(refusing_dispatcher, ("A2A-001",) + SURFACE_GATED)
        for tid, r in rs.items():
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(r), "PASS", r.details)

    def test_served_card_then_bare_403_passes(self):
        rs = _against(card_then_forbidding, SURFACE_GATED)
        for tid, r in rs.items():
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(r), "PASS", r.details)

    def test_served_compliance_fails(self):
        rs = _against(accepting_dispatcher, SURFACE_GATED)
        for tid, r in rs.items():
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(r), "FAIL", r.details)

    def test_empty_card_does_not_mask_a_jsonrpc_surface(self):
        """An empty 200 on the card makes A2A-001 INCONCLUSIVE; it must not
        hide a dispatcher that refuses every attack as JSON-RPC."""
        def route(verb, path, raw, rpc):
            if verb == "GET":
                return 200, None
            return 200, _rpc_error(rpc)
        rs = _against(route, ("A2A-001",) + SURFACE_GATED)
        self.assertEqual(_verdict(rs["A2A-001"]), "INCONCLUSIVE", rs["A2A-001"].details)
        for tid in SURFACE_GATED:
            with self.subTest(test_id=tid):
                self.assertEqual(_verdict(rs[tid]), "PASS", rs[tid].details)

    def test_bare_401_and_403_everywhere_stay_inconclusive(self):
        for status in (401, 403):
            rs = _against(lambda *a, s=status: (s, "Denied"), ("A2A-001",) + SURFACE_GATED)
            for tid, r in rs.items():
                with self.subTest(status=status, test_id=tid):
                    self.assertEqual(_verdict(r), "INCONCLUSIVE", r.details)


class TestClassifiers(unittest.TestCase):
    """The per-response rules, at the unit level, over transport shapes."""

    def test_empty_2xx_is_not_a_surface(self):
        for resp in ({"_status": 200}, {"_status": 204},
                     {"_raw": "", "_status": 200}, {"_raw": " \n", "_status": 202}):
            with self.subTest(resp=resp):
                self.assertFalse(_shows_a2a_surface(resp))
        for resp in ({"_raw": "ok", "_status": 200},
                     {"result": {}, "jsonrpc": "2.0", "id": "1"}):
            with self.subTest(resp=resp):
                self.assertTrue(_shows_a2a_surface(resp))

    def test_empty_2xx_is_not_a_served_card(self):
        for resp in ({"_status": 200}, {"_status": 204}, {}):
            with self.subTest(resp=resp):
                self.assertFalse(_served_agent_card(resp))
        self.assertTrue(_served_agent_card(dict(_CARD)))

    def test_no_card_to_judge(self):
        cases = [
            ({"_status": 200}, "an empty HTTP 200"),
            ({"_status": 204}, "an empty HTTP 204"),
            ({"_error": True, "_status": 302, "_body": ""}, "redirect loop"),
            ({"_error": True, "_status": 500, "_body": ""}, "an empty HTTP 500"),
            ({"_error": True, "_status": 503, "_body": "  "}, "an empty HTTP 503"),
        ]
        for resp, text in cases:
            with self.subTest(resp=resp):
                self.assertIn(text, _no_card_to_judge(resp) or "")
        for resp in ({"_error": True, "_status": 404, "_body": "Not Found"},
                     {"_error": True, "_status": 404, "_body": ""},
                     {"_error": True, "_status": 500, "_body": "Internal Server Error"},
                     {"_error": True, "_status": 403, "_body": "Forbidden"},
                     {"_error": True, "_exception": "refused"},
                     dict(_CARD)):
            with self.subTest(resp=resp):
                self.assertIsNone(_no_card_to_judge(resp))


if __name__ == "__main__":
    unittest.main()
