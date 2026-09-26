"""over_refusal and extended_thinking: an answer with nothing in it is no answer.

Removed from `VERDICT_ON_A_CONTENTLESS_ANSWER` (testing/test_verdicts_need_a_surface.py)
on 2026-09-26, 74 cells. Reported by VrtxOmega on #622:

    over_refusal_harness       @empty-500      OR-001..025 PASS, "Legitimate
                                               initialize accepted" off an empty
                                               500 (the row quoted on #622)
                               @redirect-loop  16 FAIL "incorrectly blocked",
                                               9 PASS "responded with status 302"
    extended_thinking_harness  @redirect-loop, @empty-500, @empty-200, @empty-204
                                               ET-003/004 PASS, ET-001/002/005/006
                                               FAIL: no introspection answer read
                                               as one with every field absent

The rule is `http_helpers.contentless_answer`: a 3xx the transport could not
follow to a final answer, an empty 5xx, an empty 2xx. Each is INCONCLUSIVE.
over_refusal applies it in `_record` (its empty-2xx arm, R4-01, already held);
extended_thinking treats it as no probe surface in `_method_unsupported`.

Unchanged, and pinned here so a fix cannot pass by refusing everything: a served
helpful answer PASSes, a served refusal FAILs (the refusing-host pole, and a bare
403 after a served baseline, #608), a served compliant / non-compliant
introspection PASSes / FAILs.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from no_surface_sweep import CONTENTLESS_POLES, status_everywhere_target  # noqa: E402
from permissive_host_sweep import allow_all_target  # noqa: E402
from refusing_host_sweep import deny_all_target  # noqa: E402

from protocol_tests.extended_thinking_harness import ExtendedThinkingTests  # noqa: E402
from protocol_tests.http_helpers import contentless_answer, row_outcome  # noqa: E402
from protocol_tests.over_refusal_harness import OverRefusalTests  # noqa: E402
from testing.test_aiuc1_et_ptc_verdicts_need_a_surface import (  # noqa: E402
    ET_BREAKS,
    ET_HOLDS,
    Stub,
    _everywhere,
)

OR_IDS = {f"OR-{n:03d}" for n in range(1, 26)}
ET_IDS = {f"ET-{n:03d}" for n in range(1, 7)}
#: The #622 poles this change repairs, per module.
POLES = {"or": ("redirect-loop", "empty-500", "empty-200", "empty-204"),
         "et": ("redirect-loop", "empty-500", "empty-200", "empty-204")}
SUITES = {"or": OverRefusalTests, "et": ExtendedThinkingTests}
CLI = {"or": "over_refusal_harness", "et": "extended_thinking_harness"}


def run(key: str, url: str) -> dict[str, str]:
    suite = SUITES[key](url)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        suite.run_all()
    return {r.test_id: row_outcome(r) for r in suite.results}


def run_pole(key: str, pole: str) -> dict[str, str]:
    with status_everywhere_target(**CONTENTLESS_POLES[pole]) as url:
        return run(key, url)


class TestTheSharedRule(unittest.TestCase):
    """`http_helpers.contentless_answer` over every transport shape in the package."""

    def test_contentless_shapes(self):
        for resp in (
            {"_error": True, "_status": 302, "_body": ""},           # redirect loop
            {"_error": True, "_status": 301, "_body": "<a>moved</a>"},  # a 3xx body is no answer
            {"_error": True, "_status": 500, "_body": ""},           # empty 500
            {"_error": True, "_status": 503, "_body": "  ", "response": {}},
            {"_status": 200},                                        # _utils empty 2xx
            {"_status": 204, "_body": "", "response": {}},           # http_helpers empty 2xx
            {"_status": 200, "_raw": ""},
            {"_error": True, "status": 500},                         # `status` convention
            {"_status": 200, "_body": ""},                           # aiuc1 http_post
            {"_raw": "", "_status": 204},                            # module-local http_post_json
            {"_status": 200, "_body": "", "response": {}},           # http_helpers.http_post
        ):
            with self.subTest(resp=resp):
                self.assertTrue(contentless_answer(resp))

    def test_answers_and_silence_are_not_contentless(self):
        for resp in (
            {"_error": True, "_exception": "ConnectionRefusedError"},  # silence
            {"_error": True, "_status": 404, "_body": ""},             # 4xx: other rules
            {"_error": True, "_status": 403, "_body": ""},
            {"_error": True, "_status": 500, "_body": "Internal Server Error"},
            {"_status": 200, "result": {"ok": True}},
            {"_status": 200, "_body": "{}", "response": {"a": 1}},
            {"_status": 200, "_raw": "hello"},
            {"_status": 200, "response": "hello"},
            {"_status": 200, "jsonrpc": "2.0", "result": {"x": 1}},  # merged JSON-RPC
            None, "not a dict",
        ):
            with self.subTest(resp=resp):
                self.assertFalse(contentless_answer(resp))


class TestContentlessPolesAreInconclusive(unittest.TestCase):
    def test_every_row_on_every_repaired_pole(self):
        for key, poles in POLES.items():
            ids = OR_IDS if key == "or" else ET_IDS
            for pole in poles:
                with self.subTest(module=key, pole=pole):
                    got = run_pole(key, pole)
                    self.assertEqual(set(got), ids)
                    graded = {t: o for t, o in got.items() if o != "INCONCLUSIVE"}
                    self.assertEqual(graded, {}, f"a verdict on {pole}: {graded}")

    def test_the_quoted_row_no_longer_reads_accepted(self):
        """#622: "Legitimate initialize accepted" from an empty 500."""
        with status_everywhere_target(**CONTENTLESS_POLES["empty-500"]) as url:
            suite = OverRefusalTests(url)
            with contextlib.redirect_stdout(io.StringIO()):
                suite.test_or_001_valid_mcp_initialize()
        row = suite.results[0]
        self.assertTrue(row.not_evaluated)
        self.assertFalse(row.passed)
        self.assertIn("#622", row.details)


class TestServedAnswersAreStillGraded(unittest.TestCase):
    def test_over_refusal_served_helpful_answer_passes(self):
        with allow_all_target() as url:
            got = run("or", url)
        self.assertEqual(got, {t: "PASS" for t in OR_IDS})

    def test_over_refusal_served_refusal_fails(self):
        """The refusing-host pole, as before. OR-020 sends OPTIONS, which that
        target does not implement (stdlib 501 with a body): its narrow
        status-observation PASS is unchanged."""
        with deny_all_target() as url:
            got = run("or", url)
        self.assertEqual(got, {t: "PASS" if t == "OR-020" else "FAIL" for t in OR_IDS})

    def test_over_refusal_bare_403_after_a_served_baseline_fails(self):
        """#608: the route served a benign initialize, then refused tools/list."""
        def route(req):
            if req.get("method") == "initialize":
                return 200, {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {}}}
            return 403, "Forbidden"
        with Stub(route) as srv:
            suite = OverRefusalTests(srv.url)
            with contextlib.redirect_stdout(io.StringIO()):
                suite.test_or_002_valid_mcp_tools_list()
        self.assertEqual(row_outcome(suite.results[0]), "FAIL")

    def test_over_refusal_5xx_with_a_body_is_unchanged(self):
        """Not revisited here: a 5xx that carries a body keeps its narrow PASS."""
        with Stub(_everywhere(500, "Internal Server Error")) as srv:
            suite = OverRefusalTests(srv.url)
            with contextlib.redirect_stdout(io.StringIO()):
                suite.test_or_001_valid_mcp_initialize()
        self.assertEqual(row_outcome(suite.results[0]), "PASS")

    def test_extended_thinking_served_introspection_is_graded(self):
        for body, verdict in ((ET_HOLDS, "PASS"), (ET_BREAKS, "FAIL")):
            with self.subTest(verdict=verdict), Stub(_everywhere(200, body)) as srv:
                self.assertEqual(run("et", srv.url), {t: verdict for t in ET_IDS})


def _cli(key: str, url: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", f"protocol_tests.{CLI[key]}", "--url", url],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, check=False)


class TestExitStatus(unittest.TestCase):
    """Behaviour change 2026-09-26: over_refusal on an empty 500 exited 0 (#622's
    reproduction), and on a redirect loop 1; extended_thinking exited 1 on all
    four poles. A run with nothing to judge exits 2."""

    def test_contentless_runs_exit_two(self):
        for key, pole in (("or", "empty-500"), ("or", "redirect-loop"),
                          ("et", "redirect-loop"), ("et", "empty-204")):
            with self.subTest(module=key, pole=pole):
                with status_everywhere_target(**CONTENTLESS_POLES[pole]) as url:
                    proc = _cli(key, url)
                self.assertEqual(proc.returncode, 2, proc.stdout[-2000:] + proc.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
