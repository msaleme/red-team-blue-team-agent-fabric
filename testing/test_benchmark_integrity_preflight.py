"""The evaluator preflight must let BI-001..004 be right, wrong, and abstain.

Those four pass when a marker is ABSENT -- no grader internals leaked, no gold
answer returned, no injection executed, no judge override accepted -- so against
a target that does not grade at all, every one is trivially true. The suite
reported "Grader context is isolated from agent environment" about hosts with no
grader to isolate.

Gating them on a preflight fixes that and introduces a worse failure if it is
wrong in the other direction: a verdict that can only ever be INCONCLUSIVE is
not a test. So all three outcomes are seeded here against local fixtures.
"""
from __future__ import annotations

import json
import sys
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from protocol_tests.benchmark_integrity_harness import (  # noqa: E402
    BenchmarkIntegrityTests,
)

GATED = ("BI-001", "BI-002", "BI-003", "BI-004")


@contextmanager
def _endpoint(responder):
    """A local /evaluate endpoint driven by `responder(payload) -> dict`."""
    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            try:
                payload = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                payload = {}
            body = json.dumps(responder(payload)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # silence
            return

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        srv.server_close()


def _clean_grader(payload):
    """Grades, and leaks nothing."""
    correct = str(payload.get("answer")) == str(payload.get("expected"))
    return {"score": 1.0 if correct else 0.0, "verdict": "correct" if correct else "incorrect"}


def _echo(payload):
    """Answers every request identically. Not a grader."""
    return {"status": "ok"}


def _leaky_grader(payload):
    """Grades, and returns the reference answer alongside the score."""
    correct = str(payload.get("answer")) == str(payload.get("expected"))
    return {"score": 1.0 if correct else 0.0,
            "expected_answer": payload.get("expected"),
            "reference_answer": "the gold answer is 4",
            "ground_truth": "4"}


def _results(url):
    return {r.test_id: r for r in BenchmarkIntegrityTests(url).run_all()}


class TestTheGatedVerdictsCanStillPass(unittest.TestCase):
    def test_a_real_grader_that_leaks_nothing_passes(self) -> None:
        """The control that matters most. Gating must not make these unpassable."""
        with _endpoint(_clean_grader) as url:
            rs = _results(url)
        for tid in GATED:
            with self.subTest(test_id=tid):
                r = rs[tid]
                self.assertFalse(
                    r.not_evaluated,
                    f"{tid} was INCONCLUSIVE against an endpoint that "
                    f"demonstrably grades: {r.details}")
                self.assertTrue(
                    r.passed,
                    f"{tid} failed against a clean grader: {r.details}")


class TestTheGatedVerdictsAbstain(unittest.TestCase):
    def test_a_non_grader_is_inconclusive_not_a_pass(self) -> None:
        """The defect. An echo endpoint scored these as controls that held."""
        with _endpoint(_echo) as url:
            rs = _results(url)
        for tid in GATED:
            with self.subTest(test_id=tid):
                r = rs[tid]
                self.assertTrue(
                    r.not_evaluated,
                    f"{tid} was graded against an endpoint that returns the "
                    f"same answer to everything: {r.details}")
                self.assertFalse(r.passed)


class TestTheGatedVerdictsCanStillFail(unittest.TestCase):
    def test_a_grader_that_leaks_gold_answers_fails(self) -> None:
        """The preflight must not swallow a real finding."""
        with _endpoint(_leaky_grader) as url:
            rs = _results(url)
        r = rs["BI-002"]
        self.assertFalse(
            r.not_evaluated,
            f"a leaking grader was reported as unmeasured: {r.details}")
        self.assertFalse(
            r.passed,
            f"BI-002 passed against an endpoint returning the reference "
            f"answer: {r.details}")


class TestThePreflightItself(unittest.TestCase):
    def test_it_runs_once_per_instance(self) -> None:
        with _endpoint(_clean_grader) as url:
            h = BenchmarkIntegrityTests(url)
            first = h._target_grades()
            self.assertIs(h._target_grades(), first, "preflight re-ran")
            self.assertTrue(first[0])

    def test_an_unreachable_endpoint_does_not_report_grading(self) -> None:
        h = BenchmarkIntegrityTests("http://127.0.0.1:1")
        grades, why = h._target_grades()
        self.assertFalse(grades)
        self.assertIn("did not answer", why)


if __name__ == "__main__":
    unittest.main()
