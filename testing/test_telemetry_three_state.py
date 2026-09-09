"""Telemetry must count what the rows say, in three states.

`_simulate_harness` marks every row `not_evaluated: True` and prints
N/N INCONCLUSIVE, and its report says `passed: 0`. The telemetry event for the
same run said `passed=len(results), failed=0`: a simulated run of N tests
reported N passes to whatever endpoint the operator had configured. Absence of
a detected attack is not evidence a control held (CLAUDE.md item 8), and a run
that contacted nothing detected nothing.

The live path had the same two-state vocabulary: `status == "PASS"` was a pass,
`FAIL`/`ERROR` a fail, everything else vanished, and the unittest fallback
scored `testsRun - failed` -- every skipped test -- as a pass.

Both now go through `telemetry.verdict_counts`, which uses the one shared
predicate `http_helpers.is_inconclusive`, and the event carries an
`inconclusive` field. `tests == passed + failed + inconclusive` always, so
`failed=0` is a finding rather than a construction.
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import protocol_tests.telemetry as tel  # noqa: E402
import protocol_tests.cli as cli  # noqa: E402

#: The exact flat payloads docs/PRIVACY.md promises. There is no JSON schema for
#: telemetry; these key sets are the schema, and PRIVACY.md is its consumer.
#: Two shapes (R4-12): counts present, or counts absent with a fixed reason.
PAYLOAD_KEYS = {"v", "module", "counts_available", "tests", "passed", "failed",
                "inconclusive", "os", "py", "ts"}
PAYLOAD_KEYS_UNAVAILABLE = {"v", "module", "counts_available", "reason", "os", "py", "ts"}


@dataclass
class Row:
    test_id: str
    passed: bool
    details: str = ""
    not_evaluated: bool = False


def mixed_rows_as_objects() -> list:
    """2 passed, 1 failed, 3 inconclusive -- one per inconclusive vocabulary."""
    return [
        Row("T-001", True, "ok"),
        Row("T-002", True, "ok"),
        Row("T-003", False, "control did not hold"),
        Row("T-004", False, "INCONCLUSIVE - target did not service the request"),
        Row("T-005", False, "", not_evaluated=True),
        # `passed: True` with the structural marker: the marker wins. A row
        # that was never serviced cannot be a pass whatever else it says.
        Row("T-006", True, "", not_evaluated=True),
    ]


def mixed_rows_as_dicts() -> list:
    return [
        {"test_id": "T-001", "passed": True, "details": "ok"},
        {"test_id": "T-002", "passed": True, "details": "ok"},
        {"test_id": "T-003", "passed": False, "details": "control did not hold"},
        {"test_id": "T-004", "passed": False,
         "details": "INCONCLUSIVE - target did not service the request"},
        {"test_id": "T-005", "passed": False, "not_evaluated": True},
        {"test_id": "T-006", "passed": False, "informational": True},
    ]


def capture_simulated_event(harness: str = "mcp") -> tuple[dict, dict]:
    """Run `_simulate_harness` with the sender captured; return (event, report)."""
    captured: list[dict] = []
    buf = io.StringIO()
    with patch.object(tel, "send_telemetry_event",
                      side_effect=lambda **kw: captured.append(kw)), \
            contextlib.redirect_stdout(buf):
        cli._simulate_harness(harness, cli.HARNESSES[harness],
                              json_output=True, html_output=None)
    assert len(captured) == 1, f"expected one event, got {captured}"
    return captured[0], json.loads(buf.getvalue())


class SimulatedRunIsNotNPasses(unittest.TestCase):
    def test_simulated_event_counts_every_row_inconclusive(self):
        event, report = capture_simulated_event("mcp")
        rows = report["results"]
        self.assertTrue(rows, "no rows to check")
        self.assertTrue(all(r.get("not_evaluated") is True for r in rows))
        self.assertEqual(event["tests"], len(rows))
        self.assertEqual(event["passed"], 0, "a simulated run claimed passes")
        self.assertEqual(event["failed"], 0, "a simulated run claimed failures")
        self.assertEqual(event["inconclusive"], len(rows))

    def test_simulated_event_agrees_with_the_report_summary(self):
        """One run, one answer: the event and the report must not disagree."""
        event, report = capture_simulated_event("mcp")
        s = report["summary"]
        for key in ("passed", "failed", "inconclusive"):
            with self.subTest(key=key):
                self.assertEqual(event[key], s[key])
        self.assertEqual(event["tests"], s["total"])


class VerdictCountsAreExact(unittest.TestCase):
    def test_object_rows(self):
        c = tel.verdict_counts(mixed_rows_as_objects())
        self.assertEqual(c, {"tests": 6, "passed": 2, "failed": 1, "inconclusive": 3})

    def test_dict_rows(self):
        c = tel.verdict_counts(mixed_rows_as_dicts())
        self.assertEqual(c, {"tests": 6, "passed": 2, "failed": 1, "inconclusive": 3})

    def test_counts_always_sum_to_tests(self):
        for rows in (mixed_rows_as_objects(), mixed_rows_as_dicts(), []):
            c = tel.verdict_counts(rows)
            self.assertEqual(c["tests"], c["passed"] + c["failed"] + c["inconclusive"])

    def test_status_only_rows_use_the_status_and_unknown_is_inconclusive(self):
        rows = [{"status": "PASS"}, {"status": "FAIL"}, {"status": "ERROR"},
                {"status": "INCONCLUSIVE"}, {"status": "SKIPPED"}, {}]
        c = tel.verdict_counts(rows)
        self.assertEqual(c, {"tests": 6, "passed": 1, "failed": 2, "inconclusive": 3})

    def test_a_row_with_no_verdict_is_never_a_pass(self):
        """Absence of a verdict is not a pass, whatever the residual bucket used to say."""
        self.assertEqual(tel.verdict_counts([{"test_id": "T-000"}])["passed"], 0)


class LivePathCountsAreThreeState(unittest.TestCase):
    def test_result_list_in_namespace(self):
        c = cli._live_run_counts({"results": mixed_rows_as_objects()})
        self.assertEqual(c, {"tests": 6, "passed": 2, "failed": 1, "inconclusive": 3,
                             "counts_available": True})

    def test_unittest_style_skipped_is_inconclusive_not_passed(self):
        class TR:
            testsRun = 10
            failures = [object()]
            errors = [object(), object()]
            skipped = [object(), object(), object()]
        c = cli._live_run_counts({"_test_result": TR()})
        self.assertEqual(c, {"tests": 10, "passed": 4, "failed": 3, "inconclusive": 3,
                             "counts_available": True})

    def test_empty_namespace_and_no_report_is_unavailable_not_zero(self):
        """R4-12. An installed AP2 run whose report held 17 rows was sent as
        0/0/0/0. Zero observations and unavailable counts are different
        states; the event must carry no count at all, with a fixed reason."""
        c = cli._live_run_counts({})
        self.assertEqual(c, {"counts_available": False,
                             "reason": cli.COUNTS_UNAVAILABLE_REASON})
        for key in ("tests", "passed", "failed", "inconclusive"):
            self.assertNotIn(key, c, f"{key} present: absence sent as a number")
        self.assertIn(cli.COUNTS_UNAVAILABLE_REASON, tel.COUNTS_UNAVAILABLE_REASONS)

    def test_a_written_report_is_read_when_the_namespace_is_empty(self):
        """The CLI already has the report the harness wrote; that is real data."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.json"
            path.write_text(json.dumps({"summary": {"total": 6},
                                        "results": mixed_rows_as_dicts()}))
            c = cli._live_run_counts({}, report_path=str(path))
        self.assertEqual(c, {"tests": 6, "passed": 2, "failed": 1, "inconclusive": 3,
                             "counts_available": True})

    def test_a_missing_or_empty_report_is_unavailable_not_zero(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "never-written.json"
            self.assertFalse(cli._live_run_counts({}, report_path=str(missing))["counts_available"])
            empty = Path(tmp) / "empty.json"
            empty.write_text(json.dumps({"summary": {"total": 0}, "results": []}))
            self.assertFalse(cli._live_run_counts({}, report_path=str(empty))["counts_available"])
            junk = Path(tmp) / "junk.json"
            junk.write_text("{not json")
            self.assertFalse(cli._live_run_counts({}, report_path=str(junk))["counts_available"])

    def test_namespace_results_win_over_a_report(self):
        """One run, one answer: the in-memory rows are the primary source."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.json"
            path.write_text(json.dumps({"results": [{"test_id": "T", "passed": True}]}))
            c = cli._live_run_counts({"results": mixed_rows_as_objects()}, report_path=str(path))
        self.assertEqual(c["tests"], 6)

    def test_the_live_call_site_passes_the_report_path(self):
        """Source-level: the dispatcher must hand the report path to the
        counter, or the report branch is dead code and 0/0/0/0 is back."""
        src = (REPO / "protocol_tests" / "cli.py").read_text(encoding="utf-8")
        self.assertIn("_live_run_counts(ns, report_path=_report_path_from(filtered_args))", src)


class ThePayloadMatchesItsDocumentedShape(unittest.TestCase):
    """No JSON schema exists for telemetry; PRIVACY.md's field table is the
    contract, and `telemetry_payload_example()` is the sample it points at."""

    def _sent_payload(self, **kw) -> dict:
        posted: list[bytes] = []

        class SyncThread:  # run the fire-and-forget POST inline so we can read it
            def __init__(self, target=None, args=(), daemon=None):
                self.target, self.args = target, args

            def start(self):
                self.target(*self.args)

        with patch.object(tel, "_is_disabled", return_value=False), \
                patch.object(tel, "_show_first_run_notice"), \
                patch.object(tel, "_post", side_effect=posted.append), \
                patch.object(tel.threading, "Thread", SyncThread):
            tel.send_telemetry_event(**kw)
        self.assertEqual(len(posted), 1)
        return json.loads(posted[0])

    def test_sent_payload_has_exactly_the_documented_keys(self):
        payload = self._sent_payload(module="mcp", tests=6, passed=2, failed=1, inconclusive=3)
        self.assertEqual(set(payload), PAYLOAD_KEYS)
        self.assertIs(payload["counts_available"], True)
        self.assertEqual((payload["tests"], payload["passed"], payload["failed"],
                          payload["inconclusive"]), (6, 2, 1, 3))
        for key in ("tests", "passed", "failed", "inconclusive"):
            self.assertIsInstance(payload[key], int)

    def test_unavailable_counts_are_omitted_not_zero(self):
        """R4-12. The event for a run of unknown size carries NO count field.
        `tests: 0` and `tests` absent are different facts, and the first one
        was being sent for a 17-row run."""
        payload = self._sent_payload(module="ap2", counts_available=False,
                                     reason=cli.COUNTS_UNAVAILABLE_REASON)
        self.assertEqual(set(payload), PAYLOAD_KEYS_UNAVAILABLE)
        self.assertIs(payload["counts_available"], False)
        self.assertEqual(payload["reason"], cli.COUNTS_UNAVAILABLE_REASON)
        for key in ("tests", "passed", "failed", "inconclusive"):
            self.assertNotIn(key, payload)

    def test_the_live_counter_output_is_sendable_in_both_states(self):
        """What `_live_run_counts` returns is exactly what the sender takes."""
        for state in (cli._live_run_counts({}),
                      cli._live_run_counts({"results": mixed_rows_as_objects()})):
            with self.subTest(counts_available=state["counts_available"]):
                payload = self._sent_payload(module="mcp", **state)
                self.assertEqual(payload["counts_available"], state["counts_available"])

    def test_the_reason_is_a_closed_vocabulary(self):
        with self.assertRaises(ValueError):
            self._sent_payload(module="mcp", counts_available=False, reason="target was slow")
        with self.assertRaises(ValueError):
            self._sent_payload(module="mcp", counts_available=False, reason=None)

    def test_available_counts_cannot_be_sent_with_a_count_missing(self):
        with self.assertRaises(ValueError):
            self._sent_payload(module="mcp", tests=None, passed=None, failed=None)

    def test_inconclusive_defaults_to_zero_for_older_callers(self):
        payload = self._sent_payload(module="mcp", tests=1, passed=1, failed=0)
        self.assertEqual(payload["inconclusive"], 0)

    def test_example_payloads_match_both_shapes(self):
        ex = tel.telemetry_payload_example()
        self.assertEqual(set(ex), PAYLOAD_KEYS)
        self.assertEqual(ex["tests"], ex["passed"] + ex["failed"] + ex["inconclusive"])
        ex2 = tel.telemetry_payload_example_counts_unavailable()
        self.assertEqual(set(ex2), PAYLOAD_KEYS_UNAVAILABLE)
        self.assertIn(ex2["reason"], tel.COUNTS_UNAVAILABLE_REASONS)

    def test_privacy_doc_lists_both_shapes(self):
        doc = (REPO / "docs" / "PRIVACY.md").read_text(encoding="utf-8")
        self.assertIn("| Inconclusive count |", doc)
        self.assertIn("| Counts available |", doc)
        self.assertIn("| Reason |", doc)
        self.assertIn("Ten fields when the counts are available, seven when they are not", doc)
        self.assertNotIn("Nine fields", doc)
        self.assertNotIn("Eight fields", doc)
        self.assertIn(cli.COUNTS_UNAVAILABLE_REASON, doc)


class TheDefectCannotBeReintroducedBySource(unittest.TestCase):
    """The simulated path must not hand the sender a count it made up."""

    @staticmethod
    def _telemetry_calls() -> list:
        tree = ast.parse((REPO / "protocol_tests" / "cli.py").read_text(encoding="utf-8"))
        return [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                and getattr(n.func, "id", getattr(n.func, "attr", None)) == "send_telemetry_event"]

    def test_cli_has_telemetry_call_sites(self):
        self.assertGreaterEqual(len(self._telemetry_calls()), 2,
                                "detector sees neither call site; it cannot be trusted")

    def test_cli_does_not_send_len_results_as_passed_or_failed_zero(self):
        for call in self._telemetry_calls():
            for kw in call.keywords:
                with self.subTest(line=call.lineno, keyword=kw.arg):
                    if kw.arg == "passed":
                        self.assertFalse(
                            isinstance(kw.value, ast.Call)
                            and getattr(kw.value.func, "id", None) == "len",
                            f"cli.py:{call.lineno} passes len(...) as the pass count")
                    if kw.arg == "failed":
                        self.assertFalse(
                            isinstance(kw.value, ast.Constant) and kw.value.value == 0,
                            f"cli.py:{call.lineno} sends failed=0 by construction")


if __name__ == "__main__":
    unittest.main()
