"""A mixed PASS/INCONCLUSIVE requirement must not aggregate to PASS, in
either artifact, and the two artifacts must compute it with one rule.

Third external review, 2026-09-07 (R3-03). `scripts/evidence_pack.py` ruled
`FAIL if failed; INCONCLUSIVE if passed == 0; PARTIAL if a mapped test was
absent; else PASS` -- so a requirement with all five mapped tests present, one
PASS and four INCONCLUSIVE, published as PASS. `scripts/html_report.py` had no
PARTIAL state at all: two of five present and green rendered PASS. Four
private rules across two files for the same question.

Now one rule (`protocol_tests/aggregate.py`), both consumers, both tables.
PASS asserts every mapped member ran and held. Anything less is PARTIAL and
names the members, or INCONCLUSIVE when nothing was established.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_tests.aggregate import aggregate_state
from scripts.evidence_pack import (compute_aiuc1_coverage, compute_owasp_coverage,
                                   generate_markdown)
from scripts.html_report import (_compute_aiuc1, _compute_owasp, _partial_note,
                                 _status_badge)

REPO = Path(__file__).resolve().parents[1]
FIVE = ["T-001", "T-002", "T-003", "T-004", "T-005"]


def _idx(ids=FIVE):
    return {"A003": {"title": "t", "category": "c", "status": "MAPPED", "test_ids": list(ids)}}


def _pass(t):
    return {"test_id": t, "passed": True}


def _inconc(t):
    return {"test_id": t, "passed": False, "not_evaluated": True,
            "details": "INCONCLUSIVE - target did not service"}


def _fail(t):
    return {"test_id": t, "passed": False, "details": "leaked"}


def _one_pass_four_inconclusive(ids=FIVE):
    return [_pass(ids[0])] + [_inconc(t) for t in ids[1:]]


def _owasp_ids():
    from protocol_tests.asi_inventory import by_category
    cats = {k: v for k, v in by_category().items() if k}
    asi = sorted(cats)[0]
    return asi, list(dict.fromkeys(cats[asi]))


class TheRule(unittest.TestCase):
    def test_mixed_pass_and_inconclusive_all_present_is_partial_not_pass(self):
        s = aggregate_state(FIVE, {r["test_id"]: r for r in _one_pass_four_inconclusive()})
        self.assertEqual(s["status"], "PARTIAL", s)
        self.assertEqual((s["passed"], s["failed"], s["inconclusive"]), (1, 0, 4))
        self.assertEqual(s["tests_absent"], [])
        self.assertEqual(s["tests_inconclusive"], FIVE[1:], "the row must say WHICH")

    def test_subset_present_all_green_is_partial_and_names_the_absent(self):
        s = aggregate_state(FIVE, {t: _pass(t) for t in FIVE[:2]})
        self.assertEqual(s["status"], "PARTIAL")
        self.assertEqual(s["tests_absent"], FIVE[2:])
        self.assertEqual(s["tests_inconclusive"], [])

    def test_every_member_present_and_passing_is_pass(self):
        s = aggregate_state(FIVE, {t: _pass(t) for t in FIVE})
        self.assertEqual(s["status"], "PASS")
        self.assertEqual((s["tests_absent"], s["tests_inconclusive"]), ([], []))

    def test_any_failure_wins_over_partial(self):
        rows = {r["test_id"]: r for r in _one_pass_four_inconclusive()[:3]}
        rows["T-004"] = _fail("T-004")
        s = aggregate_state(FIVE, rows)
        self.assertEqual(s["status"], "FAIL")
        self.assertEqual(s["tests_failed"], ["T-004"])
        self.assertEqual(s["failed"], 1, "an inconclusive row is not a failed one")

    def test_nothing_established_is_inconclusive(self):
        s = aggregate_state(FIVE, {t: _inconc(t) for t in FIVE})
        self.assertEqual(s["status"], "INCONCLUSIVE")
        self.assertEqual(s["inconclusive"], 5)

    def test_nothing_present_uses_the_callers_name(self):
        self.assertEqual(aggregate_state(FIVE, {})["status"], "NOT_TESTED")
        self.assertEqual(aggregate_state(FIVE, {}, absent_status="NO_RESULTS")["status"],
                         "NO_RESULTS")

    def test_a_structurally_inconclusive_row_is_read_by_the_predicate_not_passed(self):
        """`passed: False` + `not_evaluated: True` is inconclusive, never a fail."""
        s = aggregate_state(["T-001"], {"T-001": {"test_id": "T-001", "passed": False,
                                                  "not_evaluated": True}})
        self.assertEqual(s["status"], "INCONCLUSIVE")
        self.assertEqual(s["failed"], 0)


class BothConsumersBothTables(unittest.TestCase):
    """The fixture the review used, through every public compute path."""

    def test_evidence_pack_aiuc1(self):
        r = compute_aiuc1_coverage(_one_pass_four_inconclusive(), _idx())["requirements"]["A003"]
        self.assertEqual(r["status"], "PARTIAL", r)
        self.assertEqual(r["tests_inconclusive"], FIVE[1:])

    def test_html_report_aiuc1(self):
        r = _compute_aiuc1(_one_pass_four_inconclusive(), _idx())["requirements"]["A003"]
        self.assertEqual(r["status"], "PARTIAL", r)
        self.assertEqual(r["tests_inconclusive"], FIVE[1:])

    def test_html_report_aiuc1_subset_is_not_pass(self):
        """The renderer had no PARTIAL state; 2 of 5 green rendered PASS."""
        r = _compute_aiuc1([_pass(t) for t in FIVE[:2]], _idx())["requirements"]["A003"]
        self.assertEqual(r["status"], "PARTIAL", r)
        self.assertEqual(r["tests_absent"], FIVE[2:])

    def test_evidence_pack_owasp(self):
        asi, ids = _owasp_ids()
        r = compute_owasp_coverage(_one_pass_four_inconclusive(ids), _idx())[asi]
        self.assertEqual(r["status"], "PARTIAL", r)
        self.assertEqual(r["inconclusive"], len(ids) - 1)

    def test_html_report_owasp(self):
        asi, ids = _owasp_ids()
        r = _compute_owasp(_one_pass_four_inconclusive(ids), _idx())[asi]
        self.assertEqual(r["status"], "PARTIAL", r)
        self.assertEqual(r["inconclusive"], len(ids) - 1)

    def test_html_report_owasp_subset_is_not_pass(self):
        asi, ids = _owasp_ids()
        r = _compute_owasp([_pass(t) for t in ids[:2]], _idx())[asi]
        self.assertEqual(r["status"], "PARTIAL", r)

    def test_the_two_consumers_agree_field_for_field(self):
        for rows in (_one_pass_four_inconclusive(), [_pass(t) for t in FIVE[:2]],
                     [_inconc(t) for t in FIVE], [_pass(t) for t in FIVE]):
            with self.subTest(status=rows[0]):
                a = compute_aiuc1_coverage(rows, _idx())["requirements"]["A003"]
                b = _compute_aiuc1(rows, _idx())["requirements"]["A003"]
                for k in ("status", "passed", "failed", "inconclusive", "tests_mapped",
                          "tests_run", "tests_absent", "tests_inconclusive"):
                    self.assertEqual(a[k], b[k], k)


class OneRuleNotFour(unittest.TestCase):
    """A consumer that grows its own rule again is the defect coming back.
    Source-level: each of the four compute sites calls the shared function and
    none re-derives a status from `passed == 0` or a bare `"PASS" if passed`."""

    def _body(self, path, start, end):
        src = (REPO / path).read_text()
        return src[src.index(start):src.index(end)]

    def test_each_compute_site_calls_the_shared_function(self):
        sites = [
            ("scripts/evidence_pack.py", "def compute_aiuc1_coverage", "def compute_owasp_coverage"),
            ("scripts/evidence_pack.py", "def compute_owasp_coverage", "def compute_evidence_hash"),
            ("scripts/html_report.py", "def _compute_aiuc1", "def _compute_owasp"),
            ("scripts/html_report.py", "def _compute_owasp", "_CSS = "),
        ]
        for path, start, end in sites:
            with self.subTest(site=f"{path}:{start}"):
                body = self._body(path, start, end)
                self.assertIn("aggregate_state(", body, "site does not call the shared rule")
                for private in ('passed == 0', '"PASS" if passed', '"PASS" if len(matched)',
                                'elif passed:', 'if failed else'):
                    self.assertNotIn(private, body, f"site grew its own rule: {private!r}")


class TheMixedStateIsVisible(unittest.TestCase):
    def test_markdown_names_the_inconclusive_members(self):
        cov = compute_aiuc1_coverage(_one_pass_four_inconclusive(), _idx())
        md = generate_markdown({"total_tests": 5, "passed": 1, "failed": 0, "pass_rate": 1.0},
                               cov, {}, "t", "2026-09-07T00:00:00Z")
        row = next(l for l in md.splitlines() if l.startswith("| A003 "))
        self.assertIn("**PARTIAL**", row)
        self.assertIn("Inconclusive", md, "the table must carry an Inconclusive column")
        self.assertIn("Under-Exercised Requirements", md)
        for t in FIVE[1:]:
            self.assertIn(t, md, "the inconclusive member IDs must be named")
        self.assertNotIn("No gaps, failures, or under-exercised requirements identified.", md)

    def test_markdown_owasp_table_has_an_inconclusive_column(self):
        asi, ids = _owasp_ids()
        ow = compute_owasp_coverage(_one_pass_four_inconclusive(ids), _idx())
        md = generate_markdown({"total_tests": 5, "passed": 1, "failed": 0, "pass_rate": 1.0},
                               {"covered": 0, "total": 0, "gaps": 0, "requirements": {}},
                               ow, "t", "ts")
        row = next(l for l in md.splitlines() if l.startswith(f"| {asi} "))
        self.assertIn("**PARTIAL**", row)
        self.assertIn(f"| {len(ids) - 1} |", row)

    def test_html_badge_is_partial_not_the_grey_fallback_and_names_members(self):
        r = _compute_aiuc1(_one_pass_four_inconclusive(), _idx())["requirements"]["A003"]
        html = _status_badge(r["status"]) + _partial_note(r)
        self.assertIn('class="badge badge-partial"', html)
        self.assertNotIn('badge-pass', html)
        self.assertNotIn('badge-na', html)
        for t in FIVE[1:]:
            self.assertIn(t, html)

    def test_html_partial_note_is_empty_for_a_pass(self):
        r = _compute_aiuc1([_pass(t) for t in FIVE], _idx())["requirements"]["A003"]
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(_partial_note(r), "")


if __name__ == "__main__":
    unittest.main()
