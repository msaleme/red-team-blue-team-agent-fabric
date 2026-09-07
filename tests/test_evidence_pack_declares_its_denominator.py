"""An AIUC-1 requirement must not read PASS on a subset of its own mapped tests.

`compute_aiuc1_coverage` derived `total` from the tests it *found in the report*
rather than the tests *mapped to the requirement*, and set `status = "PASS"`
whenever none of the found ones failed. A requirement declaring five tests, of
which two were present and both green, rendered as:

    | A003 | ... | **PASS** | 2 | 0 |

An auditor reading that row cannot distinguish it from a requirement whose five
mapped tests all ran and all passed. The missing three assert nothing, and the
artifact did not say they were missing -- the markdown never printed
`len(test_ids)` at all.

This is the defect class the harness's own AIUC-1 submission argues against: a
control named, mapped, and passing while the property was never exercised. The
OWASP path in the same file already emitted `tests_mapped` / `tests_run`; this
pins the same discipline on the AIUC-1 path and on both status vocabularies.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.evidence_pack import compute_aiuc1_coverage, generate_markdown


def req_index(mapped):
    return {
        "A003": {
            "title": "Test Requirement",
            "category": "safety",
            "status": "MAPPED",
            "test_ids": list(mapped),
        }
    }


def results_for(ids, passed=True):
    return [{"test_id": t, "passed": passed} for t in ids]


FIVE = ["T-001", "T-002", "T-003", "T-004", "T-005"]


class DenominatorIsDeclared(unittest.TestCase):
    def test_two_of_five_green_is_not_a_pass(self):
        cov = compute_aiuc1_coverage(results_for(FIVE[:2]), req_index(FIVE))
        r = cov["requirements"]["A003"]
        self.assertEqual(r["status"], "PARTIAL", "a passing subset must not read PASS")
        self.assertEqual(r["tests_mapped"], 5)
        self.assertEqual(r["tests_run"], 2)
        self.assertEqual(r["tests_absent"], ["T-003", "T-004", "T-005"])

    def test_all_five_green_is_a_pass(self):
        r = compute_aiuc1_coverage(results_for(FIVE), req_index(FIVE))["requirements"]["A003"]
        self.assertEqual(r["status"], "PASS")
        self.assertEqual((r["tests_mapped"], r["tests_run"]), (5, 5))
        self.assertEqual(r["tests_absent"], [])

    def test_a_failure_still_reads_fail_even_when_incomplete(self):
        """PARTIAL must never mask a real failure."""
        results = results_for(FIVE[:2], passed=True) + results_for(["T-003"], passed=False)
        r = compute_aiuc1_coverage(results, req_index(FIVE))["requirements"]["A003"]
        self.assertEqual(r["status"], "FAIL")

    def test_nothing_present_still_reads_no_results(self):
        r = compute_aiuc1_coverage([], req_index(FIVE))["requirements"]["A003"]
        self.assertEqual(r["status"], "NO_RESULTS")
        self.assertEqual(r["tests_mapped"], 5)
        self.assertEqual(r["tests_absent"], FIVE)

    def test_the_markdown_an_auditor_reads_shows_the_denominator(self):
        cov = compute_aiuc1_coverage(results_for(FIVE[:2]), req_index(FIVE))
        md = generate_markdown(
            {"total_tests": 2, "passed": 2, "failed": 0, "pass_rate": 1.0},
            cov,
            {},
            "test-target",
            "2026-09-07T00:00:00Z",
        )
        self.assertIn("Tests Mapped", md, "the AIUC-1 table must print the denominator")
        self.assertIn("PARTIAL", md)
        self.assertIn("Under-Exercised Requirements", md)
        self.assertIn("T-003", md, "the absent test IDs must be named, not just counted")
        self.assertNotIn(
            "No gaps, failures, or under-exercised requirements identified.",
            md,
            "an under-exercised requirement must not render as a clean pack",
        )


if __name__ == "__main__":
    unittest.main()
