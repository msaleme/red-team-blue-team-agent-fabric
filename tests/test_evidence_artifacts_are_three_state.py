"""An explicitly INCONCLUSIVE report must not become a published failure claim.

Found on the installed 4.21.0 package by the third external review: the
evidence pack computed `failed = len(matched) - passed` at three sites and
`top10_failures` listed every non-pass as a failure. Neither file contained
the word `inconclusive`. A report every row of which said "the control was
not exercised" rendered as an AIUC-1 requirement FAILing, an OWASP category
FAILing, a pass rate of 0.0, and ten "top failures".

`html_report` had been fixed for this in #527; these two had not, and the
release notes said the residual bucket was gone "in three separate files".
It was gone in one.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.evidence_pack import compute_aiuc1_coverage, compute_owasp_coverage
from scripts.top10_failures import analyze_failures
import scripts.evidence_pack as _ep

INCONC = [{"test_id": t, "name": "x", "category": "c", "passed": False,
           "not_evaluated": True, "details": "INCONCLUSIVE - target did not service"}
          for t in ("T-001", "T-002", "T-003")]


def _idx():
    return {"A003": {"title": "t", "category": "c", "status": "MAPPED", "test_ids": ["T-001", "T-002", "T-003"]}}


class InconclusiveIsNotAFailure(unittest.TestCase):
    def test_aiuc1_requirement_is_inconclusive_not_fail(self):
        r = compute_aiuc1_coverage(INCONC, _idx())["requirements"]["A003"]
        self.assertEqual(r["failed"], 0, r); self.assertEqual(r["inconclusive"], 3, r)
        self.assertEqual(r["status"], "INCONCLUSIVE", r)

    def test_a_real_fail_still_wins(self):
        rows = INCONC[:2] + [{"test_id": "T-003", "name": "x", "category": "c", "passed": False, "details": "leaked"}]
        r = compute_aiuc1_coverage(rows, _idx())["requirements"]["A003"]
        self.assertEqual(r["failed"], 1); self.assertEqual(r["status"], "FAIL")

    def test_owasp_category_is_inconclusive_not_fail(self):
        # Tag the rows so asi_inventory-independent membership is exercised via results.
        rows = [dict(r, owasp_asi="ASI01") for r in INCONC]
        cov = compute_owasp_coverage(rows, _idx())
        for asi, d in cov.items():
            with self.subTest(asi):
                self.assertNotEqual(d["status"], "FAIL", d)

    def test_top10_lists_no_inconclusive_row_as_a_failure(self):
        report = {"suite": "s", "results": INCONC}
        failures = analyze_failures([report], {}, top_n=10)
        self.assertEqual([f["test_id"] for f in failures], [], failures)

    def test_the_overall_summary_is_three_state_with_no_rate_over_nothing(self):
        """The third residual site: the pack-level summary. An injection that
        restored `failed = total - passed` there passed every other test here.
        Calls build_evidence_pack with its real signature and reads the file
        it writes; an earlier version guessed the kwargs and failed on the
        correct code, which made its injection result meaningless."""
        import json, os, tempfile
        report = {"suite": "s", "timestamp": "2026-09-07T00:00:00Z",
                  "summary": {"total": 3, "passed": 0, "failed": 0}, "results": INCONC}
        with tempfile.TemporaryDirectory() as tmp:
            rp = os.path.join(tmp, "r.json")
            with open(rp, "w") as fh:
                json.dump(report, fh)
            out = _ep.build_evidence_pack(report_path=rp, target="t", output_dir=os.path.join(tmp, "pack"))
            summary = json.load(open(os.path.join(out, "evidence-summary.json")))["summary"]
        self.assertEqual(summary["failed"], 0, summary)
        self.assertEqual(summary["inconclusive"], 3, summary)
        self.assertEqual(summary["serviced"], 0, summary)
        self.assertIsNone(summary.get("pass_rate"), summary)

    def test_the_sample_report_is_in_the_public_tree(self):
        """The reproducibility fixture every doc cites must exist for a stranger."""
        import subprocess
        root = Path(__file__).resolve().parents[1]
        out = subprocess.run(["git", "ls-files", "reports/mcpstandard-dev-20260327.json"],
                             cwd=root, capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, "reports/mcpstandard-dev-20260327.json", "sample report is not tracked")


if __name__ == "__main__":
    unittest.main()
