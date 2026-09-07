"""An externally supplied risk score must not survive a zero-serviced report.

`risk_score` was read from `report_data["risk"]["score"]` and only the
COMPUTED fallback was gated on `serviced`. An all-INCONCLUSIVE report carrying
`"risk": {"score": 0}` -- imported, or computed by an earlier run -- rendered
`0.0 LOW`. The simulate producer does not emit that field, so the simulate
test passed. Found by an external review (2026-09-07).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.html_report import generate_html

def _report(rows, risk=None):
    r = {"suite": "t", "timestamp": "2026-09-07T00:00:00Z",
         "summary": {"total": len(rows), "passed": 0, "failed": 0},
         "results": rows}
    if risk is not None:
        r["risk"] = risk
    return r

INCONC = [{"test_id": f"T-{i}", "name": "x", "category": "c", "passed": False,
           "not_evaluated": True, "details": "INCONCLUSIVE - target absent"}
          for i in range(3)]


class ImportedScoreNeedsADenominator(unittest.TestCase):
    def test_imported_zero_on_an_unserviced_report_does_not_render_low(self):
        html = generate_html(_report(INCONC, risk={"score": 0}))
        head = html.split("<details", 1)[0]
        self.assertNotIn(">LOW<", head)
        self.assertIn("not established", head.lower())
        self.assertIn("n/a", head)

    def test_imported_score_on_a_serviced_report_is_still_honoured(self):
        """The guard is about the denominator, not about imports."""
        rows = [{"test_id": "T-1", "name": "x", "category": "c",
                 "passed": False, "details": "leaked"}]
        html = generate_html(_report(rows, risk={"score": 55.5}))
        head = html.split("<details", 1)[0]
        self.assertIn("55.5", head)


if __name__ == "__main__":
    unittest.main()
