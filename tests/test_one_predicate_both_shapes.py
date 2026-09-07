"""There is one inconclusive predicate, and it reads both result shapes.

An external review (2026-09-07) found `scripts/html_report._is_inconclusive`
reading `inconclusive` and `not_established` while the shared
`http_helpers.is_inconclusive` reads `not_evaluated` and `informational`.
Three rows classified differently in the two:

    FAIL carrying an honest limitation        reference FAIL   renderer INCONCLUSIVE
    structurally inconclusive, no prefix      reference INCONC renderer FAIL
    informational preflight, no prefix        reference INCONC renderer FAIL

The first is the worst: a legitimate failure removed from the serviced
denominator by adding a caveat. `not_established` is a claim-bound string --
"what this entry does NOT establish" -- and must never affect a verdict.

Root cause underneath the field names: the shared predicate used `getattr`,
which returns the default for every key on a dict, so a dict-shaped result
from a JSON report could never be inconclusive through it. That is why the
renderer grew its own. The fix is one predicate that reads both shapes.
"""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_tests.http_helpers import INCONCLUSIVE_FIELDS, is_inconclusive
from scripts.html_report import _is_inconclusive as renderer_is_inconclusive

ROWS = [
    # (name, fields, expected)
    ("FAIL carrying an honest limitation",
     dict(passed=False, details="Unauthorized effect observed",
          not_established="Deployment-wide security"), False),
    ("structurally inconclusive, no prefix",
     dict(passed=False, not_evaluated=True, details="Target absent"), True),
    ("informational preflight, no prefix",
     dict(passed=False, informational=True, details="Preflight only"), True),
    ("prefix only, no field",
     dict(passed=False, details="INCONCLUSIVE - target did not service"), True),
    ("plain PASS", dict(passed=True, details="ok"), False),
    ("plain FAIL", dict(passed=False, details="leaked"), False),
    ("simulate producer row",
     dict(passed=False, not_evaluated=True, simulated=True,
          details="INCONCLUSIVE - simulated run"), True),
]


class OnePredicateBothShapes(unittest.TestCase):
    def test_the_field_list_is_the_canonical_one(self):
        self.assertEqual(set(INCONCLUSIVE_FIELDS), {"not_evaluated", "informational"})

    def test_dict_and_object_agree_with_each_other_and_with_expected(self):
        for name, fields, expected in ROWS:
            with self.subTest(row=name):
                as_dict = is_inconclusive(dict(fields))
                as_obj = is_inconclusive(SimpleNamespace(**fields))
                self.assertEqual(as_dict, expected, f"dict shape: {name}")
                self.assertEqual(as_obj, expected, f"object shape: {name}")

    def test_the_renderer_is_the_same_predicate(self):
        for name, fields, expected in ROWS:
            with self.subTest(row=name):
                self.assertEqual(renderer_is_inconclusive(dict(fields)), expected, name)

    def test_a_limitation_never_changes_a_verdict(self):
        """Adding `not_established` to any row must not move it."""
        for name, fields, expected in ROWS:
            with self.subTest(row=name):
                with_limit = dict(fields, not_established="scope bounded to loopback")
                self.assertEqual(is_inconclusive(with_limit), expected, name)
                self.assertEqual(renderer_is_inconclusive(with_limit), expected, name)

    def test_the_renderer_has_no_field_list_of_its_own(self):
        src = (Path(__file__).resolve().parents[1] / "scripts" / "html_report.py").read_text()
        body = src[src.index("def _is_inconclusive"):src.index("def _status_badge")]
        for private in ('r.get("inconclusive")', 'r.get("not_established")',
                        'r.get("not_evaluated")', 'r.get("informational")'):
            self.assertNotIn(private, body, "renderer grew its own predicate again")


if __name__ == "__main__":
    unittest.main()
