"""A simulated PASS must say, on the row, that it is a simulation.

`--simulate` means no target was contacted. Two shapes exist:

- The reference self-test: the module runs its reference verifier against its
  reference model, with positive controls. A PASS there is a real, exercised
  check -- about the reference, not about any deployment -- and the row says
  so (`verdict_scope`, `_simulated`, `simulated`, or `not_evaluated`).
- Fake-the-answer: the module fabricates the target's response and runs the
  real check against it. Every check passes by construction. Rows carry
  nothing; only the report carries `mode: simulation`.

The distinction matters because every consumer that reads ROWS -- the
evidence pack, the HTML renderer, top10_failures, attestation migration --
never sees a report-level marker. The third external review ran the installed
4.21.0 and watched simulated rows become published pass and failure claims.
A survey of the 24 harnesses declaring `--simulate` found 11 labelling every
simulated PASS per row and 8 labelling none (2026-09-07). Those 8 are seeded
below; the list may shrink and must never grow.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_tests.cli import HARNESSES, _module_declares_flag

#: A row-level marker that tells a row consumer this PASS is not about a target.
ROW_MARKERS = ("verdict_scope", "_simulated", "simulated", "not_evaluated")

#: Simulated PASS rows carry no row-level marker. Seeded 2026-09-07. Shrink only.
#: 2026-09-08 (R4-05): the five payment harnesses left the list -- their native
#: simulate rows are now INCONCLUSIVE with `simulated`, `verdict_scope`,
#: `not_evaluated` and the reference verdict under `reference_verdict`, written
#: by the one writer in harness_base; testing/test_native_simulate_is_scoped.py
#: pins the native path and every row consumer against it.
SEEDED_UNLABELLED_COUNT = 8
GRANDFATHERED_UNLABELLED = frozenset({
    "cloud-agents", "crewai-cve", "mcp-tool-poisoning",
})
#: Declares --simulate but writes no readable report we can inspect. Shrink only.
SEEDED_UNREADABLE_COUNT = 4
GRANDFATHERED_UNREADABLE = frozenset({"receipt-claim", "framework", "kill-switch", "watermark"})

#: Floor so a registry that stops declaring --simulate fails loudly.
KNOWN_SIMULATE_MODULES = 24


def _run(name: str, tmp: Path) -> dict | None:
    mod = HARNESSES[name]["module"]; rp = tmp / f"{name}.json"
    args = [sys.executable, "-m", mod, "--simulate"]
    args += ["--report", str(rp)] if _module_declares_flag(name, "--report") else ["--json"]
    try:
        cp = subprocess.run(args, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return None
    if rp.exists():
        try:
            return json.loads(rp.read_text())
        except ValueError:
            return None
    try:
        return json.loads(cp.stdout)
    except ValueError:
        return None


def _marked(row: dict) -> bool:
    return any(row.get(k) for k in ROW_MARKERS) or "simulat" in str(row.get("details", "")).lower()


class SimulatedPassesAreScoped(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.names = [h for h in HARNESSES if _module_declares_flag(h, "--simulate")]
        cls.tmp = Path(tempfile.mkdtemp(prefix="sim-scope-"))
        cls.reports = {n: _run(n, cls.tmp) for n in cls.names}

    def test_the_survey_found_something(self):
        self.assertGreaterEqual(len(self.names), KNOWN_SIMULATE_MODULES)

    def test_every_simulated_pass_carries_a_row_marker_unless_grandfathered(self):
        offenders = {}
        for n, d in self.reports.items():
            if d is None or n in GRANDFATHERED_UNLABELLED:
                continue
            rows = d.get("results", d if isinstance(d, list) else [])
            bad = [r.get("test_id") for r in rows
                   if isinstance(r, dict) and r.get("passed") is True and not _marked(r)]
            if bad:
                offenders[n] = bad
        self.assertEqual(offenders, {}, "a simulated PASS with no row-level scope marker; "
                         "a row consumer will publish it as a target pass")

    def test_unreadable_reports_are_only_the_grandfathered_ones(self):
        unreadable = {n for n, d in self.reports.items() if d is None}
        self.assertEqual(sorted(unreadable - GRANDFATHERED_UNREADABLE), [],
                         "a module declaring --simulate produced no readable report")

    def test_the_grandfather_lists_never_grew(self):
        self.assertLessEqual(len(GRANDFATHERED_UNLABELLED), SEEDED_UNLABELLED_COUNT)
        self.assertLessEqual(len(GRANDFATHERED_UNREADABLE), SEEDED_UNREADABLE_COUNT)

    def test_grandfathered_names_still_need_to_be_there(self):
        """A module that now labels its rows must be removed from the list."""
        for n in sorted(GRANDFATHERED_UNLABELLED):
            with self.subTest(n):
                self.assertIn(n, self.reports, "no longer declares --simulate; remove")
                d = self.reports[n]
                if d is None:
                    continue
                rows = d.get("results", [])
                self.assertTrue(any(isinstance(r, dict) and r.get("passed") is True and not _marked(r) for r in rows),
                                f"{n} now labels every simulated PASS; remove it from GRANDFATHERED_UNLABELLED")


if __name__ == "__main__":
    unittest.main()
