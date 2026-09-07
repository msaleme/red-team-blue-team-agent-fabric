"""A run that contacted nothing must not render as a clean bill of health.

Two defects, one page.

`_simulate_harness` emitted `"passed": True` for every test in the catalog, so
`agent-security test <h> --simulate --html out.html` produced a self-contained
artifact reading 100% pass, risk score 0.0 LOW, AUROC 1.0000 "Excellent" -- for
a run that contacted no target at all. The repo's own schema already defines the
right word: `inconclusive` means "the control was not exercised".

And `scripts/html_report.py` was a two-state renderer, so correcting the source
alone would have inverted the lie into 100% FAIL -- a fail asserts the control
did not hold, which an unexercised control cannot establish.

Separately, `cli.py` never caught the `SystemExit` that every harness `main()`
raises, so the whole `--html` block was unreachable on the live-target path:
`--html` is advertised in `print_usage()` and produced a file for 0 of 45
harnesses, with exit 0 and no warning.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def run_cli(*args, timeout=180):
    return subprocess.run(
        [sys.executable, "-m", "protocol_tests.cli", *args],
        cwd=REPO, capture_output=True, text=True, timeout=timeout,
    )


class SimulateIsInconclusive(unittest.TestCase):
    def test_simulated_rows_are_inconclusive_not_passed(self):
        done = run_cli("test", "mcp", "--simulate", "--json")
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertTrue(report["results"], "no rows to check")
        for r in report["results"]:
            with self.subTest(test_id=r.get("test_id")):
                self.assertFalse(r["passed"], "a simulated row claimed a pass")
                self.assertTrue(r["not_evaluated"], "canonical structural marker")
                self.assertNotIn("inconclusive", r, "no renderer-private field")
                self.assertTrue(r["details"].upper().startswith("INCONCLUSIVE"))

    def test_the_summary_has_no_rate_because_nothing_was_serviced(self):
        report = json.loads(run_cli("test", "mcp", "--simulate", "--json").stdout)
        s = report["summary"]
        self.assertEqual(s["passed"], 0)
        self.assertEqual(s["failed"], 0)
        self.assertEqual(s["inconclusive"], s["total"])
        self.assertEqual(s["serviced"], 0)
        self.assertIsNone(s["pass_rate"], "a rate of zero is a claim; absence is not")
        self.assertEqual(report["status"], "inconclusive")


class TheRenderedPageMakesNoClaim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sim-html-")
        cls.path = os.path.join(cls.tmp, "evidence.html")
        done = run_cli("test", "mcp", "--simulate", "--html", cls.path)
        assert done.returncode == 0, done.stderr
        assert os.path.exists(cls.path), f"no file produced: {done.stderr}"
        cls.html = Path(cls.path).read_text()

    def test_the_page_was_produced_at_all(self):
        self.assertGreater(len(self.html), 2000)

    def test_no_pass_rate_and_no_risk_score_is_asserted(self):
        for claim in ("100.0%", ">LOW<", "1.0000"):
            with self.subTest(claim=claim):
                self.assertNotIn(claim, self.html)

    def test_the_reader_is_told_why_without_expanding_anything(self):
        """The old page disclosed simulation only inside collapsed <details>.

        "Without expanding anything" means everything before the first
        `<details>` element -- none of which are rendered `open`.
        """
        visible = self.html.split("<details", 1)[0]
        self.assertIn("nothing was serviced", visible)
        self.assertIn("Inconclusive", visible)
        self.assertIn("not established", visible.lower())

    def test_every_row_renders_as_inconclusive(self):
        """Match badge USE, not the CSS rule that defines it.

        `assertNotIn("badge-pass", html)` matched the stylesheet, which every
        page carries whether or not a single row is a pass.
        """
        self.assertIn('class="badge badge-inconclusive"', self.html)
        self.assertNotIn('class="badge badge-pass"', self.html)
        self.assertNotIn('class="badge badge-fail"', self.html)


class HtmlIsReachableOnTheLivePath(unittest.TestCase):
    def test_html_produces_a_file_against_an_unreachable_target(self):
        """The block used to be dead code: exit 0, no file, no warning."""
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "live.html")
            done = run_cli("test", "mcp", "--url", "http://127.0.0.1:9/mcp",
                           "--html", out)
            self.assertTrue(
                os.path.exists(out),
                f"--html produced no file on the live path "
                f"(exit {done.returncode})\n{done.stderr[-600:]}",
            )
            self.assertGreater(os.path.getsize(out), 2000)


if __name__ == "__main__":
    unittest.main()
