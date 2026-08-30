"""The pinned upstream MCP reference server, and what the harness claims about it.

Every defect the three synthetic sweeps could NOT reach came from a real
implementation or from reading the source. An independent review asked for the
reference-server run to become a retained job rather than an afternoon, and to
keep the result CLASSES rather than collapsing them to a boolean.

    16 PASS   2 FAIL   14 INCONCLUSIVE / not applicable

The 14 are the signal a boolean would lose. Twelve are modern-MCP RC checks with
no authorized probe material, one is MCP-007 with no sampling capability, one is
MCP-011 whose defined outcomes were not observed. If a change quietly promoted
any of those to PASS, a green/red job would not notice.

## Unmeasured is not clean

This job needs `npx` and the pinned package in the local npm cache. When it
cannot run it skips, and a skip here means the calibration did not happen. It is
NOT evidence that the class split still holds.
`test_the_pin_is_a_fixed_version` runs regardless, so something is always
asserted even when the fixture is missing.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from mcp_reference_calibration import REFERENCE_SERVER, calibrate, server_command

#: Measured 2026-08-30 against @modelcontextprotocol/server-everything@2026.8.18
#: over stdio. Independently reproduced by a reviewer on the same day.
EXPECTED = {"PASS": 16, "FAIL": 2, "INCONCLUSIVE": 14}

#: The two FAILs are findings about this reference server in this configuration.
#: MCP-008: it ignores malformed messages without reporting a parse error.
#: MCP-018: a 10 MB body leaves the process alive and the session unanswerable.
EXPECTED_FAILS = {"MCP-008", "MCP-018"}


class TestThePinItself(unittest.TestCase):
    """Runs even when the server cannot be launched."""

    def test_the_pin_is_a_fixed_version(self):
        """A floating tag turns every upstream release into a local regression."""
        self.assertNotIn("@latest", REFERENCE_SERVER)
        self.assertRegex(
            REFERENCE_SERVER, r"@\d{4}\.\d{1,2}\.\d{1,2}$",
            f"{REFERENCE_SERVER!r} is not pinned to a specific version. Bumping "
            f"it is a deliberate edit and should come with a re-read of the "
            f"class split in EXPECTED.")


class TestReferenceCalibration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cmd = server_command()
        if cmd is None:
            raise unittest.SkipTest(
                "npx unavailable; reference calibration UNMEASURED, not clean")
        try:
            cls.report = calibrate(cmd)
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(
                f"pinned reference server did not launch ({exc}); calibration "
                f"UNMEASURED, not clean. Populate the npm cache to run it.")
        if not cls.report["launched"]:
            # The failure mode this file nearly shipped with. On a machine
            # without the pinned package cached, npx exists so Popen succeeds,
            # nothing answers, and the suite returns zero results. Comparing
            # those zeros to EXPECTED produced "the class split moved", which is
            # a confident and wrong description of a fixture that never started.
            raise unittest.SkipTest(
                "the MCP session never initialised, so the pinned reference "
                "server did not start (npx present, package not cached). "
                "Calibration UNMEASURED, not clean.")

    def test_the_suite_actually_produced_results(self):
        self.assertEqual(
            self.report["total"], sum(EXPECTED.values()),
            "result count moved; the suite or the server changed")

    def test_the_class_split_holds(self):
        self.assertEqual(
            self.report["counts"], EXPECTED,
            "the class split moved. This is the check that exists so an "
            "INCONCLUSIVE cannot quietly become a PASS. Read the diff before "
            "updating EXPECTED, and say which change moved it.")

    def test_the_failures_are_the_declared_ones(self):
        got = {r["test_id"] for r in self.report["rows"] if r["class"] == "FAIL"}
        self.assertEqual(
            got, EXPECTED_FAILS,
            f"different tests are failing against the reference server: {got}")

    def test_no_inconclusive_row_claims_a_pass(self):
        """The specific way this job earns its keep."""
        for row in self.report["rows"]:
            if row["class"] == "INCONCLUSIVE":
                with self.subTest(test_id=row["test_id"]):
                    self.assertNotIn("PASS", row["details"].upper()[:12])


if __name__ == "__main__":
    unittest.main()
