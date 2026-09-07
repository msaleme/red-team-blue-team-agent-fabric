"""The three host sweeps run every registered harness, or say why not.

## The defect (R3-02, third external review, 2026-09-07)

`scripts/dead_host_sweep.py::_candidate_modules` -- shared by the permissive
and refusing sweeps -- chose modules by source text: a module was a candidate
if it contained the literal `def _record` and the literal `response_received`.
That matched 36 of the 46 registered harnesses (35 registered plus
`harness_base`, which is not a harness) and reported nothing about the other
ten. The ten included all five payment conformance modules, so R3-01 -- a
100% pass rate against a closed port -- sat in a gap the sweep could not see.

## What this pins

The candidate set is derived from `protocol_tests.cli.HARNESSES`, the one list
a harness must be on to be runnable from the CLI. Every registration is either
exercised or carries a reasoned `NOT_APPLICABLE` entry; the two are disjoint
and their union is the registry. Both the registry denominator and the
exercised set are floored, and a candidate that produces no row makes the
sweep raise rather than shrink.

The end-to-end failure path is exercised against `harness_base` -- a real
module with no suite class -- by narrowing the candidate list to it, so the
raise is measured rather than argued.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dead_host_sweep  # noqa: E402
from dead_host_sweep import (  # noqa: E402
    EXERCISED_FLOOR,
    NOT_APPLICABLE,
    REGISTRY_FLOOR,
    SweepCoverageError,
    _assert_every_candidate_exercised,
    _candidate_modules,
    registry_coverage,
    sweep,
)
from protocol_tests.cli import HARNESSES  # noqa: E402

#: The ten the text rule omitted. Every one must now be either exercised or
#: excused by name, so the gap that hid R3-01 cannot reopen under a new name.
PREVIOUSLY_OMITTED = {
    "ap2", "x402-fireblocks", "ucp-acp", "card-token", "settlement-finality",
    "delegation-chain", "hitl", "agent-data-injection", "receipt-claim",
    "mcp-supplychain", "community",
}


class TestTheCandidateSetIsTheRegistry(unittest.TestCase):
    def test_exercised_plus_excused_is_exactly_the_registry(self):
        cov = registry_coverage()
        exercised = set(cov["exercised"])
        excused = set(cov["not_applicable"])
        self.assertEqual(exercised & excused, set(), "a harness is both run and excused")
        self.assertEqual(exercised | excused, set(HARNESSES),
                         "a registered harness is neither exercised nor excused")

    def test_the_floors_hold_and_are_not_vacuous(self):
        cov = registry_coverage()
        self.assertGreaterEqual(REGISTRY_FLOOR, 46)
        self.assertGreaterEqual(len(cov["registry"]), REGISTRY_FLOOR)
        self.assertGreaterEqual(len(cov["exercised"]), EXERCISED_FLOOR)
        self.assertEqual(EXERCISED_FLOOR, REGISTRY_FLOOR - len(NOT_APPLICABLE),
                         "the exercised floor must move with the excuse list, "
                         "or an excuse can be added without the floor noticing")

    def test_every_excuse_names_a_registered_harness_with_a_reason(self):
        for name, reason in NOT_APPLICABLE.items():
            with self.subTest(harness=name):
                self.assertIn(name, HARNESSES)
                self.assertIsInstance(reason, str)
                self.assertGreaterEqual(
                    len(reason), 40,
                    "an excuse is a sentence about what the harness needs, not a tag")

    def test_the_previously_omitted_ten_are_now_accounted_for_by_name(self):
        cov = registry_coverage()
        accounted = set(cov["exercised"]) | set(cov["not_applicable"])
        self.assertEqual(PREVIOUSLY_OMITTED - accounted, set())
        # And the five R3-01 modules are RUN, not excused.
        for name in ("ap2", "x402-fireblocks", "ucp-acp", "card-token",
                     "settlement-finality"):
            self.assertIn(name, cov["exercised"], f"{name} must be exercised")

    def test_candidate_modules_are_the_exercised_stems_and_nothing_else(self):
        cov = registry_coverage()
        self.assertEqual(set(_candidate_modules()), set(cov["exercised"].values()))
        self.assertNotIn("harness_base", _candidate_modules(),
                         "harness_base is not a harness; it came from the text rule")

    def test_an_excuse_for_an_unregistered_name_is_refused(self):
        with mock.patch.dict(dead_host_sweep.NOT_APPLICABLE,
                             {"no-such-harness": "x" * 40}):
            with self.assertRaises(SweepCoverageError):
                registry_coverage()

    def test_a_shrunken_registry_is_refused(self):
        smaller = dict(list(HARNESSES.items())[:REGISTRY_FLOOR - 1])
        with mock.patch("protocol_tests.cli.HARNESSES", smaller):
            with self.assertRaises(SweepCoverageError):
                registry_coverage()


class TestTheSweepFailsRatherThanShrinks(unittest.TestCase):
    def test_a_candidate_with_no_row_raises(self):
        with self.assertRaises(SweepCoverageError) as ctx:
            _assert_every_candidate_exercised(
                ["a_harness", "b_harness"],
                [{"module": "a_harness", "status": "ran", "total": 1, "passed": 0,
                  "errors": 0, "passing_ids": []}])
        self.assertIn("b_harness", str(ctx.exception))

    def test_a_candidate_that_only_errored_raises(self):
        with self.assertRaises(SweepCoverageError):
            _assert_every_candidate_exercised(
                ["a_harness"],
                [{"module": "a_harness", "status": "TypeError: boom"}])

    def test_an_adapter_family_counts_by_its_module(self):
        _assert_every_candidate_exercised(
            ["fam"],
            [{"module": "fam::One", "status": "ran"},
             {"module": "fam::Two", "status": "ran-no-verdicts"}])

    def test_end_to_end_the_sweep_raises_on_a_module_with_no_suite(self):
        """Measured, not argued: harness_base really has no suite class."""
        with mock.patch.object(dead_host_sweep, "_candidate_modules",
                               return_value=["harness_base"]):
            with self.assertRaises(SweepCoverageError) as ctx:
                sweep()
        self.assertIn("harness_base", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
