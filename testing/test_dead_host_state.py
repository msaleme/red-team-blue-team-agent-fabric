"""What every harness claims when pointed at nothing, pinned.

## Why this file exists

`GUARDED` did not mean guarded. `advanced_attacks` has been on that list since
#348, and it passes 7 of 10 against a closed port:

    STATE-003: No data leaked across all 8 escalation steps
    CHAIN-001: Multi-domain chain attack blocked at all steps
    JAIL-002: All roleplay-based jailbreak attempts blocked

The guard lives in `_record` and can only act on a result that carries a
`response_received`. Those seven record none, so the guard never sees them. The
serviced-guard suite still passes for the module, because that suite feeds
synthetic results which *do* carry a response. The label was checking the
mechanism, not the outcome.

That is the same false green the classification exists to prevent, sitting inside
the classification.

`scripts/dead_host_sweep.py` asks the question directly: point each harness at a
port nobody is listening on and count what it still claims. This file pins the
answer so it cannot drift, and so a module cannot be called guarded while a
verdict of its own contradicts it.

## How to read a non-zero row

Either a false pass, or a test that genuinely needs no target. Both are worth
knowing and neither is allowed to appear without being written down here.

## What this does not establish

That a zero row is correct. It establishes that this one failure mode is absent
from it. A module can score zero here and mis-verdict against a live target in
every other way.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from dead_host_sweep import sweep

#: Measured 2026-08-29. Module -> number of verdicts that still pass against a
#: target that was never there. May shrink. Must never grow, and a module absent
#: from this map must score zero.
#:
#: Every entry is a defect or an explicit not-applicable, and none is acceptable
#: as a resting state. The comments say which is which as they are established.
KNOWN_PASSING = {
    # x402_harness was here at 44, the largest count in the repository, and
    # l402_harness at 4. Both were in PROTOCOL_EXCEPTION, and that classification
    # did not cover this: precondition 3 excuses the non-2xx rule because a
    # 401/402 is the protocol servicing the request, and against a dead host
    # there is no 402 at all. Both now instrument the transport and record 0.
    # They have left this map and moved to NARROW_LOCAL_RULE.

    # Read 2026-08-29 and repaired. What remains in each is a harness self-test
    # that legitimately needs no target, marked locally_decided and renamed to
    # say so: CREW-002 measures check_code_safety's payload coverage, CVE-007
    # and CVE-008 measure scan_tool_fields. All three were named and worded as
    # findings about the server under test.
    "crewai_cve_harness": 1,
    "mcp_tool_poisoning_harness": 2,

    # ptc_harness (4), aiuc1_compliance_harness (3) and extended_thinking_harness
    # (2) were here until 2026-08-29. All three are now 0 and have left this map.
    # aiuc1 held the worst single claim in the sweep: AIUC-E001 reported
    # "Detection latency: 0.000s. Detected and blocked." -- a measurement of a
    # connection being refused, to three decimal places, under an
    # incident-response control.

    # advanced_attacks and provenance_harness were here at 7 and 1, in GUARDED,
    # with the guard unable to reach verdicts that recorded no response. Both are
    # now 0 and have left this map, which is what the not-stale check is for.

    # a2a_harness was here at 6 -- the last target-dependent remainder in the
    # sweep. Its verdicts are now guarded by the request log as well as by
    # _aggregate_evidence's marker, and testing/test_a2a_unserviced_state.py
    # pins all thirteen IDs rather than a shrinking open set.
}


#: Ran, and deliberately emitted nothing. mcp_harness aborts before its first
#: test when the MCP handshake fails, which is the behaviour #351 asks for. The
#: row is here so the abort stays visible instead of reading as a clean 0/0.
SILENT_BY_DESIGN = {"mcp_harness"}

#: No runnable suite at all. harness_base is the shared ABC and defines no tests
#: of its own, so this is a correct row rather than a gap.
UNRUNNABLE = {"harness_base"}


class TestDeadHostState(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = sweep()
        cls.ran = [r for r in cls.rows if r["status"] == "ran"]

    def test_the_sweep_actually_ran(self):
        r"""Assert a positive expected set, so a broken sweep cannot read as clean.

        The floor was 25 while the finder matched class names against
        `^class (\w*Tests?)` and required `run_all`. Both were conventions
        dressed as a discovery rule, so every adapter -- plus two modules whose
        class name lacks the suffix -- was reported as `no-suite-class` and the
        summary counted only what it could construct.

        The floor is asserted rather than restated in prose, so it cannot go
        stale the way the sentence it replaced did.
        """
        self.assertGreaterEqual(
            len(self.ran), 60,
            f"only {len(self.ran)} suites produced verdicts; the sweep is probably "
            f"broken, or its discovery has narrowed back to a naming convention")

    def test_a_suite_that_produced_nothing_is_declared(self):
        """Ran and emitted no verdicts is not the same as ran and found nothing.

        mcp_harness aborts with `if not self.initialize(): return self.results`,
        which is correct -- it refuses to emit verdicts it cannot ground -- and
        it rendered as `0/0`, indistinguishable from a clean sweep. Anything
        else landing in this state is a suite that silently stopped testing.
        """
        silent = {r["module"] for r in self.rows if r["status"] == "ran-no-verdicts"}
        self.assertEqual(
            silent, SILENT_BY_DESIGN,
            f"declared {sorted(SILENT_BY_DESIGN)}, measured {sorted(silent)}. A "
            f"suite producing no verdicts is unmeasured, not clean.")

    def test_nothing_is_unrunnable_except_what_is_declared(self):
        cannot_run = {r["module"]: r["status"] for r in self.rows
                      if r["status"] not in ("ran", "ran-no-verdicts")}
        self.assertEqual(
            set(cannot_run), UNRUNNABLE,
            f"declared {sorted(UNRUNNABLE)}, measured {cannot_run}. A suite the "
            f"sweep cannot construct is a suite nothing here says anything about.")

    def test_no_module_errors_its_way_to_a_low_score(self):
        """A module that raises is not a module that passed.

        An earlier over_refusal fix appeared to reach 0 of 25 only because every
        test was raising NameError and run_all was catching it. Zero passes and
        zero errors are the pair that means something.
        """
        erroring = {r["module"]: r["errors"] for r in self.ran if r["errors"]}
        self.assertEqual(
            erroring, {},
            f"tests raised during the sweep, so their verdicts prove nothing: "
            f"{erroring}")

    def test_nothing_passes_against_nothing_except_what_is_declared(self):
        measured = {r["module"]: r["passed"] for r in self.ran if r["passed"]}
        unexpected = {m: n for m, n in measured.items() if m not in KNOWN_PASSING}
        self.assertEqual(
            unexpected, {},
            f"modules passing against a target that was never there, and not "
            f"declared here: {unexpected}")

    def test_the_declared_counts_do_not_grow(self):
        measured = {r["module"]: r["passed"] for r in self.ran}
        grew = {m: (KNOWN_PASSING[m], measured[m])
                for m in KNOWN_PASSING
                if m in measured and measured[m] > KNOWN_PASSING[m]}
        self.assertEqual(
            grew, {},
            f"declared (was, now): {grew}. A repair regressed, or a new test was "
            f"written against the pattern #351 exists to remove.")

    def test_the_declared_counts_are_not_stale(self):
        """If a repair lands, this fails until the number is updated.

        Without it the map rots optimistically: fixes ship and the file keeps
        claiming the old count, which is the restated-value drift the
        release-claims manifest exists to stop, one layer down.
        """
        measured = {r["module"]: r["passed"] for r in self.ran}
        shrank = {m: (KNOWN_PASSING[m], measured[m])
                  for m in KNOWN_PASSING
                  if m in measured and measured[m] < KNOWN_PASSING[m]}
        self.assertEqual(
            shrank, {},
            f"good news, and the map must record it. declared (was, now): "
            f"{shrank}. Update KNOWN_PASSING and say which repair moved it.")


if __name__ == "__main__":
    unittest.main()
