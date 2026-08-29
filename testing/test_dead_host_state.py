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

    # Unread. Known-defective now, with a number attached.
    "crewai_cve_harness": 9,
    "mcp_tool_poisoning_harness": 8,
    "ptc_harness": 4,
    "aiuc1_compliance_harness": 3,
    "extended_thinking_harness": 2,

    # advanced_attacks and provenance_harness were here at 7 and 1, in GUARDED,
    # with the guard unable to reach verdicts that recorded no response. Both are
    # now 0 and have left this map, which is what the not-stale check is for.

    # In NARROW_LOCAL_RULE. Partially repaired, remaining six pinned in detail
    # by testing/test_a2a_unserviced_state.py.
    "a2a_harness": 6,
}


class TestDeadHostState(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = sweep()
        cls.ran = [r for r in cls.rows if r["status"] == "ran"]

    def test_the_sweep_actually_ran(self):
        """Assert a positive expected set, so a broken sweep cannot read as clean."""
        self.assertGreaterEqual(
            len(self.ran), 25,
            f"only {len(self.ran)} modules ran; the sweep is probably broken rather "
            f"than the repository having shrunk")

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
