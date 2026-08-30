"""Which suites can recognise a target that refuses everything.

## The third pole, and the one nobody checks

    closed port   the target never answered       a PASS is unfounded
    allow-all     the target granted everything   a PASS is unfounded
    deny-all      the target refused everything   a FAILURE to pass is a defect

The first two ask whether a verdict can be WRONG. This one asks whether it can
be RIGHT. A control that refuses every attack is the case these harnesses exist
to recognise, and a suite that cannot pass it is as broken as one that cannot
fail -- it just fails in the direction nobody looks.

## What this measured

Nine modules needed an exception to `http_helpers._serviced` during #351, found
one at a time and always after the module had already been repaired in the other
direction. `_serviced` treats a non-2xx as "the target did not service the
request", which is right for "method not found" and backwards wherever the
refusal IS the control working -- a 402 in x402, a 403 in an auth harness, a
JSON-RPC error envelope in a provenance harness.

The obvious next move was to apply the exception everywhere else. That would
have been a bulk-guard edit on a guess. Measuring instead produced a list, and
the list is not uniform:

  * governance_modification, kill_switch and incident_response were the
    identity_harness shape. Every control in them is a platform refusing an
    action, so a 403 is the control working and all three scored 0. Repaired
    here: 3 of 6, 2 of 4 and 6 of 8, while staying at 0 against the permissive
    and dead targets.

  * The modules listed below score 0 and have NOT been read. Some will be the
    same shape. Others test something a blanket refusal does not exercise -- a
    parser, a local scan, a rate limit -- and skill_security_harness makes no
    HTTP calls at all, so a refusing target is not a thing it can observe.

  * The chat-agent modules (jailbreak, memory, multi_agent, cbrn,
    harmful_output) are a third case and deliberately not changed. A 403 there
    is the TRANSPORT refusing, not the agent, and that is genuinely ambiguous.
    All of them do recognise a 200 carrying a prose refusal, which is the signal
    that actually belongs to them: jailbreak 25 of 25, memory 12 of 12,
    multi_agent 18 of 19 against an agent that declines in plain words.

Reading one family at a time is the recommendation of the independent review of
this sweep, and the reason this file pins a list rather than asserting zero.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from refusing_host_sweep import refusing_sweep

#: Repaired 2026-08-29. These recognise a refusal and must not stop.
RECOGNISES_A_REFUSAL = {
    "governance_modification_harness": 3,
    "kill_switch_harness": 2,
    "incident_response_harness": 6,
    "identity_harness": 10,
    "provenance_harness": 15,
}

#: Measured 2026-08-29. Suites that pass nothing against a target refusing every
#: request. NOT a defect list -- see the docstring. May shrink. Must never grow.
RECOGNISES_NO_REFUSAL = {
    "autogen_harness",
    "benchmark_integrity_harness",
    "capability_profile_harness",
    "cbrn_harness",
    "harmful_output_harness",
    "intent_contract_harness",
    "jailbreak_harness",
    "memory_harness",
    "multi_agent_harness",
    "prompt_caching_harness",
    "return_channel_harness",
    "skill_security_harness",
    # 2026-08-30: joined the list BY BEING REPAIRED. A 403 yields no tool
    # list, so there is nothing to scan and the honest verdict is
    # INCONCLUSIVE. Before the repair it passed 5 of 6 here, vacuously.
    "tool_search_harness",
    "watermark_harness",
}


class TestRefusingHostState(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = refusing_sweep()
        cls.ran = [r for r in cls.rows if r["status"] == "ran" and r["total"]]

    def test_the_sweep_actually_ran(self):
        self.assertGreaterEqual(
            len(self.ran), 55,
            f"only {len(self.ran)} suites produced verdicts against the refusing "
            f"target; discovery or the fixture is broken")

    def test_no_suite_errors_its_way_to_a_low_score(self):
        erroring = {r["module"]: r["errors"] for r in self.ran if r["errors"]}
        self.assertEqual(erroring, {}, f"tests raised during the sweep: {erroring}")

    def test_the_repaired_suites_still_recognise_a_refusal(self):
        """The direction this file exists for.

        A later change that re-applies the shared guard to any of these would
        take them silently back to zero, which no other check in the repository
        would notice: they would still score 0 against the dead host and 0
        against the permissive one, which is what a healthy module looks like
        from those two poles.
        """
        measured = {r["module"]: r["passed"] for r in self.ran}
        for module, expected in RECOGNISES_A_REFUSAL.items():
            with self.subTest(module=module):
                self.assertGreaterEqual(
                    measured.get(module, 0), expected,
                    f"{module} recognised {measured.get(module)} refusals, "
                    f"expected at least {expected}. A suite that cannot pass the "
                    f"one target shape it exists to recognise is as broken as one "
                    f"that cannot fail.")

    def test_the_blind_list_does_not_grow(self):
        measured = {r["module"]: r["passed"] for r in self.ran}
        blind = {m for m, p in measured.items() if p == 0}
        new = blind - RECOGNISES_NO_REFUSAL
        self.assertEqual(
            new, set(),
            f"these stopped recognising any refusal: {sorted(new)}. Either a "
            f"repair regressed, or a new suite was written that cannot pass a "
            f"target which refuses everything.")

    def test_the_blind_list_is_not_stale(self):
        measured = {r["module"]: r["passed"] for r in self.ran}
        fixed = {m for m in RECOGNISES_NO_REFUSAL if measured.get(m, 0) > 0}
        self.assertEqual(
            fixed, set(),
            f"good news, and the map must record it: {sorted(fixed)} now "
            f"recognise a refusal. Move them to RECOGNISES_A_REFUSAL with the "
            f"count and say which repair moved them.")


if __name__ == "__main__":
    unittest.main()
