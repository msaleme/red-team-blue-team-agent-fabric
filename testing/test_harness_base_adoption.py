"""New harnesses must inherit the shared recording base. Existing ones are grandfathered.

This is the architectural ratchet described in `protocol_tests/harness_base.py`.

The package reached 45 result dataclasses and 44 `_record` implementations of one
concept, which is why the same verdict defect had to be fixed in v4.13.1, #348,
#350 and #351: it had 44 possible homes and each repair reached only the files
someone opened.

Collapsing all 44 at once is not the move. The #351 sweep tried a bulk application
of a *one-line* guard across fourteen modules and turned 25 correct passes into
failures, because `l402_harness` and `x402_harness` are payment-challenge
protocols where a 401/402 is the server answering correctly, and `autogen_harness`
used a different status key. It had to be reverted.

So the rule is directional rather than sweeping:

- a module already in GRANDFATHERED may keep its own `_record`;
- a module NOT in that list must inherit `RecordingHarness`;
- the list may shrink as modules migrate, and must never grow.

That gives the abstraction to everything written from now on, at none of the risk
of rewriting what already works.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.harness_base import HarnessResult, RecordingHarness  # noqa: E402
from protocol_tests.http_helpers import inconclusive_detail  # noqa: E402

# Modules defining their own `_record` before the shared base existed.
# SHRINK ONLY. Removing a name means that module migrated; adding one means a new
# harness reintroduced the duplication this list exists to retire.
GRANDFATHERED = {
    "a2a_harness",
    "advanced_attacks",
    "aiuc1_compliance_harness",
    "ap2_harness",
    "autogen_harness",
    "benchmark_integrity_harness",
    "capability_profile_harness",
    "card_token_harness",
    "cbrn_harness",
    "cloud_agent_harness",
    "crewai_cve_harness",
    "enterprise_adapters",
    "extended_enterprise_adapters",
    "extended_thinking_harness",
    "framework_adapters",
    "governance_modification_harness",
    "gtg1002_simulation",
    "harmful_output_harness",
    "harness_base",
    "hitl_harness",
    "identity_harness",
    "incident_response_harness",
    "intent_contract_harness",
    "jailbreak_harness",
    "kill_switch_harness",
    "l402_harness",
    "mcp_harness",
    "mcp_supplychain",
    "mcp_tool_poisoning_harness",
    "memory_harness",
    "multi_agent_harness",
    "over_refusal_harness",
    "prompt_caching_harness",
    "provenance_harness",
    "ptc_harness",
    "receipt_claim_harness",
    "return_channel_harness",
    "settlement_finality_harness",
    "skill_security_harness",
    "tool_search_harness",
    "ucp_acp_harness",
    "watermark_harness",
    "x402_fireblocks_harness",
    "x402_harness",
}


def _modules_with_own_record() -> set[str]:
    return {p.stem for p in sorted((REPO_ROOT / "protocol_tests").glob("*.py"))
            if "def _record" in p.read_text()}


class TestGrandfatherListOnlyShrinks(unittest.TestCase):
    def test_no_new_module_defines_its_own_record(self) -> None:
        new = _modules_with_own_record() - GRANDFATHERED
        self.assertEqual(
            new, set(),
            f"these modules define their own _record and are not grandfathered: "
            f"{sorted(new)}. Inherit protocol_tests.harness_base.RecordingHarness "
            "instead, or call super()._record(result) from an override. A 45th "
            "parallel implementation is how the same defect survived four repairs.")

    def test_list_has_not_grown(self) -> None:
        self.assertLessEqual(
            len(GRANDFATHERED), 44,
            "GRANDFATHERED grew. It is a retirement list, not a registry.")

    def test_every_grandfathered_module_still_exists(self) -> None:
        missing = {m for m in GRANDFATHERED
                   if not (REPO_ROOT / "protocol_tests" / f"{m}.py").exists()}
        self.assertEqual(missing, set(), f"grandfathered but gone: {sorted(missing)}")


class TestRecordingHarnessBehaviour(unittest.TestCase):
    """The base must do the thing four separate repairs had to retrofit."""

    def _harness(self):
        class H(RecordingHarness):
            pass
        return H()

    def test_unserviced_result_is_downgraded(self) -> None:
        for label, resp in {
            "transport failure": {"_error": True, "_status": 0},
            "http 404": {"_status": 404},
            "http 500": {"_status": 500},
            "200 with jsonrpc error body": {
                "_status": 200,
                "response": {"error": {"code": -32601, "message": "nope"}}},
        }.items():
            with self.subTest(label):
                h = self._harness()
                r = HarnessResult(test_id="X-1", name="probe", owasp_asi="ASI01",
                                  severity="HIGH", passed=True, details="control held",
                                  response_received=resp)
                h._record(r)
                self.assertFalse(r.passed, f"{label} recorded a pass")
                self.assertIn("INCONCLUSIVE", r.details)

    def test_serviced_result_is_untouched(self) -> None:
        h = self._harness()
        r = HarnessResult(test_id="X-2", name="probe", owasp_asi="ASI01",
                          severity="HIGH", passed=True, details="control held",
                          response_received={"_status": 200,
                                             "response": {"result": {"ok": True}}})
        h._record(r)
        self.assertTrue(r.passed)
        self.assertNotIn("INCONCLUSIVE", r.details)

    def test_simulated_result_is_untouched(self) -> None:
        """The false negative the #351 sweep nearly shipped."""
        h = self._harness()
        r = HarnessResult(test_id="X-3", name="probe", owasp_asi="ASI01",
                          severity="HIGH", passed=True, details="denied by platform",
                          response_received={"_status": 403, "_simulated": True})
        h._record(r)
        self.assertTrue(r.passed)

    def test_result_with_no_response_is_untouched(self) -> None:
        """Informational tests set no response; there is nothing to adjudicate."""
        h = self._harness()
        r = HarnessResult(test_id="X-4", name="probe", owasp_asi="ASI01",
                          severity="LOW", passed=True, details="informational")
        h._record(r)
        self.assertTrue(r.passed)

    def test_results_list_is_per_instance(self) -> None:
        a, b = self._harness(), self._harness()
        a._record(HarnessResult(test_id="X-5", name="p", owasp_asi="ASI01",
                                severity="LOW", passed=True, details="d"))
        self.assertEqual(len(b.results), 0, "results leaked across instances")


class TestStatusKeyConvention(unittest.TestCase):
    """Both status conventions must be understood by one place, not 44."""

    def test_underscore_status_is_read(self) -> None:
        self.assertIsNone(inconclusive_detail({"_status": 200}, "d"))
        self.assertIsNotNone(inconclusive_detail({"_status": 404}, "d"))

    def test_bare_status_is_read_when_underscore_absent(self) -> None:
        """autogen_harness returns {"status": 200}; reading only _status called it dead."""
        self.assertIsNone(inconclusive_detail({"status": 200}, "d"))
        self.assertIsNotNone(inconclusive_detail({"status": 404}, "d"))

    def test_underscore_status_wins_when_both_present(self) -> None:
        self.assertIsNotNone(inconclusive_detail({"_status": 500, "status": 200}, "d"))


if __name__ == "__main__":
    unittest.main()
