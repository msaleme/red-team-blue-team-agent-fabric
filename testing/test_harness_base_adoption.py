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

import ast
import sys
import tempfile
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


def _defines_own_record(source: str) -> bool:
    """A class in `source` defines a method named `_record`, read from the AST.

    Until 2026-09-08 this was the substring test `"def _record" in text`. A
    module spelling it `def  _record(` -- two spaces, valid Python -- was
    invisible to it, so a 45th parallel implementation could be added and
    every test in this file stayed green (fourth external review, R4-13). The
    floor below proves the familiar files remain visible; it says nothing
    about syntax the rule never matched. The AST does not care about
    whitespace, comments, decorators or `async`.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and member.name == "_record":
                    return True
    return False


def _modules_with_own_record(package_dir: Path | None = None) -> set[str]:
    """Stems of the modules in `package_dir` whose classes define `_record`.

    `package_dir` defaults to the shipped package; it is a parameter so the
    anti-vacuity tests below can point the same detector at a seeded module
    instead of writing into the package.
    """
    package_dir = package_dir if package_dir is not None else REPO_ROOT / "protocol_tests"
    return {p.stem for p in sorted(package_dir.glob("*.py"))
            if _defines_own_record(p.read_text(encoding="utf-8"))}


class TestGrandfatherListOnlyShrinks(unittest.TestCase):
    def test_no_new_module_defines_its_own_record(self) -> None:
        new = _modules_with_own_record() - GRANDFATHERED
        self.assertEqual(
            new, set(),
            f"these modules define their own _record and are not grandfathered: "
            f"{sorted(new)}. Inherit protocol_tests.harness_base.RecordingHarness "
            "instead, or call super()._record(result) from an override. A 45th "
            "parallel implementation is how the same defect survived four repairs.")

    def test_the_detector_still_sees_the_grandfathered_modules(self) -> None:
        """Anti-vacuity. With `_modules_with_own_record()` returning an empty
        set, every test in this file passed -- including with a NEW module
        defining its own `_record` seeded alongside (third external review,
        R3-08). A detector that sees nothing has nothing to compare, and the
        ratchet reads that as clean. Every grandfathered module must remain
        visible to discovery; a detector that loses one has broken, not
        improved."""
        seen = _modules_with_own_record()
        self.assertGreaterEqual(len(seen), len(GRANDFATHERED),
                                "the detector found fewer modules than are grandfathered")
        invisible = GRANDFATHERED - seen
        self.assertEqual(invisible, set(),
                         f"grandfathered modules the detector no longer sees: {sorted(invisible)}")

    def test_list_has_not_grown(self) -> None:
        self.assertLessEqual(
            len(GRANDFATHERED), 44,
            "GRANDFATHERED grew. It is a retirement list, not a registry.")

    def test_every_grandfathered_module_still_exists(self) -> None:
        missing = {m for m in GRANDFATHERED
                   if not (REPO_ROOT / "protocol_tests" / f"{m}.py").exists()}
        self.assertEqual(missing, set(), f"grandfathered but gone: {sorted(missing)}")


class TestTheDetectorReadsSyntaxNotText(unittest.TestCase):
    """R4-13. A detector that matches one spelling of a definition is a
    detector of that spelling. Each seed here is a module that DOES define its
    own `_record`, written the way the old substring rule could not see."""

    SEEDS = {
        "two_spaces": "class Seed:\n    def  _record(self, result):\n        pass\n",
        "tab": "class Seed:\n    def\t_record(self, result):\n        pass\n",
        "async": "class Seed:\n    async def _record(self, result):\n        pass\n",
        "decorated": ("class Seed:\n    @staticmethod\n    def _record(result):\n"
                      "        pass\n"),
        "nested_class": ("class Outer:\n    class Inner:\n        def  _record(self, r):\n"
                         "            pass\n"),
        "plain": "class Seed:\n    def _record(self, result):\n        pass\n",
    }

    def test_every_seeded_spelling_is_seen(self) -> None:
        for label, src in self.SEEDS.items():
            with self.subTest(seed=label):
                self.assertTrue(_defines_own_record(src), f"{label!r} seed is invisible")

    def test_a_seeded_module_in_a_temp_package_enters_the_set(self) -> None:
        """The whole path, on disk: the exact shape the review seeded."""
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp)
            (pkg / "zz_whitespace_seed.py").write_text(self.SEEDS["two_spaces"], encoding="utf-8")
            (pkg / "zz_inherits.py").write_text(
                "from protocol_tests.harness_base import RecordingHarness\n"
                "class Fine(RecordingHarness):\n    pass\n", encoding="utf-8")
            seen = _modules_with_own_record(pkg)
        self.assertIn("zz_whitespace_seed", seen)
        self.assertNotIn("zz_inherits", seen, "inheriting the base is not defining _record")

    def test_a_record_that_is_not_a_method_is_not_counted(self) -> None:
        """The rule is about harness classes. A module-level helper, a call
        site, a string or a comment mentioning `def _record` is not a 45th
        implementation, and the old text rule counted all four."""
        for label, src in {
            "call": "class H:\n    def run(self):\n        self._record(1)\n",
            "comment": "# def _record lives in harness_base\nclass H:\n    pass\n",
            "string": 'DOC = "def _record"\nclass H:\n    pass\n',
            "module_level": "def _record(result):\n    pass\n",
        }.items():
            with self.subTest(shape=label):
                self.assertFalse(_defines_own_record(src))

    def test_the_detector_agrees_with_the_inventory_facts(self) -> None:
        """#543 reads the same fact off the imported module
        (`asi_inventory.recording_facts()["defines_record"]`). Two derivations
        of one fact must agree on every registered harness, or one of them is
        a naming convention again."""
        from protocol_tests.asi_inventory import harness_modules, recording_facts
        seen = _modules_with_own_record()
        disagreements = []
        for dotted in harness_modules():
            stem = dotted.rsplit(".", 1)[-1]
            if recording_facts(dotted)["defines_record"] != (stem in seen):
                disagreements.append(stem)
        self.assertEqual(disagreements, [])


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
