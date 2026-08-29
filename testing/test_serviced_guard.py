"""#348: five harnesses reported PASS against a target that never serviced the request.

v4.13.1 fixed exactly this in hitl_harness.py and defined ``_serviced`` inside
that module. It was never promoted, so MAG, AUDIT, CHAIN, MEM and INT kept the
defect: 64 tests whose verdict logic read "no attack indicator found" as
"the control held", including against a host that was not running.

This file is the part that matters. Without it the repair gets scoped to the
site of discovery a third time. Every harness that records a response is fed
the five unserviced conditions and must not yield a pass for any of them.
"""

from __future__ import annotations

import sys
import unittest
from dataclasses import fields
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.http_helpers import _serviced, inconclusive_detail  # noqa: E402

# The five ways a target can fail to service a request. The first three are
# what _err already caught; the last two are what it did not, and the JSON-RPC
# envelope inside a 200 is the one that shipped the original 20 false passes.
UNSERVICED = {
    "transport failure": {"_error": True, "_exception": "conn refused", "_status": 0},
    "http 404": {"_status": 404, "response": {}},
    "http 500": {"_status": 500, "response": {}},
    "200 with jsonrpc error in body": {
        "_status": 200,
        "response": {"jsonrpc": "2.0", "id": 1,
                     "error": {"code": -32601, "message": "Method not found"}},
    },
    "200 with top-level jsonrpc error": {
        "_status": 200, "error": {"code": -32601, "message": "Method not found"},
    },
}

SERVICED = {
    "_status": 200,
    "response": {"jsonrpc": "2.0", "id": 1, "result": {"parts": [{"text": "refused"}]}},
}

# (module, harness class, result class) for every harness carrying the guard.
GUARDED = [
    ("protocol_tests.multi_agent_harness", "MultiAgentTests", "MultiAgentTestResult"),
    ("protocol_tests.identity_harness", "IdentitySecurityTests", "IdentityTestResult"),
    ("protocol_tests.advanced_attacks", "AdvancedAttackTests", "AdvancedTestResult"),
    ("protocol_tests.memory_harness", "MemoryTests", "MemoryTestResult"),
    ("protocol_tests.intent_contract_harness", "IntentContractTests",
     "IntentContractTestResult"),
    # #350: found by deriving the candidate set below rather than by reading five files.
    ("protocol_tests.enterprise_adapters", None, "EnterpriseTestResult"),
    ("protocol_tests.extended_enterprise_adapters", None, "ExtTestResult"),
    # #351 sweep: flagged by verdict-shape triage, then confirmed by reading it.
    ("protocol_tests.cloud_agent_harness", None, "CloudAgentTestResult"),
    # #351: 11 of 11 verdicts response-decided, the highest ratio in the package.
    # Precondition 2 was recorded as the blocker; _serviced now reads both status
    # conventions, so it no longer is.
    ("protocol_tests.autogen_harness", "AutoGenHarness", "AutoGenTestResult"),
    # #351: 25 of 25 verdicts passed against a host that was not listening, the whole
    # suite. Every one read "<attack> was blocked" while response_received carried
    # {"_error": True, "_exception": "Connection refused"}. No simulate mode to protect,
    # shared http_post_json shape, and a non-2xx is not A2A servicing the request, so all
    # three preconditions were clear.
    ("protocol_tests.jailbreak_harness", "JailbreakTests", "JailbreakTestResult"),
    # #351: guard on the shared ABC, so every adapter subclass inherits it. Blocked
    # on precondition 1 until its simulate mode marked synthesised responses
    # "_simulated" instead of "simulate"; the marker was write-only, so renaming it
    # to the established convention was the whole unblock.
    ("protocol_tests.framework_adapters", None, "AdapterTestResult"),
    # #351: all three preconditions clear. Responses come from the shared
    # http_post, nothing is synthesised despite the module name, and no non-2xx
    # is a normal answer here.
    ("protocol_tests.gtg1002_simulation", "GTG1002Simulation", "GTGTestResult"),
    # #351: PRV-006 read `is_error or not accepted`, a pass because the target
    # errored -- the #350 shape, still live after two sweeps.
    ("protocol_tests.provenance_harness", "ProvenanceTests", "ProvenanceTestResult"),
    # #351: published as clean by the #372 analyser, which missed control-flow
    # taint. It has six response-decided verdicts and a live false pass.
    ("protocol_tests.governance_modification_harness", "GovernanceModificationTests",
     "GovernanceModTestResult"),
    # The shared base itself. It IS the guard, and has its own suite in
    # testing/test_harness_base_adoption.py.
    ("protocol_tests.harness_base", None, "HarnessResult"),
]

# Every module that records a target response, and is therefore capable of this defect.
# Derived, never hand-written: #348 was scoped to five harnesses by reading five files, and
# a sixth and seventh with the same defect survived it. A hand-maintained coverage list is
# the same failure the guard exists to prevent, one level up.
def _candidate_modules() -> set[str]:
    out = set()
    for path in sorted((REPO_ROOT / "protocol_tests").glob("*.py")):
        src = path.read_text()
        if "def _record" in src and "response_received" in src:
            out.add(path.stem)
    return out


# Guarding a module requires THREE things to be true, not one. The #351 sweep
# established this by trying to bulk-apply the guard to fourteen more of them and
# being stopped by the existing suite:
#
#   1. simulation must be marked. cloud_agent_harness synthesises
#      {"_status": 403, "_simulated": True} to mean the platform denied the action.
#      An unmarked simulator cannot be told apart from a target that failed.
#   2. the response-key convention must match. RESOLVED, and left here because the
#      resolution is the point: autogen_harness returns {"status": 200}, not
#      {"_status": 200}, so _serviced used to read a missing key as 0 and call a
#      healthy 200 unserviced. That was fixed in _serviced itself rather than by
#      rewriting seven harnesses' response shape, so the precondition is no longer
#      a blocker for anything. autogen_harness was guarded in #351 on that basis.
#      A precondition that has been resolved must be marked resolved: it stood
#      recorded as autogen's blocker after it had stopped being one.
#   3. a non-2xx must not be the protocol's normal answer. l402_harness and
#      x402_harness are payment-challenge protocols where a 401/402 IS the server
#      servicing the request. Guarding them converts correct passes into
#      INCONCLUSIVE.
#
# Modules that record a response and have NOT been checked against all three. Listing them
# is the honest state: #350 confirmed the defect in two of them by reading them, so the
# rest are unknown, not clean. Tracked in #351. Shrink this list by reviewing, never by
# deleting entries.
#
# Deliberately no count here. The previous wording said "two of the 28", which went stale
# the moment #355 guarded cloud_agent_harness and left the comment contradicting the
# tripwire twelve lines below it. len(UNREVIEWED) is the number; do not restate it in prose.
#
# The point of enumerating them is the assertion below: candidates must equal
# guarded + unreviewed exactly. A newly added harness lands in neither and fails the suite
# until someone classifies it. That is the difference between a guard that composes and a
# list that has to be remembered.
UNREVIEWED = {
    "a2a_harness",
    "aiuc1_compliance_harness",
    "benchmark_integrity_harness",
    "capability_profile_harness",
    "cbrn_harness",
    "crewai_cve_harness",
    "extended_thinking_harness",
    "harmful_output_harness",
    "incident_response_harness",
    "kill_switch_harness",
    "l402_harness",
    "mcp_harness",
    "mcp_tool_poisoning_harness",
    "over_refusal_harness",
    "prompt_caching_harness",
    "ptc_harness",
    "return_channel_harness",
    "skill_security_harness",
    "tool_search_harness",
    "watermark_harness",
    "x402_harness",
}

# Concrete subclasses for the two adapter modules, whose guard lives on an ABC base rather
# than on a single Tests class.
ADAPTER_CASES = [
    ("protocol_tests.enterprise_adapters", "OpenClawAdapter", "EnterpriseTestResult"),
    ("protocol_tests.extended_enterprise_adapters", "SnowflakeAdapter", "ExtTestResult"),
    ("protocol_tests.cloud_agent_harness", "BedrockAgentAdapter", "CloudAgentTestResult"),
    ("protocol_tests.framework_adapters", "LangChainAdapter", "AdapterTestResult"),
]


def _build(result_cls, **over):
    """Minimal valid result object, derived from the dataclass rather than guessed.

    An earlier version carried a hand-written table of field names and broke on
    every harness whose result class differed. Introspect instead: supply a
    type-appropriate placeholder for each field that has no default.
    """
    import dataclasses, typing
    kw = {}
    for f in fields(result_cls):
        if f.name in over:
            kw[f.name] = over[f.name]
            continue
        has_default = (f.default is not dataclasses.MISSING
                       or f.default_factory is not dataclasses.MISSING)  # type: ignore[misc]
        if has_default:
            continue
        t = f.type if not isinstance(f.type, str) else f.type
        ts = str(t)
        if "bool" in ts:
            kw[f.name] = True
        elif "int" in ts and "str" not in ts:
            kw[f.name] = 1
        elif "float" in ts:
            kw[f.name] = 0.0
        elif "dict" in ts:
            kw[f.name] = {}
        elif "list" in ts or "tuple" in ts:
            kw[f.name] = []
        else:
            kw[f.name] = "probe"
    kw.setdefault("passed", True)
    kw.setdefault("details", "control held")
    return result_cls(**kw)


class TestServicedIsShared(unittest.TestCase):
    def test_lives_in_http_helpers_not_one_harness(self) -> None:
        """The v4.13.1 fix was local. That is why it did not carry."""
        src = (REPO_ROOT / "protocol_tests" / "http_helpers.py").read_text()
        self.assertIn("def _serviced", src)

    def test_rejects_every_unserviced_shape(self) -> None:
        for label, resp in UNSERVICED.items():
            with self.subTest(label):
                self.assertFalse(_serviced(resp), f"{label} was treated as serviced")

    def test_inconclusive_detail_reports_the_status_that_was_actually_returned(self) -> None:
        """#351: a right verdict carrying wrong evidence.

        The message read only ``_status``, so a harness writing ``status`` had
        every INCONCLUSIVE reported as ``status=0`` -- a target that answered
        404 described as never answering. ``_serviced`` already read both
        conventions, so the verdict was correct and only the evidence attached
        to it was false, which is harder to notice and no less wrong.
        """
        for label, resp, expected in [
            ("status only", {"error": "x", "status": 404}, "status=404"),
            ("_status only", {"_status": 500}, "status=500"),
            ("both, _status wins", {"_status": 500, "status": 404}, "status=500"),
            ("transport failure", {"error": "x", "status": 0}, "status=0"),
        ]:
            with self.subTest(label):
                detail = inconclusive_detail(resp, "control held")
                self.assertIsNotNone(detail, f"{label} should be inconclusive")
                self.assertIn(expected, detail)

    def test_a_simulated_response_is_not_treated_as_unserviced(self) -> None:
        """#351: the false negative the sweep nearly introduced.

        cloud_agent_harness synthesises {"_status": 403, "_simulated": True} to mean
        the platform denied the action, which is the control working. An earlier
        version of this guard used _serviced() directly and converted all 25
        simulate-mode passes into failures.
        """
        self.assertIsNone(
            inconclusive_detail({"_status": 403, "_simulated": True}, "boundary enforced"),
            "a simulated response is a fixture standing in for an answer, not a "
            "target that failed to answer")
        self.assertIsNotNone(
            inconclusive_detail({"_status": 403, "message": "denied"}, "boundary enforced"),
            "a live 403 cannot be distinguished from credentials being rejected")

    def test_accepts_a_real_response(self) -> None:
        self.assertTrue(_serviced(SERVICED))


class TestNoHarnessPassesAnUnservicedTarget(unittest.TestCase):
    """The regression. Each guarded harness must refuse to record a pass."""

    def test_every_guarded_harness_downgrades_to_inconclusive(self) -> None:
        import importlib
        for mod_name, cls_name, res_name in GUARDED:
            if cls_name is None:
                continue  # adapter modules are covered by ADAPTER_CASES
            mod = importlib.import_module(mod_name)
            harness = getattr(mod, cls_name)("http://127.0.0.1:9")
            result_cls = getattr(mod, res_name)
            for label, resp in UNSERVICED.items():
                with self.subTest(f"{cls_name} / {label}"):
                    r = _build(result_cls, passed=True, response_received=resp)
                    harness.results = []
                    harness._record(r)
                    self.assertFalse(
                        r.passed,
                        f"{cls_name} recorded a PASS for '{label}' - "
                        "absence of a detected attack is not evidence a control held")
                    self.assertIn("INCONCLUSIVE", r.details)

    def test_a_serviced_pass_is_left_alone(self) -> None:
        """The guard must not turn real passes into failures."""
        import importlib
        for mod_name, cls_name, res_name in GUARDED:
            if cls_name is None:
                continue  # adapter modules are covered by ADAPTER_CASES
            mod = importlib.import_module(mod_name)
            harness = getattr(mod, cls_name)("http://127.0.0.1:9")
            r = _build(getattr(mod, res_name), passed=True, response_received=SERVICED)
            harness.results = []
            harness._record(r)
            with self.subTest(cls_name):
                self.assertTrue(r.passed, f"{cls_name} downgraded a serviced pass")
                self.assertNotIn("INCONCLUSIVE", r.details)

    def test_adapter_base_classes_guard_every_subclass(self) -> None:
        """#350: the guard sits on the ABC, so each adapter subclass inherits it."""
        import importlib
        for mod_name, cls_name, res_name in ADAPTER_CASES:
            mod = importlib.import_module(mod_name)
            result_cls = getattr(mod, res_name)
            for label, resp in UNSERVICED.items():
                with self.subTest(f"{cls_name} / {label}"):
                    a = getattr(mod, cls_name)("http://127.0.0.1:9")
                    a.results = []
                    r = _build(result_cls, passed=True, response_received=resp)
                    a._record(r)
                    self.assertFalse(
                        r.passed,
                        f"{cls_name} recorded a PASS for '{label}' - this module set "
                        "passed=True *because* the target errored")
                    self.assertIn("INCONCLUSIVE", r.details)
            with self.subTest(f"{cls_name} / serviced pass survives"):
                a = getattr(mod, cls_name)("http://127.0.0.1:9")
                a.results = []
                r = _build(result_cls, passed=True, response_received=SERVICED)
                a._record(r)
                self.assertTrue(r.passed)


class TestCoverageListIsDerived(unittest.TestCase):
    """#350: the ratchet. A new harness cannot be silently missed a fourth time."""

    def test_every_response_recording_module_is_classified(self) -> None:
        guarded = {m.rsplit(".", 1)[1] for m, _, _ in GUARDED}
        classified = guarded | UNREVIEWED
        candidates = _candidate_modules()
        unclassified = candidates - classified
        self.assertEqual(
            unclassified, set(),
            "these modules record a target response but are in neither GUARDED nor "
            f"UNREVIEWED: {sorted(unclassified)}. Check whether the verdict can be a pass "
            "when the target never serviced the request, then add the guard or list it.")
        stale = classified - candidates
        self.assertEqual(
            stale, set(), f"listed but no longer record a response: {sorted(stale)}")

    def test_unreviewed_does_not_grow(self) -> None:
        """A tripwire on the honest number, so the backlog cannot quietly expand."""
        self.assertLessEqual(
            len(UNREVIEWED), 21,
            "UNREVIEWED grew. A new module recording a response should be guarded or "
            "reviewed, not appended to the backlog.")


if __name__ == "__main__":
    unittest.main()
