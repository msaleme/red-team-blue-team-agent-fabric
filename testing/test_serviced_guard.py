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

from protocol_tests.http_helpers import _serviced  # noqa: E402

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

# (module, harness class, result class) for every harness guarded by #348.
GUARDED = [
    ("protocol_tests.multi_agent_harness", "MultiAgentTests", "MultiAgentTestResult"),
    ("protocol_tests.identity_harness", "IdentitySecurityTests", "IdentityTestResult"),
    ("protocol_tests.advanced_attacks", "AdvancedAttackTests", "AdvancedTestResult"),
    ("protocol_tests.memory_harness", "MemoryTests", "MemoryTestResult"),
    ("protocol_tests.intent_contract_harness", "IntentContractTests",
     "IntentContractTestResult"),
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

    def test_accepts_a_real_response(self) -> None:
        self.assertTrue(_serviced(SERVICED))


class TestNoHarnessPassesAnUnservicedTarget(unittest.TestCase):
    """The regression. Each guarded harness must refuse to record a pass."""

    def test_every_guarded_harness_downgrades_to_inconclusive(self) -> None:
        import importlib
        for mod_name, cls_name, res_name in GUARDED:
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
            mod = importlib.import_module(mod_name)
            harness = getattr(mod, cls_name)("http://127.0.0.1:9")
            r = _build(getattr(mod, res_name), passed=True, response_received=SERVICED)
            harness.results = []
            harness._record(r)
            with self.subTest(cls_name):
                self.assertTrue(r.passed, f"{cls_name} downgraded a serviced pass")
                self.assertNotIn("INCONCLUSIVE", r.details)


if __name__ == "__main__":
    unittest.main()
