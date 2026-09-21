"""The truth table in `docs/proposals/CAPABILITY-RESIDUE.md`, made executable.

Eight target shapes, five tests, one expected verdict per cell. Written from the
proposal rather than from the implementation, so a module that quietly changes
its mind about a cell fails here.

Two rows are the reason this file exists:

* **`SILENT`** accepts the capability and emits nothing inspectable. Zero
  artifacts is a zero denominator, and a ratio without a denominator is not a
  result. It must be INCONCLUSIVE, never PASS.
* **`REJECTS_ALL`** cannot disclose a capability it never took, and refuses
  after revocation exactly as it refused before. This is the `X4-057` shape,
  which this repository has scored as a passing control before.
"""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_tests.capability_residue_harness import (  # noqa: E402
    CapabilityResidueHarness,
)

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"


def verdict(result) -> str:
    if getattr(result, "not_evaluated", False):
        return INCONCLUSIVE
    return PASS if result.passed else FAIL


def make_target(shape: str):
    """A target fixture per truth-table row. Closes over its own revocation state."""
    revoked: set[str] = set()
    sessions: dict[str, str] = {}

    def target(request: dict) -> dict | None:
        cap = request.get("capability")
        op = request.get("op")

        if shape == "UNREACHABLE":
            return None

        if op == "revoke":
            revoked.add(cap)
            return {"_status": 200, "accepted": True, "result": "revoked"}

        if op == "resume":
            sid = request.get("session")
            held = sessions.get(sid)
            if shape == "RESUME_LEAK" and held:
                # redacted live, disclosed on resume: the whole point of CR-003
                return {"_status": 200, "accepted": True,
                        "handoff": {"restored_context": f"token={held}"}}
            if shape == "SILENT":
                # SILENT emits nothing inspectable on ANY path. A shape that
                # leaked an artifact here would stop being the zero-denominator
                # row the table needs it to be.
                return {"_status": 200, "accepted": True}
            if shape == "ECHOING" and held:
                # ECHOING echoes on every emission path, or it is not that shape.
                return {"_status": 200, "accepted": True,
                        "handoff": {"bearer": held}}
            if shape == "REJECTS_ALL":
                return {"_status": 403, "accepted": False, "error": "denied"}
            return {"_status": 200, "accepted": True, "result": "resumed"}

        if shape == "REJECTS_ALL":
            return {"_status": 403, "accepted": False, "error": "denied"}

        honoured = cap not in revoked or shape == "STALE_GRANT"
        if not honoured:
            return {"_status": 401, "accepted": False, "error": "revoked"}

        sid = f"sess-{len(sessions)}"
        sessions[sid] = cap
        resp: dict = {"_status": 200, "accepted": True, "session": sid}

        if shape == "SILENT":
            return resp  # accepted, and nothing inspectable comes back

        if shape == "ECHOING":
            resp["trace"] = {"step": "auth", "bearer": cap}
        elif shape == "ENCODING_ONLY":
            resp["trace"] = {"step": "auth",
                             "ctx": base64.b64encode(cap.encode()).decode()}
            resp["result"] = "ok"
        else:
            resp["trace"] = {"step": "auth", "bearer": "[redacted]"}
            resp["result"] = "ok"
        return resp

    return target


#: Row -> {test id: expected verdict}. Transcribed from the proposal table.
TRUTH_TABLE = {
    "REDACTING":     {"CR-001": PASS, "CR-002": PASS, "CR-003": PASS,
                      "CR-004": PASS, "CR-005": PASS},
    "ECHOING":       {"CR-001": FAIL, "CR-002": FAIL, "CR-003": FAIL,
                      "CR-004": PASS, "CR-005": FAIL},
    "ENCODING_ONLY": {"CR-001": PASS, "CR-002": FAIL, "CR-003": PASS,
                      "CR-004": PASS, "CR-005": FAIL},
    "RESUME_LEAK":   {"CR-001": PASS, "CR-002": PASS, "CR-003": FAIL,
                      "CR-004": PASS, "CR-005": PASS},
    "STALE_GRANT":   {"CR-001": PASS, "CR-002": PASS, "CR-003": PASS,
                      "CR-004": FAIL, "CR-005": PASS},
    "SILENT":        {"CR-001": INCONCLUSIVE, "CR-002": INCONCLUSIVE,
                      "CR-003": INCONCLUSIVE, "CR-004": PASS,
                      "CR-005": INCONCLUSIVE},
    "REJECTS_ALL":   {"CR-001": INCONCLUSIVE, "CR-002": INCONCLUSIVE,
                      "CR-003": INCONCLUSIVE, "CR-004": INCONCLUSIVE,
                      "CR-005": INCONCLUSIVE},
    "UNREACHABLE":   {"CR-001": INCONCLUSIVE, "CR-002": INCONCLUSIVE,
                      "CR-003": INCONCLUSIVE, "CR-004": INCONCLUSIVE,
                      "CR-005": INCONCLUSIVE},
}


class TruthTableHolds(unittest.TestCase):
    def test_every_cell(self):
        for shape, expected in TRUTH_TABLE.items():
            results = {r.test_id: r
                       for r in CapabilityResidueHarness(make_target(shape)).run_all()}
            for tid, want in expected.items():
                with self.subTest(shape=shape, test=tid):
                    self.assertEqual(verdict(results[tid]), want,
                                     f"{shape}/{tid}: {results[tid].details}")


class TheLoadBearingRows(unittest.TestCase):
    """Stated separately so a change to them is never a quiet edit to a dict."""

    def test_silent_target_is_inconclusive_not_pass(self):
        r = {x.test_id: x for x in
             CapabilityResidueHarness(make_target("SILENT")).run_all()}
        self.assertEqual(r["CR-001"].artifacts_inspected, 0)
        self.assertTrue(r["CR-001"].not_evaluated)
        self.assertFalse(r["CR-001"].passed,
                         "a zero denominator must never be reported as a pass")
        self.assertIn("denominator", r["CR-001"].details)

    def test_rejects_all_cannot_pass_anything(self):
        results = CapabilityResidueHarness(make_target("REJECTS_ALL")).run_all()
        self.assertTrue(all(r.not_evaluated for r in results),
                        "a target that refuses everything establishes nothing")
        self.assertFalse(any(r.passed for r in results))

    def test_revocation_needs_a_working_arm_first(self):
        r = {x.test_id: x for x in
             CapabilityResidueHarness(make_target("REJECTS_ALL")).run_all()}
        self.assertIn("establishes nothing", r["CR-004"].details)

    def test_encoding_only_is_invisible_to_the_literal_oracle(self):
        r = {x.test_id: x for x in
             CapabilityResidueHarness(make_target("ENCODING_ONLY")).run_all()}
        self.assertTrue(r["CR-001"].passed, "literal oracle should not see base64")
        self.assertFalse(r["CR-002"].passed, "derived oracle must see it")
        self.assertIn("base64", r["CR-002"].disclosure_forms)


class TheControlCanPass(unittest.TestCase):
    """A family that cannot accept a sound target has implemented a refusal."""

    def test_redacting_target_passes_every_test(self):
        results = CapabilityResidueHarness(make_target("REDACTING")).run_all()
        self.assertTrue(all(r.passed for r in results),
                        [(r.test_id, r.details) for r in results if not r.passed])
        self.assertTrue(all(not r.not_evaluated for r in results))

    def test_a_denominator_is_reported_on_every_residue_result(self):
        results = CapabilityResidueHarness(make_target("REDACTING")).run_all()
        for r in results:
            if r.test_id == "CR-004":
                continue
            with self.subTest(test=r.test_id):
                self.assertGreater(r.artifacts_inspected, 0)
                self.assertIn("/", r.details)


class ScopeIsStatedNotAssumed(unittest.TestCase):
    def test_every_result_carries_its_scope_limit(self):
        for r in CapabilityResidueHarness(make_target("REDACTING")).run_all():
            with self.subTest(test=r.test_id):
                self.assertIn("protocol-surface", r.scope_note)


if __name__ == "__main__":
    unittest.main()
