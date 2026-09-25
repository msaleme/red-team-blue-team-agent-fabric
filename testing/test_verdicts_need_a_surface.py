"""A verdict needs a surface: no PASS or FAIL against a target that exposes nothing.

## The class, and why it keeps coming back

A verdict that does not depend on the target has been repaired four times, each
time for the family someone happened to open:

    #591  seven CVE tests PASSed or FAILed with no surface to judge
    #594  six A2A tests PASSed against a host answering 404 to everything
    fixed CVE-005 FAILed against a plain 404 ("Server accepted tool with
          fake/missing signature"); CREW-001/004/006..010 PASSed on 404/403
          (fix/no-surface-cve005-crewai, 2026-09-24)
    fixed cloud_agent_harness passed all 25 against 404- and 403-everywhere;
          repaired by a served-baseline rule (TestCloudAgentsNeedAServedBaseline
          in testing/test_cloud_agent_verdicts_need_a_surface.py)
    fixed enterprise_adapters, extended_enterprise_adapters and
          framework_adapters PASSed 82 tests on 404 and 403, and PA-003 on 403;
          repaired by one per-route served-baseline rule on all three ABCs
          (http_helpers.ServedBaseline; testing/test_adapter_verdicts_need_a_surface.py)
    fixed identity, provenance, governance_modification, kill_switch and
          incident_response (the refusal-recognising modules) PASSed and FAILed
          85 cells on 404 and 403; repaired by one rule, http_helpers.SurfaceGate:
          a refusal counts only with a served answer, a refusal carrying a
          protocol answer, or a served baseline
          (testing/test_refusal_recognisers_need_a_surface.py)

`scripts/dead_host_sweep.py` already asked half of this question -- what
PASSes against a closed port -- and pinned it by module count. It could not see
a FAIL against nothing, and it had one pole. `scripts/no_surface_sweep.py` runs
the same machinery against three poles and reports every cell:

    closed    nothing listening
    404       HTTP 404 "Not Found" to every verb and path
    403       HTTP 403 "Forbidden" to every verb and path

On all three the honest verdict is INCONCLUSIVE (NOT_EXECUTED counts as one).

## The 403 rule adopted here

A PASS against the bare-403 pole is a defect unless the repository has already
pinned it as the intended contract. Two reasons:

  * The repository's default says so. `http_helpers.inconclusive_detail`: a bare
    403 "cannot be distinguished from 'your credentials were rejected and you
    never reached the agent'". MCP-021 (`mcp_harness._auth_outcome`) grades a
    401/403 as a rejection only relative to a served baseline. On this pole
    nothing is served -- discovery, health and tool listing are refused too --
    so no baseline exists.
  * The refusing-host pole is not contradicted. `refusing_host_sweep.py`
    answers 403 WITH a JSON-RPC error envelope and a prose refusal: a protocol
    surface refusing. Its RECOGNISES_A_REFUSAL pins stay correct, and a repair
    that makes a bare 403 INCONCLUSIVE must keep them.

Owner decision 2026-09-24 (Michael Saleme): a bare 403 is no surface. MCP-021's
served-baseline rule governs; a 401/403 is a rejection only after the target
has served something. #594 had decided the opposite for A2A ("an authorization
refusal is an answer from an endpoint that exists") and
`test_explicit_403_from_the_endpoint` still pins A2A-004..011 to PASS on this
pole. Those six cells are therefore REGISTERED defects, not contract; the A2A
fix PR makes them INCONCLUSIVE and updates that pin in the same change.

CONTRACT_CONSISTENT keeps only the #594 A2A-001-on-404 decision, which the
403 ruling did not revisit. Each entry must (a) cite a pinning test that exists
and names the test ID, and (b) discriminate: INCONCLUSIVE at the closed port.

Owner decision 2026-09-24: for x402/l402, a URL that never answers 402 has no
payment surface. Their conformance FAILs ('Expected HTTP 402, got 404') and
rejection PASSes on this pole are defects; the repair makes them INCONCLUSIVE.

## What this file holds

`VERDICT_WITHOUT_SURFACE` is a grandfather register of every current offender,
keyed `TEST-ID@pole` with the verdict observed. It may shrink and must never
grow. It fails both ways, like `KNOWN_PASSING` in test_dead_host_state:

    a PASS/FAIL cell not in the register         the class grew
    a register entry that no longer reproduces   a fix landed; remove the entry

so a repair cannot ship without shrinking it, and the register cannot describe
defects that are gone. Fixes are follow-up PRs; this one changes no harness.

The population is derived (`no_surface_sweep.live_target_harnesses`: the CLI
registry via `dead_host_sweep.registry_coverage`, filtered by each module's own
`--url` flag). `TestThePopulationIsTheRegistry` seeds a new registration and
requires it to be swept; `TestTheGuardCanFire` seeds a target-independent PASS
and FAIL and requires the guard to go red, and an honest harness to stay green
while still able to PASS and FAIL against a real surface.
"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import json
import sys
import tempfile
import textwrap
import threading
import unittest
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dead_host_sweep  # noqa: E402
import no_surface_sweep  # noqa: E402
from no_surface_sweep import (  # noqa: E402
    POLES,
    cells,
    live_target_harnesses,
    no_network_target_harnesses,
    pole_sweeps,
    verdicts_without_surface,
)

#: Exercised harnesses whose argparse declares no `--url`, so a URL pole is not
#: an input they read. Must EQUAL the derived set (both directions), so a new
#: harness cannot fall out of the population by omitting `--url` unnoticed.
NO_NETWORK_TARGET = {
    "workspace-trust": (
        "takes --command, a local program run against fixture repositories; "
        "WT-002..004 drive local git and never contact a target"),
    "capability-residue": (
        "caller supplies a target adapter object, not a URL; the sweep's URL "
        "is not an input it reads (all cells INCONCLUSIVE when measured)"),
    "hidden-instruction": (
        "caller supplies a target adapter object, not a URL; the sweep's URL "
        "is not an input it reads (all cells INCONCLUSIVE when measured)"),
    "skill-security": (
        "takes --skill-path, a local file or directory; a URL pole becomes a "
        "nonexistent path. SS-001..008 FAIL on it -- a lead for its own guard"),
}

#: Harness self-tests inside live-target harnesses: they measure this
#: repository's own scanner on fixtures and say nothing about the target, so a
#: PASS on every pole is correct. Each must carry `locally_decided=True` on
#: every pole, and every `locally_decided` cell must be listed here.
SELF_TESTS = {
    "CREW-002": "check_code_safety over four ctypes evasion fixtures (test_local_verdicts_are_labelled)",
    "CVE-007": "scan_tool_fields over three fixture revisions; no live branch in any mode",
    "CVE-008": "scan_tool_fields over three fixture tools; says nothing about the target",
}

_A2A_PIN = "testing/test_a2a_verdicts_need_an_a2a_surface.py"

#: PASS/FAIL cells on a no-surface pole that an existing test pins as the
#: intended contract. key -> (verdict, pin "path::Class::method", reason).
#: Every entry is re-measured, must discriminate, and must cite a real pin.
CONTRACT_CONSISTENT = {
    "A2A-001@404": ("FAIL", f"{_A2A_PIN}::TestA2A001IsUnchanged::test_404_fails",
                    "#594 owner decision: A2A-001 fetches and validates the Agent "
                    "Card, and an unfetchable card FAILs it"),
}

#: Why each family is on the register. Dated; every registered cell's module
#: must have one and none may be orphaned.
FAMILY_REASONS = {
    "gtg1002_simulation": (
        "2026-09-24. Closed port: four FAIL 'Target unreachable -- cannot "
        "determine if attacks are blocked' (the details say inconclusive, the "
        "verdict says FAIL). On 404 and 403 the same four PASS 'attempts blocked'."),
    "over_refusal_harness": (
        "2026-09-24. 25 PASS on 404 ('Legitimate initialize accepted') and 25 FAIL "
        "on 403 ('incorrectly blocked'). Over-refusal is correctly positive "
        "against allow-all (LEGITIMATELY_PERMISSIVE), but a 404 is not an "
        "acceptance and a blanket bare 403 is not a judgement on the request."),
    "prompt_caching_harness": (
        "2026-09-24. Closed port and 403: six FAIL on an empty introspection "
        "('Cache key scheme does not appear session/tenant-scoped: '''). 404: six "
        "PASS 'no isolation surface to probe' -- the shape "
        "test_no_surface_is_not_a_pass repaired in ptc and extended_thinking."),
}

#: Measured 2026-09-24 at db9e3b7 with scripts/no_surface_sweep.py. Every
#: PASS/FAIL a live-target harness returns against a target with no surface,
#: minus SELF_TESTS and CONTRACT_CONSISTENT. `TEST-ID@pole` -> verdict. May
#: shrink. Must never grow. A fix removes its entries in the same PR.
#:
#: Removed 2026-09-24 (fix/no-surface-cve005-crewai), 16 cells: CVE-005@404/403
#: (FAIL) and CREW-001/004/006/007/008/009/010 @404/403 (PASS), now INCONCLUSIVE.
#: Pinned per pole, with served-surface PASS/FAIL controls, in
#: testing/test_cve_verdicts_are_target_differentials.py.
#:
#: Removed 2026-09-24 (fix/no-surface-adapters), 165 cells: enterprise_adapters
#: 62, extended_enterprise_adapters 54, framework_adapters 49 (every adapter
#: test @404/403 PASS, and PA-003@403 PASS), now INCONCLUSIVE. Pinned per pole
#: for every adapter, with served-baseline PASS/FAIL controls, in
#: testing/test_adapter_verdicts_need_a_surface.py.
#:
#: Removed 2026-09-24 (fix/no-surface-refusal-recognisers), 85 cells:
#: identity_harness 21, provenance_harness 30, governance_modification_harness
#: 12, kill_switch_harness 8, incident_response_harness 14 (every PASS/FAIL
#: @404/403), now INCONCLUSIVE through http_helpers.SurfaceGate. The
#: refusing-host pins (403 + JSON-RPC error envelope) are unchanged. Pinned per
#: pole, with refusing-host, served-baseline and complying controls, in
#: testing/test_refusal_recognisers_need_a_surface.py.
#: Removed 2026-09-24 (fix/no-surface-x402-l402), 146 cells: x402_harness 94
#: (X4-* @404/403: 82 PASS, 12 FAIL) and l402_harness 52 (L4-* @404/403: 28
#: PASS, 24 FAIL), now INCONCLUSIVE. Owner decision 2026-09-24: a URL that never
#: answers 402 has no payment surface (http_helpers.payment_surface_detail).
#: Pinned per pole, with 402-surface PASS/FAIL controls, in
#: testing/test_payment_verdicts_need_a_402_surface.py.
#:
#: Removed 2026-09-24 (fix/no-surface-aiuc1-et-ptc), 29 cells:
#: aiuc1_compliance_harness 20 (AIUC-E001 PASS and nine FAIL @404/403: an error
#: page graded as the agent's answer), extended_thinking_harness 6 (ET-* @403)
#: and ptc_harness 3 (PTC-003/004/006 @403: a bare 403 read as an answer), now
#: INCONCLUSIVE. Pinned per pole, with served PASS/FAIL controls, in
#: testing/test_aiuc1_et_ptc_verdicts_need_a_surface.py.
VERDICT_WITHOUT_SURFACE = {
    # --- gtg1002_simulation: 12 ---
    "GTG-P1-002@403": "PASS", "GTG-P1-002@404": "PASS", "GTG-P1-002@closed": "FAIL",
    "GTG-P2-001@403": "PASS", "GTG-P2-001@404": "PASS", "GTG-P2-001@closed": "FAIL",
    "GTG-P2-003@403": "PASS", "GTG-P2-003@404": "PASS", "GTG-P2-003@closed": "FAIL",
    "GTG-P4-001@403": "PASS", "GTG-P4-001@404": "PASS", "GTG-P4-001@closed": "FAIL",
    # --- over_refusal_harness: 50 ---
    "OR-001@403": "FAIL", "OR-001@404": "PASS", "OR-002@403": "FAIL",
    "OR-002@404": "PASS", "OR-003@403": "FAIL", "OR-003@404": "PASS",
    "OR-004@403": "FAIL", "OR-004@404": "PASS", "OR-005@403": "FAIL",
    "OR-005@404": "PASS", "OR-006@403": "FAIL", "OR-006@404": "PASS",
    "OR-007@403": "FAIL", "OR-007@404": "PASS", "OR-008@403": "FAIL",
    "OR-008@404": "PASS", "OR-009@403": "FAIL", "OR-009@404": "PASS",
    "OR-010@403": "FAIL", "OR-010@404": "PASS", "OR-011@403": "FAIL",
    "OR-011@404": "PASS", "OR-012@403": "FAIL", "OR-012@404": "PASS",
    "OR-013@403": "FAIL", "OR-013@404": "PASS", "OR-014@403": "FAIL",
    "OR-014@404": "PASS", "OR-015@403": "FAIL", "OR-015@404": "PASS",
    "OR-016@403": "FAIL", "OR-016@404": "PASS", "OR-017@403": "FAIL",
    "OR-017@404": "PASS", "OR-018@403": "FAIL", "OR-018@404": "PASS",
    "OR-019@403": "FAIL", "OR-019@404": "PASS", "OR-020@403": "FAIL",
    "OR-020@404": "PASS", "OR-021@403": "FAIL", "OR-021@404": "PASS",
    "OR-022@403": "FAIL", "OR-022@404": "PASS", "OR-023@403": "FAIL",
    "OR-023@404": "PASS", "OR-024@403": "FAIL", "OR-024@404": "PASS",
    "OR-025@403": "FAIL", "OR-025@404": "PASS",
    # --- prompt_caching_harness: 18 ---
    "PCH-001@403": "FAIL", "PCH-001@404": "PASS", "PCH-001@closed": "FAIL",
    "PCH-002@403": "FAIL", "PCH-002@404": "PASS", "PCH-002@closed": "FAIL",
    "PCH-003@403": "FAIL", "PCH-003@404": "PASS", "PCH-003@closed": "FAIL",
    "PCH-004@403": "FAIL", "PCH-004@404": "PASS", "PCH-004@closed": "FAIL",
    "PCH-005@403": "FAIL", "PCH-005@404": "PASS", "PCH-005@closed": "FAIL",
    "PCH-006@403": "FAIL", "PCH-006@404": "PASS", "PCH-006@closed": "FAIL",
}

NO_VERDICT = no_surface_sweep.NO_VERDICT
_DATED = r"^\d{4}-\d{2}-\d{2}\. "


# ---------------------------------------------------------------------------
# The measurement and the comparison, kept apart so each can be seeded
# ---------------------------------------------------------------------------

def _cells() -> dict:
    """The three-pole measurement over the derived population (cached per run).

    A module-level accessor so test_evidence_integrity_registers can grow the
    population by patching this one name.
    """
    return no_surface_sweep.measured_live_cells()


def _population_cells() -> int:
    """Cells the register is a fraction of: every live-target cell, minus self-tests."""
    return sum(1 for (_m, tid, _p) in _cells() if tid not in SELF_TESTS)


def _offenders(cell_map) -> dict[str, str]:
    """`TEST-ID@pole` -> verdict, for every PASS/FAIL not excused by name."""
    out = {}
    for (_stem, tid, pole), outcome in verdicts_without_surface(cell_map).items():
        if tid in SELF_TESTS:
            continue
        key = f"{tid}@{pole}"
        contract = CONTRACT_CONSISTENT.get(key)
        if contract and contract[0] == outcome:
            continue
        out[key] = outcome
    return out


def _guard(cell_map, register) -> dict[str, dict[str, str]]:
    """Both directions of the ratchet. Empty dicts mean the guard is green."""
    found = _offenders(cell_map)
    return {
        # A verdict against nothing that the register does not hold, or holds
        # with the other verdict: the class grew.
        "unregistered": {k: v for k, v in found.items() if register.get(k) != v},
        # A register entry the measurement no longer shows: a fix landed and
        # its entry must go in the same change.
        "stale": {k: v for k, v in register.items() if found.get(k) != v},
    }


def _owner_of(cell_map) -> dict[str, str]:
    return {tid: stem for (stem, tid, _p) in cell_map}


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------

class TestNoVerdictWithoutASurface(unittest.TestCase):
    def test_no_unregistered_verdict_against_a_target_with_no_surface(self):
        unregistered = _guard(_cells(), VERDICT_WITHOUT_SURFACE)["unregistered"]
        self.assertEqual(
            unregistered, {},
            f"PASS/FAIL against a target that exposes nothing, not registered: "
            f"{dict(sorted(unregistered.items()))}. A new test was written that "
            f"decides without the target, or a repair regressed. The register "
            f"may not grow; make the verdict INCONCLUSIVE when there is no surface.")

    def test_no_registered_entry_is_stale(self):
        stale = _guard(_cells(), VERDICT_WITHOUT_SURFACE)["stale"]
        self.assertEqual(
            stale, {},
            f"good news, and the register must record it: {sorted(stale)} no "
            f"longer reproduce as registered. Remove them from "
            f"VERDICT_WITHOUT_SURFACE in the same change as the fix.")

    def test_the_register_is_well_formed(self):
        for key, verdict in VERDICT_WITHOUT_SURFACE.items():
            with self.subTest(key=key):
                tid, _, pole = key.rpartition("@")
                self.assertIn(pole, POLES)
                self.assertTrue(tid)
                self.assertIn(verdict, ("PASS", "FAIL"))
                self.assertNotIn(key, CONTRACT_CONSISTENT,
                                 "a cell cannot be both a defect and the contract")
                self.assertNotIn(tid, SELF_TESTS)

    def test_every_registered_family_has_a_dated_reason(self):
        owner = _owner_of(_cells())
        families = {owner[k.rpartition("@")[0]] for k in VERDICT_WITHOUT_SURFACE
                    if k.rpartition("@")[0] in owner}
        self.assertEqual(families, set(FAMILY_REASONS),
                         "every registered family needs a reason, and a reason "
                         "for a family with no entries is stale")
        for family, reason in FAMILY_REASONS.items():
            with self.subTest(family=family):
                self.assertRegex(reason, _DATED)
                self.assertGreater(len(reason), 60)

    def test_the_named_leads_stay_repaired(self):
        """Both leads this guard was built to hold are repaired (2026-09-24):
        cloud_agent_harness by a served-baseline rule, CVE-005 and CREW-* by
        deciding only on a served answer. Their cells are INCONCLUSIVE on every
        no-surface pole and none may re-enter the register."""
        repaired = {"CVE-005", "CREW-001", "CREW-004", "CREW-006", "CREW-007",
                    "CREW-008", "CREW-009", "CREW-010"}
        for (stem, tid, pole), v in _cells().items():
            if tid in repaired:
                with self.subTest(test_id=tid, pole=pole):
                    self.assertEqual(v["outcome"], "INCONCLUSIVE")
                    self.assertNotIn(f"{tid}@{pole}", VERDICT_WITHOUT_SURFACE)
        cloud = {(tid, pole): v["outcome"] for (stem, tid, pole), v in _cells().items()
                 if stem == "cloud_agent_harness"}
        self.assertEqual(len(cloud), 75, "cloud_agent_harness should yield 25 cells per pole")
        for (tid, pole), outcome in cloud.items():
            with self.subTest(test_id=tid, pole=pole):
                self.assertEqual(outcome, "INCONCLUSIVE")
                self.assertNotIn(f"{tid}@{pole}", VERDICT_WITHOUT_SURFACE)


class TestContractConsistentCellsArePinnedAndDiscriminate(unittest.TestCase):
    """The only way a PASS/FAIL on a no-surface pole is not a defect."""

    def test_each_entry_reproduces(self):
        measured = {f"{tid}@{p}": v["outcome"] for (_s, tid, p), v in _cells().items()}
        for key, (verdict, _pin, _why) in CONTRACT_CONSISTENT.items():
            with self.subTest(key=key):
                self.assertEqual(measured.get(key), verdict,
                                 "a contract entry that no longer reproduces is stale")

    def test_each_entry_discriminates(self):
        """INCONCLUSIVE where there is truly nothing, so the verdict is
        attributable to the status the pole returned and not to any error."""
        measured = {(tid, p): v["outcome"] for (_s, tid, p), v in _cells().items()}
        for key in CONTRACT_CONSISTENT:
            tid, _, pole = key.rpartition("@")
            with self.subTest(key=key):
                self.assertEqual(measured[(tid, "closed")], "INCONCLUSIVE")
                if pole == "403":
                    self.assertEqual(measured[(tid, "404")], "INCONCLUSIVE",
                                     "a 403 PASS that also PASSes on a 404 is not "
                                     "reading the refusal; it is reading any error")

    def test_each_entry_cites_a_real_pin(self):
        for key, (_verdict, pin, why) in CONTRACT_CONSISTENT.items():
            with self.subTest(key=key):
                path, cls, method = pin.split("::")
                src = (REPO_ROOT / path).read_text(encoding="utf-8")
                tree = ast.parse(src)
                classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
                self.assertIn(cls, classes, f"{pin}: no such class")
                self.assertIn(method, {n.name for n in classes[cls].body
                                       if isinstance(n, ast.FunctionDef)},
                              f"{pin}: no such test")
                self.assertIn(key.rpartition("@")[0], src,
                              f"{pin} never names the test it is cited for")
                self.assertGreater(len(why), 30)


class TestSelfTestsAreDeclaredAndLabelled(unittest.TestCase):
    def test_the_excused_self_tests_are_exactly_the_locally_decided_cells(self):
        local = {tid for (_s, tid, _p), v in _cells().items() if v["locally_decided"]}
        self.assertEqual(local, set(SELF_TESTS),
                         "a locally_decided row that is not declared here would "
                         "be excused silently; a declared one without the flag "
                         "would hide a target verdict behind a name")

    def test_each_self_test_is_labelled_on_every_pole(self):
        for tid in SELF_TESTS:
            for pole in POLES:
                with self.subTest(test_id=tid, pole=pole):
                    cell = next(v for (_s, t, p), v in _cells().items()
                                if t == tid and p == pole)
                    self.assertTrue(cell["locally_decided"])


class TestThePopulationIsTheRegistry(unittest.TestCase):
    def test_live_plus_no_network_is_everything_the_sweep_exercises(self):
        live, offline = live_target_harnesses(), no_network_target_harnesses()
        exercised = dead_host_sweep.registry_coverage()["exercised"]
        self.assertEqual(set(live) & set(offline), set())
        self.assertEqual(set(live) | set(offline), set(exercised))

    def test_the_no_network_exclusion_is_declared_exactly(self):
        derived = set(no_network_target_harnesses())
        self.assertEqual(
            derived, set(NO_NETWORK_TARGET),
            "the harnesses taking no --url changed. A new one needs a reason "
            "here; one that gained --url is now swept and must leave this map")
        for name, reason in NO_NETWORK_TARGET.items():
            with self.subTest(harness=name):
                self.assertGreaterEqual(len(reason), 40)

    def test_an_alias_of_url_counts(self):
        """hitl declares ``add_argument("--target", "--url")``; the CLI's
        first-argument check misses it, and this population must not."""
        self.assertTrue(no_surface_sweep.declares_url("hitl"))
        self.assertIn("hitl", live_target_harnesses())

    def test_every_live_harness_produced_cells_on_every_pole(self):
        live = set(live_target_harnesses().values())
        for pole in POLES:
            with self.subTest(pole=pole):
                measured = {stem for (stem, _t, p) in _cells() if p == pole}
                self.assertEqual(measured, live,
                                 "a live-target harness produced no verdict rows on "
                                 "this pole: unmeasured, not clean")

    def test_every_pole_measured_the_same_tests(self):
        per_pole = {pole: {(s, t) for (s, t, p) in _cells() if p == pole} for pole in POLES}
        first = per_pole["closed"]
        for pole, tests in per_pole.items():
            with self.subTest(pole=pole):
                self.assertEqual(tests, first)

    def test_a_newly_registered_harness_is_swept_without_editing_this_file(self):
        with _seeded_harness() as (reg, stem):
            self.assertIn(reg, live_target_harnesses())
            self.assertIn(stem, dead_host_sweep._candidate_modules())
        self.assertNotIn(reg, live_target_harnesses())


# ---------------------------------------------------------------------------
# Controls: the guard must be able to fire, and an honest harness must not
# ---------------------------------------------------------------------------

_SEEDED_SOURCE = '''
"""Throwaway harness for testing/test_verdicts_need_a_surface. Never in the tree."""
import argparse

from protocol_tests.http_helpers import http_post_json


class SurfacelessTests:
    """Decides without reading the target: the defect this guard exists for."""

    def __init__(self, url):
        self.url = url
        self.results = []

    def run_all(self):
        self.results = [
            {"test_id": "SEED-901", "name": "seeded", "passed": True,
             "details": "control held"},
            {"test_id": "SEED-903", "name": "seeded", "passed": False,
             "details": "vulnerability found"},
        ]
        return self.results


class HonestTests:
    """PASS or FAIL only on a served JSON-RPC result; INCONCLUSIVE otherwise."""

    def __init__(self, url):
        self.url = url
        self.results = []

    def run_all(self):
        resp = http_post_json(self.url, {"jsonrpc": "2.0", "id": 1,
                                         "method": "verify"}, timeout=3)
        body = None if resp.get("_error") else resp.get("response")
        result = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, dict):
            row = {"test_id": "SEED-902", "name": "honest", "passed": False,
                   "not_evaluated": True,
                   "details": "INCONCLUSIVE - no surface answered"}
        else:
            row = {"test_id": "SEED-902", "name": "honest",
                   "passed": result.get("verified") is True,
                   "details": f"served: {result}"}
        self.results = [row]
        return self.results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url")
    return ap
'''

_SEEDED_NAME = "seeded-surfaceless"
_SEEDED_STEM = "seeded_surfaceless_harness"


@contextlib.contextmanager
def _seeded_harness():
    """Register a throwaway harness in the CLI registry for the block's duration.

    Written to a temporary directory and loaded under `protocol_tests.`, so the
    sweep imports it exactly as it imports a real one. The real tree is never
    written to (test_static_detectors_can_fire asserts that for seeded_*.py).
    """
    from protocol_tests import cli
    path = Path(tempfile.mkdtemp()) / f"{_SEEDED_STEM}.py"
    path.write_text(textwrap.dedent(_SEEDED_SOURCE), encoding="utf-8")
    modname = f"protocol_tests.{_SEEDED_STEM}"
    spec = importlib.util.spec_from_file_location(modname, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    entry = {"module": modname, "description": "seeded control (3 tests)"}
    with mock.patch.dict(sys.modules, {modname: module}), \
            mock.patch.dict(cli.HARNESSES, {_SEEDED_NAME: entry}):
        yield _SEEDED_NAME, _SEEDED_STEM


def _seeded_cells() -> dict:
    """The seeded module alone, through the real three-pole machinery."""
    with _seeded_harness() as (_reg, stem), \
            mock.patch.object(dead_host_sweep, "_candidate_modules",
                              return_value=[stem]):
        return cells(pole_sweeps(), [stem])


class _Served(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "result": {"verified": self.server.verified}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def _served(verified: bool):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Served)
    srv.verified = verified
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


class TestTheGuardCanFire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seeded = _seeded_cells()

    def test_a_seeded_target_independent_pass_and_fail_turn_the_guard_red(self):
        """Positive control: the real measurement plus the seeded module must
        fail the guard, on exactly the seeded cells and nothing else."""
        combined = {**_cells(), **self.seeded}
        result = _guard(combined, VERDICT_WITHOUT_SURFACE)
        expected = {**{f"SEED-901@{p}": "PASS" for p in POLES},
                    **{f"SEED-903@{p}": "FAIL" for p in POLES}}
        self.assertEqual(result["unregistered"], expected)
        self.assertEqual(result["stale"], {})

    def test_an_honest_harness_stays_green(self):
        """Negative control: INCONCLUSIVE on all three poles."""
        for pole in POLES:
            with self.subTest(pole=pole):
                self.assertEqual(
                    self.seeded[(_SEEDED_STEM, "SEED-902", pole)]["outcome"],
                    "INCONCLUSIVE")
        self.assertNotIn("SEED-902", {k.rpartition("@")[0] for k in _offenders(self.seeded)})

    def test_the_honest_harness_can_still_pass_and_fail(self):
        """Without this the negative control proves nothing: a harness that is
        INCONCLUSIVE everywhere would also stay green."""
        from protocol_tests.http_helpers import row_outcome
        with _seeded_harness():
            mod = sys.modules[f"protocol_tests.{_SEEDED_STEM}"]
            for verified, expected in ((True, "PASS"), (False, "FAIL")):
                with self.subTest(verified=verified), _served(verified) as url:
                    rows = mod.HonestTests(url).run_all()
                    self.assertEqual(row_outcome(rows[0]), expected)


def _a_registered_cell():
    """One registered cell, derived from the register rather than named, so a
    fix that removes the example cannot break the controls (CVE-005 was the
    named example until it was fixed). -> (cell_map key, register key, verdict)."""
    key = min(VERDICT_WITHOUT_SURFACE)
    tid, _, pole = key.rpartition("@")
    return (_owner_of(_cells())[tid], tid, pole), key, VERDICT_WITHOUT_SURFACE[key]


class TestTheRatchetFailsBothWays(unittest.TestCase):
    """The seeded reverts, at the comparison: each must turn the guard red."""

    def test_removing_a_registered_entry_is_red(self):
        _cell, key, verdict = _a_registered_cell()
        smaller = {k: v for k, v in VERDICT_WITHOUT_SURFACE.items() if k != key}
        self.assertEqual(_guard(_cells(), smaller)["unregistered"], {key: verdict})

    def test_a_fix_that_keeps_its_entry_is_red(self):
        cell, key, verdict = _a_registered_cell()
        fixed = {k: ({**v, "outcome": "INCONCLUSIVE"} if k == cell else v)
                 for k, v in _cells().items()}
        self.assertEqual(_guard(fixed, VERDICT_WITHOUT_SURFACE)["stale"],
                         {key: verdict})

    def test_a_verdict_that_flips_is_red_both_ways(self):
        cell, key, verdict = _a_registered_cell()
        other = "PASS" if verdict == "FAIL" else "FAIL"
        flipped = {k: ({**v, "outcome": other} if k == cell else v)
                   for k, v in _cells().items()}
        g = _guard(flipped, VERDICT_WITHOUT_SURFACE)
        self.assertEqual(g["unregistered"], {key: other})
        self.assertEqual(g["stale"], {key: verdict})

    def test_counts_are_reported_per_pole(self):
        """Not an assertion about a number; a check the register spans poles."""
        per_pole = Counter(k.rpartition("@")[2] for k in VERDICT_WITHOUT_SURFACE)
        self.assertEqual(set(per_pole) - set(POLES), set())


if __name__ == "__main__":
    unittest.main()
