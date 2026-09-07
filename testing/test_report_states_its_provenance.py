"""A module that writes a report states, in the report, what produced the run.

`docs/evidence/adi/2026-09-02-qwen35-n3-raw.json` is what the alternative looks
like. Its `runtime` block -- Ollama server version, model tag, manifest digest,
family, parameter size, quantisation -- was typed in by a person, because
`agent_data_injection.py --report` wrote a bare LIST and a list has nowhere to
put a header. The verdicts in that file are about a model whose identity is not
part of the record.

`agent_data_injection` is the first module migrated. This file is the ratchet
that keeps the direction one-way.

## The set is derived, not listed

The reference for this shape is `testing/test_inconclusive_summary.py`, whose
own comment records why: a detector keyed to the literal being REMOVED stops
detecting exactly when it starts mattering, and a ratchet over an empty set
passes while every module carries the defect.

So the affected set is computed by scanning `protocol_tests/*.py` for a module
that writes a report at all -- `def generate_report`, or an argparse `--report`
flag -- and `GRANDFATHERED` is seeded with every one of them except the migrated
module. It may shrink. It must never grow.

Two numbers worth keeping straight, because the plan for this change had them
confused. `def generate_report` matches twenty-seven files and
`agent_data_injection` is NOT one of them: it writes its report from `main()`
and defines no such function. Deriving the set from `def generate_report` alone
would therefore have excluded the one module this change migrated, leaving the
ratchet asserting nothing about it. The union of the two idioms matches
forty-three files, `agent_data_injection` among them, and
`test_the_migrated_module_is_actually_in_the_set` below pins that rather than
trusting it.
"""
from __future__ import annotations

import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOCOL_TESTS = REPO_ROOT / "protocol_tests"

#: "This module produces a report document." Both idioms, for the reason in the
#: module docstring: matching only `def generate_report` misses the module the
#: change was made for, and matching only `--report` misses the harnesses that
#: build a report for a caller rather than for a flag.
WRITES_A_REPORT = re.compile(
    r"^\s*def generate_report|add_argument\(\s*[\"']--report", re.M)

#: The property: the report says what produced the run.
#:
#: This must match a CALL, not the name. `\brun_provenance\b` also matched the
#: import line and the module path `protocol_tests.run_provenance`, so a module
#: that imported the builder and never called it satisfied the ratchet. Caught
#: by deleting the call from `delegation_chain_harness` while leaving its
#: import: the suite stayed green.
STATES_ITS_PROVENANCE = re.compile(r"\brun_provenance\s*\(")

#: Not report writers, for stated reasons rather than because they were
#: inconvenient.
#:
#: `cli` forwards `--report` to the module that writes the report and writes
#: none itself. It also has a separate latent defect around `runpy.run_module`
#: and `SystemExit` that deserves its own change, so it is deliberately
#: untouched here.
#: `_utils` names `--report` only inside a usage docstring.
#: `harness_base` and `http_helpers` are the shared machinery, following the
#: `NOT_A_HARNESS` precedent in `test_inconclusive_summary.py`.
NOT_A_REPORT_WRITER = {"cli", "_utils", "harness_base", "http_helpers"}

#: The module this change migrated.
MIGRATED = "agent_data_injection"

#: Report writers that do NOT yet state their provenance. May shrink. Must never
#: grow -- a new entry means a report writer was added that cannot say what
#: produced it, which is the shape `run_provenance.py` exists to remove.
#:
#: Migrating the rest is deliberately not done here. Each one has its own report
#: shape and its own callers, and a 43-module mechanical edit is not reviewable.
GRANDFATHERED: set[str] = {
    "a2a_harness", "advanced_attacks", "aiuc1_compliance_harness",
    "ap2_harness", "benchmark_integrity_harness", "capability_profile_harness",
    "card_token_harness", "cbrn_harness", "cloud_agent_harness",
    "community_runner", "crewai_cve_harness", "enterprise_adapters",
    "extended_enterprise_adapters", "extended_thinking_harness",
    "framework_adapters", "governance_modification_harness",
    "gtg1002_simulation", "harmful_output_harness", "hitl_harness",
    "identity_harness", "incident_response_harness", "intent_contract_harness",
    "jailbreak_harness", "kill_switch_harness", "l402_harness", "mcp_harness",
    "mcp_supplychain", "mcp_tool_poisoning_harness", "memory_harness",
    "multi_agent_harness", "over_refusal_harness", "prompt_caching_harness",
    "provenance_harness", "ptc_harness", "return_channel_harness",
    "settlement_finality_harness", "skill_security_harness",
    "tool_search_harness", "ucp_acp_harness", "watermark_harness",
    "x402_fireblocks_harness", "x402_harness",
}

#: The count of `def generate_report` modules at the time this was written. Used
#: as a FLOOR on the derived set: if the scan stops matching -- a renamed
#: helper, a changed argparse idiom -- the ratchet below would iterate nothing
#: and pass while nothing was checked. A detector that can silently return the
#: empty set is not a detector.
KNOWN_REPORT_WRITERS = 27

# Frozen at the seed. May shrink as modules are migrated; must never grow.
SEEDED_GRANDFATHER_COUNT = 42


def _affected() -> set[str]:
    return {
        p.stem for p in sorted(PROTOCOL_TESTS.glob("*.py"))
        if p.stem not in NOT_A_REPORT_WRITER
        and WRITES_A_REPORT.search(p.read_text(encoding="utf-8"))
    }


class TestTheDetectionStillDetects(unittest.TestCase):
    """Guards on the scan itself. Without these the ratchet can pass vacuously."""

    def test_the_affected_set_is_not_empty(self):
        self.assertGreaterEqual(
            len(_affected()), KNOWN_REPORT_WRITERS,
            f"fewer report-writing modules found than the "
            f"{KNOWN_REPORT_WRITERS} known when this was written; the "
            f"detection is probably broken rather than the repo improved")

    def test_the_migrated_module_is_actually_in_the_set(self):
        """The specific way this scan could go quiet.

        `agent_data_injection` defines no `generate_report`; it writes its
        report from `main()`. A scan keyed to `def generate_report` alone would
        exclude it, and then `_affected() - GRANDFATHERED` is empty and the
        ratchet asserts nothing about the one module that was changed.
        """
        self.assertIn(MIGRATED, _affected())

    def test_the_ratchet_has_something_to_check(self):
        """The checked set must be non-empty and must contain the migrated one.

        This asserted equality with `{MIGRATED}` when exactly one module
        complied. That was too strict in the direction that matters: a NEW
        module which states its provenance correctly is the outcome this
        ratchet exists to produce, and equality reported it as a failure.
        `delegation_chain_harness` (#524) was the first such module.

        The property being defended is that the scan is checking something and
        is checking the module that was migrated -- not that the compliant set
        never grows. Growth of GRANDFATHERED is what must not happen, and
        `test_the_grandfather_list_never_grew` pins that separately.
        """
        checked = _affected() - GRANDFATHERED
        self.assertIn(MIGRATED, checked)
        self.assertTrue(checked, "the ratchet is checking nothing")

    def test_the_grandfather_list_never_grew(self):
        """Debt may be paid down; it may not be taken on.

        A module that writes a report without provenance must be fixed, not
        added here. This is the assertion that makes the ratchet a ratchet.
        """
        self.assertLessEqual(
            len(GRANDFATHERED), SEEDED_GRANDFATHER_COUNT,
            f"GRANDFATHERED grew past its seed of "
            f"{SEEDED_GRANDFATHER_COUNT}; a new report writer was excused "
            f"instead of made to state what produced it")

    def test_grandfathered_names_all_exist(self):
        """A stale name silently shrinks the checked set to nothing."""
        for name in sorted(GRANDFATHERED):
            with self.subTest(module=name):
                self.assertTrue((PROTOCOL_TESTS / f"{name}.py").exists())

    def test_the_grandfather_list_is_a_subset_of_the_affected_set(self):
        self.assertEqual(
            GRANDFATHERED - _affected(), set(),
            "a grandfathered module is no longer detected as a report writer; "
            "either it stopped writing reports (remove it from the list) or "
            "the detection broke")


class TestReportWritersStateTheirProvenance(unittest.TestCase):
    """The ratchet. Derived, so module forty-four is caught the day it lands."""

    def test_every_non_grandfathered_report_writer_states_its_provenance(self):
        for name in sorted(_affected() - GRANDFATHERED):
            with self.subTest(module=name):
                src = (PROTOCOL_TESTS / f"{name}.py").read_text(encoding="utf-8")
                self.assertIsNotNone(
                    STATES_ITS_PROVENANCE.search(src),
                    f"{name} writes a report and never calls run_provenance(), "
                    f"so the report cannot say what produced it. That header "
                    f"then gets assembled by hand, which is how "
                    f"docs/evidence/adi/2026-09-02-qwen35-n3-raw.json came to "
                    f"carry a model digest the harness never read.")

    def test_the_migrated_module_writes_a_document_not_a_list(self):
        """The specific regression: `json.dump([...], fh)` with no header."""
        src = (PROTOCOL_TESTS / f"{MIGRATED}.py").read_text(encoding="utf-8")
        self.assertNotIn(
            "json.dump([r.__dict__ for r in results]", src,
            "the report is a bare list again; a list has nowhere to put a "
            "header, which is the whole defect")
        self.assertIn('"provenance": run_provenance()', src)

    def test_grandfather_list_may_only_shrink(self):
        """Recorded with its denominator, per docs/EVIDENCE-INTEGRITY rules.

        42 is a numerator and means nothing alone. The denominator is the
        derived set of report writers, so this reads as "42 of 43 report
        writers cannot yet say what produced them" -- a fraction that moves
        correctly whether the numerator shrinks or a new writer lands.

        `testing/test_evidence_integrity_registers.py` covers a register by
        NAME, and `GRANDFATHERED` is already claimed there by a derivation that
        reads `test_harness_base_adoption`. So this register's own numbers are
        stated here rather than assumed covered by that name collision.
        """
        affected = _affected()
        self.assertLessEqual(
            len(GRANDFATHERED), 42,
            f"GRANDFATHERED grew to {len(GRANDFATHERED)} of {len(affected)} "
            f"report writers. A report writer that cannot state what produced "
            f"it is the pattern this file exists to retire.")
        self.assertLess(
            len(GRANDFATHERED), len(affected),
            "every report writer is grandfathered, so the ratchet checks "
            "nothing")


if __name__ == "__main__":
    unittest.main()
