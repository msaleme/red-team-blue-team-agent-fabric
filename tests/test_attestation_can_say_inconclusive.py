"""An attestation record must be able to say a control was never exercised.

The harness has carried three states for a long time: `run_summary()` reports
PASS / FAIL / INCONCLUSIVE, uses `serviced` as the denominator, and returns
`pass_rate = None` rather than 0.0 when nothing was serviced, because "a rate of
zero is a claim, and absence is not."

The attestation report threw the third state away. Its `result` enum was
`pass | fail | error | skip` with `additionalProperties: false`, and the legacy
migration read `"pass" if r.get("passed") else "fail"`. So a verdict the harness
knew was unexercised left the building as a **fail** -- an assertion that the
control did not hold, which the run never made -- with the distinction surviving
only as a prefix inside a prose string an auditor is not required to read.

That is the defect this repository keeps finding, in the artifact that goes to
third parties: a claim stronger than the evidence, produced by the serialization
boundary rather than by any test.

These tests pin the third state at that boundary, and pin the two fields that let
an entry state its own limits.
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from protocol_tests.attestation import (  # noqa: E402
    AttestationEntry,
    _legacy_result,
    generate_attestation_report,
    migrate_legacy_report,
)

SCHEMA = json.loads((REPO / "schemas" / "attestation-report.json").read_text())
ENTRY = SCHEMA["$defs"]["attestation_entry"]


class TestSchemaAdmitsTheThirdState:
    def test_result_enum_contains_inconclusive(self):
        assert "inconclusive" in ENTRY["properties"]["result"]["enum"]

    def test_entry_may_state_what_it_does_not_establish(self):
        """EVIDENCE-CLASS-TAXONOMY.md gives every level a 'Does not establish'
        column. Until now no entry could carry one."""
        assert "not_established" in ENTRY["properties"]

    def test_entry_may_state_why_a_control_went_unexercised(self):
        assert "inconclusive_reason" in ENTRY["properties"]

    def test_entries_still_reject_unknown_fields(self):
        """The schema stays closed; this change widens it deliberately, not by
        loosening additionalProperties."""
        assert ENTRY["additionalProperties"] is False


class TestLegacyMigrationPreservesIt:
    @pytest.mark.parametrize("record,expected", [
        ({"passed": True, "details": "control held"}, "pass"),
        ({"passed": False, "details": "control did not hold"}, "fail"),
        ({"passed": False, "details": "INCONCLUSIVE - target did not service the request"},
         "inconclusive"),
        ({"passed": False, "not_evaluated": True, "details": "x"}, "inconclusive"),
        ({"passed": False, "informational": True, "details": "x"}, "inconclusive"),
    ])
    def test_each_state_survives(self, record, expected):
        assert _legacy_result(record) == expected

    def test_an_unexercised_control_is_not_reported_as_a_failure(self):
        """The regression. Before this change every row below became `fail`."""
        legacy = {"suite": "s", "timestamp": "2026-09-07T00:00:00Z", "results": [
            {"test_id": "T-1", "category": "c", "severity": "P4-Info", "passed": True,
             "details": "held"},
            {"test_id": "T-2", "category": "c", "severity": "P4-Info", "passed": False,
             "details": "did not hold"},
            {"test_id": "T-3", "category": "c", "severity": "P4-Info", "passed": False,
             "details": "INCONCLUSIVE - target did not service the request"},
        ]}
        report = migrate_legacy_report(legacy)
        got = {e["test_id"]: e["result"] for e in report["entries"]}
        assert got == {"T-1": "pass", "T-2": "fail", "T-3": "inconclusive"}, got

    def test_the_migration_would_fail_against_the_old_collapsing_rule(self):
        """Fault injection: the pre-fix rule, run against the same input.

        A guard that cannot be shown to fail against the defect it closes is
        decoration."""
        record = {"passed": False,
                  "details": "INCONCLUSIVE - target did not service the request"}
        collapsing_rule = "pass" if record.get("passed") else "fail"
        assert collapsing_rule == "fail"
        assert _legacy_result(record) == "inconclusive"
        assert _legacy_result(record) != collapsing_rule


class TestReportSummary:
    def _entry(self, test_id, result, **kw):
        return AttestationEntry(test_id=test_id, category="c", result=result,
                                severity="P4-Info", **kw).to_dict()

    def test_summary_counts_inconclusive(self):
        entries = [self._entry("A", "pass"), self._entry("B", "fail"),
                   self._entry("C", "inconclusive"), self._entry("D", "inconclusive")]
        s = generate_attestation_report(entries, "s", "4.20.0")["summary"]
        assert (s["total"], s["passed"], s["failed"], s["inconclusive"]) == (4, 1, 1, 2)

    def test_inconclusive_is_reported_even_at_zero(self):
        """A reader must never be able to infer passed + failed == total."""
        s = generate_attestation_report([self._entry("A", "pass")], "s", "4.20.0")["summary"]
        assert s["inconclusive"] == 0
        assert "inconclusive" in s

    def test_inconclusive_is_not_counted_as_passed_or_failed(self):
        s = generate_attestation_report(
            [self._entry("A", "inconclusive")], "s", "4.20.0")["summary"]
        assert s["passed"] == 0 and s["failed"] == 0 and s["inconclusive"] == 1

    def test_an_entry_can_carry_its_own_limits(self):
        e = self._entry("A", "inconclusive",
                        not_established="that the control holds under load",
                        inconclusive_reason="target did not service the request")
        assert e["not_established"] == "that the control holds under load"
        assert e["inconclusive_reason"] == "target did not service the request"
