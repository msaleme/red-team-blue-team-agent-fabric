"""The attestation schema must be emittable without naming one implementation (#137).

Step 2 of the standards-readiness review. The draft's working title is
"A Provider-Neutral Schema for Verifiable Agent Decisions", while the schema was
titled "Agent Security Harness Attestation Report" and *required* a top-level
`harness_version`. A format that cannot be emitted without naming one tool's
version is not provider-neutral, and a reviewer says so in the first round.

The fix is additive rather than a rename: `producer` is the neutral spelling,
`harness_version` is retained because five scripts read it, and the schema
requires one or the other via `anyOf`. Every document valid before this change
is still valid.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCHEMA = json.load(open(
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "schemas", "attestation-report.json"), encoding="utf-8"))


def _entry():
    return {"test_id": "MCP-001", "category": "injection", "result": "pass",
            "severity": "low", "scope": {"protocol": "mcp", "layer": "transport"},
            "timestamp": "2026-08-15T00:00:00Z"}


def _satisfies_anyof(doc):
    return any(all(k in doc for k in branch["required"]) for branch in SCHEMA["anyOf"])


def test_harness_version_is_not_top_level_required():
    """The specific defect: the format could not be emitted without it."""
    assert "harness_version" not in SCHEMA["required"]


def test_schema_id_is_not_the_404_form():
    """The declared $id returned 404. A standards submission cannot ship an
    identifier that does not resolve."""
    assert SCHEMA["$id"].startswith("https://raw.githubusercontent.com/")
    assert "/main/schemas/attestation-report.json" in SCHEMA["$id"]


def test_title_does_not_name_one_implementation():
    assert "Harness" not in SCHEMA["title"], SCHEMA["title"]


def test_a_neutral_producer_can_emit_a_valid_document():
    """No `harness_version` anywhere. This was impossible before."""
    doc = {"schema_version": "1.0.0",
           "producer": {"name": "some-other-tool", "version": "2.1.0"},
           "suite": "mcp", "timestamp": "2026-08-15T00:00:00Z",
           "summary": {"total": 1, "passed": 1, "failed": 0}, "entries": [_entry()]}
    assert all(k in doc for k in SCHEMA["required"])
    assert _satisfies_anyof(doc)


def test_a_legacy_document_without_producer_is_still_valid():
    """Backward compatibility is the reason this is additive rather than a rename."""
    doc = {"schema_version": "1.0.0", "harness_version": "4.15.0",
           "suite": "mcp", "timestamp": "2026-08-15T00:00:00Z",
           "summary": {"total": 1, "passed": 1, "failed": 0}, "entries": [_entry()]}
    assert all(k in doc for k in SCHEMA["required"])
    assert _satisfies_anyof(doc)


def test_a_document_identifying_no_producer_at_all_is_rejected():
    """Dropping harness_version from `required` must not mean anonymity is allowed."""
    doc = {"schema_version": "1.0.0", "suite": "mcp",
           "timestamp": "2026-08-15T00:00:00Z",
           "summary": {"total": 1, "passed": 1, "failed": 0}, "entries": [_entry()]}
    assert not _satisfies_anyof(doc)


def test_producer_requires_both_name_and_version():
    producer = SCHEMA["properties"]["producer"]
    assert producer["required"] == ["name", "version"]
    assert producer["additionalProperties"] is False


def test_the_builder_emits_both_spellings():
    """The neutral field must be exercised, not merely permitted."""
    from protocol_tests.attestation import generate_attestation_report
    report = generate_attestation_report([_entry()], suite="mcp", harness_version="4.15.0")
    assert report["producer"] == {"name": "agent-security-harness", "version": "4.15.0"}
    assert report["harness_version"] == "4.15.0", "five scripts still read this"
    assert _satisfies_anyof(report)


def test_schema_version_was_not_bumped():
    """schema_version is a `const`. Bumping it would invalidate every existing
    document, and this change is backward compatible, so it must not move."""
    assert SCHEMA["properties"]["schema_version"]["const"] == "1.0.0"
