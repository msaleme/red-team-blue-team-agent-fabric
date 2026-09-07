"""The no-jsonschema fallback validator must not be stricter than the schema.

`validate_attestation_report` has two paths. When jsonschema is installed it
validates against `schemas/attestation-report.json`. When it is not, it falls
back to hand-written structural checks that carry their own copy of the
`result` vocabulary.

Two copies of one vocabulary drift. They did: PR #520 added `inconclusive` to
the schema enum and not to the fallback, so a correct three-state report was
reported invalid -- with the message "invalid result 'inconclusive'" -- on any
machine without jsonschema. The report was right and the validator was wrong,
which is the worse direction for a validator to fail in.

These tests derive the expectation from the schema rather than restating the
list, so the next value added to the enum cannot pass while the fallback is
still unaware of it.
"""
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_tests import attestation


def schema_result_enum() -> set[str]:
    schema = json.loads(Path(attestation.SCHEMA_PATH).read_text())
    entry = schema["$defs"]["attestation_entry"]
    return set(entry["properties"]["result"]["enum"])


def fallback_result_enum() -> set[str]:
    """Read the tuple literal out of the fallback branch's source."""
    src = Path(attestation.__file__).read_text()
    m = re.search(
        r'if "result" in entry and entry\["result"\] not in \((.*?)\):',
        src,
        re.DOTALL,
    )
    assert m, "could not locate the fallback result check -- update this test"
    return set(re.findall(r'"([a-z_]+)"', m.group(1)))


class FallbackMatchesSchema(unittest.TestCase):
    def test_the_extraction_actually_found_something(self):
        # A regex that stops matching would make every assertion below vacuous.
        self.assertGreaterEqual(len(schema_result_enum()), 4)
        self.assertGreaterEqual(len(fallback_result_enum()), 4)

    def test_fallback_accepts_every_value_the_schema_accepts(self):
        missing = schema_result_enum() - fallback_result_enum()
        self.assertEqual(
            missing,
            set(),
            f"the fallback validator rejects {sorted(missing)}, which the schema "
            f"declares valid; a correct report would be reported invalid wherever "
            f"jsonschema is absent",
        )

    def test_fallback_does_not_invent_values_the_schema_rejects(self):
        extra = fallback_result_enum() - schema_result_enum()
        self.assertEqual(extra, set(), f"fallback accepts undeclared results: {sorted(extra)}")

    def test_inconclusive_survives_the_fallback_path(self):
        """End-to-end, with jsonschema forced unavailable."""
        record = attestation.generate_attestation_report(
            suite="fallback-path-check",
            harness_version="0.0.0-test",
            entries=[
                {
                    "test_id": "TST-001",
                    "category": "authorization",
                    "result": "inconclusive",
                    "severity": "high",
                    "scope": {"protocol": "mcp", "layer": "transport"},
                    "timestamp": "2026-09-07T00:00:00Z",
                    "inconclusive_reason": "target did not service the request",
                }
            ],
        )
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

        def no_jsonschema(name, *a, **kw):
            if name == "jsonschema":
                raise ImportError("forced for this test")
            return real_import(name, *a, **kw)

        import builtins

        builtins.__import__ = no_jsonschema
        try:
            errors = attestation.validate_attestation_report(record)
        finally:
            builtins.__import__ = real_import

        self.assertTrue(
            any("NOT SCHEMA-VALIDATED" in e for e in errors),
            "the fallback must still state that it degraded",
        )
        self.assertEqual(
            [e for e in errors if "invalid result" in e],
            [],
            f"fallback rejected a valid inconclusive entry: {errors}",
        )


if __name__ == "__main__":
    unittest.main()
