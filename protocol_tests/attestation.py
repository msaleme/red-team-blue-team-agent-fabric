"""Attestation report utilities for the Agent Security Harness.

Provides:
- Schema validation against schemas/attestation-report.json
- Migration from v3.7 legacy report format to v3.8 attestation format
- Report generation helpers
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "EVIDENCE_CLASSES",
    "INDEPENDENCE_LEVELS",
    "SCHEMA_VERSION",
    "AttestationEntry",
    "generate_attestation_report",
    "migrate_legacy_report",
    "validate_attestation_report",
]

SCHEMA_VERSION = "1.0.0"
def _resolve_data(*parts: str) -> Path:
    """Kept as a name; the resolution lives in one place now (package_data)."""
    from .package_data import data_path
    return data_path(*parts)


SCHEMA_PATH = _resolve_data("schemas", "attestation-report.json")

# docs/EVIDENCE-CLASS-TAXONOMY.md. Kept here so a report can state its own class
# rather than having a server assign one outside the signature (#384).
EVIDENCE_CLASSES = ("E1", "E2", "E3", "E4", "E5")
INDEPENDENCE_LEVELS = ("I0", "I1", "I2")

# ---------------------------------------------------------------------------
# Scope/remediation lookup for known test IDs
# ---------------------------------------------------------------------------

_SCOPE_DEFAULTS: dict[str, dict[str, str]] = {
    "MCP": {
        "protocol": "mcp",
        "layer": "protocol",
    },
    "A2A": {
        "protocol": "a2a",
        "layer": "protocol",
    },
    "L4": {
        "protocol": "l402",
        "layer": "protocol",
    },
    "X4": {
        "protocol": "x402",
        "layer": "protocol",
    },
    "CAP": {
        "protocol": "platform",
        "layer": "operational",
    },
    "CVE": {
        "protocol": "other",
        "layer": "protocol",
    },
    "JB": {
        "protocol": "other",
        "layer": "decision",
    },
    "OR": {
        "protocol": "other",
        "layer": "decision",
    },
    "RC": {
        "protocol": "other",
        "layer": "operational",
    },
    "GTG": {
        "protocol": "other",
        "layer": "operational",
    },
}


def _infer_scope(test_id: str, category: str = "") -> dict[str, str]:
    """Infer scope metadata from a test_id prefix."""
    prefix = test_id.split("-")[0] if "-" in test_id else test_id[:3]
    defaults = _SCOPE_DEFAULTS.get(prefix, {"protocol": "other", "layer": "operational"})
    return {
        "protocol": defaults["protocol"],
        "layer": defaults["layer"],
        "attack_type": category.replace("_", " ") if category else "unknown",
    }


def _default_remediation() -> dict[str, Any]:
    """Return a placeholder remediation block."""
    return {
        "description": "Review test details and apply protocol-specific hardening.",
        "references": [],
        "priority": "next-release",
    }


# ---------------------------------------------------------------------------
# Attestation entry builder
# ---------------------------------------------------------------------------

class AttestationEntry:
    """Builder for a single attestation entry."""

    def __init__(
        self,
        test_id: str,
        category: str,
        result: str,
        severity: str,
        timestamp: str | None = None,
        **kwargs: Any,
    ):
        self.data: dict[str, Any] = {
            "test_id": test_id,
            "category": category,
            "result": result,
            "severity": severity,
            "scope": kwargs.pop("scope", _infer_scope(test_id, category)),
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        }
        # Optional fields
        for key in (
            "name", "remediation", "elapsed_s", "agent_identity",
            "protocol_version", "owasp_asi", "statistical", "details",
            "request_sent", "response_received",
            # #520: an entry may state what it does not establish, and why a
            # control went unexercised. Without these the schema could only say
            # pass or fail, so an unexercised control left the harness as a
            # failure -- an assertion the run never made.
            "not_established", "inconclusive_reason",
        ):
            if key in kwargs:
                self.data[key] = kwargs[key]

        if "remediation" not in self.data:
            self.data["remediation"] = _default_remediation()

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_attestation_report(
    entries: list[dict[str, Any]],
    suite: str,
    harness_version: str,
    target: str | None = None,
    evidence_class: str | None = None,
    independence_level: str | None = None,
    system_under_test: str | None = None,
    provenance: dict[str, Any] | None = None,
    subject: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a complete attestation report dict.

    `independence_level` and `system_under_test` land INSIDE the report, which is
    the signed payload. Before #384 neither field existed here, so the only source
    of them was the receiving server -- assigned server-side, outside the
    signature, which is the operator assertion section 7 of the registry contract
    exists to avoid.

    An I-level is relative to a named system under test, so passing one without
    the other is rejected rather than silently recorded.

    The default is to state NO independence claim rather than to default to I0.
    Defaulting to I0 would require inventing a system under test to attach it to,
    and an operator-invented system under test is the same manufactured claim this
    change removes from the server. A record that makes no claim should be visibly
    silent; verify_attestation_record.py reports the absence explicitly.

    `provenance` and `subject` (from `protocol_tests.run_provenance`) travel
    TOGETHER or not at all. A subject with no provenance is a statement about
    what was tested with nothing saying what produced the statement -- the same
    shape as an I-level with no system under test, rejected for the same reason.
    So a `subject` without a `provenance` raises, and a `provenance` without a
    `subject` emits `subject_none()`: "this run reached no subject" is a fact,
    and an omitted key is not.

    Both stay OPTIONAL at the schema level. Records published before these
    fields existed are still valid and still hash to what they hashed to;
    invalidating them would add no information.
    """
    if independence_level is not None and independence_level not in INDEPENDENCE_LEVELS:
        raise ValueError(
            f"independence_level must be one of {INDEPENDENCE_LEVELS}, got {independence_level!r}"
        )
    if evidence_class is not None and evidence_class not in EVIDENCE_CLASSES:
        raise ValueError(
            f"evidence_class must be one of {EVIDENCE_CLASSES}, got {evidence_class!r}"
        )
    if independence_level is not None and not system_under_test:
        raise ValueError(
            "system_under_test is required whenever independence_level is set. "
            "An I-level with no named system under test is not a claim "
            "(docs/EVIDENCE-CLASS-TAXONOMY.md)."
        )
    if subject is not None and provenance is None:
        raise ValueError(
            "provenance is required whenever subject is set. A statement about "
            "what was tested, with nothing saying what produced the statement, "
            "is the hand-assembled-header shape run_provenance.py exists to "
            "remove."
        )
    passed = sum(1 for e in entries if e.get("result") == "pass")
    failed = sum(1 for e in entries if e.get("result") == "fail")
    inconclusive = sum(1 for e in entries if e.get("result") == "inconclusive")
    errored = sum(1 for e in entries if e.get("result") == "error")
    skipped = sum(1 for e in entries if e.get("result") == "skip")

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        # `producer` is the provider-neutral spelling (#137). `harness_version` is
        # retained because five scripts read it and the schema still accepts it;
        # the schema requires one or the other, not this one specifically.
        "producer": {"name": "agent-security-harness", "version": harness_version},
        "harness_version": harness_version,
        "suite": suite,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(entries),
            "passed": passed,
            "failed": failed,
            # Always present, including at zero. `run_summary()` in http_helpers
            # already treats this as a first-class bucket; omitting it here when
            # it is empty would let a reader infer pass+fail == total, which is
            # the inference this field exists to prevent.
            "inconclusive": inconclusive,
        },
        "entries": entries,
    }

    if errored:
        report["summary"]["errored"] = errored
    if skipped:
        report["summary"]["skipped"] = skipped
    if target:
        report["target"] = target
    if independence_level is not None:
        report["independence_level"] = independence_level
        report["system_under_test"] = system_under_test
    if evidence_class is not None:
        report["evidence_class"] = evidence_class
    if provenance is not None:
        # Both, always, once either is asked for.
        from .run_provenance import subject_none
        report["provenance"] = provenance
        report["subject"] = subject if subject is not None else subject_none()

    return report


# ---------------------------------------------------------------------------
# Legacy migration (v3.7 -> v3.8)
# ---------------------------------------------------------------------------

def _legacy_result(record: dict[str, Any]) -> str:
    """Map one legacy result to a schema `result`, preserving inconclusive.

    A legacy record carries `passed: bool`, so an unexercised control and a
    failed control are the same value. The third state survives only in the
    INCONCLUSIVE_PREFIX on `details` and in the `not_evaluated` / `informational`
    flags. Reading `passed` alone therefore reports "the control did not hold"
    about a run that never tested it -- an assertion the harness never made.

    The same predicate and the same field list as the in-process summary, so a
    report and a summary over the same results cannot disagree. Note the shape
    difference: `is_inconclusive` reads a result OBJECT via getattr, and a legacy
    record is a dict, so handing it the record whole silently returns False for
    every entry. The structural fields are read as keys and the prose form is
    delegated, which is the one place that mismatch has to be known.
    """
    from .http_helpers import INCONCLUSIVE_FIELDS, is_inconclusive

    if any(record.get(field) for field in INCONCLUSIVE_FIELDS):
        return "inconclusive"
    if is_inconclusive(record.get("details")):
        return "inconclusive"
    return "pass" if record.get("passed") else "fail"


def migrate_legacy_report(legacy: dict[str, Any], harness_version: str = "3.8.0") -> dict[str, Any]:
    """Convert a v3.7-style report to the v3.8 attestation format.

    v3.7 format:
        { "suite", "timestamp", "summary", "results": [{ "test_id", "name", "category",
          "owasp_asi", "severity", "passed", "details", ... }] }

    Returns a valid attestation report dict.
    """
    entries: list[dict[str, Any]] = []

    for r in legacy.get("results", []):
        result_str = _legacy_result(r)
        entry = AttestationEntry(
            test_id=r.get("test_id", "UNKNOWN"),
            category=r.get("category", ""),
            result=result_str,
            severity=r.get("severity", "P4-Info"),
            timestamp=r.get("timestamp", legacy.get("timestamp")),
            **{k: r[k] for k in ("name", "owasp_asi", "details", "elapsed_s",
                                  "request_sent", "response_received",
                                  "not_established", "inconclusive_reason")
               if r.get(k) is not None},
        )

        entries.append(entry.to_dict())

    return generate_attestation_report(
        entries=entries,
        suite=legacy.get("suite", "Unknown Suite"),
        harness_version=harness_version,
        target=legacy.get("target"),
    )


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def validate_attestation_report(report: dict[str, Any]) -> list[str]:
    """Validate a report dict against the attestation schema.

    Returns a list of error messages (empty = valid).
    Uses jsonschema if available, otherwise does basic structural checks.
    """
    errors: list[str] = []

    try:
        import jsonschema  # type: ignore[import-untyped]

        with open(SCHEMA_PATH) as f:
            schema = json.load(f)

        validator = jsonschema.Draft202012Validator(schema)
        for error in sorted(validator.iter_errors(report), key=lambda e: list(e.path)):
            path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            errors.append(f"{path}: {error.message}")

    except FileNotFoundError:
        # Same discipline as the ImportError branch below: a criterion that
        # cannot run must say so rather than raising into the caller, and must
        # never return an empty error list, which would read as "valid".
        errors.append(
            f"NOT SCHEMA-VALIDATED: the schema was not found at {SCHEMA_PATH}. "
            f"This usually means an installed copy that predates the packaging "
            f"fix; reinstall agent-security-harness. No structural checks ran."
        )
    except ImportError:
        # #384: this fallback is weaker than the schema, and before this change it
        # returned the same empty list, so "no errors" meant either "validated" or
        # "the validator was not installed". A criterion that reports success
        # without the mechanism having run is the defect class this repo tracks,
        # so the degradation is now stated rather than silent.
        errors.append(
            "NOT SCHEMA-VALIDATED: jsonschema is not installed, so only basic "
            "structural checks ran. Install jsonschema for real validation."
        )
        # Fallback: basic structural validation
        for field in ("schema_version", "harness_version", "suite", "timestamp", "summary", "entries"):
            if field not in report:
                errors.append(f"Missing required field: {field}")

        if "entries" in report:
            for i, entry in enumerate(report["entries"]):
                for req in ("test_id", "category", "result", "severity", "scope", "timestamp"):
                    if req not in entry:
                        errors.append(f"entries[{i}]: missing required field '{req}'")

                if "result" in entry and entry["result"] not in (
                    "pass",
                    "fail",
                    "inconclusive",
                    "error",
                    "skip",
                ):
                    errors.append(f"entries[{i}]: invalid result '{entry['result']}'")

                if "scope" in entry:
                    scope = entry["scope"]
                    if "protocol" not in scope:
                        errors.append(f"entries[{i}].scope: missing 'protocol'")
                    if "layer" not in scope:
                        errors.append(f"entries[{i}].scope: missing 'layer'")

    # Taxonomy rule, enforced regardless of which path above ran: an I-level is a
    # property of the relationship between a record and a NAMED system under test,
    # so a bare level is not a claim (docs/EVIDENCE-CLASS-TAXONOMY.md).
    lvl = report.get("independence_level")
    if lvl is not None:
        if lvl not in INDEPENDENCE_LEVELS:
            errors.append(f"independence_level: invalid value {lvl!r}")
        if not report.get("system_under_test"):
            errors.append(
                "independence_level is set but system_under_test is missing. "
                "An I-level with no named system under test is not a claim."
            )
    ec = report.get("evidence_class")
    if ec is not None and ec not in EVIDENCE_CLASSES:
        errors.append(f"evidence_class: invalid value {ec!r}")

    # Same placement, same reason: a rule that only the jsonschema path enforces
    # is a rule that stops existing on the machine where jsonschema is missing,
    # and that machine gets told "NOT SCHEMA-VALIDATED" and nothing else. The
    # schema ALSO carries this as an if/then, so a document that reaches a
    # third-party validator is caught there too; the duplication is the same
    # one `dependentRequired` already has for independence_level.
    subject = report.get("subject")
    if isinstance(subject, dict):
        kind = subject.get("kind")
        if kind == "model" and subject.get("model") is None:
            errors.append(
                "subject.kind is 'model' but subject.model is null. A verdict "
                "about a model that names no model is not a verdict about a "
                "model -- state kind 'none' instead."
            )
    # Outside the isinstance guard on purpose: a subject of the wrong TYPE with
    # no provenance is still a subject with no provenance.
    if "subject" in report and "provenance" not in report:
        errors.append(
            "subject is present but provenance is missing. What was tested "
            "and what produced the statement travel together."
        )

    return errors


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------

def write_attestation_report(report: dict[str, Any], output_path: str) -> None:
    """Write an attestation report to a JSON file."""
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Attestation report written to {output_path}")
