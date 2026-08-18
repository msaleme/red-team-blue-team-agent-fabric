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
from typing import Any, Dict, List, Optional

__all__ = [
    "validate_attestation_report",
    "migrate_legacy_report",
    "generate_attestation_report",
    "AttestationEntry",
    "SCHEMA_VERSION",
    "EVIDENCE_CLASSES",
    "INDEPENDENCE_LEVELS",
]

SCHEMA_VERSION = "1.0.0"
SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "attestation-report.json"

# docs/EVIDENCE-CLASS-TAXONOMY.md. Kept here so a report can state its own class
# rather than having a server assign one outside the signature (#384).
EVIDENCE_CLASSES = ("E1", "E2", "E3", "E4", "E5")
INDEPENDENCE_LEVELS = ("I0", "I1", "I2")

# ---------------------------------------------------------------------------
# Scope/remediation lookup for known test IDs
# ---------------------------------------------------------------------------

_SCOPE_DEFAULTS: Dict[str, Dict[str, str]] = {
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


def _infer_scope(test_id: str, category: str = "") -> Dict[str, str]:
    """Infer scope metadata from a test_id prefix."""
    prefix = test_id.split("-")[0] if "-" in test_id else test_id[:3]
    defaults = _SCOPE_DEFAULTS.get(prefix, {"protocol": "other", "layer": "operational"})
    return {
        "protocol": defaults["protocol"],
        "layer": defaults["layer"],
        "attack_type": category.replace("_", " ") if category else "unknown",
    }


def _default_remediation() -> Dict[str, Any]:
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
        timestamp: Optional[str] = None,
        **kwargs: Any,
    ):
        self.data: Dict[str, Any] = {
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
        ):
            if key in kwargs:
                self.data[key] = kwargs[key]

        if "remediation" not in self.data:
            self.data["remediation"] = _default_remediation()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_attestation_report(
    entries: List[Dict[str, Any]],
    suite: str,
    harness_version: str,
    target: Optional[str] = None,
    evidence_class: Optional[str] = None,
    independence_level: str = "I0",
    system_under_test: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a complete attestation report dict.

    `independence_level` and `system_under_test` land INSIDE the report, which is
    the signed payload. Before #384 neither field existed here, so the only source
    of them was the receiving server -- assigned server-side, outside the
    signature, which is the operator assertion section 7 of the registry contract
    exists to avoid.

    An I-level is relative to a named system under test, so passing one without
    the other is rejected rather than silently recorded.
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
    passed = sum(1 for e in entries if e.get("result") == "pass")
    failed = sum(1 for e in entries if e.get("result") == "fail")
    errored = sum(1 for e in entries if e.get("result") == "error")
    skipped = sum(1 for e in entries if e.get("result") == "skip")

    report: Dict[str, Any] = {
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

    return report


# ---------------------------------------------------------------------------
# Legacy migration (v3.7 -> v3.8)
# ---------------------------------------------------------------------------

def migrate_legacy_report(legacy: Dict[str, Any], harness_version: str = "3.8.0") -> Dict[str, Any]:
    """Convert a v3.7-style report to the v3.8 attestation format.

    v3.7 format:
        { "suite", "timestamp", "summary", "results": [{ "test_id", "name", "category",
          "owasp_asi", "severity", "passed", "details", ... }] }

    Returns a valid attestation report dict.
    """
    entries: List[Dict[str, Any]] = []

    for r in legacy.get("results", []):
        result_str = "pass" if r.get("passed") else "fail"
        entry = AttestationEntry(
            test_id=r.get("test_id", "UNKNOWN"),
            category=r.get("category", ""),
            result=result_str,
            severity=r.get("severity", "P4-Info"),
            timestamp=r.get("timestamp", legacy.get("timestamp")),
            **{k: r[k] for k in ("name", "owasp_asi", "details", "elapsed_s",
                                  "request_sent", "response_received")
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

def validate_attestation_report(report: Dict[str, Any]) -> List[str]:
    """Validate a report dict against the attestation schema.

    Returns a list of error messages (empty = valid).
    Uses jsonschema if available, otherwise does basic structural checks.
    """
    errors: List[str] = []

    try:
        import jsonschema  # type: ignore[import-untyped]

        with open(SCHEMA_PATH) as f:
            schema = json.load(f)

        validator = jsonschema.Draft202012Validator(schema)
        for error in sorted(validator.iter_errors(report), key=lambda e: list(e.path)):
            path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            errors.append(f"{path}: {error.message}")

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

                if "result" in entry and entry["result"] not in ("pass", "fail", "error", "skip"):
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

    return errors


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------

def write_attestation_report(report: Dict[str, Any], output_path: str) -> None:
    """Write an attestation report to a JSON file."""
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Attestation report written to {output_path}")
