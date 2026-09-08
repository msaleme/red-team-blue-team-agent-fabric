#!/usr/bin/env python3
"""Community Attack Pattern Runner.

Discovers, validates, and executes YAML-based attack patterns from the
community_modules/ directory using the existing harness infrastructure.

Usage:
    # Run all community patterns
    python -m protocol_tests.community_runner --community

    # Run a specific pattern
    python -m protocol_tests.community_runner --pattern community_modules/examples/crewai_role_escape.yaml

    # Run patterns for a specific framework
    python -m protocol_tests.community_runner --community --framework crewai

    # Validate only (no execution)
    python -m protocol_tests.community_runner --validate

    # List discovered patterns
    python -m protocol_tests.community_runner --list

Regex evaluation bound (R3-07)
------------------------------
``field_matches`` assertions carry an attacker-controlled regular expression:
the YAML is untrusted. Length caps on the pattern (MAX_REGEX_LENGTH) and the
input (MAX_REGEX_INPUT_LENGTH) do not bound ``re.search`` -- ``(a|aa)+$`` is
200 characters short of the cap and does not finish on 37 characters of input.
Every community regex is therefore evaluated in a child interpreter that is
killed at MAX_REGEX_EVAL_SECONDS of wall clock. A pattern that is rejected
before evaluation or killed during it yields an INCONCLUSIVE assertion
("pattern evaluation exceeded budget"), never PASS, never FAIL: the target was
not observed, so nothing about it was established. A pattern with any
INCONCLUSIVE assertion is an INCONCLUSIVE pattern (``not_evaluated: true``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from protocol_tests.http_helpers import INCONCLUSIVE_PREFIX, http_post_json, is_inconclusive

try:
    import yaml
except ImportError:
    # Fallback: try to parse simple YAML without the library
    yaml = None  # type: ignore


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SPEC_VERSION = "1.0.0"
DEFAULT_MIN_HARNESS_VERSION = "3.8.0"

# Security limits
MAX_YAML_FILE_SIZE = 256 * 1024  # 256 KB max per YAML file
MAX_DELAY_MS = 30_000  # 30 seconds max delay per step
MAX_PATTERN_EXECUTION_TIMEOUT_S = 120  # 2 minutes max per pattern
MAX_REGEX_LENGTH = 200  # Max regex pattern length for field_matches
MAX_REGEX_INPUT_LENGTH = 10_000  # Max input length a field_matches regex is run against
# Wall-clock budget for ONE community regex evaluation. The match runs in a
# child interpreter that is killed when this elapses (R3-07); a length cap is
# not a bound, and a thread join is not a kill. Exceeding it is INCONCLUSIVE.
MAX_REGEX_EVAL_SECONDS = 1.0
REGEX_BUDGET_EXCEEDED = "pattern evaluation exceeded budget"
MAX_ATTACK_STEPS = 20  # Max number of attack steps per pattern
MAX_ASSERTIONS = 50  # Max number of assertions per pattern (R4-14)
PATTERN_BUDGET_EXCEEDED = "pattern execution exceeded budget"

#: Frameworks for which a live adapter exists. The adapter speaks JSON-RPC 2.0
#: over HTTP POST to ``--url``: MCP and A2A are JSON-RPC protocols and
#: ``generic`` is the plugin author saying "an HTTP JSON-RPC endpoint". The
#: agent frameworks (autogen, crewai, langgraph) have no wire protocol of
#: their own, and the payment protocols (x402, l402) are HTTP 402 flows, not
#: JSON-RPC; a live run against those is INCONCLUSIVE, never a PASS.
LIVE_ADAPTER_FRAMEWORKS = frozenset({"mcp", "a2a", "generic"})
NO_ADAPTER_DETAIL = "no adapter bound; the target was not contacted"
DRY_RUN_DETAIL = "(dry run \u2014 not evaluated)"

# Trust tiers (ordered by privilege)
TRUST_CORE = "core"          # Maintained by project maintainers
TRUST_VERIFIED = "verified"  # Reviewed and approved by maintainers
TRUST_COMMUNITY = "community"  # Submitted by community, restricted execution
TRUST_UNREVIEWED = "unreviewed"  # Not yet reviewed, validate-only
VALID_TRUST_TIERS = frozenset({TRUST_CORE, TRUST_VERIFIED, TRUST_COMMUNITY, TRUST_UNREVIEWED})

# Trust tiers that allow execution
EXECUTABLE_TRUST_TIERS = frozenset({TRUST_CORE, TRUST_VERIFIED, TRUST_COMMUNITY})

MANIFEST_FILE = "MANIFEST.yaml"

VALID_FRAMEWORKS = frozenset({
    "mcp", "a2a", "autogen", "crewai", "langgraph", "x402", "l402", "generic"
})

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})

VALID_EVIDENCE_TYPES = frozenset({
    "string", "object", "list", "integer", "boolean", "number"
})

REQUIRED_FIELDS = frozenset({
    "id", "version", "name", "description", "framework",
    "severity", "owasp_category", "attack_steps", "assertions", "evidence_schema"
})

REQUIRED_STEP_FIELDS = frozenset({"action", "target", "payload"})
REQUIRED_ASSERTION_FIELDS = frozenset({"type"})

ID_PATTERN = re.compile(r"^CP-\d{4}$")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ValidationError:
    """A single validation error."""
    file_path: str
    field: str
    message: str

    def __str__(self) -> str:
        return f"{self.file_path}: [{self.field}] {self.message}"


@dataclass
class PatternResult:
    """Result from executing a single community pattern."""
    test_id: str
    name: str
    category: str = "community"
    source_file: str = ""
    owasp_asi: str = ""
    severity: str = ""
    passed: bool = False
    details: str = ""
    elapsed_s: float = 0.0
    timestamp: str = ""
    evidence: dict = field(default_factory=dict)
    framework: str = ""
    assertions_passed: int = 0
    assertions_total: int = 0
    # INCONCLUSIVE marker read by http_helpers.is_inconclusive: at least one
    # assertion could not be evaluated, so no verdict on the target exists.
    not_evaluated: bool = False
    assertions_inconclusive: int = 0
    # How many steps reached the target and how many the target answered.
    # Zero answered means no assertion can be evaluated (R4-07).
    requests_sent: int = 0
    requests_answered: int = 0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        # The prefix in prose must imply the field, so a serialised record is
        # readable without re-parsing English (testing/test_inconclusive_is_structural).
        if not self.not_evaluated and is_inconclusive(self.details):
            self.not_evaluated = True
        if self.not_evaluated:
            self.passed = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackPattern:
    """Parsed and validated community attack pattern."""
    id: str
    version: str
    name: str
    description: str
    framework: str
    severity: str
    owasp_category: str
    attack_steps: list[dict]
    assertions: list[dict]
    evidence_schema: dict
    source_file: str = ""
    cve_reference: str = ""
    prerequisites: list[str] = field(default_factory=list)
    blue_team_mitigation: str = ""
    contributor: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    min_harness_version: str = DEFAULT_MIN_HARNESS_VERSION


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

def load_yaml(file_path: str) -> dict | None:
    """Load a YAML file and return as dict.

    Security: enforces file size limit to prevent YAML bombs (billion laughs).
    """
    if yaml is None:
        print("  ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
        return None

    try:
        # Check file size before loading (YAML bomb protection)
        file_size = os.path.getsize(file_path)
        if file_size > MAX_YAML_FILE_SIZE:
            print(f"  ERROR: {file_path} exceeds max size ({file_size} > {MAX_YAML_FILE_SIZE} bytes)", file=sys.stderr)
            return None

        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return None
        return data
    except yaml.YAMLError as e:
        print(f"  ERROR: Failed to parse {file_path}: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"  ERROR: Failed to read {file_path}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Manifest & integrity verification
# ---------------------------------------------------------------------------

def compute_file_hash(file_path: str) -> str:
    """Compute SHA-256 hash of a file's contents."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ManifestEntry:
    """A single entry in the community pattern manifest."""
    file: str
    id: str
    sha256: str | None
    trust: str
    reviewed_by: str = ""
    reviewed_at: str = ""


def load_manifest(community_dir: str) -> dict[str, ManifestEntry]:
    """Load the MANIFEST.yaml from the community directory.

    Returns a dict mapping relative file paths to ManifestEntry objects.
    Returns empty dict if no manifest exists (all patterns treated as unreviewed).
    """
    manifest_path = Path(community_dir) / MANIFEST_FILE
    if not manifest_path.exists():
        return {}

    data = load_yaml(str(manifest_path))
    if data is None:
        print("  WARNING: MANIFEST.yaml exists but failed to parse", file=sys.stderr)
        return {}

    entries = {}
    for item in data.get("patterns", []):
        if not isinstance(item, dict):
            continue
        file_rel = item.get("file", "")
        trust = str(item.get("trust", TRUST_UNREVIEWED)).lower()
        if trust not in VALID_TRUST_TIERS:
            trust = TRUST_UNREVIEWED
        entries[file_rel] = ManifestEntry(
            file=file_rel,
            id=item.get("id", ""),
            sha256=item.get("sha256"),
            trust=trust,
            reviewed_by=str(item.get("reviewed_by", "")),
            reviewed_at=str(item.get("reviewed_at", "")),
        )
    return entries


def verify_pattern_integrity(
    file_path: str,
    community_dir: str,
    manifest: dict[str, ManifestEntry],
    strict: bool = True,
) -> tuple[str, str | None]:
    """Verify a pattern file against the manifest.

    Returns (trust_tier, error_message).
    If error_message is not None, the pattern should not be executed.
    """
    # Compute relative path from community_dir
    try:
        rel_path = str(Path(file_path).resolve().relative_to(Path(community_dir).resolve()))
    except ValueError:
        return TRUST_UNREVIEWED, f"Pattern is outside community directory: {file_path}"

    # Check if pattern is in manifest
    entry = manifest.get(rel_path)
    if entry is None:
        if strict:
            return TRUST_UNREVIEWED, (
                f"Pattern not in MANIFEST.yaml: {rel_path}. "
                f"Add an entry to MANIFEST.yaml manually, or use --no-strict to skip verification."
            )
        return TRUST_UNREVIEWED, None  # Allow in non-strict mode

    # Verify SHA-256 hash if present
    if entry.sha256 and entry.sha256 != "null":
        actual_hash = compute_file_hash(file_path)
        if actual_hash != entry.sha256:
            return entry.trust, (
                f"Hash mismatch for {rel_path}: "
                f"expected {entry.sha256[:16]}..., got {actual_hash[:16]}... "
                f"File may have been tampered with."
            )

    # Unreviewed patterns can be validated but not executed
    if entry.trust == TRUST_UNREVIEWED:
        return TRUST_UNREVIEWED, None  # Will be blocked at execution time

    return entry.trust, None


def update_manifest(community_dir: str):
    """Update MANIFEST.yaml with current file hashes."""
    manifest_path = Path(community_dir) / MANIFEST_FILE
    if not manifest_path.exists():
        print(f"No MANIFEST.yaml found at {manifest_path}")
        return

    data = load_yaml(str(manifest_path))
    if data is None:
        return

    updated = 0
    for item in data.get("patterns", []):
        file_rel = item.get("file", "")
        full_path = Path(community_dir) / file_rel
        if full_path.exists():
            new_hash = compute_file_hash(str(full_path))
            old_hash = item.get("sha256")
            if old_hash != new_hash:
                item["sha256"] = new_hash
                updated += 1
                print(f"  Updated hash for {file_rel}: {new_hash[:16]}...")

    if updated > 0:
        with open(manifest_path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
        print(f"\nManifest updated: {updated} hash(es) written to {manifest_path}")
    else:
        print("All hashes are current. No updates needed.")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_patterns(base_dir: str) -> list[str]:
    """Find all YAML files in the community_modules directory tree."""
    patterns = []
    base = Path(base_dir)

    if not base.exists():
        return patterns

    for path in sorted(base.rglob("*.yaml")):
        # Skip the template and manifest
        if path.name in ("TEMPLATE.yaml", "MANIFEST.yaml"):
            continue
        patterns.append(str(path))

    for path in sorted(base.rglob("*.yml")):
        patterns.append(str(path))

    return patterns


def find_community_dir() -> str:
    """Locate the community_modules directory relative to the project root."""
    # Check common locations
    candidates = [
        Path("community_modules"),
        Path(__file__).parent.parent / "community_modules",
        Path.cwd() / "community_modules",
    ]

    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return str(candidate)

    return "community_modules"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_pattern(data: dict, file_path: str) -> tuple[AttackPattern | None, list[ValidationError]]:
    """Validate a parsed YAML dict against the plugin spec.

    Returns (pattern, errors). If errors is non-empty, pattern may be None.
    """
    errors: list[ValidationError] = []

    # Check required fields
    for req in REQUIRED_FIELDS:
        if req not in data:
            errors.append(ValidationError(file_path, req, f"Required field '{req}' is missing"))

    if errors:
        return None, errors

    # Validate ID format
    pattern_id = str(data["id"])
    if not ID_PATTERN.match(pattern_id):
        errors.append(ValidationError(
            file_path, "id",
            f"ID '{pattern_id}' does not match required format CP-XXXX (four digits)"
        ))

    # Validate framework
    framework = str(data["framework"]).lower()
    if framework not in VALID_FRAMEWORKS:
        errors.append(ValidationError(
            file_path, "framework",
            f"Framework '{framework}' is not valid. Must be one of: {', '.join(sorted(VALID_FRAMEWORKS))}"
        ))

    # Validate severity
    severity = str(data["severity"]).lower()
    if severity not in VALID_SEVERITIES:
        errors.append(ValidationError(
            file_path, "severity",
            f"Severity '{severity}' is not valid. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        ))

    # Validate attack_steps
    steps = data.get("attack_steps", [])
    if not isinstance(steps, list) or len(steps) == 0:
        errors.append(ValidationError(file_path, "attack_steps", "Must have at least one attack step"))
    else:
        if len(steps) > MAX_ATTACK_STEPS:
            errors.append(ValidationError(
                file_path, "attack_steps",
                f"Too many attack steps ({len(steps)} > {MAX_ATTACK_STEPS})"
            ))
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(ValidationError(file_path, f"attack_steps[{i}]", "Step must be an object"))
                continue
            for req in REQUIRED_STEP_FIELDS:
                if req not in step:
                    errors.append(ValidationError(
                        file_path, f"attack_steps[{i}].{req}",
                        f"Required step field '{req}' is missing"
                    ))
            action = step.get("action")
            if action is not None and str(action) not in VALID_ACTIONS:
                errors.append(ValidationError(
                    file_path, f"attack_steps[{i}].action",
                    f"Action '{action}' is not valid. Must be one of: {', '.join(sorted(VALID_ACTIONS))}"
                ))

    # Validate assertions
    assertions = data.get("assertions", [])
    if not isinstance(assertions, list) or len(assertions) == 0:
        errors.append(ValidationError(file_path, "assertions", "Must have at least one assertion"))
    else:
        if len(assertions) > MAX_ASSERTIONS:
            errors.append(ValidationError(
                file_path, "assertions",
                f"Too many assertions ({len(assertions)} > {MAX_ASSERTIONS})"
            ))
        for i, assertion in enumerate(assertions):
            if not isinstance(assertion, dict):
                errors.append(ValidationError(file_path, f"assertions[{i}]", "Assertion must be an object"))
                continue
            for req in REQUIRED_ASSERTION_FIELDS:
                if req not in assertion:
                    errors.append(ValidationError(
                        file_path, f"assertions[{i}].{req}",
                        f"Required assertion field '{req}' is missing"
                    ))
            atype = assertion.get("type")
            if atype is not None and str(atype) not in VALID_ASSERTION_TYPES:
                errors.append(ValidationError(
                    file_path, f"assertions[{i}].type",
                    f"Assertion type '{atype}' is not valid. Must be one of: {', '.join(sorted(VALID_ASSERTION_TYPES))}"
                ))

    # Validate evidence_schema: it must be an object. A string or list here
    # was accepted and later iterated as characters/items (R4-14).
    schema = data.get("evidence_schema", {})
    if not isinstance(schema, dict):
        errors.append(ValidationError(
            file_path, "evidence_schema",
            f"Must be an object mapping field names to types, got {type(schema).__name__}"
        ))
    else:
        for key, type_name in schema.items():
            if str(type_name).lower() not in VALID_EVIDENCE_TYPES:
                errors.append(ValidationError(
                    file_path, f"evidence_schema.{key}",
                    f"Type '{type_name}' is not valid. Must be one of: {', '.join(sorted(VALID_EVIDENCE_TYPES))}"
                ))

    if errors:
        return None, errors

    # Build the pattern object
    pattern = AttackPattern(
        id=pattern_id,
        version=str(data["version"]),
        name=str(data["name"]),
        description=str(data["description"]),
        framework=framework,
        severity=severity,
        owasp_category=str(data["owasp_category"]),
        attack_steps=steps,
        assertions=assertions,
        evidence_schema=schema,
        source_file=file_path,
        cve_reference=str(data.get("cve_reference", "")),
        prerequisites=data.get("prerequisites", []) or [],
        blue_team_mitigation=str(data.get("blue_team_mitigation", "")),
        contributor=data.get("contributor", {}) or {},
        tags=data.get("tags", []) or [],
        min_harness_version=str(data.get("min_harness_version", DEFAULT_MIN_HARNESS_VERSION)),
    )

    return pattern, []


# ---------------------------------------------------------------------------
# Execution engine
# ---------------------------------------------------------------------------

# Map framework names to harness modules for delegation
FRAMEWORK_HARNESS_MAP = {
    "mcp": "protocol_tests.mcp_harness",
    "a2a": "protocol_tests.a2a_harness",
    "l402": "protocol_tests.l402_harness",
    "x402": "protocol_tests.x402_harness",
    "autogen": "protocol_tests.framework_adapters",
    "crewai": "protocol_tests.framework_adapters",
    "langgraph": "protocol_tests.framework_adapters",
}


class HttpJsonRpcAdapter:
    """The one live adapter: JSON-RPC 2.0 over HTTP POST to ``--url``.

    Before this existed, ``send_message``, ``send_jsonrpc`` and ``call_tool``
    returned ``{"status": "sent", "response": None}`` with the comment
    "Populated by harness integration", so a "live" run with ``--url`` never
    opened a socket and an absence assertion passed against a target that
    was never reached (R4-07, fourth external review, 2026-09-08).

    Every call returns the namespaced dict ``http_post_json`` produces:
    ``_status`` when the target answered (any HTTP status is an answer),
    ``_exception`` when it did not.
    """

    def __init__(self, url: str, timeout_s: int = 15):
        self.url = url
        self.timeout_s = timeout_s

    def send_jsonrpc(self, message: dict) -> dict:
        return http_post_json(self.url, message, timeout=self.timeout_s)

    @staticmethod
    def answered(resp: dict) -> bool:
        return isinstance(resp, dict) and "_status" in resp and "_exception" not in resp


def bind_adapter(framework: str, target_url: str):
    """Return the live adapter for *framework* at *target_url*, or None."""
    if not target_url:
        return None
    if framework not in LIVE_ADAPTER_FRAMEWORKS:
        return None
    return HttpJsonRpcAdapter(target_url)


class StepExecutor:
    """Executes individual attack steps.

    This is the bridge between YAML-declared steps and the harness infrastructure.
    Each action type maps to a method that delegates to the appropriate harness.

    Three actions contact the target through ``self.adapter``: ``send_message``,
    ``send_jsonrpc`` and ``call_tool``. The rest are local simulations that
    never open a socket, and say so in their result. With no adapter bound the
    three record ``not_sent`` and count nothing as answered, which run_pattern
    turns into INCONCLUSIVE for every assertion.
    """

    def __init__(self, pattern: AttackPattern, target_url: str = "",
                 verbose: bool = False, adapter=None):
        self.pattern = pattern
        self.target_url = target_url
        self.verbose = verbose
        self.evidence: dict[str, Any] = {}
        self.responses: list[dict] = []
        self.adapter = adapter if adapter is not None else bind_adapter(
            pattern.framework, target_url)
        self.requests_sent = 0
        self.requests_answered = 0

    def _live(self, target: str, message: dict, extra: dict) -> dict:
        """Send *message* through the adapter and record whether it was answered."""
        if self.adapter is None:
            return {"status": "not_sent", "target": target,
                    "reason": NO_ADAPTER_DETAIL, **extra}
        self.requests_sent += 1
        resp = self.adapter.send_jsonrpc(message)
        answered = HttpJsonRpcAdapter.answered(resp)
        if answered:
            self.requests_answered += 1
        record = {
            "status": "sent" if answered else "unanswered",
            "target": target,
            "request_sent": message,
            "response": resp.get("response") if isinstance(resp, dict) else None,
            "http_status": resp.get("_status") if isinstance(resp, dict) else None,
            **extra,
        }
        if not answered:
            record["error"] = resp.get("_exception", "no answer") if isinstance(resp, dict) else "no answer"
        return record

    def execute_step(self, step: dict) -> dict:
        """Execute a single attack step and return the result."""
        action = step.get("action", "unknown")
        target = step.get("target", "unknown")
        payload = step.get("payload", {})
        delay_ms = step.get("delay_ms", 0)

        # Cap delay to prevent YAML-controlled blocking (max 30s, floor at 0)
        if delay_ms > 0:
            delay_ms = max(0, min(delay_ms, MAX_DELAY_MS))
            time.sleep(delay_ms / 1000.0)

        handler = getattr(self, f"_do_{action}", None)
        if handler is None:
            if self.verbose:
                print(f"    WARNING: Unknown action '{action}', skipping")
            return {"status": "skipped", "reason": f"Unknown action: {action}"}

        try:
            result = handler(target, payload)
            self.responses.append(result)
            return result
        except Exception as e:
            error_result = {"status": "error", "error": str(e)}
            self.responses.append(error_result)
            return error_result

    def _do_send_message(self, target: str, payload: dict) -> dict:
        """Send a message to the target as an A2A ``message/send`` request."""
        content = str(payload.get("content", ""))
        message = {
            "jsonrpc": "2.0",
            "method": "message/send",
            "params": {
                "message": {
                    "role": payload.get("role") or "user",
                    "parts": [{"kind": "text", "text": content}],
                    "messageId": f"community-{uuid.uuid4().hex[:12]}",
                    "metadata": payload.get("metadata", {}) or {},
                },
            },
            "id": payload.get("id", "community-test-1"),
        }
        return self._live(target, message, {
            "role": payload.get("role", ""),
            "content_length": len(content),
        })

    def _do_send_jsonrpc(self, target: str, payload: dict) -> dict:
        """Send a raw JSON-RPC 2.0 message to the target."""
        message = {
            "jsonrpc": "2.0",
            "method": payload.get("method", ""),
            "params": payload.get("params", {}),
            "id": payload.get("id", "community-test-1"),
        }
        return self._live(target, message, {})

    def _do_call_tool(self, target: str, payload: dict) -> dict:
        """Invoke a tool by name as an MCP ``tools/call`` request."""
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": payload.get("tool_name", ""),
                "arguments": payload.get("arguments", {}) or {},
            },
            "id": payload.get("id", "community-test-1"),
        }
        return self._live(target, message, {
            "tool_name": payload.get("tool_name", ""),
        })

    def _do_inject_description(self, target: str, payload: dict) -> dict:
        """Simulate injecting a modified tool description (never contacts the target)."""
        return {
            "status": "injected",
            "live": False,
            "target": target,
            "tool_name": payload.get("tool_name", ""),
            "injected_length": len(str(payload.get("injected_text", ""))),
        }

    def _do_register_tool(self, target: str, payload: dict) -> dict:
        """Simulate registering a new tool (never contacts the target)."""
        return {
            "status": "registered",
            "live": False,
            "target": target,
            "tool_name": payload.get("tool_name", ""),
            "description_length": len(str(payload.get("description", ""))),
            "schema": payload.get("schema", {}),
        }

    def _do_modify_context(self, target: str, payload: dict) -> dict:
        """Simulate modifying agent context (never contacts the target)."""
        return {
            "status": "modified",
            "live": False,
            "target": target,
            "context_key": payload.get("context_key", ""),
        }

    def _do_http_request(self, target: str, payload: dict) -> dict:
        """Simulate an HTTP request (for exfiltration detection; never sent)."""
        return {
            "status": "simulated",
            "live": False,
            "method": payload.get("method", "GET"),
            "url": payload.get("url", ""),
            "note": "HTTP request simulated - not actually sent during dry run",
        }

    def _do_wait(self, target: str, payload: dict) -> dict:
        """Wait for a specified duration (capped at MAX_DELAY_MS, floor at 0)."""
        duration_ms = max(0, min(payload.get("duration_ms", 0), MAX_DELAY_MS))
        time.sleep(duration_ms / 1000.0)
        return {"status": "waited", "duration_ms": duration_ms}

    def _do_assert_state(self, target: str, payload: dict) -> dict:
        """Check intermediate state (local; never contacts the target)."""
        return {
            "status": "checked",
            "live": False,
            "condition": payload.get("condition", ""),
            "expected": payload.get("expected", ""),
        }


class AssertionEvaluator:
    """Evaluates assertions against collected evidence and responses."""

    def __init__(self, evidence: dict, responses: list[dict]):
        self.evidence = evidence
        self.responses = responses

    def evaluate(self, assertion: dict) -> tuple[bool, str]:
        """Evaluate a single assertion. Returns (passed, detail_message)."""
        atype = assertion.get("type", "")
        handler = getattr(self, f"_check_{atype}", None)

        if handler is None:
            return False, f"Unknown assertion type: {atype}"

        try:
            return handler(assertion)
        except Exception as e:
            return False, f"Assertion error: {e}"

    def _check_response_must_not_contain(self, assertion: dict) -> tuple[bool, str]:
        field_name = assertion.get("field", "")
        forbidden = str(assertion.get("value", ""))
        all_text = json.dumps(self.responses) + json.dumps(self.evidence)

        if forbidden.lower() in all_text.lower():
            return False, f"Found forbidden value '{forbidden}' in {field_name}"
        return True, f"Value '{forbidden}' not found in responses (good)"

    def _check_response_must_contain(self, assertion: dict) -> tuple[bool, str]:
        field_name = assertion.get("field", "")
        required = str(assertion.get("value", ""))
        all_text = json.dumps(self.responses) + json.dumps(self.evidence)

        if required.lower() in all_text.lower():
            return True, f"Found required value '{required}' in {field_name}"
        return False, f"Required value '{required}' not found in {field_name}"

    def _check_status_code_equals(self, assertion: dict) -> tuple[bool, str]:
        expected = assertion.get("value")
        for resp in self.responses:
            code = resp.get("status_code")
            if code is not None and int(code) == int(expected):
                return True, f"Status code {expected} matched"
        return False, f"Expected status code {expected} not found"

    def _check_role_boundary_held(self, assertion: dict) -> tuple[bool, str]:
        expected_role = assertion.get("expected_role", "")
        role_start = self.evidence.get("role_at_start", expected_role)
        role_end = self.evidence.get("role_at_end", expected_role)

        if role_start == expected_role and role_end == expected_role:
            return True, f"Role boundary held: {expected_role}"
        return False, f"Role boundary violated: started as '{role_start}', ended as '{role_end}'"

    def _check_no_data_exfiltration(self, assertion: dict) -> tuple[bool, str]:
        exfil = self.evidence.get("exfiltration_attempted", False)
        if exfil:
            return False, "Data exfiltration was attempted"
        return True, "No data exfiltration detected"

    def _check_error_returned(self, assertion: dict) -> tuple[bool, str]:
        for resp in self.responses:
            if "error" in resp:
                expected_code = assertion.get("error_code")
                if expected_code is None:
                    return True, f"Error returned: {resp['error']}"
                if resp.get("error_code") == expected_code:
                    return True, f"Error code {expected_code} returned"
        return False, "No error response found"

    def _check_tool_not_executed(self, assertion: dict) -> tuple[bool, str]:
        tool_name = str(assertion.get("value", ""))
        tools_called = self.evidence.get("tools_called", [])
        actions_executed = self.evidence.get("actions_executed", [])

        if tool_name in tools_called or tool_name in actions_executed:
            return False, f"Tool '{tool_name}' was executed (should not have been)"
        return True, f"Tool '{tool_name}' was not executed (good)"

    def _check_field_equals(self, assertion: dict) -> tuple[bool, str]:
        field_name = assertion.get("field", "")
        expected = assertion.get("value")
        actual = self.evidence.get(field_name)

        if actual == expected:
            return True, f"Field '{field_name}' equals '{expected}'"
        return False, f"Field '{field_name}' is '{actual}', expected '{expected}'"

    def _check_field_matches(self, assertion: dict) -> tuple[bool, str]:
        field_name = assertion.get("field", "")
        pattern = str(assertion.get("value", ""))
        actual = str(self.evidence.get(field_name, ""))

        # ReDoS protection, layer 1: caps. These bound the *size* of the work,
        # not its running time -- see MAX_REGEX_EVAL_SECONDS for the bound.
        if len(pattern) > MAX_REGEX_LENGTH:
            return False, (f"{INCONCLUSIVE_PREFIX}{REGEX_BUDGET_EXCEEDED}: regex pattern "
                           f"too long ({len(pattern)} > {MAX_REGEX_LENGTH} chars)")
        # Truncate input to prevent catastrophic backtracking on large data
        if len(actual) > MAX_REGEX_INPUT_LENGTH:
            actual = actual[:MAX_REGEX_INPUT_LENGTH]
        # Layer 2: reject the one syntactic ReDoS shape that is cheap to name
        # (nested quantifiers). Ambiguous alternation such as (a|aa)+ is not
        # named here and is why layer 3 exists.
        if re.search(r'\([^)]*[+*][^)]*\)[+*]', pattern):
            return False, (f"{INCONCLUSIVE_PREFIX}{REGEX_BUDGET_EXCEEDED}: regex contains "
                           f"nested quantifiers (potential ReDoS)")
        # Layer 3: the wall-clock bound, enforced by killing a child process.
        outcome, message = evaluate_regex_bounded(pattern, actual)
        if outcome == "match":
            return True, f"Field '{field_name}' matches pattern '{pattern}'"
        if outcome == "nomatch":
            return False, f"Field '{field_name}' does not match pattern '{pattern}'"
        if outcome == "error":
            return False, f"{INCONCLUSIVE_PREFIX}invalid regex pattern: {message}"
        return False, f"{INCONCLUSIVE_PREFIX}{REGEX_BUDGET_EXCEEDED}: {message}"


#: The action and assertion vocabularies, derived from the two dispatch tables
#: rather than written down a second time: a handler that exists is valid, a
#: name with no handler is rejected at validation instead of being skipped or
#: reported "Unknown assertion type" at run time (R4-14).
VALID_ACTIONS = frozenset(
    name[len("_do_"):] for name in vars(StepExecutor) if name.startswith("_do_"))
VALID_ASSERTION_TYPES = frozenset(
    name[len("_check_"):] for name in vars(AssertionEvaluator) if name.startswith("_check_"))


# ---------------------------------------------------------------------------
# Bounded regex evaluation (R3-07)
# ---------------------------------------------------------------------------

# Runs in a separate interpreter: reads {"pattern", "text"} on stdin, writes
# {"matched": bool} or {"error": str} on stdout. Only stdlib, isolated mode.
_REGEX_WORKER_SRC = (
    "import json, re, sys\n"
    "job = json.load(sys.stdin)\n"
    "try:\n"
    "    out = {'matched': re.search(job['pattern'], job['text']) is not None}\n"
    "except re.error as exc:\n"
    "    out = {'error': str(exc)}\n"
    "sys.stdout.write(json.dumps(out))\n"
)


def evaluate_regex_bounded(
    pattern: str,
    text: str,
    budget_s: float | None = None,
) -> tuple[str, str]:
    """Run ``re.search(pattern, text)`` under a hard wall-clock bound.

    Returns ``(outcome, message)`` where outcome is one of ``"match"``,
    ``"nomatch"``, ``"error"`` (the pattern does not compile) or
    ``"timeout"`` (the child was killed at the budget). The match runs in a
    child interpreter so that the kill is real: a thread that is joined with
    a timeout keeps running, a child process that is killed does not.
    """
    budget = MAX_REGEX_EVAL_SECONDS if budget_s is None else budget_s
    job = json.dumps({"pattern": pattern, "text": text})
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", _REGEX_WORKER_SRC],
            input=job,
            capture_output=True,
            text=True,
            timeout=budget,
        )
    except subprocess.TimeoutExpired:
        # subprocess.run has already killed the child on this path.
        return "timeout", f"regex did not finish within {budget:g}s"
    except (OSError, ValueError) as exc:
        return "timeout", f"regex worker could not be started ({exc})"
    if proc.returncode != 0:
        return "timeout", f"regex worker exited {proc.returncode}"
    try:
        out = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return "timeout", "regex worker returned no verdict"
    if "error" in out:
        return "error", str(out["error"])
    if "matched" not in out:
        return "timeout", "regex worker returned no verdict"
    return ("match" if out["matched"] else "nomatch"), ""


# ---------------------------------------------------------------------------
# Pattern runner
# ---------------------------------------------------------------------------

def _budget_result(pattern: AttackPattern, elapsed: float, where: str,
                   executor: "StepExecutor | None" = None) -> PatternResult:
    """INCONCLUSIVE: the pattern ran past its budget, so nothing was verified."""
    return PatternResult(
        test_id=pattern.id,
        name=pattern.name,
        source_file=pattern.source_file,
        owasp_asi=pattern.owasp_category,
        severity=pattern.severity,
        passed=False,
        details=(f"{INCONCLUSIVE_PREFIX}{PATTERN_BUDGET_EXCEEDED}: {elapsed:.2f}s "
                 f"elapsed (limit: {MAX_PATTERN_EXECUTION_TIMEOUT_S}s) at {where}; "
                 f"no assertion verdict was recorded"),
        elapsed_s=round(elapsed, 3),
        framework=pattern.framework,
        assertions_total=len(pattern.assertions),
        assertions_inconclusive=len(pattern.assertions),
        not_evaluated=True,
        requests_sent=executor.requests_sent if executor else 0,
        requests_answered=executor.requests_answered if executor else 0,
    )


def run_pattern(
    pattern: AttackPattern,
    target_url: str = "",
    verbose: bool = False,
    dry_run: bool = False,
    adapter=None,
) -> PatternResult:
    """Execute a community attack pattern and return the result.

    Each pattern is capped at MAX_PATTERN_EXECUTION_TIMEOUT_S seconds of
    wall clock across ALL steps and ALL assertions. The deadline is checked
    before and after every step, after every assertion and once at the end;
    overrunning it is INCONCLUSIVE (R4-14). It used to be checked only before
    each step, so a final step or the assertion phase could run unbounded.

    Verdict rules (R4-07):

    * dry run: no step runs, every assertion is INCONCLUSIVE with
      ``(dry run \u2014 not evaluated)``; the pattern is INCONCLUSIVE.
    * no adapter bound (no ``--url``, or a framework with no live adapter):
      every assertion is INCONCLUSIVE with ``no adapter bound; the target was
      not contacted``.
    * adapter bound but the target answered none of the requests sent (or no
      step contacts the target at all): every assertion is INCONCLUSIVE.
    * otherwise the assertions are evaluated against what the target said.
    """
    start_time = time.monotonic()

    def over_budget() -> float | None:
        elapsed = time.monotonic() - start_time
        return elapsed if elapsed > MAX_PATTERN_EXECUTION_TIMEOUT_S else None

    executor = StepExecutor(pattern, target_url=target_url, verbose=verbose, adapter=adapter)

    # Execute attack steps
    if verbose:
        print(f"\n  Running: {pattern.id} - {pattern.name}")
        print(f"  Framework: {pattern.framework} | Severity: {pattern.severity}")
        print(f"  Steps: {len(pattern.attack_steps)} | Assertions: {len(pattern.assertions)}")
        if not dry_run and executor.adapter is None:
            print(f"  WARNING: {NO_ADAPTER_DETAIL}")

    n_steps = len(pattern.attack_steps)
    for i, step in enumerate(pattern.attack_steps):
        elapsed = over_budget()
        if elapsed is not None:
            if verbose:
                print(f"    TIMEOUT: Pattern exceeded {MAX_PATTERN_EXECUTION_TIMEOUT_S}s limit")
            return _budget_result(pattern, elapsed, f"before step {i + 1}/{n_steps}", executor)

        if verbose:
            desc = step.get("description", step.get("action", "step"))
            print(f"    Step {i+1}/{n_steps}: {step['action']} -> {step['target']}")

        if not dry_run:
            executor.execute_step(step)
        else:
            if verbose:
                print("      (dry run - skipped)")

        elapsed = over_budget()
        if elapsed is not None:
            if verbose:
                print(f"    TIMEOUT: Pattern exceeded {MAX_PATTERN_EXECUTION_TIMEOUT_S}s limit")
            return _budget_result(pattern, elapsed, f"after step {i + 1}/{n_steps}", executor)

    # Build evidence from schema defaults
    evidence = {}
    for key, type_name in pattern.evidence_schema.items():
        evidence[key] = executor.evidence.get(key, _default_for_type(type_name))

    # Decide, once, whether any assertion can be evaluated at all.
    unevaluable: str | None = None
    if dry_run:
        unevaluable = DRY_RUN_DETAIL
    elif executor.adapter is None:
        why = ("no --url given" if not target_url
               else f"no live adapter for framework '{pattern.framework}'")
        unevaluable = f"{NO_ADAPTER_DETAIL} ({why})"
    elif executor.requests_sent == 0:
        unevaluable = ("no step contacts the target (only simulated actions); "
                       "the target was not contacted")
    elif executor.requests_answered == 0:
        unevaluable = (f"the target answered none of {executor.requests_sent} "
                       f"request(s); nothing to evaluate")

    # Evaluate assertions
    evaluator = AssertionEvaluator(evidence, executor.responses)
    assertions_passed = 0
    assertion_details = []

    assertions_inconclusive = 0

    n_assertions = len(pattern.assertions)
    for i, assertion in enumerate(pattern.assertions):
        if unevaluable is not None:
            passed = False
            detail = f"{INCONCLUSIVE_PREFIX}{unevaluable}"
        else:
            passed, detail = evaluator.evaluate(assertion)

        # An assertion that could not be evaluated (regex budget exceeded,
        # R3-07; no target contact, R4-07) is a third state: it is not a
        # target failure and it is never a pass.
        inconclusive = (not passed) and is_inconclusive(detail)
        if passed:
            assertions_passed += 1
        elif inconclusive:
            assertions_inconclusive += 1

        status = "PASS" if passed else ("INCONCLUSIVE" if inconclusive else "FAIL")
        desc = assertion.get("description", assertion.get("type", ""))
        assertion_details.append(f"{status}: {desc} - {detail}")

        if verbose:
            icon = "ok" if passed else status
            print(f"    Assertion {i+1}: [{icon}] {desc}")

        elapsed = over_budget()
        if elapsed is not None:
            if verbose:
                print(f"    TIMEOUT: Pattern exceeded {MAX_PATTERN_EXECUTION_TIMEOUT_S}s limit")
            return _budget_result(pattern, elapsed, f"after assertion {i + 1}/{n_assertions}", executor)

    elapsed = over_budget()
    if elapsed is not None:
        return _budget_result(pattern, elapsed, "end of pattern", executor)

    elapsed = time.monotonic() - start_time
    all_passed = assertions_passed == len(pattern.assertions)
    not_evaluated = assertions_inconclusive > 0
    details = "; ".join(assertion_details)
    if not_evaluated:
        details = f"{INCONCLUSIVE_PREFIX}{assertions_inconclusive} assertion(s) not evaluated; {details}"

    result = PatternResult(
        test_id=pattern.id,
        name=pattern.name,
        source_file=pattern.source_file,
        owasp_asi=pattern.owasp_category,
        severity=pattern.severity,
        passed=all_passed and not not_evaluated,
        details=details,
        elapsed_s=round(elapsed, 3),
        evidence=evidence,
        framework=pattern.framework,
        assertions_passed=assertions_passed,
        assertions_total=len(pattern.assertions),
        not_evaluated=not_evaluated,
        assertions_inconclusive=assertions_inconclusive,
        requests_sent=executor.requests_sent,
        requests_answered=executor.requests_answered,
    )

    if verbose:
        status = "PASS" if result.passed else ("INCONCLUSIVE" if not_evaluated else "FAIL")
        print(f"  Result: {status} ({assertions_passed}/{len(pattern.assertions)} assertions)")

    return result


def _default_for_type(type_name: str) -> Any:
    """Return a default value for an evidence schema type."""
    defaults = {
        "string": "",
        "object": {},
        "list": [],
        "integer": 0,
        "boolean": False,
        "number": 0.0,
    }
    return defaults.get(str(type_name).lower(), None)


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def run_community_tests(
    community_dir: str | None = None,
    pattern_file: str | None = None,
    framework_filter: str | None = None,
    severity_filter: str | None = None,
    target_url: str = "",
    verbose: bool = False,
    validate_only: bool = False,
    list_only: bool = False,
    dry_run: bool = False,
    strict: bool = True,
) -> dict:
    """Discover, validate, and run community patterns.

    Returns a summary dict compatible with the core harness JSON output.
    """
    # Discover patterns
    if pattern_file:
        yaml_files = [pattern_file]
    else:
        base_dir = community_dir or find_community_dir()
        yaml_files = discover_patterns(base_dir)

    if not yaml_files:
        print("No community patterns found.")
        return {"patterns_found": 0, "results": []}

    print(f"Discovered {len(yaml_files)} community pattern(s)")

    # Load manifest for integrity verification
    base_dir = community_dir or find_community_dir()
    manifest = load_manifest(base_dir)
    if manifest:
        print(f"Manifest loaded: {len(manifest)} registered pattern(s)")
    elif strict:
        print("WARNING: No MANIFEST.yaml found. Use --update-manifest to create hashes.")
        print("         Running in strict mode - unmanifested patterns will be rejected.")

    # Load and validate
    patterns: list[AttackPattern] = []
    pattern_trust: dict[str, str] = {}  # pattern_id -> trust tier
    all_errors: list[ValidationError] = []
    seen_ids: set[str] = set()

    for fp in yaml_files:
        # Manifest integrity check
        trust_tier, integrity_error = verify_pattern_integrity(fp, base_dir, manifest, strict=strict)
        if integrity_error:
            all_errors.append(ValidationError(fp, "integrity", integrity_error))
            continue

        data = load_yaml(fp)
        if data is None:
            all_errors.append(ValidationError(fp, "file", "Failed to parse YAML"))
            continue

        pattern, errors = validate_pattern(data, fp)
        if errors:
            all_errors.extend(errors)
            continue

        assert pattern is not None

        # Check ID uniqueness
        if pattern.id in seen_ids:
            all_errors.append(ValidationError(fp, "id", f"Duplicate ID '{pattern.id}'"))
            continue
        seen_ids.add(pattern.id)

        # Block patterns outside executable trust tiers
        if trust_tier not in EXECUTABLE_TRUST_TIERS and not validate_only and not list_only:
            print(f"  SKIP {pattern.id}: trust tier '{trust_tier}' is not executable (requires: {', '.join(sorted(EXECUTABLE_TRUST_TIERS))})")
            continue

        pattern_trust[pattern.id] = trust_tier
        patterns.append(pattern)

    # Report validation errors
    if all_errors:
        print(f"\nValidation errors ({len(all_errors)}):")
        for err in all_errors:
            print(f"  {err}")

    if validate_only:
        valid = len(patterns)
        total = len(yaml_files)
        print(f"\nValidation complete: {valid}/{total} patterns valid")
        return {
            "patterns_found": total,
            "patterns_valid": valid,
            "errors": [str(e) for e in all_errors],
        }

    # Apply filters
    if framework_filter:
        frameworks = {f.strip().lower() for f in framework_filter.split(",")}
        patterns = [p for p in patterns if p.framework in frameworks]

    if severity_filter:
        severities = {s.strip().lower() for s in severity_filter.split(",")}
        patterns = [p for p in patterns if p.severity in severities]

    # List mode
    if list_only:
        print(f"\nCommunity patterns ({len(patterns)}):")
        for p in patterns:
            trust = pattern_trust.get(p.id, "?")
            print(f"  {p.id:10s} [{p.severity:8s}] [{p.framework:10s}] [{trust:10s}] {p.name}")
            if p.cve_reference:
                print(f"             CVE: {p.cve_reference}")
        return {"patterns_found": len(patterns), "patterns": [asdict(p) for p in patterns]}

    # Execute patterns
    print(f"\nRunning {len(patterns)} community pattern(s)...\n")
    if dry_run:
        print("  DRY RUN: no step is executed and no assertion is evaluated; "
              "every pattern below is INCONCLUSIVE.")
    elif not target_url:
        print(f"  WARNING: {NO_ADAPTER_DETAIL} (no --url given). Every assertion "
              "below is INCONCLUSIVE. Pass --url to run live, or --dry-run to "
              "say so explicitly.")
    else:
        unsupported = sorted({p.framework for p in patterns
                              if p.framework not in LIVE_ADAPTER_FRAMEWORKS})
        if unsupported:
            print(f"  WARNING: no live adapter for framework(s) "
                  f"{', '.join(unsupported)}; those patterns are INCONCLUSIVE "
                  f"(live adapters: {', '.join(sorted(LIVE_ADAPTER_FRAMEWORKS))}).")
    results: list[PatternResult] = []

    for pattern in patterns:
        result = run_pattern(pattern, target_url=target_url, verbose=verbose, dry_run=dry_run)
        results.append(result)
        status = "PASS" if result.passed else ("INCONCLUSIVE" if result.not_evaluated else "FAIL")
        print(f"  {status} {result.test_id}: {result.name} "
              f"({result.assertions_passed}/{result.assertions_total} assertions, "
              f"{result.elapsed_s:.2f}s)")

    # Summary -- INCONCLUSIVE is counted apart from FAIL, not folded into it.
    passed = sum(1 for r in results if r.passed)
    inconclusive = sum(1 for r in results if not r.passed and r.not_evaluated)
    failed = len(results) - passed - inconclusive
    total_time = sum(r.elapsed_s for r in results)

    print(f"\n{'='*60}")
    print(f"Community Pattern Results: {passed} passed, {failed} failed, "
          f"{inconclusive} inconclusive ({len(results)} total, {total_time:.2f}s)")
    print(f"{'='*60}")

    summary = {
        "spec_version": SPEC_VERSION,
        "harness": "community_runner",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "patterns_found": len(yaml_files),
        "patterns_valid": len(patterns),
        "patterns_run": len(results),
        "passed": passed,
        "failed": failed,
        "inconclusive": inconclusive,
        "total_time_s": round(total_time, 3),
        "results": [r.to_dict() for r in results],
    }

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Community Attack Pattern Runner for Agent Security Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --community                          Run all community patterns
  %(prog)s --pattern path/to/pattern.yaml       Run a specific pattern
  %(prog)s --community --framework crewai       Run CrewAI patterns only
  %(prog)s --community --severity critical,high Run critical+high only
  %(prog)s --validate                           Validate without running
  %(prog)s --list                               List discovered patterns
        """,
    )

    parser.add_argument("--community", action="store_true",
                        help="Run all community patterns")
    parser.add_argument("--pattern", type=str,
                        help="Run a specific pattern YAML file")
    parser.add_argument("--community-dir", type=str,
                        help="Path to community_modules directory")
    parser.add_argument("--framework", type=str,
                        help="Filter by framework (comma-separated)")
    parser.add_argument("--severity", type=str,
                        help="Filter by severity (comma-separated)")
    parser.add_argument("--url", type=str, default="",
                        help="Target URL for live testing (JSON-RPC 2.0 over HTTP POST; "
                             "frameworks mcp, a2a, generic). Without it no target is "
                             "contacted and every assertion is INCONCLUSIVE.")
    parser.add_argument("--validate", action="store_true",
                        help="Validate patterns without running them")
    parser.add_argument("--list", action="store_true",
                        help="List discovered patterns")
    parser.add_argument("--dry-run", action="store_true",
                        help="Walk the pattern without executing steps or evaluating "
                             "assertions; every result is INCONCLUSIVE, never PASS")
    parser.add_argument("--no-strict", action="store_true",
                        help="Allow patterns not in MANIFEST.yaml (not recommended)")
    parser.add_argument("--update-manifest", action="store_true",
                        help="Update MANIFEST.yaml with current file SHA-256 hashes")
    parser.add_argument("--hash", type=str, metavar="FILE",
                        help="Print SHA-256 hash of a pattern file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--report", type=str,
                        help="Write JSON report to file")

    args = parser.parse_args()

    # Handle --hash (standalone utility, restricted to project directory)
    if args.hash:
        hash_path = Path(args.hash).resolve()
        cwd = Path.cwd().resolve()
        if not hash_path.is_relative_to(cwd):
            print("ERROR: --hash path must be within the project directory", file=sys.stderr)
            sys.exit(1)
        h = compute_file_hash(args.hash)
        print(f"{h}  {args.hash}")
        sys.exit(0)

    # Handle --update-manifest (standalone utility)
    if args.update_manifest:
        base_dir = args.community_dir or find_community_dir()
        update_manifest(base_dir)
        sys.exit(0)

    if not (args.community or args.pattern or args.validate or args.list):
        parser.print_help()
        sys.exit(1)

    # Path traversal protection for --pattern (use is_relative_to for correct containment)
    if args.pattern:
        pattern_path = Path(args.pattern).resolve()
        cwd = Path.cwd().resolve()
        if not pattern_path.is_relative_to(cwd):
            print("ERROR: --pattern path must be within the project directory", file=sys.stderr)
            sys.exit(1)

    # Path traversal protection for --report
    if args.report:
        report_path = Path(args.report).resolve()
        cwd = Path.cwd().resolve()
        if not report_path.is_relative_to(cwd):
            print("ERROR: --report path must be within the project directory", file=sys.stderr)
            sys.exit(1)

    summary = run_community_tests(
        community_dir=args.community_dir,
        pattern_file=args.pattern,
        framework_filter=args.framework,
        severity_filter=args.severity,
        target_url=args.url,
        verbose=args.verbose,
        validate_only=args.validate,
        list_only=args.list,
        dry_run=args.dry_run,
        strict=not args.no_strict,
    )

    if args.json:
        print(json.dumps(summary, indent=2))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"\nReport written to {args.report}", file=sys.stderr)

    # Exit code: 0 all passed, 1 any failed, 2 none failed but at least one
    # INCONCLUSIVE (a dry run, a target never contacted, a budget overrun).
    # An unevaluated pattern is not a green run.
    if summary.get("failed", 0) > 0:
        sys.exit(1)
    if summary.get("inconclusive", 0) > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
