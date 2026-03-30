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
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

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

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

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
    """Load a YAML file and return as dict."""
    if yaml is None:
        print(f"  ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
        return None

    try:
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
# Discovery
# ---------------------------------------------------------------------------

def discover_patterns(base_dir: str) -> list[str]:
    """Find all YAML files in the community_modules directory tree."""
    patterns = []
    base = Path(base_dir)

    if not base.exists():
        return patterns

    for path in sorted(base.rglob("*.yaml")):
        # Skip the template
        if path.name == "TEMPLATE.yaml":
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

    # Validate assertions
    assertions = data.get("assertions", [])
    if not isinstance(assertions, list) or len(assertions) == 0:
        errors.append(ValidationError(file_path, "assertions", "Must have at least one assertion"))
    else:
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

    # Validate evidence_schema
    schema = data.get("evidence_schema", {})
    if isinstance(schema, dict):
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


class StepExecutor:
    """Executes individual attack steps.

    This is the bridge between YAML-declared steps and the harness infrastructure.
    Each action type maps to a method that delegates to the appropriate harness.
    """

    def __init__(self, pattern: AttackPattern, target_url: str = "", verbose: bool = False):
        self.pattern = pattern
        self.target_url = target_url
        self.verbose = verbose
        self.evidence: dict[str, Any] = {}
        self.responses: list[dict] = []

    def execute_step(self, step: dict) -> dict:
        """Execute a single attack step and return the result."""
        action = step.get("action", "unknown")
        target = step.get("target", "unknown")
        payload = step.get("payload", {})
        delay_ms = step.get("delay_ms", 0)

        if delay_ms > 0:
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
        """Simulate sending a message to an agent or server."""
        return {
            "status": "sent",
            "target": target,
            "role": payload.get("role", ""),
            "content_length": len(str(payload.get("content", ""))),
            "response": None,  # Populated by harness integration
        }

    def _do_send_jsonrpc(self, target: str, payload: dict) -> dict:
        """Send a JSON-RPC 2.0 message."""
        message = {
            "jsonrpc": "2.0",
            "method": payload.get("method", ""),
            "params": payload.get("params", {}),
            "id": payload.get("id", "community-test-1"),
        }
        return {
            "status": "sent",
            "target": target,
            "message": message,
            "response": None,
        }

    def _do_call_tool(self, target: str, payload: dict) -> dict:
        """Invoke a tool by name."""
        return {
            "status": "called",
            "target": target,
            "tool_name": payload.get("tool_name", ""),
            "arguments": payload.get("arguments", {}),
            "response": None,
        }

    def _do_inject_description(self, target: str, payload: dict) -> dict:
        """Simulate injecting a modified tool description."""
        return {
            "status": "injected",
            "target": target,
            "tool_name": payload.get("tool_name", ""),
            "injected_length": len(str(payload.get("injected_text", ""))),
        }

    def _do_register_tool(self, target: str, payload: dict) -> dict:
        """Simulate registering a new tool."""
        return {
            "status": "registered",
            "target": target,
            "tool_name": payload.get("tool_name", ""),
            "description_length": len(str(payload.get("description", ""))),
            "schema": payload.get("schema", {}),
        }

    def _do_modify_context(self, target: str, payload: dict) -> dict:
        """Simulate modifying agent context."""
        return {
            "status": "modified",
            "target": target,
            "context_key": payload.get("context_key", ""),
        }

    def _do_http_request(self, target: str, payload: dict) -> dict:
        """Simulate an HTTP request (for exfiltration detection)."""
        return {
            "status": "simulated",
            "method": payload.get("method", "GET"),
            "url": payload.get("url", ""),
            "note": "HTTP request simulated - not actually sent during dry run",
        }

    def _do_wait(self, target: str, payload: dict) -> dict:
        """Wait for a specified duration."""
        duration_ms = payload.get("duration_ms", 0)
        time.sleep(duration_ms / 1000.0)
        return {"status": "waited", "duration_ms": duration_ms}

    def _do_assert_state(self, target: str, payload: dict) -> dict:
        """Check intermediate state."""
        return {
            "status": "checked",
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

        if re.search(pattern, actual):
            return True, f"Field '{field_name}' matches pattern '{pattern}'"
        return False, f"Field '{field_name}' does not match pattern '{pattern}'"


# ---------------------------------------------------------------------------
# Pattern runner
# ---------------------------------------------------------------------------

def run_pattern(
    pattern: AttackPattern,
    target_url: str = "",
    verbose: bool = False,
    dry_run: bool = False,
) -> PatternResult:
    """Execute a community attack pattern and return the result."""
    start_time = time.time()

    executor = StepExecutor(pattern, target_url=target_url, verbose=verbose)

    # Execute attack steps
    if verbose:
        print(f"\n  Running: {pattern.id} - {pattern.name}")
        print(f"  Framework: {pattern.framework} | Severity: {pattern.severity}")
        print(f"  Steps: {len(pattern.attack_steps)} | Assertions: {len(pattern.assertions)}")

    for i, step in enumerate(pattern.attack_steps):
        if verbose:
            desc = step.get("description", step.get("action", "step"))
            print(f"    Step {i+1}/{len(pattern.attack_steps)}: {step['action']} -> {step['target']}")

        if not dry_run:
            executor.execute_step(step)
        else:
            if verbose:
                print(f"      (dry run - skipped)")

    # Build evidence from schema defaults
    evidence = {}
    for key, type_name in pattern.evidence_schema.items():
        evidence[key] = executor.evidence.get(key, _default_for_type(type_name))

    # Evaluate assertions
    evaluator = AssertionEvaluator(evidence, executor.responses)
    assertions_passed = 0
    assertion_details = []

    for i, assertion in enumerate(pattern.assertions):
        if dry_run:
            passed = True
            detail = "(dry run - assertion not evaluated)"
        else:
            passed, detail = evaluator.evaluate(assertion)

        if passed:
            assertions_passed += 1

        status = "PASS" if passed else "FAIL"
        desc = assertion.get("description", assertion.get("type", ""))
        assertion_details.append(f"{status}: {desc} - {detail}")

        if verbose:
            icon = "ok" if passed else "FAIL"
            print(f"    Assertion {i+1}: [{icon}] {desc}")

    elapsed = time.time() - start_time
    all_passed = assertions_passed == len(pattern.assertions)

    result = PatternResult(
        test_id=pattern.id,
        name=pattern.name,
        source_file=pattern.source_file,
        owasp_asi=pattern.owasp_category,
        severity=pattern.severity,
        passed=all_passed,
        details="; ".join(assertion_details),
        elapsed_s=round(elapsed, 3),
        evidence=evidence,
        framework=pattern.framework,
        assertions_passed=assertions_passed,
        assertions_total=len(pattern.assertions),
    )

    if verbose:
        status = "PASS" if all_passed else "FAIL"
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

    # Load and validate
    patterns: list[AttackPattern] = []
    all_errors: list[ValidationError] = []
    seen_ids: set[str] = set()

    for fp in yaml_files:
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
            print(f"  {p.id:10s} [{p.severity:8s}] [{p.framework:10s}] {p.name}")
            if p.cve_reference:
                print(f"             CVE: {p.cve_reference}")
        return {"patterns_found": len(patterns), "patterns": [asdict(p) for p in patterns]}

    # Execute patterns
    print(f"\nRunning {len(patterns)} community pattern(s)...\n")
    results: list[PatternResult] = []

    for pattern in patterns:
        result = run_pattern(pattern, target_url=target_url, verbose=verbose, dry_run=dry_run)
        results.append(result)
        status = "PASS" if result.passed else "FAIL"
        print(f"  {status} {result.test_id}: {result.name} "
              f"({result.assertions_passed}/{result.assertions_total} assertions, "
              f"{result.elapsed_s:.2f}s)")

    # Summary
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    total_time = sum(r.elapsed_s for r in results)

    print(f"\n{'='*60}")
    print(f"Community Pattern Results: {passed} passed, {failed} failed "
          f"({len(results)} total, {total_time:.2f}s)")
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
                        help="Target URL for live testing")
    parser.add_argument("--validate", action="store_true",
                        help="Validate patterns without running them")
    parser.add_argument("--list", action="store_true",
                        help="List discovered patterns")
    parser.add_argument("--dry-run", action="store_true",
                        help="Execute steps but skip live interactions")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--report", type=str,
                        help="Write JSON report to file")

    args = parser.parse_args()

    if not (args.community or args.pattern or args.validate or args.list):
        parser.print_help()
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
    )

    if args.json:
        print(json.dumps(summary, indent=2))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"\nReport written to {args.report}")

    # Exit code: 0 if all passed, 1 if any failed
    if "failed" in summary and summary["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
