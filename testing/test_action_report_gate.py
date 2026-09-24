"""The GitHub Action's failure gate counts every report shape correctly.

Defect (found during #595, pre-existing): `action.yml` and the reusable
`security-scan.yml` counted ``critical_failures`` as rows with
``status == "FAIL"`` and ``severity.lower() == "critical"``. No harness report
row carries ``status`` (derived below), and the MCP harness writes severity as
``"P0-Critical"``, so the default ``fail_on: critical`` could never fire.

Both now call `protocol_tests.report_gate`, which classifies rows with
`http_helpers.row_outcome` -- the function `run_summary` counts with. These
tests feed it real report JSON from the harnesses' own writers, derive the row
shapes and severity spellings from source rather than listing them, and run
the Action's own `run:` scripts so the wiring cannot silently regress.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from dataclasses import MISSING, asdict, fields
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.http_helpers import (  # noqa: E402
    INCONCLUSIVE_FIELDS,
    INCONCLUSIVE_PREFIX,
    row_outcome,
    run_summary,
)
from protocol_tests.mcp_harness import (  # noqa: E402
    MCPTestResult,
    Severity,
    build_differential_report,
    build_report,
    generate_report,
)
from protocol_tests.report_gate import (  # noqa: E402
    gate_counts,
    is_critical,
    main as gate_main,
    threshold_breached,
)

CLOSED_PORT_URL = "http://127.0.0.1:9"
ACTION = REPO_ROOT / "action.yml"
REUSABLE = REPO_ROOT / ".github" / "workflows" / "security-scan.yml"


def _row(cls, **overrides):
    """A result of `cls` built from its own fields, so no field list is guessed."""
    kw = dict(overrides)
    for f in fields(cls):
        if f.name in kw or f.default is not MISSING or f.default_factory is not MISSING:
            continue
        kw[f.name] = False if f.type in ("bool", bool) else "fixture"
    return cls(**kw)


def _mcp(test_id, severity, passed, details="fixture"):
    return _row(MCPTestResult, test_id=test_id, severity=severity, passed=passed, details=details)


def _written(report: dict) -> dict:
    """Round-trip through JSON, which is what the Action actually reads."""
    return json.loads(json.dumps(report, default=str))


# ---------------------------------------------------------------------------
# Derived shapes
# ---------------------------------------------------------------------------

PROTOCOL_TESTS = REPO_ROOT / "protocol_tests"
_NON_CRITICAL = re.compile(r"^(p[1-4]-)?(high|medium|low|info)$", re.I)
_PRIORITY_SHAPED = re.compile(r"^p\d+-[a-z]+$", re.I)


def _result_dataclasses(directory: Path = PROTOCOL_TESTS):
    """Every dataclass under `directory` that carries a `passed` verdict."""
    found = []
    for path in sorted(directory.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any("dataclass" in ast.dump(d) for d in node.decorator_list):
                continue
            names = {s.target.id for s in node.body
                     if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)}
            bases = {getattr(b, "id", "") for b in node.bases}
            if "passed" in names or "HarnessResult" in bases:
                found.append((f"{path.name}:{node.name}", names))
    return found


def status_outcome_classes(directory: Path = PROTOCOL_TESTS) -> list[str]:
    """Result classes carrying a `status` field the gate would not read as outcome."""
    return [n for n, f in _result_dataclasses(directory) if "status" in f]


def severity_spellings(directory: Path = PROTOCOL_TESTS) -> set[str]:
    """Every literal severity in code: `severity="..."` keywords and defaults,
    `"severity": "..."` dict entries, enum `CRITICAL = "..."` members, and any
    ``P<n>-<Level>`` literal wherever it sits. Read
    from the AST, so prose describing a spelling does not count as one."""
    found = set()

    def lit(node):
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    for path in directory.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if lit(node) and _PRIORITY_SHAPED.match(node.value):
                # Severities also arrive through tables and variables
                # (`severity=severity`); every "P<n>-<Level>" literal is one.
                found.add(node.value)
            elif isinstance(node, ast.keyword) and node.arg == "severity" and lit(node.value):
                found.add(node.value.value)
            elif isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if k is not None and lit(k) == "severity" and lit(v):
                        found.add(v.value)
            elif (isinstance(node, (ast.Assign, ast.AnnAssign)) and lit(node.value)
                  and any(isinstance(t, ast.Name) and t.id in ("severity", "CRITICAL")
                          for t in (node.targets if isinstance(node, ast.Assign)
                                    else [node.target]))):
                found.add(node.value.value)
    found.discard("")
    return found


def unclassified_severities(directory: Path = PROTOCOL_TESTS) -> list[str]:
    """Severity spellings in source that are neither critical nor a known lower level."""
    return sorted(s for s in severity_spellings(directory)
                  if not is_critical({"severity": s}) and not _NON_CRITICAL.match(s))


class DerivedRowShapes(unittest.TestCase):
    def test_no_result_row_carries_a_status_outcome(self):
        """Why the old gate could never fire: the field it read does not exist."""
        self.assertGreater(len(_result_dataclasses()), 40,
                           "derivation found too few result classes to trust")
        self.assertEqual(status_outcome_classes(), [], "a result class grew a `status` "
                         "field; decide whether row_outcome must read it before this passes")

    def test_every_inconclusive_field_in_source_is_one_the_classifier_reads(self):
        known = set(INCONCLUSIVE_FIELDS)
        suspicious = {"not_evaluated", "informational", "inconclusive", "not_executed",
                      "skipped", "unevaluated"}
        unread = sorted(f"{n}.{f}" for n, fs in _result_dataclasses()
                        for f in fs & suspicious if f not in known)
        self.assertEqual(unread, [])

    def test_every_severity_spelling_in_source_is_classified(self):
        """A new critical spelling (say "Sev0") must not silently read as non-critical."""
        spellings = severity_spellings()
        self.assertTrue({"P0-Critical", "critical", "CRITICAL"} <= spellings, spellings)
        self.assertEqual(unclassified_severities(), [])
        for s in spellings:
            if _NON_CRITICAL.match(s):
                self.assertFalse(is_critical({"severity": s}), s)
        self.assertTrue(is_critical({"severity": Severity.CRITICAL}))
        self.assertFalse(is_critical({}), "a row with no severity is not critical")


# ---------------------------------------------------------------------------
# Real report JSON, per shape
# ---------------------------------------------------------------------------

class MCPReports(unittest.TestCase):
    def test_critical_fail_is_counted_and_breaches_the_default(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            generate_report([_mcp("MCP-001", Severity.CRITICAL.value, False),
                             _mcp("MCP-002", Severity.HIGH.value, False),
                             _mcp("MCP-003", Severity.CRITICAL.value, True)], str(path))
            report = json.loads(path.read_text())
        counts = gate_counts(report)
        self.assertEqual(counts["critical_failures"], 1)
        self.assertEqual(counts["failed"], 2)
        self.assertEqual(counts["passed"], 1)
        self.assertIsNotNone(threshold_breached(counts, "critical"))
        self.assertIsNotNone(threshold_breached(counts, "any"))
        self.assertIsNone(threshold_breached(counts, "none"))

    def test_high_fail_breaches_any_not_critical(self):
        counts = gate_counts(_written(build_report([_mcp("MCP-002", Severity.HIGH.value, False)])))
        self.assertEqual(counts["critical_failures"], 0)
        self.assertIsNone(threshold_breached(counts, "critical"))
        self.assertIsNotNone(threshold_breached(counts, "any"))

    def test_inconclusive_critical_rows_are_not_failures(self):
        report = _written(build_report([
            _mcp("MCP-001", Severity.CRITICAL.value, False,
                 f"{INCONCLUSIVE_PREFIX}target did not service the request"),
            _mcp("MCP-003", Severity.CRITICAL.value, True)]))
        counts = gate_counts(report)
        self.assertEqual((counts["failed"], counts["critical_failures"], counts["inconclusive"]),
                         (0, 0, 1))
        self.assertIsNone(threshold_breached(counts, "critical"))
        self.assertIsNone(threshold_breached(counts, "any"))

    def test_prefix_only_row_from_an_older_writer_is_inconclusive(self):
        """Pre-field reports carry the state only as the detail prefix."""
        row = {"test_id": "MCP-001", "severity": "P0-Critical", "passed": False,
               "details": f"{INCONCLUSIVE_PREFIX}no answer"}
        counts = gate_counts({"results": [row]})
        self.assertEqual((counts["failed"], counts["inconclusive"]), (0, 1))

    def test_gate_agrees_with_the_report_summary(self):
        report = _written(build_report([
            _mcp("MCP-001", Severity.CRITICAL.value, False),
            _mcp("MCP-002", Severity.LOW.value, False, f"{INCONCLUSIVE_PREFIX}x"),
            _mcp("MCP-003", Severity.MEDIUM.value, True)]))
        counts = gate_counts(report)
        for k_gate, k_rep in (("total_tests", "total"), ("passed", "passed"),
                              ("failed", "failed"), ("inconclusive", "inconclusive")):
            self.assertEqual(counts[k_gate], report["summary"][k_rep], k_gate)

    def test_closed_port_not_executed_rows_never_gate(self):
        """Real harness run: a refused bootstrap emits one NOT_EXECUTED row per test."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            subprocess.run(
                [sys.executable, "-m", "protocol_tests.mcp_harness", "--transport", "http",
                 "--url", CLOSED_PORT_URL, "--report", str(path)],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=False)
            report = json.loads(path.read_text())
        rows = report["results"]
        self.assertTrue(rows)
        # The real rows carry severity "", so they could not read as critical
        # anyway. Stamp them P0-Critical: the verdict must come from the
        # NOT_EXECUTED state, not from the severity happening to be blank.
        for stamped in (False, True):
            if stamped:
                for r in rows:
                    r["severity"] = Severity.CRITICAL.value
            counts = gate_counts(report)
            self.assertEqual(counts["inconclusive"], len(rows))
            self.assertEqual((counts["failed"], counts["critical_failures"]), (0, 0))
            self.assertIsNone(threshold_breached(counts, "critical"))
            self.assertIsNone(threshold_breached(counts, "any"))

    def test_differential_report_counts_both_runs(self):
        legacy = _written(build_report([_mcp("MCP-001", Severity.CRITICAL.value, True)]))
        modern = _written(build_report([_mcp("MCP-001", Severity.CRITICAL.value, False)]))
        counts = gate_counts(_written(build_differential_report(legacy, modern)))
        self.assertEqual((counts["total_tests"], counts["critical_failures"]), (2, 1))

    def test_trials_report_rows(self):
        """`--trials` writers dump result objects with default=str, so rows are
        repr strings. The gate refuses that report; with object rows it counts."""
        from protocol_tests.trial_runner import run_with_trials
        merged = run_with_trials(
            lambda: {"results": [_mcp("MCP-001", Severity.CRITICAL.value, False)]}, trials=2)
        as_written = _written(merged)
        self.assertIsInstance(as_written["results"][0], str)
        with self.assertRaises(ValueError):
            gate_counts(as_written)
        as_objects = _written({**merged, "results": [asdict(r) for r in merged["results"]]})
        self.assertEqual(gate_counts(as_objects)["critical_failures"], 1)


class OtherHarnessShapes(unittest.TestCase):
    def test_a2a_writer_critical_fail_counted_and_inconclusive_not(self):
        from protocol_tests.a2a_harness import A2ATestResult, generate_report as a2a_report
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            a2a_report([_row(A2ATestResult, test_id="A2A-001", severity="P0-Critical", passed=False),
                        _row(A2ATestResult, test_id="A2A-013", severity="P0-Critical", passed=False,
                             details=f"{INCONCLUSIVE_PREFIX}card unavailable")], str(path))
            report = json.loads(path.read_text())
        counts = gate_counts(report)
        self.assertEqual((counts["failed"], counts["critical_failures"], counts["inconclusive"]),
                         (1, 1, 1))
        # A2A's own written summary is two-bucket (failed == 2). The gate
        # recomputes from rows rather than trusting it.
        self.assertEqual(report["summary"]["failed"], 2)

    def test_identity_informational_row_is_not_a_failure(self):
        from protocol_tests.identity_harness import IdentityTestResult
        row = asdict(_row(IdentityTestResult, severity="P0-Critical", passed=False, informational=True))
        counts = gate_counts({"results": [row]})
        self.assertEqual((counts["failed"], counts["inconclusive"]), (0, 1))

    def test_lowercase_critical_severity_counts(self):
        counts = gate_counts({"results": [{"test_id": "X-001", "severity": "critical",
                                           "passed": False, "details": "leaked"}]})
        self.assertEqual(counts["critical_failures"], 1)

    def test_status_shaped_rows_keep_their_old_meaning(self):
        """The shape the old gate assumed. No writer here emits it; it is kept."""
        rows = [{"test_id": "A", "status": "FAIL", "severity": "critical"},
                {"test_id": "B", "status": "PASS", "severity": "critical"},
                {"test_id": "C", "status": "FAIL", "severity": "high"},
                {"test_id": "D", "status": "INCONCLUSIVE", "severity": "critical"}]
        counts = gate_counts({"results": rows})
        self.assertEqual((counts["passed"], counts["failed"], counts["critical_failures"],
                          counts["inconclusive"]), (1, 2, 1, 1))

    def test_row_outcome_is_what_run_summary_counts(self):
        rows = [{"passed": True}, {"passed": False}, {"passed": False, "not_evaluated": True}]
        self.assertEqual([row_outcome(r) for r in rows], ["PASS", "FAIL", "INCONCLUSIVE"])
        s = run_summary(rows)
        self.assertEqual((s["passed"], s["failed"], s["inconclusive"]), (1, 1, 1))

    def test_unknown_fail_on_is_an_error_not_a_silent_pass(self):
        with self.assertRaises(ValueError):
            threshold_breached(gate_counts({"results": []}), "crtical")


# ---------------------------------------------------------------------------
# Wiring: action.yml and security-scan.yml actually call the gate
# ---------------------------------------------------------------------------

def _steps(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    steps = doc["runs"]["steps"] if "runs" in doc else doc["jobs"]["security-scan"]["steps"]
    return {s.get("name"): s for s in steps}


def _run_step(script: str, env: dict) -> subprocess.CompletedProcess:
    full = {**os.environ, **env}
    full.pop("PYTHONPATH", None)
    return subprocess.run(["bash", "-e", "-c", script], cwd=env.get("CWD", REPO_ROOT),
                          env=full, capture_output=True, text=True, timeout=120, check=False)


class ActionWiring(unittest.TestCase):
    def test_no_inline_status_counting_remains(self):
        for path in (ACTION, REUSABLE):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn('get("status")', text, path.name)
            self.assertIn("protocol_tests.report_gate summarize", text, path.name)
            self.assertIn("protocol_tests.report_gate gate", text, path.name)

    def test_action_exposes_an_inconclusive_output(self):
        outputs = yaml.safe_load(ACTION.read_text())["outputs"]
        self.assertIn("inconclusive", outputs)
        self.assertIn("steps.parse-report.outputs.inconclusive", outputs["inconclusive"]["value"])

    def _action_run(self, report: dict, fail_on: str):
        steps = _steps(ACTION)
        with tempfile.TemporaryDirectory() as td:
            rpath = Path(td) / "r.json"
            rpath.write_text(json.dumps(report, default=str))
            out = Path(td) / "out"
            summ = Path(td) / "summary"
            out.touch()
            summ.touch()
            # Run from an unrelated cwd: the gate must come from GITHUB_ACTION_PATH.
            env = {"GITHUB_ACTION_PATH": str(REPO_ROOT), "GITHUB_OUTPUT": str(out),
                   "GITHUB_STEP_SUMMARY": str(summ), "REPORT_PATH": str(rpath),
                   "INPUT_FAIL_ON": fail_on, "CWD": td}
            parse = _run_step(steps["Parse report"]["run"], env)
            gate = _run_step(steps["Evaluate threshold"]["run"], env)
            outputs = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
        return parse, gate, outputs

    def test_action_fails_on_an_mcp_critical_failure(self):
        """The defect, end to end through the Action's own step scripts."""
        report = _written(build_report([_mcp("MCP-001", Severity.CRITICAL.value, False)]))
        parse, gate, outputs = self._action_run(report, "critical")
        self.assertEqual(parse.returncode, 0, parse.stderr)
        self.assertEqual(outputs.get("critical_failures"), "1", outputs)
        self.assertEqual(gate.returncode, 1, gate.stdout + gate.stderr)

    def test_action_passes_an_inconclusive_mcp_run(self):
        report = _written(build_report([_mcp("MCP-001", Severity.CRITICAL.value, False,
                                             f"{INCONCLUSIVE_PREFIX}NOT_EXECUTED: bootstrap")]))
        for fail_on in ("critical", "any"):
            parse, gate, outputs = self._action_run(report, fail_on)
            self.assertEqual(outputs.get("inconclusive"), "1", outputs)
            self.assertEqual(outputs.get("failed"), "0", outputs)
            self.assertEqual(gate.returncode, 0, gate.stdout + gate.stderr)

    def test_action_imports_the_gate_from_its_own_checkout(self):
        """Not from whatever `protocol_tests` is installed (CI installs this repo
        editable, so a passing run alone cannot show where the import resolved)."""
        steps = _steps(ACTION)
        with tempfile.TemporaryDirectory() as td:
            pkg = Path(td) / "action" / "protocol_tests"
            pkg.mkdir(parents=True)
            (pkg / "__init__.py").write_text("")
            marker = Path(td) / "marker"
            (pkg / "report_gate.py").write_text(
                f"import sys\nopen({str(marker)!r}, 'a').write(sys.argv[1] + '\\n')\n")
            env = {"GITHUB_ACTION_PATH": str(pkg.parent), "REPORT_PATH": "r.json",
                   "INPUT_FAIL_ON": "critical", "GITHUB_OUTPUT": os.devnull,
                   "GITHUB_STEP_SUMMARY": os.devnull, "CWD": td}
            for name in ("Parse report", "Evaluate threshold"):
                self.assertEqual(_run_step(steps[name]["run"], env).returncode, 0, name)
            self.assertEqual(marker.read_text().split(), ["summarize", "gate"])

    def test_action_missing_report_fails(self):
        steps = _steps(ACTION)
        env = {"GITHUB_ACTION_PATH": str(REPO_ROOT), "REPORT_PATH": "/nonexistent/r.json",
               "GITHUB_OUTPUT": os.devnull, "GITHUB_STEP_SUMMARY": os.devnull}
        self.assertNotEqual(_run_step(steps["Parse report"]["run"], env).returncode, 0)

    def test_gate_cli_exit_codes(self):
        report = _written(build_report([_mcp("MCP-001", Severity.CRITICAL.value, False)]))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            path.write_text(json.dumps(report))
            self.assertEqual(gate_main(["gate", str(path), "--fail-on", "critical"]), 1)
            self.assertEqual(gate_main(["gate", str(path), "--fail-on", "none"]), 0)
            self.assertEqual(gate_main(["gate", str(path), "--fail-on", "bogus"]), 1)


if __name__ == "__main__":
    unittest.main()
