"""Guards for the v4.30.0 clean-install dry run, 2026-11-18.

A clean `pip install agent-security-harness==4.30.0` run found:

1. The CLI's own help example, ``--categories tool_poisoning,capability_escalation``,
   names no MCP category. It selected nothing, printed "No tests run", exit 2.
2. ``test mcp --simulate --categories ...`` listed all 34 tests.
3. ``version`` printed 10.5281/zenodo.19162104 as "Research": version 1.2.1 of the
   governance preprint, not the latest and not this software.

Each guard below has a control that fails on the defect it exists to catch.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from protocol_tests import cli  # noqa: E402
from protocol_tests.mcp_harness import (  # noqa: E402
    MCPSecurityTests, _test_identity, category_keys)

_EXAMPLE = re.compile(r"agent-security test mcp\b[^\n]*--categories[ =](\S+)")
_HARNESS_EXAMPLE = re.compile(r"--categories[ =](\S+)")


def unknown_in_examples(text: str, pattern=_EXAMPLE) -> list[str]:
    keys = set(category_keys())
    found = [c for m in pattern.finditer(text) for c in m.group(1).split(",")]
    if not found:
        return ["<no --categories example found>"]
    return [c for c in found if c not in keys]


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "protocol_tests.cli", *args],
                          cwd=REPO, capture_output=True, text=True, timeout=120)


class HelpExamplesNameRealCategories(unittest.TestCase):
    def test_cli_docstring_example(self):
        self.assertEqual(unknown_in_examples(cli.__doc__ or ""), [])

    def test_mcp_harness_docstring_example(self):
        import protocol_tests.mcp_harness as m
        self.assertEqual(unknown_in_examples(m.__doc__ or "", _HARNESS_EXAMPLE), [])

    def test_control_the_v4_30_0_example_fails(self):
        old = "agent-security test mcp --url http://x --categories tool_poisoning,capability_escalation"
        self.assertEqual(unknown_in_examples(old), ["tool_poisoning", "capability_escalation"])

    def test_category_keys_are_the_live_registry(self):
        reg = MCPSecurityTests.__new__(MCPSecurityTests).test_registry()
        self.assertEqual(category_keys(), list(reg))
        self.assertIn("tool_discovery", category_keys())


class UnknownCategoriesAreRefused(unittest.TestCase):
    def test_simulate_refuses_an_unknown_key(self):
        r = _run_cli("test", "mcp", "--simulate", "--categories", "tool_poisoning")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown MCP category: tool_poisoning", r.stderr)
        self.assertNotIn("[SIM]", r.stdout, "nothing may be listed for an unknown key")

    def test_cli_live_path_refuses_without_the_wrapper_line(self):
        # The module's refusal used to be followed by the wrapper's exit-2 gloss,
        # "no test failed, but ... INCONCLUSIVE", for a run that never started.
        r = _run_cli("test", "mcp", "--transport", "http", "--url",
                     "http://127.0.0.1:9/mcp", "--categories", "nope")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown MCP category: nope", r.stderr)
        self.assertNotIn("no test failed", r.stdout + r.stderr)

    def test_live_run_refuses_before_connecting(self):
        # Port 9 (discard) on loopback: the refusal must come before any connection.
        r = subprocess.run([sys.executable, "-m", "protocol_tests.mcp_harness", "--transport",
                            "http", "--url", "http://127.0.0.1:9/mcp", "--categories", "nope"],
                           cwd=REPO, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown MCP category: nope", r.stderr)
        self.assertNotIn("Could not connect", r.stdout + r.stderr)


class SimulateHonoursCategories(unittest.TestCase):
    def test_mcp_simulate_lists_exactly_the_selected_tests(self):
        cats = ["tool_discovery", "capability_negotiation"]
        reg = MCPSecurityTests.__new__(MCPSecurityTests).test_registry(cats)
        expected = {_test_identity(fn)[0] for fns in reg.values() for fn in fns}
        r = _run_cli("test", "mcp", "--simulate", "--categories", ",".join(cats))
        listed = set(re.findall(r"\[SIM\] (\S+)", r.stdout))
        self.assertEqual(listed, expected)
        self.assertLess(len(listed), 34, "control: the full catalog is 34")

    def test_other_harnesses_say_the_filter_is_not_applied(self):
        r = _run_cli("test", "a2a", "--simulate", "--categories", "agent_card")
        self.assertIn("--categories is applied only to live runs", r.stderr)


class CitationLinesAreCurrent(unittest.TestCase):
    def test_version_prints_concept_dois(self):
        out = _run_cli("version").stdout
        self.assertIn(cli.SOFTWARE_CONCEPT_DOI, out)
        self.assertIn(cli.RESEARCH_CONCEPT_DOI, out)

    def test_cli_source_carries_no_version_specific_research_doi(self):
        # Control: the v4.30.0 DOI must not come back as a printed line.
        src = (REPO / "protocol_tests" / "cli.py").read_text(encoding="utf-8")
        printed = re.findall(r'print\([^)]*zenodo\.(\d+)', src)
        self.assertNotIn("19162104", printed)


if __name__ == "__main__":
    unittest.main()
