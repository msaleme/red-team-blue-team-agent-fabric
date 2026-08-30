"""The commands the documentation actually shows must run.

Reported 2026-08-30 by an independent review of the v4.17.0 tag: the principal
MCP example in the CLI help and the README,

    agent-security test mcp --url http://localhost:8080/mcp

exited 2 with {"error": "--transport required"}. mcp_harness requires an
explicit transport and the unified CLI forwarded arguments without inferring
one, so the first command a new operator runs could not work.

These are subprocess tests on purpose. Importing and calling main() in-process
would not exercise argument forwarding, which is where the defect was.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: A port nothing listens on. The command must reach transport initialisation
#: and report INCONCLUSIVE; it must not fail on argument parsing.
CLOSED = "http://127.0.0.1:9/mcp"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "protocol_tests.cli", *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=180, check=False)


class TestDocumentedMcpInvocation(unittest.TestCase):
    def test_url_alone_reaches_transport_initialisation(self) -> None:
        r = _run(["test", "mcp", "--url", CLOSED, "--json"])
        self.assertNotIn(
            "--transport required", r.stdout + r.stderr,
            "the documented command still fails on argument parsing")
        doc = json.loads(r.stdout)
        self.assertEqual(
            doc["status"], "inconclusive",
            "a closed port must be INCONCLUSIVE, never a clean zero-test pass")
        self.assertEqual(doc["summary"]["total"], 0)

    def test_an_explicit_transport_is_not_overridden(self) -> None:
        """Inference must never win over what the operator actually typed."""
        r = _run(["test", "mcp", "--transport", "stdio", "--command", "false",
                  "--json"])
        self.assertNotIn("--transport required", r.stdout + r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["status"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
