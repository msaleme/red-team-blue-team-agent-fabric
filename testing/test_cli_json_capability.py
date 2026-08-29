"""`--json` must be refused before dispatch on harnesses that do not declare it.

Reported 2026-08-29 by an independent-reviewer sweep, which hit it on two
subcommands:

    agent-security test a2a            --url ... --json
    agent-security test return-channel --url ... --json
    -> error: unrecognized arguments: --json     (exit 2, raised inside the submodule)

Deriving the set rather than trusting the two reported instances put the real
number at **33 of 44**. Only 11 registered harnesses declare `--json`, so the
CLI was advertising a common flag that three quarters of its subcommands reject,
and the failure surfaced as an argparse error from a module the user did not
invoke by name.

The CLI already carried the correct intent one line above the defect:

    # Also pass --json through to harness modules that support it
    filtered_args.append("--json")

The comment described a capability check. The code appended unconditionally.

## What this fixes and what it does not

This does not make `--json` work everywhere. A common JSON contract across 44
harnesses is a separate project, and pretending otherwise by scraping console
output would be worse than the error it replaced -- the reviewer said so
explicitly: "Do not silently fall back to human console parsing."

It replaces a confusing failure with an accurate one, and points at `--report`,
which 32 of the 33 unsupported harnesses do accept and which writes the same JSON
to a file.
"""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.cli import (
    HARNESSES,
    _json_capable_count,
    _module_declares_flag,
)


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "protocol_tests.cli", *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=False,
    )


class TestJsonCapabilityIsDerived(unittest.TestCase):
    def test_capability_is_read_from_the_module_not_a_list(self):
        """A maintained list is the thing that drifts; assert the derived answer."""
        self.assertTrue(_module_declares_flag("mcp", "--json"))
        self.assertFalse(_module_declares_flag("a2a", "--json"))
        self.assertTrue(_module_declares_flag("a2a", "--report"))

    def test_unknown_harness_is_not_reported_as_capable(self):
        self.assertFalse(_module_declares_flag("no-such-harness", "--json"))

    def test_capable_count_is_positive_and_bounded(self):
        """Assert a real range, so a lookup that silently fails everywhere fails here.

        If _module_declares_flag started returning False for everything -- a bad
        path, a changed argparse idiom -- every refusal below would still 'pass'
        while the CLI refused every subcommand. Pin that it finds some and not all.
        """
        n = _json_capable_count()
        self.assertGreater(n, 0, "no harness detected as --json capable; the "
                                 "source lookup is probably broken")
        self.assertLess(n, len(HARNESSES), "every harness reported capable; the "
                                           "detection is probably matching too broadly")


class TestUnsupportedJsonIsRefusedBeforeDispatch(unittest.TestCase):
    def test_a2a_json_is_refused_with_an_accurate_message(self):
        proc = _run("test", "a2a", "--url", "http://127.0.0.1:9", "--json")
        self.assertEqual(proc.returncode, 2, f"expected exit 2, got {proc.returncode}")
        err = proc.stderr
        self.assertIn("does not support --json", err)
        self.assertNotIn(
            "unrecognized arguments", err,
            "the submodule argparse error is what this replaces; it should no "
            "longer reach the user")
        self.assertIn("--report", err, "the message must name the alternative that works")

    def test_the_message_states_the_real_ratio(self):
        """The count in the message is derived, so it cannot go stale."""
        proc = _run("test", "return-channel", "--url", "http://127.0.0.1:9", "--json")
        m = re.search(r"(\d+) of (\d+) registered", proc.stderr)
        self.assertIsNotNone(m, f"message no longer states the ratio:\n{proc.stderr}")
        self.assertEqual(int(m.group(1)), _json_capable_count())
        self.assertEqual(int(m.group(2)), len(HARNESSES))


class TestSupportedJsonStillWorks(unittest.TestCase):
    def test_mcp_json_is_not_refused(self):
        """The guard must not over-refuse, or it is worse than the defect."""
        proc = _run("test", "mcp", "--transport", "http",
                    "--url", "http://127.0.0.1:9", "--json")
        self.assertNotIn("does not support --json", proc.stderr)
        self.assertIn('"suite"', proc.stdout, "mcp --json no longer emits its JSON report")


if __name__ == "__main__":
    unittest.main()
