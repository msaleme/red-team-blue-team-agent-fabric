"""``--json`` must put exactly one JSON document on stdout, and nothing else.

Raised by an independent review of the live-calibration work, running

    python -m protocol_tests.mcp_harness --transport http --url ... \
        --json --report /tmp/report.json

and getting stdout that ``json.loads`` refuses, because ``generate_report``
printed "Report written to ..." ahead of the document.

Not a false verdict, and still a defect. ``--json`` is a machine interface, and
a consumer that reads the documented contract gets a parse error rather than a
result. It breaks CI and any downstream evidence tooling.

## It was a class, not an instance

The report named one module. Sixty print sites across the package had the same
notice on stdout, and five CLIs additionally print a run banner from
``run_all`` before the document:

    ============================================================
    AP2 MANDATE-CHAIN CONFORMANCE SUITE
    ============================================================
    {
      "suite": ...

The notice moved to stderr unconditionally -- it is progress, not output, in
every mode -- and the five banner CLIs wrap their run in
``_utils.json_stdout_only``.

## Why this test invokes subprocesses

The defect lives in the boundary between the module and its caller. Importing
``main()`` and capturing ``sys.stdout`` would not have caught it: the notice is
emitted by a helper several frames down, and the banner by the suite itself. The
only faithful check is the one the reviewer ran.

The module list is derived from source rather than written down, so a CLI added
tomorrow is covered without being listed anywhere.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: These take a subcommand or a mode flag before any target, so the bare
#: invocation below is a usage error rather than a run. Their JSON paths are not
#: exercised here; they are excluded by name so the exclusion is visible.
NOT_A_BARE_CLI = {"cli", "community_runner", "mcp_supplychain"}

#: Nothing is listening here.
CLOSED_PORT = "http://127.0.0.1:9"


def _json_cli_modules() -> list[str]:
    """Every protocol_tests module whose CLI accepts both --json and --report."""
    out = []
    for path in sorted((REPO_ROOT / "protocol_tests").glob("*.py")):
        if path.stem in NOT_A_BARE_CLI:
            continue
        src = path.read_text(encoding="utf-8")
        if '"--json"' in src and '"--report"' in src:
            out.append(path.stem)
    return out


class TestJsonStdoutPurity(unittest.TestCase):
    def test_the_module_list_is_not_empty(self):
        """Assert a positive expected set, so a broken finder cannot read as clean."""
        mods = _json_cli_modules()
        self.assertGreaterEqual(
            len(mods), 6,
            f"only {len(mods)} modules found with both flags; the source scan is "
            f"probably broken rather than the package having shrunk")

    def test_stdout_is_exactly_one_json_document(self):
        for mod in _json_cli_modules():
            with self.subTest(module=mod), \
                    tempfile.NamedTemporaryFile(suffix=".json") as report:
                proc = subprocess.run(
                    [sys.executable, "-m", f"protocol_tests.{mod}",
                     "--json", "--report", report.name, "--url", CLOSED_PORT],
                    capture_output=True, text=True, timeout=180, cwd=REPO_ROOT,
                    # A harness exits non-zero when its own tests fail, which
                    # is the normal path here. The exit code is not the subject.
                    check=False)
                stdout = proc.stdout.strip()
                if not stdout:
                    continue          # this CLI writes nothing on this path
                try:
                    json.loads(stdout)
                except json.JSONDecodeError as exc:
                    first = stdout.split("\n", 1)[0][:70]
                    self.fail(
                        f"{mod} --json emitted non-JSON on stdout: {exc}. "
                        f"First line: {first!r}. Progress and notices belong on "
                        f"stderr; see _utils.json_stdout_only.")

    def test_the_report_notice_is_not_on_stdout(self):
        """The specific line the reviewer hit, asserted directly.

        The check above would also catch it, but only while the document
        happens to be the thing it breaks. If a future CLI emitted the notice
        and no JSON at all, stdout would be non-empty prose and this names why.
        """
        for mod in _json_cli_modules():
            with self.subTest(module=mod), \
                    tempfile.NamedTemporaryFile(suffix=".json") as report:
                proc = subprocess.run(
                    [sys.executable, "-m", f"protocol_tests.{mod}",
                     "--json", "--report", report.name, "--url", CLOSED_PORT],
                    capture_output=True, text=True, timeout=180, cwd=REPO_ROOT,
                    # A harness exits non-zero when its own tests fail, which
                    # is the normal path here. The exit code is not the subject.
                    check=False)
                self.assertNotIn(
                    "Report written to", proc.stdout,
                    f"{mod} printed the report notice to stdout in --json mode")


if __name__ == "__main__":
    unittest.main()
