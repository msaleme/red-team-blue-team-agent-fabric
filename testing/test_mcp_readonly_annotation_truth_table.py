"""Truth table for "a read-only annotation must match behaviour", before any probe (rule 9).

Issue #716, from CVE-2026-126816 (awslabs.aws-pricing-mcp-server < 1.0.31): the
`generate_cost_report` tool wrote `output_file` wherever it pointed while annotated
`readOnlyHint=true`. GHSA-mqm3-w68j-75mw: "Because the tool was annotated as read-only,
MCP clients configured to auto-approve read-only tools could run it without user
confirmation." The annotation is a value the server author types; nothing checks it.

MCP specification 2025-03-26 onward (server/tools, ToolAnnotations): `readOnlyHint`
"If true, the tool does not modify its environment", and clients "MUST consider tool
annotations to be untrusted unless they come from trusted servers".

    observable capability    a tool the server lists with annotations.readOnlyHint=true
    adversarial precondition each path-shaped argument of that tool pointed at a canary
                             location the harness owns: an absolute path, and the same
                             location as a `..` traversal relative to the server's
                             working directory
    deterministic oracle     whether any file appears in the canary directory. Only
                             observable when the harness launched the server (stdio):
                             over HTTP the filesystem is someone else's.
    positive control         `truthful`: read-only and never writes -> must PASS
    negative controls        `mislabelled` (writes anywhere) and `traversal_only`
                             (refuses absolute paths, writes `..`) -> must FAIL
    semantics                TRUTH_TABLE below

MEASURED at main dccabea (v4.31.0 + docs): the full MCP suite over stdio gives the
**same verdict on every test** against `truthful` and `mislabelled`. No test can tell
a read-only tool that writes from one that does not. That is the gap; the register
`SUITE_CANNOT_TELL` records it, shrink-only, and the probe's arrival must flip it.

REPAIRED: MCP-023 (`test_mcp_readonly_annotation_truth`) applies this method in the
harness. Against every fixture it reaches FIXTURE_EXPECTATIONS, over HTTP it is
INCONCLUSIVE, and the suite now tells truthful from mislabelled (MCP-023 PASS vs FAIL).

Limitations, stated rather than hidden: a write that does not go through a path-shaped
argument (a fixed log file, a database) is not observed, and neither is a symlink
escape from a server-side base directory the harness cannot see.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "testing" / "annotation_fixture_server.py"
PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
#: Argument names treated as path-shaped. Deliberately broad: a miss is an
#: unprobed tool (INCONCLUSIVE), never a PASS.
PATH_WORDS = ("path", "file", "dir", "dest", "output", "out", "target", "location", "save")


def verdict(stdio: bool, readonly_tools: int, probeable: int, answered: int, writes: int) -> str:
    """Reference grader. Arguments are counts the probe observes."""
    if writes:
        return FAIL           # a read-only tool wrote: the annotation is false
    if not stdio:
        return INCONCLUSIVE   # the filesystem cannot be observed
    if not readonly_tools or not probeable:
        return INCONCLUSIVE   # nothing claims read-only, or nothing write-shaped to try
    if not answered:
        return INCONCLUSIVE   # no call was serviced; silence is not a control holding
    return PASS               # answered (a refusal counts) and nothing was written


#: (case, stdio, readonly_tools, probeable, answered, writes, expected)
TRUTH_TABLE = [
    ("read-only tool wrote the canary", True, 1, 1, 1, 1, FAIL),
    ("read-only tool refused, nothing written", True, 1, 1, 1, 0, PASS),
    ("read-only tool answered, nothing written", True, 1, 1, 1, 0, PASS),
    ("HTTP target: filesystem not observable", False, 1, 1, 1, 0, INCONCLUSIVE),
    ("no tool claims read-only", True, 0, 0, 0, 0, INCONCLUSIVE),
    ("read-only tools, none path-shaped", True, 1, 0, 0, 0, INCONCLUSIVE),
    ("read-only tool, every call unanswered", True, 1, 1, 0, 0, INCONCLUSIVE),
    ("a write is a FAIL even if every call errored", True, 1, 1, 0, 1, FAIL),
]

#: fixture mode -> the verdict the probe must reach against it
FIXTURE_EXPECTATIONS = {
    "truthful": PASS,
    "mislabelled": FAIL,
    "traversal_only": FAIL,
    "not_readonly": INCONCLUSIVE,
    "no_path": INCONCLUSIVE,
    "refuses_calls": PASS,   # answered with an error and wrote nothing
}


def _rpc(proc, msg):
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()
    if "id" not in msg:
        return None
    line = proc.stdout.readline()
    return json.loads(line) if line else None


def reference_probe(mode: str) -> tuple[str, dict]:
    """Drive the fixture directly with the probe's method, and grade it."""
    canary = Path(tempfile.mkdtemp(prefix="ash-annot-"))
    proc = subprocess.Popen([sys.executable, str(FIXTURE), "--mode", mode],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    obs = {"readonly": 0, "probeable": 0, "answered": 0, "writes": 0}
    try:
        _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t"}}})
        _rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = (_rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) or {}
                 ).get("result", {}).get("tools", [])
        for t in tools:
            if not (t.get("annotations") or {}).get("readOnlyHint") is True:
                continue
            obs["readonly"] += 1
            props = (t.get("inputSchema") or {}).get("properties") or {}
            paths = [k for k in props if any(w in k.lower() for w in PATH_WORDS)]
            if not paths:
                continue
            obs["probeable"] += 1
            for variant in ("absolute", "traversal"):
                target = canary / f"{t['name']}-{variant}.txt"
                value = str(target) if variant == "absolute" else os.path.relpath(target, os.getcwd())
                args = {k: "ash-probe" for k in props}
                args.update({k: value for k in paths})
                resp = _rpc(proc, {"jsonrpc": "2.0", "id": 10 + obs["answered"], "method": "tools/call",
                                   "params": {"name": t["name"], "arguments": args}})
                if isinstance(resp, dict) and ("result" in resp or "error" in resp):
                    obs["answered"] += 1
        obs["writes"] = sum(1 for _ in canary.iterdir())
    finally:
        proc.kill()
        proc.wait()
        for f in canary.iterdir():
            f.unlink()
        canary.rmdir()
    return verdict(True, obs["readonly"], obs["probeable"], obs["answered"], obs["writes"]), obs


def suite_verdicts(mode: str, *extra: str) -> dict[str, str]:
    """The full MCP suite over stdio against one fixture mode."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "r.json"
        cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(FIXTURE))} --mode {mode}"
        subprocess.run([sys.executable, "-m", "protocol_tests.mcp_harness", "--transport", "stdio",
                        "--command", cmd, "--json", "--report", str(report), *extra],
                       cwd=REPO, capture_output=True, timeout=300, check=False)
        rows = json.loads(report.read_text())["results"]
    return {r["test_id"]: ("INCONCLUSIVE" if r.get("not_evaluated")
                           else "PASS" if r.get("passed") else "FAIL") for r in rows}


#: Measured True at dccabea (identical verdicts against truthful and mislabelled);
#: False since MCP-023. Checked both directions.
SUITE_CANNOT_TELL = False


class TruthTable(unittest.TestCase):
    def test_reference_grader(self):
        for case, stdio, ro, pr, ans, wr, expected in TRUTH_TABLE:
            with self.subTest(case=case):
                self.assertEqual(verdict(stdio, ro, pr, ans, wr), expected)

    def test_table_has_all_three_poles(self):
        self.assertEqual({row[-1] for row in TRUTH_TABLE}, {PASS, FAIL, INCONCLUSIVE})


class TheFixturesSitOnTheirRows(unittest.TestCase):
    """Controls for the controls: each fixture reaches its verdict under the method."""

    def test_each_fixture(self):
        for mode, expected in FIXTURE_EXPECTATIONS.items():
            with self.subTest(mode=mode):
                got, obs = reference_probe(mode)
                self.assertEqual(got, expected, obs)

    def test_traversal_variant_is_what_catches_traversal_only(self):
        # traversal_only refuses the absolute path, so exactly one write lands.
        _, obs = reference_probe("traversal_only")
        self.assertEqual(obs["writes"], 1)

    def test_the_canary_is_cleaned_up(self):
        before = {p.name for p in Path(tempfile.gettempdir()).glob("ash-annot-*")}
        reference_probe("mislabelled")
        after = {p.name for p in Path(tempfile.gettempdir()).glob("ash-annot-*")}
        self.assertEqual(after - before, set())


class TheSuiteCannotTellToday(unittest.TestCase):
    """The measured gap, shrink-only in both directions."""

    def test_register_matches_measurement(self):
        truthful, mislabelled = suite_verdicts("truthful"), suite_verdicts("mislabelled")
        self.assertGreaterEqual(len(truthful), 30, "the suite did not run")
        self.assertEqual(truthful == mislabelled, SUITE_CANNOT_TELL,
                         "the suite now tells them apart: set SUITE_CANNOT_TELL = False")


class HarnessFollowsTheTable(unittest.TestCase):
    """MCP-023 itself, against every fixture, and its HTTP pole."""

    def test_mcp_023_against_each_fixture(self):
        for mode, expected in FIXTURE_EXPECTATIONS.items():
            with self.subTest(mode=mode):
                got = suite_verdicts(mode, "--categories", "tool_annotations")
                self.assertEqual(got.get("MCP-023"), expected)

    def test_http_is_inconclusive(self):
        sys.path.insert(0, str(REPO))
        from protocol_tests.mcp_harness import MCPSecurityTests, StreamableHTTPTransport
        suite = MCPSecurityTests(StreamableHTTPTransport("http://127.0.0.1:9/mcp"), json_output=True)
        suite.test_mcp_readonly_annotation_truth()
        self.assertTrue(suite.results[-1].not_evaluated)
        self.assertIn("requires stdio", suite.results[-1].details)

    def test_the_harness_canary_is_cleaned_up(self):
        before = {p.name for p in Path(tempfile.gettempdir()).glob("ash-annot-*")}
        suite_verdicts("mislabelled", "--categories", "tool_annotations")
        after = {p.name for p in Path(tempfile.gettempdir()).glob("ash-annot-*")}
        self.assertEqual(after - before, set())


if __name__ == "__main__":
    unittest.main()
