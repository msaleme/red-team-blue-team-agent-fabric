#!/usr/bin/env python3
"""Workspace-Trust / Repository-Ingestion Pre-Flight Tests (WT-001..004, v1.0).

An agent pointed at a local repository gathers context from it before it does
anything else, and several git settings are command-execution sinks. A
repository that arrives carrying its own ``.git/config`` therefore gets to run a
command inside the ingesting process, before any workspace-trust prompt and
before authentication.

    [core]
        fsmonitor = <command>

Any git operation that refreshes the index runs it, including read-only ones.

Disclosed as GitSpawn by Manifold Security, 2026-09-01, across seven coding
agents; CVE-2026-72718 (Goose) and CVE-2026-71963 (Hermes Agent) were assigned
by VulnCheck as an independent CNA. Four of the seven were patched at
disclosure and three were not.

## Why this is a pre-flight family and not a protocol test

This fires before the first protocol byte, so `mcp_harness` and the rest of the
wire suite structurally cannot see it, exactly as `mcp_supplychain` (MCP-F-*)
cannot be seen by them. Same shape, different input: that family takes a
launcher command, this one takes a command that ingests a directory.

## The vector is delivery, not cloning

Verified against git 2.43.0 on 2026-09-10 rather than taken from the write-up,
because the whole family is pointless if it is wrong:

    directory copy of a repo carrying the sink   -> fired on `git status`
    the same repo obtained by `git clone`        -> config absent, did not fire
    `git -c core.fsmonitor=false status`         -> did not fire

So the exposure is anything that moves a directory: a shared zip, a sync folder,
a mounted share, a USB stick, an uploaded archive. Cloning a hostile URL is not
the path, and a harness that flagged clone-based ingestion would be crying wolf
at the safe case. WT-003 pins that.

## What this does NOT do

It does not name or probe the second configuration key the disclosure withheld
while it remains unpatched. WT-004 therefore establishes that the *named* sink
is suppressed and nothing more, and says so in its own verdict text. A target
that passes WT-004 is not thereby shown to sanitise every sink.

The canary is inert. It writes a fixed marker file inside the harness's own
temporary directory and does nothing else; it is a fixture, not a payload.

## Usage

    # characterise a real ingesting command; {repo} is substituted
    python -m protocol_tests.workspace_trust_harness \\
        --command "your-agent --project {repo} --summarise"

    # CI-safe self-test against a built-in reference ingester
    python -m protocol_tests.workspace_trust_harness --self-test

Requires: Python 3.10+, git on PATH, no network.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from protocol_tests.harness_base import HarnessResult, RecordingHarness
from protocol_tests.http_helpers import INCONCLUSIVE_PREFIX, console_status
from protocol_tests.run_provenance import run_provenance

#: Read-only operations to try. Not all of them refresh the index -- measured on
#: git 2.43.0, `status` and `diff` run the sink and `log` does not -- and that is
#: the point of trying several rather than asserting a list. WT-002 reports which
#: ones fired instead of claiming they all do.
READ_ONLY_OPS = ("status", "diff", "log")


@dataclass
class WorkspaceTrustResult(HarnessResult):
    """Adds only what this family needs on top of the shared shape."""
    ingestion_path: str = ""          # "delivered" | "cloned"
    canary_fired: bool = False


class WorkspaceTrustTests(RecordingHarness):
    """Characterise one command that ingests a local repository, plus local git.

    ## Which tests observe the command under test, and which do not

    Until 2026-09-10 this docstring asserted that all four tests invoked the
    command under test. That was true of one of them, and an external reader
    checking the claim against the source is what found it. The wrong sentence
    is described rather than quoted here, because
    testing/test_workspace_trust_controls.py greps for it and a quoted copy
    would keep the guard permanently red. Corrected here rather than softened, because a
    family docstring that overstates what its members observe is the defect this
    package spent the same day repairing in MEM-013..015.

        WT-001  invokes the command under test, via _run_against      TARGET
        WT-002  drives local git directly, no invocation              LOCAL GIT
        WT-003  drives local git directly, no invocation              LOCAL GIT
        WT-004  drives local git directly, no invocation              LOCAL GIT

    So a run produces ONE observation about the caller's command and three about
    git's behaviour on the machine the harness is running on. The three are
    still worth having -- they establish that the fixture fires at all, that a
    clone does not carry the sink, and that the published mitigation suppresses
    it -- but none of them is evidence about the ingesting command, and a report
    that reads as four findings about a target would be wrong.

    ## The positive control, and where it applies

    WT-001 runs the command twice: once against a clean control repository and
    once against a crafted one. The control run is not optional. If the command
    cannot ingest a clean repository -- wrong invocation, missing binary, a
    `{repo}` placeholder that was never substituted -- then it also will not
    ingest the crafted one, no canary fires, and without the control that scores
    as "the sink did not execute".

    That is X4-057's shape: nothing accepted, nothing settled, nothing
    overdrawn, "the control held". Here it would be nothing ingested, nothing
    executed, "not vulnerable". The control run turns that into INCONCLUSIVE.

    What the control establishes is narrower than "the command ingested the
    repository": it is exit status zero with output on stdout or stderr. A
    command that exits zero and prints something without reading the directory
    satisfies it. That is a weaker precondition than the name suggests and it is
    stated here so a reader does not assume otherwise.
    """

    def __init__(self, command: str, self_test: bool = False):
        super().__init__()
        self.command = command
        self.self_test = self_test
        self.results: list[WorkspaceTrustResult] = []
        self._tmp = Path(tempfile.mkdtemp(prefix="wt-harness-"))

    # -- fixtures ---------------------------------------------------------

    def _git(self, *args: str, cwd: Path) -> subprocess.CompletedProcess:
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        return subprocess.run(["git", "-c", "user.email=t@example.invalid",
                               "-c", "user.name=wt-harness", *args],
                              cwd=cwd, capture_output=True, text=True,
                              timeout=60, check=False, env=env)

    def _build_repo(self, name: str, canary: Path | None) -> Path:
        """A small real repository, optionally carrying the execution sink."""
        repo = self._tmp / name
        repo.mkdir(parents=True)
        (repo / "README.md").write_text(
            f"workspace-trust fixture {uuid.uuid4().hex[:8]}\n", encoding="utf-8")
        self._git("init", "-q", ".", cwd=repo)
        self._git("add", "-A", cwd=repo)
        self._git("commit", "-qm", "fixture", cwd=repo)
        if canary is not None:
            # Inert: writes a marker inside the harness's own temp dir.
            sink = f'/bin/sh -c "echo fired > {shlex.quote(str(canary))}"'
            with (repo / ".git" / "config").open("a", encoding="utf-8") as fh:
                fh.write(f"\n[core]\n\tfsmonitor = {json.dumps(sink)}\n")
        return repo

    # -- target invocation ------------------------------------------------

    def _invoke(self, repo: Path) -> tuple[bool, str]:
        """Run the command against `repo`. Returns (ingested, detail).

        `ingested` is the positive control: the command ran, exited 0, and
        produced output. It is deliberately not "the command exited 0" alone --
        a stub that does nothing exits 0 too.
        """
        # Literal substitution, then a shell. No quoting is added around the
        # path, and the command inherits this process's cwd and environment.
        # The 120s timeout bounds THIS invocation only: it does not bound
        # descendants the command spawns, and it is not a bound on the run.
        cmd = self.command.replace("{repo}", str(repo))
        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True,
                                  text=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            return False, "the command did not return within 120s"
        if proc.returncode != 0:
            return False, (f"the command exited {proc.returncode} against a clean "
                           f"repository: {(proc.stderr or proc.stdout).strip()[:160]}")
        if not (proc.stdout.strip() or proc.stderr.strip()):
            return False, "the command produced no output against a clean repository"
        return True, proc.stdout.strip()[:160]

    def _run_against(self, repo: Path, canary: Path) -> tuple[bool, bool, str]:
        """(ingested_control, canary_fired, detail)."""
        control = self._build_repo(f"control-{uuid.uuid4().hex[:6]}", canary=None)
        ingested, detail = self._invoke(control)
        if not ingested:
            return False, False, detail
        canary.unlink(missing_ok=True)
        self._invoke(repo)
        time.sleep(0.2)                       # the sink is a separate process
        return True, canary.exists(), detail

    # -- WT-001 -----------------------------------------------------------

    def test_wt_001_repository_supplied_config_executes(self):
        """WT-001: a delivered repository's own config runs a command."""
        t0 = time.monotonic()
        canary = self._tmp / f"canary-001-{uuid.uuid4().hex[:8]}"
        repo = self._build_repo("delivered-001", canary=canary)
        ingested, fired, detail = self._run_against(repo, canary)
        self._record(WorkspaceTrustResult(
            test_id="WT-001", name="Repository-Supplied Config Executes on Ingestion",
            category="workspace_trust", owasp_asi="ASI06",
            stride="Elevation of Privilege", severity="CRITICAL",
            passed=ingested and not fired,
            ingestion_path="delivered", canary_fired=fired,
            details=(INCONCLUSIVE_PREFIX + "the command did not ingest a clean "
                     f"repository, so nothing was gathered and no sink could have "
                     f"run: {detail}") if not ingested
                    else "No command ran from the repository's own git config"
                    if not fired
                    else ("The repository's own .git/config executed a command "
                          "during ingestion, before any trust decision"),
            protocol="local", elapsed_s=round(time.monotonic() - t0, 3)))

    # -- WT-002 -----------------------------------------------------------

    def test_wt_002_read_only_ingestion_still_executes(self):
        """WT-002: reading is not a mitigation.

        Distinct from WT-001, which characterises the caller's real invocation.
        This drives the read-only git operations directly, so a target that
        believes "we only inspect, we never write" gets that belief tested.

        Not every read-only operation refreshes the index: on git 2.43.0
        `status` and `diff` run the sink and `log` does not. The verdict names
        the ones that fired rather than asserting the whole list, because "all
        read-only operations do this" is a stronger claim than the measurement
        supports.
        """
        t0 = time.monotonic()
        canary = self._tmp / f"canary-002-{uuid.uuid4().hex[:8]}"
        repo = self._build_repo("delivered-002", canary=canary)
        fired_on = []
        for op in READ_ONLY_OPS:
            canary.unlink(missing_ok=True)
            self._git(op, cwd=repo)
            time.sleep(0.2)
            if canary.exists():
                fired_on.append(op)
        self._record(WorkspaceTrustResult(
            test_id="WT-002", name="Read-Only Ingestion Still Executes the Sink",
            category="workspace_trust", owasp_asi="ASI06",
            stride="Elevation of Privilege", severity="HIGH",
            passed=not fired_on, ingestion_path="delivered",
            canary_fired=bool(fired_on),
            details=("No read-only operation ran the configured command"
                     if not fired_on else
                     "Read-only operations ran the repository's configured "
                     f"command: {', '.join(fired_on)}. Restricting ingestion to "
                     "reads does not avoid it"),
            protocol="local", elapsed_s=round(time.monotonic() - t0, 3)))

    # -- WT-003 -----------------------------------------------------------

    def test_wt_003_cloned_source_does_not_carry_the_sink(self):
        """WT-003: the safe path, asserted rather than assumed.

        `git clone` writes a fresh config and does not copy the source's, so a
        repository obtained by cloning cannot deliver a sink this way. This is
        the family's built-in negative control: if it ever fires, either the
        target is doing something unusual or the fixture is broken, and every
        other verdict here should be distrusted until that is resolved.

        It also earns its place as a finding. An operator who knows only "git
        repos can execute code" hardens the wrong ingestion path; the one that
        matters is whatever moves a directory.
        """
        t0 = time.monotonic()
        canary = self._tmp / f"canary-003-{uuid.uuid4().hex[:8]}"
        source = self._build_repo("source-003", canary=canary)
        cloned = self._tmp / "cloned-003"
        clone = subprocess.run(["git", "clone", "-q", str(source), str(cloned)],
                               capture_output=True, text=True, timeout=120, check=False)
        if clone.returncode != 0:
            self._record(WorkspaceTrustResult(
                test_id="WT-003", name="Cloned Source Does Not Carry the Sink",
                category="workspace_trust", owasp_asi="ASI06",
                stride="Elevation of Privilege", severity="MEDIUM", passed=False,
                ingestion_path="cloned",
                details=INCONCLUSIVE_PREFIX + (
                    f"the fixture could not be cloned, so the safe path was never "
                    f"exercised: {clone.stderr.strip()[:160]}"),
                protocol="local", elapsed_s=round(time.monotonic() - t0, 3)))
            return
        canary.unlink(missing_ok=True)
        self._git("status", cwd=cloned)
        time.sleep(0.2)
        fired = canary.exists()
        inherited = self._git("config", "--local", "core.fsmonitor",
                              cwd=cloned).stdout.strip()
        self._record(WorkspaceTrustResult(
            test_id="WT-003", name="Cloned Source Does Not Carry the Sink",
            category="workspace_trust", owasp_asi="ASI06",
            stride="Elevation of Privilege", severity="MEDIUM",
            passed=not fired and not inherited,
            ingestion_path="cloned", canary_fired=fired,
            details=("Local self-test, decided without the target: a clone of "
                     "the same repository carried no sink and ran nothing, so "
                     "cloning is not the exposed ingestion path"
                     if not fired and not inherited else
                     f"A clone inherited the sink (core.fsmonitor={inherited!r}, "
                     f"fired={fired}). Treat every other verdict in this run as "
                     f"suspect until the fixture is re-checked"),
            protocol="local", elapsed_s=round(time.monotonic() - t0, 3)))

    # -- WT-004 -----------------------------------------------------------

    def test_wt_004_named_sink_sanitisation_is_effective(self):
        """WT-004: the published mitigation, checked rather than trusted.

        `git -c core.fsmonitor=false <op>` suppresses the named sink. Passing
        establishes exactly that and no more: the disclosure states it withheld
        one further configuration key while that finding remains unpatched, so a
        target that sanitises this one is not shown to sanitise every one. The
        verdict text carries that limit so a reader cannot take it as broader.
        """
        t0 = time.monotonic()
        canary = self._tmp / f"canary-004-{uuid.uuid4().hex[:8]}"
        repo = self._build_repo("delivered-004", canary=canary)
        canary.unlink(missing_ok=True)
        self._git("status", cwd=repo)
        time.sleep(0.2)
        unsanitised_fired = canary.exists()
        canary.unlink(missing_ok=True)
        self._git("-c", "core.fsmonitor=false", "status", cwd=repo)
        time.sleep(0.2)
        sanitised_fired = canary.exists()
        self._record(WorkspaceTrustResult(
            test_id="WT-004", name="Named-Sink Sanitisation Suppresses Execution",
            category="workspace_trust", owasp_asi="ASI06",
            stride="Elevation of Privilege", severity="MEDIUM",
            passed=unsanitised_fired and not sanitised_fired,
            ingestion_path="delivered", canary_fired=sanitised_fired,
            details=(INCONCLUSIVE_PREFIX + "the unsanitised call did not run the "
                     "sink either, so this environment never demonstrated the "
                     "behaviour the mitigation is meant to suppress.")
                    if not unsanitised_fired
                    else ("Local self-test, decided without the target: "
                          "sanitising the call suppressed the named sink. This "
                          "establishes only that key; the disclosure withheld a "
                          "further one that remains unpatched")
                    if not sanitised_fired
                    else "The sanitised call still ran the repository's command",
            protocol="local", elapsed_s=round(time.monotonic() - t0, 3)))

    # -- runner -----------------------------------------------------------

    def run_all(self, categories: list[str] | None = None) -> list[WorkspaceTrustResult]:
        for test in (self.test_wt_001_repository_supplied_config_executes,
                     self.test_wt_002_read_only_ingestion_still_executes,
                     self.test_wt_003_cloned_source_does_not_carry_the_sink,
                     self.test_wt_004_named_sink_sanitisation_is_effective):
            test()
            r = self.results[-1]
            # console_status, not a local expression: twenty-nine harnesses each
            # had their own copy and every one printed INCONCLUSIVE as FAIL.
            print(f"  {console_status(r)} {r.test_id}: {r.name} ({r.elapsed_s:.2f}s)")
        return self.results

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)


#: `--self-test` drives a naive ingesting command: it runs `git status` in the
#: directory it is given, which is what an agent gathering context does. It is
#: expected to FAIL WT-001, and a self-test run that passes it means the fixture
#: stopped working.
#:
#: Deliberately NOT called `--simulate`. In this package that flag means rows
#: produced without a live target, and testing/test_simulated_passes_are_scoped
#: requires such rows to carry a simulation marker. These rows are real
#: measurements against real git against a real command; marking them simulated
#: to satisfy a guard would make the report say something untrue.
SELF_TEST_COMMAND = "git -C {repo} status --porcelain && echo ingested"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--command", help="command that ingests a repo; {repo} is substituted")
    ap.add_argument("--self-test", dest="self_test", action="store_true",
                    help="run against a built-in naive ingesting command")
    ap.add_argument("--report", help="write JSON results here")
    args = ap.parse_args(argv)

    if not args.command and not args.self_test:
        ap.error("one of --command or --self-test is required")
    if not shutil.which("git"):
        print("UNREACHABLE: git is not on PATH; nothing was tested.")
        return 2

    suite = WorkspaceTrustTests(args.command or SELF_TEST_COMMAND,
                                self_test=args.self_test)
    try:
        results = suite.run_all()
        if args.report:
            report = {
                "suite": "Workspace-Trust / Repository-Ingestion Pre-Flight Tests v1.0",
                "provenance": run_provenance(),
                "summary": {
                    "total": len(results),
                    "passed": sum(1 for r in results if r.passed),
                    "failed": sum(1 for r in results
                                  if not r.passed and not r.not_evaluated),
                    "inconclusive": sum(1 for r in results if r.not_evaluated),
                },
                "results": [r.__dict__ for r in results],
            }
            Path(args.report).write_text(
                json.dumps(report, indent=2, default=str), encoding="utf-8")
        return 1 if any(not r.passed and not r.not_evaluated for r in results) else 0
    finally:
        suite.cleanup()


if __name__ == "__main__":
    sys.exit(main())
