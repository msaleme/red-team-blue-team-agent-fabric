#!/usr/bin/env python3
r"""Run mcp_harness against a pinned upstream MCP reference server, locally.

## Why this exists as a job rather than a one-off

The three target sweeps use fixtures this repository wrote. They cannot falsify
the assumptions the harness already holds, because the same author wrote both.
Every defect found on 2026-08-29/30 that the sweeps could NOT reach came from a
real implementation or from someone reading the source:

    MCP-002/008/018   the protocol's in-band result.isError rejection idiom
    MCP-003           an error envelope read as absence of capabilities
    MCP-017           a P0 control never exercised, because stdio never ran
    MCP-009           a response claimed from elapsed time

Keeping one real implementation in the loop is the cheapest correction for that,
and an independent review asked for it to become a retained job rather than an
afternoon.

## What it reports, and why not a boolean

    16 PASS   2 FAIL   14 INCONCLUSIVE / not-applicable

Collapsing that to green/red loses the thing worth watching. The 14 are controls
whose preconditions the reference server does not meet -- twelve modern-MCP RC
checks with no authorized probe material, MCP-007 with no sampling capability,
MCP-011 whose defined outcomes were not observed. If a future change quietly
promoted any of those to PASS, a boolean would not notice. The class split is
the signal.

The two FAILs are findings about the reference server in this configuration, not
about the harness and not a security assessment of the package.

## The version is pinned on purpose

Upstream behaviour and version can both move, which is the standing uncertainty
in this job. A floating `@latest` would turn every upstream release into an
unexplained diff in our own regression state. REFERENCE_SERVER pins it; bumping
it is a deliberate edit that should come with a re-read of the class split.

    python3 scripts/mcp_reference_calibration.py           # table
    python3 scripts/mcp_reference_calibration.py --json    # machine-readable
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

#: Pinned. See the docstring: a floating tag makes upstream releases look like
#: regressions in this repository.
REFERENCE_SERVER = "@modelcontextprotocol/server-everything@2026.8.18"


def server_command(offline_first: bool = True) -> list[str] | None:
    """The npx invocation, or None when the server cannot be launched here.

    Tries the local npm cache first so a normal run needs no network. Returns
    None rather than raising, because "the fixture is unavailable" is a state
    this job must report as unmeasured, never as success.
    """
    if shutil.which("npx") is None:
        return None
    return ["npx", "--offline", "-y", REFERENCE_SERVER, "stdio"] if offline_first \
        else ["npx", "-y", REFERENCE_SERVER, "stdio"]


def calibrate(command: list[str]) -> dict:
    """Run the full MCP suite over stdio against *command* and classify."""
    from protocol_tests.http_helpers import is_inconclusive
    from protocol_tests.mcp_harness import MCPSecurityTests, StdioTransport

    transport = StdioTransport(command)
    suite = MCPSecurityTests(transport)
    try:
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            suite.run_all()
    finally:
        with contextlib.suppress(Exception):
            transport.proc.kill()

    results = list(suite.results)
    rows = []
    for r in results:
        detail = r.details or ""
        if r.passed:
            cls = "PASS"
        elif is_inconclusive(detail) or "Not applicable" in detail \
                or "not applicable" in detail:
            cls = "INCONCLUSIVE"
        else:
            cls = "FAIL"
        rows.append({"test_id": r.test_id, "class": cls, "details": detail[:160]})

    counts = {c: sum(1 for x in rows if x["class"] == c)
              for c in ("PASS", "FAIL", "INCONCLUSIVE")}
    # Zero results means the MCP session never initialised, which in practice
    # means the server never started: `npx` exists but the pinned package is not
    # in the local cache, so `--offline` cannot resolve it. Popen still succeeds,
    # nothing answers, and run_all returns empty.
    #
    # This has to be its own state. The first version of this job only caught an
    # exception, so on a machine without the cache the caller received
    # {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0} and the state test read it as
    # "the class split moved" -- turning UNMEASURED into a confident and wrong
    # failure message. That is the defect this whole job exists to catch, in the
    # job itself.
    return {"server": REFERENCE_SERVER, "total": len(rows),
            "launched": bool(rows), "counts": counts, "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--network", action="store_true",
                    help="allow npx to fetch the pinned server if not cached")
    args = ap.parse_args()

    cmd = server_command(offline_first=not args.network)
    if cmd is None:
        print("npx is not available; the reference server cannot be launched.",
              file=sys.stderr)
        print("UNMEASURED, not clean.", file=sys.stderr)
        return 2
    try:
        report = calibrate(cmd)
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed into a pass
        print(f"reference server did not run: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        print("UNMEASURED, not clean. Retry with --network if it is not cached.",
              file=sys.stderr)
        return 2

    if not report["launched"]:
        print(f"{REFERENCE_SERVER} produced no results: the MCP session never "
              f"initialised, so the server almost certainly did not start.",
              file=sys.stderr)
        print("UNMEASURED, not clean. Retry with --network to populate the cache.",
              file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    c = report["counts"]
    print(f"{report['server']}  (stdio, loopback child process)")
    print("-" * 78)
    for row in report["rows"]:
        print(f"  {row['class']:13} {row['test_id']:12} {row['details'][:52]}")
    print("-" * 78)
    print(f"  {c['PASS']} PASS   {c['FAIL']} FAIL   {c['INCONCLUSIVE']} "
          f"INCONCLUSIVE / not applicable   of {report['total']}")
    print("The class split is the signal. A boolean would hide an INCONCLUSIVE")
    print("quietly becoming a PASS, which is what this job exists to watch.")
    print("FAILs are findings about this reference server in this configuration,")
    print("not a security assessment of the package.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
