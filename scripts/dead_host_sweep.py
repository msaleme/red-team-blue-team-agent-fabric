#!/usr/bin/env python3
"""Run every candidate harness against a closed port and report what still passes.

## Why this exists

`scripts/audit_verdict_taint.py` orders #351 work by static analysis: it walks
each `passed=` expression and asks whether a target response reaches it. It is
useful and it is not a triage. On 2026-08-29 it scored four modules at 0%
false-pass shape. Run against a closed port, those four reported:

    over_refusal_harness         25 of 25 passed
    mcp_tool_poisoning_harness    8 of 10
    aiuc1_compliance_harness      3 of 12
    skill_security_harness        0 of 8

The 25 was the largest false-pass count in the whole sweep, in the module the
ordering metric called cleanest. `over_refusal`'s `_is_allowed` returned True for
a refused connection, and no `passed=` expression referenced a response directly,
so the taint walk had nothing to follow.

The auditor's own output says this: "absence of taint means only 'not reached by
these mechanisms, under these names'. It is NOT a proof that a verdict is sound."
That sentence is correct and it was still being read as a ranking.

This script asks the question behind the ranking instead of a proxy for it: point
the harness at nothing and see what it claims. A test that passes here is either
a false pass or a test that does not need a target, and both are worth knowing.

## What a row means

    module  passed/total  errors  verdict

`passed` is the count that survived a target which was never there. Anything
above zero needs reading. `errors` is tests that raised; a module that errors is
not a module that passed, and the two must not be conflated -- an earlier fix
appeared to reach 0 of 25 only because every test was raising NameError and the
runner was catching it.

## What this does NOT establish

That a module with 0 passing is correct. It establishes that this particular
failure mode is absent. A module can score 0 here and still mis-verdict against a
live target in every other way.

    python3 scripts/dead_host_sweep.py            # table, ordered worst first
    python3 scripts/dead_host_sweep.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import inspect
import io
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

#: Nothing listens here. Same target the serviced-guard suite uses.
CLOSED_PORT = "http://127.0.0.1:9"


def _candidate_modules() -> list[str]:
    """Same rule the guard suite uses, so the two cannot drift apart."""
    out = []
    for path in sorted((REPO_ROOT / "protocol_tests").glob("*.py")):
        src = path.read_text(encoding="utf-8")
        if "def _record" in src and "response_received" in src:
            out.append(path.stem)
    return out


def _suite_class(mod_name: str):
    """The module's test-suite class, found by convention rather than a list."""
    try:
        mod = importlib.import_module(f"protocol_tests.{mod_name}")
    except Exception:  # noqa: BLE001 - a module that will not import is a row, not a crash
        return None, None
    src = (REPO_ROOT / "protocol_tests" / f"{mod_name}.py").read_text(encoding="utf-8")
    for name in re.findall(r"^class (\w*Tests?)\b", src, re.MULTILINE):
        cls = getattr(mod, name, None)
        if cls is not None and hasattr(cls, "run_all"):
            return mod, cls
    return mod, None


def _instantiate(cls):
    """Best-effort construction. Harnesses take a url, a transport, or neither."""
    params = list(inspect.signature(cls.__init__).parameters)[1:]
    first = params[0] if params else None
    if first in ("url", "base_url", "target", "endpoint"):
        return cls(CLOSED_PORT)
    if first == "transport":
        mod = sys.modules[cls.__module__]
        for attr in dir(mod):
            if attr.endswith("Transport"):
                return cls(getattr(mod, attr)(CLOSED_PORT))
    return cls(CLOSED_PORT)


def sweep() -> list[dict]:
    rows = []
    for name in _candidate_modules():
        _, cls = _suite_class(name)
        if cls is None:
            rows.append({"module": name, "status": "no-suite-class"})
            continue
        try:
            suite = _instantiate(cls)
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                suite.run_all()
            results = list(getattr(suite, "results", []))
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            rows.append({"module": name, "status": f"{type(exc).__name__}: {exc}"[:70]})
            continue
        passed = [r.test_id for r in results if getattr(r, "passed", False)]
        errored = [r.test_id for r in results
                   if str(getattr(r, "name", "")).startswith("ERROR")]
        rows.append({
            "module": name,
            "status": "ran",
            "total": len(results),
            "passed": len(passed),
            "errors": len(errored),
            "passing_ids": passed,
        })
    # worst first: most passes against nothing
    rows.sort(key=lambda r: (-(r.get("passed") or 0), r["module"]))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    rows = sweep()
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(f"{'module':34s} {'pass/total':>11s} {'err':>4s}  passing against nothing")
        print("-" * 96)
        for r in rows:
            if r["status"] != "ran":
                print(f"{r['module']:34s} {'--':>11s} {'--':>4s}  {r['status']}")
                continue
            ids = ", ".join(r["passing_ids"][:6])
            if len(r["passing_ids"]) > 6:
                ids += f", +{len(r['passing_ids']) - 6} more"
            print(f"{r['module']:34s} {r['passed']:>5}/{r['total']:<5} "
                  f"{r['errors']:>4}  {ids}")
        ran = [r for r in rows if r["status"] == "ran"]
        dirty = [r for r in ran if r["passed"]]
        print("-" * 96)
        print(f"{len(ran)} modules ran, {len(dirty)} still pass something against a "
              f"target that was never there.")
        print("A row above zero is either a false pass or a test that needs no "
              "target. Both are worth reading.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
