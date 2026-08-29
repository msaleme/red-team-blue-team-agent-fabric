#!/usr/bin/env python3
r"""Run every candidate harness against a closed port and report what still passes.

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

    module[::Class]  passed/total  errors  verdict

A module holding several suites -- the adapter families -- gets one row per
concrete adapter. Single-suite modules keep the bare module name, because the
pins in testing/test_dead_host_state.py refer to them by it.

Three statuses are not the same thing and used to look the same:

    ran                 produced verdicts; the count is a measurement
    ran-no-verdicts     ran and produced nothing; NOT a clean row
    <exception>         could not be run at all

`mcp_harness` is the second kind. It aborts with

    if not self.initialize():
        return self.results

which is the correct behaviour -- it refuses to emit verdicts it cannot ground
-- and it rendered as `0/0`, indistinguishable from a suite that ran everything
and found nothing. No failures is not the same as passing, one level up from the
rule this script exists to enforce.

`passed` is the count that survived a target which was never there. Anything
above zero needs reading. `errors` is tests that raised; a module that errors is
not a module that passed, and the two must not be conflated -- an earlier fix
appeared to reach 0 of 25 only because every test was raising NameError and the
runner was catching it.

## What this does NOT establish

That a module with 0 passing is correct. It establishes that this particular
failure mode is absent. A module can score 0 here and still mis-verdict against a
live target in every other way.

## The finder was a naming convention

Until 2026-08-29 this script looked for a class matching `^class (\w*Tests?)`
that had `run_all`. Both halves were conventions dressed as a discovery rule,
and eight modules came back `no-suite-class` -- a row that reads as a fact about
the module when it was a fact about the finder:

    autogen_harness, gtg1002_simulation      class name lacks "Tests"
    cloud_agent_harness                      6 adapters, run_tests not run_all
    enterprise_adapters                     10 adapters, run_tests not run_all
    extended_enterprise_adapters            12 adapters, run_tests not run_all
    framework_adapters                       7 adapters, run_tests not run_all

The summary line counted modules it could construct and said nothing at all
about the rest, which is the failure this script exists to catch, aimed at
itself. No count is restated here; testing/test_dead_host_state.py asserts a
floor and fails if discovery narrows back to a naming convention.

The adapters turned out to be guarded already, at the base class -- but that was an
argument ("every subclass inherits it") and the guard suite verified it for four
of them with synthetic fixtures. It is now measured for all of them.

Discovery is by capability: a non-abstract class defined in the module with a
callable `run_all` or `run_tests`. `harness_base` legitimately has neither; that
row now means what it says.

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


def _suites(mod_name: str):
    r"""Every runnable suite in a module, found by capability rather than by name.

    The first version of this asked for a class whose name matched
    ``^class (\w*Tests?)`` and which had ``run_all``. Both halves were naming
    conventions dressed as a discovery rule, and eight modules came back as
    ``no-suite-class`` -- a row that reads as a fact about the module when it was
    a fact about the finder:

        autogen_harness         AutoGenHarness       (no "Tests" suffix)
        gtg1002_simulation      GTG1002Simulation    (no "Tests" suffix)
        cloud_agent_harness     6 adapters           (run_tests, not run_all)
        enterprise_adapters     10 adapters          (run_tests, not run_all)
        extended_enterprise_adapters  12 adapters    (run_tests, not run_all)
        framework_adapters      7 adapters           (run_tests, not run_all)

    That is 34 suites the sweep reported nothing about while reporting 28
    modules clean. "No failures" was not the same as "passing", one level up
    from the rule this whole script exists to enforce.

    A module may still legitimately have none: ``harness_base`` is the shared
    ABC and defines no tests of its own. That row now means what it says.
    """
    try:
        mod = importlib.import_module(f"protocol_tests.{mod_name}")
    except Exception:  # noqa: BLE001 - a module that will not import is a row, not a crash
        return None, []
    found = []
    for name, obj in vars(mod).items():
        if not (inspect.isclass(obj) and obj.__module__ == mod.__name__):
            continue
        if getattr(obj, "__abstractmethods__", ()):
            continue                      # an ABC is a base, not a suite
        runner = next((r for r in ("run_all", "run_tests")
                       if callable(getattr(obj, r, None))), None)
        if runner:
            found.append((name, obj, runner))
    return mod, found


def _transport_for(cls, target: str = CLOSED_PORT):
    """A concrete transport from the suite's own module, for suites that take one."""
    mod = sys.modules[cls.__module__]
    for name, obj in vars(mod).items():
        if not (inspect.isclass(obj) and name.endswith("Transport")):
            continue
        if getattr(obj, "__abstractmethods__", ()):
            continue
        params = list(inspect.signature(obj.__init__).parameters)[1:]
        # Named parameters only. MCPTransport takes (*args, **kwargs), which
        # accepts a URL and does nothing with it -- a candidate that constructs
        # successfully and cannot talk to anything, which is the worst kind.
        if not params or params[0] not in ("url", "base_url", "target", "endpoint"):
            continue
        try:
            return obj(target)
        except Exception:  # noqa: BLE001,S112 - a bad candidate is not an error
            continue
    return None


def _instantiate(cls, target: str = CLOSED_PORT):
    """Best-effort construction. Suites take a url, a transport, or neither."""
    params = list(inspect.signature(cls.__init__).parameters)[1:]
    first = params[0] if params else None
    if first == "transport":
        transport = _transport_for(cls, target)
        if transport is None:
            raise TypeError(f"no concrete transport found for {cls.__name__}")
        return cls(transport)
    if first is None:
        return cls()
    return cls(target)


def sweep(target: str = CLOSED_PORT) -> list[dict]:
    """Run every discoverable suite against *target* and report what passes.

    The target is a parameter because the closed port is one shape of a
    question, not the whole question. scripts/permissive_host_sweep.py passes
    the opposite pole: a server that accepts every request.
    """
    rows = []
    for name in _candidate_modules():
        _, suites = _suites(name)
        if not suites:
            rows.append({"module": name, "status": "no-suite-class"})
            continue
        for cls_name, cls, runner in suites:
            # Label by class only where a module holds more than one, so the
            # single-suite rows keep the names every existing pin refers to.
            label = name if len(suites) == 1 else f"{name}::{cls_name}"
            try:
                suite = _instantiate(cls, target)
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    returned = getattr(suite, runner)()
                results = list(getattr(suite, "results", None) or returned or [])
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                rows.append({"module": label,
                             "status": f"{type(exc).__name__}: {exc}"[:70]})
                continue
            if not results:
                # Distinct from "ran, everything zero". mcp_harness aborts with
                # `if not self.initialize(): return self.results`, which is the
                # right behaviour and produces a 0/0 row that reads exactly like
                # a clean sweep. No failures is not the same as passing.
                rows.append({"module": label, "status": "ran-no-verdicts",
                             "total": 0, "passed": 0, "errors": 0,
                             "passing_ids": []})
                continue
            passed = [_test_id(r) for r in results if getattr(r, "passed", False)]
            errored = [_test_id(r) for r in results
                       if str(getattr(r, "name", "")).startswith("ERROR")]
            rows.append({
                "module": label,
                "status": "ran",
                "total": len(results),
                "passed": len(passed),
                "errors": len(errored),
                "passing_ids": passed,
            })
    # worst first: most passes against nothing
    rows.sort(key=lambda r: (-(r.get("passed") or 0), r["module"]))
    return rows


def _test_id(result) -> str:
    return str(getattr(result, "test_id", None) or getattr(result, "name", "?"))


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
            if r["status"] == "ran-no-verdicts":
                print(f"{r['module']:34s} {'0/0':>11s} {'--':>4s}  "
                      f"produced no verdicts -- nothing measured, not clean")
                continue
            if r["status"] != "ran":
                print(f"{r['module']:34s} {'--':>11s} {'--':>4s}  {r['status']}")
                continue
            ids = ", ".join(r["passing_ids"][:6])
            if len(r["passing_ids"]) > 6:
                ids += f", +{len(r['passing_ids']) - 6} more"
            print(f"{r['module']:34s} {r['passed']:>5}/{r['total']:<5} "
                  f"{r['errors']:>4}  {ids}")
        ran = [r for r in rows if r["status"] == "ran"]
        silent = [r for r in rows if r["status"] == "ran-no-verdicts"]
        skipped = [r for r in rows if r["status"] not in ("ran", "ran-no-verdicts")]
        dirty = [r for r in ran if r["passed"]]
        print("-" * 96)
        print(f"{len(ran)} suites produced verdicts, {len(dirty)} still pass "
              f"something against a target that was never there.")
        print("A row above zero is either a false pass or a test that needs no "
              "target. Both are worth reading.")
        if silent:
            print(f"{len(silent)} produced no verdicts at all "
                  f"({', '.join(r['module'] for r in silent)}) -- unmeasured, not clean.")
        if skipped:
            print(f"{len(skipped)} could not be run "
                  f"({', '.join(r['module'] for r in skipped)}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
