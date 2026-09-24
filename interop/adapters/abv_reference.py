"""Adapter: the Approval Binding Vectors reference checker (``check.py``).

Upstream: https://github.com/msaleme/approval-binding-vectors (MIT).

Each vector is run through the checker twice, in fresh subprocesses, and both
answers are recorded verbatim:

  1. ``verify(record)`` from the pinned ``check.py``, called through a
     ten-line shim, gives the checker's own verdict and predicate. This is the
     observed outcome the runner compares against the fixture's ``expect``.
  2. ``python3 check.py <vector>`` is the checker's own CLI. It prints
     ``PASS``/``FAIL`` for whether the checker thinks it matched the fixture.
     The runner treats that as a second opinion: if it disagrees with the
     runner's own comparison, the vector is reported as an error.

No vocabulary mapping is done. ABV verdicts are already ``accept``/``reject``,
and the reason code is the ABV predicate (``P1``..``P6``) exactly as returned.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ADAPTER_ID = "abv-reference-check-py"
ACCEPT_VERDICTS = frozenset({"accept"})

_SHIM = r"""
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("abv_checker_under_test", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
rec = json.loads(open(sys.argv[2], encoding="utf-8").read())
try:
    verdict, predicate, reason = mod.verify(rec)
except mod.Reject as r:
    verdict, predicate, reason = "reject", r.predicate, r.reason
print(json.dumps({"verdict": verdict, "predicate": predicate, "reason": reason}))
"""


def _env() -> dict:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"  # never write into the pinned checkout
    return env


def _call(argv: list[str], cwd: Path, timeout: float) -> dict:
    try:
        cp = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                            timeout=timeout, env=_env(), check=False)
    except subprocess.TimeoutExpired:
        return {"argv": argv, "exit_code": None, "stdout": "", "stderr": "",
                "timed_out": True}
    return {"argv": argv, "exit_code": cp.returncode, "stdout": cp.stdout,
            "stderr": cp.stderr, "timed_out": False}


def run(checker: Path, vector_path: Path, timeout: float) -> dict:
    cwd = checker.parent
    verify_call = _call([sys.executable, "-c", _SHIM, str(checker), str(vector_path)],
                        cwd, timeout)
    cli_call = _call([sys.executable, str(checker), str(vector_path)], cwd, timeout)
    raw = {"verify": verify_call, "cli": cli_call,
           # Kept at the top level too, so run.log shows the checker's own words.
           "stdout": cli_call["stdout"], "stderr": verify_call["stderr"] + cli_call["stderr"],
           "exit_code": cli_call["exit_code"]}

    if verify_call["timed_out"] or cli_call["timed_out"]:
        return {"observed": None, "raw": raw, "error": f"timed out after {timeout}s"}
    if verify_call["exit_code"] != 0:
        return {"observed": None, "raw": raw,
                "error": f"verify() exited {verify_call['exit_code']}"}
    try:
        answer = json.loads(verify_call["stdout"].strip().splitlines()[-1])
        observed = {"verdict": answer["verdict"], "reason_code": answer["predicate"],
                    "reason": answer["reason"]}
    except (ValueError, IndexError, KeyError, TypeError) as exc:
        return {"observed": None, "raw": raw,
                "error": f"unreadable verify() output ({type(exc).__name__})"}

    first = (cli_call["stdout"].split() or [""])[0]
    self_report = {"PASS": "pass", "FAIL": "fail"}.get(first)
    if self_report is None:
        return {"observed": observed, "raw": raw,
                "error": f"checker CLI printed no PASS/FAIL (exit {cli_call['exit_code']})"}
    return {"observed": observed, "raw": raw, "error": None, "self_report": self_report}
