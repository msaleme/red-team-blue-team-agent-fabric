#!/usr/bin/env python3
r"""Run every live-target harness against three targets with no surface, and report any verdict.

## The defect class

A verdict that does not depend on the target. It has been repaired one family
at a time:

    #591  seven CVE tests PASSed or FAILed with no surface to judge
    #594  six A2A tests PASSed against a host answering 404 to everything

and each repair reached only the tests someone had opened. This sweep asks the
question of every registered harness at once. It points each one at three
targets that have no surface to judge, where the only honest verdict is
INCONCLUSIVE (or NOT_EXECUTED, which `row_outcome` counts as INCONCLUSIVE):

    closed    nothing listening on the port
    404       every verb, every path: HTTP 404, body "Not Found"
    403       every verb, every path: HTTP 403, body "Forbidden"

A PASS on any of them says a control held on a target that exposes nothing. A
FAIL says a vulnerability was found on one. Both are the same defect.

## Why 403-everywhere is a no-surface pole

A 403 can be the control working. `refusing_host_sweep.py` exists to check that
suites can recognise that, and it keeps doing so: its target answers 403 WITH a
JSON-RPC error envelope and a refusal in prose, which is a protocol surface
refusing. The target here is different -- a bare 403 with no protocol shape, to
discovery, health, tool listing and the attack alike. Nothing on it is served,
so nothing shows there is a surface behind the refusal. The repository already
has two statements of what that means:

  * `http_helpers.inconclusive_detail`: "A bare 403 cannot be distinguished
    from 'your credentials were rejected and you never reached the agent', and
    that ambiguity is exactly what INCONCLUSIVE exists to report."
  * `mcp_harness._auth_outcome` / MCP-021: a 401/403 is graded a rejection only
    relative to a served baseline.

So the default here is INCONCLUSIVE. Where the repository has already pinned a
PASS against a bare 403 as the intended contract -- #594's A2A-004..011, "an
authorization refusal is an answer from an endpoint that exists" -- the guard
records it as contract-consistent, cites the pinning test, and requires the
verdict to discriminate (INCONCLUSIVE at the 404 pole and the closed port).
It does not call it a defect, and it does not extend it to anything unpinned.
See `testing/test_verdicts_need_a_surface.py`.

## Population

Derived, not listed: `dead_host_sweep.registry_coverage()` -- the CLI registry
minus the sweep's reasoned NOT_APPLICABLE -- filtered to the harnesses whose own
argparse accepts `--url` (`declares_url`, any argument position). A harness registered
tomorrow with `--url` is in the population without anyone editing this file.

    python3 scripts/no_surface_sweep.py            # table, worst first
    python3 scripts/no_surface_sweep.py --json     # machine-readable cells
"""

from __future__ import annotations

import argparse
import functools
import json
import sys
import threading
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from dead_host_sweep import CLOSED_PORT, registry_coverage, sweep  # noqa: E402

#: Pole name -> (HTTP status, body), or None for a closed port.
POLES: dict[str, tuple[int, str] | None] = {
    "closed": None,
    "404": (404, "Not Found"),
    "403": (403, "Forbidden"),
}

#: The outcomes that are not a verdict about the target. `row_outcome` folds
#: NOT_EXECUTED into INCONCLUSIVE, so this is the whole set.
NO_VERDICT = frozenset({"INCONCLUSIVE"})


def _handler(status: int, body: str):
    payload = body.encode()

    class _Everywhere(BaseHTTPRequestHandler):
        def _answer(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(n)
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _answer

        def log_message(self, *args):
            """Silence. The sweep captures harness output; this is server noise."""

    return _Everywhere


class status_everywhere_target:
    """A loopback server answering one status and body to every request.

    Port 0 on 127.0.0.1, like the permissive and refusing targets, so a sweep
    cannot collide with a real service or expose anything off the machine.
    """

    def __init__(self, status: int, body: str):
        self._status, self._body = status, body

    def __enter__(self) -> str:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0),
                                           _handler(self._status, self._body))
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.01},
                                        daemon=True)
        self._thread.start()
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        return False


def declares_url(harness_name: str) -> bool:
    """Whether the harness's own argparse accepts `--url`, in any position.

    `cli._module_declares_flag` matches only a FIRST argument of `--url`, so
    `hitl_harness`'s ``add_argument("--target", "--url", ...)`` reads as no
    `--url` there. That is right for what the CLI uses it for and wrong for a
    population: hitl talks to a URL. Parsed with `ast` rather than a regex, so
    an alias in any position counts and prose mentioning the flag does not.
    """
    import ast
    import importlib.util

    from protocol_tests.cli import HARNESSES
    spec = importlib.util.find_spec(HARNESSES[harness_name]["module"])
    if not spec or not spec.origin:
        return False
    tree = ast.parse(Path(spec.origin).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"
                and any(isinstance(a, ast.Constant) and a.value == "--url"
                        for a in node.args)):
            return True
    return False


def live_target_harnesses() -> dict[str, str]:
    """Registry name -> module stem, for every exercised harness taking `--url`.

    Two derivations composed, neither a list: the sweep's registry coverage
    (which raises rather than shrinks), and each module's own argparse.
    """
    exercised = registry_coverage()["exercised"]
    return {name: stem for name, stem in exercised.items() if declares_url(name)}


def no_network_target_harnesses() -> dict[str, str]:
    """Exercised harnesses that take no `--url`: a URL pole is not their input."""
    exercised = registry_coverage()["exercised"]
    live = live_target_harnesses()
    return {name: stem for name, stem in exercised.items() if name not in live}


def pole_sweeps() -> dict[str, list[dict]]:
    """Pole -> the dead-host sweep's rows against that pole. Same machinery."""
    out: dict[str, list[dict]] = {}
    for pole, spec in POLES.items():
        if spec is None:
            out[pole] = sweep(target=CLOSED_PORT)
            continue
        with status_everywhere_target(*spec) as url:
            out[pole] = sweep(target=url)
    return out


def cells(rows_by_pole: dict[str, list[dict]], stems) -> dict[tuple[str, str, str], dict]:
    """(module stem, test id, pole) -> {"outcome", "locally_decided"}.

    Only for modules in *stems*. Raises if one test id is produced by two
    modules, or twice by one module on one pole: a cell must name one verdict.
    """
    stems = set(stems)
    out: dict[tuple[str, str, str], dict] = {}
    owner: dict[str, str] = {}
    for pole, rows in rows_by_pole.items():
        for row in rows:
            stem = row["module"].split("::")[0]
            if stem not in stems or row.get("status") != "ran":
                continue
            for o in row.get("outcomes", []):
                tid = o["test_id"]
                if owner.setdefault(tid, stem) != stem:
                    raise ValueError(f"{tid} is produced by {owner[tid]} and {stem}")
                key = (stem, tid, pole)
                if key in out:
                    raise ValueError(f"{tid} produced twice on the {pole} pole")
                out[key] = {"outcome": o["outcome"],
                            "locally_decided": o["locally_decided"]}
    return out


@functools.lru_cache(maxsize=1)
def measured_live_cells() -> dict[tuple[str, str, str], dict]:
    """The three-pole measurement over the derived population, taken once.

    Cached per process because two test files read it (the guard and the
    evidence-integrity registers) and each run costs three full sweeps.
    """
    return cells(pole_sweeps(), live_target_harnesses().values())


def verdicts_without_surface(cell_map) -> dict[tuple[str, str, str], str]:
    """Every cell whose outcome is a verdict, i.e. PASS or FAIL."""
    return {k: v["outcome"] for k, v in cell_map.items()
            if v["outcome"] not in NO_VERDICT}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    live = live_target_harnesses()
    cell_map = cells(pole_sweeps(), live.values())
    found = verdicts_without_surface(cell_map)
    if args.json:
        print(json.dumps([
            {"module": m, "test_id": t, "pole": p, "outcome": o,
             "locally_decided": cell_map[(m, t, p)]["locally_decided"]}
            for (m, t, p), o in sorted(found.items())], indent=2))
        return 0

    per = defaultdict(Counter)
    for (m, _t, p), o in found.items():
        per[m][f"{p}:{o}"] += 1
    cols = [f"{p}:{o}" for p in POLES for o in ("PASS", "FAIL")]
    print(f"{'module':34s} " + " ".join(f"{c:>11s}" for c in cols))
    print("-" * (35 + 12 * len(cols)))
    for m in sorted(per, key=lambda m: (-sum(per[m].values()), m)):
        print(f"{m:34s} " + " ".join(f"{per[m][c] or '':>11}" for c in cols))
    print("-" * (35 + 12 * len(cols)))
    total = Counter(p for (_m, _t, p) in cell_map)
    print(f"{len(live)} live-target harnesses, {len(cell_map)} cells "
          f"({', '.join(f'{p}: {n}' for p, n in total.items())}); "
          f"{len(found)} are a PASS or FAIL against a target with no surface.")
    print("Self-tests (locally_decided) are included above; the guard in "
          "testing/test_verdicts_need_a_surface.py excludes them by name.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
