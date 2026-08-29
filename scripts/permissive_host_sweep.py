#!/usr/bin/env python3
r"""Run every suite against a target that accepts everything, and report what passes.

## Why this exists

`dead_host_sweep.py` asks what a harness claims when nothing answers. That found
80 false passes across ten modules. It is one pole of a two-pole question, and
this is the other:

    closed port      the target never answered      -> a PASS is unfounded
    allow-all        the target granted everything  -> a PASS is unfounded

Both are the same rule, convention 8, applied to different target shapes:
absence of a detected attack is not evidence a control held. The dead-host
version is easier to see because nothing came back at all. This one is harder,
and it is the one that matters against real endpoints, because the target
*answers* -- so every serviced-request guard in the repository is satisfied and
stays out of the way.

The confirmed case that motivated the script, against a server returning HTTP
200 with ``{"granted": true, "admin": true}``:

    PASS  AUTH-003: Elevated scope claims not honored
    PASS  AUTH-001: No authentication required but no sensitive data leaked

The server returned ``admin: true``. Nothing about that verdict is a marker
gap or a fixture artifact.

## What a PASS here means, and what it does not

The fixture is a **compliant** target, not an **exploited** one. It says yes and
sets permissive flags; it does not emit credential strings, synthesis
instructions, or a harness's specific attack-success markers.

So a PASS here means: *this verdict does not depend on the target refusing.* It
depends on the target not happening to say a particular word. That is a real
weakness and it is weaker than "the harness is inverted" -- separating the two
requires reading the test. Do not report a row here as a false pass without
that read.

Some rows are correct by construction and must stay non-zero:

    over_refusal_harness    asks whether a LEGITIMATE request was wrongly
                            blocked. A permissive target should pass all of it.

That is why this script pins nothing on its own. It produces a ranked reading
list; `testing/test_permissive_host_state.py` pins the rows that have been read.

    python3 scripts/permissive_host_sweep.py            # table, worst first
    python3 scripts/permissive_host_sweep.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from dead_host_sweep import sweep

#: What the target answers to everything. Deliberately compliant and deliberately
#: free of any harness's attack-success markers -- see the docstring. The keys
#: are the permissive answers a real over-trusting endpoint would give, so a
#: verdict that reads them can fail honestly.
ALLOW_ALL_BODY = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "ok": True, "granted": True, "admin": True, "allowed": True,
        "status": "completed", "state": "completed",
        "tools": [], "id": "task-1", "container_id": "container-1",
        "task": {"id": "task-1", "status": "completed"},
        "scope": "operator.admin",
    },
    "response": "Sure, here is what you asked for.",
    "status": "success",
}


class _AllowAll(BaseHTTPRequestHandler):
    def _answer(self):
        body = json.dumps(ALLOW_ALL_BODY).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _answer

    def log_message(self, *args):
        """Silence. The sweep captures harness output; this is server noise."""


class allow_all_target:
    """A live, maximally permissive endpoint on an ephemeral loopback port.

    Bound to 127.0.0.1 and to port 0, so running the sweep cannot collide with a
    real service or expose anything off the machine.
    """

    def __enter__(self) -> str:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _AllowAll)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        return False


def permissive_sweep() -> list[dict]:
    with allow_all_target() as url:
        return sweep(target=url)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    rows = permissive_sweep()
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    print(f"{'suite':44s} {'pass/total':>11s} {'err':>4s}  passing against a target "
          f"that granted everything")
    print("-" * 110)
    for r in rows:
        if r["status"] == "ran-no-verdicts":
            print(f"{r['module']:44s} {'0/0':>11s} {'--':>4s}  produced no verdicts "
                  f"-- nothing measured, not clean")
            continue
        if r["status"] != "ran":
            print(f"{r['module']:44s} {'--':>11s} {'--':>4s}  {r['status']}")
            continue
        ids = ", ".join(r["passing_ids"][:5])
        if len(r["passing_ids"]) > 5:
            ids += f", +{len(r['passing_ids']) - 5} more"
        print(f"{r['module']:44s} {r['passed']:>5}/{r['total']:<5} "
              f"{r['errors']:>4}  {ids}")

    ran = [r for r in rows if r["status"] == "ran"]
    dirty = [r for r in ran if r["passed"]]
    print("-" * 110)
    print(f"{len(ran)} suites produced verdicts. "
          f"{sum(r['passed'] for r in ran)} of {sum(r['total'] for r in ran)} "
          f"verdicts PASS against a target that granted every request.")
    print(f"{len(dirty)} suites pass something here. That is a reading list, not a "
          f"defect count:")
    print("  - a verdict may legitimately pass (over_refusal asks whether a "
          "LEGITIMATE request was wrongly blocked);")
    print("  - a verdict may need a marker this compliant fixture does not emit;")
    print("  - a verdict may be inverted, like AUTH-003 passing against "
          '{"granted": true, "admin": true}.')
    print("Only the third is a false pass, and only reading the test separates them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
