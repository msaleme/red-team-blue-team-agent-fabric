#!/usr/bin/env python3
r"""Run every suite against a target that refuses everything, and report what passes.

## The third pole

    closed port   the target never answered       a PASS is unfounded
    allow-all     the target granted everything   a PASS is unfounded
    deny-all      the target refused everything   a FAILURE to pass is a defect

The first two ask whether a verdict can be wrong. This one asks whether it can
be right. A security control that refuses every attack is the case these
harnesses exist to recognise, and a suite that cannot pass it is as broken as
one that cannot fail -- it just fails silently, in the direction nobody checks.

## Why this is not a bulk-guard exercise

`http_helpers._serviced` treats a non-2xx as "the target did not service the
request". That is right for "method not found" and backwards wherever the
refusal IS the control working -- a 402 in x402, a 403 in an auth harness, a
JSON-RPC error envelope in a provenance harness. Nine modules needed that
exception during #351, found one at a time, each after the module had already
been repaired in the other direction.

The remaining call sites of `inconclusive_detail` might have the same problem or
might be correct. Guessing produces a bulk edit; measuring produces a list. A
suite that scores zero here, while its subject matter is a refusal, is the
identity_harness shape and needs reading. A suite that scores zero here because
its subject matter is something else entirely is fine.

## What a PASS here means

That the verdict recognised a refusal. It says nothing about whether the suite
would catch a real vulnerability -- that is what the other two poles and a live
target are for.

    python3 scripts/refusing_host_sweep.py            # table, worst first
    python3 scripts/refusing_host_sweep.py --json     # machine-readable
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

#: HTTP 403 with a JSON-RPC error envelope. Both conventions at once, because
#: the harnesses split on which one they read: some check `_status`, some check
#: for an `error` key, and a real gateway refusing an action sets both.
DENY_STATUS = 403
DENY_BODY = {
    "jsonrpc": "2.0",
    "id": 1,
    "error": {"code": -32001, "message": "request refused by policy"},
    "detail": "I cannot comply with that request. It is not appropriate.",
}


class _DenyAll(BaseHTTPRequestHandler):
    def _answer(self):
        body = json.dumps(DENY_BODY).encode()
        self.send_response(DENY_STATUS)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _answer

    def log_message(self, *args):
        """Silence. The sweep captures harness output; this is server noise."""


class deny_all_target:
    """A live endpoint that refuses everything, on an ephemeral loopback port."""

    def __enter__(self) -> str:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _DenyAll)
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


def refusing_sweep() -> list[dict]:
    with deny_all_target() as url:
        return sweep(target=url)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    rows = refusing_sweep()
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    ran = [r for r in rows if r["status"] == "ran"]
    # A suite that recognises nothing is the interesting row here, so sort the
    # other way from the first two sweeps: fewest passes first.
    ran.sort(key=lambda r: (r["passed"] / r["total"] if r["total"] else 1,
                            r["module"]))
    print(f"{'suite':44s} {'pass/total':>11s} {'err':>4s}  recognised the refusal")
    print("-" * 100)
    for r in ran:
        mark = "  <- recognises nothing" if r["passed"] == 0 and r["total"] else ""
        print(f"{r['module']:44s} {r['passed']:>5}/{r['total']:<5} "
              f"{r['errors']:>4}{mark}")
    blind = [r for r in ran if r["total"] and r["passed"] == 0]
    print("-" * 100)
    print(f"{len(ran)} suites produced verdicts. "
          f"{sum(r['passed'] for r in ran)} of {sum(r['total'] for r in ran)} "
          f"verdicts pass against a target that refused every request.")
    print(f"{len(blind)} suites recognised no refusal at all. That is a reading "
          f"list, not a defect count:")
    print("  - a suite may test something a blanket refusal does not exercise "
          "(a parser, a local scan, a rate limit);")
    print("  - or it may be the identity_harness shape, unable to pass the one "
          "target shape it exists to recognise.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
