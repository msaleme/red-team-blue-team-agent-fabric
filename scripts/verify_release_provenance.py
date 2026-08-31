#!/usr/bin/env python3
"""Check a published release against its provenance statement.

The reviewer's acceptance criterion for the v4.17.0 finding was not only that a
provenance statement exist, but that "CI/release verification fetch and validate
it". A statement nobody checks is a log, not a control -- the same argument this
repository already applied to the recorded build environment.

What this asserts:

    every artifact digest in the statement matches the digest PyPI publishes
    the statement's version matches the version being verified
    the statement names a commit, and that commit is the one the tag resolves to
    the statement was produced by a CI run, not a laptop

What it cannot assert, and says so rather than implying otherwise: that the
signer was authorised, or that the source is correct. Digest agreement is a
correspondence claim. `gh attestation verify` is the identity claim, and it is a
separate command against a separate authority.

Usage:
    python scripts/verify_release_provenance.py --provenance provenance.json
    python scripts/verify_release_provenance.py --provenance p.json --offline
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

PYPI = "https://pypi.org/pypi/{name}/{version}/json"


def fetch_pypi(name: str, version: str) -> dict:
    req = urllib.request.Request(PYPI.format(name=name, version=version),
                                 headers={"User-Agent": "agent-security-harness-provenance"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def check(statement: dict, offline: bool) -> list[str]:
    failures: list[str] = []

    def bad(msg: str) -> None:
        failures.append(msg)
        print(f"  [FAIL] {msg}")

    def ok(msg: str) -> None:
        print(f"  [PASS] {msg}")

    name = statement["package"]["name"]
    version = statement["package"]["version"]

    if statement.get("schema") != "agent-security-harness/release-provenance/v1":
        bad(f"unknown schema {statement.get('schema')!r}")
    else:
        ok(f"schema {statement['schema']}")

    src = statement.get("source") or {}
    if not src.get("commit"):
        bad("statement names no commit")
    elif src.get("tree_is_dirty"):
        bad(f"built from a dirty tree at {src['commit'][:12]}; not a release build")
    else:
        ok(f"commit {src['commit'][:12]}, clean tree")

    ci = statement.get("ci") or {}
    if not ci.get("run_id"):
        bad("no CI run identity: this statement was not produced by a workflow")
    else:
        ok(f"CI run {ci.get('repository')} #{ci['run_id']} attempt {ci.get('run_attempt')}")

    ref = src.get("ref_name")

    # v4.18.0rc2 is why this exists. The tag was cut, pyproject.toml was never
    # bumped from 4.18.0rc1, and the whole pipeline -- build, attestation,
    # offline verification, PyPI upload, release assets, post-publish digest
    # comparison -- passed while publishing a version whose name did not match
    # its tag. Every check agreed, because none of them compared those two
    # things.
    #
    # A tag is the name a release is referred to by. If it names a version the
    # artifact does not carry, every later citation of that tag points at
    # something else.
    if ref and re.fullmatch(r"v\d+.*", ref or ""):
        tagged = ref[1:]
        if tagged != version:
            bad(f"tag {ref} does not match the packaged version {version}; "
                f"the artifact would be published as {version} under a tag "
                f"naming {tagged}")
        else:
            ok(f"tag {ref} matches the packaged version")

    if ref:
        try:
            resolved = subprocess.run(("git", "rev-list", "-n", "1", ref),
                                      capture_output=True, text=True, check=True).stdout.strip()
            if resolved != src.get("commit"):
                bad(f"tag {ref} resolves to {resolved[:12]}, statement says "
                    f"{str(src.get('commit'))[:12]}")
            else:
                ok(f"tag {ref} resolves to the stated commit")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"  [SKIP] tag {ref} not resolvable here (shallow clone or no git)")

    if offline:
        print("  [SKIP] PyPI digest comparison (--offline)")
        return failures

    try:
        pypi = fetch_pypi(name, version)
    except Exception as exc:                                  # network, 404, ...
        bad(f"could not fetch PyPI metadata for {name} {version}: {exc}")
        return failures

    published = {u["filename"]: u["digests"]["sha256"] for u in pypi.get("urls", [])}
    if not published:
        bad(f"PyPI lists no files for {name} {version}")

    for art in statement["artifacts"]:
        fn, want = art["filename"], art["sha256"]
        got = published.get(fn)
        if got is None:
            bad(f"{fn} is in the statement but not published on PyPI")
        elif got != want:
            bad(f"{fn} digest mismatch\n         statement {want}\n         PyPI      {got}")
        else:
            ok(f"{fn} matches PyPI ({want[:16]}...)")

    unlisted = set(published) - {a["filename"] for a in statement["artifacts"]}
    if unlisted:
        bad(f"PyPI publishes files the statement does not cover: {sorted(unlisted)}")

    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--provenance", type=Path, required=True)
    ap.add_argument("--offline", action="store_true",
                    help="skip the PyPI comparison; everything else still runs")
    args = ap.parse_args()

    statement = json.loads(args.provenance.read_text(encoding="utf-8"))
    print(f"Verifying {statement['package']['name']} "
          f"{statement['package']['version']} against {args.provenance}")
    failures = check(statement, args.offline)

    print()
    if failures:
        print(f"{len(failures)} check(s) failed", file=sys.stderr)
        return 1
    print("all checks passed")
    print("NOTE: digest agreement is a correspondence claim, not an identity one. "
          "For identity run:\n"
          "  gh attestation verify <artifact> --repo msaleme/red-team-blue-team-agent-fabric")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
