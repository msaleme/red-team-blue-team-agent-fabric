#!/usr/bin/env python3
"""Fail when a release-facing fact disagrees with the manifest that owns it (#369).

## Why this exists

`testing/test_code_quality.py::TestRegTestCount` pins the **main-branch** count into
`pyproject.toml`, `README.md`, `SKILL.md` and `cli.py`. `scripts/check_public_metadata.py`
pins the GitHub description. Between them, main's count is well guarded.

The **release** count is not. `main` is at 606 and v4.15.0 carries 603, and README states
the 603 twice in prose that no suite reads. The failure mode is not hypothetical and it is
not a typo: when the next release ships, `count_tests.py` moves and every main-count surface
updates with it automatically, while 603 stays exactly where it is and silently becomes a
false claim about a release. A number that only a human remembers to update is a number that
drifts, and this repository has the history to prove it (see the header of
`check_public_metadata.py` for two more instances of the same class).

So this checks the fact that had no owner, and gives the ones that do a single place to
declare their provenance.

## Two modes, and the difference is reported, never hidden

    SURFACE     Does every declared surface state the manifest's value?
                Pure text. Runs anywhere, including a shallow CI clone.

    REGENERATE  Does re-running the declared command at the declared revision still
                produce that value? Requires the tag object, so it needs a full clone.

`actions/checkout@v4` defaults to depth 1 and the test jobs in `ci.yml` do not override it,
so REGENERATE cannot run there. It would have been easy to skip it silently and let the run
go green. That is the "no failures is not the same as passing" trap: a green result would
then mean "the text agrees with itself", while reading as "the number was reproduced".

This prints which modes actually ran, and `--require-regenerate` turns an unavailable
revision into a failure for callers that can guarantee a full clone.

## Usage

    python3 scripts/verify_release_claims.py                      # surface + regenerate if possible
    python3 scripts/verify_release_claims.py --require-regenerate  # fail if a revision is unreachable
    python3 scripts/verify_release_claims.py --json                # machine-readable result

## What this does not establish

Provenance, not truth. A reproduced count proves the command yields that value at that
revision. It does not make the fact meaningful, and a test count is an inventory fact rather
than a security-efficacy claim. Reproducing a claim says nothing about the E-class or
I-level of any result the harness produces.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "docs" / "release-claims.json"

OK, BAD, SKIP = "PASS", "FAIL", "SKIP"


def _load() -> dict:
    with MANIFEST.open(encoding="utf-8") as fh:
        return json.load(fh)


def _revision_available(rev: str) -> bool:
    if rev in ("HEAD", None):
        return True
    return subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"],
        cwd=REPO_ROOT, capture_output=True, check=False,
    ).returncode == 0


def check_surfaces(claim: dict) -> list[tuple[str, str, str]]:
    """Every declared surface must state the manifest's value."""
    out = []
    for surface in claim.get("surfaces", []):
        path = REPO_ROOT / surface["path"]
        label = f"{claim['id']} surface {surface['path']}"
        if not path.is_file():
            out.append((BAD, label, f"declared surface does not exist: {surface['path']}"))
            continue
        found = re.findall(surface["pattern"], path.read_text(encoding="utf-8"))
        if not found:
            out.append((BAD, label, (
                f"pattern {surface['pattern']!r} matched nothing. Either the surface was "
                f"reworded and the manifest was not updated, or the claim was removed from "
                f"the document without being removed here.")))
        elif any(str(f) != str(claim["value"]) for f in found):
            out.append((BAD, label, (
                f"states {found!r}, manifest says {claim['value']!r}")))
        else:
            out.append((OK, label, f"states {claim['value']}"))
    return out


def tag_commit(tag: str) -> str | None:
    """The commit a tag resolves to, or None if the tag is absent here."""
    proc = subprocess.run(["git", "rev-parse", f"{tag}^{{commit}}"],
                          cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else None


def check_tag_binds_commit(claim: dict) -> tuple[str, str, str] | None:
    """A release claim must name the commit its tag resolves to.

    Reported 2026-08-30 by an independent review of the v4.17.0 tag. The
    manifest declared `release_tag: v4.17.0` alongside the commit of the *4.16.0*
    release merge. `regenerate` reproduced 608 from it and reported PASS,
    because that commit is an ancestor and carries the same count -- so the
    number was right and the provenance was false.

    The manifest's stated purpose is to bind a fact to the revision that
    produced it. Nothing asserted the two fields agreed, so they could drift
    silently for exactly as long as the value happened not to change.
    """
    tag = claim.get("release_tag")
    if not tag:
        return None
    label = f"{claim['id']} tag binds commit"
    resolved = tag_commit(tag)
    if resolved is None:
        return (SKIP, label, f"tag {tag} is not present in this clone")
    declared = claim.get("commit")
    if not declared:
        return (OK, label, f"{tag} resolves to {resolved[:12]}; no commit pinned, derived")
    if declared != resolved:
        return (BAD, label, (
            f"{tag} resolves to {resolved[:12]} but the manifest declares "
            f"{declared[:12]}. The value may still reproduce -- an ancestor with "
            f"the same count will -- and the provenance is still false."))
    return (OK, label, f"{tag} -> {resolved[:12]}, as declared")


def regenerate(claim: dict) -> tuple[str, str, str]:
    """Re-run the declared command at the declared revision and compare."""
    rev = claim.get("commit") or (claim.get("release_tag") and
                                  tag_commit(claim["release_tag"])) or "HEAD"
    label = f"{claim['id']} regenerate @ {claim.get('release_tag') or rev[:12]}"

    if not _revision_available(rev):
        return (SKIP, label, (
            f"revision {rev[:12]} is not present in this clone (shallow checkout?). "
            f"The value was NOT reproduced. Run in a full clone, or pass "
            f"--require-regenerate to make this a failure."))

    cmd = claim["command"].split()
    try:
        if rev == "HEAD":
            proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True,
                                  text=True, timeout=300, check=False)
        else:
            # A worktree so the checked-out tree is never disturbed. Running the
            # command against a temporary checkout is the point: reading the value
            # out of the current tree would reproduce nothing.
            with tempfile.TemporaryDirectory() as td:
                wt = Path(td) / "rev"
                add = subprocess.run(
                    ["git", "worktree", "add", "--detach", str(wt), rev],
                    cwd=REPO_ROOT, capture_output=True, text=True, check=False)
                if add.returncode != 0:
                    return (SKIP, label, f"could not create worktree: {add.stderr.strip()[:160]}")
                try:
                    proc = subprocess.run(cmd, cwd=wt, capture_output=True, text=True,
                                          timeout=300, check=False)
                finally:
                    subprocess.run(["git", "worktree", "remove", "--force", str(wt)],
                                   cwd=REPO_ROOT, capture_output=True, check=False)
    except subprocess.TimeoutExpired:
        return (BAD, label, f"command timed out: {claim['command']}")

    if proc.returncode != 0:
        return (BAD, label, f"command failed rc={proc.returncode}: {proc.stderr.strip()[:160]}")

    m = re.search(claim["value_extraction"], proc.stdout)
    if not m:
        return (BAD, label, (
            f"value_extraction {claim['value_extraction']!r} matched nothing in the output of "
            f"{claim['command']!r}. The command may have changed its output format."))
    got = m.group(1)
    if got != str(claim["value"]):
        return (BAD, label, (
            f"reproduced {got!r}, manifest says {claim['value']!r}. Either the manifest is "
            f"stale or the revision does not carry the value claimed for it."))
    return (OK, label, f"reproduced {got}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--require-regenerate", action="store_true",
                    help="treat an unreachable revision as a failure (full clones only)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = ap.parse_args()

    manifest = _load()
    rows: list[tuple[str, str, str]] = []
    for claim in manifest["claims"]:
        rows.extend(check_surfaces(claim))
        _bind = check_tag_binds_commit(claim)
        if _bind is not None:
            rows.append(_bind)
        rows.append(regenerate(claim))

    failed = [r for r in rows if r[0] == BAD]
    skipped = [r for r in rows if r[0] == SKIP]

    if args.json:
        print(json.dumps({
            "manifest_version": manifest["manifest_version"],
            "results": [{"status": s, "check": c, "detail": d} for s, c, d in rows],
            "failed": len(failed), "skipped": len(skipped),
        }, indent=2))
    else:
        for status, check, detail in rows:
            print(f"  [{status}] {check}: {detail}")
        print()
        print(f"{len(rows) - len(failed) - len(skipped)} passed, "
              f"{len(failed)} failed, {len(skipped)} not reproduced")
        if skipped and not args.require_regenerate:
            print("NOTE: a SKIP means the value was not reproduced, only that its surfaces "
                  "agree with the manifest. Do not read this run as having verified it.")

    if failed:
        return 1
    if skipped and args.require_regenerate:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
