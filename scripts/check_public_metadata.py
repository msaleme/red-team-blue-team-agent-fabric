#!/usr/bin/env python3
"""Fail when the repository's public GitHub metadata disagrees with the code.

## Why this exists

`testing/test_code_quality.py::TestRegTestCount` already pins the test count in
every file inside the repository: `pyproject.toml`, `README.md`, `SKILL.md`,
`cli.py`. All of those are checked because all of those are *in the tree*.

The GitHub repository **description** is not in the tree, so nothing checked it,
and it drifted twice:

    2026-08-02  description advertised an older test count and version
    2026-08-08  description still carried the version string of a release two
                behind the published one. Its test count was correct for that
                release, which is why count and version are checked separately

That field is not decoration. It is the text GitHub repository search matches.
The only outside reproduction this project has received arrived through

    agent security benchmark in:name,description stars:>20 pushed:>2026-06-01

so a stale description is a discovery defect, not a cosmetic one. Repairing it by
hand is what produced the second drift; this is the check instead.

## What it compares

The description is a claim about a *published release*, not about `main`, because
that is what a visitor installs. So the workflow checks out the latest release tag
and runs this against that tree. Comparing a release-facing string to `main` would
fail every time `main` is legitimately ahead.

    count    scripts/count_tests.py at the checked-out ref
    version  pyproject.toml at the checked-out ref, via protocol_tests.version

## Exit codes

    0  description agrees with the tree
    1  disagreement, with the exact fields printed
    2  UNREACHABLE: could not read the description

2 is deliberately distinct from 0. A check that cannot reach its source has not
passed, and reporting "no disagreement found" when nothing was read is the exact
defect class this repository keeps finding (see #348).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO = "msaleme/red-team-blue-team-agent-fabric"


def canonical_count() -> str:
    out = subprocess.check_output(
        [sys.executable, str(REPO_ROOT / "scripts" / "count_tests.py")],
        text=True, cwd=REPO_ROOT)
    m = re.search(r"Definitive count:\s*(\d+)", out)
    if not m:
        raise SystemExit("count_tests.py produced no definitive count")
    return m.group(1)


def canonical_version() -> str:
    sys.path.insert(0, str(REPO_ROOT))
    from protocol_tests.version import get_harness_version
    return get_harness_version()


def fetch_description(repo: str) -> str:
    url = f"https://api.github.com/repos/{repo}"
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "agent-security-harness-metadata-check"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r).get("description") or ""


def extract(description: str) -> tuple[str | None, str | None]:
    """Pull the test count and version out of the description.

    Returns (count, version), either of which may be None when the description
    does not state it. A missing field is a failure, not a pass: the description
    is expected to carry both.
    """
    c = re.search(r"(\d{3,4})\s+executable tests", description)
    v = re.search(r"\bv(\d+\.\d+\.\d+)\b", description)
    return (c.group(1) if c else None, v.group(1) if v else None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=os.environ.get("METADATA_REPO", DEFAULT_REPO))
    ap.add_argument("--print-expected", action="store_true",
                    help="print the description fields the tree implies, then exit 0")
    args = ap.parse_args()

    want_count = canonical_count()
    want_version = canonical_version()

    if args.print_expected:
        print(f"count={want_count} version=v{want_version}")
        return 0

    try:
        description = fetch_description(args.repo)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"UNREACHABLE: could not read the description for {args.repo}: "
              f"{type(e).__name__}: {e}")
        print("This is not a pass. Re-run when the API is reachable.")
        return 2

    got_count, got_version = extract(description)

    problems = []
    if got_count is None:
        problems.append("description states no test count "
                        "(expected '<N> executable tests')")
    elif got_count != want_count:
        problems.append(f"test count: description says {got_count}, "
                        f"tree says {want_count}")
    if got_version is None:
        problems.append("description states no version (expected 'vX.Y.Z')")
    elif got_version != want_version:
        problems.append(f"version: description says v{got_version}, "
                        f"tree says v{want_version}")

    if not problems:
        print(f"OK  {args.repo} description matches the tree "
              f"({want_count} tests, v{want_version})")
        return 0

    print(f"DRIFT in the GitHub description for {args.repo}\n")
    for p in problems:
        print(f"  - {p}")
    print(f"\ncurrent : {description}")
    print(f"\nThe description is the text repository search matches, so this is a")
    print(f"discovery defect. Fix it at Settings -> About, or:")
    print(f"\n  gh repo edit {args.repo} --description '<corrected text>'")
    return 1


if __name__ == "__main__":
    sys.exit(main())
