#!/usr/bin/env python3
"""Emit a provenance statement binding built artifacts to the commit that made them.

Why this exists. Two independent reviews of v4.17.0 reached the same finding by
different routes: the release is *content*-strong and *identity*-weak. A reviewer
rebuilt from the exact tag and compared every file inside both wheels -- 95 of 95
identical -- which establishes that the published payload corresponds to the
tagged source. It establishes nothing about who built it, on what, or in which
environment. The tag is annotated and unsigned, and the GitHub Release carried no
assets at all, so there was nothing release-attached to check.

What this closes and what it does not. This statement is a machine-readable
binding of artifact digests to a commit, a tag, a workflow run, and a build
environment. On its own it is a text file and proves nothing -- anyone can write
one. It becomes evidence when the release workflow also attests it through
Sigstore (`actions/attest-build-provenance`), which signs the artifact digests
against the workflow identity that produced them. The statement is the thing an
attestation is *about*; keep the two claims separate and do not describe an
unattested statement as provenance.

Usage:
    python scripts/build_provenance.py --dist dist/ --out provenance.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from pathlib import Path

# `git()`, `ci_identity()` and `tool_versions()` used to be defined here. They
# now live in `protocol_tests/run_provenance.py`, which needs the same three
# answers for a RUN statement. Two implementations of "what commit is this"
# that can disagree is not a thing a provenance feature may contain, so this
# script imports the one. They are re-exported by name because
# `testing/test_release_provenance.py` reaches for `build_provenance.git` and
# `build_provenance.tool_versions` directly.
#
# The path insert is load-bearing: this file is invoked as
# `python scripts/build_provenance.py` from `publish-pypi.yml`, so sys.path[0]
# is `scripts/` and the repository root is not on the path at all.
_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from protocol_tests.run_provenance import (  # noqa: E402
    ci_identity,
    git,
    tool_versions,
)

SCHEMA = "agent-security-harness/release-provenance/v1"

__all__ = ["SCHEMA", "build", "ci_identity", "git", "main", "sha256_file",
           "tool_versions"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build(dist: Path, source_date: str | None = None) -> dict:
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if not wheels or not sdists:
        raise SystemExit(
            f"expected at least one wheel and one sdist in {dist}, "
            f"found {len(wheels)} wheel(s) and {len(sdists)} sdist(s)")

    artifacts = [
        {"filename": p.name, "kind": kind, "size_bytes": p.stat().st_size,
         "sha256": sha256_file(p)}
        for kind, group in (("wheel", wheels), ("sdist", sdists))
        for p in group
    ]

    # Version comes from the artifact filenames rather than an import, so the
    # statement describes what was BUILT and not what happens to be importable
    # in the process writing it.
    version = wheels[0].name.split("-")[1]

    return {
        "schema": SCHEMA,
        "package": {"name": "agent-security-harness", "version": version},
        "artifacts": artifacts,
        "source": {
            "commit": os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD"),
            "ref_name": os.environ.get("GITHUB_REF_NAME") or git("describe", "--tags", "--exact-match"),
            # `--untracked-files=no` is load-bearing, and v4.18.0rc1 is why.
            #
            # This asked `git status --porcelain`, which reports untracked files.
            # By the time this script runs, `python -m build` has already created
            # `dist/`, `*.egg-info/` and `build/`, and the workflow has written
            # `build-environment.txt`. So every CI build looked dirty, and the
            # verifier correctly refused a statement that was correctly produced.
            # The rehearsal failed at the step it was cut to exercise.
            #
            # The question this field exists to answer is whether the SOURCE
            # differs from the commit being claimed. Build output is not source,
            # and a release build always has some.
            "tree_is_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        },
        "build_environment": {
            "python": sys.version.split()[0],
            "python_full": sys.version.replace("\n", " "),
            "platform": platform.platform(),
            "tools": tool_versions(),
        },
        "ci": ci_identity(),
        "generated_at": source_date or os.environ.get("SOURCE_DATE_EPOCH") or None,
        "not_claimed": [
            "This statement is not itself signed. Signing is done separately by "
            "the release workflow through Sigstore, over the artifact digests.",
            "Matching digests establish that a published artifact corresponds to "
            "this build. They do not establish that the source was reviewed, that "
            "the tests are adequate, or anything about the security of a target.",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dist", type=Path, default=Path("dist"))
    ap.add_argument("--out", type=Path, default=Path("provenance.json"))
    args = ap.parse_args()

    statement = build(args.dist)
    args.out.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(f"wrote {args.out}")
    for a in statement["artifacts"]:
        print(f"  {a['kind']:6} {a['sha256']}  {a['filename']}")
    print(f"  commit {statement['source']['commit']}  ref {statement['source']['ref_name']}")
    if statement["source"]["tree_is_dirty"]:
        print("  WARNING: built from a dirty tree; this is not a release build",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
