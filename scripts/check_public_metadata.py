#!/usr/bin/env python3
"""Fail when the repository's public GitHub metadata disagrees with the code.

## Why this exists

`testing/test_code_quality.py::TestRegTestCount` already pins the test count in
every file inside the repository: `pyproject.toml`, `README.md`, `SKILL.md`,
`cli.py`. All of those are checked because all of those are *in the tree*.

Public surfaces outside the tree are not checked by that suite, and they drift.
The repository **description** drifted twice:

    2026-08-02  description advertised an older test count and version
    2026-08-08  description still carried the version string of a release two
                behind the published one. Its test count was correct for that
                release, which is why count and version are checked separately

That field is not decoration. It is the text GitHub repository search matches.
The only outside reproduction this project has received arrived through

    agent security benchmark in:name,description stars:>20 pushed:>2026-06-01

so a stale description is a discovery defect, not a cosmetic one. Repairing it by
hand is what produced the second drift; this is the check instead.

The same class was live on three further surfaces on 2026-08-08, none of which
any suite covered:

    msaleme/msaleme     understated the count by 134 and the module count by 15
    msaleme/start-here  six releases behind, including a copyable Action pin
    CITATION.cff        date-released was 13 days off the actual release

(Figures are described rather than quoted here: a literal count in a live file
is what test_no_stale_test_count_anywhere exists to catch, and it caught this
docstring first.)

CITATION.cff is the file GitHub reads for "Cite this repository", and
test_code_quality.py already records it as a file that went stale on counts
while CI passed. It was fixed for counts and went stale on the release date
instead, which is why the date is checked and not only the numbers.

## Release sequencing, and --apply

The workflow also runs on `release: published`. That run compares the description
against the tree at the tag that was just published, and it fails whenever the
description is edited AFTER the release is created, because at that instant the
description still names the previous version. It failed that way on four
consecutive releases (v4.18.0, v4.19.0rc1, v4.19.0, v4.20.0), each time correctly,
and each time the description was fixed by hand a few minutes later. A red run
that is always right and always stale is a process defect, not a checker defect.

The Actions token cannot edit the description (that needs repository
administration), so the edit has to happen on the releasing side, BEFORE
`gh release create`:

    python3 scripts/check_public_metadata.py --apply

`--apply` reads the live description, rewrites every release-facing figure to
what the tree at HEAD implies (`rewrite_description`, pure and tested offline),
PATCHes it with the caller's token, then runs the normal comparison so the
output ends in OK or DRIFT rather than in "applied". It refuses to write a
description the checker itself would still reject.

## What it compares

The description is a claim about a *published release*, not about `main`, because
that is what a visitor installs. So the workflow checks out the latest release tag
and runs this against that tree. Comparing a release-facing string to `main` would
fail every time `main` is legitimately ahead.

    count    scripts/count_tests.py at the checked-out ref
    modules  len(protocol_tests.cli.HARNESSES) at the checked-out ref
    version  pyproject.toml at the checked-out ref, via protocol_tests.version
    date     the release date of the checked-out tag, from the GitHub API

Every remote surface is read over the public API, so this needs no credentials
beyond the default Actions token.

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

# Public surfaces that restate figures owned by this repository. Each entry is
# (label, repo, what to check). They are READMEs read over the public API, so no
# credentials beyond the default Actions token are needed.
#
# The rule for adding one: if a page states a number that lives authoritatively
# in this tree, it belongs here. If a page can state it without a number, prefer
# removing the restatement (see #359).
REMOTE_READMES = (
    ("profile README", "msaleme/msaleme"),
    ("start-here", "msaleme/start-here"),
)


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


def canonical_modules() -> str:
    """Test-bearing module count, from count_tests.py.

    This returned len(HARNESSES) until 2026-08-09, which is the REGISTERED
    count (44) rather than the test-bearing one (43). The difference is
    community_runner.py, which hosts community-contributed tests and ships none
    of its own. That error propagated to the profile README and start-here
    before it was caught, so this now reads the declared source of truth.
    """
    out = subprocess.check_output(
        [sys.executable, str(REPO_ROOT / "scripts" / "count_tests.py")],
        text=True, cwd=REPO_ROOT)
    rows = [ln for ln in out.splitlines()
            if re.match(r"^\s+\S.*\s+\d+\s*$", ln)
            and not re.search(r"TOTAL|SUM OF|Definitive", ln)]
    return str(len(rows))


def fetch_readme(repo: str) -> str:
    return _api(f"https://api.github.com/repos/{repo}/readme",
                accept="application/vnd.github.raw")


def fetch_release_date(repo: str, tag: str) -> str:
    """Published date of a tag, YYYY-MM-DD, from the GitHub API."""
    data = json.loads(_api(f"https://api.github.com/repos/{repo}/releases/tags/{tag}"))
    return (data.get("published_at") or "")[:10]


def citation_fields(repo: str | None = None) -> tuple[str | None, str | None]:
    """(version, date_released) from CITATION.cff on the DEFAULT BRANCH.

    Deliberately not read from the checked-out tree. The workflow checks out the
    latest release tag, and a tag is immutable: a date-released that was wrong
    when the tag was cut can never be corrected there, so checking the tag's copy
    would fail permanently no matter what anyone does. A permanent failure is a
    muted check.

    The fixable copy is the one on the default branch, so that is the one checked.
    Falls back to the local tree when no repo is given, which keeps the tests
    offline.
    """
    if repo is None:
        path = REPO_ROOT / "CITATION.cff"
        if not path.is_file():
            return (None, None)
        text = path.read_text(encoding="utf-8")
    else:
        try:
            text = _api(f"https://api.github.com/repos/{repo}/contents/CITATION.cff",
                        accept="application/vnd.github.raw")
        except Exception:                          # noqa: BLE001
            return (None, None)
    v = re.search(r'^version:\s*"?([^"\s]+)"?', text, re.MULTILINE)
    d = re.search(r'^date-released:\s*"?(\d{4}-\d{2}-\d{2})"?', text, re.MULTILINE)
    return (v.group(1) if v else None, d.group(1) if d else None)


def _api(url: str, accept: str = "application/vnd.github+json") -> str:
    headers = {"Accept": accept,
               "User-Agent": "agent-security-harness-metadata-check"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")


def fetch_description(repo: str) -> str:
    return json.loads(_api(f"https://api.github.com/repos/{repo}")).get("description") or ""


def _patch_description(repo: str, description: str) -> None:
    """PATCH the repository description. Needs a token with admin rights."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise PermissionError("GITHUB_TOKEN or GH_TOKEN is required to edit the description")
    body = json.dumps({"description": description}).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}", data=body, method="PATCH",
        headers={"Accept": "application/vnd.github+json",
                 "Content-Type": "application/json",
                 "Authorization": f"Bearer {token}",
                 "User-Agent": "agent-security-harness-metadata-check"})
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


# Strings that identify a line as being about THIS project. Used to scope the
# version check, because every package has a version and these pages legitimately
# mention other packages' versions.
HARNESS_TOKENS = ("red-team-blue-team-agent-fabric", "agent-security-harness")

# Figures a public page can restate: (label, regex, canonical key, line_scoped).
# A page is only checked for a figure it actually states; silence is allowed.
#
# line_scoped=True restricts matching to lines naming this project. Versions need
# it: the first run of this check flagged `v0.7.0` on start-here, which is
# constitutional-agent on PyPI and entirely correct. A check that fails on a true
# statement gets muted, so the scope is narrowed instead.
#
# Versions are also satisfied by PRESENCE rather than by exclusivity: a harness
# line passes if it names the current version anywhere on it. This exists because
# the first version of this check flagged
#
#     ...(v4.15.0) - 97.9% pass rate measured at v4.4.2...
#
# which is correct and deliberate. Pinning a historical measurement to the version
# it was measured at is exactly the honesty this check is supposed to protect, and
# a check that punishes it would be worse than no check.
#
# Counts are not line-scoped, because on these pages "N tests" and "N modules"
# refer to this project. If another project's test count is ever added to one of
# these READMEs, that assumption breaks and this needs the same treatment.
SURFACE_PATTERNS = (
    ("test count", re.compile(r"(\d{3,4})\s+(?:executable\s+)?(?:security\s+)?tests?\b"), "count", False),
    ("module count", re.compile(r"(\d{2,3})\s+modules?\b"), "modules", False),
    ("version", re.compile(r"\bv(\d+\.\d+\.\d+)\b"), "version", True),
)


def check_surface(label: str, text: str, want: dict[str, str]) -> list[str]:
    """Every figure the text states about this project must match the tree."""
    problems = []
    harness_lines = "\n".join(
        ln for ln in text.splitlines()
        if any(tok in ln for tok in HARNESS_TOKENS))
    for figure, pattern, key, line_scoped in SURFACE_PATTERNS:
        if line_scoped:
            # Presence, not exclusivity: each line naming this project must state
            # the current version somewhere on it. Other versions alongside it are
            # allowed, because citing the version a measurement came from is right.
            for line in harness_lines.splitlines():
                found = {m.group(1) for m in pattern.finditer(line)}
                if found and want[key] not in found:
                    problems.append(
                        f"{label}: {figure} says {', '.join(sorted(found))} "
                        f"with no mention of {want[key]}, tree says {want[key]}")
            continue
        found = {m.group(1) for m in pattern.finditer(text)}
        wrong = sorted(f for f in found if f != want[key])
        if wrong:
            problems.append(f"{label}: {figure} says {', '.join(wrong)}, tree says {want[key]}")
    return problems


# A description may state one test count or two. When it states two, the
# release figure is the one this check is about: the workflow compares against
# the tree at the latest release tag, so the main-branch figure is a claim about
# something else entirely. The description grew to this shape:
#
#     "<main count> executable tests on main, <release count> in the vX.Y.Z release"
#
# re.search returns the FIRST match, so a bare "<N> executable tests" pattern
# read the MAIN count and compared it against the release tree, which of course
# holds the release count. The description was correct and the check was wrong,
# and it failed that way on two consecutive scheduled runs (2026-08-17 and
# 2026-08-24) before anyone looked at it.
#
# (Figures are described rather than quoted here, for the same reason the module
# docstring gives: a literal count in a live file is what
# test_no_stale_test_count_anywhere exists to catch, and quoting the main count
# in a comment would go stale the next time main's count moves.)
#
# A check that fails on a true statement gets muted. That is the same reasoning
# that made the version check presence-scoped rather than exclusive above, and
# the fix is the same shape: narrow what the check reads instead of asking the
# honest text to get worse. Naming both counts is more informative than naming
# one, so the parser learns the phrasing rather than the description losing it.
RELEASE_COUNT_RE = re.compile(
    r"(\d{3,4})\s+(?:executable\s+tests\s+)?in the v\d+\.\d+\.\d+ release")

# Fallback for a description that names a single count, which is the shape this
# check was written against and still the shape of the two remote READMEs.
BARE_COUNT_RE = re.compile(r"(\d{3,4})\s+executable tests")


def extract(description: str) -> tuple[str | None, str | None]:
    """Pull the release-facing test count and version out of the description.

    Returns (count, version), either of which may be None when the description
    does not state it. A missing field is a failure, not a pass: the description
    is expected to carry both.

    When the description names both a main-branch and a release count, this
    returns the RELEASE one, because the release tree is what it is compared
    against. See RELEASE_COUNT_RE above.
    """
    c = RELEASE_COUNT_RE.search(description) or BARE_COUNT_RE.search(description)
    v = re.search(r"\bv(\d+\.\d+\.\d+)\b", description)
    return (c.group(1) if c else None, v.group(1) if v else None)


def _swap_group1(m: re.Match[str], value: str) -> str:
    """The whole match with group 1 replaced, everything else untouched."""
    start, end = m.start(1) - m.start(0), m.end(1) - m.start(0)
    whole = m.group(0)
    return whole[:start] + value + whole[end:]


def rewrite_description(description: str, want: dict[str, str]) -> str:
    """Return the description with every release-facing figure set to the tree's.

    Pure: no network, no side effects, safe to unit-test. Three rewrites:

      1. the release phrase, "<N> [executable tests] in the vX.Y.Z release",
         gets the tree's count AND version;
      2. any bare "<N> executable tests" gets the tree's count. This runs at
         release time, when main and the tag are the same tree, so a main
         figure and a release figure are legitimately equal;
      3. every "vX.Y.Z" token becomes the tree's version. extract() reads the
         FIRST version token, so leaving any stale one is leaving the check
         red. Historical "measured at vA.B.C" pins belong on the READMEs
         (see check_surface), not in the one-line description.
    """
    count, version = want["count"], want["version"]
    text = RELEASE_COUNT_RE.sub(lambda m: _swap_group1(m, count), description)
    text = BARE_COUNT_RE.sub(lambda m: _swap_group1(m, count), text)
    text = re.sub(r"\bv\d+\.\d+\.\d+\b", f"v{version}", text)
    return text


def apply_description(repo: str, want: dict[str, str]) -> int:
    """Rewrite the live description to match the tree, or explain why not.

    Exit codes follow main(): 0 written (or already matching), 1 the rewrite
    would still fail the check so nothing was written, 2 unreachable or no
    token. A write that the checker would reject is not applied; that is the
    positive control on the rewrite itself.
    """
    try:
        current = fetch_description(repo)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"UNREACHABLE: could not read the description for {repo}: "
              f"{type(e).__name__}: {e}")
        return 2
    proposed = rewrite_description(current, want)
    if extract(proposed) != (want["count"], want["version"]):
        print("REFUSED: the rewritten description would still fail this check, "
              "so it was not written.")
        print(f"\ncurrent  : {current}\nproposed : {proposed}")
        return 1
    if proposed == current:
        print("description already matches the tree; nothing written")
        return 0
    try:
        _patch_description(repo, proposed)
    except PermissionError as e:
        print(f"UNREACHABLE: {e}")
        return 2
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"UNREACHABLE: could not write the description for {repo}: "
              f"{type(e).__name__}: {e}")
        return 2
    print(f"applied  : {repo} description updated\nbefore   : {current}\nafter    : {proposed}\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=os.environ.get("METADATA_REPO", DEFAULT_REPO))
    ap.add_argument("--print-expected", action="store_true",
                    help="print the description fields the tree implies, then exit 0")
    ap.add_argument("--apply", action="store_true",
                    help="rewrite the live description to the tree's figures, then check")
    args = ap.parse_args()

    want = {"count": canonical_count(),
            "version": canonical_version(),
            "modules": canonical_modules()}

    if args.print_expected:
        print(f"count={want['count']} modules={want['modules']} version=v{want['version']}")
        return 0

    want_count, want_version = want["count"], want["version"]

    if args.apply:
        rc = apply_description(args.repo, want)
        if rc:
            return rc

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

    # CITATION.cff is local, so it is checked even when the network is down.
    cff_version, cff_date = citation_fields(args.repo)
    if cff_version is not None and cff_version != want_version:
        problems.append(f"CITATION.cff: version says {cff_version}, tree says {want_version}")

    unreachable = []
    try:
        released = fetch_release_date(args.repo, f"v{want_version}")
        if cff_date is not None and released and cff_date != released:
            problems.append(f"CITATION.cff: date-released says {cff_date}, "
                            f"v{want_version} was published {released}")
    except Exception as e:                        # noqa: BLE001
        unreachable.append(f"release date for v{want_version} ({type(e).__name__})")

    for label, repo in REMOTE_READMES:
        try:
            problems.extend(check_surface(label, fetch_readme(repo), want))
        except Exception as e:                    # noqa: BLE001
            unreachable.append(f"{label} at {repo} ({type(e).__name__})")

    if unreachable:
        print("UNREACHABLE: " + "; ".join(unreachable))
        print("This is not a pass. Those surfaces were not checked.")
        if not problems:
            return 2

    if not problems:
        print(f"OK  {args.repo} description, CITATION.cff and "
              f"{len(REMOTE_READMES)} remote READMEs match the tree "
              f"({want_count} tests, {want['modules']} modules, v{want_version})")
        return 0

    print(f"DRIFT in public metadata for {args.repo}\n")
    for p in problems:
        print(f"  - {p}")
    print(f"\ncurrent : {description}")
    print("\nThe description is the text repository search matches, so this is a")
    print("discovery defect. Fix it at Settings -> About, or:")
    print(f"\n  gh repo edit {args.repo} --description '<corrected text>'")
    return 1


if __name__ == "__main__":
    sys.exit(main())
