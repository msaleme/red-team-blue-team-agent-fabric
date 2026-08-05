#!/usr/bin/env python3
"""Generate HARNESS_TEST_CATALOG.md from protocol_tests/ source.

The catalog is the citation authority for public claims about this project.
Before this script existed it was maintained by hand: the last extraction was
2026-04-19 and it had drifted badly behind the repository it authorises claims
about (see issue #339). A stale citation authority cannot confirm that a test
exists, and cannot support a claim that one does not.

Extraction constants are imported from scripts/count_tests.py rather than
redefined here, so catalog membership and the canonical count are derived from
one set of patterns and cannot disagree.

Usage:
    python scripts/generate_test_catalog.py                 # write the catalog
    python scripts/generate_test_catalog.py --check         # verify, exit 1 on drift
    python scripts/generate_test_catalog.py --out PATH      # write elsewhere
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from count_tests import (  # noqa: E402
    ARG_ID_RE,
    EXCLUDE_IDS,
    HARNESS_DIR,
    MODULE_NAMES,
    TEST_ID_RE,
    _ERR_SUFFIX,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "HARNESS_TEST_CATALOG.md"
CORPUS_FILE = REPO_ROOT / "benchmarks" / "decision_behavior_corpus.py"

# name= appearing in the same constructor call as test_id=
_ID_THEN_NAME = re.compile(
    r'test_id\s*=\s*["\']([^"\']+)["\'][^)]*?name\s*=\s*["\']([^"\']+)["\']',
    re.S,
)
# name= appearing before test_id= in the same call
_NAME_THEN_ID = re.compile(
    r'name\s*=\s*["\']([^"\']+)["\'][^)]*?test_id\s*=\s*["\']([^"\']+)["\']',
    re.S,
)
# Docstring form:  """SS-002: Permission Declaration Validation (HIGH, category: x)
_DOCSTRING = re.compile(
    r'"""\s*([A-Z][A-Z0-9]*(?:-[A-Z0-9]+[a-z]?)+)\s*:\s*([^\n(]+?)\s*(?:\(|\n|""")'
)

# Decision Behavior Benchmark corpus entries. These are scenario definitions, NOT
# executable protocol tests, and are counted separately so the count_tests.py
# figure is never inflated by them. Entries are chunked on the id= boundary
# rather than matched with one regex, because each entry body contains
# parenthesised strings that a [^)]* scan cannot cross.
_CORPUS_ID = re.compile(r'id\s*=\s*["\'](DBC-[0-9]+[a-z]?)["\']')
_FIELD = {
    "name": re.compile(r'\bname\s*=\s*["\']([^"\']+)["\']'),
    "executable_test": re.compile(r'\bexecutable_test\s*=\s*["\']([^"\']*)["\']'),
}


def collect_corpus() -> list[tuple[str, str, str, int]]:
    """Return [(dbc_id, name, executable_test, line)] from the benchmark corpus."""
    if not CORPUS_FILE.exists():
        return []
    text = CORPUS_FILE.read_text(encoding="utf-8")
    marks = [(m.group(1), m.start()) for m in _CORPUS_ID.finditer(text)]
    out = []
    for i, (tid, pos) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(text)
        chunk = text[pos:end]
        name = _FIELD["name"].search(chunk)
        ex = _FIELD["executable_test"].search(chunk)
        line = text.count("\n", 0, pos) + 1
        out.append((tid, name.group(1) if name else "", ex.group(1) if ex else "", line))
    return out


HEADER = """# Agent Security Harness — Canonical Test Catalog

**Source repo:** msaleme/red-team-blue-team-agent-fabric
**Generated:** `scripts/generate_test_catalog.py` at commit `{commit}`
**Test count:** {total} unique test IDs across {modules} registered harness modules ({bearing} contain test IDs; `community_runner.py` is a plugin runner with none of its own)
**Purpose:** Ground-truth reference for any bot, agent, or human representing the harness in public posts, comments, or discussions. Cite only tests listed here. Do not invent IDs or statistics.

## Rules for Citation
1. Test IDs must match verbatim.
2. Do not attribute a finding to a test unless the test's description above actually covers that finding.
3. Numeric statistics (e.g. "X tool calls") must appear in the repo or published reports. If not present, do not cite them.
4. When in doubt, say "we have tests in this area" and skip specifics.
5. **Absence from this catalog is evidence only if the catalog is current.** Check the commit above against `main` before claiming that no test covers something. This file is generated; regenerate it rather than editing it by hand.

## Tests
"""


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0


def collect(path: Path) -> tuple[dict[str, tuple[str, int]], set[str]]:
    """Return {test_id: (name, line)} plus IDs found with no resolvable name."""
    text = path.read_text(encoding="utf-8")

    ids = set(TEST_ID_RE.findall(text)) | set(ARG_ID_RE.findall(text))
    ids -= EXCLUDE_IDS
    ids = {i for i in ids if not i.endswith(_ERR_SUFFIX)}

    names: dict[str, str] = {}
    for tid, name in _ID_THEN_NAME.findall(text):
        names.setdefault(tid, name)
    for name, tid in _NAME_THEN_ID.findall(text):
        names.setdefault(tid, name)
    for tid, title in _DOCSTRING.findall(text):
        names.setdefault(tid, title.strip())

    resolved: dict[str, tuple[str, int]] = {}
    unnamed: set[str] = set()
    for tid in ids:
        line = _line_of(text, f'"{tid}"') or _line_of(text, f"'{tid}'")
        if tid in names:
            resolved[tid] = (names[tid], line)
        else:
            # Never invent a description. Record the ID with no name and report it.
            resolved[tid] = ("", line)
            unnamed.add(tid)
    return resolved, unnamed


def build() -> tuple[str, int, set[str]]:
    per_module: dict[str, dict[str, tuple[str, int]]] = {}
    unnamed_all: set[str] = set()

    for pyfile in sorted(HARNESS_DIR.glob("*.py")):
        if pyfile.name.startswith("__"):
            continue
        resolved, unnamed = collect(pyfile)
        if resolved:
            per_module[pyfile.name] = resolved
            unnamed_all |= unnamed

    total = len({t for m in per_module.values() for t in m})

    # Canonical module count is the harness registry in cli.py, which is what
    # README and the rest of the repo cite. It is 44; one of them
    # (community_runner.py) is a plugin runner and contributes no test IDs of
    # its own, so the per-module sections below number one fewer.
    try:
        sys.path.insert(0, str(REPO_ROOT))
        from protocol_tests.cli import HARNESSES
        modules = len(HARNESSES)
    except Exception:
        modules = len(per_module)
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        commit = "unknown"

    out = [HEADER.format(commit=commit, total=total, modules=modules,
                         bearing=len(per_module))]

    for fname in sorted(per_module):
        label = MODULE_NAMES.get(fname, fname)
        entries = per_module[fname]
        out.append(f"\n### {label} (`protocol_tests/{fname}`) — {len(entries)} tests\n")
        out.append("```")
        for tid in sorted(entries):
            name, line = entries[tid]
            desc = f" | {name}" if name else " | (no description in source)"
            out.append(f"{tid}{desc} | protocol_tests/{fname}:{line}")
        out.append("```")

    if unnamed_all:
        out.append("\n## Test IDs with no description in source\n")
        out.append(
            "These exist and may be cited by ID, but this file carries no description "
            "for them, so rule 2 cannot be satisfied from the catalog alone. Read the "
            "source before attributing a finding to one.\n"
        )
        out.append("```")
        out.extend(sorted(unnamed_all))
        out.append("```")

    corpus = collect_corpus()
    if corpus:
        out.append(f"\n## Decision Behavior Benchmark corpus (`benchmarks/decision_behavior_corpus.py`) — {len(corpus)} scenarios\n")
        out.append(
            "These are **scenario definitions, not executable protocol tests**, and are "
            "excluded from the test count above. Each names the executable test that "
            "exercises it, where one exists. Cite a DBC ID as a scenario; cite its "
            "`executable_test` when claiming something was run.\n"
        )
        out.append("```")
        for tid, name, ex, line in corpus:
            tail = f" | exercised by {ex}" if ex else " | no executable test"
            out.append(f"{tid} | {name}{tail} | benchmarks/decision_behavior_corpus.py:{line}")
        out.append("```")

    return "\n".join(out) + "\n", total, unnamed_all


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify the catalog on disk matches source; exit 1 on drift")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    content, total, unnamed = build()

    if args.check:
        if not args.out.exists():
            print(f"FAIL: {args.out} does not exist", file=sys.stderr)
            return 1
        current = args.out.read_text(encoding="utf-8")
        # Compare test lines only; the commit stamp legitimately changes every commit.
        def ids_in(t: str) -> set[str]:
            return set(re.findall(r"^([A-Z][A-Z0-9]*(?:-[A-Z0-9]+[a-z]?)+) \|", t, re.M))
        have, want = ids_in(current), ids_in(content)
        if have != want:
            missing, extra = sorted(want - have), sorted(have - want)
            print(f"FAIL: catalog drift. {len(missing)} missing, {len(extra)} stale.",
                  file=sys.stderr)
            if missing:
                print(f"  missing: {', '.join(missing[:15])}"
                      f"{' ...' if len(missing) > 15 else ''}", file=sys.stderr)
            if extra:
                print(f"  stale:   {', '.join(extra[:15])}"
                      f"{' ...' if len(extra) > 15 else ''}", file=sys.stderr)
            print("  run: python scripts/generate_test_catalog.py", file=sys.stderr)
            return 1
        print(f"PASS: catalog matches source ({total} test IDs).")
        return 0

    args.out.write_text(content, encoding="utf-8")
    print(f"wrote {args.out}  ({total} test IDs)")
    if unnamed:
        print(f"  note: {len(unnamed)} ID(s) have no description in source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
