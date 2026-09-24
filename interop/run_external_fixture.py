#!/usr/bin/env python3
"""Run someone else's conformance fixtures through a pinned checker; publish the raw result.

This is the generic form of the scripts beside it. It answers one question per
vector: given the outcome the fixture's author declared, what did the pinned
checker actually return? It writes that answer down with the raw checker output
and SHA-256 digests of every input and output, and adds nothing on top.

What it deliberately does not do:

  * judge the fixture. A disagreement between the fixture and the checker is
    reported as a disagreement. Which side is wrong is a question for a reader.
  * map one vocabulary onto another. Any translation from the fixture's terms
    to the checker's lives in the ADAPTER, a separate file whose digest is
    recorded in the bundle, so the mapping is inspectable rather than implied.
  * upgrade an unknown. States are ``pass`` / ``fail`` / ``inconclusive`` /
    ``error`` with the meanings in docs/EXTERNAL-FIXTURES.md. An error or an
    unanswerable comparison is never counted as a pass.

A run in which no positive (acceptance) control was accepted is labelled
NOT A RESULT, whatever the negative vectors did. A checker that rejects
everything satisfies every negative vector ever written.

Exit codes:
    0   a result; every vector passed
    1   a result; at least one vector is fail, inconclusive or error
    2   NOT A RESULT: no positive control was declared, or none was accepted
    3   aborted before running: a pin did not match, or the output dir is in use
    64  usage error

Usage (see docs/EXTERNAL-FIXTURES.md for the full procedure):

    python3 interop/run_external_fixture.py \\
        --fixtures  ../approval-binding-vectors/vectors \\
        --fixture-commit 50c64293c12d99f15de65626124006fd81aaba17 \\
        --adapter   interop/adapters/abv_reference.py \\
        --checker   ../approval-binding-vectors/check.py \\
        --checker-commit 50c64293c12d99f15de65626124006fd81aaba17 \\
        --out       /tmp/abv-run
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent

RUNNER_FORMAT = "ash-external-fixture-run/1"

PASS, FAIL, INCONCLUSIVE, ERROR = "pass", "fail", "inconclusive", "error"
STATES = (PASS, FAIL, INCONCLUSIVE, ERROR)

EXIT_ALL_PASS = 0
EXIT_NOT_ALL_PASS = 1
EXIT_NOT_A_RESULT = 2
EXIT_ABORTED = 3
EXIT_USAGE = 64

DEFAULT_ACCEPT_VERDICTS = frozenset({"accept", "allow"})


class Aborted(Exception):
    """A precondition failed. Nothing was run and no bundle is written."""


# --- small helpers ------------------------------------------------------------

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(("git", *args), cwd=cwd, capture_output=True,
                          check=False)


def git_state(path: Path) -> dict:
    """Where a file or directory sits in git, if anywhere. Never raises."""
    where = path if path.is_dir() else path.parent
    top = _git(where, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return {"repo": None, "head": None, "dirty": None}
    root = Path(top.stdout.decode().strip())
    head = _git(root, "rev-parse", "HEAD")
    status = _git(root, "status", "--porcelain", "--untracked-files=no")
    return {
        "repo": str(root),
        "head": head.stdout.decode().strip() if head.returncode == 0 else None,
        "dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
    }


def verify_pin(path: Path, commit: str) -> dict:
    """Refuse unless ``path`` is byte-identical to its copy at ``commit``.

    Byte identity with the pinned revision, not ancestry and not "HEAD equals
    the pin": an in-repo checker is usually read from a later HEAD, and what the
    pin promises is that the file under test is the one that was named.
    """
    state = git_state(path)
    if state["repo"] is None:
        raise Aborted(f"{path} is not inside a git repository, so the pin "
                      f"{commit} cannot be checked. Clone the pinned source.")
    root = Path(state["repo"])
    full = _git(root, "rev-parse", "--verify", f"{commit}^{{commit}}")
    if full.returncode != 0:
        raise Aborted(f"pinned commit {commit} does not exist in {root}. "
                      "Fetch it (git fetch --tags) before running.")
    resolved = full.stdout.decode().strip()
    rel = path.resolve().relative_to(root.resolve()).as_posix()
    blob = _git(root, "show", f"{resolved}:{rel}")
    if blob.returncode != 0:
        raise Aborted(f"{rel} does not exist at the pinned commit {resolved[:12]}")
    if blob.stdout != path.read_bytes():
        raise Aborted(
            f"{rel} differs from its copy at the pinned commit {resolved[:12]}.\n"
            f"  pinned sha256 : {hashlib.sha256(blob.stdout).hexdigest()}\n"
            f"  on disk       : {sha256_file(path)}\n"
            "Refusing to report a result for a file that is not the one pinned.")
    changed = _git(root, "diff", "--name-only", resolved, "--")
    return {
        "commit": resolved,
        "verified": "byte-identical to the pinned commit",
        # Files elsewhere in the same repository that differ from the pin. The
        # pin covers the named file; its imports come from whatever is on disk.
        "repo_files_changed_since_pin": sorted(
            changed.stdout.decode().split()) if changed.returncode == 0 else None,
    }


def load_adapter(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"_ash_adapter_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise Aborted(f"cannot load adapter {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "run", None)):
        raise Aborted(f"adapter {path} defines no run(checker, vector_path, timeout)")
    return module


def collect_fixtures(path: Path, pattern: str) -> tuple[Path, list[Path]]:
    """Return (root, files). A directory is read non-recursively, sorted."""
    if path.is_file():
        return path.parent, [path]
    if path.is_dir():
        files = sorted(p for p in path.glob(pattern) if p.is_file())
        if not files:
            raise Aborted(f"no files matching {pattern!r} in {path}")
        return path, files
    raise Aborted(f"fixture path {path} does not exist")


def default_expected(vector: dict) -> dict | None:
    """Read the ``expect`` block most corpora use. Adapters may override."""
    want = vector.get("expect") if isinstance(vector, dict) else None
    if not isinstance(want, dict) or "verdict" not in want:
        return None
    reason = want.get("reason_code", want.get("reason", want.get("predicate")))
    return {"verdict": want["verdict"], "reason_code": reason}


def _norm(value) -> str | None:
    return None if value is None else str(value).strip().lower()


# --- the comparison, which is the only judgement the runner makes ------------

def compare(expected: dict | None, observed: dict | None, *,
            accept_verdicts: frozenset, verdict_only: bool) -> tuple[str, str]:
    """Return (state, why). Exact comparison of lowercased strings, nothing more."""
    if expected is None:
        return INCONCLUSIVE, "the fixture declares no expected outcome for this vector"
    if observed is None or observed.get("verdict") is None:
        return INCONCLUSIVE, "the checker returned no verdict the adapter could read"
    # Compared lowercased; displayed exactly as each side wrote it.
    ev, ov = expected["verdict"], observed["verdict"]
    if _norm(ev) != _norm(ov):
        return FAIL, f"expected {ev}, observed {ov}"
    if _norm(ev) in accept_verdicts:
        return PASS, f"expected {ev}, observed {ov}"
    er, orc = expected.get("reason_code"), observed.get("reason_code")
    if er is None:
        return PASS, f"expected {ev}, observed {ov} (fixture declares no reason)"
    if verdict_only:
        return PASS, f"expected {ev}, observed {ov} (reason {er} not compared: --verdict-only)"
    if orc is None:
        return INCONCLUSIVE, (f"verdict matches ({ov}), but the fixture declares "
                              f"reason {er} and the checker reports none to compare")
    if _norm(er) != _norm(orc):
        return FAIL, f"expected {ev} for {er}, observed {ov} for {orc}"
    return PASS, f"expected {ev} for {er}, observed {ov} for {orc}"


def run_vector(adapter: ModuleType, checker: Path, vector_path: Path, *,
               timeout: float, accept_verdicts: frozenset,
               verdict_only: bool) -> dict:
    row: dict = {"file": vector_path.name, "sha256": sha256_file(vector_path)}
    try:
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        row.update(id=vector_path.stem, expected=None, observed=None, raw=None,
                   state=ERROR, why=f"fixture unreadable: {exc}", control=False)
        return row

    ident = getattr(adapter, "vector_id", None)
    row["id"] = ident(vector, vector_path) if ident else (
        vector.get("id") if isinstance(vector, dict) and vector.get("id")
        else vector_path.stem)
    expected_fn = getattr(adapter, "expected", None) or default_expected
    expected = expected_fn(vector)
    row["expected"] = expected
    row["control"] = bool(expected and _norm(expected["verdict"]) in accept_verdicts)

    try:
        out = adapter.run(checker, vector_path, timeout)
    except Exception as exc:  # noqa: BLE001 -- an adapter crash is an instrument failure
        row.update(observed=None, raw=None, state=ERROR,
                   why=f"adapter raised {type(exc).__name__}: {exc}")
        return row

    row["observed"] = out.get("observed")
    row["raw"] = out.get("raw")
    if out.get("error"):
        row.update(state=ERROR, why=f"checker error: {out['error']}")
        return row

    state, why = compare(expected, row["observed"], accept_verdicts=accept_verdicts,
                         verdict_only=verdict_only)

    # Some checkers also report their own agreement with the fixture. If that
    # and the runner's comparison disagree, one of the two instruments is wrong,
    # and the runner cannot tell which. That is an error, not either answer.
    self_report = out.get("self_report")
    row["checker_self_report"] = self_report
    if self_report in (PASS, FAIL) and state in (PASS, FAIL) and self_report != state:
        row.update(state=ERROR, why=(f"runner comparison says {state} ({why}) but the "
                                     f"checker's own report says {self_report}"))
        return row
    row.update(state=state, why=why)
    return row


# --- the bundle ---------------------------------------------------------------

def summarise(rows: list[dict], verdict_only: bool) -> dict:
    counts = {s: sum(1 for r in rows if r["state"] == s) for s in STATES}
    declared = sum(1 for r in rows if r["control"])
    accepted = sum(1 for r in rows if r["control"] and r["state"] == PASS)
    if declared == 0:
        reason = ("the fixture declares no positive (acceptance) control, so a "
                  "checker that rejects everything would score the same")
    elif accepted == 0:
        reason = (f"0 of {declared} declared positive controls were accepted; a "
                  "checker that rejects everything satisfies every negative vector")
    else:
        reason = None
    return {
        "vectors": len(rows),
        **counts,
        "controls_declared": declared,
        "controls_accepted": accepted,
        "is_result": reason is None,
        "not_a_result_reason": reason,
        "comparison": "verdict-only" if verdict_only else "verdict and declared reason",
    }


def render_log(meta: dict, rows: list[dict], summary: dict) -> str:
    lines = [
        "ASH external fixture run",
        f"  format           : {RUNNER_FORMAT}",
        f"  started (UTC)    : {meta['started_utc']}",
        (f"  harness commit   : {meta['harness']['head']}"
         f"{' (dirty)' if meta['harness']['dirty'] else ''}"),
        f"  adapter          : {meta['adapter']['path']} sha256 {meta['adapter']['sha256']}",
        f"  checker          : {meta['checker']['path']} sha256 {meta['checker']['sha256']}",
        f"  checker pin      : {meta['checker']['pin']['commit'] if meta['checker']['pin'] else 'NOT PINNED'}",
        f"  fixtures         : {meta['fixtures']['root']}",
        f"  fixture pin      : {meta['fixtures']['pin'] or 'NOT PINNED'}",
        f"  python           : {meta['environment']['python']}",
        f"  platform         : {meta['environment']['platform']}",
        "",
    ]
    for r in rows:
        lines.append(f"  {r['state'].upper():<13} {r['id']:<22} {r['why']}")
        raw = r.get("raw") or {}
        for key in ("stdout", "stderr"):
            text = (raw.get(key) or "").rstrip()
            if text:
                for part in text.splitlines():
                    lines.append(f"      {key}: {part}")
        if raw.get("exit_code") not in (None, 0):
            lines.append(f"      exit_code: {raw['exit_code']}")
    lines += [
        "",
        (f"{summary['pass']}/{summary['vectors']} vectors: observed outcome matches "
         "the fixture's declared expectation"),
        (f"  fail {summary['fail']}, inconclusive {summary['inconclusive']}, "
         f"error {summary['error']}; compared on {summary['comparison']}"),
        (f"acceptance controls: {summary['controls_accepted']} of "
         f"{summary['controls_declared']} declared were accepted"),
    ]
    if summary["is_result"]:
        lines.append("RESULT (raw; not a certification of the checker, the fixture, "
                     "or the fixture author's protocol)")
    else:
        lines.append(f"NOT A RESULT: {summary['not_a_result_reason']}")
    return "\n".join(lines) + "\n"


def write_bundle(out: Path, meta: dict, rows: list[dict], summary: dict,
                 inputs: list[tuple[str, Path]], copy_inputs: bool) -> str:
    out.mkdir(parents=True, exist_ok=True)
    doc = {"format": RUNNER_FORMAT, **meta, "summary": summary, "vectors": rows}
    (out / "results.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")
    log = render_log(meta, rows, summary)
    (out / "run.log").write_text(log, encoding="utf-8")

    sums = []
    for label, src in inputs:
        sums.append(f"{sha256_file(src)}  {label}")
        if copy_inputs:
            dest = out / label
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
    for name in ("results.json", "run.log"):
        sums.append(f"{sha256_file(out / name)}  {name}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return log


# --- entry point --------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # keep exit 2 for NOT A RESULT only
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def main(argv: list[str] | None = None) -> int:
    p = _Parser(description=__doc__.splitlines()[0])
    p.add_argument("--fixtures", type=Path, required=True,
                   help="a fixture file, or a directory of them (non-recursive)")
    p.add_argument("--glob", default="*.json", help="file pattern in a fixture dir")
    p.add_argument("--fixture-commit", default=None,
                   help="refuse unless every fixture file is byte-identical to this commit")
    p.add_argument("--adapter", type=Path, required=True,
                   help="adapter file that invokes the checker and reads its answer")
    p.add_argument("--checker", type=Path, required=True,
                   help="the checker file the adapter runs")
    p.add_argument("--checker-commit", default=None,
                   help="refuse unless the checker file is byte-identical to this commit")
    p.add_argument("--out", type=Path, required=True, help="bundle directory (new or empty)")
    p.add_argument("--copy-inputs", action="store_true",
                   help="copy fixtures, checker and adapter into the bundle. Only "
                        "when their licences permit redistribution.")
    p.add_argument("--verdict-only", action="store_true",
                   help="compare verdicts only; declared reasons are recorded, not compared")
    p.add_argument("--timeout", type=float, default=60.0, help="seconds per vector")
    args = p.parse_args(argv)

    try:
        return _run(args)
    except Aborted as exc:
        print(f"ABORTED, nothing run, no bundle written:\n  {exc}", file=sys.stderr)
        return EXIT_ABORTED


def _run(args: argparse.Namespace) -> int:
    started = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if args.out.exists() and any(args.out.iterdir()):
        raise Aborted(f"output directory {args.out} is not empty")
    checker = args.checker.resolve()
    adapter_path = args.adapter.resolve()
    if not checker.is_file():
        raise Aborted(f"checker {checker} does not exist")
    if not adapter_path.is_file():
        raise Aborted(f"adapter {adapter_path} does not exist")
    root, files = collect_fixtures(args.fixtures.resolve(), args.glob)

    # Pins are checked before anything runs. A mismatch aborts; it never warns.
    checker_pin = verify_pin(checker, args.checker_commit) if args.checker_commit else None
    fixture_pin = None
    if args.fixture_commit:
        pins = [verify_pin(f, args.fixture_commit) for f in files]
        fixture_pin = pins[0]["commit"]

    adapter = load_adapter(adapter_path)
    accept = frozenset(_norm(v) for v in getattr(adapter, "ACCEPT_VERDICTS",
                                                  DEFAULT_ACCEPT_VERDICTS))

    rows = [run_vector(adapter, checker, f, timeout=args.timeout,
                       accept_verdicts=accept, verdict_only=args.verdict_only)
            for f in files]
    summary = summarise(rows, args.verdict_only)

    meta = {
        "started_utc": started,
        "finished_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "harness": {"repo": "msaleme/red-team-blue-team-agent-fabric",
                    **{k: v for k, v in git_state(REPO_ROOT).items() if k != "repo"}},
        "adapter": {"path": str(adapter_path), "sha256": sha256_file(adapter_path),
                    "id": getattr(adapter, "ADAPTER_ID", adapter_path.stem),
                    "accept_verdicts": sorted(accept)},
        "checker": {"path": str(checker), "sha256": sha256_file(checker),
                    "git": git_state(checker), "pin": checker_pin},
        "fixtures": {"root": str(root), "glob": args.glob, "git": git_state(root),
                     "pin": fixture_pin,
                     "files": [{"file": f.relative_to(root).as_posix(),
                                "sha256": sha256_file(f)} for f in files]},
        "environment": {"python": sys.version.split()[0],
                        "python_executable": sys.executable,
                        "platform": platform.platform()},
        "claims": ("Raw output of the named checker on the named fixtures. Not a "
                   "certification, endorsement or validation of the checker, the "
                   "fixtures, or any protocol they describe."),
    }
    inputs = [(f"inputs/fixtures/{f.relative_to(root).as_posix()}", f) for f in files]
    inputs += [(f"inputs/checker/{checker.name}", checker),
               (f"inputs/adapter/{adapter_path.name}", adapter_path)]
    log = write_bundle(args.out, meta, rows, summary, inputs, args.copy_inputs)
    print(log, end="")
    print(f"bundle: {args.out.resolve()}")

    if not summary["is_result"]:
        return EXIT_NOT_A_RESULT
    return EXIT_ALL_PASS if summary["pass"] == summary["vectors"] else EXIT_NOT_ALL_PASS


if __name__ == "__main__":
    raise SystemExit(main())
