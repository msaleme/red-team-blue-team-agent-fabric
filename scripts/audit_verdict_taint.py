#!/usr/bin/env python3
"""Derive which harness verdicts can be decided by a response that never arrived (#351).

#348 was scoped by reading five files and two more modules with the same defect
survived it. #350's fix was to derive the *candidate* set instead of hand-writing
it. This script goes one step further and derives, per verdict expression, whether
the verdict is reachable from a target response at all -- directly, or through a
local assigned from one.

That distinction is the whole audit. A verdict that never touches a response
cannot report a pass against a host that is not running. A verdict that reads
``not leaked``, where ``leaked`` was computed from ``resp``, can and does: on an
unserviced target nothing leaks, so the control "held".

Output is a triage, not a verdict. Direction (false pass vs false fail) is a
heuristic on the expression shape and every TAINTED row still has to be read.
Absence of taint is the only conclusion this script draws on its own.

    python3 scripts/audit_verdict_taint.py
    python3 scripts/audit_verdict_taint.py --module jailbreak_harness --verbose
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_TESTS = REPO_ROOT / "protocol_tests"

# Names a target response is bound to across the package. Extend rather than
# rename: a miss here shows up as a module wrongly reported clean.
RESPONSE_NAMES = frozenset({
    "resp", "response", "reply", "res", "body", "raw", "http_resp", "result_resp",
})

# On an unserviced target every detector returns falsy: nothing leaked, nothing
# succeeded, no unsafe entries. These shapes then evaluate TRUE, which is the
# #348 signature -- absence of a detected attack read as a control holding.
NEGATED_SHAPES = ("not ", "len(", "== 0", "== []", "is None", "not in ")


def free_names(node: ast.AST) -> set[str]:
    """Names in an expression, minus those bound by a comprehension or lambda."""
    bound: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for gen in child.generators:
                bound |= {t.id for t in ast.walk(gen.target) if isinstance(t, ast.Name)}
        elif isinstance(child, ast.Lambda):
            bound |= {a.arg for a in child.args.args}
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} - bound


class VerdictScanner(ast.NodeVisitor):
    """Collect every ``passed=`` expression and whether a response reaches it."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def visit_FunctionDef(self, fn: ast.FunctionDef) -> None:  # noqa: N802
        deps: dict[str, set[str]] = {}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                rhs = free_names(node.value)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        deps.setdefault(target.id, set()).update(rhs)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                if isinstance(node.target, ast.Name):
                    deps.setdefault(node.target.id, set()).update(free_names(node.value))

        def tainted(name: str, seen: frozenset[str] = frozenset()) -> bool:
            if name in RESPONSE_NAMES:
                return True
            if name in seen:
                return False
            return any(tainted(d, seen | {name}) for d in deps.get(name, ()))

        for expr in self._verdicts(fn):
            names = free_names(expr)
            direct = bool(names & RESPONSE_NAMES)
            reaches = direct or any(tainted(n) for n in names)
            text = ast.unparse(expr)
            self.rows.append({
                "function": fn.name,
                "expr": text,
                "tainted": reaches,
                "direct": direct,
                "false_pass_shape": any(s in text for s in NEGATED_SHAPES),
            })
        self.generic_visit(fn)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    @staticmethod
    def _verdicts(fn: ast.AST) -> list[ast.AST]:
        out = []
        for node in ast.walk(fn):
            if isinstance(node, ast.keyword) and node.arg == "passed":
                out.append(node.value)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    is_verdict = (
                        (isinstance(target, ast.Attribute) and target.attr == "passed")
                        or (isinstance(target, ast.Name) and target.id == "passed")
                    )
                    if is_verdict:
                        out.append(node.value)
        return out


def audit(module_path: Path) -> list[dict]:
    scanner = VerdictScanner()
    scanner.visit(ast.parse(module_path.read_text(encoding="utf-8")))
    return scanner.rows


def candidate_modules() -> list[Path]:
    """Same derivation as testing/test_serviced_guard.py: records a response."""
    out = []
    for path in sorted(PROTOCOL_TESTS.glob("*.py")):
        src = path.read_text(encoding="utf-8")
        if "def _record" in src and "response_received" in src:
            out.append(path)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--module", help="audit one module stem, e.g. jailbreak_harness")
    ap.add_argument("--verbose", action="store_true", help="print every tainted verdict")
    args = ap.parse_args()

    paths = candidate_modules()
    if args.module:
        paths = [p for p in paths if p.stem == args.module]
        if not paths:
            print(f"no candidate module named {args.module!r}", file=sys.stderr)
            return 2

    print(f"{'module':<34}{'verdicts':>9}{'tainted':>9}{'direct':>8}{'false-pass shape':>18}")
    print("-" * 78)
    totals = [0, 0, 0, 0]
    for path in paths:
        rows = audit(path)
        tainted = [r for r in rows if r["tainted"]]
        direct = [r for r in tainted if r["direct"]]
        shaped = [r for r in tainted if r["false_pass_shape"]]
        totals = [totals[0] + len(rows), totals[1] + len(tainted),
                  totals[2] + len(direct), totals[3] + len(shaped)]
        print(f"{path.stem:<34}{len(rows):>9}{len(tainted):>9}{len(direct):>8}{len(shaped):>18}")
        if args.verbose:
            for row in tainted:
                mark = "FALSE-PASS?" if row["false_pass_shape"] else "           "
                print(f"    {mark} {row['function']}(): {row['expr'][:88]}")
    print("-" * 78)
    print(f"{'TOTAL':<34}{totals[0]:>9}{totals[1]:>9}{totals[2]:>8}{totals[3]:>18}")
    print(
        "\nA tainted verdict is decided by a response. If the target never answered, the "
        "\nresponse is empty and every detector is falsy, so a 'false-pass shape' verdict "
        "\nreports that the control held. Clean means only: no response reaches it."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
