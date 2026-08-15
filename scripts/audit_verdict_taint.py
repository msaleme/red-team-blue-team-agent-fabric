#!/usr/bin/env python3
"""Derive which harness verdicts can be decided by a response that never arrived (#351).

#348 was scoped by reading five files and two more modules with the same defect
survived it. #350's fix was to derive the *candidate* set instead of hand-writing
it. This derives one step further: per verdict expression, whether a target
response reaches it at all.

That distinction is the audit. A verdict that never touches a response cannot
report a pass against a host that is not running. A verdict reading
``not leaked``, where ``leaked`` came from ``resp``, can: on an unserviced
target nothing leaks, so the control "held".

Taint reaches a verdict two ways, and the first version of this script only
followed one of them
---------------------------------------------------------------------------
**Data dependency** -- the response appears on an assignment's right-hand side::

    leaked = "secret" in str(resp)
    passed = not leaked

**Control dependency** -- the response appears in a *condition* that governs the
assignment, and never on the right-hand side at all::

    succeeded = False
    if _response_allows_change(resp):
        succeeded = True
    passed = not succeeded

The second shape is the common one in this package, and the version of this
script merged in #372 missed all of it. It reported
``governance_modification_harness`` as one of only two modules with no
response-decided verdict; that module has five, and a live false pass reading
"All gate-disable attempts were rejected -- HC-12 enforced" against a host that
never answered. Both forms are now followed, by treating the names in a
governing condition as dependencies of every assignment inside it.

**Deliberately over-reports.** A verdict inside ``if self.verbose:`` inherits
that condition's names. For a triage tool the errors are not symmetric: a false
positive costs someone a read, a false negative is a module shipped as clean.
The #372 version made the second kind, so this one is tuned to make the first.

Output is a triage, not a verdict. Direction is a heuristic on expression shape
and every TAINTED row still has to be read. Absence of taint means only "no
response reaches it *by the mechanisms below, under the names in
RESPONSE_NAMES*" -- it is not a proof of cleanliness, and must never again be
reported as one.

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

# A floor, not the list. These cover responses that arrive as a *parameter*
# (``def _leak(resp)``) where there is no assignment to derive from.
#
# The list itself is DERIVED per module by derive_response_names(). Hand-writing
# it was the #372 defect one level up: the shipped version carried twelve names
# and the package binds responses to at least twenty-one more -- resp1, resp2,
# audit_resp, ks_probe, hc12_probe, schema -- so every verdict reading one of
# those was reported clean. #350 already established that a hand-maintained
# coverage list is the same failure the guard exists to prevent. It applies here
# too, and it was not applied.
RESPONSE_NAMES = frozenset({
    "resp", "response", "reply", "res", "body", "raw", "http_resp", "result_resp",
})

# Callables that return a target response.
HTTP_CALL_NAMES = frozenset({"urlopen", "_post", "_send", "_call", "_get", "_request"})


def derive_response_names(tree: ast.AST) -> set[str]:
    """Every name in this module bound from a call that returns a response.

    Self-updating: a new harness writing ``foo_resp = http_post(...)`` is covered
    the moment it lands, with nothing to remember.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        fname = (func.id if isinstance(func, ast.Name)
                 else func.attr if isinstance(func, ast.Attribute) else "")
        if fname.startswith("http_") or fname in HTTP_CALL_NAMES:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out.add(target.id)
    return out

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


def _assigned_names(node: ast.AST) -> set[str]:
    out: set[str] = set()
    if isinstance(node, ast.Assign):
        for target in node.targets:
            out |= {t.id for t in ast.walk(target) if isinstance(t, ast.Name)}
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        if isinstance(node.target, ast.Name):
            out.add(node.target.id)
    elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
        out.add(node.target.id)
    return out


def build_dependencies(fn: ast.AST) -> dict[str, set[str]]:
    """name -> names it depends on, through data OR control flow.

    Control dependency is folded into the same map by passing the names of every
    governing condition down as extra dependencies of the assignments beneath it.
    """
    deps: dict[str, set[str]] = {}

    def visit(stmts: list[ast.stmt], guards: frozenset[str]) -> None:
        for node in stmts:
            if isinstance(node, (ast.If, ast.While)):
                inner = guards | free_names(node.test)
                visit(node.body, inner)
                visit(node.orelse, inner)
            elif isinstance(node, ast.For):
                inner = guards | free_names(node.iter)
                for name in _assigned_names(node.target) | {
                    t.id for t in ast.walk(node.target) if isinstance(t, ast.Name)
                }:
                    deps.setdefault(name, set()).update(inner)
                visit(node.body, inner)
                visit(node.orelse, inner)
            elif isinstance(node, ast.Try):
                visit(node.body, guards)
                for handler in node.handlers:
                    visit(handler.body, guards)
                visit(node.orelse, guards)
                visit(node.finalbody, guards)
            elif isinstance(node, ast.With):
                visit(node.body, guards)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # its own scope; scanned separately
            else:
                rhs: set[str] = set()
                value = getattr(node, "value", None)
                if value is not None:
                    rhs = free_names(value)
                for name in _assigned_names(node):
                    deps.setdefault(name, set()).update(rhs | guards)
                # walrus and nested assignments inside an expression statement
                for child in ast.walk(node):
                    if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                        deps.setdefault(child.target.id, set()).update(
                            free_names(child.value) | guards
                        )

    body = getattr(fn, "body", [])
    visit(body, frozenset())
    return deps


class VerdictScanner(ast.NodeVisitor):
    """Collect every ``passed=`` expression and whether a response reaches it."""

    def __init__(self, response_names: frozenset[str] = RESPONSE_NAMES) -> None:
        self.rows: list[dict] = []
        self.response_names = response_names

    def visit_FunctionDef(self, fn: ast.FunctionDef) -> None:  # noqa: N802
        deps = build_dependencies(fn)

        def tainted(name: str, seen: frozenset[str] = frozenset()) -> bool:
            if name in self.response_names:
                return True
            if name in seen:
                return False
            return any(tainted(d, seen | {name}) for d in deps.get(name, ()))

        for expr in self._verdicts(fn):
            names = free_names(expr)
            direct = bool(names & self.response_names)
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
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    names = frozenset(RESPONSE_NAMES | derive_response_names(tree))
    scanner = VerdictScanner(names)
    scanner.visit(tree)
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
        "\nA tainted verdict is decided by a response, through data flow or through a "
        "\ncondition governing it. Absence of taint means only 'not reached by these "
        "\nmechanisms, under these names'. It is NOT a proof that a verdict is sound."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
