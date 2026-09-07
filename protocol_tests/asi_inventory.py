"""The corpus-wide test -> OWASP ASI inventory, read from source by AST.

This is the ONE source for "which tests evidence which ASI category". The
inline `owasp_asi=` tag on each test's result constructor is authoritative;
this module reads it the way `scripts/count_tests.py` reads test IDs -- from
the source tree at call time -- so there is no table to keep in sync.

Why not a regex: 844 tag sites span three literal shapes and multi-line
constructor calls. A regex either misses sites or matches an ASI in a
docstring. `ast` sees the keyword on the call.

Why not the AIUC-1 mapping YAML: it carried a second, requirement-level
ASI assignment, and the coverage tables built test membership from it
transitively. The two paths disagreed (F002 "CBRN Content Prevention" said
ASI05; the CBRN tests' own tags said ASI06), and a test could appear under
different categories in different views. Found by an external review,
2026-09-07. That path is deleted; this is what replaced it.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

_PT = Path(__file__).resolve().parent
_ASI = re.compile(r"^ASI(0[1-9]|10)$")
_TEST_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3}[a-z]?$")

#: The ten published categories. `""` means "no ASI primary" -- a positive
#: control, a content-safety refusal check, or a protocol-robustness row.
VALID = frozenset(f"ASI{n:02d}" for n in range(1, 11)) | {""}


def _const(n: ast.AST) -> str | None:
    return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None


def sites() -> dict[str, list[tuple[str, int, str]]]:
    """Every (file, line, value) where a test ID is constructed with an ASI tag."""
    out: dict[str, list[tuple[str, int, str]]] = {}
    for f in sorted(_PT.glob("*.py")):
        # A module that does not parse is not "no tags"; it is an inventory
        # that cannot see part of the corpus. Continuing silently returned None
        # for four HITL rows while the file had a syntax error, and the caller
        # read that as "untagged". Raise, so the gap is loud.
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        # A test ID assigned to a local name and passed on by that name
        # (an Assign of an ID-shaped constant to a name, then that name passed
        #  as the constructor's id -- the framework_adapters PA-* shape)
        # is resolved within the enclosing function only. No wider dataflow:
        # one Assign of a single Name to an ID-shaped constant, in the same
        # FunctionDef as the Call. Anything less local stays invisible, and the
        # ratchet's grandfathered-untagged set is where that is recorded.
        local_ids: dict[ast.AST, dict[str, str]] = {}
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names: dict[str, str] = {}
                for st in ast.walk(fn):
                    if (isinstance(st, ast.Assign) and len(st.targets) == 1
                            and isinstance(st.targets[0], ast.Name)
                            and _const(st.value) and _TEST_ID.match(_const(st.value))):
                        names[st.targets[0].id] = _const(st.value)
                for st in ast.walk(fn):
                    local_ids[st] = names
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                scope = local_ids.get(node, {})
                def _resolve(a):
                    if _const(a) and _TEST_ID.match(_const(a)):
                        return _const(a)
                    if isinstance(a, ast.Name) and a.id in scope:
                        return scope[a.id]
                    return None
                tids = [x for x in (_resolve(a) for a in node.args) if x]
                tids += [x for x in (_resolve(k.value) for k in node.keywords if k.arg == "test_id") if x]
                for k in node.keywords:
                    if k.arg in ("owasp_asi", "owasp") and _const(k.value) is not None:
                        for t in tids:
                            out.setdefault(t, []).append((f.name, k.value.lineno, _const(k.value)))
            elif isinstance(node, ast.Dict):
                for key, val in zip(node.keys, node.values):
                    t = _const(key) if key is not None else None
                    if t and _TEST_ID.match(t) and isinstance(val, ast.Dict):
                        for k2, v2 in zip(val.keys, val.values):
                            if k2 is not None and _const(k2) == "owasp_asi" and _const(v2) is not None:
                                out.setdefault(t, []).append((f.name, v2.lineno, _const(v2)))
    return out


def unattributed_literals() -> dict[str, set[str]]:
    """{module: ASI values on calls whose test_id the locator could NOT resolve}.

    A helper like `_inconclusive(test_id, ...)` builds a result from a
    parameter. Its `owasp_asi=` literal is real and reaches results, but no
    literal ID sits on that call, so `sites()` cannot attribute it. Left
    unchecked, such a literal can put a row in a category none of that
    module's attributed tests use -- which is exactly how a category came to
    vary with the OUTCOME for four HITL rows. The ratchet checks that every
    module's unattributed values are a subset of its attributed ones.
    """
    out: dict[str, set[str]] = {}
    for f in sorted(_PT.glob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            asi = [_const(k.value) for k in node.keywords
                   if k.arg in ("owasp_asi", "owasp") and _const(k.value) is not None]
            if not asi:
                continue
            has_literal_id = any(_const(a) and _TEST_ID.match(_const(a)) for a in node.args) or any(
                k.arg == "test_id" and _const(k.value) and _TEST_ID.match(_const(k.value)) for k in node.keywords)
            has_param_id = any(k.arg == "test_id" and isinstance(k.value, ast.Name) for k in node.keywords) or any(
                isinstance(a, ast.Name) and a.id in ("test_id", "tid") for a in node.args)
            if has_param_id and not has_literal_id:
                out.setdefault(f.name, set()).update(asi)
    return out


def corpus_asi() -> dict[str, str]:
    """{test_id: ASI or ""} for every test that carries a tag.

    Raises if a test's sites disagree -- a category that varies with the
    outcome is the defect this module exists to make impossible.
    """
    result: dict[str, str] = {}
    for tid, ss in sites().items():
        values = {v for _, _, v in ss}
        if len(values) != 1:
            raise ValueError(f"{tid} is tagged inconsistently: "
                             + ", ".join(f"{f}:{ln}={v!r}" for f, ln, v in ss))
        result[tid] = values.pop()
    return result


def by_category() -> dict[str, list[str]]:
    """{ASI: sorted test IDs}; tests with no primary are under ""."""
    inv: dict[str, list[str]] = {}
    for tid, asi in corpus_asi().items():
        inv.setdefault(asi, []).append(tid)
    return {k: sorted(v) for k, v in inv.items()}
