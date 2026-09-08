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
#: Must accept every ID shape scripts/count_tests.py accepts. The first version
#: required a trailing `-\d{3}`, which rejects `AIUC-E001` and `AIUC-C003a`; all
#: twelve AIUC-1 tests were therefore never attributed and sat in the untagged
#: grandfather list as if they carried no tag. They carry ASI01/02/07. Found
#: when the helper-literal rule was broadened (third external review, R3-09).
_TEST_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[A-Z]?\d{3}[a-z]?$")

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
            # Any ASI-bearing call the locator could NOT attribute is recorded,
            # whatever shape its id expression takes. This used to require a
            # second narrow pattern (a Name in the test_id keyword or a
            # positional `test_id`/`tid`) and so ignored `test_id=str(row_id)`
            # -- a Call -- entirely. The third external review seeded exactly
            # that shape and the whole ASI test file stayed green (R3-09).
            # Unknown attribution is the case to record, not the case to skip.
            if not has_literal_id:
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


# ---------------------------------------------------------------------------
# Which registered modules record a target response.
#
# Until 2026-09-07 two consumers -- testing/test_serviced_guard.py and
# scripts/audit_verdict_taint.py -- each carried the same source-text rule:
# a module recorded a response if its file contained the literal text of a
# `_record` def AND the literal `response_received`. A module that inherits
# `_record` from `harness_base.RecordingHarness` defines none of its own, so
# `agent_data_injection` and `delegation_chain_harness` -- the two modules
# written the way CLAUDE.md item 7 asks for -- were invisible to both. An
# invisible module is neither guarded nor counted in UNREVIEWED; it drops out
# of the remainder that CLAUDE.md item 10 says is the progress metric. The
# same rule had already been replaced in scripts/dead_host_sweep.py the same
# morning (R3-02); this is the same replacement for the other two.
#
# The denominator is the CLI registry, as in dead_host_sweep.registry_coverage,
# plus the module that defines the shared base. The fact is read off the
# imported module rather than its text: a class defined in the module has a
# callable `_record` -- its own or inherited -- and a result dataclass in the
# module's namespace carries a `response_received` field, which is the one
# field the shared guard reads. Every module the text rule found satisfies
# both; the two it missed satisfy both; nothing the text rule found fails.
# ---------------------------------------------------------------------------

def harness_modules() -> list[str]:
    """Every dotted module the CLI registry names, plus the shared base.

    `protocol_tests.cli.HARNESSES` is the one list a harness has to be on to
    be runnable, and `harness_base` is where the inherited `_record` lives.
    A module that is on neither is not a harness this package ships.
    """
    from protocol_tests.cli import HARNESSES
    from protocol_tests.harness_base import RecordingHarness
    out: list[str] = []
    for info in HARNESSES.values():
        if info["module"] not in out:
            out.append(info["module"])
    if RecordingHarness.__module__ not in out:
        out.append(RecordingHarness.__module__)
    return out


def recording_facts(module: str) -> dict:
    """The import-level facts a records-a-response classification is built on.

    ``defines_record``   a class defined in the module has `_record` in its own
                         namespace
    ``inherits_record``  a class defined in the module has a callable `_record`
                         it did not define
    ``response_field``   a dataclass in the module namespace, defined or
                         imported, has a field named `response_received`
    ``records_response`` (defines_record or inherits_record) and response_field
    """
    import dataclasses
    import importlib
    import inspect

    mod = importlib.import_module(module)
    defines = inherits = response_field = False
    for obj in list(vars(mod).values()):
        if not inspect.isclass(obj):
            continue
        if dataclasses.is_dataclass(obj) and any(
                f.name == "response_received" for f in dataclasses.fields(obj)):
            response_field = True
        if obj.__module__ != mod.__name__:
            continue
        if "_record" in vars(obj):
            defines = True
        elif callable(getattr(obj, "_record", None)):
            inherits = True
    return {
        "module": module,
        "defines_record": defines,
        "inherits_record": inherits,
        "response_field": response_field,
        "records_response": (defines or inherits) and response_field,
    }


def response_recording_modules(modules: list[str] | None = None) -> set[str]:
    """Stems of the modules that record a target response, from `modules`.

    Defaults to `harness_modules()`. The ONE derivation behind
    testing/test_serviced_guard.py and scripts/audit_verdict_taint.py; the
    two used to carry a copy each of a text rule, and a copy is where a rule
    drifts.
    """
    names = harness_modules() if modules is None else list(modules)
    return {m.rsplit(".", 1)[-1] for m in names
            if recording_facts(m)["records_response"]}
