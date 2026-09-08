"""Shipped scripts must resolve package data through `protocol_tests.package_data`.

R3-12 (third external review, 2026-09-07). `docs/QUICKSTART.md` told a pip user
to run `python -m testing.mock_mcp_server`; `testing/` is not in the wheel and
the command raised ModuleNotFoundError. The same review found that four scripts
which ARE in the wheel resolved their inputs as `ROOT / "docs/..."` with ROOT
two levels above their own file -- a checkout in a clone, `site-packages` in a
wheel -- and raised FileNotFoundError from an installed copy. #526 had tested
the resolver; these scripts bypassed it.

This is a ratchet, in the style of `test_harness_base_adoption.py`:

- the set of scripts checked is DERIVED from `pyproject.toml` package
  discovery, not written here, so a script added to a shipped directory is
  covered without anyone remembering it;
- a checkout-relative join (`REPO_ROOT / "x"`, `os.path.join(ROOT, "x")`,
  `ROOT.joinpath("x")`, `Path(__file__).parent.parent / "x"`) is found by AST,
  not by grep, so renaming the constant does not hide it;
- a join whose first segment is itself a shipped top-level package
  (`ROOT / "protocol_tests"`, `ROOT / "scripts" / "count_tests.py"`) is valid
  on an installed copy -- both sit in site-packages -- and is not counted; that
  set is derived from the same package discovery;
- a script NOT in GRANDFATHERED may carry none; a script in it may carry at
  most its floor; the floor may go down and the list may shrink, never grow.

What a floor means: those lines were read. Some resolve a resource that is
legitimately checkout-only (`docs/release-claims.json`, git history,
`red_team_automation.py`) and the script says so in its docstring and exits
with one line naming the resource. Others are simply not yet migrated. The
number either way is the count of lines an installed copy cannot trust.

The second class asserts the quickstart itself: the mock server is in a shipped
directory, exposes a `python -m` entry, has a console script, and no document
in the repository still promises the old `testing.` path.
"""

from __future__ import annotations

import ast
import fnmatch
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

PYPROJECT = REPO_ROOT / "pyproject.toml"

#: script stem -> maximum number of source LINES that join a path onto a root
#: two levels above the file. SHRINK ONLY. Lowering a floor means lines were
#: migrated to package_data (or removed); raising one, or adding a script,
#: reintroduces the R3-12 defect for whoever installs the wheel.
GRANDFATHERED: dict[str, int] = {
    # Seeded 2026-09-07 at the R3-12 fix. "checkout-only, gated" means the
    # script's docstring says so and it exits with one line naming the resource.
    "aiuc1_prep": 1,                       # output dir under the checkout; not read
    "check_public_metadata": 1,            # CITATION.cff -- checkout-only, not gated yet
    "generate_owasp_agentic_coverage": 5,  # writes docs/ views -- a checkout generator
    "generate_test_catalog": 2,            # HARNESS_TEST_CATALOG.md + benchmarks/ corpus
    "monthly_security_report": 3,          # pyproject.toml + configs/ default + reports/
    "validate_owasp_agentic_mapping": 6,   # docs views, pyproject, git -- checkout-only, gated
    "validate_result_semantics": 1,        # docs/result-semantics.json -- checkout-only, gated
    "verify_release_claims": 2,            # docs/release-claims.json + surfaces -- checkout-only, gated
}

#: Scripts named in R3-12. Anti-vacuity anchor for the derived list.
R3_12_SCRIPTS = (
    "owasp_agentic_select",
    "validate_result_semantics",
    "validate_owasp_agentic_mapping",
    "verify_release_claims",
)


# --------------------------------------------------------------------------
# What ships: derived from pyproject.toml, never listed here
# --------------------------------------------------------------------------

def _find_include_patterns(text: str) -> list[str]:
    """`[tool.setuptools.packages.find].include`, via tomllib when present
    (3.11+) and by a section-aware line scan on 3.10."""
    try:
        import tomllib
    except ImportError:  # pragma: no cover - 3.10
        tomllib = None
    if tomllib is not None:
        return list(tomllib.loads(text)["tool"]["setuptools"]["packages"]["find"]["include"])
    section = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        if section == "tool.setuptools.packages.find" and stripped.startswith("include"):
            return re.findall(r'"([^"]+)"', stripped.split("=", 1)[1])
    raise AssertionError("no [tool.setuptools.packages.find] include in pyproject.toml")


def shipped_top_level_dirs() -> list[str]:
    patterns = _find_include_patterns(PYPROJECT.read_text(encoding="utf-8"))
    return sorted(
        d.name for d in REPO_ROOT.iterdir()
        if d.is_dir() and any(fnmatch.fnmatch(d.name, pat) for pat in patterns))


def shipped_scripts() -> list[Path]:
    """Every scripts/*.py the wheel carries. Empty if `scripts` stops shipping,
    which the anti-vacuity test below turns into a failure, not a pass."""
    if "scripts" not in shipped_top_level_dirs():
        return []
    return sorted(p for p in (REPO_ROOT / "scripts").glob("*.py") if p.name != "__init__.py")


# --------------------------------------------------------------------------
# The detector
# --------------------------------------------------------------------------

def _mentions_file(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Name) and n.id == "__file__" for n in ast.walk(node))


def _is_dirname(func: ast.AST) -> bool:
    return isinstance(func, ast.Attribute) and func.attr == "dirname"


def _climbs_two_levels(node: ast.AST) -> bool:
    """`Path(__file__)...parents[k>=1]`, `...parent.parent`, or
    `dirname(dirname(__file__))` -- the shapes that leave a script's own
    directory. One level (`Path(__file__).parent`) is the script's siblings and
    is valid on an installed copy."""
    if not _mentions_file(node):
        return False
    for n in ast.walk(node):
        if (isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute)
                and n.value.attr == "parents"
                and isinstance(n.slice, ast.Constant)
                and isinstance(n.slice.value, int) and n.slice.value >= 1):
            return True
        if (isinstance(n, ast.Attribute) and n.attr == "parent"
                and isinstance(n.value, ast.Attribute) and n.value.attr == "parent"):
            return True
        if (isinstance(n, ast.Call) and _is_dirname(n.func) and n.args
                and isinstance(n.args[0], ast.Call) and _is_dirname(n.args[0].func)):
            return True
    return False


def _root_names(tree: ast.Module) -> set[str]:
    """Names bound, anywhere in the file, to an expression that climbs from __file__."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) and _climbs_two_levels(node.value):
            names.add(node.targets[0].id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.value is not None and _climbs_two_levels(node.value):
            names.add(node.target.id)
    return names


def _is_root(node: ast.AST, roots: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in roots
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
            and node.func.id == "str" and len(node.args) == 1:
        return _is_root(node.args[0], roots)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _is_root(node.left, roots)
    return _climbs_two_levels(node)


def _first_segment(node: ast.AST, roots: set[str]):
    """The first path component joined onto the root, when it is a literal.
    `ROOT / "docs" / "x"` -> "docs"; `ROOT / "scripts/count_tests.py"` ->
    "scripts"; `ROOT / e["module"]` -> None (not knowable statically)."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        # Descend to the innermost join whose left side is the root itself.
        inner = node
        while isinstance(inner.left, ast.BinOp) and isinstance(inner.left.op, ast.Div) \
                and _is_root(inner.left.left, roots):
            inner = inner.left
        first = inner.right
    elif isinstance(node, ast.Call):
        args = node.args if node.func.attr == "joinpath" else node.args[1:]  # type: ignore[attr-defined]
        first = args[0] if args else None
    else:
        return None
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value.replace("\\", "/").split("/")[0]
    return None


def _is_join(node: ast.AST, roots: set[str]) -> bool:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _is_root(node.left, roots)
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "joinpath":
            return _is_root(f.value, roots)
        if isinstance(f, ast.Attribute) and f.attr == "join" \
                and isinstance(f.value, ast.Attribute) and f.value.attr == "path" \
                and node.args:
            return _is_root(node.args[0], roots)
    return False


def checkout_relative_join_lines(source: str, shipped: set[str] | None = None) -> list[int]:
    """Line numbers (distinct) that join a path onto a checkout root, excluding
    joins whose first literal segment is a shipped top-level package (those
    resolve in site-packages too). `shipped` defaults to package discovery."""
    if shipped is None:
        shipped = set(shipped_top_level_dirs())
    tree = ast.parse(source)
    roots = _root_names(tree)
    lines = set()
    for n in ast.walk(tree):
        if _is_join(n, roots) and _first_segment(n, roots) not in shipped:
            lines.add(n.lineno)
    return sorted(lines)


def _count(path: Path) -> list[int]:
    return checkout_relative_join_lines(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Guards on the detector, so the ratchet cannot pass vacuously
# --------------------------------------------------------------------------

class TestTheDetectorStillDetects(unittest.TestCase):
    POSITIVE = '''
import os
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]
ROOT2 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = REPO_ROOT / "docs" / "x.json"
B = os.path.join(ROOT2, "configs", "a.yaml")
C = REPO_ROOT.joinpath("schemas", "s.json")
D = Path(__file__).resolve().parent.parent / "pyproject.toml"
E = os.path.join(str(REPO_ROOT), "docs")
F = (REPO_ROOT / "protocol_tests").glob("*.py")
G = REPO_ROOT / "scripts/count_tests.py"
def f():
    root = Path(__file__).parent.parent
    return root / "reports"
'''

    NEGATIVE = '''
import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
from protocol_tests.package_data import data_path, data_dir
A = data_path("configs", "a.yaml")
B = data_dir("schemas") / "s.json"
C = Path(__file__).parent / "sibling.py"
D = Path(__file__).resolve().parent
def run(cwd=REPO_ROOT):
    return cwd
'''

    def test_every_join_shape_is_seen(self) -> None:
        """With nothing exempt, every join line -- including the two onto shipped
        packages and the one inside a function -- is reported."""
        self.assertEqual(checkout_relative_join_lines(self.POSITIVE, shipped=set()),
                         [6, 7, 8, 9, 10, 11, 12, 15])

    def test_joins_onto_shipped_packages_are_exempt(self) -> None:
        self.assertEqual(
            checkout_relative_join_lines(self.POSITIVE, shipped={"protocol_tests", "scripts"}),
            [6, 7, 8, 9, 10, 15])

    def test_the_exemption_set_is_derived_not_empty(self) -> None:
        self.assertIn("protocol_tests", shipped_top_level_dirs())

    def test_package_data_and_sys_path_setup_are_not_joins(self) -> None:
        self.assertEqual(checkout_relative_join_lines(self.NEGATIVE, shipped=set()), [])

    def test_the_seeded_injection_shape_is_seen(self) -> None:
        """The exact line the fault-injection step adds to a shipped script."""
        src = self.NEGATIVE + '\n_INJECTED = REPO_ROOT / "docs" / "x.json"\n'
        self.assertEqual(len(checkout_relative_join_lines(src)), 1)


class TestTheShippedSetIsDerived(unittest.TestCase):
    def test_scripts_ship_and_testing_does_not(self) -> None:
        dirs = shipped_top_level_dirs()
        self.assertIn("scripts", dirs, "scripts/ no longer ships; this ratchet would be vacuous")
        self.assertIn("protocol_tests", dirs)
        self.assertNotIn("testing", dirs,
                         "testing/ now ships? Then the mock server alias is redundant; re-read R3-12.")

    def test_the_r3_12_scripts_are_in_the_derived_set(self) -> None:
        stems = {p.stem for p in shipped_scripts()}
        self.assertGreater(len(stems), 20)
        for s in R3_12_SCRIPTS:
            self.assertIn(s, stems)

    def test_no_grandfathered_entry_is_stale(self) -> None:
        """Every entry names a shipped script the detector still sees.
        A script that reached zero must be REMOVED, so the list shrinks."""
        by_stem = {p.stem: p for p in shipped_scripts()}
        for stem, floor in GRANDFATHERED.items():
            with self.subTest(script=stem):
                self.assertIn(stem, by_stem, f"{stem} is not a shipped script; remove the entry")
                self.assertGreater(floor, 0, f"{stem} has floor 0; remove the entry")
                self.assertGreater(len(_count(by_stem[stem])), 0,
                                   f"{stem} no longer resolves anything checkout-relative; "
                                   f"remove the entry so the list shrinks")


# --------------------------------------------------------------------------
# The ratchet
# --------------------------------------------------------------------------

class TestShippedScriptsDoNotBypassPackageData(unittest.TestCase):
    def test_each_shipped_script_is_at_or_under_its_floor(self) -> None:
        scripts = shipped_scripts()
        self.assertTrue(scripts)
        for path in scripts:
            lines = _count(path)
            floor = GRANDFATHERED.get(path.stem, 0)
            with self.subTest(script=path.stem):
                self.assertLessEqual(
                    len(lines), floor,
                    f"scripts/{path.name} joins a path onto the checkout root on "
                    f"{len(lines)} line(s) {lines}; floor is {floor}. On an installed "
                    f"wheel that root is site-packages and the file is not there. "
                    f"Resolve shipped data through protocol_tests.package_data; for a "
                    f"resource that is legitimately checkout-only, say so in the "
                    f"docstring and exit with one line naming it. Do not raise the floor.")

    def test_the_named_scripts_resolve_shipped_data_through_the_resolver(self) -> None:
        """The three that read a shipped file. verify_release_claims reads
        none: it is entirely checkout-only and is covered by the gate test."""
        for stem in ("owasp_agentic_select", "validate_result_semantics",
                     "validate_owasp_agentic_mapping"):
            src = (REPO_ROOT / "scripts" / f"{stem}.py").read_text(encoding="utf-8")
            with self.subTest(script=stem):
                self.assertIn("protocol_tests.package_data", src)
                self.assertNotIn('/ "docs/coverage/', src)
                self.assertNotIn('/ "schemas" /', src)

    def test_the_checkout_only_scripts_say_so_and_exit_two(self) -> None:
        """A missing checkout resource is one line and exit 2, never a traceback."""
        for stem in ("validate_result_semantics", "validate_owasp_agentic_mapping",
                     "verify_release_claims"):
            src = (REPO_ROOT / "scripts" / f"{stem}.py").read_text(encoding="utf-8")
            doc = ast.get_docstring(ast.parse(src)) or ""
            with self.subTest(script=stem):
                self.assertIn("checkout-only", doc.lower(),
                              "docstring must state which resources are checkout-only")
                self.assertIn("checkout-only resource missing", src)


# --------------------------------------------------------------------------
# The quickstart is true from the wheel
# --------------------------------------------------------------------------

class TestQuickstartMockServerShips(unittest.TestCase):
    def test_mock_server_is_in_a_shipped_package(self) -> None:
        self.assertTrue((REPO_ROOT / "protocol_tests" / "mock_mcp_server.py").is_file())
        self.assertIn("protocol_tests", shipped_top_level_dirs())

    def test_module_and_console_script_entry_points(self) -> None:
        from protocol_tests import mock_mcp_server
        self.assertTrue(callable(mock_mcp_server.main))
        self.assertTrue(hasattr(mock_mcp_server, "MockMCPHandler"))
        text = PYPROJECT.read_text(encoding="utf-8")
        self.assertIn('agent-security-mock-mcp = "protocol_tests.mock_mcp_server:main"', text)

    def test_help_exits_zero_without_binding(self) -> None:
        from protocol_tests import mock_mcp_server
        with self.assertRaises(SystemExit) as ctx:
            mock_mcp_server.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_checkout_alias_still_answers(self) -> None:
        import importlib
        alias = importlib.import_module("testing.mock_mcp_server")
        from protocol_tests import mock_mcp_server as shipped
        self.assertIs(alias.MockMCPHandler, shipped.MockMCPHandler)
        self.assertIs(alias.main, shipped.main)

    def test_shipped_mock_is_standard_library_only(self) -> None:
        """docker/Dockerfile.mcp copies the file alone; a package import breaks it."""
        tree = ast.parse((REPO_ROOT / "protocol_tests" / "mock_mcp_server.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertFalse((node.module or "").startswith("protocol_tests"),
                                 f"line {node.lineno}: imports {node.module}")
                self.assertEqual(node.level, 0, f"line {node.lineno}: relative import")

    def test_no_document_promises_the_unshipped_path(self) -> None:
        offenders = []
        for md in REPO_ROOT.rglob("*.md"):
            rel = md.relative_to(REPO_ROOT)
            parts = rel.parts
            if parts[0] in {"build", "dist", ".git", "node_modules"} or "CRITICAL_EVALUATION" in md.name \
                    or md.name == "CHANGELOG.md":
                continue
            if "-m testing.mock_mcp_server" in md.read_text(encoding="utf-8", errors="replace"):
                offenders.append(str(rel))
        self.assertEqual(offenders, [], "still documents the checkout-only path")


if __name__ == "__main__":
    unittest.main()
