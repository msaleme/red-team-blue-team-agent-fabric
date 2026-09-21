"""A wheel installed into a throwaway venv, with its own preconditions checked.

Three tests across two files install a built wheel into a fresh venv and run a
probe subprocess against it. Before this module they all reported the same thing
on failure: whatever the probe printed to stderr, usually a bare
``ModuleNotFoundError``. That single message covers at least four different
causes, and the caller could not tell them apart:

  1. the wheel does not contain the module
  2. pip reported success but the distribution is not in the venv
  3. the distribution is installed but the module is not importable from it
  4. the probe itself is wrong

On 2026-09-11 and again on 2026-09-21 an external clean-room sentinel reported
cause 1 -- "modules absent from the installed distribution" -- for all three
tests. The wheel demonstrably contains both packages, the same three tests pass
in CI on four Python versions, and they pass in a clean room built to the same
recipe. The report was not wrong to be suspicious; it had nothing else to go on,
because the test told it nothing else.

So this module does two things the previous code did not:

**It asserts the install landed before it probes.** Between the install and the
probe there is now a step that asks the venv whether the distribution is
present and whether each package imports. A failure there names the step.

**It separates INCONCLUSIVE from FAIL.** `CLAUDE.md` item 8 already says a
target that never serviced the request is INCONCLUSIVE and never a pass. The
same discipline applies here inverted: a venv that could not be created, or a
pip that could not install, is not evidence that packaging is broken. Those
report `INCONCLUSIVE (environment)`. Only a venv that was built and populated,
and still cannot import or run what the wheel claims to ship, reports
`FAIL (packaging)`. Both are red. They are not the same finding, and a run that
cannot tell them apart sends the reader to the wrong repository.

Neither state is a skip. An unestablished verdict stays visible.
"""
from __future__ import annotations

import json
import subprocess
import sys
import sysconfig
from pathlib import Path

#: What the distribution is called on PyPI, for the presence check.
DIST = "agent-security-harness"

_ENV_PROBE = r"""
import json, sys, sysconfig
out = {"executable": sys.executable, "version": sys.version.split()[0],
       "path": sys.path, "purelib": sysconfig.get_paths().get("purelib")}
try:
    from importlib.metadata import version, distributions
    try:
        out["dist_version"] = version(%(dist)r)
    except Exception as exc:
        out["dist_version"] = None
        out["dist_error"] = f"{type(exc).__name__}: {exc}"
    out["installed"] = sorted(d.metadata["Name"] for d in distributions()
                              if d.metadata["Name"])
except Exception as exc:
    out["dist_version"] = None
    out["dist_error"] = f"{type(exc).__name__}: {exc}"
    out["installed"] = []
out["imports"] = {}
for name in %(packages)r:
    try:
        mod = __import__(name)
        out["imports"][name] = getattr(mod, "__file__", None) or "<namespace>"
    except Exception as exc:
        out["imports"][name] = f"ERROR {type(exc).__name__}: {exc}"
print(json.dumps(out))
"""


class EnvironmentInconclusive(AssertionError):
    """The venv could not be built or populated. Not a packaging verdict."""


class InstalledConsumer:
    """A throwaway venv holding one built wheel, plus the diagnostics to explain it."""

    def __init__(self, wheel: Path, workdir: Path, extras: tuple[str, ...] = ()):
        self.wheel = Path(wheel)
        self.workdir = Path(workdir)
        self.venv = self.workdir / "venv"
        bindir = "Scripts" if sysconfig.get_platform().startswith("win") else "bin"
        self.python = self.venv / bindir / ("python.exe" if bindir == "Scripts" else "python")
        self._env: dict | None = None
        self._create(extras)

    # -- construction --------------------------------------------------------

    def _run(self, argv, **kw):
        return subprocess.run(argv, capture_output=True, text=True, **kw)

    def _create(self, extras: tuple[str, ...]) -> None:
        made = self._run([sys.executable, "-m", "venv", str(self.venv)])
        if made.returncode != 0:
            raise EnvironmentInconclusive(
                "INCONCLUSIVE (environment): could not create a venv, so nothing "
                "about packaging was tested.\n"
                f"  parent python : {sys.executable} ({sys.version.split()[0]})\n"
                f"  stderr        : {made.stderr.strip()[:800]}")
        got = self._run([str(self.python), "-m", "pip", "-q", "install",
                         str(self.wheel), *extras])
        if got.returncode != 0:
            raise EnvironmentInconclusive(
                "INCONCLUSIVE (environment): pip could not install the wheel, so "
                "nothing about packaging was tested.\n"
                f"  wheel  : {self.wheel.name}\n"
                f"  extras : {list(extras)}\n"
                f"  stdout : {got.stdout.strip()[:600]}\n"
                f"  stderr : {got.stderr.strip()[:800]}")
        self._pip_output = (got.stdout or "") + (got.stderr or "")

    # -- the precondition that was missing -----------------------------------

    def environment(self, packages: tuple[str, ...]) -> dict:
        """Ask the venv what it actually has. Cached per consumer."""
        if self._env is None:
            code = _ENV_PROBE % {"dist": DIST, "packages": list(packages)}
            seen = self._run([str(self.python), "-c", code], cwd=str(self.workdir))
            if seen.returncode != 0:
                raise EnvironmentInconclusive(
                    "INCONCLUSIVE (environment): the installed interpreter could not "
                    "run a trivial introspection probe.\n"
                    f"  python : {self.python}\n"
                    f"  stderr : {seen.stderr.strip()[:800]}")
            self._env = json.loads(seen.stdout)
        return self._env

    def assert_landed(self, case, packages: tuple[str, ...]) -> None:
        """Between install and probe: did the install put the packages here?

        Distinguishes 'pip said yes and placed nothing' (environment) from
        'the distribution is here and the module is not' (packaging).
        """
        env = self.environment(packages)
        # Before anything else: did the interpreter resolve to the venv we built?
        # Remove or corrupt a venv's pyvenv.cfg and python still runs, but it
        # resolves site-packages to the BASE prefix. If the base happens to hold
        # the distribution -- which it does here, because the runner installs the
        # harness editable before invoking pytest -- then `dist_version` is found,
        # every package import is evaluated against the WRONG prefix, and a
        # keyed-on-presence check calls an unresolved venv a packaging defect.
        # Seeded and caught by test_a_venv_that_resolves_elsewhere_is_environment.
        purelib = env.get("purelib") or ""
        if not purelib.startswith(str(self.venv)):
            raise EnvironmentInconclusive(
                "INCONCLUSIVE (environment): the interpreter did not resolve to the "
                "venv under test, so every import below was evaluated against another "
                "prefix.\n"
                f"  venv under test : {self.venv}\n"
                f"  resolved purelib: {purelib or '<unknown>'}\n"
                "  A venv whose pyvenv.cfg is missing or malformed falls back to the "
                "base prefix exactly this way.\n"
                + self.diagnostics())
        if env.get("dist_version") is None:
            raise EnvironmentInconclusive(
                f"INCONCLUSIVE (environment): pip reported success but {DIST} is not "
                "present in the venv, so the wheel's contents were never exercised.\n"
                + self.diagnostics())
        broken = {n: v for n, v in env["imports"].items() if str(v).startswith("ERROR")}
        if broken:
            case.fail(
                "FAIL (packaging): the distribution is installed and these packages "
                "are still not importable from it.\n"
                + "".join(f"  {n}: {v}\n" for n, v in broken.items())
                + self.diagnostics())

    # -- probing -------------------------------------------------------------

    def probe(self, code: str):
        """Run a probe from OUTSIDE the checkout. cwd is the workdir by design."""
        return self._run([str(self.python), "-c", code], cwd=str(self.workdir))

    def assert_probe_ok(self, case, code: str, expect: str = "OK") -> str:
        done = self.probe(code)
        if done.returncode != 0:
            case.fail("FAIL (packaging): the installed copy could not run the "
                      "documented call.\n"
                      f"  stdout : {done.stdout.strip()[:600]}\n"
                      f"  stderr : {done.stderr.strip()[:1200]}\n"
                      + self.diagnostics())
        if expect not in done.stdout:
            case.fail(f"FAIL (packaging): probe succeeded but did not print {expect!r}.\n"
                      f"  stdout : {done.stdout.strip()[:600]}\n" + self.diagnostics())
        return done.stdout

    # -- the part that makes a remote report readable ------------------------

    def diagnostics(self) -> str:
        env = self._env or {}
        lines = [
            "  --- installed consumer ---",
            f"  wheel         : {self.wheel.name}",
            f"  venv python   : {self.python}",
            f"  venv version  : {env.get('version')}",
            f"  {DIST:<13} : {env.get('dist_version') or 'NOT INSTALLED'}",
            f"  purelib       : {env.get('purelib')}",
        ]
        for name, where in (env.get("imports") or {}).items():
            lines.append(f"  import {name:<7}: {where}")
        lines.append(f"  sys.path      : {env.get('path')}")
        lines.append(f"  distributions : {env.get('installed')}")
        lines.append(f"  parent python : {sys.executable} ({sys.version.split()[0]})")
        pip = getattr(self, "_pip_output", "").strip()
        if pip:
            lines.append(f"  pip output    : {pip[:400]}")
        return "\n".join(lines) + "\n"
