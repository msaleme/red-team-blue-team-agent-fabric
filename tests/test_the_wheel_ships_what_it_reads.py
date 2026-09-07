"""Data files read at runtime must exist in an installed wheel.

`attestation.SCHEMA_PATH` was `Path(__file__).parent.parent / "schemas" / ...`.
In a source checkout that is the repo root and it works. In an installed wheel
`parent.parent` is `site-packages`, so it pointed at `site-packages/schemas/` --
a directory that does not exist and that this project has no business creating.
Every `pip install` user calling the documented `validate_attestation_report`
got an uncaught `FileNotFoundError`; the `try` caught only `ImportError`.

**The source tree cannot catch this.** Every existing test passed while the
published artifact was broken, because in a checkout the wrong path happens to
be right. So this test builds a wheel, installs it into a throwaway venv, and
runs the import from there. It is slow on purpose -- the cheap version is the
one that missed the bug for four releases.
"""
import json
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

#: Every data file the package opens at run time, as (import-relative parts).
RUNTIME_DATA = [
    ("schemas", "attestation-report.json"),
    ("schemas", "result-semantics.schema.json"),
    ("configs", "aiuc1_mapping.yaml"),
]


def _build_wheel(outdir: Path) -> Path:
    """Build from a clean tree.

    `python -m build` reuses `build/` and `*.egg-info` when they are present,
    so a wheel can be produced that reflects a PREVIOUS state of the packaging
    config. That is not hypothetical: while writing this test, deleting the
    `protocol_tests/schemas` symlink and re-running produced a green result
    from a cached wheel that still contained the file. An injected fault that
    does not reach the artifact under test proves nothing, and here it proved
    the opposite of the truth.
    """
    for stale in (REPO / "build", *REPO.glob("*.egg-info")):
        shutil.rmtree(stale, ignore_errors=True)
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "-o", str(outdir)],
        cwd=REPO, check=True, capture_output=True,
    )
    wheels = list(outdir.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"
    return wheels[0]


@unittest.skipIf(shutil.which("python3") is None, "needs a python to build with")
class TheWheelShipsWhatItReads(unittest.TestCase):
    """Built once for the class; building is the expensive part."""

    @classmethod
    def setUpClass(cls):
        try:
            import build  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("the `build` package is not installed")
        cls._tmp = tempfile.mkdtemp(prefix="wheel-ships-")
        cls.wheel = _build_wheel(Path(cls._tmp))
        cls.names = zipfile.ZipFile(cls.wheel).namelist()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def test_the_build_produced_something_to_check(self):
        """A wheel with no modules would make every assertion below vacuous."""
        modules = [n for n in self.names if n.endswith(".py")]
        self.assertGreater(len(modules), 20, "wheel looks empty; build is broken")

    def test_every_runtime_data_file_is_in_the_wheel(self):
        for parts in RUNTIME_DATA:
            with self.subTest(data="/".join(parts)):
                expected = "protocol_tests/" + "/".join(parts)
                self.assertIn(
                    expected, self.names,
                    f"{expected} is read at run time but is not in the wheel; "
                    f"an installed copy will raise FileNotFoundError",
                )

    def test_the_symlinked_data_is_a_real_file_in_the_wheel(self):
        """A symlink that shipped as a symlink would dangle after install."""
        with zipfile.ZipFile(self.wheel) as z:
            body = z.read("protocol_tests/schemas/attestation-report.json")
        self.assertGreater(len(body), 200, "schema entry is not a real file")
        json.loads(body)  # raises if it shipped as a link target string

    def test_validation_works_against_the_installed_copy(self):
        """The end-to-end property: install it and call the documented function."""
        venv = Path(self._tmp) / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                       capture_output=True)
        bindir = "Scripts" if sysconfig.get_platform().startswith("win") else "bin"
        py = venv / bindir / "python"
        subprocess.run([str(py), "-m", "pip", "-q", "install", str(self.wheel),
                        "jsonschema"], check=True, capture_output=True)
        probe = (
            "from protocol_tests.attestation import (generate_attestation_report,"
            " validate_attestation_report, SCHEMA_PATH);"
            "assert SCHEMA_PATH.exists(), f'missing: {SCHEMA_PATH}';"
            "r = generate_attestation_report(suite='s', harness_version='0.0.0',"
            " entries=[]);"
            "e = validate_attestation_report(r);"
            "assert e == [], e;"
            "print('OK')"
        )
        done = subprocess.run([str(py), "-c", probe], capture_output=True, text=True,
                              cwd=self._tmp)
        self.assertEqual(
            done.returncode, 0,
            f"the installed wheel could not validate a report it produced:\n"
            f"{done.stdout}\n{done.stderr}",
        )
        self.assertIn("OK", done.stdout)


if __name__ == "__main__":
    unittest.main()
