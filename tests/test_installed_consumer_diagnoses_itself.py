"""The installed-consumer helper must name which step failed, not just that one did.

Every test here seeds the defect first. A guard that has never been shown to
fail is not a guard.

This exists because of a real, repeated miss. An external clean-room sentinel
reported the same three installed-consumer tests failing on 2026-09-11 and again
on 2026-09-21, both times with a bare `ModuleNotFoundError`, and both times
inferred the cause as "modules absent from the installed distribution." The
wheel ships both packages, the same tests pass in CI on four Python versions,
and they pass in a clean room built to the sentinel's own recipe. The inference
was the only one available, because the assertion message carried the probe's
stderr and nothing else.

Four different causes produced one identical message. These tests assert that
they no longer can.
"""
from __future__ import annotations

import glob
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _installed_consumer import (  # noqa: E402
    DIST,
    EnvironmentInconclusive,
    InstalledConsumer,
)
from test_the_wheel_ships_what_it_reads import _build_wheel  # noqa: E402


class InstalledConsumerSeparatesItsFailureModes(unittest.TestCase):
    """Three seeded defects, three distinct verdicts, and an unseeded control."""

    @classmethod
    def setUpClass(cls):
        try:
            import build  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("the `build` package is not installed")
        cls._tmp = tempfile.mkdtemp(prefix="consumer-diag-")
        cls.wheel = _build_wheel(Path(cls._tmp))

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def test_a_failed_install_is_environment_not_packaging(self):
        """Seed: pip cannot resolve an extra. Nothing about the wheel was tested."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(EnvironmentInconclusive) as caught:
                InstalledConsumer(self.wheel, Path(tmp),
                                  ("this-package-does-not-exist-zzz",))
        message = str(caught.exception)
        self.assertIn("INCONCLUSIVE (environment)", message)
        self.assertNotIn("FAIL (packaging)", message)

    def test_a_missing_distribution_is_environment_not_packaging(self):
        """Seed: the venv exists and pip claimed success, but the dist is absent."""
        with tempfile.TemporaryDirectory() as tmp:
            consumer = InstalledConsumer(self.wheel, Path(tmp))
            consumer._env = {"dist_version": None, "imports": {},
                             "path": [], "installed": []}
            with self.assertRaises(EnvironmentInconclusive) as caught:
                consumer.assert_landed(self, ("protocol_tests",))
        message = str(caught.exception)
        self.assertIn("INCONCLUSIVE (environment)", message)
        self.assertIn(DIST, message)

    def test_an_unimportable_package_is_packaging_not_environment(self):
        """Seed: the dist IS installed and a required package still will not import."""
        with tempfile.TemporaryDirectory() as tmp:
            consumer = InstalledConsumer(self.wheel, Path(tmp))
            with self.assertRaises(AssertionError) as caught:
                consumer.assert_landed(self, ("a_module_the_wheel_does_not_ship",))
        message = str(caught.exception)
        self.assertIn("FAIL (packaging)", message)
        self.assertNotIn("INCONCLUSIVE (environment)", message)

    def test_a_venv_that_resolves_elsewhere_is_environment(self):
        """Seed: remove pyvenv.cfg. Python still runs and falls back to the base prefix.

        This is the mechanism that survives every other hypothesis for the
        2026-09-11 and 2026-09-21 sentinel failures. Run order, an injected
        pytest plugin, an inherited PYTHONPATH, three-level venv nesting and a
        3.11 interpreter with pip 24.0 were each reproduced here and each
        passed. A venv that does not resolve to itself is the remaining shape
        that produces ModuleNotFoundError from an install pip reported as
        successful.

        It is also the case that caught the first version of this helper. The
        base prefix may itself contain the distribution -- the sentinel runner
        installs the harness editable before invoking pytest -- so a check keyed
        only on the distribution being findable calls this a packaging defect.
        It is not. Nothing about the wheel was exercised.
        """
        with tempfile.TemporaryDirectory() as tmp:
            consumer = InstalledConsumer(self.wheel, Path(tmp))
            consumer.assert_landed(self, ("protocol_tests",))   # sound first
            (consumer.venv / "pyvenv.cfg").unlink()             # then seeded
            consumer._env = None
            with self.assertRaises(EnvironmentInconclusive) as caught:
                consumer.assert_landed(self, ("protocol_tests",))
        message = str(caught.exception)
        self.assertIn("INCONCLUSIVE (environment)", message)
        self.assertIn("did not resolve to the venv under test", message)
        self.assertNotIn("FAIL (packaging)", message)

    def test_the_control_passes_and_carries_diagnostics(self):
        """Unseeded. A helper that refuses every environment has diagnosed nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            consumer = InstalledConsumer(self.wheel, Path(tmp))
            consumer.assert_landed(self, ("protocol_tests", "scripts"))
            env = consumer.environment(("protocol_tests", "scripts"))
            self.assertIsNotNone(env["dist_version"],
                                 "the control must find the distribution installed")
            report = consumer.diagnostics()
        # The point of the change: a remote reader gets the venv's own state.
        for expected in ("venv python", "sys.path", "distributions", "purelib"):
            with self.subTest(field=expected):
                self.assertIn(expected, report)

    def test_diagnostics_name_the_interpreter_that_ran_the_probe(self):
        """The sentinel's environment differs from ours; the report must say how."""
        with tempfile.TemporaryDirectory() as tmp:
            consumer = InstalledConsumer(self.wheel, Path(tmp))
            consumer.assert_landed(self, ("protocol_tests",))
            report = consumer.diagnostics()
        self.assertIn("parent python", report)
        self.assertIn(sys.version.split()[0], report)


if __name__ == "__main__":
    unittest.main()
