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
import os
import shutil
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
            # Deliberately NOT asserting a sound install first. The earlier
            # version did, and it could not run on the one host where the
            # environment was actually broken: Hermes's 2026-09-21 sentinel hit
            # the precondition and never reached the seed. A control that
            # requires a working environment cannot test a broken one, which is
            # the same defect this file exists to catch, one level up.
            (consumer.venv / "pyvenv.cfg").unlink()
            consumer._env = None
            with self.assertRaises(EnvironmentInconclusive) as caught:
                consumer.assert_landed(self, ("protocol_tests",))
        message = str(caught.exception)
        self.assertIn("INCONCLUSIVE (environment)", message)
        self.assertNotIn("FAIL (packaging)", message)
        # Either environment branch is correct here. On a host where the install
        # lands, removing pyvenv.cfg sends the interpreter to another prefix; on
        # a host where it does not, the distribution is simply absent. Both are
        # environment, neither is packaging, and pinning the exact sentence made
        # this assertion host-dependent.
        self.assertTrue(
            "did not resolve to the venv under test" in message
            or "is not present in the venv" in message, message)

    def test_an_import_from_outside_the_venv_is_not_a_landed_wheel(self):
        """Seed the worse half of the PYTHONPATH bug: a silent false pass.

        With the checkout on PYTHONPATH the nested pip skips the wheel, but the
        packages stay importable from the SOURCE TREE, and the distribution
        stays discoverable through agent_security_harness.egg-info. So the
        distribution check passes, every import succeeds, and a check keyed on
        "did it import" reports a landed wheel while the wheel sat untouched.

        Reproduced against this repo root on 2026-09-22: one test failed loudly
        and the rest passed for that reason, which is the outcome worth guarding
        against. Importable is not installed HERE.
        """
        checkout = Path(__file__).resolve().parents[1]
        self.assertTrue((checkout / "protocol_tests").is_dir(),
                        "seed requires the source tree to be importable")

        with tempfile.TemporaryDirectory() as tmp:
            consumer = InstalledConsumer(self.wheel, Path(tmp),
                                         seeded_pythonpath=str(checkout))
            with self.assertRaises(EnvironmentInconclusive) as caught:
                consumer.assert_landed(self, ("protocol_tests",))
        message = str(caught.exception)

        self.assertIn("INCONCLUSIVE (environment)", message)
        self.assertNotIn("FAIL (packaging)", message)
        self.assertIn("imported from OUTSIDE", message)
        # The report must name the path it actually resolved to, so a reader can
        # see it was the working tree rather than guess.
        self.assertIn(str(checkout / "protocol_tests"), message)

    def test_a_skipped_wheel_install_is_named_not_guessed(self):
        """Seed pip's own skip: deps install, the wheel does not, and rc is 0.

        This is the signature an external sentinel reported on 2026-09-11 and
        2026-09-21, and it went ten days unexplained because the helper ran
        `pip -q install`. The `-q` suppresses the single line that names the
        cause, so every report carried a trailing "a new release of pip is
        available" notice and nothing else.

        Seeded by making distribution metadata discoverable on the install
        interpreter's path. pip then resolves the wheel, installs its
        dependencies, declines to install the wheel itself, and exits 0.

        The assertion is on the DIAGNOSTIC, not on the cause: this test does not
        claim to know which channel any particular host used. It claims the
        failure message now carries enough to tell you.
        """
        shadow = tempfile.mkdtemp(prefix="shadow-meta-")
        self.addCleanup(shutil.rmtree, shadow, True)
        # Version is DERIVED from the wheel under test, never written here. The
        # first draft hardcoded 4.21.3 and stopped seeding the moment the release
        # PR bumped pyproject: pip saw a different version, installed the wheel
        # normally, and the seeded skip silently did not happen. A control that
        # goes quiet on a version bump is not a control.
        version = self.wheel.name.split("-")[1]
        di = Path(shadow) / f"{DIST.replace('-', '_')}-{version}.dist-info"
        di.mkdir()
        (di / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {DIST}\nVersion: {version}\n")
        (di / "RECORD").write_text("")
        (di / "INSTALLER").write_text("pip\n")

        # Seeded through the explicit constructor seam, not os.environ. On
        # 2026-09-22 the helper began stripping inherited PYTHONPATH from its
        # subprocesses -- the actual cause of the sentinel's ten-day failure --
        # and that change silently disarmed this seed: pip stopped seeing the
        # shadow metadata, installed the wheel normally, and the test passed
        # while testing nothing. The fix must not be able to switch off the
        # control that proves it was needed.
        with tempfile.TemporaryDirectory() as tmp:
            consumer = InstalledConsumer(self.wheel, Path(tmp),
                                         seeded_pythonpath=shadow)
            with self.assertRaises(AssertionError) as caught:
                consumer.assert_landed(self, ("protocol_tests",))
            report = str(caught.exception)

        # The three things the old message could not say.
        self.assertIn("already installed with the same version", report,
                      "pip's own explanation must survive into the report; "
                      "running pip with -q is what lost it")
        self.assertIn("metadata on sys.path", report)
        self.assertIn(shadow, report,
                      "the diagnostic must name WHERE the shadowing metadata is")
        self.assertIn("pyvenv.cfg", report)

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
