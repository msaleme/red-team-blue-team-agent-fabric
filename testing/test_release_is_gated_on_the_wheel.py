"""A release must not publish a wheel nothing tested, and calibration must run.

Fourth external review, 2026-09-08 (R4-16). `publish` depended on `build` and
on nothing else. The workflow built distributions, wrote and attested a
provenance statement, and uploaded -- so it established WHO built the artifact
and that it corresponds to the tagged source, and nothing about whether the
artifact works. CI is a separate push/PR workflow whose install check runs
inside the checkout, where `import protocol_tests` can resolve to the source
tree rather than to the installed wheel; a wheel that ships nothing at all can
pass a check performed next to the sources.

Actions cannot run here, so these are static assertions on the workflow text,
in the style of `TestTheWorkflowWiring` in test_release_provenance.py. Each one
names the property it is standing in for:

    publish is unreachable unless the wheel was tested   `needs`
    the test ran outside the checkout                    `cd "$RUNNER_TEMP"`
    the R3-01 reproduction is in the release path        closed-port assertion
    the pinned calibration cannot skip quietly           junit `<skipped` gate
    fork PRs stay read-only                              permissions

A workflow assertion is weaker than an execution. It is what is available for a
job that fires on `release: published`, and the alternative -- asserting
nothing -- is how this dependency edge went missing in the first place.
"""

from __future__ import annotations

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUBLISH = REPO / ".github" / "workflows" / "publish-pypi.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"


def _load(path: Path) -> dict:
    try:
        import yaml
    except ImportError:  # pragma: no cover - environment dependent
        raise unittest.SkipTest("pyyaml not installed")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _steps(job: dict) -> list[dict]:
    return job.get("steps", [])


def _runs(job: dict) -> str:
    return "\n".join(s.get("run") or "" for s in _steps(job))


class TestPublishIsGatedOnTestingTheWheel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = _load(PUBLISH)
        cls.jobs = cls.doc["jobs"]

    def test_a_wheel_test_job_exists(self):
        self.assertIn("test-wheel", self.jobs,
                      "no job tests the built wheel; publish would gate on nothing")

    def test_publish_needs_the_wheel_test(self):
        """The edge itself. Without it the job can exist and never run."""
        needs = self.jobs["publish"]["needs"]
        needs = [needs] if isinstance(needs, str) else list(needs)
        self.assertIn("test-wheel", needs,
                      f"publish needs {needs}; a failing wheel test would not stop "
                      f"the upload")
        self.assertIn("build", needs)

    def test_the_wheel_test_consumes_the_built_artifact_not_a_fresh_build(self):
        """Testing a rebuild tests a different file than the one published."""
        job = self.jobs["test-wheel"]
        downloads = [s for s in _steps(job)
                     if "download-artifact" in (s.get("uses") or "")]
        self.assertTrue(downloads, "test-wheel builds or invents its own wheel")
        self.assertEqual(downloads[0]["with"]["name"], "dist")
        self.assertNotIn("python -m build", _runs(job),
                         "test-wheel rebuilds instead of testing what publish uploads")

    def test_the_wheel_is_installed_and_run_outside_the_checkout(self):
        """Source shadowing is the reason the CI smoke check proves less than
        it looks like it proves."""
        runs = _runs(self.jobs["test-wheel"])
        self.assertIn('cd "$RUNNER_TEMP"', runs,
                      "every step must leave the checkout before importing")
        self.assertIn("python -m venv", runs, "a fresh interpreter, not the runner's")
        self.assertIn("site-packages", runs,
                      "nothing asserts the import resolved to the installed wheel")

    def test_the_smoke_commands_are_the_documented_entry_points(self):
        runs = _runs(self.jobs["test-wheel"])
        for command in ("agent-security --version",
                        "protocol_tests.mock_mcp_server --help"):
            with self.subTest(command=command):
                self.assertIn(command, runs)

    def test_the_closed_port_reproduction_is_in_the_release_path(self):
        """R3-01: installed 4.21.0 reported 17/17 PASS against a dead port. The
        reproduction is a release gate now, not a story in a changelog."""
        runs = _runs(self.jobs["test-wheel"])
        self.assertIn("http://127.0.0.1:9", runs, "no closed-port run")
        self.assertIn("test ap2", runs, "the reproduction names no payment harness")
        self.assertIn("PASS against a port nothing listens on", runs,
                      "the closed-port run does not assert anything about passes")
        self.assertIn("unmeasured, not clean", runs,
                      "a run that produced no verdicts would read as zero passes")

    def test_packaged_behaviour_tests_run_against_the_installed_copy(self):
        runs = _runs(self.jobs["test-wheel"])
        self.assertIn("pytest", runs, "no test suite runs against the wheel")
        self.assertIn("tests/test_registry_schema_validity_is_enforced.py", runs)
        named = [line.strip().rstrip(" \\")
                 for line in runs.splitlines() if line.strip().startswith("tests/")]
        self.assertGreaterEqual(len(named), 5,
                                f"only {len(named)} packaged test file(s) run from the wheel")
        for rel in named:
            with self.subTest(test=rel):
                self.assertTrue((REPO / rel).is_file(), f"{rel} does not exist")

    def test_the_wheel_test_job_does_not_widen_permissions(self):
        self.assertEqual(self.jobs["test-wheel"].get("permissions"),
                         {"contents": "read"})


class TestTheCalibrationIsRequiredNotOptional(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = _load(CI)
        cls.jobs = cls.doc["jobs"]

    def test_a_calibration_job_exists(self):
        self.assertIn("mcp-reference-calibration", self.jobs)

    def test_it_populates_the_cache_with_the_pin_the_script_declares(self):
        """A pin typed into the workflow drifts from the pin in the script."""
        runs = _runs(self.jobs["mcp-reference-calibration"])
        self.assertIn("from scripts.mcp_reference_calibration import REFERENCE_SERVER", runs,
                      "the workflow hard-codes a version instead of reading the pin")
        self.assertIn("npx -y -p", runs, "nothing populates the npm cache")

    def test_the_pin_is_still_a_fixed_version_in_the_script(self):
        import sys
        sys.path.insert(0, str(REPO / "scripts"))
        from mcp_reference_calibration import REFERENCE_SERVER
        self.assertRegex(REFERENCE_SERVER, r"^@modelcontextprotocol/server-everything@\d{4}\.\d{1,2}\.\d{1,2}$")

    def test_a_skip_fails_the_job(self):
        """The whole finding: the calibration skips when the package is not
        cached, and a skip reads green. Unmeasured is not clean."""
        runs = _runs(self.jobs["mcp-reference-calibration"])
        self.assertIn("--junitxml", runs, "nothing records what actually ran")
        self.assertIn("<skipped", runs, "nothing inspects the run for skips")
        self.assertIn("UNMEASURED", runs.upper())
        self.assertIn("testing/test_mcp_reference_calibration.py", runs)

    def test_the_job_asserts_a_floor_on_testcases_run(self):
        """A junit file with no testcases contains no `<skipped` either."""
        self.assertIn("<testcase ", _runs(self.jobs["mcp-reference-calibration"]))

    def test_pull_request_jobs_stay_read_only(self):
        self.assertEqual(self.doc.get("permissions"), {"contents": "read"})
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                perms = job.get("permissions")
                if perms is not None:
                    self.assertEqual(perms, {"contents": "read"})

    def test_the_test_job_installs_what_the_contract_tests_need(self):
        """`pytest.importorskip` turns a missing optional dependency into a
        silent pass, and the registry contract tests are behind two of them."""
        runs = _runs(self.jobs["test"])
        for dep in ("cryptography", "jsonschema"):
            with self.subTest(dependency=dep):
                self.assertIn(dep, runs,
                              f"{dep} is not installed in CI, so every test behind "
                              f"importorskip({dep!r}) skips and reads as green")


if __name__ == "__main__":
    unittest.main()
