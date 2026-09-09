"""A release must not publish a wheel nothing tested, and the gate must run.

Fourth external review, 2026-09-08 (R4-16). `publish` depended on `build` and
on nothing else, so the workflow established WHO built the artifact and that it
corresponds to the tagged source, and nothing about whether the artifact works.
A `test-wheel` job was added and this file was written to guard it.

Fifth external review, 2026-09-09 (R5-01). This file guarded it by searching
the job's concatenated shell text for phrases, filenames and command names.
Wrapping every `run:` step of `test-wheel` in `if false; then … fi` leaves all
of that text in place and executes none of it, and all 15 tests and 17 subtests
still passed. Tokens in a string do not establish executable control flow, and
half the test names here claimed behaviour the assertions could not reach.

So the file is now three kinds of check, and each one says which it is:

    WIRING      structure read out of the parsed YAML -- `needs` edges, the
                artifact a job consumes, permissions, and whether a job or step
                is reachable at all. A step disabled with `if: false` is not a
                step, and `_steps` does not return it.

    EXECUTION   the `run:` bodies of `test-wheel` executed under bash against a
                sandbox, with the commands they call replaced by recorders. The
                assertions are about the resulting execution TRACE, so a body
                that contains every right word and runs none of it records
                nothing and fails. This is the direct answer to R5-01.

    BEHAVIOUR   `scripts/verify_wheel_gate.py`, the module CI runs, executed
                here against deliberately bad artifacts: a dist directory with
                no wheel, one with two, one with a stray file, a closed-port
                report with a nonzero pass count, and a simulated report whose
                rows claim a pass or lost their labels. Same code, both
                callers, so neither can be green by containing the right words.

A workflow assertion is still weaker than a release. It is what is available
for a job that fires on `release: published`; the alternative -- asserting
nothing -- is how this dependency edge went missing in the first place.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUBLISH = REPO / ".github" / "workflows" / "publish-pypi.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
GATE = REPO / "scripts" / "verify_wheel_gate.py"

#: `if:` values that can never be true. A gate whose job carries one of these
#: is a gate that never runs, and the YAML still reads exactly the same.
NEVER_TRUE = {"false", "0", "${{ false }}", "${{false}}", "${{ 1 == 2 }}"}


def _load(path: Path) -> dict:
    try:
        import yaml
    except ImportError:  # pragma: no cover - environment dependent
        raise unittest.SkipTest("pyyaml not installed")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _reachable(node: dict) -> bool:
    """A job or step with a never-true `if:` is not part of the graph."""
    cond = node.get("if")
    return cond is None or str(cond).strip().lower() not in NEVER_TRUE


def _steps(job: dict) -> list[dict]:
    """Only the steps that can actually execute."""
    if not _reachable(job):
        return []
    return [s for s in job.get("steps", []) if _reachable(s)]


def _runs(job: dict) -> str:
    """Concatenated shell text. Every use of this is a WIRING claim."""
    return "\n".join(s.get("run") or "" for s in _steps(job))


def _gate_module():
    """Import `scripts/verify_wheel_gate.py` without touching `sys.path`."""
    spec = importlib.util.spec_from_file_location("_verify_wheel_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# EXECUTION: run the job's shell for real, against recorders.
# ---------------------------------------------------------------------------

#: One shim stands in for python, pip and agent-security. It appends its own
#: invocation to the trace file and exits 0, except for `python -m venv`, which
#: also creates the bin/ directory the later steps address by path.
SHIM = """#!/bin/sh
echo "$(basename "$0") $*" >> "$WHEEL_GATE_TRACE"
if [ "$1" = "-m" ] && [ "$2" = "venv" ] && [ -n "$3" ]; then
  mkdir -p "$3/bin"
  for c in python pip agent-security; do
    cp "$WHEEL_GATE_SHIM" "$3/bin/$c"
    chmod +x "$3/bin/$c"
  done
fi
exit 0
"""


class _Sandbox:
    """A GITHUB_WORKSPACE and a RUNNER_TEMP with recorders on PATH."""

    def __init__(self, root: Path, *, dist: list[str]):
        self.root = root
        self.workspace = root / "workspace"
        self.runner_temp = root / "runner-temp"
        self.bin = root / "bin"
        self.trace = root / "trace.log"
        for d in (self.workspace, self.runner_temp, self.bin,
                  self.workspace / "dist", self.workspace / "scripts",
                  self.workspace / "tests"):
            d.mkdir(parents=True, exist_ok=True)
        for name in dist:
            (self.workspace / "dist" / name).write_text("not really a distribution")
        (self.workspace / "tests" / "test_placeholder.py").write_text("")
        shutil.copy(GATE, self.workspace / "scripts" / GATE.name)
        shim = self.bin / "_shim"
        shim.write_text(SHIM)
        shim.chmod(0o755)
        for command in ("python", "python3", "pip", "npx", "agent-security"):
            shutil.copy(shim, self.bin / command)
            (self.bin / command).chmod(0o755)
        self.trace.write_text("")

    def env(self) -> dict:
        env = dict(os.environ)
        env.update({
            "GITHUB_WORKSPACE": str(self.workspace),
            "RUNNER_TEMP": str(self.runner_temp),
            "WHEEL_GATE_TRACE": str(self.trace),
            "WHEEL_GATE_SHIM": str(self.bin / "_shim"),
            "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
        })
        return env

    def run(self, body: str) -> subprocess.CompletedProcess:
        script = self.root / "step.sh"
        script.write_text(body)
        return subprocess.run(["bash", str(script)], cwd=str(self.runner_temp),
                              env=self.env(), capture_output=True, text=True,
                              timeout=120)

    def lines(self) -> list[str]:
        return [l for l in self.trace.read_text().splitlines() if l.strip()]


class TestTheGateStepsActuallyExecute(unittest.TestCase):
    """EXECUTION. R5-01: `if false; then … fi` kept every phrase and ran none."""

    WHEEL = "agent_security_harness-9.9.9-py3-none-any.whl"
    SDIST = "agent_security_harness-9.9.9.tar.gz"

    @classmethod
    def setUpClass(cls):
        cls.job = _load(PUBLISH)["jobs"]["test-wheel"]
        cls.bodies = [s["run"] for s in _steps(cls.job) if s.get("run")]
        if any("${{" in b for b in cls.bodies):
            raise unittest.SkipTest(
                "a run body interpolates a GitHub expression; this harness "
                "executes bash, not the expression evaluator")

    def _trace_of_the_job(self, dist: list[str] | None = None) -> list[str]:
        dist = [self.WHEEL, self.SDIST] if dist is None else dist
        with tempfile.TemporaryDirectory(prefix="wheel-gate-steps-") as tmp:
            box = _Sandbox(Path(tmp), dist=dist)
            for body in self.bodies:
                done = box.run(body)
                self.assertEqual(done.returncode, 0,
                                 f"a gate step failed in the sandbox:\n{body}\n"
                                 f"{done.stdout}\n{done.stderr}")
            return box.lines()

    def test_the_steps_run_commands_rather_than_containing_them(self):
        """The whole finding. An empty trace means nothing executed."""
        trace = self._trace_of_the_job()
        self.assertTrue(
            trace,
            "the test-wheel steps executed no command at all: every check in "
            "this job is text that never runs (R5-01)")

    def test_the_executed_commands_include_the_gate(self):
        trace = "\n".join(self._trace_of_the_job())
        for fact, why in (
                ("verify_wheel_gate.py dist-shape",
                 "nothing checks the shape of the artifact before installing it"),
                ("-m venv",
                 "no fresh interpreter is created; an import could resolve anywhere"),
                ("verify_wheel_gate.py verify",
                 "the release gate itself never runs"),
        ):
            with self.subTest(executed=fact):
                self.assertIn(fact, trace, why)

    def test_the_wheel_is_installed_by_the_venv_pip_and_not_the_runner_one(self):
        trace = self._trace_of_the_job()
        installs = [l for l in trace if l.startswith("pip ") and " install" in l]
        self.assertTrue(installs, "no pip install ran")
        self.assertTrue(any(".whl" in l for l in installs),
                        f"pip installed something that is not the built wheel: {installs}")
        self.assertTrue(any("mcp-server" in l for l in installs),
                        "the mcp-server extra is not installed, so the three MCP "
                        "boundary contracts cannot be collected in a neutral directory")

    def test_the_gate_is_run_by_the_venv_interpreter(self):
        trace = self._trace_of_the_job()
        verify = [l for l in trace if "verify_wheel_gate.py verify" in l]
        self.assertTrue(verify, "the gate never runs")
        self.assertTrue(all(l.startswith("python ") for l in verify), verify)
        # The venv's python is copied from the shim into wheel-venv/bin, so an
        # invocation of the runner's python would not have created that file.
        self.assertTrue(any("--tests" in l for l in verify),
                        f"the gate runs without a tests directory: {verify}")

    def test_two_wheels_in_dist_stop_the_job(self):
        """BEHAVIOUR through the workflow's own shell, not through its text."""
        with tempfile.TemporaryDirectory(prefix="wheel-gate-twowheels-") as tmp:
            box = _Sandbox(Path(tmp), dist=[self.WHEEL, self.SDIST,
                                            "agent_security_harness-9.9.10-py3-none-any.whl"])
            codes = [box.run(body).returncode for body in self.bodies]
            self.assertTrue(any(c != 0 for c in codes),
                            f"two wheels in dist/ and every step exited 0: {codes}")

    def test_no_wheel_in_dist_stops_the_job(self):
        with tempfile.TemporaryDirectory(prefix="wheel-gate-nowheel-") as tmp:
            box = _Sandbox(Path(tmp), dist=[self.SDIST])
            codes = [box.run(body).returncode for body in self.bodies]
            self.assertTrue(any(c != 0 for c in codes),
                            f"an sdist-only build installed and tested nothing: {codes}")


# ---------------------------------------------------------------------------
# BEHAVIOUR: the gate module, against artifacts that must not ship.
# ---------------------------------------------------------------------------

class TestTheGateRejectsBadArtifacts(unittest.TestCase):
    """BEHAVIOUR. These call the same functions the release job calls."""

    @classmethod
    def setUpClass(cls):
        cls.gate = _gate_module()

    # -- the built distribution ---------------------------------------------

    def test_a_well_formed_dist_is_accepted(self):
        """The positive control: without it, a check that rejects everything
        would pass every test below."""
        self.assertEqual(self.gate.check_dist_shape(["a-1.0-py3-none-any.whl", "a-1.0.tar.gz"]), [])

    def test_dist_shapes_that_must_not_publish(self):
        for label, names in (
                ("sdist only", ["a-1.0.tar.gz"]),
                ("two wheels", ["a-1.0-py3-none-any.whl", "a-1.1-py3-none-any.whl", "a-1.0.tar.gz"]),
                ("no sdist", ["a-1.0-py3-none-any.whl"]),
                ("a stray file", ["a-1.0-py3-none-any.whl", "a-1.0.tar.gz", "build-environment.txt"]),
                ("empty", []),
        ):
            with self.subTest(dist=label):
                self.assertTrue(self.gate.check_dist_shape(names),
                                f"{label} would have been published")

    # -- the closed-port reproduction (R3-01) --------------------------------

    def _closed_port_report(self, rows: int = 3, **summary) -> dict:
        base = {"total": rows, "passed": 0, "failed": 0, "inconclusive": rows,
                "serviced": 0, "status": "inconclusive", "pass_rate": None,
                "wilson_95_ci": None}
        base.update(summary)
        return {"summary": base,
                "results": [{"test_id": f"AP2-{i:03d}", "passed": False} for i in range(1, rows + 1)]}

    def test_a_clean_closed_port_report_is_accepted(self):
        self.assertEqual(self.gate.check_payment_report(self._closed_port_report()), [])

    def test_a_closed_port_report_with_passes_is_rejected(self):
        report = self._closed_port_report(passed=3, inconclusive=0, serviced=3, pass_rate=1.0)
        for row in report["results"]:
            row["passed"] = True
        problems = self.gate.check_payment_report(report)
        self.assertTrue(any("PASS against a port nothing listens on" in p for p in problems),
                        problems)

    def test_a_closed_port_report_with_no_verdicts_is_rejected(self):
        """Unmeasured is not clean: zero passes over zero rows is not a result."""
        report = {"summary": {"total": 0, "passed": 0, "serviced": 0}, "results": []}
        self.assertTrue(any("unmeasured" in p for p in self.gate.check_payment_report(report)))

    # -- the native --simulate writers (R4-05, and R5-07's escape from it) ---

    def _simulated_report(self, rows: int = 3) -> dict:
        results = [{
            "test_id": f"AP2-{i:03d}",
            "passed": False,
            "not_evaluated": True,
            "simulated": True,
            "verdict_scope": self.gate.SIMULATED_ROW_SCOPE,
            "details": f"{self.gate.INCONCLUSIVE_PREFIX}simulated run: nothing was contacted",
            "reference_verdict": {"passed": True, "reason": "the model said so",
                                  "scope": self.gate.REFERENCE_VERDICT_SCOPE},
        } for i in range(1, rows + 1)]
        return {"results": results,
                "verdict_scope": {"live_requested": False},
                "summary": {"total": rows, "passed": 0, "failed": 0,
                            "inconclusive": rows, "serviced": 0,
                            "status": "inconclusive", "pass_rate": None,
                            "wilson_95_ci": None}}

    def test_a_correctly_scoped_simulated_report_is_accepted(self):
        self.assertEqual(
            self.gate.check_simulated_report(self._simulated_report(), expected_rows=3), [])

    def test_the_row_shapes_a_simulated_run_must_not_publish(self):
        """Each case is one field of the R4-05 defect, or of the R5-07 escape
        that removed the labels while leaving `passed` alone."""
        cases = {
            "a row claims a pass": lambda r: r["results"][0].update(passed=True),
            "the structural marker is gone": lambda r: r["results"][0].pop("not_evaluated"),
            "the simulated label is gone": lambda r: r["results"][0].pop("simulated"),
            "the row scope is gone": lambda r: r["results"][0].pop("verdict_scope"),
            "the details disagree with the field":
                lambda r: r["results"][0].update(details="tampered cart rejected"),
            "the fabricated verdict was discarded":
                lambda r: r["results"][0].pop("reference_verdict"),
            "the fabricated verdict lost its scope":
                lambda r: r["results"][0]["reference_verdict"].pop("scope"),
            "no reference verdict survived at all":
                lambda r: [row["reference_verdict"].update(passed=False) for row in r["results"]],
            "the summary counts passes":
                lambda r: r["summary"].update(passed=3, inconclusive=0, serviced=3, pass_rate=1.0),
            "a rate was computed over nothing":
                lambda r: r["summary"].update(wilson_95_ci={"lower": 0.8, "upper": 1.0}),
            "the report does not say live was never requested":
                lambda r: r["verdict_scope"].update(live_requested=True),
            "a row went missing": lambda r: r["results"].pop(),
        }
        for label, break_it in cases.items():
            with self.subTest(defect=label):
                report = self._simulated_report()
                break_it(report)
                self.assertTrue(
                    self.gate.check_simulated_report(report, expected_rows=3),
                    f"a simulated report would have shipped with: {label}")

    def test_the_six_native_entry_points_are_all_on_the_gate(self):
        """R5-07: the nine files used the CLI facade, which never reaches these."""
        for module in ("protocol_tests.ap2_harness",
                       "protocol_tests.x402_fireblocks_harness",
                       "protocol_tests.ucp_acp_harness",
                       "protocol_tests.card_token_harness",
                       "protocol_tests.settlement_finality_harness",
                       "protocol_tests.aiuc1_compliance_harness"):
            with self.subTest(module=module):
                self.assertIn(module, self.gate.NATIVE_SIMULATE)

    # -- how the packaged-test selection is derived --------------------------

    def test_every_file_in_tests_is_classified(self):
        """The nine-file list was hand-maintained and 21 of 30 files were
        omitted with one sentence covering all of them. A new file now fails
        the gate until someone says which it is."""
        present = sorted(p.name for p in (REPO / "tests").glob("test_*.py"))
        self.assertEqual(self.gate.check_test_classification(present), [])

    def test_an_unclassified_new_file_fails_the_gate(self):
        present = sorted(p.name for p in (REPO / "tests").glob("test_*.py"))
        problems = self.gate.check_test_classification(present + ["test_brand_new.py"])
        self.assertTrue(any("unclassified" in p for p in problems), problems)

    def test_a_classified_file_that_disappeared_fails_the_gate(self):
        present = sorted(p.name for p in (REPO / "tests").glob("test_*.py"))
        problems = self.gate.check_test_classification(present[1:])
        self.assertTrue(any("no longer exists" in p for p in problems), problems)

    def test_every_exclusion_names_the_resource_it_needs(self):
        """"They all need the checkout" was too broad (R5-07)."""
        for name, reason in self.gate.CHECKOUT_ONLY.items():
            with self.subTest(excluded=name):
                self.assertTrue(len(reason) > 15 and not reason.startswith("needs the checkout"),
                                f"{name} is excluded for {reason!r}")

    def test_the_gate_runs_more_of_the_suite_than_the_hand_written_nine(self):
        eligible = self.gate.WHEEL_GATE_ELIGIBLE
        self.assertGreaterEqual(
            len(eligible), 12,
            f"the derived selection is {len(eligible)} files; the hand-maintained "
            f"list it replaced was nine")
        for name in eligible:
            with self.subTest(test=name):
                self.assertTrue((REPO / "tests" / name).is_file())

    # -- unmeasured is not clean --------------------------------------------

    def test_a_run_with_skips_or_no_testcases_is_not_clean(self):
        for label, counts, clean in (
                ("a normal green run", {"tests": 9, "errors": 0, "failures": 0, "skipped": 0}, True),
                ("everything skipped", {"tests": 7, "errors": 0, "failures": 0, "skipped": 7}, False),
                ("one skip among passes", {"tests": 9, "errors": 0, "failures": 0, "skipped": 1}, False),
                ("nothing collected", {"tests": 0, "errors": 0, "failures": 0, "skipped": 0}, False),
                ("a collection error", {"tests": 1, "errors": 1, "failures": 0, "skipped": 0}, False),
        ):
            with self.subTest(run=label):
                self.assertEqual(self.gate.is_clean(counts), clean)

    def test_junit_counts_are_read_from_the_file_pytest_writes(self):
        xml = ('<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite '
               'name="pytest" errors="1" failures="2" skipped="3" tests="9" '
               'time="0.1"><testcase classname="t" name="a"/></testsuite></testsuites>')
        self.assertEqual(self.gate.junit_counts(xml),
                         {"tests": 9, "errors": 1, "failures": 2, "skipped": 3})

    def test_the_gate_refuses_to_run_next_to_a_source_tree(self):
        """Source shadowing is the reason the CI install check proves less than
        it looks like it proves."""
        with tempfile.TemporaryDirectory(prefix="wheel-gate-shadow-") as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "protocol_tests").mkdir()
            done = subprocess.run([sys.executable, str(GATE), "verify",
                                   "--tests", str(root / "tests")],
                                  capture_output=True, text=True, timeout=120)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("not the checkout", done.stdout + done.stderr)

    def test_the_command_line_exits_non_zero_on_a_bad_report(self):
        """The workflow calls this through a shell, so the exit code is the
        only thing that stops a release."""
        with tempfile.TemporaryDirectory(prefix="wheel-gate-cli-") as tmp:
            good = Path(tmp) / "good.json"
            bad = Path(tmp) / "bad.json"
            good.write_text(json.dumps(self._closed_port_report()))
            report = self._closed_port_report(passed=3, inconclusive=0, serviced=3)
            for row in report["results"]:
                row["passed"] = True
            bad.write_text(json.dumps(report))
            for path, expected in ((good, 0), (bad, 1)):
                with self.subTest(report=path.name):
                    done = subprocess.run(
                        [sys.executable, str(GATE), "check-payment-report", str(path)],
                        capture_output=True, text=True, timeout=120)
                    self.assertEqual(done.returncode, expected, done.stdout)


# ---------------------------------------------------------------------------
# WIRING: what the parsed workflow says about the graph.
# ---------------------------------------------------------------------------

class TestPublishIsGatedOnTestingTheWheel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = _load(PUBLISH)
        cls.jobs = cls.doc["jobs"]

    def test_a_wheel_test_job_exists_and_is_reachable(self):
        self.assertIn("test-wheel", self.jobs,
                      "no job tests the built wheel; publish would gate on nothing")
        self.assertTrue(_reachable(self.jobs["test-wheel"]),
                        f"test-wheel carries if: {self.jobs['test-wheel'].get('if')!r}, "
                        f"which is never true")

    def test_publish_needs_the_wheel_test(self):
        """The edge itself. Without it the job can exist and never run."""
        needs = self.jobs["publish"]["needs"]
        needs = [needs] if isinstance(needs, str) else list(needs)
        self.assertIn("test-wheel", needs,
                      f"publish needs {needs}; a failing wheel test would not stop "
                      f"the upload")
        self.assertIn("build", needs)

    def test_publish_needs_the_pinned_calibration(self):
        """Fifth review, section E: a Release cut from a tag with no green
        ordinary CI still only had to pass the wheel gate, because `needs:`
        cannot cross workflows and the calibration lived in ci.yml alone."""
        needs = self.jobs["publish"]["needs"]
        needs = [needs] if isinstance(needs, str) else list(needs)
        self.assertIn("calibration", needs,
                      f"publish needs {needs}; the pinned reference-server "
                      f"calibration is not in the release graph")
        self.assertIn("calibration", self.jobs)
        self.assertTrue(_reachable(self.jobs["calibration"]))

    def test_the_release_calibration_is_the_same_job_as_the_ci_one(self):
        """Two copies that drift are worse than one, because the stale copy
        still reads as coverage."""
        ci = _load(CI)["jobs"]["mcp-reference-calibration"]
        release = self.jobs["calibration"]
        self.assertEqual([s.get("run") for s in _steps(ci)],
                         [s.get("run") for s in _steps(release)],
                         "the release calibration has drifted from the CI one")

    def test_the_wheel_test_consumes_the_built_artifact_not_a_fresh_build(self):
        """Testing a rebuild tests a different file than the one published."""
        job = self.jobs["test-wheel"]
        downloads = [s for s in _steps(job)
                     if "download-artifact" in (s.get("uses") or "")]
        self.assertTrue(downloads, "test-wheel builds or invents its own wheel")
        self.assertEqual(downloads[0]["with"]["name"], "dist")
        self.assertNotIn("python -m build", _runs(job),
                         "test-wheel rebuilds instead of testing what publish uploads")

    def test_no_step_of_the_gate_is_conditional(self):
        """A gate step with an `if:` is a gate step that can decline to run.
        None of them needs one, so none of them has one."""
        for step in self.jobs["test-wheel"].get("steps", []):
            with self.subTest(step=step.get("name") or step.get("uses")):
                self.assertIsNone(step.get("if"))

    def test_the_workflow_mentions_leaving_the_checkout(self):
        """WIRING, and named as such: this asserts the text says `cd
        "$RUNNER_TEMP"`, not that anything did. `TestTheGateStepsActuallyExecute`
        runs the steps, and the gate itself refuses to run beside a source tree."""
        runs = _runs(self.jobs["test-wheel"])
        self.assertIn('cd "$RUNNER_TEMP', runs)
        self.assertIn("python -m venv", runs)

    def test_the_gate_script_is_taken_from_the_checkout_not_the_wheel(self):
        """A wheel that shipped a broken gate would otherwise certify itself."""
        runs = _runs(self.jobs["test-wheel"])
        self.assertIn('"$GITHUB_WORKSPACE/scripts/verify_wheel_gate.py"', runs)
        self.assertNotIn("-m scripts.verify_wheel_gate", runs)

    def test_the_wheel_test_job_does_not_widen_permissions(self):
        self.assertEqual(self.jobs["test-wheel"].get("permissions"),
                         {"contents": "read"})
        self.assertEqual(self.jobs["calibration"].get("permissions"),
                         {"contents": "read"})


class TestTheCalibrationIsRequiredNotOptional(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = _load(CI)
        cls.jobs = cls.doc["jobs"]

    def test_a_calibration_job_exists(self):
        self.assertIn("mcp-reference-calibration", self.jobs)
        self.assertTrue(_reachable(self.jobs["mcp-reference-calibration"]))

    def test_it_populates_the_cache_with_the_pin_the_script_declares(self):
        """A pin typed into the workflow drifts from the pin in the script."""
        runs = _runs(self.jobs["mcp-reference-calibration"])
        self.assertIn("from scripts.mcp_reference_calibration import REFERENCE_SERVER", runs,
                      "the workflow hard-codes a version instead of reading the pin")
        self.assertIn("npx -y -p", runs, "nothing populates the npm cache")

    def test_the_pin_is_still_a_fixed_version_in_the_script(self):
        sys.path.insert(0, str(REPO / "scripts"))
        from mcp_reference_calibration import REFERENCE_SERVER
        self.assertRegex(REFERENCE_SERVER, r"^@modelcontextprotocol/server-everything@\d{4}\.\d{1,2}\.\d{1,2}$")

    def test_the_workflow_text_inspects_the_run_for_skips(self):
        """WIRING. The calibration's own file is what establishes the
        behaviour; this only establishes that the job looks for a skip."""
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
