"""The release-provenance statement and its verifier, exercised without a release.

`publish-pypi.yml` runs only on `release: published`. That is how v4.16.0 was
tagged clean and never reached PyPI: a change landed in the workflow, no push, no
PR and no scheduled job could exercise it, and the defect surfaced one release
later. Infrequent automation is unverified automation.

So the provenance logic lives in two scripts rather than in workflow YAML, and
this exercises both against synthetic distributions on every run.

The wiring is checked statically by `TestTheWorkflowWiring` below. That is not
the same as running the workflow -- nothing here proves PyPI accepts the upload
or that Sigstore issues an attestation -- but it does catch the class that broke
v4.16.0: a step referring to something that is not there.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import build_provenance  # noqa: E402
import verify_release_provenance  # noqa: E402


def _dist(tmp: Path, version: str = "9.9.9") -> Path:
    """A dist/ that is shaped like a real one. Contents are irrelevant to digests."""
    d = tmp / "dist"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"agent_security_harness-{version}-py3-none-any.whl").write_bytes(b"wheel bytes")
    (d / f"agent_security_harness-{version}.tar.gz").write_bytes(b"sdist bytes")
    return d


class TestTheStatement(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())

    def test_digests_are_the_real_sha256_of_the_files(self):
        d = _dist(self.tmp)
        st = build_provenance.build(d)
        for art in st["artifacts"]:
            expected = hashlib.sha256((d / art["filename"]).read_bytes()).hexdigest()
            self.assertEqual(art["sha256"], expected,
                             f"{art['filename']} digest is not its content hash")

    def test_version_comes_from_the_artifact_not_the_interpreter(self):
        """The statement must describe what was built, not what is importable."""
        st = build_provenance.build(_dist(self.tmp, "9.9.9"))
        self.assertEqual(st["package"]["version"], "9.9.9")

    def test_both_kinds_are_covered(self):
        st = build_provenance.build(_dist(self.tmp))
        self.assertEqual({a["kind"] for a in st["artifacts"]}, {"wheel", "sdist"})

    def test_a_dist_missing_a_kind_is_refused(self):
        """Half a release is not a release. v4.16.0 published neither."""
        d = self.tmp / "half"; d.mkdir()
        (d / "agent_security_harness-9.9.9-py3-none-any.whl").write_bytes(b"x")
        with self.assertRaises(SystemExit):
            build_provenance.build(d)

    def test_a_missing_build_tool_is_recorded_as_absent_not_omitted(self):
        tools = build_provenance.tool_versions(("setuptools", "definitely-not-installed"))
        self.assertIn("definitely-not-installed", tools)
        self.assertIsNone(tools["definitely-not-installed"])


class TestTheDirtyTreeQuestion(unittest.TestCase):
    """`tree_is_dirty` must mean modified SOURCE, not build output.

    v4.18.0rc1 failed on this and nothing in the unit tests could have caught it,
    because they build synthetic dists in a temp directory and never run
    `python -m build` in the repository. In CI the real build had already created
    `dist/`, `*.egg-info/` and `build-environment.txt` before this script ran, so
    `git status --porcelain` reported untracked files, every CI build looked
    dirty, and the verifier correctly refused a statement that was correctly
    produced.

    Tested against a throwaway repository rather than this one, so the assertion
    does not depend on whether the working tree happens to be clean right now.
    """

    def setUp(self):
        import subprocess as sp
        import tempfile
        self.repo = Path(tempfile.mkdtemp())
        run = lambda *a: sp.run(a, cwd=self.repo, capture_output=True, check=True)
        run("git", "init", "-q", ".")
        (self.repo / "tracked.txt").write_text("source\n")
        run("git", "add", "tracked.txt")
        run("git", "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "init")

    def _dirty(self) -> bool:
        return bool(build_provenance.git(
            "status", "--porcelain", "--untracked-files=no", cwd=self.repo))

    def test_untracked_build_output_does_not_make_the_tree_dirty(self):
        (self.repo / "build-environment.txt").write_text("x\n")
        (self.repo / "dist").mkdir()
        (self.repo / "dist" / "pkg.whl").write_text("x\n")
        self.assertFalse(self._dirty(),
                         "build output was counted as a modified source tree; "
                         "this is the defect that failed v4.18.0rc1")

    def test_a_modified_tracked_file_does_make_the_tree_dirty(self):
        """The positive control. A check that never fires is not a check."""
        (self.repo / "tracked.txt").write_text("source, edited\n")
        self.assertTrue(self._dirty(),
                        "a modified tracked file was not reported; the dirty-tree "
                        "check cannot detect the thing it exists for")


class TestTheVerifier(unittest.TestCase):
    """The verifier has to be able to fail. A checker that always passes is not one."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.st = build_provenance.build(_dist(self.tmp))
        self.st["source"]["commit"] = "a" * 40
        self.st["source"]["ref_name"] = None
        self.st["source"]["tree_is_dirty"] = False
        self.st["ci"]["run_id"] = "12345"
        self.st["ci"]["repository"] = "msaleme/red-team-blue-team-agent-fabric"

    def test_a_clean_ci_statement_passes_offline(self):
        self.assertEqual(verify_release_provenance.check(self.st, offline=True), [])

    def test_a_dirty_tree_fails(self):
        self.st["source"]["tree_is_dirty"] = True
        failures = verify_release_provenance.check(self.st, offline=True)
        self.assertTrue(any("dirty tree" in f for f in failures), failures)

    def test_a_statement_with_no_ci_identity_fails(self):
        """A laptop-built statement must not be indistinguishable from a CI one."""
        self.st["ci"]["run_id"] = None
        failures = verify_release_provenance.check(self.st, offline=True)
        self.assertTrue(any("not produced by a workflow" in f for f in failures), failures)

    def test_an_unknown_schema_fails(self):
        self.st["schema"] = "something/else/v0"
        failures = verify_release_provenance.check(self.st, offline=True)
        self.assertTrue(any("unknown schema" in f for f in failures), failures)

    def test_a_tag_naming_a_different_version_fails(self):
        """v4.18.0rc2 shipped 4.18.0rc1 and every check passed.

        The tag was cut, pyproject.toml was never bumped, and build, attestation,
        offline verification, PyPI upload, release assets and the post-publish
        digest comparison all agreed -- because none of them compared the tag to
        the version. A tag is the name a release is cited by; if it names a
        version the artifact does not carry, every later citation points at
        something else.
        """
        self.st["source"]["ref_name"] = "v9.9.10"      # artifacts are 9.9.9
        failures = verify_release_provenance.check(self.st, offline=True)
        self.assertTrue(any("does not match the packaged version" in f
                            for f in failures), failures)

    def test_a_tag_naming_the_shipped_version_passes(self):
        """The positive control. This must not reject a correct release."""
        self.st["source"]["ref_name"] = "v9.9.9"
        failures = [f for f in verify_release_provenance.check(self.st, offline=True)
                    if "packaged version" in f]
        self.assertEqual(failures, [])

    def test_a_non_version_ref_is_not_checked_against_the_version(self):
        """A branch name is not a claim about the version, so it is not one to break."""
        self.st["source"]["ref_name"] = "main"
        failures = [f for f in verify_release_provenance.check(self.st, offline=True)
                    if "packaged version" in f]
        self.assertEqual(failures, [])

    def test_a_statement_with_no_commit_fails(self):
        self.st["source"]["commit"] = None
        failures = verify_release_provenance.check(self.st, offline=True)
        self.assertTrue(any("names no commit" in f for f in failures), failures)


class TestTheDigestComparison(unittest.TestCase):
    """The PyPI comparison, driven without touching the network."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.st = build_provenance.build(_dist(self.tmp))
        self.st["source"].update(commit="b" * 40, ref_name=None, tree_is_dirty=False)
        self.st["ci"].update(run_id="1", repository="r")
        self._real = verify_release_provenance.fetch_pypi

    def tearDown(self):
        verify_release_provenance.fetch_pypi = self._real

    def _serve(self, files):
        verify_release_provenance.fetch_pypi = lambda name, version: {
            "urls": [{"filename": fn, "digests": {"sha256": d}} for fn, d in files.items()]}

    def test_matching_digests_pass(self):
        self._serve({a["filename"]: a["sha256"] for a in self.st["artifacts"]})
        self.assertEqual(verify_release_provenance.check(self.st, offline=False), [])

    def test_a_changed_digest_fails(self):
        served = {a["filename"]: a["sha256"] for a in self.st["artifacts"]}
        first = next(iter(served))
        served[first] = "0" * 64
        self._serve(served)
        failures = verify_release_provenance.check(self.st, offline=False)
        self.assertTrue(any("digest mismatch" in f for f in failures), failures)

    def test_a_file_on_pypi_the_statement_does_not_cover_fails(self):
        """The interesting direction. An extra published file is unaccounted for."""
        served = {a["filename"]: a["sha256"] for a in self.st["artifacts"]}
        served["agent_security_harness-9.9.9-py2-none-any.whl"] = "c" * 64
        self._serve(served)
        failures = verify_release_provenance.check(self.st, offline=False)
        self.assertTrue(any("does not cover" in f for f in failures), failures)

    def test_a_missing_file_on_pypi_fails(self):
        served = {a["filename"]: a["sha256"] for a in self.st["artifacts"]}
        served.pop(next(iter(served)))
        self._serve(served)
        failures = verify_release_provenance.check(self.st, offline=False)
        self.assertTrue(any("not published on PyPI" in f for f in failures), failures)


class TestTheScriptsRunAsCommands(unittest.TestCase):
    """They are invoked from workflow YAML, so the CLI path has to work too."""

    #: The GitHub variables `build_provenance.py` reads for CI identity. They are
    #: scrubbed or injected explicitly below rather than inherited, because the
    #: first version of this test asserted "no CI identity" and passed on a
    #: laptop for that reason alone -- then failed on all four Pythons in CI,
    #: where `GITHUB_RUN_ID` is set and the statement legitimately had one. A
    #: test whose outcome depends on where it runs is measuring the runner.
    CI_VARS = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY",
               "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF", "GITHUB_SERVER_URL",
               "GITHUB_SHA", "GITHUB_REF_NAME", "RUNNER_OS", "RUNNER_ARCH",
               "GITHUB_EVENT_NAME")

    def _run(self, argv, env_overrides):
        import os
        env = {k: v for k, v in os.environ.items() if k not in self.CI_VARS}
        env.update(env_overrides)
        return subprocess.run(argv, capture_output=True, text=True, cwd=REPO, env=env)

    def _build(self, tmp, env_overrides):
        out = tmp / "provenance.json"
        r = self._run([sys.executable, str(REPO / "scripts" / "build_provenance.py"),
                       "--dist", str(_dist(tmp)), "--out", str(out)], env_overrides)
        self.assertEqual(r.returncode, 0, r.stderr)
        return out

    def test_a_statement_built_outside_ci_is_refused(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        out = self._build(tmp, {})
        self.assertEqual(json.loads(out.read_text())["package"]["version"], "9.9.9")

        r = self._run([sys.executable, str(REPO / "scripts" / "verify_release_provenance.py"),
                       "--provenance", str(out), "--offline"], {})
        self.assertEqual(r.returncode, 1,
                         "a statement built with no CI identity passed verification; "
                         "the CI-identity check is not doing anything")
        self.assertIn("not produced by a workflow", r.stdout)

    def test_a_statement_built_inside_ci_is_accepted(self):
        """The positive control. A verifier that refuses everything is not one."""
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        # GITHUB_REF_NAME is pinned, and pinned to the version the synthetic
        # dist actually carries. Two reasons, both learned the hard way:
        #
        # Left unset, `build_provenance.py` falls back to
        # `git describe --exact-match` and picks up whatever tag this working
        # copy sits on -- which it did, the moment v4.18.0rc1 was cut on this
        # commit. A fixture that reads the surrounding repository is testing the
        # repository.
        #
        # Pinned to a placeholder like `v0.0.0-not-a-real-tag`, it then failed
        # the tag-matches-version check added after v4.18.0rc2 shipped 4.18.0rc1.
        # The check was right; a positive control has to be positive in every
        # respect, not only the one under test.
        ci = {"GITHUB_RUN_ID": "424242", "GITHUB_RUN_ATTEMPT": "1",
              "GITHUB_REPOSITORY": "msaleme/red-team-blue-team-agent-fabric",
              "GITHUB_WORKFLOW": "Publish to PyPI",
              "GITHUB_SERVER_URL": "https://github.com",
              "GITHUB_REF_NAME": "v9.9.9",   # matches _dist()
              "GITHUB_SHA": "d" * 40, "GITHUB_EVENT_NAME": "release"}
        out = self._build(tmp, ci)
        statement = json.loads(out.read_text())
        self.assertEqual(statement["ci"]["run_id"], "424242")
        self.assertEqual(statement["source"]["commit"], "d" * 40)

        # The working tree of this repository may legitimately be dirty while
        # someone is editing it; the release path never is. Assert the field is
        # reported rather than pinning it.
        statement["source"]["tree_is_dirty"] = False
        out.write_text(json.dumps(statement))

        r = self._run([sys.executable, str(REPO / "scripts" / "verify_release_provenance.py"),
                       "--provenance", str(out), "--offline"], ci)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestTheWorkflowWiring(unittest.TestCase):
    """Static checks on publish-pypi.yml, because nothing else can reach it.

    v4.16.0 failed on an upload-artifact path that produced `dist/dist/<wheel>`.
    No test could have caught it, because the workflow runs only on
    `release: published`. These assertions cover the same class -- a step that
    references something absent -- for the steps added since.
    """

    WORKFLOW = REPO / ".github" / "workflows" / "publish-pypi.yml"

    @classmethod
    def setUpClass(cls):
        cls.text = cls.WORKFLOW.read_text(encoding="utf-8")
        try:
            import yaml
        except ImportError:                      # pragma: no cover - env-dependent
            raise unittest.SkipTest("pyyaml not installed")
        cls.doc = yaml.safe_load(cls.text)

    def test_every_script_the_workflow_runs_exists(self):
        import re
        referenced = set(re.findall(r"python (scripts/[\w./-]+\.py)", self.text))
        self.assertTrue(referenced, "no scripts referenced; the regex is wrong, not the workflow")
        for rel in sorted(referenced):
            with self.subTest(script=rel):
                self.assertTrue((REPO / rel).exists(),
                                f"publish-pypi.yml runs {rel}, which does not exist")

    def test_a_job_that_runs_a_repo_script_checks_the_repo_out(self):
        """The defect I introduced writing this, caught before it shipped."""
        for name, job in self.doc["jobs"].items():
            steps = job.get("steps", [])
            runs_script = any("python scripts/" in (s.get("run") or "") for s in steps)
            if not runs_script:
                continue
            with self.subTest(job=name):
                self.assertTrue(
                    any("actions/checkout" in (s.get("uses") or "") for s in steps),
                    f"job {name!r} runs a repository script but never checks the "
                    f"repository out")

    def test_the_permissions_the_new_steps_need_are_granted(self):
        perms = self.doc.get("permissions", {})
        self.assertEqual(perms.get("attestations"), "write",
                         "attest-build-provenance needs attestations: write")
        self.assertEqual(perms.get("id-token"), "write",
                         "Sigstore and PyPI trusted publishing both need id-token: write")
        self.assertEqual(perms.get("contents"), "write",
                         "attaching assets to the Release needs contents: write")

    def test_non_docker_actions_are_pinned_to_a_sha(self):
        import re
        for uses in re.findall(r"uses: (\S+)", self.text):
            if uses.startswith("pypa/gh-action-pypi-publish"):
                continue                          # docker action; needs a tag ref
            with self.subTest(uses=uses):
                ref = uses.split("@")[-1]
                self.assertRegex(ref, r"^[0-9a-f]{40}$",
                                 f"{uses} is not pinned to a commit SHA")

    def test_the_statement_is_verified_before_and_after_publishing(self):
        """Once is not enough: offline before, against PyPI after.

        The pre-publish run cannot compare digests -- nothing is published yet --
        and the post-publish run is the only one that can. Dropping either leaves
        a claim unchecked.
        """
        runs = [s.get("run") or "" for j in self.doc["jobs"].values()
                for s in j.get("steps", [])]
        verifications = [r for r in runs if "verify_release_provenance.py" in r]
        self.assertEqual(len(verifications), 2,
                         f"expected an offline check before publish and a digest "
                         f"check after; found {len(verifications)}")
        self.assertTrue(any("--offline" in r for r in verifications))
        self.assertTrue(any("--offline" not in r for r in verifications))


if __name__ == "__main__":
    unittest.main()
