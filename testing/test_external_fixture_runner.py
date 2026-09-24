"""The external fixture runner reports what the checker returned, and nothing kinder.

`interop/run_external_fixture.py` runs someone else's vectors through a pinned
checker and writes a raw result bundle. Its whole value is that it cannot be
more generous than the checker was, so most of this file is controls that try
to make it be:

  positive   ABV v0.1.2 through its own reference checker reproduces the
             corpus's published result: 13/13 as specified, 3 controls accepted.
  negative   an altered expectation, an accept-everything checker, a
             reject-everything checker, a crashing checker, a checker whose own
             report contradicts the runner, a missing expectation, a missing
             reason, a corpus with no controls, and a pin that does not match.
             Each must surface as fail / inconclusive / error / NOT A RESULT /
             ABORTED, and none may be counted as a pass.

The ABV copy under `testing/fixtures/abv-v0.1.2/` is vendored (MIT, LICENSE
alongside) from tag v0.1.2 of https://github.com/msaleme/approval-binding-vectors
so the positive control runs offline. `test_vendored_corpus_is_the_published_one`
pins it to the upstream `SHA256SUMS`, whose own digest is recorded below.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "interop" / "run_external_fixture.py"
ADAPTER = REPO_ROOT / "interop" / "adapters" / "abv_reference.py"
ABV = REPO_ROOT / "testing" / "fixtures" / "abv-v0.1.2"

#: sha256 of `git show v0.1.2:SHA256SUMS` in msaleme/approval-binding-vectors.
ABV_SUMS_SHA256 = "541f72c1695ba91d777c401e7e857e64fa336e674c7dc621ec43205a977fa084"

ABV_CONTROLS = ("CTRL-01", "CTRL-02", "CTRL-03")


_BUNDLES = tempfile.TemporaryDirectory(prefix="ash-xfix-")


def tearDownModule():
    _BUNDLES.cleanup()


def run_runner(*args: str) -> tuple[subprocess.CompletedProcess, dict | None]:
    """Run the runner as a subprocess, exactly as the doc shows, and load results.json."""
    out = Path(tempfile.mkdtemp(dir=_BUNDLES.name)) / "bundle"
    cp = subprocess.run(
        [sys.executable, str(RUNNER), *args, "--out", str(out)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, check=False)
    results = out / "results.json"
    doc = json.loads(results.read_text()) if results.is_file() else None
    return cp, doc


def by_id(doc: dict) -> dict:
    return {r["id"]: r for r in doc["vectors"]}


# A checker stub with ABV's interface: verify() plus a single-file CLI that
# reports PASS/FAIL against the vector's own `expect`, as check.py does.
STUB_HEADER = textwrap.dedent('''
    import json, sys
    from pathlib import Path

    class Reject(Exception):
        def __init__(self, predicate, reason):
            super().__init__(reason)
            self.predicate, self.reason = predicate, reason
''')
STUB_CLI = textwrap.dedent('''
    if __name__ == "__main__":
        rec = json.loads(Path(sys.argv[1]).read_text())
        want = rec.get("expect", {})
        try:
            verdict, pred, reason = verify(rec)
        except Reject as r:
            verdict, pred, reason = "reject", r.predicate, r.reason
        ok = want.get("verdict") == verdict and (
            verdict == "accept" or want.get("predicate") == pred)
        print(("PASS " if ok else "FAIL ") + str(reason))
        raise SystemExit(0 if ok else 1)
''')


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ash-xfix-case-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def stub(self, body: str, cli: str = STUB_CLI) -> Path:
        path = self.tmp / "stub_check.py"
        path.write_text(STUB_HEADER + textwrap.dedent(body) + cli)
        return path

    def vectors_copy(self) -> Path:
        dest = self.tmp / "vectors"
        shutil.copytree(ABV / "vectors", dest)
        return dest


class VendoredCorpus(unittest.TestCase):
    def test_vendored_corpus_is_the_published_one(self):
        sums = (ABV / "SHA256SUMS").read_bytes()
        self.assertEqual(hashlib.sha256(sums).hexdigest(), ABV_SUMS_SHA256,
                         "SHA256SUMS is not the file published at ABV v0.1.2")
        listed = {}
        for line in sums.decode().splitlines():
            if line and not line.startswith("#"):
                digest, name = line.split(None, 1)
                listed[name.removeprefix("./")] = digest
        vendored = [p for p in ABV.rglob("*") if p.is_file() and p.name != "SHA256SUMS"]
        self.assertEqual(len(vendored), 15, "expected check.py, LICENSE and 13 vectors")
        for path in vendored:
            rel = path.relative_to(ABV).as_posix()
            with self.subTest(file=rel):
                self.assertIn(rel, listed, f"{rel} is not a published ABV file")
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), listed[rel])


class PositiveControl(unittest.TestCase):
    """The runner must reproduce the corpus's own published result."""

    @classmethod
    def setUpClass(cls):
        cls.cp, cls.doc = run_runner("--fixtures", str(ABV / "vectors"),
                                     "--adapter", str(ADAPTER),
                                     "--checker", str(ABV / "check.py"))

    def test_reproduces_13_of_13_with_3_controls_accepted(self):
        self.assertEqual(self.cp.returncode, 0, self.cp.stdout + self.cp.stderr)
        s = self.doc["summary"]
        self.assertEqual((s["vectors"], s["pass"], s["fail"], s["inconclusive"], s["error"]),
                         (13, 13, 0, 0, 0))
        self.assertEqual((s["controls_declared"], s["controls_accepted"]), (3, 3))
        self.assertTrue(s["is_result"])
        self.assertIn("13/13 vectors", self.cp.stdout)
        self.assertIn("acceptance controls: 3 of 3 declared were accepted", self.cp.stdout)

    def test_every_negative_is_matched_on_its_predicate_not_just_its_verdict(self):
        for vid, row in by_id(self.doc).items():
            with self.subTest(vector=vid):
                if vid in ABV_CONTROLS:
                    self.assertTrue(row["control"])
                    self.assertEqual(row["observed"]["verdict"], "accept")
                else:
                    self.assertFalse(row["control"])
                    self.assertEqual(row["observed"]["verdict"], "reject")
                    self.assertEqual(row["observed"]["reason_code"],
                                     row["expected"]["reason_code"])
                self.assertEqual(row["checker_self_report"], "pass")

    def test_raw_checker_output_is_kept_verbatim(self):
        row = by_id(self.doc)["NEG-P1-01"]
        self.assertEqual(row["raw"]["cli"]["stdout"].strip(),
                         "PASS P1: approved action 'deploy.apply', executed 'deploy.destroy'")

    def test_bundle_hashes_verify_and_cover_inputs_and_outputs(self):
        bundle = Path(self.cp.stdout.strip().splitlines()[-1].split("bundle: ", 1)[1])
        lines = (bundle / "SHA256SUMS").read_text().splitlines()
        names = {ln.split("  ", 1)[1]: ln.split("  ", 1)[0] for ln in lines}
        self.assertIn("results.json", names)
        self.assertIn("run.log", names)
        self.assertIn("inputs/checker/check.py", names)
        self.assertIn("inputs/adapter/abv_reference.py", names)
        self.assertEqual(sum(n.startswith("inputs/fixtures/") for n in names), 13)
        for name in ("results.json", "run.log"):
            self.assertEqual(hashlib.sha256((bundle / name).read_bytes()).hexdigest(),
                             names[name])
        self.assertEqual(names["inputs/fixtures/CTRL-01.json"],
                         hashlib.sha256((ABV / "vectors/CTRL-01.json").read_bytes()).hexdigest())

    def test_run_environment_is_recorded(self):
        for key in ("started_utc", "finished_utc"):
            self.assertRegex(self.doc[key], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertRegex(self.doc["harness"]["head"] or "", r"^[0-9a-f]{40}$")
        self.assertTrue(self.doc["environment"]["python"])
        self.assertTrue(self.doc["environment"]["platform"])
        self.assertIsNone(self.doc["checker"]["pin"], "no --checker-commit was given")


class NegativeControls(_Tmp):
    """Every way to be kinder than the checker must be visible in the result."""

    def test_an_altered_expectation_is_reported_as_a_disagreement(self):
        vectors = self.vectors_copy()
        p = vectors / "NEG-P1-01.json"
        rec = json.loads(p.read_text())
        rec["expect"]["predicate"] = "P2"          # the checker will still say P1
        p.write_text(json.dumps(rec))
        cp, doc = run_runner("--fixtures", str(vectors), "--adapter", str(ADAPTER),
                             "--checker", str(ABV / "check.py"))
        self.assertEqual(cp.returncode, 1)
        row = by_id(doc)["NEG-P1-01"]
        self.assertEqual(row["state"], "fail")
        self.assertIn("expected reject for P2, observed reject for P1", row["why"])
        self.assertEqual(doc["summary"]["pass"], 12)
        self.assertNotIn("13/13", cp.stdout)

    def test_an_altered_control_is_a_fail_and_leaves_the_count_honest(self):
        vectors = self.vectors_copy()
        p = vectors / "CTRL-01.json"
        rec = json.loads(p.read_text())
        rec["expect"] = {"verdict": "reject", "predicate": "P1"}
        p.write_text(json.dumps(rec))
        cp, doc = run_runner("--fixtures", str(vectors), "--adapter", str(ADAPTER),
                             "--checker", str(ABV / "check.py"))
        self.assertEqual(cp.returncode, 1)
        self.assertEqual(by_id(doc)["CTRL-01"]["state"], "fail")
        self.assertEqual((doc["summary"]["controls_declared"],
                          doc["summary"]["controls_accepted"]), (2, 2))

    def test_an_accept_everything_checker_fails_every_negative(self):
        stub = self.stub('''
            def verify(rec):
                return ("accept", None, "accepted without looking")
        ''')
        cp, doc = run_runner("--fixtures", str(ABV / "vectors"), "--adapter", str(ADAPTER),
                             "--checker", str(stub))
        self.assertEqual(cp.returncode, 1)
        s = doc["summary"]
        self.assertEqual((s["pass"], s["fail"], s["controls_accepted"]), (3, 10, 3))

    def test_a_reject_everything_checker_is_not_a_result(self):
        """The principle ABV's check.py states: 0 controls accepted is not a result."""
        stub = self.stub('''
            def verify(rec):
                raise Reject(rec.get("expect", {}).get("predicate", "P1"), "refused")
        ''')
        cp, doc = run_runner("--fixtures", str(ABV / "vectors"), "--adapter", str(ADAPTER),
                             "--checker", str(stub))
        self.assertEqual(cp.returncode, 2)
        s = doc["summary"]
        self.assertEqual(s["pass"], 10, "every negative 'passes' against a refuser")
        self.assertEqual(s["controls_accepted"], 0)
        self.assertFalse(s["is_result"])
        self.assertIn("NOT A RESULT", cp.stdout)

    def test_a_crashing_checker_is_an_error_never_a_pass(self):
        stub = self.stub('''
            def verify(rec):
                raise RuntimeError("checker bug")
        ''')
        cp, doc = run_runner("--fixtures", str(ABV / "vectors"), "--adapter", str(ADAPTER),
                             "--checker", str(stub))
        self.assertEqual(cp.returncode, 2)
        self.assertEqual(doc["summary"]["error"], 13)
        self.assertEqual(doc["summary"]["pass"], 0)
        self.assertIn("RuntimeError: checker bug", by_id(doc)["CTRL-01"]["raw"]["stderr"])

    def test_a_contradicting_self_report_is_an_error(self):
        """Checker says PASS about itself while its verdict disagrees with the fixture."""
        stub = self.stub('''
            def verify(rec):
                return ("accept", None, "accepted")
        ''', cli=textwrap.dedent('''
            if __name__ == "__main__":
                print("PASS looks fine to me")
        '''))
        _cp, doc = run_runner("--fixtures", str(ABV / "vectors"), "--adapter", str(ADAPTER),
                             "--checker", str(stub))
        rows = by_id(doc)
        self.assertEqual(rows["NEG-P4-01"]["state"], "error")
        self.assertIn("checker's own report says pass", rows["NEG-P4-01"]["why"])
        self.assertEqual(rows["CTRL-01"]["state"], "pass")
        self.assertEqual(doc["summary"]["error"], 10)

    def test_a_missing_reason_is_inconclusive_unless_verdict_only_is_declared(self):
        stub = self.stub('''
            def verify(rec):
                if rec.get("expect", {}).get("verdict") == "accept":
                    return ("accept", None, "ok")
                raise Reject(None, "rejected, reason unknown")
        ''')
        cp, doc = run_runner("--fixtures", str(ABV / "vectors"), "--adapter", str(ADAPTER),
                             "--checker", str(stub))
        self.assertEqual(cp.returncode, 1)
        self.assertEqual((doc["summary"]["pass"], doc["summary"]["inconclusive"]), (3, 10))

        cp, doc = run_runner("--fixtures", str(ABV / "vectors"), "--adapter", str(ADAPTER),
                             "--checker", str(stub), "--verdict-only")
        # The stub's own CLI still compares predicates and reports FAIL, so the
        # two instruments disagree; that must surface, not be averaged away.
        self.assertEqual(doc["summary"]["comparison"], "verdict-only")
        self.assertEqual(doc["summary"]["error"], 10)

    def test_a_vector_with_no_expectation_is_inconclusive(self):
        vectors = self.vectors_copy()
        p = vectors / "NEG-P2-01.json"
        rec = json.loads(p.read_text())
        del rec["expect"]
        p.write_text(json.dumps(rec))
        cp, doc = run_runner("--fixtures", str(vectors), "--adapter", str(ADAPTER),
                             "--checker", str(ABV / "check.py"))
        self.assertEqual(cp.returncode, 1)
        self.assertEqual(by_id(doc)["NEG-P2-01"]["state"], "inconclusive")

    def test_a_corpus_with_no_controls_is_not_a_result(self):
        vectors = self.vectors_copy()
        for vid in ABV_CONTROLS:
            (vectors / f"{vid}.json").unlink()
        cp, doc = run_runner("--fixtures", str(vectors), "--adapter", str(ADAPTER),
                             "--checker", str(ABV / "check.py"))
        self.assertEqual(cp.returncode, 2)
        self.assertEqual(doc["summary"]["pass"], 10)
        self.assertFalse(doc["summary"]["is_result"])
        self.assertIn("declares no positive", doc["summary"]["not_a_result_reason"])


class Pinning(_Tmp):
    def _repo_with_checker(self) -> tuple[Path, str]:
        repo = self.tmp / "checker-repo"
        repo.mkdir()
        shutil.copy(ABV / "check.py", repo / "check.py")
        git = ["git", "-C", str(repo), "-c", "user.email=t@example.invalid",
               "-c", "user.name=t", "-c", "commit.gpgsign=false"]
        subprocess.run(git[:3] + ["init", "-q"], check=True)
        subprocess.run(git + ["add", "check.py"], check=True)
        subprocess.run(git + ["commit", "-qm", "pin"], check=True)
        sha = subprocess.run(git[:3] + ["rev-parse", "HEAD"], capture_output=True,
                             text=True, check=True).stdout.strip()
        return repo, sha

    def test_a_matching_pin_is_recorded(self):
        repo, sha = self._repo_with_checker()
        cp, doc = run_runner("--fixtures", str(ABV / "vectors"), "--adapter", str(ADAPTER),
                             "--checker", str(repo / "check.py"), "--checker-commit", sha)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(doc["checker"]["pin"]["commit"], sha)

    def test_a_checker_that_differs_from_its_pin_aborts_without_a_bundle(self):
        repo, sha = self._repo_with_checker()
        with (repo / "check.py").open("a") as fh:
            fh.write("\n# edited after pinning\n")
        cp, doc = run_runner("--fixtures", str(ABV / "vectors"), "--adapter", str(ADAPTER),
                             "--checker", str(repo / "check.py"), "--checker-commit", sha)
        self.assertEqual(cp.returncode, 3)
        self.assertIsNone(doc, "an aborted run must not leave a results.json")
        self.assertIn("differs from its copy at the pinned commit", cp.stderr)

    def test_a_pin_outside_git_aborts(self):
        loose = self.tmp / "check.py"
        shutil.copy(ABV / "check.py", loose)
        cp, doc = run_runner("--fixtures", str(ABV / "vectors"), "--adapter", str(ADAPTER),
                             "--checker", str(loose), "--checker-commit", "0" * 40)
        self.assertEqual(cp.returncode, 3)
        self.assertIsNone(doc)


if __name__ == "__main__":
    unittest.main()
