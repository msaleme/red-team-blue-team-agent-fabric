"""The reference registry must refuse to validate without its schema, and
must find that schema on an installed copy.

Third external review, 2026-09-07 (R3-04). `scripts/registry_reference_server.py`
resolved `REPO_ROOT / "schemas" / "attestation-report.json"` -- a path that
exists only in a checkout. `load_schema_required()` returned `[]` on the
OSError. So on the installed wheel the required-key check (contract 5.5) had
nothing to check, and a submission whose `payload.report` was `{}` came back
201 with a record labelled "Tested with Agent Security Harness". The same
input in a checkout was rejected 422.

Two properties, pinned separately:
  (a) missing validation configuration is a refusal, never "no requirements";
  (b) the schema resolves from an installed wheel, built the way the publish
      workflow builds it (`python -m build`, no flags), called from OUTSIDE
      the checkout.

(b) is slow on purpose. Every in-checkout test passed while the installed
artifact accepted an empty report.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.registry_reference_server as srv  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def _empty_report_submission():
    payload = {"server_name": "demo-server", "contact": None, "report": {},
               "published_at": "2026-09-07T00:00:00Z"}
    return {
        "payload": payload,
        "signature": "00" * 64,
        "verification_hash": hashlib.sha256(srv.canonical_bytes(payload)).hexdigest(),
    }


class MissingConfigurationIsARefusal(unittest.TestCase):
    def test_loader_refuses_a_nonexistent_schema_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "attestation-report.json"
            self.assertFalse(missing.exists())
            with self.assertRaises(srv.SchemaUnavailable):
                srv.load_schema_required(missing)

    def test_loader_refuses_a_schema_with_no_required_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "attestation-report.json"
            p.write_text(json.dumps({"type": "object"}))
            with self.assertRaises(srv.SchemaUnavailable):
                srv.load_schema_required(p)
            p.write_text("{not json")
            with self.assertRaises(srv.SchemaUnavailable):
                srv.load_schema_required(p)

    def test_loader_never_returns_an_empty_list(self):
        """The old contract: `[]` on failure. There is no input for which the
        loader now returns `[]`; it either returns the schema's list or raises."""
        req = srv.load_schema_required()
        self.assertTrue(req, "the shipped schema must declare required keys")
        self.assertIn("entries", req)

    def test_validator_refuses_an_empty_requirement_list_rather_than_accepting(self):
        """Defence at the point of use: even a caller that hands the validator
        `[]` does not get a record. The old code accepted the empty report."""
        with self.assertRaises(srv.SchemaUnavailable):
            srv.validate_and_build(_empty_report_submission(), [])
        with self.assertRaises(srv.SchemaUnavailable):
            srv.validate_and_build(_empty_report_submission(), None)

    def test_empty_report_is_rejected_422_with_the_real_schema(self):
        with self.assertRaises(srv.Rejected) as ctx:
            srv.validate_and_build(_empty_report_submission(), srv.load_schema_required())
        self.assertEqual(ctx.exception.status, 422)
        self.assertIn("schema-required keys", ctx.exception.reason)

    def test_the_server_refuses_to_start_when_the_schema_is_missing(self):
        """`build_server` loads the schema once; a server that started with no
        requirements would issue the claim label on anything."""
        original = srv.SCHEMA_PATH
        with tempfile.TemporaryDirectory() as tmp:
            srv.SCHEMA_PATH = Path(tmp) / "nope.json"
            try:
                with self.assertRaises(srv.SchemaUnavailable):
                    srv.build_server(0)
            finally:
                srv.SCHEMA_PATH = original

    def test_a_handler_with_no_requirements_answers_503_never_201(self):
        """If the requirement list is emptied after start, the POST path still
        does not issue a record."""
        import threading
        import urllib.error
        import urllib.request
        httpd = srv.build_server(0)
        saved = srv.Handler.required_keys
        srv.Handler.required_keys = []
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            body = json.dumps(_empty_report_submission()).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{httpd.server_address[1]}/", data=body,
                headers={"Content-Type": "application/json"}, method="POST")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(ctx.exception.code, 503)
        finally:
            srv.Handler.required_keys = saved
            httpd.shutdown()
            httpd.server_close()

    def test_the_schema_is_resolved_through_the_package_resolver(self):
        src = (REPO / "scripts" / "registry_reference_server.py").read_text()
        self.assertIn('_data_path("schemas", "attestation-report.json")', src)
        self.assertNotIn('REPO_ROOT / "schemas"', src, "checkout-only path came back")
        self.assertNotIn("return []", src, "the empty-list fallback came back")


class TheInstalledRegistryRejectsAnEmptyReport(unittest.TestCase):
    """(b). Same pattern as tests/test_the_wheel_ships_what_it_reads.py:
    `python -m build` with no flags (sdist, then wheel from the sdist -- the
    publish workflow's route), install into a throwaway venv, call the
    validator from a cwd that is NOT the checkout."""

    def test_installed_copy_finds_its_schema_and_rejects_an_empty_report(self):
        try:
            import build  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("the `build` package is not installed")
        with tempfile.TemporaryDirectory(prefix="registry-wheel-") as tmp:
            src = Path(tmp) / "src"
            shutil.copytree(REPO, src, symlinks=True,
                            ignore=shutil.ignore_patterns(".git", ".venv", "build",
                                                          "*.egg-info", "__pycache__", "dist"))
            out = Path(tmp) / "dist"
            done = subprocess.run([sys.executable, "-m", "build", "-o", str(out)],
                                  cwd=src, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0,
                             f"default build failed:\n{done.stdout[-1500:]}\n{done.stderr[-1500:]}")
            wheels = list(out.glob("*.whl"))
            self.assertEqual(len(wheels), 1, wheels)
            venv = Path(tmp) / "venv"
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                           capture_output=True)
            bindir = "Scripts" if sysconfig.get_platform().startswith("win") else "bin"
            py = venv / bindir / "python"
            subprocess.run([str(py), "-m", "pip", "-q", "install", str(wheels[0])],
                           check=True, capture_output=True)
            probe = "\n".join([
                "import hashlib, sys",
                "import scripts.registry_reference_server as s",
                "assert 'site-packages' in str(s.SCHEMA_PATH), s.SCHEMA_PATH",
                "assert s.SCHEMA_PATH.is_file(), f'schema not found: {s.SCHEMA_PATH}'",
                "req = s.load_schema_required(); assert 'entries' in req, req",
                "p = {'server_name': 'demo', 'contact': None, 'report': {},"
                " 'published_at': '2026-09-07T00:00:00Z'}",
                "sub = {'payload': p, 'signature': '00'*64,"
                " 'verification_hash': hashlib.sha256(s.canonical_bytes(p)).hexdigest()}",
                "try:",
                "    s.validate_and_build(sub, req)",
                "except s.Rejected as e:",
                "    assert e.status == 422, e.status; print('REJECTED', e.reason)",
                "else:",
                "    print('ACCEPTED'); sys.exit(3)",
            ])
            # cwd=tmp: NOT the checkout. That is the whole test.
            done = subprocess.run([str(py), "-c", probe], capture_output=True, text=True,
                                  cwd=tmp)
            self.assertEqual(done.returncode, 0,
                             f"installed registry did not reject an empty report:\n"
                             f"{done.stdout}\n{done.stderr[-1200:]}")
            self.assertIn("REJECTED", done.stdout)
            self.assertIn("schema-required keys", done.stdout)


if __name__ == "__main__":
    unittest.main()
