#!/usr/bin/env python3
"""The release gate, as code that runs, rather than as text a test can read.

The fourth external review (R4-16, 2026-09-08) found that `publish` depended on
`build` and on nothing that had tested the artifact. A `test-wheel` job was
added. The fifth review (R5-01, R5-07, 2026-09-09) found two things about it:

  R5-01  The contract test in `testing/test_release_is_gated_on_the_wheel.py`
         searched the concatenated shell text of the job for phrases, filenames
         and command names. Wrapping every `run:` step in `if false; then … fi`
         leaves all of that text in place and executes none of it: all 15 tests
         and 17 subtests still passed. Tokens in a string do not establish
         executable control flow.

  R5-07  The gate ran nine hand-listed files from `tests/`. Replacing the
         installed `harness_base.simulated_row` with `return dict(row)` strips
         the row labels off all 66 rows of the six native `--simulate` writers,
         and those nine files stay green (78 tests, 69 subtests). Break
         `http_helpers.fold_live_verdict` as well and the same six modules write
         66 `passed: true` rows with `serviced: 17` and `pass_rate: 1.0` -- the
         exact R4-05 defect -- and the nine files are still green.

Both findings have the same shape: the gate's strength was asserted somewhere
other than where the gate ran. So the gate lives here now, in one module that
CI executes against the installed wheel and that
`testing/test_release_is_gated_on_the_wheel.py` executes against deliberately
bad artifacts. A check that only one of the two can reach is a check nobody has
seen fail.

Run it with the interpreter of the venv the wheel was installed into, from a
directory that is NOT the checkout::

    /path/to/wheel-venv/bin/python scripts/verify_wheel_gate.py verify --tests tests

Every sub-command exits non-zero, with the reason on stdout, when its check
fails. Nothing here prints a green result it did not establish: a run that
produced no verdicts is reported as unmeasured, never as clean.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable

_HERE = str(Path(__file__).resolve().parent)


def _drop_the_checkout_from_sys_path() -> None:
    """Running this file by path puts its own directory on `sys.path`, which
    would let `import auroc` -- and 29 other sibling script names -- resolve to
    the checkout while the point of the exercise is to resolve everything to
    the installed wheel.

    Called from `main`, not at import: nothing here imports the package at
    module level, and a test that imports this module must not have the
    checkout removed from under it.
    """
    sys.path[:] = [p for p in sys.path if p not in ("", ".", _HERE)]


# ---------------------------------------------------------------------------
# The vocabulary a simulated row must carry.
# ---------------------------------------------------------------------------
#
# Stated here as literals rather than imported from `protocol_tests`, because
# the module under test is the thing whose labels are in question. Importing
# them would let one edit satisfy both sides. `check_scope_vocabulary` compares
# these with the installed constants, so drift is a failure rather than a
# silent agreement.

INCONCLUSIVE_PREFIX = "INCONCLUSIVE - "
SIMULATED_ROW_SCOPE = "reference-model self-test (no target)"
REFERENCE_VERDICT_SCOPE = (
    "reference model in this module; not an observation of the target")

#: The six harnesses that handle ``--simulate`` in their own ``main()``, and the
#: number of rows each writes. The CLI facade never reaches them, which is why
#: R4-05 shipped: the tests that existed covered the facade.
NATIVE_SIMULATE = {
    "protocol_tests.ap2_harness": 17,
    "protocol_tests.x402_fireblocks_harness": 17,
    "protocol_tests.ucp_acp_harness": 12,
    "protocol_tests.card_token_harness": 12,
    "protocol_tests.settlement_finality_harness": 8,
    "protocol_tests.aiuc1_compliance_harness": 12,
}

#: Files in `tests/` that must pass against nothing but the installed wheel:
#: at least one testcase, no failure, no error, and no skip. A skip here is
#: unmeasured, and unmeasured is not clean.
#:
#: This list is REVIEWED here and DERIVED by `audit_packaged_tests`, which runs
#: every file in `tests/` from the neutral directory and requires each one to
#: behave as classified. A file that stops needing the checkout, or starts
#: needing it, fails the gate until someone moves it -- which is the review the
#: hand-maintained nine-file list never got.
WHEEL_GATE_ELIGIBLE = {
    "test_auroc.py",
    "test_evidence_pack_declares_its_denominator.py",
    "test_fallback_validator_matches_schema.py",
    "test_fb013_quorum_binds_distinct_approvers.py",
    "test_fria_evidence.py",
    "test_imported_risk_score_needs_a_denominator.py",
    "test_mcp021_auth_fail_open.py",
    "test_mcp_sdk_schema_resolution_boundary.py",
    "test_mcp_server_runtime.py",
    "test_mcp_server_streamable_http_boundary.py",
    "test_registry_schema_validity_is_enforced.py",
    "test_simulate_does_not_claim_a_pass.py",
}

#: Files that read something the wheel does not ship, with the resource named.
#: "They all need the checkout" was too broad (R5-07); each of these was run
#: from the neutral directory and the reason recorded is the one it gave.
CHECKOUT_ONLY = {
    "test_aggregate_state_is_shared.py": "opens scripts/*.py by checkout path",
    "test_attestation_can_say_inconclusive.py": "opens REPO/schemas/attestation-report.json",
    "test_attestation_schema_neutrality.py": "opens REPO/schemas/attestation-report.json",
    "test_community_manifest_integrity.py": "reads community_modules/MANIFEST.yaml",
    "test_dgb_bundle_export.py": "reads fixtures/dgb/, docs/paper-dgb/, benchmarks/",
    "test_evidence_artifacts_are_three_state.py": "reads reports/ and runs git",
    "test_one_predicate_both_shapes.py": "opens scripts/html_report.py by checkout path",
    "test_owasp_agentic_mapping.py": "reads docs/coverage/ and runs git",
    "test_owasp_asi_is_one_source.py": "reads configs/, scripts/, protocol_tests/ as files",
    "test_owasp_titles_have_one_source.py": "opens scripts/*.py by checkout path",
    "test_rcl_fixture_export.py": "reads fixtures/rcl/rcl-oracle-fixtures.v1.json",
    "test_record_states_its_own_independence.py": "runs scripts/verify_attestation_record.py by path",
    "test_registry_refuses_without_schema.py": "runs scripts/registry_reference_server.py by path",
    "test_registry_server_contract.py": "runs scripts/verify_attestation_record.py by path",
    "test_report_states_its_provenance.py": "reads docs/evidence/ and attestations/",
    "test_result_semantics_predeclared.py": "reads docs/result-semantics.json",
    "test_the_wheel_ships_what_it_reads.py": "builds a wheel from the source tree",
    "test_verdict_taint_audit.py": "reads protocol_tests/*.py as files",
}


# ---------------------------------------------------------------------------
# Pure checks. Each returns a list of problems; an empty list is a pass.
# ---------------------------------------------------------------------------

def check_dist_shape(names: Iterable[str]) -> list[str]:
    """`dist/` must hold exactly one wheel, at least one sdist, nothing else.

    v4.16.0 failed to publish on 2026-08-30 because a build-environment record
    landed in `dist/` and twine met it as an InvalidDistribution. An sdist-only
    build is the other direction: nothing to install, so nothing to test.
    """
    names = sorted(names)
    wheels = [n for n in names if n.endswith(".whl")]
    sdists = [n for n in names if n.endswith(".tar.gz")]
    others = [n for n in names if not n.endswith((".whl", ".tar.gz"))]
    problems = []
    if len(wheels) != 1:
        problems.append(f"expected exactly one wheel in dist/, found {len(wheels)}: {wheels}")
    if not sdists:
        problems.append("no sdist in dist/")
    if others:
        problems.append(f"dist/ contains non-distribution files: {others}")
    return problems


def check_payment_report(report: dict) -> list[str]:
    """R3-01: installed 4.21.0 reported 17/17 PASS against a port nothing listens on."""
    problems = []
    summary = report.get("summary")
    if not isinstance(summary, dict):
        return ["the closed-port report has no summary"]
    total = summary.get("total", 0)
    if total < 1:
        problems.append("the closed-port run produced no verdicts: unmeasured, not clean")
    if summary.get("passed", 0) != 0:
        problems.append(f"{summary.get('passed')} of {total} PASS against a port "
                        f"nothing listens on (R3-01)")
    if summary.get("serviced", 0) != 0:
        problems.append(f"serviced={summary.get('serviced')} against a closed port: "
                        f"a denominator was counted for requests nobody answered")
    rows = report.get("results") or []
    claimed = [r.get("test_id") for r in rows if r.get("passed") is True]
    if claimed:
        problems.append(f"rows claim a pass against a closed port: {claimed[:5]}")
    return problems


def check_simulated_report(report: dict, *, expected_rows: int | None = None) -> list[str]:
    """Every layer of a native `--simulate --report` file, not just `passed`.

    R5-07's first mutation leaves `passed` false and removes `simulated` and
    `verdict_scope` from all 66 rows; its second turns them into 66 passes with
    a Wilson interval. A check that reads one field catches one of the two.
    """
    problems = []
    rows = report.get("results")
    if not isinstance(rows, list) or not rows:
        return ["the simulated run wrote no rows"]
    if expected_rows is not None and len(rows) != expected_rows:
        problems.append(f"{len(rows)} rows, expected {expected_rows}: a simulated row went missing")

    reference_passes = 0
    for row in rows:
        tid = row.get("test_id", "?")
        if row.get("passed") is not False:
            problems.append(f"{tid}: a simulated row claimed passed={row.get('passed')!r}")
        if row.get("not_evaluated") is not True:
            problems.append(f"{tid}: no `not_evaluated` marker on a fabricated-answer row")
        if row.get("simulated") is not True:
            problems.append(f"{tid}: row is not labelled `simulated`")
        if row.get("verdict_scope") != SIMULATED_ROW_SCOPE:
            problems.append(f"{tid}: verdict_scope is {row.get('verdict_scope')!r}, "
                            f"expected {SIMULATED_ROW_SCOPE!r}")
        details = str(row.get("details") or "")
        if not details.startswith(INCONCLUSIVE_PREFIX):
            problems.append(f"{tid}: details do not agree with the field: {details[:60]!r}")
        ref = row.get("reference_verdict")
        if not isinstance(ref, dict):
            problems.append(f"{tid}: the fabricated verdict was discarded, not scoped")
            continue
        if ref.get("scope") != REFERENCE_VERDICT_SCOPE:
            problems.append(f"{tid}: reference_verdict.scope is {ref.get('scope')!r}")
        if not isinstance(ref.get("passed"), bool):
            problems.append(f"{tid}: reference_verdict.passed is not a bool")
        if not str(ref.get("reason") or ""):
            problems.append(f"{tid}: reference_verdict carries no reason")
        reference_passes += bool(ref.get("passed"))

    if reference_passes == 0:
        problems.append("no reference verdict survived: the fabricated outcome was "
                        "deleted rather than scoped, so nothing shows what the "
                        "module answered itself")

    summary = report.get("summary")
    if not isinstance(summary, dict):
        problems.append("the simulated run wrote no summary")
    else:
        n = len(rows)
        expected = {"total": n, "passed": 0, "failed": 0, "inconclusive": n,
                    "serviced": 0, "status": "inconclusive",
                    "pass_rate": None, "wilson_95_ci": None}
        actual = {k: summary.get(k) for k in expected}
        if actual != expected:
            problems.append(f"summary disagrees with the rows, or a rate was computed "
                            f"over nothing: {actual} != {expected}")
    scope = report.get("verdict_scope")
    if not isinstance(scope, dict) or scope.get("live_requested") is not False:
        problems.append("the report does not say that nothing live was requested")
    return problems


_TESTSUITE = re.compile(r"<testsuite\b([^>]*)>")


def junit_counts(xml_text: str) -> dict:
    """`tests/errors/failures/skipped` from a pytest JUnit file.

    Read by attribute name rather than by position: pytest writes them in
    alphabetical order and a version that reorders them must not be read as a
    file with no failures in it. The element counts are the fallback when the
    `<testsuite>` attributes are absent.
    """
    fields = ("tests", "errors", "failures", "skipped")
    m = _TESTSUITE.search(xml_text)
    if m:
        attrs = dict(re.findall(r'([A-Za-z_]+)="([^"]*)"', m.group(1)))
        if all(attrs.get(f, "").isdigit() for f in fields):
            return {f: int(attrs[f]) for f in fields}
    return {
        "tests": len(re.findall(r"<testcase\b", xml_text)),
        "errors": len(re.findall(r"<error\b", xml_text)),
        "failures": len(re.findall(r"<failure\b", xml_text)),
        "skipped": len(re.findall(r"<skipped\b", xml_text)),
    }


def is_clean(counts: dict) -> bool:
    """At least one testcase, and no failure, error or skip in it."""
    return (counts["tests"] >= 1 and counts["errors"] == 0
            and counts["failures"] == 0 and counts["skipped"] == 0)


def check_test_classification(present: Iterable[str]) -> list[str]:
    """Every file in `tests/` is either gate-eligible or a named exclusion."""
    present = set(present)
    known = WHEEL_GATE_ELIGIBLE | set(CHECKOUT_ONLY)
    problems = []
    for name in sorted(present - known):
        problems.append(f"{name} is new and unclassified: add it to "
                        f"WHEEL_GATE_ELIGIBLE or to CHECKOUT_ONLY with its reason")
    for name in sorted(known - present):
        problems.append(f"{name} is classified but no longer exists in tests/")
    both = WHEEL_GATE_ELIGIBLE & set(CHECKOUT_ONLY)
    if both:
        problems.append(f"classified twice: {sorted(both)}")
    return problems


# ---------------------------------------------------------------------------
# Checks that run something.
# ---------------------------------------------------------------------------

def _run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=900, **kw)


def check_imports_resolve_to_the_wheel() -> list[str]:
    """Source shadowing is why the CI install check proves less than it looks."""
    problems = []
    for name in ("protocol_tests", "scripts"):
        try:
            module = __import__(name)
        except ImportError as exc:  # pragma: no cover - a broken wheel
            problems.append(f"the installed wheel does not provide {name}: {exc}")
            continue
        where = list(module.__path__)[0]
        if "site-packages" not in where:
            problems.append(f"{name} resolved to {where}, not to the installed wheel")
        else:
            print(f"  {name} -> {where}")
    return problems


def check_scope_vocabulary() -> list[str]:
    """The gate's literals and the package's constants must be the same words."""
    try:
        from protocol_tests import http_helpers
    except ImportError as exc:  # pragma: no cover
        return [f"cannot import protocol_tests.http_helpers: {exc}"]
    problems = []
    for label, mine, theirs in (
            ("INCONCLUSIVE_PREFIX", INCONCLUSIVE_PREFIX, http_helpers.INCONCLUSIVE_PREFIX),
            ("SIMULATED_ROW_SCOPE", SIMULATED_ROW_SCOPE, http_helpers.SIMULATED_ROW_SCOPE),
            ("REFERENCE_VERDICT_SCOPE", REFERENCE_VERDICT_SCOPE,
             http_helpers.REFERENCE_VERDICT_SCOPE)):
        if mine != theirs:
            problems.append(f"{label} drifted: gate says {mine!r}, package says {theirs!r}")
    return problems


def check_entry_points(bindir: Path) -> list[str]:
    """The documented entry points, run as a consumer runs them."""
    problems = []
    commands = [
        [str(bindir / "agent-security"), "--version"],
        [sys.executable, "-m", "protocol_tests.mock_mcp_server", "--help"],
        [sys.executable, "-m", "scripts.registry_reference_server", "--help"],
    ]
    for argv in commands:
        done = _run(argv)
        if done.returncode != 0:
            problems.append(f"{' '.join(argv)} exited {done.returncode}: "
                            f"{(done.stderr or done.stdout)[-300:]}")
        else:
            print(f"  ok: {' '.join(argv)}")
    return problems


def check_closed_port(bindir: Path, workdir: Path) -> list[str]:
    """R3-01, in the release path rather than in a changelog."""
    report = workdir / "ap2-closed-port.json"
    done = _run([str(bindir / "agent-security"), "test", "ap2",
                 "--url", "http://127.0.0.1:9", "--report", str(report)],
                cwd=str(workdir))
    print(f"  closed-port harness exit code: {done.returncode}")
    if not report.exists():
        return [f"the closed-port run wrote no report: {(done.stderr or done.stdout)[-400:]}"]
    problems = check_payment_report(json.loads(report.read_text()))
    if not problems:
        summary = json.loads(report.read_text())["summary"]
        print(f"  closed-port summary: {summary}")
    return problems


def check_native_simulate(workdir: Path) -> list[str]:
    """The six native `--simulate` entry points, which the facade never reaches.

    This is the surface R5-07 named: the gate's nine files use the CLI facade,
    so a broken shared writer -- `harness_base.simulated_row`, or the
    `fold_live_verdict` simulate branch under it -- ships green.
    """
    problems = []
    for module, expected in NATIVE_SIMULATE.items():
        report = workdir / f"{module.rsplit('.', 1)[1]}-simulate.json"
        done = _run([sys.executable, "-m", module, "--simulate", "--report", str(report)],
                    cwd=str(workdir))
        if not report.exists():
            problems.append(f"{module}: no report written "
                            f"(exit {done.returncode}): {(done.stderr or done.stdout)[-300:]}")
            continue
        found = check_simulated_report(json.loads(report.read_text()),
                                       expected_rows=expected)
        if found:
            problems.extend(f"{module}: {p}" for p in found)
        else:
            print(f"  {module}: {expected} rows, all INCONCLUSIVE and labelled")
    return problems


def _pytest_one(tests_dir: Path, name: str, junit: Path) -> dict:
    done = _run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                 str(Path(tests_dir.name) / name), f"--junitxml={junit}"],
                cwd=str(tests_dir.parent))
    counts = junit_counts(junit.read_text()) if junit.exists() else {
        "tests": 0, "errors": 1, "failures": 0, "skipped": 0}
    counts["returncode"] = done.returncode
    counts["tail"] = (done.stdout or done.stderr or "").strip().splitlines()[-1:] or [""]
    return counts


def audit_packaged_tests(tests_dir: Path, workdir: Path) -> list[str]:
    """Run every file in `tests/` and require it to behave as classified.

    Eligible files must be clean against nothing but the wheel. Excluded files
    must NOT be -- an exclusion whose file now passes here is an exclusion
    nobody has re-read, which is how nine files stayed nine while `tests/` grew
    to thirty.
    """
    present = sorted(p.name for p in tests_dir.glob("test_*.py"))
    problems = check_test_classification(present)
    if problems:
        return problems

    for name in present:
        junit = workdir / f"junit-{name}.xml"
        counts = _pytest_one(tests_dir, name, junit)
        clean = is_clean(counts)
        expected_clean = name in WHEEL_GATE_ELIGIBLE
        mark = "eligible" if expected_clean else "excluded"
        print(f"  [{mark:8}] {name:52} {counts['tests']:3} tests "
              f"{counts['failures']} failed {counts['errors']} errors "
              f"{counts['skipped']} skipped")
        if expected_clean and not clean:
            problems.append(
                f"{name} is on the wheel gate and did not pass against the "
                f"installed wheel alone: {counts['tests']} tests, "
                f"{counts['failures']} failures, {counts['errors']} errors, "
                f"{counts['skipped']} skipped -- {counts['tail'][0]}")
        if not expected_clean and clean:
            problems.append(
                f"{name} is excluded as \"{CHECKOUT_ONLY[name]}\" but passed "
                f"cleanly against the installed wheel: move it to "
                f"WHEEL_GATE_ELIGIBLE or correct the reason")
    return problems


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def _report(title: str, problems: list[str]) -> int:
    if problems:
        print(f"FAIL {title}")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"ok   {title}")
    return 0


def cmd_dist_shape(args) -> int:
    dist = Path(args.dist)
    names = sorted(p.name for p in dist.iterdir()) if dist.is_dir() else []
    if not dist.is_dir():
        return _report(f"dist shape ({dist})", [f"{dist} is not a directory"])
    print(f"  dist/ holds: {names}")
    return _report("dist shape", check_dist_shape(names))


def cmd_check_payment_report(args) -> int:
    return _report(f"closed-port report {args.path}",
                   check_payment_report(json.loads(Path(args.path).read_text())))


def cmd_check_simulated_report(args) -> int:
    return _report(f"simulated report {args.path}",
                   check_simulated_report(json.loads(Path(args.path).read_text()),
                                          expected_rows=args.expect_rows))


def cmd_eligible_tests(args) -> int:
    tests_dir = Path(args.tests).resolve()
    present = sorted(p.name for p in tests_dir.glob("test_*.py"))
    problems = check_test_classification(present)
    for name in sorted(WHEEL_GATE_ELIGIBLE):
        print(name)
    print(f"# {len(WHEEL_GATE_ELIGIBLE)} of {len(present)} files in "
          f"{tests_dir} are wheel-gate eligible", file=sys.stderr)
    return _report("test classification", problems) if problems else 0


def cmd_verify(args) -> int:
    tests_dir = Path(args.tests).resolve()
    if not tests_dir.is_dir():
        print(f"FAIL {tests_dir} is not a directory")
        return 1
    if Path(tests_dir.parent / "protocol_tests").exists():
        print(f"FAIL {tests_dir.parent} contains a protocol_tests source tree; "
              f"run the gate from a directory that is not the checkout")
        return 1

    failures = 0
    with tempfile.TemporaryDirectory(prefix="wheel-gate-") as tmp:
        workdir = Path(tmp)
        stages = [
            ("imports resolve to the installed wheel", check_imports_resolve_to_the_wheel, ()),
            ("the gate and the package use one vocabulary", check_scope_vocabulary, ()),
            ("documented entry points run", check_entry_points, (Path(sys.executable).parent,)),
            ("a payment harness against a closed port passes nothing",
             check_closed_port, (Path(sys.executable).parent, workdir)),
            ("native --simulate publishes no pass, anywhere a row is read",
             check_native_simulate, (workdir,)),
            ("packaged-behaviour tests, classified by what they need",
             audit_packaged_tests, (tests_dir, workdir)),
        ]
        for title, fn, fnargs in stages:
            print(f"\n== {title}")
            failures += _report(title, fn(*fnargs))
    print()
    if failures:
        print(f"RELEASE GATE FAILED: {failures} stage(s)")
        return 1
    print("RELEASE GATE PASSED")
    return 0


def main(argv: list[str] | None = None) -> int:
    _drop_the_checkout_from_sys_path()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("dist-shape", help="exactly one wheel, an sdist, nothing else")
    p.add_argument("--dist", required=True)
    p.set_defaults(func=cmd_dist_shape)

    p = sub.add_parser("verify", help="run the whole gate against the installed wheel")
    p.add_argument("--tests", required=True, help="a copy of tests/ in a neutral directory")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("eligible-tests", help="print the derived gate-eligible test files")
    p.add_argument("--tests", required=True)
    p.set_defaults(func=cmd_eligible_tests)

    p = sub.add_parser("check-payment-report", help="apply the closed-port assertions to a report")
    p.add_argument("path")
    p.set_defaults(func=cmd_check_payment_report)

    p = sub.add_parser("check-simulated-report", help="apply the simulated-row contract to a report")
    p.add_argument("path")
    p.add_argument("--expect-rows", type=int, default=None)
    p.set_defaults(func=cmd_check_simulated_report)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
