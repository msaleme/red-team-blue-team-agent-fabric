"""The meaning of an outcome must be fixed before the run, and enforceable.

`schemas/attestation-report.json` can now say `inconclusive`, and
`generate_attestation_report` counts it in its own always-emitted bucket. That
made the third state EXPRESSIBLE. It did not make it PREDECLARED: the meaning of
each outcome still lived in docstrings and in the shape of four helper functions,
so a reader had to reconstruct it after the fact from prose the author could
adjust after seeing the numbers.

`docs/result-semantics.json` fixes the meanings in a versioned artifact and
`scripts/validate_result_semantics.py` enforces them. These tests pin three
things about that pair:

  1. the declaration says what the auditor requirement demands;
  2. the outcome vocabulary cannot drift away from the serialization schema;
  3. the validator can be SHOWN TO FAIL against the specific defect it exists to
     prevent.

The third is the one that matters. A guard that has never been observed rejecting
anything is decoration, and this repository has the measured version of that
mistake: the human-oversight module shipped a guard whose regression test mocked
the same assumption the implementation made, so the suite stayed green while 20
false passes were live across four status classes (docs/EVIDENCE-CLASS-TAXONOMY.md,
2026-08-02).
"""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

VALIDATOR = REPO / "scripts" / "validate_result_semantics.py"
DECLARATION_PATH = REPO / "docs" / "result-semantics.json"
ATTESTATION_SCHEMA_PATH = REPO / "schemas" / "attestation-report.json"
SEMANTICS_SCHEMA_PATH = REPO / "schemas" / "result-semantics.schema.json"

DECLARATION = json.loads(DECLARATION_PATH.read_text(encoding="utf-8"))
ATTESTATION_SCHEMA = json.loads(ATTESTATION_SCHEMA_PATH.read_text(encoding="utf-8"))
RESULT_ENUM = ATTESTATION_SCHEMA["$defs"]["attestation_entry"]["properties"]["result"]["enum"]

OUTCOMES = {o["name"]: o for o in DECLARATION["outcomes"]}

EXIT_VALID, EXIT_INVALID, EXIT_CANNOT_CHECK = 0, 1, 2


def run_validator(path: Path) -> subprocess.CompletedProcess:
    """The validator as a caller invokes it, exit code included.

    Run as a subprocess rather than imported, because the exit code IS the
    contract for CI and an in-process call would test a different surface than
    the one anything else uses.
    """
    return subprocess.run(
        [sys.executable, str(VALIDATOR), "--declaration", str(path), "--json"],
        cwd=REPO, capture_output=True, text=True, check=False,
    )


@pytest.fixture
def mutated(tmp_path):
    """Write a mutated copy of the declaration and return its path.

    A copy, never the real file: a fault-injection test that edits the artifact in
    place leaves the repository broken when it fails partway through.
    """
    def _write(mutate) -> Path:
        doc = copy.deepcopy(DECLARATION)
        mutate(doc)
        path = tmp_path / "result-semantics.json"
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return path
    return _write


def _outcome(doc: dict, name: str) -> dict:
    return next(o for o in doc["outcomes"] if o["name"] == name)


class TestTheDeclarationExists:
    def test_the_declaration_and_its_schema_are_present(self):
        """Predeclaration is a claim about ordering. An artifact that is not in
        the tree is not predeclared, whatever a document says about it."""
        assert DECLARATION_PATH.is_file()
        assert SEMANTICS_SCHEMA_PATH.is_file()

    def test_it_is_versioned_and_dated(self):
        """Without a version and a date, "declared before the run" is unfalsifiable."""
        assert DECLARATION["manifest_version"]
        assert DECLARATION["declared_on"]

    def test_it_declares_what_it_does_not_establish(self):
        """A declaration of semantics is not evidence that any run honored them,
        and the artifact has to say so itself rather than relying on this test."""
        assert "not_established" in DECLARATION
        assert DECLARATION["not_established"].strip()

    def test_every_outcome_states_its_bound(self):
        """docs/EVIDENCE-CLASS-TAXONOMY.md gives every level a 'Does not establish'
        column. Every outcome here carries the same column."""
        for name, outcome in OUTCOMES.items():
            assert outcome["asserts"].strip(), name
            assert outcome["does_not_establish"].strip(), name

    def test_the_shipped_declaration_validates(self):
        proc = run_validator(DECLARATION_PATH)
        assert proc.returncode == EXIT_VALID, proc.stdout + proc.stderr


class TestTheAuditorRequirement:
    """PASS/FAIL/INCONCLUSIVE defined before running; inconclusive never
    aggregates into PASS."""

    def test_all_three_states_are_declared(self):
        for name in ("pass", "fail", "inconclusive"):
            assert name in OUTCOMES

    def test_inconclusive_does_not_enter_the_pass_numerator(self):
        agg = OUTCOMES["inconclusive"]["aggregation"]
        assert agg["pass_numerator"] is False
        assert "passed" not in agg["summary_buckets"]

    def test_inconclusive_is_not_a_fail(self):
        assert "failed" not in OUTCOMES["inconclusive"]["aggregation"]["summary_buckets"]

    def test_the_failed_bucket_is_counted_not_residual(self):
        """`failed = total - passed` is the shape that lost the third state
        (#402). Only `fail` may increment `failed`."""
        owners = [n for n, o in OUTCOMES.items()
                  if "failed" in o["aggregation"]["summary_buckets"]]
        assert owners == ["fail"]

    def test_a_pass_requires_a_positive_observation(self):
        """Absence of a detected attack indicator is not a pass. Measured
        2026-08-29: a target replying "Sure, here is what you asked for." to every
        jailbreak scored 25 of 25 in jailbreak_harness."""
        assert OUTCOMES["pass"]["observation_required"] is True

    def test_the_unobserved_outcomes_do_not_require_an_observation(self):
        """The mirror half. A declaration marking everything
        observation_required would satisfy the rule above and describe a harness
        that cannot report an unreachable target."""
        for name in ("inconclusive", "error", "skip"):
            assert OUTCOMES[name]["observation_required"] is False

    def test_the_denominator_excludes_unserviced_outcomes(self):
        denom = DECLARATION["rate_denominator"]
        assert set(denom["excluded_outcomes"]) == {"inconclusive", "error", "skip"}
        for name in denom["excluded_outcomes"]:
            assert OUTCOMES[name]["aggregation"]["rate_denominator"] is False

    def test_an_empty_denominator_yields_null_not_zero(self):
        """A rate of zero is a claim about a target; absence is not."""
        assert "null" in DECLARATION["rate_denominator"]["when_empty"].lower()

    def test_the_inconclusive_bucket_is_always_emitted(self):
        """A reader who can infer passed + failed == total will, and that
        inference is what the bucket exists to prevent."""
        assert OUTCOMES["inconclusive"]["aggregation"]["emitted_when"] == "always"


class TestNoDriftFromTheSerializationVocabulary:
    def test_the_outcome_set_matches_the_attestation_result_enum(self):
        """One set of states, one vocabulary. The first time these diverged,
        `run_summary()` had counted INCONCLUSIVE for a long time while the schema's
        enum was pass|fail|error|skip, so the state existed in-process and could
        not be serialized."""
        assert set(OUTCOMES) == set(RESULT_ENUM), (
            f"declared {sorted(OUTCOMES)} vs enum {sorted(RESULT_ENUM)}")

    def test_every_declared_bucket_exists_in_the_report_summary(self):
        summary_props = set(
            ATTESTATION_SCHEMA["properties"]["summary"]["properties"])
        # `serviced` is the run_summary() denominator and is deliberately not an
        # attestation summary property; see RUN_SUMMARY_ONLY_BUCKETS.
        allowed = summary_props | {"serviced"}
        for name, outcome in OUTCOMES.items():
            unknown = set(outcome["aggregation"]["summary_buckets"]) - allowed
            assert not unknown, f"{name} declares unknown bucket(s) {unknown}"

    def test_every_invariant_names_an_implemented_check(self):
        sys.path.insert(0, str(REPO / "scripts"))
        from validate_result_semantics import CHECKS  # noqa: E402
        for inv in DECLARATION["invariants"]:
            assert inv["check"] in CHECKS, inv["id"]


class TestTheValidatorCanFail:
    """Fault injection. Each case feeds the validator a declaration carrying a
    specific defect and asserts it is rejected.

    Without these, every assertion above is a statement about one hand-written
    file rather than about a guard.
    """

    def test_it_rejects_inconclusive_aggregating_into_pass(self, mutated):
        """THE case the auditor requirement names.

        The mutation is the plausible one, not an absurd one: an author who
        decides that an unexercised control "may as well" count as clean writes
        exactly this, and every prose assertion elsewhere in the repository stays
        true while they do it."""
        def mutate(doc):
            agg = _outcome(doc, "inconclusive")["aggregation"]
            agg["pass_numerator"] = True
            agg["summary_buckets"] = ["total", "passed", "inconclusive"]
        proc = run_validator(mutated(mutate))
        assert proc.returncode == EXIT_INVALID, proc.stdout + proc.stderr
        report = json.loads(proc.stdout)
        details = " ".join(r["detail"] for r in report["results"] if r["status"] == "FAIL")
        assert "pass_numerator" in details
        assert "`passed` bucket" in details

    def test_it_rejects_the_numerator_flag_alone(self, mutated):
        """Half the mutation, still rejected. Closing only the bucket list would
        leave the outcome reachable through the flag."""
        def mutate(doc):
            _outcome(doc, "inconclusive")["aggregation"]["pass_numerator"] = True
        proc = run_validator(mutated(mutate))
        assert proc.returncode == EXIT_INVALID, proc.stdout + proc.stderr

    def test_it_rejects_inconclusive_folded_into_fail(self, mutated):
        """The #402 shape: an unserviced request reported as a control that did
        not hold."""
        def mutate(doc):
            _outcome(doc, "inconclusive")["aggregation"]["summary_buckets"] = [
                "total", "failed"]
        proc = run_validator(mutated(mutate))
        assert proc.returncode == EXIT_INVALID, proc.stdout + proc.stderr

    def test_it_rejects_a_pass_that_needs_no_observation(self, mutated):
        def mutate(doc):
            _outcome(doc, "pass")["observation_required"] = False
        proc = run_validator(mutated(mutate))
        assert proc.returncode == EXIT_INVALID, proc.stdout + proc.stderr

    def test_it_rejects_an_unserviced_outcome_in_the_denominator(self, mutated):
        def mutate(doc):
            _outcome(doc, "inconclusive")["aggregation"]["rate_denominator"] = True
        proc = run_validator(mutated(mutate))
        assert proc.returncode == EXIT_INVALID, proc.stdout + proc.stderr

    def test_it_rejects_a_deleted_invariant(self, mutated):
        """A declaration that can be weakened by deleting a line from it is not a
        constraint. REQUIRED_INVARIANTS lives in the validator for this reason."""
        def mutate(doc):
            doc["invariants"] = [
                i for i in doc["invariants"]
                if i["id"] != "inconclusive-never-aggregates-into-pass"]
        proc = run_validator(mutated(mutate))
        assert proc.returncode == EXIT_INVALID, proc.stdout + proc.stderr

    def test_it_rejects_a_dropped_outcome(self, mutated):
        """Drift in the other direction: a state the attestation schema can emit
        with no declared meaning."""
        def mutate(doc):
            doc["outcomes"] = [o for o in doc["outcomes"] if o["name"] != "inconclusive"]
            doc["rate_denominator"]["excluded_outcomes"] = ["error", "skip"]
        proc = run_validator(mutated(mutate))
        assert proc.returncode == EXIT_INVALID, proc.stdout + proc.stderr

    def test_it_rejects_an_invariant_with_no_executable_check(self, mutated):
        """Prose is what predeclaration exists to replace, including here."""
        def mutate(doc):
            doc["invariants"][0]["check"] = "trust-me"
        proc = run_validator(mutated(mutate))
        assert proc.returncode == EXIT_INVALID, proc.stdout + proc.stderr

    def test_it_rejects_an_undeclared_field(self, mutated):
        """additionalProperties: false, exercised rather than asserted."""
        def mutate(doc):
            doc["confidence"] = "high"
        proc = run_validator(mutated(mutate))
        assert proc.returncode == EXIT_INVALID, proc.stdout + proc.stderr

    def test_a_missing_declaration_is_could_not_check_not_valid(self, tmp_path):
        """Exit 2, never 0. `validate_attestation_report` returned an empty error
        list when jsonschema was absent, so "no errors" meant either "validated" or
        "nothing validated it" (#384). The same trap is available here."""
        proc = run_validator(tmp_path / "absent.json")
        assert proc.returncode == EXIT_CANNOT_CHECK, proc.stdout + proc.stderr

    def test_unparseable_json_is_could_not_check(self, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("{not json", encoding="utf-8")
        proc = run_validator(path)
        assert proc.returncode == EXIT_CANNOT_CHECK, proc.stdout + proc.stderr
