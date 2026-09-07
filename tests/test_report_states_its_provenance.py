"""A report must state what produced it and what it ran against, in the file.

`docs/evidence/adi/2026-09-02-qwen35-n3-raw.json` is the exhibit. It carries an
Ollama server version, a model tag, a manifest digest, a family, a parameter
size and a quantisation, and the harness produced none of them: `--report`
wrote `json.dump([r.__dict__ for r in results], fh)` -- a bare LIST, with
nowhere for a header to go -- so a person typed the header in from a shell
session that is not part of the record.

That file is not edited by this change. It is a record of a run that happened,
and editing a dated evidence artifact so it looks machine-generated is
fabrication. What changes is that the next one cannot be produced that way.

## What is pinned here

1. **Unknown is not omitted, and neither is spelled "unknown".** Every key in
   both blocks is always present. A null is paired with an `_absent_reason`
   from a closed enum, and exactly one of the two is non-null. The string
   `"unknown"` never appears as a value: it cannot be told apart from a model
   literally tagged `unknown`, a corpus named `unknown`, or a bug that
   stringified a `None`. `protocol_tests/version.py` returns exactly that
   string on failure, so this is a live hazard and not a hypothetical one.

2. **Argv redaction.** Documented usage includes
   `--header "Authorization: Bearer ..."`. This block is meant to be published
   and signed, so a raw argv would make a provenance feature a
   credential-disclosure feature. Tested with realistic fake credentials, by
   asserting the secret does not appear anywhere in the serialised document --
   not by asserting a particular redacted spelling, which would pass while the
   secret sat in a neighbouring field.

3. **The published records are untouched.** Both committed attestation records
   still validate, and their `verification_hash` still recomputes to the value
   they were published under. New schema fields that silently invalidate signed
   history are not new schema fields, they are a break.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from protocol_tests.attestation import (  # noqa: E402
    SCHEMA_PATH,
    _infer_scope,
    generate_attestation_report,
    validate_attestation_report,
)
from protocol_tests.run_provenance import (  # noqa: E402
    ABSENT_REASONS,
    PROVENANCE_SCHEMA,
    redact_argv,
    run_provenance,
    subject_corpus,
    subject_http,
    subject_model,
    subject_none,
)

SCHEMA = json.loads(SCHEMA_PATH.read_text())

ENTRY = {
    "test_id": "ADI-001",
    "category": "agent_data_injection",
    "result": "inconclusive",
    "severity": "P0-Critical",
    "scope": _infer_scope("ADI-001", "agent_data_injection"),
    "timestamp": "2026-09-07T00:00:00+00:00",
}

#: Shaped like the real things and valid nowhere. The point of using realistic
#: shapes is that a redactor keyed to a toy value ("secret123") passes on the
#: toy and leaks the real one.
#: A canary with no auth word in it, assembled at runtime where it is used so
#: no source literal has the shape of a credential -- the secret scanner
#: flags `://user:pass@` and `Bearer <token>` on sight, and the repo rule is
#: to change the fixture, never the scanner.
CANARY = "zq7" + "hunter2" + "wq"

FAKE_BEARER = "sk-ant-api03-Qx7NOTAREALKEY0000000000000000000000000000000000AA"
# Not AWS's canonical example access key: that literal trips this repo's own
# secret scanner (testing/test_code_quality.py), and a fixture that teaches
# people to add exclusions to a secret scanner costs more than it tests. The
# name is FAKE_PAT and not FAKE_PAT for the same reason -- that scanner also
# matches `api_key = "..."`, and it is right to.
FAKE_PAT = "ghp_NOTAREALTOKEN0000000000000000000000"
FAKE_PASSWORD = "hunter2-correct-horse-battery-staple"


def _report(**kw):
    return generate_attestation_report([ENTRY], suite="adi",
                                       harness_version="4.20.0", **kw)


def _walk(obj, path="$"):
    """Yield (path, key, value) for every mapping entry, depth-first."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield f"{path}.{k}", k, v
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


# --- 1. unknown vs omitted -------------------------------------------------

BLOCKS = {
    "provenance": lambda: run_provenance(),
    "subject_http": lambda: subject_http("http://localhost:8080/mcp"),
    "subject_http_missing": lambda: subject_http(None),
    "subject_model": lambda: subject_model("qwen3.5:latest"),
    "subject_corpus": lambda: subject_corpus(__file__),
    "subject_none": lambda: subject_none(),
}


def _is_absent(value) -> bool:
    """Null, or a block whose every value is null.

    The second case is `ci`, which stays a dict of nine keys outside CI so a
    reader can see WHICH nine were consulted, and so a local statement cannot
    pass for a CI one. A block in which nothing is known is an absence, and the
    invariant would be untotal -- with a documented exception -- if it only
    understood the scalar case.
    """
    if value is None:
        return True
    return isinstance(value, dict) and bool(value) and all(
        v is None for v in value.values())


@pytest.mark.parametrize("name", sorted(BLOCKS))
def test_every_null_is_paired_with_a_reason_and_only_a_reason(name):
    """The invariant, stated as an exclusive or.

    A null with no reason is an absence that explains nothing. A reason beside
    a present value is a document asserting two incompatible things about the
    same field.
    """
    block = BLOCKS[name]()
    reasons = [(p, k) for p, k, _ in _walk(block) if k.endswith("_absent_reason")]
    assert reasons, f"{name} carries no paired reasons at all"

    for path, key in reasons:
        parent = _resolve(block, path[: -(len(key) + 1)])
        field = key[: -len("_absent_reason")]
        assert field in parent, f"{path}: reason with no field beside it"
        value, reason = parent[field], parent[key]
        assert _is_absent(value) == (reason is not None), (
            f"{path}: value={value!r} reason={reason!r}. A reason accompanies "
            f"an absence and nothing else.")
        if reason is not None:
            assert reason in ABSENT_REASONS, f"{path}: {reason!r} is off-enum"


def _resolve(root, path):
    node = root
    for part in path.split(".")[1:]:
        node = node[part]
    return node


@pytest.mark.parametrize("name", sorted(BLOCKS))
def test_no_key_is_ever_omitted(name):
    """A missing key cannot be told apart from a producer that dropped one."""
    block = BLOCKS[name]()
    if name.startswith("subject"):
        assert set(block) == {
            "kind", "url", "url_absent_reason", "model", "model_absent_reason",
            "corpus", "corpus_absent_reason",
        }, "the subject union must carry every arm's keys in every arm"
    else:
        assert set(block) == {
            "schema", "started_at", "tool", "source", "runtime", "invocation",
            "ci", "ci_absent_reason", "not_claimed",
        }


@pytest.mark.parametrize("name", sorted(BLOCKS))
def test_the_string_unknown_never_appears_as_a_value(name):
    """`"unknown"` is indistinguishable from a model literally tagged that.

    It is also what `protocol_tests/version.py::get_harness_version()` returns
    when it fails, which is why this is checked rather than assumed.
    """
    for path, _, value in _walk(BLOCKS[name]()):
        if isinstance(value, str):
            assert value.strip().lower() != "unknown", f"{path} is the string 'unknown'"


def test_a_failed_version_lookup_becomes_null_not_the_word_unknown():
    """The live hazard, exercised: the sentinel must not travel as data."""
    with mock.patch("protocol_tests.version.get_harness_version", return_value="unknown"):
        tool = run_provenance()["tool"]
    assert tool["version"] is None
    assert tool["version_absent_reason"] == "version_not_discoverable"


def test_ci_block_is_present_and_all_null_outside_ci():
    """A locally produced statement must not be able to pass for a CI one."""
    scrubbed = {k: v for k, v in os.environ.items()
                if not k.startswith(("GITHUB_", "RUNNER_"))}
    with mock.patch.dict(os.environ, scrubbed, clear=True):
        p = run_provenance()
    assert p["ci_absent_reason"] == "not_running_in_ci"
    assert set(p["ci"]) == {"repository", "workflow", "workflow_ref", "run_id",
                            "run_attempt", "run_url", "runner_os",
                            "runner_arch", "event"}
    assert all(v is None for v in p["ci"].values())


def test_a_subject_model_with_no_tag_is_refused():
    """kind 'model' with model null is a claim about a model that names none."""
    with pytest.raises(ValueError, match="requires a tag"):
        subject_model("")


def test_model_details_default_to_not_queried_rather_than_to_absent():
    """The ADI case exactly. The tool reaches /api/generate, never /api/show."""
    model = subject_model("qwen3.5:latest")["model"]
    assert model["tag"] == "qwen3.5:latest"
    for field in ("runtime", "digest", "family", "parameter_size", "quantization"):
        assert model[field] is None
        assert model[f"{field}_absent_reason"] == "not_queried", (
            "these are facts the tool could obtain and does not ask for; "
            "'not_queried' is the difference between that and 'unavailable'")


def test_a_subject_arm_that_does_not_apply_says_not_applicable():
    """Distinct from not_supplied: 'no URL because it is a model' is a fact."""
    assert subject_model("m")["url_absent_reason"] == "not_applicable"
    assert subject_http(None)["url_absent_reason"] == "not_supplied"


# --- 2. argv redaction -----------------------------------------------------

def test_a_bearer_header_does_not_reach_the_document():
    """The headline. Asserted as absence from the whole serialised block.

    Checking for the literal `[REDACTED]` instead would pass while the secret
    sat in a neighbouring field, which is the failure mode worth testing for.
    """
    argv = ["/home/someone/.venv/bin/agent-security", "test", "mcp",
            "--url", "http://localhost:8080/mcp",
            "--header", f"Authorization: Bearer {FAKE_BEARER}"]
    with mock.patch.object(sys, "argv", argv):
        blob = json.dumps(run_provenance())
    assert FAKE_BEARER not in blob
    assert "[REDACTED]" in blob
    assert json.loads(blob)["invocation"]["argv_redacted"] is True


@pytest.mark.parametrize("argv,secret", [
    (["p", "--header", f"Authorization: Bearer {FAKE_BEARER}"], FAKE_BEARER),
    (["p", "-H", f"X-Api-Key: {FAKE_PAT}"], FAKE_PAT),
    (["p", f"--api-key={FAKE_PAT}"], FAKE_PAT),
    (["p", "--api-key", FAKE_PAT], FAKE_PAT),
    (["p", "--token", FAKE_BEARER], FAKE_BEARER),
    (["p", "--auth-token", FAKE_BEARER], FAKE_BEARER),
    (["p", "--password", FAKE_PASSWORD], FAKE_PASSWORD),
    (["p", f"--authorization=Bearer {FAKE_BEARER}"], FAKE_BEARER),
    (["p", f"Authorization: Bearer {FAKE_BEARER}"], FAKE_BEARER),
    (["p", f"Bearer {FAKE_BEARER}"], FAKE_BEARER),
    (["p", f"--secret={FAKE_PASSWORD}"], FAKE_PASSWORD),
    (["p", "--cookie", f"session={FAKE_BEARER}"], FAKE_BEARER),
    # --- the three shapes an external review got through, 2026-09-07 ---
    # Equals form of a flag that IS in _AUTH_FLAGS but whose bare name is not
    # in _AUTH_NAME_RE. Separated `--key VALUE` was redacted; this was not.
    (["p", f"--key={FAKE_PAT}"], FAKE_PAT),
    # Recognized flag, custom header name inside the value. The value of a
    # recognized flag is redacted whole; parsing it for an auth-shaped key is
    # how this got through.
    (["p", f"--header=X-Custom: {FAKE_PAT}"], FAKE_PAT),
    # Attached short-option value: one element carrying flag AND secret.
    (["p", "-H" + "Authorization: Bearer " + FAKE_BEARER], FAKE_BEARER),
    # Credentials in URL userinfo: a credential under another name that no
    # flag-name path ever sees.
    (["p", "--url", "https://alice:" + FAKE_PASSWORD + "@host.example/mcp"], FAKE_PASSWORD),
    # A canary containing NO auth word, so this cannot pass by the value
    # happening to match the name regex. Must pass on the flag path alone.
    (["p", "--key=" + CANARY], CANARY),
    (["p", "--header=X-Custom: " + CANARY], CANARY),
    (["p", "-H" + "Authorization: Bearer " + CANARY], CANARY),
    # --- third review, 2026-09-07: a credential in a URL QUERY ---
    # Equals-form flag: the flag's own `=` hid the query's `=` from the
    # inline matcher, and the userinfo strip never looks past the netloc.
    # (`api_key` and its `=` are separate literals so the repo's own secret
    # scanner does not read the fixture as an assignment.)
    (["p", "--url=http://127.0.0.1:9/?api_key" + "=" + CANARY], CANARY),
    (["p", "--url=http://127.0.0.1:9/mcp?token=" + CANARY], CANARY),
    # Separated form was caught by accident (partition at the right `=`);
    # pinned so the URL parser, not the accident, is what holds it.
    (["p", "--url", "http://127.0.0.1:9/?token=" + CANARY], CANARY),
    # Names the auth regex does not know. Only an allowlist catches these.
    (["p", "--url", "http://127.0.0.1:9/?sig=" + CANARY], CANARY),
    (["p", "--url=http://127.0.0.1:9/?k=" + CANARY], CANARY),
    (["p", "--url=http://127.0.0.1:9/?transport=sse&code=" + CANARY], CANARY),
    # Bare URL, no flag. And a fragment, which OAuth implicit flows use.
    (["p", "http://127.0.0.1:9/?signature=" + CANARY], CANARY),
    (["p", "http://127.0.0.1:9/cb#access_token=" + CANARY], CANARY),
])
def test_credential_shapes_are_redacted(argv, secret):
    out, redacted = redact_argv(argv)
    assert secret not in " ".join(out), out
    assert redacted is True, out


def test_ordinary_arguments_survive_intact():
    """Over-redaction that eats the command is its own failure.

    A provenance record that cannot say which model or which target was used
    has replaced one unverifiable claim with another.
    """
    out, redacted = redact_argv(
        ["p", "test", "agent-data-injection", "--model", "qwen3.5:latest",
         "--trials", "3", "--url", "http://localhost:8080/mcp"])
    assert out == ["p", "test", "agent-data-injection", "--model",
                   "qwen3.5:latest", "--trials", "3", "--url",
                   "http://localhost:8080/mcp"]
    assert redacted is False


def test_the_rest_of_the_url_survives_query_redaction():
    """Reproducibility: scheme, host, port, path and allowlisted selectors
    are kept byte-for-byte; only the unallowlisted VALUE is replaced."""
    out, redacted = redact_argv(
        ["p", "--url=http://127.0.0.1:9/mcp?transport=sse&api_key" + "=" + CANARY])
    assert out == ["p", "--url=http://127.0.0.1:9/mcp?transport=sse&api_key=[REDACTED]"]
    assert redacted is True


def test_allowlisted_query_selectors_do_not_set_the_flag():
    """`?transport=sse` is a protocol selector, not a secret. Replacing it
    would both lose the reproduction and make `argv_redacted` mean nothing."""
    out, redacted = redact_argv(
        ["p", "--url", "http://localhost:8080/mcp?transport=sse&version=2"])
    assert out == ["p", "--url", "http://localhost:8080/mcp?transport=sse&version=2"]
    assert redacted is False


def test_the_query_allowlist_is_stated_in_not_claimed():
    """A reader of the published block must be able to tell a [REDACTED]
    query value from a credential without reading this module."""
    from protocol_tests.run_provenance import _QUERY_PARAM_ALLOWLIST
    with mock.patch.object(sys, "argv", ["p"]):
        text = " ".join(run_provenance()["not_claimed"])
    for name in _QUERY_PARAM_ALLOWLIST:
        assert name in text, name
    assert "not evidence that a credential was there" in text


def test_help_is_not_treated_as_a_header_flag():
    """`-H` is the header short flag; `-h` is --help. Case matters."""
    out, redacted = redact_argv(["p", "-h", "mcp"])
    assert out == ["p", "-h", "mcp"]
    assert redacted is False


def test_absolute_paths_are_reduced_but_that_is_not_redaction():
    """docs/PRIVACY.md: usernames, directories and topology do not travel.

    It must not set argv_redacted, or the flag stops meaning 'a credential was
    replaced' and starts meaning 'something was reformatted'.
    """
    out, redacted = redact_argv(
        ["/home/alice/.venv/bin/agent-security", "--report",
         "/home/alice/evidence/run.json"])
    assert out == ["agent-security", "--report", "run.json"]
    assert redacted is False
    assert "alice" not in " ".join(out)


@pytest.mark.parametrize("arg,expect", [
    # Windows spellings, tested as DATA on whatever host runs this: the
    # privacy rule is about the record, not about the runner's OS.
    ("--report=C:\\Users\\SyntheticUser\\evidence\\run.json", "--report=run.json"),
    ("C:\\Users\\SyntheticUser\\evidence\\run.json", "run.json"),
    ("--report=C:/Users/SyntheticUser/run.json", "--report=run.json"),
    # UNC carries a HOSTNAME, the first thing docs/PRIVACY.md excludes.
    ("\\\\SyntheticHost\\share\\run.json", "run.json"),
    ("--report=\\\\SyntheticHost\\share\\run.json", "--report=run.json"),
    ("//SyntheticHost/share/run.json", "run.json"),
    # POSIX equals form, and ~user.
    ("--report=/home/alice/evidence/run.json", "--report=run.json"),
    ("--report=~alice/evidence/run.json", "--report=run.json"),
    ("~alice/evidence/run.json", "run.json"),
])
def test_every_absolute_path_spelling_is_reduced_in_both_forms(arg, expect):
    """`--report=C:\\...` and `\\\\host\\share\\...` both survived while
    `not_claimed` promised no absolute path is recorded. Path reduction saw
    only bare arguments and only `/`, `X:\\`, `~/`. Third review, 2026-09-07."""
    out, redacted = redact_argv(["p", arg])
    assert out == ["p", expect], out
    assert redacted is False, "path reduction is not redaction"
    for leak in ("SyntheticUser", "SyntheticHost", "alice", "Users", "share"):
        assert leak not in " ".join(out)


def test_no_hostname_username_or_working_directory_is_recorded():
    """Stated as a decision in the schema; enforced here."""
    import getpass
    import socket

    with mock.patch.object(sys, "argv", ["agent-security", "test", "mcp"]):
        block = run_provenance()

    # Check VALUES, not a substring of the serialised blob. A blob-wide grep
    # collides with legitimate key names: on GitHub Actions the username is
    # literally "runner", and the CI block correctly carries the fields
    # `runner_os` and `runner_arch`. That is a field name, not a leaked
    # identity, and a substring assertion cannot tell the two apart -- it
    # failed CI on #525 for exactly that reason.
    #
    # The `ci` block is exempt: its contents are GitHub-supplied public
    # identifiers (repository, workflow ref, run url) that are emitted on
    # purpose and pinned by their own schema. `not_claimed` is exempt because
    # it is prose that names these very fields in order to say they are absent.
    forbidden_keys = {"hostname", "host", "user", "username", "cwd",
                      "working_directory", "home"}

    def values(node, path="", skip=("ci", "not_claimed")):
        if isinstance(node, dict):
            for k, v in node.items():
                assert k not in forbidden_keys, (
                    f"provenance emitted a forbidden key {k!r} at {path}"
                )
                if k in skip:
                    continue
                yield from values(v, f"{path}.{k}", skip)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from values(v, f"{path}[{i}]", skip)
        elif isinstance(node, str):
            yield path, node

    leaks = [leak for leak in (socket.gethostname(), getpass.getuser(),
                               os.getcwd(), str(Path.home()))
             if leak and len(leak) > 3]
    for path, value in values(block):
        for leak in leaks:
            assert leak not in value, (
                f"{leak!r} reached the provenance block at {path} = {value!r}"
            )


# --- 3. the report carries both blocks -------------------------------------

def test_both_blocks_are_emitted_when_either_is_given():
    """Half a provenance claim is the hand-assembled-header shape again."""
    r = _report(provenance=run_provenance())
    assert r["subject"]["kind"] == "none", "an absent subject is stated, not omitted"
    assert r["provenance"]["schema"] == PROVENANCE_SCHEMA


def test_a_subject_without_a_provenance_is_refused():
    with pytest.raises(ValueError, match="provenance is required"):
        _report(subject=subject_model("qwen3.5:latest"))


def test_neither_is_emitted_when_neither_is_asked_for():
    """Backward compatibility is the whole reason these are optional."""
    r = _report()
    assert "provenance" not in r
    assert "subject" not in r


def test_a_report_carrying_both_validates_clean():
    r = _report(provenance=run_provenance(), subject=subject_model("qwen3.5:latest"))
    errs = [e for e in validate_attestation_report(r) if "NOT SCHEMA-VALIDATED" not in e]
    assert errs == [], errs


def test_validator_rejects_a_model_subject_that_names_no_model():
    r = _report(provenance=run_provenance(), subject=subject_model("qwen3.5:latest"))
    r["subject"]["model"] = None
    assert any("names no model" in e for e in validate_attestation_report(r))


def test_the_model_rule_also_fires_without_jsonschema():
    """The rule must not evaporate on a machine where the validator is absent.

    That machine is told 'NOT SCHEMA-VALIDATED' and, before this, nothing else.
    """
    r = _report(provenance=run_provenance(), subject=subject_model("qwen3.5:latest"))
    r["subject"]["model"] = None
    with mock.patch.dict(sys.modules, {"jsonschema": None}):
        errs = validate_attestation_report(r)
    assert any("NOT SCHEMA-VALIDATED" in e for e in errs), "wrong path exercised"
    assert any("names no model" in e for e in errs), errs


def test_off_enum_absent_reasons_are_rejected():
    """The vocabulary is closed, so an invented reason is not a novel fact."""
    r = _report(provenance=run_provenance(), subject=subject_model("qwen3.5:latest"))
    r["subject"]["model"]["digest_absent_reason"] = "because_reasons"
    assert validate_attestation_report(r)


def test_a_dropped_key_is_rejected():
    """additionalProperties:false catches additions; `required` catches losses."""
    r = _report(provenance=run_provenance(), subject=subject_http("http://x/y"))
    del r["subject"]["url"]
    assert any("'url' is a required property" in e
               for e in validate_attestation_report(r))


# --- 3b. publishing a report keeps the blocks well-formed ------------------

def test_publishing_redacts_the_target_without_deleting_the_key():
    """`strip_sensitive_fields` DELETES any key containing 'url'.

    Applied naively to these blocks that removes `subject.url`,
    `subject.url_absent_reason` and `ci.run_url` -- all three schema-required
    -- so a published record stopped validating. It was found by trying it,
    not by reading the stripper.

    The rule is right about what must not travel and wrong about how: a deleted
    key destroys exactly the property these blocks exist to have.
    """
    from protocol_tests.attestation_registry import strip_sensitive_fields

    target = "http://internal.example.invalid:8080/mcp"
    r = _report(provenance=run_provenance(), subject=subject_http(target))
    cleaned = strip_sensitive_fields(r)

    errs = [e for e in validate_attestation_report(cleaned)
            if "NOT SCHEMA-VALIDATED" not in e]
    assert errs == [], errs
    assert cleaned["subject"]["url"] is None
    assert cleaned["subject"]["url_absent_reason"] == "redacted_for_publication"
    assert cleaned["provenance"]["ci"]["run_url"] is None
    assert "internal.example.invalid" not in json.dumps(cleaned), (
        "the target survived publication; the redaction is decorative")


def test_redaction_for_publication_is_its_own_reason():
    """Four different facts about the same null, kept apart.

    'we did not ask', 'it does not apply', 'we asked and could not tell' and
    'we know and are not putting it in this copy' are not the same, and a
    reader of a published record has to be able to tell the last from the rest.
    """
    from protocol_tests.run_provenance import redact_for_publication

    model = redact_for_publication(subject_model("qwen3.5:latest"))
    assert model["url_absent_reason"] == "not_applicable", (
        "a model subject never had a URL; redaction must not overwrite that")
    assert model["model"]["digest_absent_reason"] == "not_queried"

    http = redact_for_publication(subject_http("http://x.invalid/y"))
    assert http["url_absent_reason"] == "redacted_for_publication"

    absent = redact_for_publication(subject_http(None))
    assert absent["url_absent_reason"] == "not_supplied", (
        "nothing was withheld, so nothing may claim to have been")


# --- 4. nothing already published moved ------------------------------------

RECORDS = sorted((REPO / "attestations").rglob("*-record.json"))


def test_there_are_records_to_check():
    """A loop over an empty glob passes and proves nothing."""
    assert len(RECORDS) >= 2, RECORDS


@pytest.mark.parametrize("record", RECORDS, ids=lambda p: p.name)
def test_a_published_record_still_validates(record):
    rec = json.loads(record.read_text())
    errs = [e for e in validate_attestation_report(rec["payload"]["report"])
            if "NOT SCHEMA-VALIDATED" not in e]
    assert errs == [], errs


@pytest.mark.parametrize("record", RECORDS, ids=lambda p: p.name)
def test_a_published_record_still_hashes_to_what_it_was_published_as(record):
    """The canonicalisation is pinned in the server contract, section 4.1.

    If a schema change forced a republish, the signature over the old bytes
    would be worthless and the old citation would break. Optional fields are
    how that is avoided; this is the assertion that says so.
    """
    rec = json.loads(record.read_text())
    payload_bytes = json.dumps(rec["payload"], sort_keys=True).encode()
    assert hashlib.sha256(payload_bytes).hexdigest() == rec["verification_hash"]


def test_schema_version_was_not_bumped():
    """A `const`. Bumping it invalidates every document already in the world."""
    assert SCHEMA["properties"]["schema_version"]["const"] == "1.0.0"


def test_the_new_fields_are_optional():
    assert "provenance" not in SCHEMA["required"]
    assert "subject" not in SCHEMA["required"]
    assert SCHEMA["dependentRequired"]["subject"] == ["provenance"]


def test_the_new_defs_are_closed():
    """additionalProperties:false, or the block accepts anything at all."""
    for name in ("provenance", "subject", "model_identity"):
        assert SCHEMA["$defs"][name]["additionalProperties"] is False, name


def test_the_schema_enum_matches_the_code_enum():
    """One vocabulary. Two that can drift is the defect shape, not the fix."""
    enum = SCHEMA["$defs"]["model_identity"]["properties"]["digest_absent_reason"]["enum"]
    assert enum == [None, *ABSENT_REASONS]


# --- 5. the module this was built for --------------------------------------

def test_adi_report_is_a_document_with_a_header(tmp_path):
    """End to end, through the module's own `--report`."""
    out = tmp_path / "adi.json"
    env = dict(os.environ)
    env.update({
        "HARNESS_ADI_MODEL": "qwen3.5:latest",
        # A closed port, so the probe fails fast and deterministically instead
        # of depending on whether this machine happens to be running Ollama.
        "HARNESS_ADI_OLLAMA": "http://127.0.0.1:1/api/generate",
    })
    proc = subprocess.run(
        [sys.executable, "-m", "protocol_tests.agent_data_injection",
         "--trials", "1", "--report", str(out)],
        cwd=REPO, env=env, capture_output=True, text=True)
    assert out.exists(), proc.stdout + proc.stderr

    doc = json.loads(out.read_text())
    assert not isinstance(doc, list), (
        "the report is a bare list again; there is nowhere to put a header and "
        "the next one gets assembled by hand")
    assert set(doc) == {"provenance", "subject", "results"}
    assert doc["subject"]["kind"] == "model"
    assert doc["subject"]["model"]["tag"] == "qwen3.5:latest"
    assert doc["subject"]["model"]["digest_absent_reason"] == "not_queried"
    assert doc["provenance"]["schema"] == PROVENANCE_SCHEMA
    assert FAKE_BEARER not in json.dumps(doc)
    assert len(doc["results"]) == 3


def test_the_hand_assembled_evidence_file_is_left_alone():
    """It is a record of a run that happened.

    Editing a dated evidence artifact so it looks machine-generated is
    fabrication, which is worse than the defect. It stays as it is, and this
    test exists so nobody 'tidies' it into the new shape later.
    """
    raw = REPO / "docs" / "evidence" / "adi" / "2026-09-02-qwen35-n3-raw.json"
    doc = json.loads(raw.read_text())
    assert doc["runtime"]["model_tag"] == "qwen3.5:latest"
    assert "provenance" not in doc, (
        "this file predates run_provenance and must keep saying so; the header "
        "in it was typed by a person and no later edit can make that untrue")


# ---------------------------------------------------------------------------
# The publication copy is where a leak actually matters.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv,secret", [
    (["p", "--key=" + CANARY], CANARY),
    (["p", "--header=X-Custom: " + CANARY], CANARY),
    (["p", "-H" + "Authorization: Bearer " + CANARY], CANARY),
    (["p", "--url", "https://alice:" + CANARY + "@host.example/mcp"], CANARY),
    # equals form of the same thing; the strip was anchored to the element
    (["p", "--url=https://alice:" + CANARY + "@host.example/mcp"], CANARY),
    # third review: a recognized credential NAME in the query, equals-form
    # flag. Survived run_provenance() -> strip_sensitive_fields() with
    # argv_redacted=False.
    (["p", "--url=http://127.0.0.1:9/?api_key" + "=" + CANARY], CANARY),
    (["p", "--url", "http://127.0.0.1:9/?sig=" + CANARY], CANARY),
])
def test_no_recognized_credential_survives_into_the_publication_copy(argv, secret):
    """`run_provenance()` -> `strip_sensitive_fields()` is the path a record
    takes to a registry. An external review found three recognized-flag
    shapes surviving it with `argv_redacted=False`. The stripper is not a
    second scrubber; the provenance block must arrive already clean.
    """
    from protocol_tests.attestation_registry import strip_sensitive_fields
    with mock.patch.object(sys, "argv", argv):
        block = run_provenance()
    published = strip_sensitive_fields({"provenance": block})
    assert secret not in json.dumps(published), published["provenance"]["invocation"]
    assert published["provenance"]["invocation"]["argv_redacted"] is True


@pytest.mark.parametrize("argv", [
    ["p", "--report=C:\\Users\\SyntheticUser\\evidence\\run.json"],
    ["p", "--report", "\\\\SyntheticHost\\share\\run.json"],
])
def test_no_absolute_path_survives_into_the_publication_copy(argv):
    """The `not_claimed` sentence promises no absolute path is recorded. Held
    at the publication copy, for the two spellings that broke it."""
    from protocol_tests.attestation_registry import strip_sensitive_fields
    with mock.patch.object(sys, "argv", argv):
        block = run_provenance()
    published = json.dumps(strip_sensitive_fields({"provenance": block}))
    assert "SyntheticUser" not in published
    assert "SyntheticHost" not in published
    assert "run.json" in published


def test_innocent_arguments_are_not_redacted():
    """Over-redaction hides what was run; the flag must mean 'a secret was here'."""
    out, redacted = redact_argv(["p", "--url", "http://localhost:8080/mcp",
                                 "--trials", "5", "--report", "/home/alice/out.json"])
    assert redacted is False, out
    assert out == ["p", "--url", "http://localhost:8080/mcp", "--trials", "5",
                   "--report", "out.json"], out
