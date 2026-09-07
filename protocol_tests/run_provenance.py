"""What produced this run, and what it was run against -- stated in the artifact.

## The defect this closes

`docs/evidence/adi/2026-09-02-qwen35-n3-raw.json` carries a `runtime` block
naming an Ollama server version, a model tag, a manifest digest, a parameter
size and a quantisation. None of it came from the harness. `--report` in
`agent_data_injection.py` wrote `json.dump([r.__dict__ for r in results], fh)`
-- a bare LIST, with nowhere to put a header -- so the header was assembled by
hand from a shell session that is not part of the record. A verdict about a
model whose identity was typed in beside it is a verdict about nothing
checkable.

The module DOES talk to the model: `ollama_model()` POSTs to
`/api/generate`. What it never does is ask `/api/show` who answered. Generation
and identity are different questions and only one of them was being asked.

## The invariant

**Every key in a provenance or subject block is always present.** Absence of
knowledge is `null` PAIRED WITH a sibling `<field>_absent_reason` naming why,
drawn from a closed enum. Formally, for every field `X` that has a sibling
`X_absent_reason`, exactly one of the two is non-null.

Two things are forbidden and both have bitten this repository:

- **A missing key.** A reader cannot distinguish "the producer does not emit
  this" from "the producer emitted it and something dropped it". This is the
  same argument `summary.inconclusive` won in #521: emitted at zero, always,
  because a reader who can infer a value from the others will.
- **The string `"unknown"`.** It is indistinguishable from a model literally
  tagged `unknown`, from a corpus named `unknown`, and from a bug that
  stringified a `None`. `protocol_tests/version.py::get_harness_version()`
  returns exactly that string as its last resort, so this module translates it
  back into `None` plus `version_not_discoverable` rather than letting a
  sentinel that means "we failed" travel as if it were data.

## What is deliberately NOT recorded

No hostname, no username, no working directory, no absolute paths.
`docs/PRIVACY.md` lists "Hostnames, paths, or any part of your infrastructure
topology" under what is never collected, and a report a user is invited to
publish is held to the same line as telemetry. EVERY absolute path in argv is
reduced to its basename for that reason -- not only `argv[0]`. On a developer
machine `--report /home/<username>/evidence/run.json` carries a username and a
directory tree just as surely as the interpreter path does.

## Argv redaction is the load-bearing part

Documented usage includes `--header "Authorization: Bearer ..."`. Recording raw
argv into an artifact that is meant to be published and signed would turn a
provenance feature into a credential-disclosure feature -- the argument is not
that a leak is likely, it is that this block exists to be handed to third
parties. `redact_argv()` therefore redacts by flag name, by `--flag=value`,
and by `key: value` / `key=value` embedded inside a single argument, and sets
`argv_redacted` when anything was replaced.

Redaction is best-effort and says so: it recognises a list of auth-shaped
names, and a credential passed under a name not on that list survives. That is
why the field is `argv_redacted` (something was replaced) and not
`argv_is_safe` (a claim about what remains).
"""
from __future__ import annotations

import copy
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "ABSENT_REASONS",
    "PROVENANCE_SCHEMA",
    "ci_identity",
    "git",
    "redact_argv",
    "redact_for_publication",
    "run_provenance",
    "subject_corpus",
    "subject_http",
    "subject_model",
    "subject_none",
    "tool_versions",
]

PROVENANCE_SCHEMA = "agent-security-harness/run-provenance/v1"

#: The closed vocabulary a null value may cite. A reason outside this set is a
#: bug, and `schemas/attestation-report.json` pins the same list, so a document
#: that invents one fails validation rather than reading as a novel fact.
ABSENT_REASONS = (
    # the fact was never sought
    "not_queried",          # the tool never asked the thing that knows
    "not_supplied",         # the caller did not pass it
    # the fact does not apply
    "not_applicable",       # wrong arm of the subject union
    "not_running_in_ci",    # no workflow produced this
    # the fact was sought and could not be had
    "not_a_git_checkout",
    "git_unavailable",
    "no_matching_tag",
    "version_not_discoverable",
    "package_not_installed",
    "not_readable",         # the file is there in name and could not be read
    "unsupported_by_target",
    # the fact was known and deliberately withheld from THIS copy
    "redacted_for_publication",
)

#: One spelling of the paired-reason suffix, so the invariant cannot drift
#: between the builder and the redactor.
_REASON_SUFFIX = "_absent_reason"

REDACTED = "[REDACTED]"

#: Names whose VALUE is a credential. Matched as a substring of a flag name and
#: of a `key: value` key, case-insensitively, so `--api-key`, `--apiKey`,
#: `X-Api-Key:` and `--bearer-token=` are all caught by one pattern.
_AUTH_NAME_RE = re.compile(
    r"(authorization|authentication|\bauth\b|token|api[-_]?key|apikey|secret|"
    r"password|passwd|credential|cookie|bearer|private[-_]?key|session[-_]?id)",
    re.IGNORECASE,
)

#: Flags whose NEXT argv element is the value. `-H` is here because that is the
#: short spelling of the header flag; lowercase `-h` is NOT, because it is
#: `--help` and redacting the argument after it would corrupt the record to
#: hide a value that was never a credential. Matching is case-sensitive for
#: exactly that reason.
_AUTH_FLAGS = {
    "-H", "--header", "--headers",
    "--token", "--auth-token", "--bearer",
    "--api-key", "--apikey", "--key",
    "--auth", "--authorization",
    "--secret", "--password", "--passwd", "--credential", "--cookie",
}


# ---------------------------------------------------------------------------
# Moved here from scripts/build_provenance.py
#
# These three answered "what commit is this", "what workflow ran this" and
# "what built this" for the RELEASE statement. A run statement needs the same
# three answers. Two implementations of "what commit is this" that can disagree
# is the defect shape this file exists to avoid, so there is one, here, and
# scripts/build_provenance.py imports it.
# ---------------------------------------------------------------------------

def git(*args: str, cwd: Path | None = None) -> str | None:
    """Run a git command; None if git is absent or the command failed.

    None is deliberately ambiguous between "no git binary" and "not a checkout"
    at THIS level -- the callers below distinguish them, because only they know
    which question was being asked.
    """
    try:
        return subprocess.run(("git", *args), cwd=cwd, capture_output=True,
                              text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def tool_versions(names=("setuptools", "wheel", "build", "pip")) -> dict:
    """Versions of the tools that govern what the artifact contains.

    setuptools is the build backend, so its version is part of what shipped.
    A tool that is absent is recorded as absent rather than omitted: a missing
    key and a tool that was not installed are different facts.
    """
    from importlib.metadata import PackageNotFoundError, version
    out = {}
    for name in names:
        try:
            out[name] = version(name)
        except PackageNotFoundError:
            out[name] = None
    return out


def ci_identity() -> dict:
    """The workflow run that produced this, from the environment GitHub sets.

    Every value is None outside CI. That is deliberate: a locally built
    statement must not look like a CI-built one, and the verifier can tell.
    """
    env = os.environ.get
    run_id, repo = env("GITHUB_RUN_ID"), env("GITHUB_REPOSITORY")
    return {
        "repository": repo,
        "workflow": env("GITHUB_WORKFLOW"),
        "workflow_ref": env("GITHUB_WORKFLOW_REF"),
        "run_id": run_id,
        "run_attempt": env("GITHUB_RUN_ATTEMPT"),
        "run_url": (f"{env('GITHUB_SERVER_URL', 'https://github.com')}/{repo}"
                    f"/actions/runs/{run_id}") if (run_id and repo) else None,
        "runner_os": env("RUNNER_OS"),
        "runner_arch": env("RUNNER_ARCH"),
        "event": env("GITHUB_EVENT_NAME"),
    }


# ---------------------------------------------------------------------------
# The paired-null helper. One function, so the invariant cannot be spelled two
# ways in two places.
# ---------------------------------------------------------------------------

def _pair(name: str, value: Any, reason: str) -> dict[str, Any]:
    """`{name: value, name_absent_reason: None}` or `{name: None, ...: reason}`.

    `value` is normalised: empty string and the literal `"unknown"` are treated
    as absence, because a producer that failed and a producer that observed the
    word are otherwise the same document.
    """
    if reason not in ABSENT_REASONS:
        raise ValueError(f"{reason!r} is not one of ABSENT_REASONS")
    if isinstance(value, str) and value.strip().lower() in ("", "unknown"):
        value = None
    return {name: value,
            f"{name}{_REASON_SUFFIX}": None if value is not None else reason}


# ---------------------------------------------------------------------------
# Argv redaction
# ---------------------------------------------------------------------------

def _split_flag(arg: str) -> tuple[str, str] | None:
    """`--api-key=sk-...` -> ('--api-key', 'sk-...'); otherwise None."""
    if arg.startswith("-") and "=" in arg:
        flag, _, value = arg.partition("=")
        return flag, value
    return None


def _redact_inline(arg: str) -> str:
    """Redact the value half of an embedded `key: value` or `key=value`.

    This is the `--header "Authorization: Bearer ..."` case, where the
    credential is inside ONE argv element and flag-name matching never sees it.
    """
    for sep in (":", "="):
        if sep in arg:
            key, _, value = arg.partition(sep)
            if value.strip() and _AUTH_NAME_RE.search(key):
                return f"{key}{sep} {REDACTED}" if sep == ":" else f"{key}{sep}{REDACTED}"
    # A bare token pasted as its own argument, with no key beside it. Matched
    # on the scheme word rather than on token shape, because a shape heuristic
    # ("looks high-entropy") eats innocent arguments AND still misses the
    # shapes nobody thought of -- it buys false positives without buying
    # completeness.
    if re.match(r"^(bearer|basic|token)\s+\S", arg, re.IGNORECASE):
        scheme = arg.split(None, 1)[0]
        return f"{scheme} {REDACTED}"
    return arg


def _basename_if_absolute(arg: str) -> str:
    """`/home/alice/runs/out.json` -> `out.json`; everything else unchanged.

    Applied to EVERY element, not only `argv[0]`. `--report
    /home/<user>/evidence/run.json` puts a username and a directory tree into
    the record just as surely as the interpreter path does, and the first
    version of this function only cleaned `argv[0]` -- which read as a rule
    about paths while enforcing one about position.
    """
    if arg.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", arg) or arg.startswith("~/"):
        return os.path.basename(arg.replace("\\", "/")) or arg
    return arg


def redact_argv(argv: list[str]) -> tuple[list[str], bool]:
    """Return (argv with credentials removed, whether a credential was replaced).

    Two different reductions happen here and only one of them sets the flag.

    *Credential redaction* replaces a value that is a secret, and sets
    `argv_redacted`. That flag is the signal an auditor reads.

    *Path reduction* replaces every absolute path with its basename,
    unconditionally, because `docs/PRIVACY.md` says usernames, directories and
    topology do not travel. It is not evidence of anything and does not set the
    flag; it is stated in `not_claimed` on every document instead, so a reader
    who sees a bare basename knows it was never a full path in this record.
    """
    if not argv:
        return [], False

    out = [_basename_if_absolute(argv[0])]
    redacted = False
    expect_value = False

    for arg in argv[1:]:
        if expect_value:
            out.append(REDACTED)
            redacted = True
            expect_value = False
            continue

        if arg in _AUTH_FLAGS or (arg.startswith("-") and _AUTH_NAME_RE.search(arg)
                                  and "=" not in arg):
            out.append(arg)
            expect_value = True
            continue

        split = _split_flag(arg)
        if split and _AUTH_NAME_RE.search(split[0]) and split[1]:
            out.append(f"{split[0]}={REDACTED}")
            redacted = True
            continue

        cleaned = _redact_inline(arg)
        if cleaned != arg:
            redacted = True
        out.append(_basename_if_absolute(cleaned))

    # A trailing auth flag with no value after it. Nothing to redact, and
    # dropping the flag would misreport the command that was run.
    return out, redacted


# ---------------------------------------------------------------------------
# Subjects
# ---------------------------------------------------------------------------

_SUBJECT_KEYS = ("url", "model", "corpus")


def _subject(kind: str, **present: Any) -> dict[str, Any]:
    """A tagged union with a FIXED key set.

    Every arm carries every key. The arms that do not apply cite
    `not_applicable`, which is a different fact from `not_supplied`: "this run
    had no URL because its subject was a model" and "this run had a URL and
    nobody recorded it" must not be the same document.
    """
    block: dict[str, Any] = {"kind": kind}
    for key in _SUBJECT_KEYS:
        if key in present:
            value, reason = present[key]
            block.update(_pair(key, value, reason))
        else:
            block.update(_pair(key, None, "not_applicable"))
    return block


def subject_http(url: str | None = None) -> dict[str, Any]:
    """The subject is an HTTP target."""
    return _subject("http", url=(url, "not_supplied"))


def subject_model(
    tag: str | None = None,
    *,
    runtime: str | None = None,
    digest: str | None = None,
    family: str | None = None,
    parameter_size: str | None = None,
    quantization: str | None = None,
    detail_reason: str = "not_queried",
) -> dict[str, Any]:
    """The subject is a model in the loop.

    `detail_reason` defaults to `not_queried` and that default is the point.
    The ADI module reaches Ollama's `/api/generate` and never its `/api/show`,
    so the digest, family, parameter size and quantisation are facts the tool
    could obtain and does not. Recording that as `not_queried` says so; leaving
    the keys out would let the next hand-assembled header slide in beside them.

    A model subject with no tag is rejected here rather than validated later:
    `kind: "model"` with `model: null` is a claim about a model that names no
    model, and the caller passing None knows more about why than the schema
    does.
    """
    if not tag:
        raise ValueError(
            "subject_model() requires a tag. A run whose subject is a model "
            "that cannot be named is not a run about a model -- use "
            "subject_none() and state that no model was configured.")
    identity: dict[str, Any] = {"tag": tag}
    identity.update(_pair("runtime", runtime, detail_reason))
    identity.update(_pair("digest", digest, detail_reason))
    identity.update(_pair("family", family, detail_reason))
    identity.update(_pair("parameter_size", parameter_size, detail_reason))
    identity.update(_pair("quantization", quantization, detail_reason))
    return _subject("model", model=(identity, "not_supplied"))


def subject_corpus(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """The subject is a local corpus. Only the basename and size travel.

    The directory a corpus sits in is infrastructure topology; the file itself
    is the subject. A digest is left to the caller: hashing a large corpus is a
    cost this function should not impose on every run without being asked.
    """
    if path is None:
        return _subject("corpus", corpus=(None, "not_supplied"))
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError:
        size = None
    corpus = {"name": p.name}
    corpus.update(_pair("size_bytes", size, "not_readable"))
    return _subject("corpus", corpus=(corpus, "not_supplied"))


def subject_none() -> dict[str, Any]:
    """No subject: the run did not reach one. Every arm is `not_applicable`."""
    return _subject("none")


def redact_for_publication(block: dict[str, Any]) -> dict[str, Any]:
    """Null out the target-identifying fields of a provenance or subject block.

    `attestation_registry.strip_sensitive_fields()` DELETES any key whose name
    contains `url`, `endpoint`, `host`, `address` or `path`. Applied to these
    blocks that removes `subject.url`, `subject.url_absent_reason` and
    `ci.run_url` -- three keys the schema requires -- so a published record no
    longer validated. The stripper is right about what must not travel and
    wrong about how: deleting a key here destroys the property the block exists
    to have, which is that a reader can always tell an unknown from an omission.

    So the value goes and the key stays, with `redacted_for_publication` as the
    reason. That is a fourth distinct state and it should be: "we did not ask",
    "it does not apply", "we asked and could not tell" and "we know and are not
    putting it in this copy" are four different facts about the same null.

    `ci.run_url` is a public github.com actions URL rather than a target, but
    it is nulled too: the stripper's rule is about what leaves the machine, and
    narrowing it here would be this function deciding which of the stripper's
    judgements to honour.
    """
    out = copy.deepcopy(block)
    if "url" in out and f"url{_REASON_SUFFIX}" in out:
        if out["url"] is not None:
            out["url"] = None
            out[f"url{_REASON_SUFFIX}"] = "redacted_for_publication"
    ci = out.get("ci")
    if isinstance(ci, dict) and "run_url" in ci:
        ci["run_url"] = None
    return out


# ---------------------------------------------------------------------------
# The statement
# ---------------------------------------------------------------------------

def _source_block(repo: Path) -> dict[str, Any]:
    """Commit, ref and dirtiness, each with its own reason for being absent.

    They fail for DIFFERENT reasons, which is why there is a reason per field
    and not one for the block: a checkout with no tag on HEAD knows its commit
    perfectly well.

    `--untracked-files=no` is carried over from the release statement, where
    v4.18.0rc1 is the reason it is there: `dist/`, `*.egg-info/` and `build/`
    exist by the time any report is written, so a status that counts untracked
    files reports every real run as dirty.
    """
    env = os.environ.get
    commit = env("GITHUB_SHA") or git("rev-parse", "HEAD", cwd=repo)
    if commit is None:
        reason = "git_unavailable" if git("--version") is None else "not_a_git_checkout"
        block = _pair("commit", None, reason)
        block.update(_pair("ref_name", None, reason))
        block.update(_pair("tree_is_dirty", None, reason))
        return block

    block = _pair("commit", commit, "not_a_git_checkout")
    block.update(_pair(
        "ref_name",
        env("GITHUB_REF_NAME") or git("describe", "--tags", "--exact-match", cwd=repo),
        "no_matching_tag"))
    status = git("status", "--porcelain", "--untracked-files=no", cwd=repo)
    block.update(_pair("tree_is_dirty", None if status is None else bool(status),
                       "not_a_git_checkout"))
    return block


def _harness_version() -> str | None:
    """None rather than the string this repository already returns for failure.

    `get_harness_version()` ends `return "unknown"`. Five call sites want a
    string and that is fine for them. A signed artifact is not one of them.
    """
    try:
        from .version import get_harness_version
        return get_harness_version()
    except Exception:                                    # noqa: BLE001 - reported
        return None


def run_provenance(**overrides: Any) -> dict[str, Any]:
    """Build the provenance block for one run.

    Keyword overrides replace top-level keys, for callers that know something
    this function cannot -- and for tests, which must be able to pin every
    environment-derived value or they measure the runner rather than the code
    (the lesson `testing/test_release_provenance.py` records at `CI_VARS`).

    An override is not validated against `ABSENT_REASONS`: a caller replacing a
    whole sub-block is responsible for its shape, and the schema is what
    catches a wrong one.
    """
    repo = Path(__file__).resolve().parent.parent
    argv, argv_redacted = redact_argv(list(sys.argv))

    ci = ci_identity()
    tool: dict[str, Any] = {"name": "agent-security-harness"}
    tool.update(_pair("version", _harness_version(), "version_not_discoverable"))

    statement: dict[str, Any] = {
        "schema": PROVENANCE_SCHEMA,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "source": _source_block(repo),
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "tools": tool_versions(),
        },
        "invocation": {
            "argv": argv,
            # Something WAS replaced -- not a claim that what remains is safe.
            # The name list is best-effort by construction.
            "argv_redacted": argv_redacted,
        },
        # Present at every key even outside CI, where every value is None. A
        # locally produced statement must not be able to pass for a CI one, and
        # a reader must be able to see that it was asked.
        "ci": ci,
        # The pairing, spelled out rather than via `_pair`: `ci` is a block of
        # nine values, and it is the WHOLE block that is absent outside CI.
        "ci_absent_reason": (
            None if any(v is not None for v in ci.values()) else "not_running_in_ci"),
        "not_claimed": [
            "This block states what produced a run. It does not state that the "
            "run's verdicts are correct, that the target was configured as an "
            "operator intended, or that anything about the target is secure.",
            "argv_redacted true means something was replaced. It is not a claim "
            "that no credential remains: redaction matches a list of auth-shaped "
            "names and a credential passed under another name survives.",
            "No hostname, username, working directory or absolute path is "
            "recorded, by the rule in docs/PRIVACY.md. Every absolute path in "
            "argv is reduced to its basename, unconditionally and without "
            "setting argv_redacted, so a bare filename here was never a full "
            "path in this record. Their absence is a decision, not an omission.",
        ],
    }
    statement.update(overrides)
    return statement
