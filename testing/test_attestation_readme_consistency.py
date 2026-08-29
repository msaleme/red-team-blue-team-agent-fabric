"""Every attestation README must state the verification_hash its record carries.

Why this exists (#369, found while auditing #384's material):

`attestations/self/README.md` published `verification_hash: e69e70f8...` for a record
whose canonical hash is `48235d1b...`. The stated value matched no artifact in the
repository -- not a file digest, not either record, not either report. It was a
64-hex identifier with no referent, sitting in the one directory whose entire purpose
is evidentiary integrity.

The cause was not carelessness about a number. #386 (`2c7a9ec`) regenerated the record
so it states its own independence inside the signature. That changed the signed payload,
which changed the canonical hash by construction. The record moved and its README did
not, so the README kept describing the pre-fix record -- both the old hash and a "known
gap" that the same commit had closed.

That is the #369 drift class: a fact restated in prose next to the artifact that owns
it, with nothing asserting the two agree. The durable fix for a restated value is to
delete it or to automate the comparison. These records are published evidence, so the
hash has to stay legible in the README -- which leaves automating the comparison.

Scope: this checks one fact, that README prose agrees with the record it documents. It
is not the #369 release-claims manifest and does not check test counts, release tags, or
coverage revisions. It says nothing about whether a record's contents are true; a
matching hash proves the README and the record agree, not that either is correct.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ATTESTATIONS = REPO_ROOT / "attestations"

# Both README styles carry the value on one line with its label:
#   - `verification_hash`: `<64 hex>`
#   | `verification_hash` | `<64 hex>` |
HASH_ON_LABELLED_LINE = re.compile(r"verification_hash.*?([0-9a-f]{64})")


def _record_files() -> list[Path]:
    if not ATTESTATIONS.is_dir():
        return []
    return sorted(ATTESTATIONS.glob("*/*-record.json"))


def test_attestation_records_are_present():
    """Assert a positive expected set, so an empty glob cannot read as success.

    Without this, deleting the attestations directory would make every parametrised
    case below vanish and the suite would still report green.
    """
    records = _record_files()
    assert records, (
        "no attestation records found under attestations/*/*-record.json. "
        "If records were intentionally removed, remove this test in the same commit."
    )
    dirs = {p.parent.name for p in records}
    assert {"self", "external"} <= dirs, (
        f"expected both self/ and external/ attestation records, found dirs: {sorted(dirs)}"
    )


@pytest.mark.parametrize("record_path", _record_files(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_readme_states_the_hash_its_record_carries(record_path: Path):
    record = json.loads(record_path.read_text(encoding="utf-8"))
    actual = record.get("verification_hash")
    assert actual, f"{record_path.relative_to(REPO_ROOT)} carries no verification_hash"

    readme = record_path.parent / "README.md"
    assert readme.is_file(), (
        f"{record_path.relative_to(REPO_ROOT)} has no sibling README.md. A published "
        f"record without a README is unreviewable by a reader who is not us."
    )

    stated = HASH_ON_LABELLED_LINE.findall(readme.read_text(encoding="utf-8"))
    assert stated, (
        f"{readme.relative_to(REPO_ROOT)} states no verification_hash. The record at "
        f"{record_path.name} carries {actual}, and a reader has no way to check they agree."
    )
    assert actual in stated, (
        f"{readme.relative_to(REPO_ROOT)} states verification_hash {stated!r}, but "
        f"{record_path.name} carries {actual!r}. The README is describing a different "
        f"record than the one committed beside it -- most likely the record was "
        f"regenerated and the prose was not updated (see #386)."
    )
