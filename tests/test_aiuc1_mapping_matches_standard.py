"""The AIUC-1 mapping must say what the published standard says.

Until 2026-10-30 `configs/aiuc1_mapping.yaml` attached titles to AIUC-1 requirement IDs that were not
AIUC-1's: 0 of its 24 titles matched the standard (B003 was "Protocol Downgrade Prevention"; the
requirement is "Manage public release of technical details"). Every row was COVERED, and README, SKILL.md,
TEST-INVENTORY and aiuc1-prep repeated "19 of 20 testable requirements (95%)". The YAML is hashed into every
evidence pack, so the invented titles shipped to users. An outside review found it; nothing here did.

These checks pin the mapping and the crosswalk to a dated snapshot of the standard
(`configs/aiuc1_standard_2026-10-15.json`, from standard.aiuc-1.com/llms.txt). Refreshing the snapshot is a
deliberate, dated change; when AIUC-1 ships a new release the titles here must follow it.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "configs" / "aiuc1_standard_2026-10-15.json"
MAPPING = ROOT / "configs" / "aiuc1_mapping.yaml"
CROSSWALK = ROOT / "docs" / "AIUC1-CROSSWALK.md"
CLAIM_SURFACES = ["README.md", "SKILL.md", "docs/TEST-INVENTORY.md", "docs/aiuc1-prep.md", "docs/AIUC1-CROSSWALK.md",
                  "docs/AIUC1-SUBMISSION-OUTLINE.md", "docs/AIUC1-SUBMISSION-EMAIL.md", "docs/QUICKSTART.md"]
OUTLINE = ROOT / "docs" / "AIUC1-SUBMISSION-OUTLINE.md"
# Retired coverage claims: "19 of 20" / "95%" (pre-2026-10-30) and the 24-requirement set
# ("23/24", "23 of 24", "all 24", "of 24 requirements") that the outline, email and quickstart kept after it.
RETIRED_CLAIM = re.compile(r"19 of\s*20|19/20|\b95%|\b23\s*(?:/|of)\s*24\b|\ball 24\b|\bof 24 requirements")


def _snapshot() -> dict[str, dict]:
    data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    return {r["id"]: r for r in data["requirements"]}


def _mapping_rows(cfg: dict) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for category in (cfg.get("categories") or {}).values():
        for req_id, req in (category.get("requirements") or {}).items():
            rows[req_id] = req
    return rows


def title_mismatches(rows: dict[str, dict], snapshot: dict[str, dict]) -> list[str]:
    """Rows whose ID is unknown, retired, or titled differently from the published standard."""
    problems = []
    for req_id, req in rows.items():
        live = snapshot.get(req_id)
        if live is None:
            problems.append(f"{req_id}: not an AIUC-1 requirement ID")
        elif live["status"] != "active":
            problems.append(f"{req_id}: retired in the snapshot release")
        elif req.get("title") != live["title"]:
            problems.append(f"{req_id}: {req.get('title')!r} != published {live['title']!r}")
    return problems


def test_the_snapshot_is_the_release_it_claims_to_be():
    data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert data["release"] == "2026-10-15"
    assert data["counts"] == {"total": 55, "active": 50, "retired": 5}
    assert len(data["requirements"]) == 55


def test_every_mapping_title_is_the_published_title():
    rows = _mapping_rows(yaml.safe_load(MAPPING.read_text(encoding="utf-8")))
    assert len(rows) >= 10, "no requirement rows were read; the check would pass vacuously"
    assert title_mismatches(rows, _snapshot()) == []


def test_a_seeded_invented_title_is_caught():
    """Positive control: the check above must fail on the kind of row it exists to stop."""
    seeded = {"B003": {"title": "Protocol Downgrade Prevention", "status": "MAPPED"}}
    assert title_mismatches(seeded, _snapshot()) == [
        "B003: 'Protocol Downgrade Prevention' != published 'Manage public release of technical details'"]


def test_statuses_are_mapped_or_gap_never_covered():
    rows = _mapping_rows(yaml.safe_load(MAPPING.read_text(encoding="utf-8")))
    assert {r["status"] for r in rows.values()} <= {"MAPPED", "GAP"}
    for req_id, req in rows.items():
        assert bool(req.get("test_ids")) == (req["status"] == "MAPPED"), req_id


def test_every_named_test_exists_in_the_code():
    sys.path.insert(0, str(ROOT / "scripts"))
    import count_tests

    known = set().union(*count_tests.module_ids().values())
    rows = _mapping_rows(yaml.safe_load(MAPPING.read_text(encoding="utf-8")))
    missing = sorted({t for r in rows.values() for t in (r.get("test_ids") or []) if t not in known})
    assert missing == []


def test_every_crosswalk_row_is_titled_as_published():
    text = CROSSWALK.read_text(encoding="utf-8")
    rows = {m.group(1): {"title": m.group(2).strip()}
            for m in re.finditer(r"^\|\s*\*\*([A-F]\d{3})\*\*\s*\|\s*([^|]+?)\s*\|", text, re.M)}
    assert len(rows) >= 10
    assert title_mismatches(rows, _snapshot()) == []


@pytest.mark.parametrize("surface", CLAIM_SURFACES)
def test_no_surface_states_the_retired_coverage_claim(surface):
    """Retired coverage claims may appear only inside a correction note that quotes them as wrong."""
    assert retired_claims((ROOT / surface).read_text(encoding="utf-8").splitlines()) == []


def retired_claims(lines: list[str]) -> list[str]:
    return [ln for ln in lines if RETIRED_CLAIM.search(ln) and not ln.lstrip().startswith(">")]


def test_seeded_retired_claims_are_caught():
    """Positive control: each retired phrasing that shipped must trip the check; a quoted correction must not."""
    shipped = ["| **AIUC-1** | 23/24 requirements mapped, 19 production-ready |",
               "We currently map to 23 of 24 AIUC-1 requirements.",
               "Maps results to all 24 AIUC-1 requirements with gap analysis.",
               "**Current AIUC-1 coverage:** 15 of 24 requirements have production-ready tests.",
               "19 of 20 testable requirements (95%)"]
    assert retired_claims(shipped) == shipped
    assert retired_claims(["> Previously claimed: 23/24 requirements mapped."]) == []
    assert retired_claims(["23 of 50 active requirements listed, 19 with named tests"]) == []


def test_the_prep_tool_reads_the_same_mapping():
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "scripts"))
    import aiuc1_prep

    rows = _mapping_rows(yaml.safe_load(MAPPING.read_text(encoding="utf-8")))
    assert {k: v["title"] for k, v in aiuc1_prep.AIUC1_REQUIREMENTS.items()} == {k: v["title"] for k, v in rows.items()}


def _category_counts() -> dict[str, tuple[int, int, int, int]]:
    """(active in standard, listed, MAPPED, GAP) per category letter, from the snapshot and the mapping."""
    active: dict[str, int] = {}
    for r in _snapshot().values():
        if r["status"] == "active":
            active[r["id"][0]] = active.get(r["id"][0], 0) + 1
    rows = _mapping_rows(yaml.safe_load(MAPPING.read_text(encoding="utf-8")))
    out = {}
    for letter, n in active.items():
        mine = [r for k, r in rows.items() if k[0] == letter]
        out[letter] = (n, len(mine), sum(r["status"] == "MAPPED" for r in mine), sum(r["status"] == "GAP" for r in mine))
    return out


def test_the_outline_category_table_matches_the_mapping():
    """The submission outline's coverage table must be derivable from the snapshot and the mapping."""
    text = OUTLINE.read_text(encoding="utf-8")
    table = {m.group(1): tuple(int(x) for x in m.groups()[1:])
             for m in re.finditer(r"^\|\s*\*\*([A-F])\. [^|]+\*\*\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", text, re.M)}
    assert table == _category_counts()
    totals = tuple(sum(v[i] for v in table.values()) for i in range(4))
    assert re.search(r"\*\*Total\*\*\s*\|\s*\*\*%d\*\*\s*\|\s*\*\*%d\*\*\s*\|\s*\*\*%d\*\*\s*\|\s*\*\*%d\*\*" % totals, text)


RMF_SUB = re.compile(r"\b(GOVERN|MAP|MEASURE|MANAGE) (\d+(?:\.\d+)?)")
RMF_SURFACES = ["docs/AIUC1-SUBMISSION-OUTLINE.md", "docs/AIUC1-CROSSWALK.md"]


def _rmf_tags_in_code() -> set[str]:
    tags: set[str] = set()
    for f in (ROOT / "protocol_tests").glob("*.py"):
        for m in re.finditer(r"NIST AI RMF:([^\n\"]*)", f.read_text(encoding="utf-8")):
            tags |= {" ".join(t) for t in RMF_SUB.findall(m.group(1))}
    return tags


def rmf_claim_problems(lines: list[str], tagged: set[str]) -> list[str]:
    """A NIST AI RMF claim may name only subcategories the tests are tagged with, and never 'full'/'covered'."""
    problems = []
    for ln in lines:
        if "NIST AI RMF" not in ln:
            continue
        if re.search(r"full alignment|functions covered|\bfull\b", ln, re.I):
            problems.append(f"blanket claim: {ln.strip()}")
        named = {" ".join(t) for t in RMF_SUB.findall(ln)}
        if named and named != tagged:
            problems.append(f"names {sorted(named)} but tests tag {sorted(tagged)}: {ln.strip()}")
    return problems


@pytest.mark.parametrize("surface", RMF_SURFACES)
def test_nist_ai_rmf_claims_match_the_test_tags(surface):
    tagged = _rmf_tags_in_code()
    assert tagged, "no NIST AI RMF tags were read; the check would pass vacuously"
    assert rmf_claim_problems((ROOT / surface).read_text(encoding="utf-8").splitlines(), tagged) == []


def test_seeded_nist_overclaims_are_caught():
    """Positive control: both shipped overclaims trip the check."""
    tagged = {"GOVERN 1.1", "GOVERN 6.1", "MANAGE 2.2"}
    shipped = ["| **NIST AI RMF / IR 8596** | Full alignment on evaluation methodology |",
               "- **NIST AI RMF** - GOVERN, MAP, MEASURE, MANAGE functions covered",
               "- **NIST AI RMF** - tests tagged to GOVERN 1.1, MAP 1.1 and MANAGE 2.2"]
    assert len(rmf_claim_problems(shipped, tagged)) == 3
    assert rmf_claim_problems(["- **NIST AI RMF** - tests tagged to GOVERN 1.1, GOVERN 6.1 and MANAGE 2.2"], tagged) == []


def test_the_outline_gap_list_is_the_mapping_gap_list():
    """Section 8 must list exactly the GAP rows, titled as published (the old plan listed retired IDs)."""
    text = OUTLINE.read_text(encoding="utf-8")
    section = text[text.index("## 8. Gap Closure Plan"):text.index("## 9.")]
    listed = {m.group(1): {"title": m.group(2).strip()}
              for m in re.finditer(r"^\|\s*([A-F]\d{3})\s*\|\s*([^|]+?)\s*\|", section, re.M)}
    rows = _mapping_rows(yaml.safe_load(MAPPING.read_text(encoding="utf-8")))
    assert set(listed) == {k for k, r in rows.items() if r["status"] == "GAP"}
    assert title_mismatches(listed, _snapshot()) == []

