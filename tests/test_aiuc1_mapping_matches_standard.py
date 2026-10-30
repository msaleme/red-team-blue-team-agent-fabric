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
CLAIM_SURFACES = ["README.md", "SKILL.md", "docs/TEST-INVENTORY.md", "docs/aiuc1-prep.md", "docs/AIUC1-CROSSWALK.md"]


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
    """'19 of 20' / '95%' may appear only inside a correction note that quotes it as wrong."""
    lines = (ROOT / surface).read_text(encoding="utf-8").splitlines()
    offending = [ln for ln in lines
                 if re.search(r"19 of\s*20|19/20|\b95%", ln) and not ln.lstrip().startswith(">")]
    assert offending == []


def test_the_prep_tool_reads_the_same_mapping():
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "scripts"))
    import aiuc1_prep

    rows = _mapping_rows(yaml.safe_load(MAPPING.read_text(encoding="utf-8")))
    assert {k: v["title"] for k, v in aiuc1_prep.AIUC1_REQUIREMENTS.items()} == {k: v["title"] for k, v in rows.items()}
