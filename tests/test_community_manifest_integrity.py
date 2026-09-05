"""The community trust manifest must actually verify.

`community_modules/MANIFEST.yaml` records a sha256, a trust tier and a reviewer
per pattern, and `community_runner.py` refuses in strict mode to load a pattern
whose hash does not match. That is a real control, and nothing ran it.

`examples/mcp_description_exfil.yaml` was legitimately edited on 2026-07-10 by
#235 (a CVE misattribution fix). The manifest had not been touched since
2026-03-30, when integrity verification was added. So from July onward CP-0002
failed its integrity check and silently did not load: `--list` reported one
community pattern where the repository ships two, and the runner's own message
called it possible tampering. Nobody saw it, because no test invoked the runner.

A manifest that is never verified is a claim about integrity, not evidence of it.
These tests make the manifest falsifiable in CI: a content change that does not
update the hash now fails here rather than silently unloading a pattern.
"""
import hashlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
COMMUNITY = REPO / "community_modules"

yaml = pytest.importorskip("yaml")


def _manifest():
    return yaml.safe_load((COMMUNITY / "MANIFEST.yaml").read_text())


def test_every_manifest_entry_points_at_a_file_that_exists():
    missing = [e["file"] for e in _manifest()["patterns"]
               if not (COMMUNITY / e["file"]).is_file()]
    assert missing == [], f"manifest references files that do not exist: {missing}"


def test_every_registered_hash_matches_the_file_on_disk():
    """The regression. A content edit that leaves the hash stale fails here."""
    bad = []
    for entry in _manifest()["patterns"]:
        path = COMMUNITY / entry["file"]
        if not path.is_file():
            continue
        recorded = entry.get("sha256")
        if not recorded or recorded == "null":
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != recorded:
            bad.append(f"{entry['file']}: manifest {recorded[:16]}… vs file {actual[:16]}…")
    assert bad == [], (
        "stale manifest hashes — the pattern will fail integrity and silently not load:\n  "
        + "\n  ".join(bad))


def test_strict_mode_loads_every_registered_pattern():
    """The positive control: verifying nothing would also produce no mismatches."""
    from protocol_tests.community_runner import load_manifest  # noqa: E402
    registered = {e["file"] for e in _manifest()["patterns"]}
    assert registered, "manifest is empty; this test would pass vacuously"
    loaded = load_manifest(str(COMMUNITY))
    assert len(loaded) == len(registered), (
        f"runner loaded {len(loaded)} manifest entries for {len(registered)} registered patterns")
