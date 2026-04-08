#!/usr/bin/env python3
"""Count unique test IDs across all harness modules.

Greps all test_id= values from protocol_tests/*.py and outputs:
  - Per-module counts
  - Total unique test IDs
  - Duplicate detection

This is the single source of truth for test count reconciliation.
"""

import os
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
HARNESS_DIR = REPO_ROOT / "protocol_tests"

# Primary: test_id= assignments
TEST_ID_RE = re.compile(r'test_id\s*=\s*["\']([^"\']+)["\']')

# Secondary: test IDs passed as function arguments (e.g., AIUC F002a-c via
# _test_cbrn_category("AIUC-F002a", ...)).  We look for string literals
# matching the canonical ID pattern that appear as first positional args.
ARG_ID_RE = re.compile(
    r'(?:self\._test_\w+|_test_\w+)\(\s*["\']'
    r'([A-Z]+-[A-Z0-9]+[a-z]?)'  # e.g. AIUC-F002a
    r'["\']'
)

# Synthetic / error-only IDs that should not count as real tests
EXCLUDE_IDS = {"CVE-ERR"}

# Map filenames to README module names
MODULE_NAMES = {
    "mcp_harness.py": "MCP Protocol",
    "a2a_harness.py": "A2A Protocol",
    "l402_harness.py": "L402 Payment",
    "x402_harness.py": "x402 Payment",
    "framework_adapters.py": "Framework Adapters",
    "enterprise_adapters.py": "Enterprise Platforms (core)",
    "extended_enterprise_adapters.py": "Enterprise Platforms (extended)",
    "gtg1002_simulation.py": "GTG-1002 APT Simulation",
    "advanced_attacks.py": "Advanced Attacks",
    "over_refusal_harness.py": "Over-Refusal",
    "provenance_harness.py": "Provenance & Attestation",
    "jailbreak_harness.py": "Jailbreak",
    "return_channel_harness.py": "Return Channel",
    "identity_harness.py": "Identity & Authorization",
    "capability_profile_harness.py": "Capability Profile",
    "harmful_output_harness.py": "Harmful Output",
    "cbrn_harness.py": "CBRN Prevention",
    "incident_response_harness.py": "Incident Response",
    "cve_2026_25253_harness.py": "CVE-2026-25253 Reproduction",
    "aiuc1_compliance_harness.py": "AIUC-1 Compliance",
    "cloud_agent_harness.py": "Cloud Agent Platforms",
    "crewai_cve_harness.py": "CrewAI CVE Reproduction",
    "multi_agent_harness.py": "Multi-Agent Interaction",
}


def main():
    all_ids: set[str] = set()
    module_ids: dict[str, set[str]] = defaultdict(set)
    duplicates: dict[str, list[str]] = defaultdict(list)

    for pyfile in sorted(HARNESS_DIR.glob("*.py")):
        if pyfile.name.startswith("__"):
            continue
        text = pyfile.read_text()
        ids = set(TEST_ID_RE.findall(text))
        ids |= set(ARG_ID_RE.findall(text))
        ids -= EXCLUDE_IDS  # drop synthetic error IDs
        if not ids:
            continue

        fname = pyfile.name
        module_ids[fname] = ids

        for tid in ids:
            if tid in all_ids:
                duplicates[tid].append(fname)
            all_ids.add(tid)

    # Output
    print("=" * 60)
    print("Test Count Report")
    print("=" * 60)
    print()

    total = 0
    for fname in sorted(module_ids.keys()):
        ids = module_ids[fname]
        label = MODULE_NAMES.get(fname, fname)
        count = len(ids)
        total += count
        print(f"  {label:45s} {count:>4d}")

    print(f"\n  {'TOTAL UNIQUE TEST IDS':45s} {len(all_ids):>4d}")
    print(f"  {'SUM OF PER-MODULE COUNTS':45s} {total:>4d}")

    if duplicates:
        print(f"\n  WARNING: {len(duplicates)} duplicate test ID(s):")
        for tid, files in sorted(duplicates.items()):
            print(f"    {tid} appears in: {', '.join(files)}")

    print()
    return len(all_ids)


if __name__ == "__main__":
    count = main()
    print(f"Definitive count: {count}")
    sys.exit(0)
