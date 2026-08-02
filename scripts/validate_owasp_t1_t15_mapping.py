#!/usr/bin/env python3
"""Validate the OWASP Agentic T1-T15 coverage mapping.

Enforces every rule in section 10 of the coverage-report specification, plus
two rules the specification does not name but this audit needed:

  symbol_resolves               section 10 rule 5 resolves the test *id* only.
                                Two evidence rows had ids and modules that were
                                correct while their `symbol` named a function
                                that does not exist. An id-only check cannot see
                                that.

  no_permissive_oracle_as_direct
                                red_team_automation.py passes on
                                `status in expected_status AND ttd < 3s AND no
                                leak`. Tests listing 200 alongside 4xx pass
                                whether the attack was blocked or succeeded, so
                                they cannot back a `direct` verdict.

Exit code 0 = all rules pass. Non-zero = at least one rule failed.

    python scripts/validate_owasp_t1_t15_mapping.py
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import re
import subprocess
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    raise SystemExit(2)

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAPPING = ROOT / "docs/coverage/owasp-agentic-t1-t15.yaml"
REPORT = ROOT / "docs/OWASP-AGENTIC-T1-T15-COVERAGE.md"

CANONICAL_TITLES = {
    "T1": "Memory Poisoning",
    "T2": "Tool Misuse",
    "T3": "Privilege Compromise",
    "T4": "Resource Overload",
    "T5": "Cascading Hallucination Attacks",
    "T6": "Intent Breaking & Goal Manipulation",
    "T7": "Misaligned & Deceptive Behaviors",
    "T8": "Repudiation & Untraceability",
    "T9": "Identity Spoofing & Impersonation",
    "T10": "Overwhelming Human in the Loop",
    "T11": "Unexpected RCE and Code Attacks",
    "T12": "Agent Communication Poisoning",
    "T13": "Rogue Agents in Multi-Agent Systems",
    "T14": "Human Attacks on Multi-Agent Systems",
    "T15": "Human Manipulation",
}

COVERAGE_VALUES = {"direct", "partial", "not_evidenced"}
DISPOSITIONS = {"in_scope", "roadmap", "out_of_scope"}
EVIDENCE_TYPES = {"live_target", "simulation", "fixture", "static_preflight"}

PROHIBITED = [
    "owasp certified",
    "owasp approved",
    "owasp validated",
    "fully mitigates",
    "complete coverage",
    "guarantees security",
]


def _test_index() -> dict[str, set[str]]:
    """Map test id -> set of repo-relative modules that define it."""
    index: dict[str, set[str]] = collections.defaultdict(set)
    sources = list((ROOT / "protocol_tests").glob("*.py"))
    sources.append(ROOT / "red_team_automation.py")
    for path in sources:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path.relative_to(ROOT))
        for match in re.finditer(r'test_id\s*=\s*["\']([A-Z0-9]+-\d{3})["\']', text):
            index[match.group(1)].add(rel)
    return index


def _symbol_present(module: pathlib.Path, symbol: str) -> bool:
    text = module.read_text(encoding="utf-8", errors="replace")
    if symbol.startswith("test_"):
        return re.search(r"def\s+" + re.escape(symbol) + r"\s*\(", text) is not None
    return f'"{symbol}"' in text or f"'{symbol}'" in text


def validate(check_report: bool = True) -> list[str]:
    failures: list[str] = []

    def fail(rule: str, detail: str) -> None:
        failures.append(f"[{rule}] {detail}")

    data = yaml.safe_load(MAPPING.read_text(encoding="utf-8"))
    threats = data["threats"]
    index = _test_index()

    # 1. exactly T1..T15, once each, in numeric order
    ids = [t["id"] for t in threats]
    expected = [f"T{i}" for i in range(1, 16)]
    if ids != expected:
        fail("r1_ids", f"expected {expected}, got {ids}")

    for t in threats:
        tid = t["id"]

        # 2. canonical titles
        if t["title"] != CANONICAL_TITLES.get(tid):
            fail("r2_title", f"{tid}: {t['title']!r} != {CANONICAL_TITLES.get(tid)!r}")

        # 10. disposition present and valid
        if t.get("disposition") not in DISPOSITIONS:
            fail("r10_disposition", f"{tid}: {t.get('disposition')!r}")

        if t["coverage"] not in COVERAGE_VALUES:
            fail("r_vocab", f"{tid}: coverage {t['coverage']!r}")

        evidence = t.get("evidence") or []

        # 3. direct/partial need evidence
        if t["coverage"] in {"direct", "partial"} and not evidence:
            fail("r3_evidence", f"{tid} is {t['coverage']} with no evidence")

        # 4. not_evidenced has no evidence and does have a rationale
        if t["coverage"] == "not_evidenced":
            if evidence:
                fail("r4_not_evidenced", f"{tid} is not_evidenced but lists evidence")
            if not t.get("rationale"):
                fail("r4_not_evidenced", f"{tid} is not_evidenced with no rationale")

        # 9. partial needs at least one explicit limitation
        if t["coverage"] == "partial" and not t.get("limitations"):
            fail("r9_partial_limits", f"{tid} is partial with no limitations")

        for e in evidence:
            eid = e["test_id"]

            # 5. id resolves to a registered test
            if eid not in index:
                fail("r5_id_resolves", f"{tid}/{eid} resolves to no registered test")
                continue

            # 6. module exists AND actually defines that test
            module = ROOT / e["module"]
            if not module.exists():
                fail("r6_module_exists", f"{tid}/{eid}: {e['module']} does not exist")
                continue
            if e["module"] not in index[eid]:
                fail(
                    "r6_module_defines",
                    f"{tid}/{eid}: {e['module']} does not define it "
                    f"(defined in {sorted(index[eid])})",
                )

            # EXTRA: symbol resolves in the declared module
            if not _symbol_present(module, e["symbol"]):
                fail(
                    "x_symbol_resolves",
                    f"{tid}/{eid}: symbol {e['symbol']!r} not found in {e['module']}",
                )

            # 7. execution command present and non-trivial
            if not e.get("execution") or len(e["execution"]) < 8:
                fail("r7_execution", f"{tid}/{eid}: no usable execution selector")

            # 8. direct evidence needs attack_path and assertion
            if t["coverage"] == "direct":
                if not e.get("attack_path"):
                    fail("r8_attack_path", f"{tid}/{eid}: empty attack_path")
                if not e.get("assertion"):
                    fail("r8_assertion", f"{tid}/{eid}: empty assertion")

            if e.get("evidence_type") not in EVIDENCE_TYPES:
                fail("r_evidence_type", f"{tid}/{eid}: {e.get('evidence_type')!r}")

    # EXTRA: permissive-oracle tests may not back a direct verdict
    permissive = set(data.get("oracle_notes", {}).get("status_permissive_tests", []))
    for t in threats:
        if t["coverage"] != "direct":
            continue
        for e in t.get("evidence") or []:
            if e["test_id"] in permissive:
                fail(
                    "x_permissive_oracle",
                    f"{t['id']}/{e['test_id']} backs a direct verdict but its oracle "
                    "cannot distinguish blocked from allowed",
                )

    # 11. counts are derived, never hand-entered
    unique = {e["test_id"] for t in threats for e in (t.get("evidence") or [])}
    if data["assessment"]["unique_mapped_tests"] != len(unique):
        fail(
            "r11_counts",
            f"unique_mapped_tests says {data['assessment']['unique_mapped_tests']}, "
            f"mapping has {len(unique)}",
        )

    count_script = ROOT / "scripts/count_tests.py"
    if count_script.exists():
        out = subprocess.run(
            [sys.executable, str(count_script)], capture_output=True, text=True, cwd=ROOT
        ).stdout
        m = re.search(r"Definitive count:\s*(\d+)", out)
        if m and int(m.group(1)) != data["assessment"]["total_repository_tests"]:
            fail(
                "r11_total_tests",
                f"mapping says {data['assessment']['total_repository_tests']}, "
                f"count_tests.py says {m.group(1)}",
            )

    # version + commit agreement
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    if data["assessment"]["harness_version"] != version:
        fail(
            "r_version",
            f"mapping says {data['assessment']['harness_version']}, pyproject says {version}",
        )
    sha = data["assessment"]["git_commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha or ""):
        fail("r_commit", f"git_commit must be a full 40-char SHA, got {sha!r}")

    # 12. prohibited language, in mapping and report
    for path in [MAPPING] + ([REPORT] if REPORT.exists() else []):
        low = path.read_text(encoding="utf-8").lower()
        for phrase in PROHIBITED:
            if phrase in low:
                fail("r12_prohibited", f"{path.name} contains {phrase!r}")

    # 13. committed report equals freshly generated output
    if check_report:
        if not REPORT.exists():
            fail("r13_report", "docs/OWASP-AGENTIC-T1-T15-COVERAGE.md is missing")
        else:
            gen = ROOT / "scripts/generate_owasp_t1_t15_report.py"
            fresh = subprocess.run(
                [sys.executable, str(gen), "--stdout"],
                capture_output=True,
                text=True,
                cwd=ROOT,
            ).stdout
            if fresh.strip() != REPORT.read_text(encoding="utf-8").strip():
                fail("r13_report", "committed report differs from freshly generated output")

    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--skip-report",
        action="store_true",
        help="skip rule 13 (used while generating the report for the first time)",
    )
    args = ap.parse_args()

    failures = validate(check_report=not args.skip_report)
    if failures:
        print(f"FAIL - {len(failures)} rule violation(s):\n")
        for f in failures:
            print(f"  {f}")
        return 1
    print("PASS - all mapping validation rules hold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
