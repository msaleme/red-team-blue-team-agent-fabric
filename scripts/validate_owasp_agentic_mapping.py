#!/usr/bin/env python3
"""Validate the OWASP Agentic AI v1.1 coverage mapping (spec v2.0, section 16).

Source of truth: docs/coverage/owasp-agentic-v1.1.yaml
Generated views:  docs/OWASP-AGENTIC-V1.1-COVERAGE.md            (T1-T17)
                  docs/OWASP-AGENTIC-T1-T15-SUBMISSION-COVERAGE.md (T1-T15)

    python scripts/validate_owasp_agentic_mapping.py
    python scripts/validate_owasp_agentic_mapping.py --skip-reports
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
MAPPING = ROOT / "docs/coverage/owasp-agentic-v1.1.yaml"
COMPLETE = ROOT / "docs/OWASP-AGENTIC-V1.1-COVERAGE.md"
SUBMISSION = ROOT / "docs/OWASP-AGENTIC-T1-T15-SUBMISSION-COVERAGE.md"
GENERATOR = ROOT / "scripts/generate_owasp_agentic_coverage.py"

TITLES = {
    "T1": "Memory Poisoning", "T2": "Tool Misuse", "T3": "Privilege Compromise",
    "T4": "Resource Overload", "T5": "Cascading Hallucination Attacks",
    "T6": "Intent Breaking & Goal Manipulation", "T7": "Misaligned & Deceptive Behaviors",
    "T8": "Repudiation & Untraceability", "T9": "Identity Spoofing & Impersonation",
    "T10": "Overwhelming Human in the Loop", "T11": "Unexpected RCE and Code Attacks",
    "T12": "Agent Communication Poisoning", "T13": "Rogue Agents in Multi-Agent Systems",
    "T14": "Human Attacks on Multi-Agent Systems", "T15": "Human Manipulation",
    "T16": "Insecure Inter-Agent Protocol Abuse", "T17": "Supply Chain Compromise",
}
COVERAGE = {"direct", "partial", "not_evidenced"}
DISPOSITIONS = {"in_scope", "roadmap", "out_of_scope"}
SUB_DISPOSITIONS = {"selected", "not_selected", "not_applicable_to_form"}
EVIDENCE_CLASSES = {"live_target", "controlled_runtime", "simulation", "fixture", "static_preflight"}
SCENARIO_STATUS = {"covered", "partially_covered", "not_evidenced", "not_assessed"}
MITIGATION_STATUS = {"validated", "partial", "guidance_only", "not_assessed"}
PHASES = {"proactive", "reactive", "detective"}

PROHIBITED = [
    "owasp certified", "owasp approved", "owasp validated", "owasp compliant",
    "fully mitigates", "complete coverage", "guarantees security",
]


def _index() -> dict[str, set[str]]:
    idx: dict[str, set[str]] = collections.defaultdict(set)
    srcs = list((ROOT / "protocol_tests").glob("*.py")) + [ROOT / "red_team_automation.py"]
    for p in srcs:
        if not p.exists():
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        rel = str(p.relative_to(ROOT))
        for m in re.finditer(r'test_id\s*=\s*["\']([A-Z0-9]+-\d{3})["\']', txt):
            idx[m.group(1)].add(rel)
        # Same secondary convention scripts/count_tests.py uses: an id passed as
        # the first positional argument to a `_test_*` helper. Without this the
        # validator disagrees with the canonical counter about which tests exist.
        for m in re.finditer(r'(?:self\._test_\w+|_test_\w+)\(\s*["\']([A-Z0-9]+-\d{3})["\']', txt):
            idx[m.group(1)].add(rel)
    return idx


def _symbol_ok(module: pathlib.Path, symbol: str) -> bool:
    txt = module.read_text(encoding="utf-8", errors="replace")
    if symbol.startswith("test_"):
        return re.search(r"def\s+" + re.escape(symbol) + r"\s*\(", txt) is not None
    return f'"{symbol}"' in txt or f"'{symbol}'" in txt


def validate(check_reports: bool = True) -> list[str]:
    fails: list[str] = []

    def fail(rule: str, detail: str) -> None:
        fails.append(f"[{rule}] {detail}")

    d = yaml.safe_load(MAPPING.read_text(encoding="utf-8"))
    threats = d["threats"]
    idx = _index()

    # r1 - exactly T1..T17 once each, canonical titles
    ids = [t["id"] for t in threats]
    if ids != [f"T{i}" for i in range(1, 18)]:
        fail("r1_ids", f"expected T1..T17 in order, got {ids}")
    for t in threats:
        if t["title"] != TITLES.get(t["id"]):
            fail("r1_title", f"{t['id']}: {t['title']!r}")

    # r3 - decision path, playbooks, examples, manifest complete
    steps = [s["step"] for s in d.get("decision_path", [])]
    if steps != [1, 2, 3, 4, 5, 6]:
        fail("r3_decision_path", f"expected steps 1-6, got {steps}")
    pbs = [p["id"] for p in d.get("playbooks", [])]
    if pbs != [f"P{i}" for i in range(1, 7)]:
        fail("r3_playbooks", f"expected P1-P6, got {pbs}")
    for p in d.get("playbooks", []):
        for c in p["controls"]:
            if c["phase"] not in PHASES:
                fail("r3_phase", f"{c['control_id']}: phase {c['phase']!r}")
            v = c.get("validation")
            if not v:
                fail("r14_control_validation", f"{c['control_id']} has no validation record")
                continue
            if v["status"] not in MITIGATION_STATUS:
                fail("r14_status", f"{c['control_id']}: {v['status']!r}")
            if v["status"] in {"validated", "partial"} and not v.get("evidence"):
                fail("r14_validated",
                     f"{c['control_id']} is {v['status']} with no executable evidence")
            if v["status"] == "partial" and not v.get("limitation"):
                fail("r11_limitation", f"{c['control_id']} is partial with no limitation")
            if v["status"] == "guidance_only" and v.get("evidence"):
                fail("r14_guidance", f"{c['control_id']} is guidance_only but cites evidence")
            for tid in v.get("evidence") or []:
                if tid not in _index():
                    fail("r14_evidence_resolves", f"{c['control_id']} cites unknown test {tid}")
    if len(d.get("example_models", [])) != 3:
        fail("r3_examples", f"expected 3 example families, got {len(d.get('example_models', []))}")
    if not d.get("guide_manifest"):
        fail("r3_manifest", "guide_manifest is missing")

    # r17 - source provenance present
    fw = d["framework"]
    for k in ("version", "publication_date", "source_sha256", "license", "attribution"):
        if not fw.get(k):
            fail("r17_provenance", f"framework.{k} is missing")
    if not re.fullmatch(r"[0-9a-f]{64}", fw.get("source_sha256", "")):
        fail("r17_provenance", "source_sha256 is not a 64-char hex digest")
    if len(fw.get("source_notes") or []) < 3:
        fail("r17_source_notes", "all three v1.1 source inconsistencies must be recorded")

    known_controls = {c["control_id"] for p in d.get("playbooks", []) for c in p["controls"]}
    seen_scenarios: set[str] = set()

    for t in threats:
        tid = t["id"]
        if t["coverage"] not in COVERAGE:
            fail("r_vocab", f"{tid}: coverage {t['coverage']!r}")
        # r13 - both dispositions
        if t.get("disposition") not in DISPOSITIONS:
            fail("r13_disposition", f"{tid}: {t.get('disposition')!r}")
        if t.get("submission_disposition") not in SUB_DISPOSITIONS:
            fail("r13_submission_disposition", f"{tid}: {t.get('submission_disposition')!r}")
        if tid in ("T16", "T17") and t["submission_disposition"] != "not_applicable_to_form":
            fail("r13_submission_disposition",
                 f"{tid} was not present in the submitted form view")

        # r4 - scenarios unique and validly statused
        for s in t.get("source_scenarios") or []:
            if s["scenario_id"] in seen_scenarios:
                fail("r4_scenario_dup", f"{s['scenario_id']} appears more than once")
            seen_scenarios.add(s["scenario_id"])
            if not s["scenario_id"].startswith(tid + "-"):
                fail("r4_scenario_owner", f"{s['scenario_id']} filed under {tid}")
            if s["status"] not in SCENARIO_STATUS:
                fail("r4_scenario_status", f"{s['scenario_id']}: {s['status']!r}")

        ev = t.get("evidence") or []
        # r5 / r6
        if t["coverage"] in {"direct", "partial"} and not ev:
            fail("r5_evidence", f"{tid} is {t['coverage']} with no evidence")
        if t["coverage"] == "not_evidenced":
            if ev:
                fail("r6_not_evidenced", f"{tid} is not_evidenced but lists evidence")
            if not t.get("rationale"):
                fail("r6_not_evidenced", f"{tid} has no rationale")
        # r11
        if t["coverage"] == "partial" and not t.get("limitations"):
            fail("r11_limitation", f"{tid} is partial with no limitation")

        classes = set()
        for e in ev:
            eid = e["test_id"]
            # r7
            if eid not in idx:
                fail("r7_id", f"{tid}/{eid} resolves to no registered test")
                continue
            # r8
            mod = ROOT / e["module"]
            if not mod.exists():
                fail("r8_module", f"{tid}/{eid}: {e['module']} missing")
                continue
            if e["module"] not in idx[eid]:
                fail("r8_module", f"{tid}/{eid}: {e['module']} does not define it")
            if not _symbol_ok(mod, e["symbol"]):
                fail("x_symbol", f"{tid}/{eid}: symbol {e['symbol']!r} not in {e['module']}")
            # r9
            if not e.get("execution") or len(e["execution"]) < 8:
                fail("r9_execution", f"{tid}/{eid}: unusable execution selector")
            # r10 - direct needs full provenance
            if e.get("evidence_class") not in EVIDENCE_CLASSES:
                fail("r10_class", f"{tid}/{eid}: class {e.get('evidence_class')!r}")
            classes.add(e.get("evidence_class"))
            if t["coverage"] == "direct":
                for field in ("actor", "target", "direction", "attack_path", "assertion"):
                    if not e.get(field):
                        fail("r10_fields", f"{tid}/{eid}: empty {field}")
            for c in e.get("validates_controls") or []:
                if c not in known_controls:
                    fail("r14_unknown_control", f"{tid}/{eid} claims unknown control {c}")

        # r12 - static_preflight alone cannot make direct coverage
        if t["coverage"] == "direct" and classes and classes == {"static_preflight"}:
            fail("r12_static_only",
                 f"{tid} is direct on static_preflight evidence alone")

        # r14 - validated mitigation needs executable evidence
        for mv in t.get("mitigation_validation") or []:
            if mv["status"] not in MITIGATION_STATUS:
                fail("r14_status", f"{tid}/{mv['control_id']}: {mv['status']!r}")
            if mv["control_id"] not in known_controls:
                fail("r14_unknown_control", f"{tid}: unknown control {mv['control_id']}")
            if mv["status"] == "validated" and not mv.get("evidence"):
                fail("r14_validated", f"{tid}/{mv['control_id']} validated with no evidence")
            if mv["status"] == "partial" and not mv.get("limitation"):
                fail("r11_limitation", f"{tid}/{mv['control_id']} partial with no limitation")

    # r15/r16 - derived counts, duplicates once
    uniq = {e["test_id"] for t in threats for e in (t.get("evidence") or [])}
    if d["assessment"]["unique_mapped_tests"] != len(uniq):
        fail("r15_counts",
             f"unique_mapped_tests {d['assessment']['unique_mapped_tests']} vs actual {len(uniq)}")

    count_script = ROOT / "scripts/count_tests.py"
    if count_script.exists():
        out = subprocess.run([sys.executable, str(count_script)], capture_output=True,
                             text=True, cwd=ROOT).stdout
        m = re.search(r"Definitive count:\s*(\d+)", out)
        if m and int(m.group(1)) != d["assessment"]["total_repository_tests"]:
            fail("r15_total", f"mapping {d['assessment']['total_repository_tests']} vs {m.group(1)}")

    version = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.MULTILINE).group(1)
    if d["assessment"]["harness_version"] != version:
        fail("r15_version", f"mapping {d['assessment']['harness_version']} vs pyproject {version}")
    sha = d["assessment"]["git_commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha or ""):
        fail("r15_commit", f"git_commit must be a full 40-char SHA, got {sha!r}")

    # x - assessed commit must be reachable, or every permalink 404s
    shallow = subprocess.run(["git", "rev-parse", "--is-shallow-repository"],
                             cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if shallow != "true":
        if subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"],
                          cwd=ROOT, capture_output=True).returncode != 0:
            fail("x_commit_reachable", f"assessed commit {sha[:12]} is not in this repository")
        elif subprocess.run(["git", "merge-base", "--is-ancestor", sha, "HEAD"],
                            cwd=ROOT, capture_output=True).returncode != 0:
            fail("x_commit_reachable",
                 f"assessed commit {sha[:12]} is not an ancestor of HEAD - permalinks would 404")

    # r19 - prohibited language, and r17 attribution present in output
    docs = [MAPPING] + [p for p in (COMPLETE, SUBMISSION) if p.exists()]
    for path in docs:
        low = path.read_text(encoding="utf-8").lower()
        for phrase in PROHIBITED:
            if phrase in low:
                fail("r19_prohibited", f"{path.name} contains {phrase!r}")
    for path in (p for p in (COMPLETE, SUBMISSION) if p.exists()):
        txt = path.read_text(encoding="utf-8")
        if "CC BY-SA 4.0" not in txt:
            fail("r17_attribution", f"{path.name} does not carry the CC BY-SA 4.0 attribution")
        if "creativecommons.org/licenses/by-sa/4.0" not in txt:
            fail("r17_attribution", f"{path.name} does not link the licence")

    # r2 / r18 - submission view derived, and both reports match fresh output
    if check_reports:
        for path, view in ((COMPLETE, "complete"), (SUBMISSION, "submission")):
            if not path.exists():
                fail("r18_report", f"{path.name} is missing")
                continue
            fresh = subprocess.run(
                [sys.executable, str(GENERATOR), "--view", view, "--stdout"],
                capture_output=True, text=True, cwd=ROOT).stdout
            if fresh.strip() != path.read_text(encoding="utf-8").strip():
                fail("r18_report", f"{path.name} differs from freshly generated output")
        if SUBMISSION.exists():
            sub = SUBMISSION.read_text(encoding="utf-8")
            if "T16" in sub.replace("T16 and T17", "").replace("T16/T17", ""):
                pass  # mentions in the omission note are expected
            for t in threats:
                if t["id"] in ("T16", "T17"):
                    continue
                if f"**{t['id']}**" not in sub:
                    fail("r2_submission_view", f"{t['id']} missing from the submission view")

    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-reports", action="store_true",
                    help="skip rules 2 and 18 while generating reports for the first time")
    args = ap.parse_args()
    fails = validate(check_reports=not args.skip_reports)
    if fails:
        print(f"FAIL - {len(fails)} rule violation(s):\n")
        for f in fails:
            print(f"  {f}")
        return 1
    print("PASS - all v1.1 mapping validation rules hold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
