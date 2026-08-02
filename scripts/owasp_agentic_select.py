#!/usr/bin/env python3
"""Resolve OWASP Agentic v1.1 threats, scenarios and controls to runnable tests.

Spec v2.0 section 15.2 asks for execution selectors. Full CLI integration is
larger than this pull request, so this is the deterministic script form: it
resolves a T-code, scenario id or control id against the canonical mapping and
prints the tests and the commands that run them.

    python scripts/owasp_agentic_select.py --threat T16
    python scripts/owasp_agentic_select.py --threat T1,T6,T12
    python scripts/owasp_agentic_select.py --scenario T16-S2
    python scripts/owasp_agentic_select.py --control P4-PRO-001
    python scripts/owasp_agentic_select.py --playbook P5
    python scripts/owasp_agentic_select.py --threat T16 --format json
    python scripts/owasp_agentic_select.py --list

Exit code 1 if a selector resolves to nothing, so it is usable in scripts.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    raise SystemExit(2)

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAPPING = ROOT / "docs/coverage/owasp-agentic-v1.1.yaml"


def _load() -> dict:
    return yaml.safe_load(MAPPING.read_text(encoding="utf-8"))


def _test_index() -> dict[str, str]:
    idx: dict[str, str] = {}
    srcs = list((ROOT / "protocol_tests").glob("*.py")) + [ROOT / "red_team_automation.py"]
    for p in srcs:
        if not p.exists():
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r'test_id\s*=\s*["\']([A-Z0-9]+-\d{3})["\']', txt):
            idx.setdefault(m.group(1), str(p.relative_to(ROOT)))
    return idx


def resolve(d: dict, *, threats=None, scenario=None, control=None, playbook=None) -> dict:
    """Return {selector, tests:[{test_id, module, execution, why}], notes:[]}."""
    out: dict = {"selector": {}, "tests": [], "notes": []}
    seen: set[str] = set()

    def add(tid: str, module: str, execution: str, why: str) -> None:
        if tid in seen:
            return
        seen.add(tid)
        out["tests"].append({"test_id": tid, "module": module,
                             "execution": execution, "why": why})

    if threats:
        out["selector"]["threats"] = threats
        for t in d["threats"]:
            if t["id"] not in threats:
                continue
            if not t["evidence"]:
                out["notes"].append(
                    f"{t['id']} is {t['coverage']} - no evidence records to run.")
            for e in t["evidence"]:
                add(e["test_id"], e["module"], e["execution"],
                    f"{t['id']} evidence")

    if scenario:
        out["selector"]["scenario"] = scenario
        found = None
        for t in d["threats"]:
            for s in t["source_scenarios"]:
                if s["scenario_id"] == scenario:
                    found = (t, s)
        if not found:
            out["notes"].append(f"{scenario} is not a known scenario id.")
        else:
            t, s = found
            out["notes"].append(f"{scenario} ({s['title']}) is {s['status']} under {t['id']}.")
            if s["status"] in {"not_evidenced", "not_assessed"}:
                out["notes"].append(
                    "No test is mapped to this scenario. The threat's tests below are its "
                    "closest context, not evidence for this scenario.")
            for tid in s.get("covered_by") or []:
                ev = next((e for e in t["evidence"] if e["test_id"] == tid), None)
                if ev:
                    add(tid, ev["module"], ev["execution"], f"{scenario} coverage")
            if not (s.get("covered_by") or []):
                for e in t["evidence"]:
                    add(e["test_id"], e["module"], e["execution"], f"{t['id']} context")

    ctrl_ids: list[str] = []
    if control:
        ctrl_ids = [control]
        out["selector"]["control"] = control
    if playbook:
        out["selector"]["playbook"] = playbook
        pb = next((p for p in d["playbooks"] if p["id"] == playbook), None)
        if not pb:
            out["notes"].append(f"{playbook} is not a known playbook id.")
        else:
            ctrl_ids += [c["control_id"] for c in pb["controls"]]

    if ctrl_ids:
        idx = _test_index()
        for cid in ctrl_ids:
            c = next((c for p in d["playbooks"] for c in p["controls"]
                      if c["control_id"] == cid), None)
            if not c:
                out["notes"].append(f"{cid} is not a known control id.")
                continue
            v = c["validation"]
            out["notes"].append(f"{cid} is {v['status']}: {c['summary']}")
            if v["status"] == "guidance_only":
                out["notes"].append(
                    f"  {cid} has no test at this commit - it is cited, not validated.")
            for tid in v["evidence"]:
                add(tid, idx.get(tid, "?"), f"# see the report's rerun column for {tid}",
                    f"{cid} validation")

    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--threat", help="T-code or comma list, e.g. T1,T6,T16")
    ap.add_argument("--scenario", help="scenario id, e.g. T16-S2")
    ap.add_argument("--control", help="control id, e.g. P4-PRO-001")
    ap.add_argument("--playbook", help="playbook id, e.g. P5")
    ap.add_argument("--list", action="store_true", help="list every selectable id")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    args = ap.parse_args()

    d = _load()

    if args.list:
        print("Threats:")
        for t in d["threats"]:
            print(f"  {t['id']:<5} {t['title']:<42} {t['coverage']}")
        print("\nScenarios:")
        for t in d["threats"]:
            for s in t["source_scenarios"]:
                print(f"  {s['scenario_id']:<9} {s['title'][:52]:<54} {s['status']}")
        print("\nControls:")
        for p in d["playbooks"]:
            for c in p["controls"]:
                print(f"  {c['control_id']:<12} {c['phase']:<10} {c['validation']['status']}")
        return 0

    if not any((args.threat, args.scenario, args.control, args.playbook)):
        ap.print_help()
        return 2

    threats = [x.strip().upper() for x in args.threat.split(",")] if args.threat else None
    res = resolve(d, threats=threats, scenario=args.scenario,
                  control=args.control, playbook=args.playbook)

    if args.format == "json":
        print(json.dumps(res, indent=2))
        return 0 if res["tests"] else 1

    for n in res["notes"]:
        print(f"note: {n}")
    if not res["tests"]:
        print("\nNo tests resolved for that selector.")
        return 1
    print(f"\n{len(res['tests'])} test(s):\n")
    for t in res["tests"]:
        print(f"  {t['test_id']:<10} {t['module']}")
        print(f"             {t['execution']}")
        print(f"             ({t['why']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
