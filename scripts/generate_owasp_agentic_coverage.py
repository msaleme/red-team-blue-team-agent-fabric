#!/usr/bin/env python3
"""Render the OWASP Agentic AI v1.1 coverage reports from the canonical mapping.

One source, four outputs:

    docs/OWASP-AGENTIC-V1.1-COVERAGE.md               complete, T1-T17
    docs/OWASP-AGENTIC-T1-T15-SUBMISSION-COVERAGE.md  filtered to the form's T1-T15
    docs/coverage/owasp-agentic-v1.1.json             machine-readable
    docs/OWASP-ASI-TOP10-CROSSWALK.md                 OWASP's ASI Top 10 <-> T1-T17

Never edit the Markdown by hand; the validator fails if it drifts.

    python scripts/generate_owasp_agentic_coverage.py                 # write all
    python scripts/generate_owasp_agentic_coverage.py --view complete --stdout
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
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
JSON_OUT = ROOT / "docs/coverage/owasp-agentic-v1.1.json"
ASI_CROSSWALK = ROOT / "docs/OWASP-ASI-TOP10-CROSSWALK.md"

LABEL = {"direct": "Direct test coverage", "partial": "Partial test coverage",
         "not_evidenced": "Not evidenced"}
SLABEL = {"covered": "covered", "partially_covered": "partial",
          "not_evidenced": "not evidenced", "not_assessed": "not assessed"}
MLABEL = {"validated": "Validated control behavior",
          "partial": "Partially validated control behavior",
          "guidance_only": "Guidance only", "not_assessed": "Not assessed"}


def _anchor(t: dict) -> str:
    s = f"{t['id']} {t['title']}".lower()
    return "#" + "".join(c if c.isalnum() or c == " " else "" for c in s).replace(" ", "-")


def _summary(text: str, limit: int = 165) -> str:
    text = " ".join(text.split())
    parts = [s.strip() for s in text.split(". ") if s.strip()]
    out = ""
    for s in parts:
        cand = (out + " " if out else "") + s.rstrip(".") + "."
        if out and len(cand) > limit:
            break
        out = cand
        if len(out) >= 70:
            break
    if len(out) < 70 and len(text) > len(out):
        out = text
    if len(out) > limit:
        out = out[:limit].rsplit(" ", 1)[0].rstrip(",;:") + " …"
    return out


def _scen_counts(t: dict) -> str:
    sc = collections.Counter(s["status"] for s in t.get("source_scenarios") or [])
    total = sum(sc.values())
    return f"{sc['covered']}/{total} covered" if total else "—"


def render(d: dict, view: str) -> str:
    fw, a = d["framework"], d["assessment"]
    sha, repo = a["git_commit"], a["repository"]
    all_threats = d["threats"]
    threats = [t for t in all_threats if view == "complete" or int(t["id"][1:]) <= 15]
    denom = len(threats)
    counts = collections.Counter(t["coverage"] for t in threats)
    uniq = {e["test_id"] for t in threats for e in (t.get("evidence") or [])}

    o: list[str] = []
    w = o.append
    complete = view == "complete"

    w("# OWASP Agentic AI " + ("v1.1 Threat Coverage Report" if complete
      else "T1–T15 Coverage — Solutions Landscape Submission View"))
    w("")
    w("*Evidence-based mapping of executable adversarial tests — not a certification, "
      "conformance claim, mitigation guarantee, or OWASP endorsement.*")
    w("")
    if not complete:
        w("> **This is a filtered view.** It contains T1–T15 only, because the OWASP Solutions "
          "Landscape form that was submitted presented that taxonomy. Guide v1.1 defines "
          "**T1–T17**; T16 (Insecure Inter-Agent Protocol Abuse) and T17 (Supply Chain "
          "Compromise) are omitted here **solely** for that reason, not for lack of evidence — "
          "both are adjudicated `direct` in the complete report. "
          "**[Read the complete T1–T17 report →](OWASP-AGENTIC-V1.1-COVERAGE.md)**")
        w("")

    w("## Snapshot")
    w("")
    w("| | |")
    w("|---|---|")
    w("| Report view | " + ("Complete (T1–T17)" if complete else "Submission (T1–T15)") + " |")
    w("| Report version | 1.0 |")
    w(f"| Project | {a['project']} |")
    w(f"| Harness version | `{a['harness_version']}` |")
    w(f"| Assessed commit | [`{sha}`]({repo}/commit/{sha}) |")
    w(f"| Assessed at | {a['assessed_at']} |")
    w(f"| Repository tests | {a['total_repository_tests']} (`{a['total_tests_command']}`) |")
    w(f"| Unique tests mapped in this view | {len(uniq)} |")
    w(f"| OWASP source | *{fw['title']}*, **v{fw['version']}**, {fw['publication_date']} |")
    w(f"| Source landing page | [{fw['source_url']}]({fw['source_url']}) |")
    w(f"| Source PDF | `{fw['source_pdf']}`, {fw['source_pages']} pp, "
      f"SHA-256 `{fw['source_sha256']}` |")
    w(f"| Licence | [{fw['license']}]({fw['license_url']}) |")
    w(f"| Adjudicated by | {a['adjudicated_by']} |")
    if complete:
        w("| Submission view | [T1–T15 →](OWASP-AGENTIC-T1-T15-SUBMISSION-COVERAGE.md) |")
    if d.get("asi_top10_crosswalk"):
        w("| Where OWASP files these threats | "
          "[ASI Top 10 crosswalk →](OWASP-ASI-TOP10-CROSSWALK.md) (transcription, not coverage) |")
    w("")

    w("## Scope, attribution and disclaimer")
    w("")
    w("> This report documents adversarial test capability provided by Agent Security Harness at "
      "the identified commit. “Direct test coverage” means the repository contains executable "
      "tests applicable to the stated OWASP threat; it does not mean a tested system mitigates "
      "the threat, that the harness enforces OWASP's recommended controls, or that OWASP has "
      "validated, endorsed, approved, or certified the harness. Threat and scenario summaries "
      "are adapted from OWASP *Agentic AI — Threats and Mitigations*, Version 1.1, under "
      "[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).")
    w("")
    w("This report evaluates **the harness**, not the security posture of any target system.")
    w("")
    w(f"**Attribution.** {fw['attribution']}")
    w("")
    w("**Threat coverage and mitigation validation are separate dimensions.** A test that shows a "
      "threat is exercisable says nothing about whether any recommended control works. The two "
      "are never inferred from each other.")
    w("")

    w("## Executive threat summary")
    w("")
    w("| Threat | Step | Status | Tests | Scenarios | Rationale | |")
    w("|---|---|---|---|---|---|---|")
    for t in threats:
        w(f"| **{t['id']}** {t['title']} | {','.join(str(s) for s in t['decision_steps'])} | "
          f"{LABEL[t['coverage']]} | {len(t.get('evidence') or [])} | {_scen_counts(t)} | "
          f"{_summary(t['rationale'])} | [detail]({_anchor(t)}) |")
    w("")
    w(f"**Derived totals — {counts['direct']} direct · {counts['partial']} partial · "
      f"{counts['not_evidenced']} not evidenced**, denominator **{denom}**. "
      "Partial is never folded into direct.")
    w("")

    if complete:
        w("## Submission-view reconciliation")
        w("")
        w("The landscape form selected T1–T9 and T11–T14; T10 and T15 were not selected. Those "
          "13 boxes are **claims to audit, not statuses to preserve.**")
        w("")
        w("| Threat | Form selection | Audited status | Action |")
        w("|---|---|---|---|")
        for t in threats:
            if int(t["id"][1:]) > 15:
                continue
            sel = {"selected": "selected", "not_selected": "not selected"}[t["submission_disposition"]]
            if t["submission_disposition"] == "selected" and t["coverage"] == "direct":
                act = "Supported"
            elif t["submission_disposition"] == "selected":
                act = "**Downgrade — disclose to OWASP**"
            elif t["coverage"] == "not_evidenced":
                act = "Correctly unselected"
            else:
                act = "Review"
            w(f"| **{t['id']}** {t['title']} | {sel} | {LABEL[t['coverage']]} | {act} |")
        w("")
        down = [t["id"] for t in threats if t["submission_disposition"] == "selected"
                and t["coverage"] != "direct"]
        if down:
            w(f"**{len(down)} submitted claim(s) downgraded: {', '.join(down)}.** These must be "
              "disclosed rather than preserved.")
            w("")

        w("## Architecture and threat-model context")
        w("")
        w("OWASP frames agent capability as planning/reasoning, memory/statefulness, action and "
          "tool use, and varying autonomy. The guide uses a reference-architecture-led threat "
          "model and names STRIDE, PASTA and MAESTRO as context rather than mandating one. Its "
          "four threat-modelling questions are:")
        w("")
        w("1. What are we working on?")
        w("2. What can go wrong?")
        w("3. What are we going to do about it?")
        w("4. Did we do a good enough job?")
        w("")
        w("Evidence records carry the architecture surface they touch — memory, tool and "
          "execution, identity and authorization, inter-agent channel, human interaction, "
          "supply-chain component — so a reader can tell which boundary a test actually crosses. "
          "Architecture and pattern metadata are descriptive and never establish coverage alone.")
        w("")

    w("## Methodology")
    w("")
    w(f"Every status is adjudicated at commit `{sha[:12]}`. A test is **direct** evidence only "
      "when its attack input matches the OWASP definition or a named scenario, its actor, "
      "target and direction are explicit, and its assertion observes a security-relevant "
      "outcome. **Partial** means a meaningful part is exercised but an important actor, "
      "direction, propagation path, boundary or variant is missing — stated explicitly. "
      "**Not evidenced** means no qualifying test exists at this commit; it is not a claim that "
      "the harness could never test it.")
    w("")
    w("None of these establish coverage alone: a README claim, an ASI or LLM Top 10 crosswalk, "
      "a similarly-worded test name, a mitigation recommendation, a playbook without an "
      "executable probe, a module-level count, a test concerning the opposite actor or "
      "direction, a static scanner result where the threat requires dynamic behaviour, or a "
      "generic prompt-injection test that does not exercise the agentic extension of the threat.")
    w("")
    w("**Evidence classes.** `live_target` executes against a real target; `controlled_runtime` "
      "against an instrumented local runtime; `simulation` models an interaction without a live "
      "target; `fixture` compares deterministic behaviour against committed data; "
      "`static_preflight` inspects configuration without executing the attack path. "
      "**Static-preflight evidence alone cannot establish direct coverage** for a behaviourally "
      "defined threat, and a validator rule enforces that.")
    w("")
    w("**Duplicate handling.** A test may support several threats and is listed under each, but "
      "counted once in the unique total.")
    w("")
    on = d.get("oracle_notes") or {}
    if on:
        w("**Oracle note.** `red_team_automation.py` passes on "
          f"`{on['red_team_automation_pass_rule']}`. Tests listing 200 alongside 4xx pass whether "
          "an attack was blocked or succeeded, so their only live security assertion is the "
          "response-body leak check: "
          + ", ".join(f"`{x}`" for x in on["status_permissive_tests"]) +
          ". They are evidence about data leakage, not blocking, and back no direct verdict.")
        w("")

    if complete:
        w("## Decision path")
        w("")
        w("The guide routes a system to relevant threats through six questions. This is a routing "
          "aid, not a score, and the steps are not mutually exclusive.")
        w("")
        w("| Step | Question | Threats |")
        w("|---|---|---|")
        for s in d["decision_path"]:
            w(f"| **{s['step']}. {s['name']}** | {s['question']} | "
              f"{', '.join(s['threats'])} |")
        w("")

    ed = d.get("llm_top10_editions") or {}
    if ed:
        src, suc = ed["refs_edition_source"], ed["successor_edition_source"]
        w("## Reading the OWASP LLM Top 10 refs")
        w("")
        w(f"**Every `LLM..` ref below is the {ed['refs_edition']} edition, and carries its "
          "entry title for that reason.** " + " ".join(ed["why"].split()))
        w("")
        w(f"Refs are pinned to *{src['title']}* ({src['edition']}), entries read from "
          f"[the OWASP project repository]({src['entries_source']}) on {src['retrieved']}. "
          f"The successor is *{suc['title']}*, {suc['document_version']}, posted to its "
          f"[landing page]({suc['landing_page']}) on {suc['landing_page_posted']}; "
          f"`{suc['source_pdf']}`, {suc['source_pages']} pp, SHA-256 "
          f"`{suc['source_sha256']}`, read {suc['retrieved']}.")
        w("")
        w("**The successor document does not state a publication date.** "
          + " ".join(suc["publication_status_note"].split()))
        w("")
        w(" ".join(ed["not_remapped"].split()))
        w("")
        w("| 2025 ref | 2026 ref | Moved |")
        w("|---|---|---|")
        for r in ed["renumbering"]:
            moved = "re-scoped" if r.get("rescoped") else ("yes" if r["moved"] else "—")
            w(f"| {r['id_2025']}:2025 {r['title_2025']} | "
              f"{r['id_2026']}:2026 {r['title_2026']} | {moved} |")
        w("")
        w(" ".join(ed["rescope_note"].split()))
        w("")

    w("## Threat detail")
    for t in threats:
        w("")
        w(f"### {t['id']} {t['title']}")
        w("")
        w(f"**Status:** {LABEL[t['coverage']]} &nbsp;·&nbsp; **Decision step:** "
          f"{', '.join(str(s) for s in t['decision_steps'])} &nbsp;·&nbsp; "
          f"**Scope:** `{t['disposition']}` &nbsp;·&nbsp; "
          f"**Form:** `{t['submission_disposition']}`")
        if t.get("related_framework_refs"):
            w("")
            w(f"**Related OWASP refs:** {', '.join(t['related_framework_refs'])}")
        w("")
        w(f"**Threat (adapted from the guide).** {t['threat_interpretation'].strip()}")
        w("")
        w(f"**Rationale.** {t['rationale'].strip()}")
        w("")
        scen = t.get("source_scenarios") or []
        if scen:
            w("**OWASP scenario coverage.** Scenario coverage does not replace the threat status; "
              "a threat can be direct without every scenario being covered.")
            w("")
            w("| Scenario | Status |")
            w("|---|---|")
            for s in scen:
                w(f"| `{s['scenario_id']}` {s['title']} | {SLABEL[s['status']]} |")
            w("")
        ev = t.get("evidence") or []
        if ev:
            w("| Test | Module | Actor → target | Attack path | Assertion | Class | Rerun |")
            w("|---|---|---|---|---|---|---|")
            for e in ev:
                link = f"{repo}/blob/{sha}/{e['module']}"
                w(f"| `{e['test_id']}` | [`{e['module'].split('/')[-1]}`]({link}) | "
                  f"{e['actor']} → {e['target']} | {e['attack_path']} | {e['assertion']} | "
                  f"`{e['evidence_class']}` | `{e['execution']}` |")
            w("")
        else:
            w("*No evidence records — see rationale.*")
            w("")
        mv = [m for m in (t.get("mitigation_validation") or []) if m["status"] != "guidance_only"]
        if mv:
            w("**Mitigation controls validated.**")
            w("")
            w("| Control | Status | Evidence |")
            w("|---|---|---|")
            for m in mv:
                w(f"| `{m['control_id']}` | {MLABEL[m['status']]} | "
                  f"{', '.join('`'+x+'`' for x in m['evidence']) or '—'} |")
            w("")
        for lim in t.get("limitations") or []:
            w(f"- **Limitation.** {lim}")
        if t.get("limitations"):
            w("")

    if complete:
        w("## Mitigation playbooks")
        w("")
        w("All six playbooks from the guide. A control counted as **validated** has an executable "
          "test asserting a control-specific outcome. **Guidance only** means the harness cites "
          "the control but does not test it at this commit. A control count is not an "
          "effectiveness score.")
        w("")
        allmv = {c["control_id"]: c["validation"]["status"]
                 for p in d["playbooks"] for c in p["controls"]}
        w("| Playbook | Step | Threats | Controls | Validated | Partial | Guidance only |")
        w("|---|---|---|---|---|---|---|")
        for p in d["playbooks"]:
            ids = [c["control_id"] for c in p["controls"]]
            v = sum(1 for c in ids if allmv.get(c) == "validated")
            pa = sum(1 for c in ids if allmv.get(c) == "partial")
            g = sum(1 for c in ids if allmv.get(c, "not_assessed") == "guidance_only")
            flag = " ⚠️" if v == 0 and pa == 0 else ""
            w(f"| **{p['id']}** {p['title']}{flag} | {p['decision_step']} | "
              f"{', '.join(p['threats'])} | {len(ids)} | {v} | {pa} | {g} |")
        w("")
        untested = [p for p in d["playbooks"]
                    if all(c["validation"]["status"] == "guidance_only" for c in p["controls"])]
        for p in untested:
            w(f"**⚠️ {p['id']} has no validated control at this commit.** Every control in "
              f"*{p['title']}* is cited but untested, and the threats it maps to "
              f"({', '.join(p['threats'])}) are themselves not evidenced. The gap is visible "
              "from both directions, which is the clearest signal in this report about where "
              "the harness does not reach.")
            w("")
        w("<details><summary>Paraphrased controls</summary>")
        w("")
        for p in d["playbooks"]:
            w(f"**{p['id']} — {p['title']}**")
            w("")
            for c in p["controls"]:
                v = c["validation"]
                ev = ", ".join(f"`{x}`" for x in v["evidence"])
                line = (f"- `{c['control_id']}` *({c['phase']})* — {c['summary']} "
                        f"— **{MLABEL[v['status']]}**")
                if ev:
                    line += f" via {ev}"
                w(line)
                if v.get("limitation"):
                    w(f"  - *Limitation.* {v['limitation']}")
            w("")
        w("</details>")
        w("")

        w("## Example threat models")
        w("")
        w("The guide publishes three example scenario families. Analogy is contextual and never "
          "changes a threat status.")
        w("")
        w("| Example | OWASP threats shown | Analogy | Approximating tests |")
        w("|---|---|---|---|")
        for x in d["example_models"]:
            w(f"| **{x['title']}** | {', '.join(x['threats'])} | `{x['analogy']}` | "
              f"{', '.join('`'+t+'`' for t in x['approximating_tests'])} |")
        w("")
        for x in d["example_models"]:
            w(f"- **{x['title']}.** {x['analogy_note']}")
        w("")

    w("## Known gaps and roadmap")
    w("")
    gaps = [t for t in threats if t["coverage"] != "direct"]
    w("| Threat | Status | Disposition | Missing capability |")
    w("|---|---|---|---|")
    for t in gaps:
        w(f"| **{t['id']}** {t['title']} | {LABEL[t['coverage']]} | `{t['disposition']}` | "
          f"{(t.get('limitations') or ['—'])[0]} |")
    w("")
    unc = [(t["id"], s["scenario_id"], s["title"]) for t in threats
           for s in (t.get("source_scenarios") or []) if s["status"] == "not_evidenced"]
    w(f"**{len(unc)} named OWASP scenarios are not evidenced** in this view. Roadmap items are "
      "not counted as current coverage.")
    w("")
    w("<details><summary>Unevidenced scenarios</summary>")
    w("")
    for tid, sid, title in unc:
        w(f"- `{sid}` {title} ({tid})")
    w("")
    w("</details>")
    w("")

    w("## Reproduction")
    w("")
    w("```bash")
    w(f"git clone {repo}.git && cd red-team-blue-team-agent-fabric")
    w(f"git checkout {sha}")
    w("pip install -e '.[dev]'")
    w("")
    w("python scripts/count_tests.py                              # repository test count")
    w("python scripts/validate_owasp_agentic_mapping.py           # all validation rules")
    w("python scripts/generate_owasp_agentic_coverage.py          # regenerate both views + JSON")
    w("")
    w("# verify the OWASP source you are reading is the one assessed")
    w(f"sha256sum {fw['source_pdf']}")
    w(f"# expect {fw['source_sha256']}")
    w("```")
    w("")
    w("Per-test rerun commands are in the `Rerun` column of each evidence table.")
    w("")

    if complete:
        w("## Guide Coverage Manifest")
        w("")
        w("Explicit proof that the whole publication was considered, not only its threat table.")
        w("")
        w("| Guide part | Treatment | Where | Note |")
        w("|---|---|---|---|")
        for g in d["guide_manifest"]:
            w(f"| {g['section']} | `{g['treatment']}` | {g['report_location']} | {g['note']} |")
        w("")

        w("## Source notes and limitations")
        w("")
        w("Recorded for source fidelity, not as criticism of OWASP. Inconsistencies in the source "
          "are disclosed rather than silently repaired.")
        w("")
        for n in fw["source_notes"]:
            mark = "confirmed in the source text" if n.get("verified") else "**reported but not confirmed**"
            w(f"- **`{n['id']}`** — {n['note']} *({mark}.)*")
        w("")
        w("- External links and factual examples in the OWASP guide were not independently "
          "revalidated.")
        w("- The adjudication was performed by the corpus author and is **not independent "
          "review**. It does not discharge the single-author limitation.")
        w("")

    w("## Change history")
    w("")
    w("| Report | Source | Harness | Commit | Date | Change |")
    w("|---|---|---|---|---|---|")
    # Was a single hardcoded "1.0" row, so a re-pin could not be recorded and the
    # header could claim a harness version the pinned commit did not contain.
    history = a.get("report_history") or [{
        "report": "1.0", "commit": sha, "harness": a["harness_version"],
        "date": a["assessed_at"][:10],
        "change": "Initial T1–T17 adjudication against guide v1.1."}]
    for h in history:
        w(f"| {h['report']} | v{fw['version']} `{fw['source_sha256'][:12]}` | {h['harness']} | "
          f"`{h['commit'][:12]}` | {h['date']} | {h['change']} |")
    w("")
    w("A status changes only through a reviewed mapping change.")
    w("")

    return "\n".join(o) + "\n"


def render_asi_crosswalk(d: dict) -> str:
    """OWASP's own ASI Top 10 <-> T1-T17 mapping, transcribed, not adjudicated.

    Kept out of the coverage reports on purpose. Those documents adjudicate
    harness evidence against a threat; this one records where another OWASP
    document files that threat. Mixing them would put an unadjudicated
    statement inside a report whose whole value is that everything in it was
    adjudicated, and the methodology section already says a crosswalk
    establishes no coverage.
    """
    x = d["asi_top10_crosswalk"]
    src, tt = x["source"], {t["id"]: t["title"] for t in d["threats"]}
    out: list[str] = []
    w = out.append

    w("# OWASP ASI Top 10 (2026) -> Agentic AI Threats & Mitigations (T1-T17)")
    w("")
    w("> **This is a transcription, not an adjudication, and not a coverage claim.**")
    w("> " + " ".join(x["what_this_is"].split()))
    w("")
    w(f"**Source.** *{src['title']}*, {src['publisher']}, version {src['version']}, "
      f"{src['document_date']}. [Landing page]({src['landing_page']}). "
      f"`{src['source_pdf']}`, {src['source_pages']} pp, {src['license']}, SHA-256 "
      f"`{src['source_sha256']}`, retrieved {src['retrieved']}. "
      f"Primary table: {src['primary_table']}.")
    w("")
    w("**Relation semantics.** " + " ".join(x["relation_semantics"].split()))
    w("")

    w("## ASI entry -> threats")
    w("")
    # Titles below are v1.1's, because the mapping is by NUMBER. Where the ASI
    # document gives that number a different title, the cell is marked so the
    # reader is not shown a title the source never used. See the discrepancy
    # table further down.
    diff = {(r["entry"], r["t_id"]) for r in x["title_discrepancies"]["observed"]}

    def _t(entry_id: str, tid: str, bold: bool) -> str:
        s = f"**{tid}** {tt[tid]}" if bold else f"{tid} {tt[tid]}"
        return s + " †" if (entry_id, tid) in diff else s

    w("| ASI | Title | Maps to (primary) | Contributing / related | AIVSS core risk |")
    w("|---|---|---|---|---|")
    for e in x["entries"]:
        prim = ", ".join(_t(e["id"], i, True) for i in e["threats_primary"]) or "_none stated_"
        con = ", ".join(_t(e["id"], i, False) for i in e["threats_contributing"]) or "—"
        w(f"| {e['id']} | {e['title']} | {prim} | {con} | {e.get('aivss_core_risk', '—')} |")
    w("")
    if diff:
        w("† The ASI document gives this threat number a different title from v1.1. The number is "
          "what the source states and what is transcribed; the title shown is v1.1's. See "
          "[Threat titles that disagree with v1.1](#threat-titles-that-disagree-with-v11).")
        w("")

    w("## Threat -> ASI entries")
    w("")
    w("| Threat | Primary for | Contributing to |")
    w("|---|---|---|")
    for t in d["threats"]:
        p = [e["id"] for e in x["entries"] if t["id"] in e["threats_primary"]]
        c = [e["id"] for e in x["entries"] if t["id"] in e["threats_contributing"]]
        w(f"| **{t['id']}** {t['title']} | {', '.join(p) or '—'} | {', '.join(c) or '—'} |")
    w("")
    w(" ".join(x["t9_not_referenced"].split()))
    w("")

    td = x["title_discrepancies"]
    w("## Threat titles that disagree with v1.1")
    w("")
    w(" ".join(td["note"].split()))
    w("")
    w("| Threat | Title in the ASI Top 10 | Title in v1.1 | Seen in |")
    w("|---|---|---|---|")
    for r in td["observed"]:
        w(f"| {r['t_id']} | {r['asi_doc_title']} | {r['v1_1_title']} | {r['seen_in']} |")
    w("")

    w("## Statements transcribed")
    w("")
    for e in x["entries"]:
        w(f"- **{e['id']} {e['title']}** — "
          + (f"\"{e['source_statement']}\"" if e.get("source_statement")
             else " ".join(e["source_statement_note"].split())))
    w("")
    w(f"Generated from `{MAPPING.relative_to(ROOT)}` by "
      f"`{pathlib.Path(__file__).relative_to(ROOT)}`. Do not edit by hand.")
    w("")
    return "\n".join(out)


def build_json(d: dict) -> dict:
    counts = {v: collections.Counter(t["coverage"] for t in d["threats"]
              if v == "complete" or int(t["id"][1:]) <= 15) for v in ("complete", "submission")}
    return {
        "framework": d["framework"], "assessment": d["assessment"],
        # Carried into the machine-readable artifact on purpose: a consumer reading
        # related_framework_refs needs to know which edition the IDs belong to, and
        # that eight of the ten were renumbered by the 2026 edition.
        "llm_top10_editions": d["llm_top10_editions"],
        # OWASP's own ASI Top 10 <-> T1-T17 mapping. Transcribed, not adjudicated;
        # a consumer must not read it as a coverage verdict.
        "asi_top10_crosswalk": d["asi_top10_crosswalk"],
        "decision_path": d["decision_path"], "playbooks": d["playbooks"],
        "example_models": d["example_models"], "guide_manifest": d["guide_manifest"],
        "threats": d["threats"],
        "totals": {v: dict(c) for v, c in counts.items()},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--view", choices=["complete", "submission"], help="render one view")
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = ap.parse_args()

    d = yaml.safe_load(MAPPING.read_text(encoding="utf-8"))

    if args.stdout:
        sys.stdout.write(render(d, args.view or "complete"))
        return 0

    COMPLETE.write_text(render(d, "complete"), encoding="utf-8")
    SUBMISSION.write_text(render(d, "submission"), encoding="utf-8")
    JSON_OUT.write_text(json.dumps(build_json(d), indent=2, sort_keys=False) + "\n", encoding="utf-8")
    ASI_CROSSWALK.write_text(render_asi_crosswalk(d), encoding="utf-8")

    c = collections.Counter(t["coverage"] for t in d["threats"])
    s = collections.Counter(t["coverage"] for t in d["threats"] if int(t["id"][1:]) <= 15)
    print(f"wrote {COMPLETE.relative_to(ROOT)}   T1-T17: {c['direct']}d {c['partial']}p {c['not_evidenced']}n")
    print(f"wrote {SUBMISSION.relative_to(ROOT)}   T1-T15: {s['direct']}d {s['partial']}p {s['not_evidenced']}n")
    print(f"wrote {JSON_OUT.relative_to(ROOT)}")
    n = len(d["asi_top10_crosswalk"]["entries"])
    print(f"wrote {ASI_CROSSWALK.relative_to(ROOT)}   ASI01-ASI{n:02d} transcribed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
