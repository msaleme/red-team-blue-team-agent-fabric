#!/usr/bin/env python3
"""Generate the OWASP Agentic T1-T15 coverage report from the canonical mapping.

The mapping at docs/coverage/owasp-agentic-t1-t15.yaml is the source of truth.
This renders docs/OWASP-AGENTIC-T1-T15-COVERAGE.md from it. Never edit the
Markdown by hand - the validator fails if the committed file differs from fresh
output.

    python scripts/generate_owasp_t1_t15_report.py            # write the report
    python scripts/generate_owasp_t1_t15_report.py --stdout   # print instead
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    raise SystemExit(2)

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAPPING = ROOT / "docs/coverage/owasp-agentic-t1-t15.yaml"
OUTPUT = ROOT / "docs/OWASP-AGENTIC-T1-T15-COVERAGE.md"

STATUS_LABEL = {
    "direct": "Direct test coverage",
    "partial": "Partial test coverage",
    "not_evidenced": "Not evidenced",
}


def _permalink(repo: str, sha: str, path: str) -> str:
    return f"{repo}/blob/{sha}/{path}"


def _summary(rationale: str, limit: int = 165) -> str:
    """One-sentence summary for the coverage table.

    Takes whole sentences, never a mid-word cut. Keeps adding sentences while
    the result stays short, because a first sentence like "VERDICT CHANGED on
    reading guide v1.1." is true but tells a reader nothing on its own.
    """
    text = " ".join(rationale.split())
    sentences = [s.strip() for s in text.replace("? ", ". ").split(". ") if s.strip()]
    out = ""
    for s in sentences:
        candidate = (out + " " if out else "") + s.rstrip(".") + "."
        if out and len(candidate) > limit:
            break
        out = candidate
        if len(out) >= 70:
            break
    # A first sentence can be true and still say nothing on its own - "VERDICT
    # CHANGED on reading guide v1.1." is 38 characters of no information. If the
    # next sentence was too long to append, truncate the full rationale instead
    # of shipping the stub.
    if len(out) < 70 and len(text) > len(out):
        out = text
    if len(out) > limit:
        out = out[:limit].rsplit(" ", 1)[0].rstrip(",;:") + " …"
    return out


def render(data: dict) -> str:
    fw = data["framework"]
    a = data["assessment"]
    threats = data["threats"]
    sha = a["git_commit"]
    repo = a["repository"]

    counts = collections.Counter(t["coverage"] for t in threats)
    unique = {e["test_id"] for t in threats for e in (t.get("evidence") or [])}

    o: list[str] = []
    w = o.append

    w("# OWASP Agentic AI T1–T15 Test Coverage Report")
    w("")
    w("*Evidence-based mapping of executable adversarial tests — not a certification "
      "or mitigation guarantee.*")
    w("")

    # 7.1 snapshot metadata
    w("## Snapshot")
    w("")
    w("| | |")
    w("|---|---|")
    w(f"| Project | {a['project']} |")
    w(f"| Harness version | `{a['harness_version']}` |")
    w(f"| Assessed commit | [`{sha}`]({repo}/commit/{sha}) |")
    w(f"| Assessed at | {a['assessed_at']} |")
    w(f"| Repository tests | {a['total_repository_tests']} "
      f"(`{a['total_tests_command']}`) |")
    w(f"| Unique tests mapped into this report | {len(unique)} |")
    w(f"| Taxonomy | {fw['publisher']} *{fw['title']}*, {fw['scope']}, "
      f"published {fw['publication_date']} |")
    w(f"| Taxonomy source | [{fw['source_url']}]({fw['source_url']}) |")
    if fw.get("local_document_version"):
        w(f"| Guide version read | v{fw['local_document_version']} "
          f"(SHA-256 `{fw['source_pdf_sha256'][:16]}…`) |")
    w(f"| Adjudicated by | {a['adjudicated_by']} |")
    w("")

    # 7.2 scope and disclaimer
    w("## Scope and disclaimer")
    w("")
    w("> This report documents adversarial test coverage provided by Agent Security "
      "Harness. “Direct test coverage” means the assessed repository commit contains "
      "executable tests applicable to the stated OWASP threat. It does not mean a "
      "tested system mitigates the threat, that the harness enforces the recommended "
      "controls, or that OWASP has validated, endorsed, or certified the harness.")
    w("")
    w("This report evaluates the **harness's test capability**, not the security "
      "posture of any target system.")
    w("")
    if fw.get("scope_note"):
        w(f"**Scope.** {fw['scope_note'].strip()}")
        w("")
    w(f"**Provenance of interpretations.** {fw['note'].strip()}")
    w("")

    # 7.3 executive summary
    w("## Coverage summary")
    w("")
    w("| Threat | Status | Tests | Rationale | |")
    w("|---|---|---|---|---|")
    for t in threats:
        n = len(t.get("evidence") or [])
        anchor = f"#{t['id'].lower()}-" + t["title"].lower().replace(" ", "-").replace("&", "").replace("--", "-")
        w(f"| **{t['id']}** {t['title']} | {STATUS_LABEL[t['coverage']]} | {n} | "
          f"{_summary(t['rationale'])} | [detail]({anchor}) |")
    w("")
    w(f"**Derived totals — {counts['direct']} direct · {counts['partial']} partial · "
      f"{counts['not_evidenced']} not evidenced**, across {len(threats)} threats. "
      "Partial coverage is not folded into the direct count.")
    w("")

    # 7.4 methodology
    w("## Methodology")
    w("")
    w(f"Every status is adjudicated at commit `{sha[:12]}` against the evidence "
      "threshold below. A test is **direct** evidence only when its attack input "
      "matches the threat definition *and* its assertion observes a security-relevant "
      "outcome — block, allow, alert, isolation, rejection, rate limiting or safe "
      "failure. A test is **partial** evidence when it exercises a meaningful part of "
      "the threat but not its defining end-to-end behaviour; the missing part is "
      "stated. **Not evidenced** means no executable test at this commit supports a "
      "coverage statement — it is not a claim that the harness could never test it.")
    w("")
    w("The following do not establish coverage on their own: a README claim, an "
      "ASI01–ASI10 crosswalk, a similarly-worded test name, a mitigation "
      "recommendation, a playbook without an executable probe, or a module-level "
      "test count.")
    w("")
    w("**Evidence types.** `live_target` runs against a running target. "
      "`simulation` runs a modelled scenario. `fixture` compares against committed "
      "data. `static_preflight` inspects configuration without exploitation.")
    w("")
    w("**Duplicate handling.** A test may support more than one threat and is listed "
      "under each, but counted once in the unique-evidence total.")
    w("")
    on = data.get("oracle_notes")
    if on:
        w("**Oracle note — this decides several statuses.** `red_team_automation.py` "
          f"passes on `{on['red_team_automation_pass_rule']}`. Tests listing 200 "
          "alongside 4xx pass whether the attack was blocked or succeeded, so their "
          "only live security assertion is the response-body leak check. "
          f"Affected: {', '.join(f'`{t}`' for t in on['status_permissive_tests'])}. "
          "These are evidence about data leakage, not about blocking, and back no "
          "direct verdict here. A validator rule enforces that.")
        w("")

    # 7.5 detail
    w("## Threat detail")
    for t in threats:
        w("")
        w(f"### {t['id']} {t['title']}")
        w("")
        w(f"**Status:** {STATUS_LABEL[t['coverage']]} &nbsp;·&nbsp; "
          f"**Disposition:** `{t['disposition']}`")
        w("")
        w(f"**Threat (per guide).** {t['threat_interpretation'].strip()}")
        w("")
        w(f"**Rationale.** {t['rationale'].strip()}")
        w("")
        ev = t.get("evidence") or []
        if ev:
            w("| Test | Module | Attack path | Assertion | Type | Rerun |")
            w("|---|---|---|---|---|---|")
            for e in ev:
                link = _permalink(repo, sha, e["module"])
                w(f"| `{e['test_id']}` | [`{e['module']}`]({link}) | "
                  f"{e['attack_path']} | {e['assertion']} | `{e['evidence_type']}` | "
                  f"`{e['execution']}` |")
            w("")
        else:
            w("*No evidence records — see rationale above.*")
            w("")
        for lim in t.get("limitations") or []:
            w(f"- **Limitation.** {lim}")
        if t.get("limitations"):
            w("")

    # 7.6 gaps
    w("## Known gaps and roadmap")
    w("")
    gaps = [t for t in threats if t["coverage"] != "direct"]
    if gaps:
        w("| Threat | Status | Disposition | Missing capability |")
        w("|---|---|---|---|")
        for t in gaps:
            miss = (t.get("limitations") or ["—"])[0]
            w(f"| **{t['id']}** {t['title']} | {STATUS_LABEL[t['coverage']]} | "
              f"`{t['disposition']}` | {miss} |")
        w("")
    w("Roadmap items are not counted as current coverage.")
    w("")

    # 7.7 reproduction
    w("## Reproduction")
    w("")
    w("```bash")
    w(f"git clone {repo}.git")
    w("cd red-team-blue-team-agent-fabric")
    w(f"git checkout {sha}")
    w("pip install -e '.[dev]'")
    w("")
    w("python scripts/count_tests.py                          # repository test count")
    w("python scripts/validate_owasp_t1_t15_mapping.py        # validate the mapping")
    w("python scripts/generate_owasp_t1_t15_report.py         # regenerate this report")
    w("```")
    w("")
    w("Per-test rerun commands are in the `Rerun` column of each evidence table.")
    w("")

    # appendix
    appendix = data.get("appendix_out_of_scope")
    if appendix:
        w("## Appendix — guide threats outside this report's scope")
        w("")
        w("Guide v1.1 defines T1–T17. This report covers T1–T15, the taxonomy the "
          "OWASP submission form presents. The following are **excluded from every "
          "count and headline above** and have not been adjudicated. "
          "`not_assessed` is not a finding.")
        w("")
        for x in appendix:
            w(f"**{x['id']} {x['title']}** — {x['guide_definition'].strip()}")
            w("")
            w(f"> {x['note'].strip()}")
            w("")

    # 7.8 change history
    w("## Change history")
    w("")
    w("| Report | Harness | Commit | Date | Change |")
    w("|---|---|---|---|---|")
    w(f"| 1.0 | {a['harness_version']} | `{sha[:12]}` | {a['assessed_at'][:10]} | "
      "Initial adjudication of T1–T15 against guide v1.1. |")
    w("")
    w("A threat's status may change only through a mapping change reviewed in a pull "
      "request.")
    w("")

    return "\n".join(o) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = ap.parse_args()

    data = yaml.safe_load(MAPPING.read_text(encoding="utf-8"))
    text = render(data)

    if args.stdout:
        sys.stdout.write(text)
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(text, encoding="utf-8")
        counts = collections.Counter(t["coverage"] for t in data["threats"])
        unique = {e["test_id"] for t in data["threats"] for e in (t.get("evidence") or [])}
        print(
            f"wrote {OUTPUT.relative_to(ROOT)} - "
            f"{counts['direct']} direct, {counts['partial']} partial, "
            f"{counts['not_evidenced']} not evidenced, {len(unique)} unique tests"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
