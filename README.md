# Agent Security Harness

[![PyPI version](https://badge.fury.io/py/agent-security-harness.svg)](https://pypi.org/project/agent-security-harness/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/security%20tests-608-green.svg)](#three-layers-of-agent-decision-security)
[![OWASP Agentic T1-T17](https://img.shields.io/badge/OWASP%20Agentic%20v1.1-13%2F17%20direct-blue.svg)](docs/OWASP-AGENTIC-V1.1-COVERAGE.md)
[![ClawScan](https://img.shields.io/badge/ClawScan-Benign-brightgreen)](https://clawhub.ai/msaleme/agent-security-harness)
[![Static Analysis](https://img.shields.io/badge/Static%20Analysis-Benign-brightgreen)](https://clawhub.ai/msaleme/agent-security-harness)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-0%2F92_Clean-brightgreen)](https://www.virustotal.com/gui/url/37318967b56cd3cc1678972ebf0c53dbd37868b67ba3f6891447d53d51767cd2)

**Even if an agent is properly authenticated and authorized, can it still be manipulated into unsafe or policy-violating behavior?**

**A test that did not reach the target is not a passing security test.**

This harness sends adversarial traffic at a live endpoint, records what the target actually
serviced, and reports PASS, FAIL or **INCONCLUSIVE**. It will not convert a request the target
never answered — or a capability the target never exposed, or an answer that establishes
nothing either way — into evidence that a control held.
That distinction is enforced by `testing/test_serviced_guard.py` and
`testing/test_x402_capability_controls.py` rather than asserted here, and the repairs that put
it there are in [CHANGELOG.md](CHANGELOG.md).

### How that is checked: four target shapes

A verdict is only worth what it does when the target changes. Three scripts point every
suite at a sentinel that differs only in how it answers, and three state files under
`testing/` pin what each one claims:

```bash
python3 scripts/dead_host_sweep.py        # a closed port: nothing answers
python3 scripts/permissive_host_sweep.py  # HTTP 200, grants everything
python3 scripts/refusing_host_sweep.py    # HTTP 403, refuses everything
```

The fourth shape is a **live agent** rather than a transport, and it is asserted in
`testing/test_refusal_establishes_a_pass.py` rather than run as a script: one agent that
complies with every request without using an indicator word, and one that declines in plain
prose. A prose-graded module must pass **nothing** against the first and **something** against
the second. Those two assertions are what v4.17.0 repaired eight modules against.

The first two ask whether a verdict can be **wrong**: a PASS against either is a control
reported as holding when it was never exercised. The third asks whether a verdict can be
**right**, which the other two cannot see — a suite that cannot pass a target which refuses
every attack scores zero against all three, and that is what a healthy module looks like from
the first two poles.

These are diagnostic sentinels, not conformant implementations. A non-zero row is a reading
list rather than a defect count: it may be correct by construction (`over_refusal_harness`
asks whether *legitimate* requests are wrongly blocked, so it should pass a target that blocks
nothing), it may need a marker the generic sentinel does not emit, or it may be a real
inversion. Only reading the test separates them.

Sentinels are the floor. The first run against a real MCP implementation found two defect
classes all three had structurally missed, because every sentinel spoke the response idiom the
harness already expected.

```
$ agent-security test mcp --url http://localhost:8080/mcp
Running MCP Protocol Security Tests v4.17.0...
 MCP-001: Tool List Integrity Check [PASS] (0.234s)
 MCP-002: Tool Registration via Call Injection [PASS] (0.412s)
 MCP-003: Capability Escalation via Initialize [FAIL] (0.156s)
...
Results: 8/10 passed (80% pass rate) - see report.json
```

> Illustrative output. A target the harness cannot reach, or that answers without
> servicing the request, reports **INCONCLUSIVE** — never PASS. See
> [v4.13.1](CHANGELOG.md) for why that distinction is enforced rather than assumed.

608 executable security tests across 43 test-bearing modules on `main` (verified 2026-08-30 via `scripts/count_tests.py`; the v4.18.0 release carries 608). MCP + A2A + L402 + x402 wire-protocol testing, plus UCP/ACP merchant-journey, AP2 mandate-chain, Fireblocks x402 hardening, Visa TAP / Mastercard Agentic Token funding-instrument, and denial-of-settlement finality conformance across the full agentic-payments stack. Decision-layer attack scenarios. One `pip install` away.

If this evidence discipline is useful in your agent-security work, **star this
repository to follow releases**.

## Evidence before coverage

Every claim in this project is bounded by the
[E1-E5 Evidence Class Taxonomy](docs/EVIDENCE-CLASS-TAXONOMY.md): observation,
runtime characterization, enforcement, persistence/replay resistance, and
isolation. A second axis, **I0-I2**, states who produced the oracle:
self-authored, independently reimplemented, or an independent sensor the target
does not control. Strength and independence are different properties, so both
are cited. A result is not promoted beyond what its retained artifact and
execution record demonstrate. Author-performed mappings and test runs are not
independent certification.

The [AIUC-1 Evidence Field Guide](https://msaleme.github.io/aiuc1-readiness/) is a
plain-language companion that applies this same taxonomy. It adds one distinction
the ladder above does not encode: whether evidence is *mapped* (a documented
requirement relationship), *executed* (a recorded run against a stated target and
pinned revision), or *independently reviewed* (assessed by a qualified outside
party). Those describe the status of evidence and are orthogonal to E1-E5, which
describes its strength. A mapping alone is E1-level material regardless of how many
requirements it covers. The taxonomy in this repository is canonical; the field
guide is hosted outside it and is not version-pinned.

**[OWASP Agentic AI v1.1 Threat Coverage Report](docs/OWASP-AGENTIC-V1.1-COVERAGE.md)** — commit-pinned mapping from the full **T1–T17** taxonomy to executable tests: **13 direct, 4 partial, 0 not evidenced**, across 96 mapped tests and 66 named OWASP scenarios. Mitigation-control validation is tracked separately from threat coverage (11 validated, 10 partial, 1 guidance-only), and every gap, evidence class and reproduction command is in the report. ([T1–T15 submission view](docs/OWASP-AGENTIC-T1-T15-SUBMISSION-COVERAGE.md) · [canonical mapping](docs/coverage/owasp-agentic-v1.1.yaml))

> Adapted from OWASP *Agentic AI — Threats and Mitigations* v1.1 under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). A test-capability report — not a certification, conformance claim, or OWASP endorsement. The adjudication is author-performed and is not independent review.

## Quick Start

```bash
pipx install agent-security-harness
```

`pipx` is the recommended install because this is a command-line tool. It builds
an isolated environment and puts `agent-security` on your PATH, with no `sudo`
and no PATH edits. Get it with `brew install pipx`, `apt install pipx`, or
`python3 -m pip install --user pipx`.

<details>
<summary>Installing with pip instead</summary>

Use a virtual environment:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install agent-security-harness
```

**`pip install agent-security-harness` outside a virtual environment fails on
most current systems**, including Homebrew Python on macOS and Linux, Debian,
Ubuntu, and Fedora:

```
error: externally-managed-environment
```

Those interpreters ship a [PEP 668](https://peps.python.org/pep-0668/) marker
that blocks installs into the system environment. `--user` does not bypass it.
`--break-system-packages` does, and is a bad idea on a Homebrew Python. Use
`pipx` or a venv.

</details>

<details>
<summary>Keeping it updated</summary>

```bash
pipx upgrade agent-security-harness
```

[topgrade](https://github.com/topgrade-rs/topgrade) picks this up automatically
through its `pipx` step, or its `pip3` step for a `--user` install. No
configuration needed.

There is no Homebrew formula for this package.

</details>

```bash
# Confirm which build you're on:
agent-security --version

# See it work immediately — no server needed:
agent-security test mcp --simulate

# Then test your real MCP server:
agent-security test mcp --url http://localhost:8080/mcp

# Test an x402 payment endpoint
agent-security test x402 --url https://your-x402-endpoint.com

# Human-oversight surface: reviewer exposure (T10) and agent-to-human
# manipulation (T15). An unreachable target reports INCONCLUSIVE, never PASS.
agent-security test hitl --url http://localhost:8080

# Which tests back a given OWASP threat, scenario or mitigation control
python scripts/owasp_agentic_select.py --threat T16
python scripts/owasp_agentic_select.py --control P5-REA-001
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for mock server setup, rate limiting, MCP server mode, and CI/CD integration.

---

## Three Layers of Agent Decision Security

| Layer | What it covers | Example focus |
|-------|----------------|---------------|
| **Protocol Integrity** | Prevent spoofing, replay, downgrade, diversion, and malformed protocol behavior | MCP, A2A, L402, x402 wire-level tests |
| **Operational Governance** | Validate session state, capability boundaries, platform actions, trust chains, and execution context | capability escalation, facilitator trust, provenance, session security |
| **Decision Governance** | Test whether an agent should act at all under its authority, confidence, scope, and policy constraints | autonomy scoring, scope creep, return-channel poisoning, normalization-of-deviance |
| **Human Oversight** | Test whether the human review layer can be saturated, starved, blinded, or turned against its own principal | approval flooding, risk starvation, stripped decision context, agent→human manipulation (OWASP T10/T15) |

---

## How This Differs From Other Projects

| Capability | [Snyk Agent Scan](https://github.com/snyk/agent-scan) (2.9K stars) | [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) (1.0K stars) | [NVIDIA Garak](https://github.com/NVIDIA/garak) (8.7K stars) | **This framework** |
|---|---|---|---|---|
| **What it does** | Scans agent/MCP configs for tool poisoning and skill security | YARA + LLM-as-judge for malicious tools | LLM model vulnerability testing | Active protocol exploitation + decision governance |
| **Approach** | Static analysis | Static + LLM classification | Model-layer probing | **Wire-protocol adversarial testing** |
| **MCP coverage** | Tool descriptions, config files | Tool descriptions, YARA rules | - | **46 tests: protocol (32) + supply-chain (4) + tool-poisoning repro (10), real JSON-RPC 2.0 attacks** |
| **A2A coverage** | - | - | - | **13 tests** |
| **L402/x402 coverage** | - | - | - | **85 tests** (L402 33 + x402 52) |
| **Merchant journey (UCP/ACP)** | - | - | - | **12 tests: agent-profile + cross-merchant cart + delegated checkout** |
| **Funding instrument (Visa TAP / MC Agentic Tokens)** | - | - | - | **12 tests: holder/merchant/amount/velocity scope + dynamic cryptogram + revocation** |
| **Settlement finality (denial-of-settlement)** | - | - | - | **8 tests: release-before-finality, reorg revocation, withheld-settlement liveness** |
| **Payment authz/hardening** | - | - | - | **AP2 mandate (17) + Fireblocks x402 (17)** |
| **Enterprise platforms** | - | - | - | **25 cloud + 58 enterprise** (core 31 + extended 27) |
| **Human oversight (T10/T15)** | - | - | - | **8 tests: reviewer exposure + agent→human manipulation** |
| **APT simulation** | - | - | - | **GTG-1002 (17 tests)** |
| **Jailbreak/over-refusal** | - | - | Yes | **50 tests (25 + 25 FPR)** |
| **AIUC-1 certification** | - | - | - | **Maps to 19 of 20 testable requirements** (2026-Q1/Q2 set; [Q3 delta](docs/AIUC1-CROSSWALK.md)) |
| **OWASP Agentic v1.1** | - | - | - | **T1–T17 commit-pinned: 13 direct, 4 partial, 0 not evidenced** |
| **Research backing** | - | Cisco blog | Papers | **7 DOIs + 3 NIST submissions** (self-authored; see [Research](#research)) |
| **MCP server mode** | - | - | - | **Yes - invoke from any AI agent** |
| **Statistical testing** | - | - | - | **Wilson CIs, multi-trial** |
| **Total tests** | Config checks | YARA rules | Model probes | **608 active tests across 43 test-bearing modules** |

Star counts verified 2026-08-02 via the GitHub API. Invariant Labs' `mcp-scan` now redirects to
`snyk/agent-scan` and is listed once rather than as two separate projects. Competitor rows describe
what each tool does by design; a dash means the capability is outside its stated scope, not a defect.

**What the table does not measure.** Every row above is coverage: what gets tested, and how much.
Coverage says nothing about what a result licenses you to claim. That is what the
[E1-E5 Evidence Class Taxonomy](docs/EVIDENCE-CLASS-TAXONOMY.md) is for, and it is applied to this
project's own output first: the AIUC-1 crosswalk is E1 material regardless of covering 19 of 20
requirements, and this harness holds **no I2 evidence** at all, because it reads protocol responses
the target itself emits. No claim here is deliberately made about how other projects handle this.

**One external check.** The `Research backing` row says self-authored because it is. The one
exception is [#304](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/304), where an
outside party reimplemented the receipt-claim oracle from the published contract and replayed a
pinned corpus. One reproduction, of one corpus, by one party, is not independent review of the
harness as a whole, and this project still does not have that.

**Use both.** Scan with [Snyk Agent Scan](https://github.com/snyk/agent-scan) or [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) for static analysis. Test with this framework for active exploitation. They're complementary layers.

---

## Research

Seven public preprints and notes deposited on Zenodo (not represented as peer-reviewed publications) and three NIST submissions underpin the methodology. Every DOI below was re-verified on 2026-08-02 by content negotiation against `doi.org` — title and authorship confirmed:

| Publication | DOI |
|---|---|
| **Constitutional Self-Governance for Autonomous AI Agents** — 12 governance mechanisms, 77 days production data, 56 agents | [10.5281/zenodo.19162104](https://doi.org/10.5281/zenodo.19162104) |
| **Detecting Normalization of Deviance in Multi-Agent Systems** — First empirical demonstration that automated harnesses detect behavioral drift | [10.5281/zenodo.19195516](https://doi.org/10.5281/zenodo.19195516) |
| **Decision Load Index (DLI): A Quantitative Framework for Agent Autonomy Risk** — Measuring cognitive burden of AI agent oversight | [10.5281/zenodo.18217577](https://doi.org/10.5281/zenodo.18217577) |
| **Beyond Identity Governance: A Protocol-Level Security Testing Framework for Multi-Agent Systems** | [10.5281/zenodo.19343034](https://doi.org/10.5281/zenodo.19343034) |
| **Community-Driven Security for AI Agents: Evolution of an Adversarial Test Corpus** | [10.5281/zenodo.19343108](https://doi.org/10.5281/zenodo.19343108) |
| **Claim-Level Negative Testing for Agent-Governance Evidence** — Receipt-claim decomposition; the RCL-001..011 receipt-verification module in this harness | [10.5281/zenodo.21418701](https://doi.org/10.5281/zenodo.21418701) |
| **Signing Is Not Authorization: Claim-Level Negative Vectors for Agent-Payment Receipts** — payment-authority application of the receipt-claim decomposition; RCL-001..011 under adversarial payment receipts | [10.5281/zenodo.21535452](https://doi.org/10.5281/zenodo.21535452) |

**On citation counts.** These records carry internal citation lineage across later work in this
portfolio. An OpenAlex `cited_by` audit on 2026-08-02 found **30 citation edges and 0 qualifying
independent citations** — every edge is a self-citation, collapsing to nine duplicate/version records
across three title families. Nothing here should be read as third-party validation or scholarly
adoption. The one external check this project has received is an independent reproduction, listed
under [Used By](#used-by).

> **Correction (2026-08-02).** Two entries previously in this table cited DOIs belonging to other
> researchers — `10.5281/zenodo.15105866` (a MALDI mass-spectrometry dataset by Ranes et al.) and
> `10.5281/zenodo.15106553` (an e-learning article by Toshtemirov). They were attributed here to
> *"Normalization of Deviance in Autonomous Agent Systems"* and *"Cognitive Style Governance for
> Multi-Agent Deployments"*. No Zenodo record under those titles by this author was located, so both
> rows were removed rather than re-pointed. The surviving *Detecting Normalization of Deviance in
> Multi-Agent Systems* record (`19195516`) is unaffected and was already listed separately.

---

## Related Projects

### Constitutional Governance (WHY layer)

The [constitutional-agent](https://github.com/CognitiveThoughtEngine/constitutional-agent-governance) package provides the governance gates and hard constraints that complement this test harness. Six gates, 12 hard constraints, amendment protocol — enforced in code, not YAML policy files. `pip install constitutional-agent`.

---

## Documentation

| Resource | Link |
|---|---|
| Expanded Quick Start | [docs/QUICKSTART.md](docs/QUICKSTART.md) |
| Full Test Inventory (608 tests) | [docs/TEST-INVENTORY.md](docs/TEST-INVENTORY.md) |
| OWASP Agentic v1.1 Coverage (T1–T17) | [docs/OWASP-AGENTIC-V1.1-COVERAGE.md](docs/OWASP-AGENTIC-V1.1-COVERAGE.md) |
| Canonical coverage mapping (source of truth) | [docs/coverage/owasp-agentic-v1.1.yaml](docs/coverage/owasp-agentic-v1.1.yaml) |
| Release history & known gaps | [ROADMAP.md](ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) |
| E1-E5 Evidence Class Taxonomy (canonical) | [docs/EVIDENCE-CLASS-TAXONOMY.md](docs/EVIDENCE-CLASS-TAXONOMY.md) |
| Reproducing this harness (and disagreeing with it) | [docs/REPRODUCING.md](docs/REPRODUCING.md) |
| The one external reproduction, written up (E2/I1 for the fixture corpus) | [docs/RCL-CROSS-IMPLEMENTATION-INTEROP.md](docs/RCL-CROSS-IMPLEMENTATION-INTEROP.md) |
| The acceptance criterion that does not require the mechanism (5 recorded instances) | [docs/VERIFICATION-DESIGN-DEFECT.md](docs/VERIFICATION-DESIGN-DEFECT.md) |
| Attestation registry (client, opt-in publishing) | [docs/attestation-registry.md](docs/attestation-registry.md) |
| Attestation registry server contract (self-hosted; no registry is operated by this project) | [docs/ATTESTATION-REGISTRY-SERVER-CONTRACT.md](docs/ATTESTATION-REGISTRY-SERVER-CONTRACT.md) |
| AIUC-1 Evidence Field Guide (external, not version-pinned) | [msaleme.github.io/aiuc1-readiness](https://msaleme.github.io/aiuc1-readiness/) |
| AIUC-1 Crosswalk | [docs/AIUC1-CROSSWALK.md](docs/AIUC1-CROSSWALK.md) |
| Advanced Capabilities | [docs/ADVANCED.md](docs/ADVANCED.md) |
| MCP Server | [docs/mcp-server.md](docs/mcp-server.md) |
| CI/CD GitHub Action | [docs/github-action.md](docs/github-action.md) |
| Payment Attack Taxonomy | [docs/PAYMENT-ATTACK-TAXONOMY.md](docs/PAYMENT-ATTACK-TAXONOMY.md) |
| Decision Governance Checklist | [docs/DECISION-GOVERNANCE-CHECKLIST.md](docs/DECISION-GOVERNANCE-CHECKLIST.md) |
| Decision Governance Benchmark Leaderboard | [benchmarks/LEADERBOARD.md](benchmarks/LEADERBOARD.md) |
| Related Work | [docs/RELATED-WORK.md](docs/RELATED-WORK.md) |
| Comparison (detailed) | [docs/COMPARISON.md](docs/COMPARISON.md) |
| Privacy & Telemetry | [docs/PRIVACY.md](docs/PRIVACY.md) |

---

## Roadmap

**Current: v4.17.0** (2026-08-30). Recent shipped work — v4.5 skill supply chain and governance
modification · v4.6–v4.9 payment-stack depth (AP2 mandate chain, UCP/ACP merchant journey, card-network
agentic tokens, settlement finality, Fireblocks x402) · v4.10 benchmark integrity · v4.11–v4.12
decision-governance corpus currency and provenance repair · **v4.13 OWASP Agentic v1.1 T1–T17 coverage
mapping and the human-in-the-loop harness** · v4.13.1 a correctness fix to that harness · v4.14.0
endpoint provenance · v4.16.0 three target shapes: a verdict must be able to be wrong AND to be right · v4.17.0 eight modules could not tell a refusal from a compliance · **v4.18.0 INCONCLUSIVE became a field, and the read-list emptied** · v4.15.0 unserviced requests are no longer recorded as passes (see
[CHANGELOG.md](CHANGELOG.md)).

The release carries **608** tests; `main` is at **608**. They agree at v4.18.0 because the tag was cut
from `main` with no test added or removed since. They do not always agree: at v4.15.0 the release carried
603 while `main` was at 608, the difference being MAG-019, MEM-011, MEM-012, X4-056 and X4-057, all
landing after the tag. Both numbers were correct for their own ref, which is why
`scripts/check_public_metadata.py` compares public claims against the release rather than against `main`,
and why `docs/release-claims.json` pins the release count to a commit where re-running the command
reproduces it.

**Next — Standards & Evidence.** Reproducible settlement-time payment evidence, a methodology paper,
and the attestation/evidence schema submitted to a standards venue. Coverage breadth and test count are
explicitly *not* goals. Full detail and the anti-goals in [ROADMAP.md](ROADMAP.md).

---

## Used By

| Who | Use Case |
|-----|----------|
| [FransDevelopment / Open Agent Trust Registry](https://github.com/FransDevelopment/open-agent-trust-registry) | OATR SDK v1.2.0 test fixtures (X4-021 through X4-030) -- Ed25519 attestation verification |

### Independent reproduction

The only external check this project has received. [@VrtxOmega](https://github.com/VrtxOmega), in
[veritas-agent-trust-lab](https://github.com/VrtxOmega/veritas-agent-trust-lab), wrote a **separate Node
verifier** for the portable receipt-claim oracle fixtures and ran it against a pinned commit and fixture
hash, matching all 11 RCL results including both acceptance controls — so it did not pass by rejecting
everything. Reported in [#304](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/304);
named here with their consent, granted 2026-08-31. The result is written up in
[docs/RCL-CROSS-IMPLEMENTATION-INTEROP.md](docs/RCL-CROSS-IMPLEMENTATION-INTEROP.md),
with their own report and verifier runner linked as the primary artifacts.

The exchange also produced two corrections to this repository: `signature_algorithm` now names the
actual encoding and states plainly that it is **not** RFC 8785 JCS, and `coverage_gaps` now declares
that freshness is exercised only in the stale direction. Both are in `fixtures/rcl/`.

It is a reproduction of a pinned artifact by one external party, submitted as a report and explicitly
**not** as a contribution, endorsement, certification, or adoption. It is not a substitute for
independent review of the harness as a whole, which this project still does not have.

**"A third independent implementation is worth more to this corpus than any additional vector."**
That is [`fixtures/rcl/CONFORMANCE.md`](fixtures/rcl/CONFORMANCE.md) §7, verbatim, and it is not
modesty. Two implementations agreeing establishes that they share a reading; only a third can tell
you whether that reading is the contract or a coincidence.

The bar is lower than it sounds. The corpus is eleven vectors, one fixture file, and a pinned hash;
the run above was a single Node script written against the published format.
[`docs/REPRODUCING.md`](docs/REPRODUCING.md) has the pin, the canonical byte basis that is the most
common reason a correct implementation computes a different digest, and the table of what does and
does not count as independent. §7 of `CONFORMANCE.md` adds the one rule that decides whether your
result counts at all: **write the verifier from the published contract, not from
`protocol_tests/receipt_claim_harness.py`.** Reading our implementation first turns an independent
result into a port, and the value is entirely in the independence. File it with the
[reproduction report template](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/new?template=reproduction-report.yml).

**A result that contradicts ours gets published too.** #304 is the precedent for that as well: it
matched 11 of 11 and *still* surfaced two defects in our own contract description, both corrected
above. Disagreement is the more useful outcome, not the awkward one — a reproduction that only
agrees may just mean two implementations share the same wrong assumption.

*Using the harness? Open a PR to add yourself, or tag us in your project.*

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines, [SECURITY_POLICY.md](SECURITY_POLICY.md) for security policy, and [CONTRIBUTION_REVIEW_CHECKLIST.md](CONTRIBUTION_REVIEW_CHECKLIST.md) for the PR checklist.

## Citation

If you cite this work in research:

> Saleme, M. K. (2026). *Agent Security Harness* — multi-protocol agent security testing framework. ORCID: [0009-0003-6736-1900](https://orcid.org/0009-0003-6736-1900). https://github.com/msaleme/red-team-blue-team-agent-fabric

Related Zenodo preprints are listed in full under [Research](#research); that table is the single
source of truth for DOIs in this repository. Do not cite a DOI for this work that does not appear there.

---

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
