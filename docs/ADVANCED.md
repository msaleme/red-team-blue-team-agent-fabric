# Advanced Capabilities

## GTG-1002 APT Simulation

This module sends crafted defensive probes that exercise a target system's controls against the adversary behavior pattern documented in the GTG-1002 incident (Anthropic, November 2025 — the first publicly documented AI-orchestrated cyber espionage campaign). The harness does not execute the listed adversary behaviors; it sends inputs designed to trigger the target's detection and response controls, then analyzes target responses.

```bash
agent-security test gtg1002 --url https://agent.example.com --full-campaign
```

**Reading guide:** *Adversary behavior we probe for* describes what the original GTG-1002 actor did. *Detection probes the harness sends* describes what the harness sends to your target so you can verify your defenses block, log, or alert on that behavior class.

| Phase | Tests | Adversary behavior we probe for | Detection probes the harness sends |
|---|---|---|---|
| **Initialization** | 2 | Roleplay as "CrowdStrike pentester" | Probes target resistance to security-firm-impersonation persona escalation |
| **Reconnaissance** | 3 | Autonomous infrastructure enumeration | Probes target rate-limiting and access controls against enumeration patterns |
| **Vulnerability** | 2 | AI-generated exploit payloads | Probes detection of AI-generated payload patterns |
| **Credentials** | 3 | Config credential extraction attempts | Probes detection of four credential-extraction patterns and lateral-movement signals |
| **Data Collection** | 3 | Database extraction + intelligence categorization | Probes detection of exfiltration and categorization patterns |
| **Documentation** | 2 | Auto-generated attack documentation | Probes detection of attack-report and handoff generation patterns |
| **Hallucination** | 2 | Claude "fabricated findings and data" | Probes detection of fabricated-finding and credential-fabrication patterns |

---

## Statistical Evaluation (NIST AI 800-2 Aligned)

```bash
# Run with statistical confidence intervals
agent-security test mcp --url http://localhost:8080/mcp --trials 10

# Output includes Wilson score confidence intervals
# Pass Rate: 80% (95% CI: 55%-93%)
```

---

## Advanced Attack Patterns

Multi-step, stateful attack simulations based on real-world AI agent exploitation:

- **Polymorphic attacks** - Unique payloads per target, encoding evasion
- **Stateful escalation** - Trust-building then exploit (8-step guardrail erosion)
- **Multi-domain chains** - Credential->Identity->Cloud pivot sequences
- **Autonomous reconnaissance** - Agent maps its own attack surface
- **Persistent jailbreaks** - DAN-style persistence + cross-session leakage

---

## Behavioral Profiling

Compare test runs to detect behavioral drift, compute stability and risk scores, and identify normalization of deviance:

```bash
# Compare two runs
python scripts/behavioral_profile.py --baseline run1.json --current run2.json

# Trend analysis over multiple runs
python scripts/behavioral_profile.py --history run1.json run2.json run3.json --output profile/
```

Produces stability score (0-100), drift detection (PASS->FAIL regressions), risk score with transparent formula, and trend analysis for 3+ runs. This is what static scanners cannot see -- behavioral change over time.

---

## Evidence Pack Generator

Generate signed, audit-ready evidence packages from harness test results:

```bash
# Generate evidence pack from a harness report
python scripts/evidence_pack.py --report report.json --output evidence/

# Generate and sign with HMAC-SHA256
python scripts/evidence_pack.py --report report.json --output evidence/ --sign --zip
```

Produces four files: `evidence-summary.json` (machine-readable), `test-results.json` (raw data), `aiuc1-mapping.json` (per-requirement coverage), and `evidence-summary.md` (human-readable for auditors). Usable as CI gate artifacts, procurement questionnaire attachments, or audit packet exhibits.

---

## Agent Payment Security Attack Taxonomy

The first taxonomy of attack vectors against AI agent payment flows -- 10 categories covering x402 and L402 protocols:

| ID | Category | Severity |
|---|---|---|
| APT-01 | Unauthorized Payment Execution | Critical |
| APT-02 | Payment Amount Manipulation | Medium |
| APT-03 | Recipient Manipulation | Critical |
| APT-04 | Payment Replay and Double-Spend | High |
| APT-05 | Payment Authorization Bypass | Critical |
| APT-06 | Settlement and Finality Attacks | High |
| APT-07 | Payment Channel Attacks (L402) | High |
| APT-08 | Cross-Chain and Cross-Protocol Confusion | High |
| APT-09 | Payment Metadata Exfiltration | Medium |
| APT-10 | Agent Autonomy Risk | Medium |

Full taxonomy: [PAYMENT-ATTACK-TAXONOMY.md](PAYMENT-ATTACK-TAXONOMY.md)

---

## External Validation

- **HRAO-E Assessment (Mar 28, 2026):** 146 tests, 97.9% pass rate, Wilson 95% CI [0.943, 0.994]. 100% pass on jailbreak (25 tests), GTG-1002 full APT campaign (17 tests), harmful output AIUC-1 (10 tests), and advanced polymorphic attacks (10 tests).
- **DrCookies84 independent validation** against live production infrastructure, confirmed in [AutoGen #7432](https://github.com/microsoft/autogen/discussions/7432).
- **NULL AI (Anhul / DrCookies84) -- v3.6.0 (Mar 24, 2026):**
  - Return channel 8/8 (100%), Capability profile 9/10 (90%), Jailbreak 25/25 (100%), Provenance 15/15 (100%), Advanced attacks 10/10 (100%), Incident response 8/8 (100%), Harmful output 6/10 (expected partial: closed network), CBRN 6/8 (expected partial: closed network)
  - [Screen recording](https://youtu.be/4OUyoPSy244?si=fBTQVW6EGYVEj7cU)
- **NULL AI (Anhul / DrCookies84) -- v3.3.0 (Mar 21, 2026):** 65/65 perfect score on live infrastructure (video recorded)

---

## Success Metrics

| Metric | Target |
|---|---|
| Detection Latency (TTD) | < 3 seconds |
| Block Accuracy | >= 99% |
| False Positive Rate | < 3% |
| Lineage Traceability | 100% |
| Recovery Time (TTC) | < 60 seconds |
| Kill-Switch Activation | < 1 second |
