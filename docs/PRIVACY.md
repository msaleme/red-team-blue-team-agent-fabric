# Privacy Policy

## Our Promise

We built a security testing tool. We understand the irony of a security tool that phones home.

Here's exactly how we handle your trust.

This framework runs entirely on your machine. Every test, every result, every URL you scan stays local. The only thing that leaves your machine is a small, anonymous usage ping - and you can turn that off in 10 seconds.

We're security professionals building for security professionals. We know that vague privacy policies destroy credibility. So this one is specific, auditable, and backed by open source code you can grep yourself.

---

## What We Collect (Anonymous Usage Stats)

When telemetry is enabled (opt-IN, off by default), we collect:

| Field | Example | Why |
|-------|---------|-----|
| Harness version | `3.8.0` | Know which versions are in use, prioritize backports |
| Module name | `mcp` | Know which harnesses matter most to users |
| Test count | `13` | Understand typical workload size |
| Passed count | `11` | Identify modules with high failure rates (may indicate bugs in our tests) |
| Failed count | `2` | Same as above |
| OS | `linux` | Platform-specific bug triage |
| Python version | `3.12` | Know which Python versions to keep supporting |
| Timestamp | `2026-03-28T00:00:00Z` | Understand usage patterns (weekday vs weekend, not time-of-day) |

That's it. Eight fields. Flat JSON. No nesting, no extensibility, no "other" bucket.

You can see the exact payload in code:

```python
from protocol_tests.telemetry import telemetry_payload_example
print(telemetry_payload_example())
```

---

## What We NEVER Collect

- **Target URLs** - We never see what you're scanning
- **Test results or details** - Only pass/fail counts, never which tests failed or why
- **Attestation report contents** - Reports stay on your machine unless you explicitly publish them
- **API keys or credentials** - We never touch your `.env`, auth tokens, or secrets
- **IP addresses** - Hashed at the edge before any processing. We cannot reverse them.
- **Request/response payloads** - The actual HTTP traffic from tests never leaves your machine
- **Hostnames, paths, or any part of your infrastructure topology**

---

## How to Opt In

Telemetry is **OFF by default**. To enable anonymous usage statistics:

### 1. Environment variable (fastest)

```bash
export AGENT_SECURITY_TELEMETRY=on
```

Add to your `.bashrc`, `.zshrc`, or CI environment.

### 2. CLI command

```bash
agent-security config --telemetry
```

This writes `{"enabled": true}` to `~/.agent-security/telemetry.json`.

### How to Opt Out Again

If you previously opted in:

```bash
export AGENT_SECURITY_TELEMETRY=off
# or
agent-security config --no-telemetry
# or
rm -rf ~/.agent-security/
```

Any of these will disable telemetry completely.

---

## Attestation Registry (Opt-IN)

The attestation registry is a **voluntary, opt-in** public directory where you can publish proof that your server passed security testing.

- **You must explicitly run a publish command.** Nothing is ever published automatically.
- **You control what's shared.** Sensitive fields (request/response payloads) are stripped before submission.
- **You can delete your listing** at any time.
- **You own your data.** We store only what you explicitly submit.

The registry exists so teams can display a "Verified by Agent Security Harness" badge in their AgentCards, READMEs, and documentation. It's a trust signal, not a requirement.

See [attestation-registry.md](attestation-registry.md) for full details.

---

## Enterprise Engagements

For enterprise and consulting engagements:

- All work is contract-based with explicit scope
- NDA available and expected for sensitive environments
- Test artifacts retained for 30 days maximum, then permanently deleted
- No telemetry is collected during enterprise engagements unless explicitly agreed
- Dedicated infrastructure, no shared analytics

---

## Verification

This is open source. Audit us:

```bash
# Find every outbound network call in the test modules
grep -r 'requests.post\|urllib\|httpx\|socket' protocol_tests/

# Read the telemetry module yourself (it's ~80 lines)
cat protocol_tests/telemetry.py

# See exactly what would be sent
python -c "from protocol_tests.telemetry import telemetry_payload_example; print(telemetry_payload_example())"
```

If you find something that doesn't match this policy, open an issue. We'll fix it or explain it within 48 hours.

---

## Data Infrastructure

- **Self-hosted analytics.** No Google Analytics, no third-party trackers, no CDN-based collection.
- **Data region:** US-Central (configurable for self-hosted deployments).
- **Retention:**
  - Anonymous usage stats: 90 days, then permanently deleted
  - Attestation registry: Permanent, but user-controlled (you can delete your listing anytime)
- **Telemetry endpoint:** Configurable via environment variable for organizations running their own analytics infrastructure.

---

## Changes

We will announce any changes to this privacy policy through:

1. GitHub Discussions (pinned post)
2. CHANGELOG.md entry
3. README.md notice

No silent changes. Ever. The git history of this file is your audit trail.

---

## Legal Basis (GDPR)

With telemetry set to opt-in by default, the legal basis for processing is **consent**. You explicitly choose to enable telemetry. You can withdraw consent at any time by disabling telemetry (see "How to Opt Out Again" above).

### Data Subject Rights

Under GDPR, you have the right to:

- **Access** - Request a copy of any data we hold about you
- **Deletion** - Request permanent deletion of your data
- **Portability** - Receive your data in a structured, machine-readable format
- **Rectification** - Request correction of inaccurate data
- **Restriction** - Request that we limit processing of your data

Since telemetry is anonymous (no IP addresses retained, no user identifiers), we may not be able to identify your specific data. However, we will make best efforts to honor any request.

To exercise these rights, contact us at **trusted@synapseops.com**. We respond within 30 days.

### Data Controller

**Signal Ops / Michael K. Saleme**
Contact for data protection inquiries: **trusted@synapseops.com**

---

## CCPA Compliance (California)

- **We do not sell personal information.** We never have and never will.
- **We do not share personal information** with third parties for their marketing purposes.
- **Right to know:** You may request what data we collect (see table above - that's all of it).
- **Right to delete:** Contact us to request deletion.
- **Non-discrimination:** We will not discriminate against you for exercising your CCPA rights.

---

## Contact

Questions, concerns, or audit requests:

**trusted@synapseops.com**

We respond to privacy inquiries within 48 hours.
