# Attestation Registry

## What It Is

The Attestation Registry is a **voluntary, opt-in** public directory where you can prove your MCP server, A2A agent, or payment endpoint passed security testing with Agent Security Harness.

Think of it as a "Verified by Agent Security Harness" badge - a trust signal you can display in your AgentCard, README, or documentation.

**Nothing is ever published automatically.** You must explicitly run the publish command.

---

## Why Use It

- **Trust signal** - Show users and integrators that your agent/server has been independently security-tested
- **AgentCard enhancement** - Reference your attestation in A2A Agent Cards for machine-readable trust
- **CI/CD gating** - Prove that deployments pass security testing before release
- **Compliance evidence** - Attach attestation IDs to audit documentation

---

## How to Publish

### CLI

```bash
# Run your tests first
agent-security test mcp --url http://localhost:8080/mcp --output report.json

# Publish to the registry (interactive, confirms before sending)
agent-security publish --attestation report.json --server-name "my-mcp-server"

# With optional contact
agent-security publish --attestation report.json --server-name "my-mcp-server" --contact you@example.com
```

### Python API

```python
from protocol_tests.attestation_registry import publish_attestation
import json

report = json.load(open("report.json"))
result = publish_attestation(
    report=report,
    server_name="my-mcp-server",
    contact="you@example.com",  # optional
)

print(f"Registry URL: {result['registry_url']}")
print(f"Badge markdown: {result['badge_markdown']}")
```

---

## How to Verify

### CLI

```bash
agent-security verify --attestation-id <registry_id>
```

### Python API

```python
from protocol_tests.attestation_registry import verify_attestation

result = verify_attestation("abc123def456")
print(result)
```

### Web

Visit: `https://registry.agentsecurity.dev/v1/attestation/<registry_id>`

---

## How to Delete Your Listing

Your attestation, your decision. To delete:

1. **Email:** Send a deletion request to trusted@synapseops.com with your registry ID
2. **API:** `DELETE https://registry.agentsecurity.dev/v1/attestation/<registry_id>` (requires signature from your original signing key)

Deletion is permanent and immediate.

---

## What's Included vs. Stripped

When you publish, the following fields are **automatically stripped** from your report before it leaves your machine:

### Stripped (NEVER sent)

| Field | Why |
|-------|-----|
| `request_sent` | Contains actual HTTP requests to your server |
| `response_received` | Contains your server's responses |
| `raw_request` / `raw_response` | Same as above, alternate format |
| `headers` | May contain auth tokens, API keys |
| `auth_token` / `api_key` | Credentials |
| `target_url` / `url` / `endpoint` | Your infrastructure URLs |

### Included (published)

| Field | Why |
|-------|-----|
| Server name (you provide) | Identifies what was tested |
| Test module name | Which harness ran (e.g., "mcp", "a2a") |
| Test names | Which security tests were executed |
| Pass/fail status per test | The actual results |
| Timestamp | When testing occurred |
| Harness version | Which version produced the results |
| Overall grade | Summary assessment |

You can inspect the exact stripped output before publishing:

```python
from protocol_tests.attestation_registry import strip_sensitive_fields
import json

report = json.load(open("report.json"))
cleaned = strip_sensitive_fields(report)
print(json.dumps(cleaned, indent=2))
```

---

## Badge / Embed Code

After publishing, you receive badge embed code:

### Markdown (for README)

```markdown
[![Verified by Agent Security Harness](https://registry.agentsecurity.dev/badge/<id>)](https://registry.agentsecurity.dev/v1/attestation/<id>)
```

### HTML

```html
<a href="https://registry.agentsecurity.dev/v1/attestation/<id>">
  <img src="https://registry.agentsecurity.dev/badge/<id>" alt="Verified by Agent Security Harness" />
</a>
```

### AgentCard Reference

```json
{
  "security_attestation": {
    "framework": "agent-security-harness",
    "registry_url": "https://registry.agentsecurity.dev/v1/attestation/<id>",
    "verification_hash": "<sha256>"
  }
}
```

---

## Signing & Verification

Attestations are signed with an Ed25519 key generated on first use and stored locally at `~/.agent-security/signing_key.pem`. The public key is at `~/.agent-security/signing_key_pub.pem`.

- The private key never leaves your machine
- The registry stores your public key fingerprint to verify updates and deletions
- You can rotate keys, but previously signed attestations will remain linked to the original key

---

## Self-Hosted Registry

For organizations running their own registry:

```bash
export AGENT_SECURITY_REGISTRY_URL=https://your-internal-registry.example.com/v1/attestation
```

The registry API is a simple REST interface. Documentation for self-hosting the server component is coming in a future release.
