# Attestation Registry

> ## Status: the public registry is not running
>
> **Verified 2026-08-04.** Every `registry.agentsecurity.dev` URL in this document
> returns HTTP 404 — the publish endpoint, the verify endpoint, and the badge
> endpoint. The domain resolves; no registry service is answering on it.
>
> `agent-security publish` and `agent-security verify` are registered commands and
> will run. They will not reach a registry. Do not rely on the publish flow, the
> badge, or the AgentCard reference below.
>
> **The only supported path today is a self-hosted registry** via
> `AGENT_SECURITY_REGISTRY_URL`. See [Self-Hosted Registry](#self-hosted-registry).
> The server contract is being specified in #333.
>
> Everything below describes a client that is implemented and a server that is not.

## What It Is

The Attestation Registry is a **voluntary, opt-in** public directory where you can
record that your MCP server, A2A agent, or payment endpoint was tested with Agent
Security Harness, and what the run returned.

**Nothing is ever published automatically.** You must explicitly run the publish command.

---

## Why Use It

- **Disclosure** - Show users and integrators that your agent or server was tested with this harness, and what the run returned.
- **AgentCard enhancement** - Reference your attestation in A2A Agent Cards for machine-readable disclosure
- **CI/CD gating** - Gate deployments on a recorded harness run
- **Compliance evidence** - Attach attestation IDs to audit documentation, bounded by the claim discipline below

### What an attestation does not establish

You ran this harness against your own target. Under the
[Evidence Class Taxonomy](EVIDENCE-CLASS-TAXONOMY.md) that result is **I0**:
self-authored, because the same party produced the oracle and the system under
test. Publishing it to a registry records that you published it. It does not make
it independent, and a registry entry is not a review, a certification, or a
conformance claim.

Describe an attestation as *tested with*, not as *independently verified*.

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

> **Not usable against the public endpoint**, which returns 404. These commands
> work against a self-hosted registry set via `AGENT_SECURITY_REGISTRY_URL`.

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

> **Nothing can currently be listed, so nothing needs deleting.** No public registry
> is running, and no attestation submitted through the default endpoint was stored.
> The route below describes the intended policy for a registry that exists.

Your attestation, your decision. To delete:

1. **Email:** Send a deletion request to trusted@synapseops.com with your registry ID
2. **API:** `DELETE https://registry.agentsecurity.dev/v1/attestation/<registry_id>` (requires signature from your original signing key)

Deletion is intended to be permanent and immediate. A self-hosted registry sets its
own retention policy; this document does not bind it.

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

> **Not usable.** The badge endpoint returns 404, so every image below renders
> broken. Kept as the intended format, not as working embed code.
>
> When a registry does exist, the badge text must not claim independence. A badge
> reading "Verified by Agent Security Harness" on a self-run result would present
> I0 evidence as third-party verification, which is the failure the taxonomy exists
> to prevent. "Tested with Agent Security Harness" is the accurate wording.

After publishing, you would receive badge embed code:

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
- You can rotate keys, but previously signed attestations will remain linked to the original key
- A registry is expected to store your public key fingerprint to verify updates and deletions. No public registry currently does, because none is running.

The signing and stripping behaviour is client-side and works today. It is the part
of this document you can rely on.

---

## Self-Hosted Registry

**This is the only supported deployment.** Point the client at a server you control:

```bash
export AGENT_SECURITY_REGISTRY_URL=https://your-internal-registry.example.com/v1/attestation
```

The client validates that the URL is `https://`, or `http://` for `localhost`,
`127.0.0.1`, and `::1` during development.

The server contract is not yet published. #333 tracks specifying it, including what
is submitted, what a submission establishes, and how a third party verifies an entry
without trusting the registry operator. Until that lands, a self-hosted server has to
be written against `protocol_tests/attestation_registry.py` directly.
