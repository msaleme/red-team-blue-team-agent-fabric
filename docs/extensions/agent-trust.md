# x402 `agent-trust` Extension – Harness Contract

_Last updated: 2026-03-27_

The `agent-trust` extension lets the Red Team / Blue Team Agent Fabric measure payment safety signals when exercising the x402 rail. When the harness triggers a `payment_required` action, it looks for an optional `extensions.agent-trust` object in the event payload. This object communicates the agent’s identity, behavioral score, and (optionally) the Operator Attestation Registry (OATR) attestation chain used to vouch for the agent.

## Required fields
| Field | Type | Description |
| --- | --- | --- |
| `agent_did` | `string` | The agent’s DID. Must match the DID used elsewhere in the payment record and resolve to at least one Ed25519 verification key. |
| `trust_score` | `integer` (0-100) | Composite behavioral score (higher ⇒ safer). Harness uses it to rank-payments and drive policy branches. |

## Optional fields
| Field | Type | Description |
| --- | --- | --- |
| `score_breakdown` | `object` | Component metrics that explain the composite score. Recognized keys today: `action_reliability`, `selector_stability`, `interaction_count`, `confidence`. Additional vendor-specific keys are allowed. |
| `attestation` | `string` | Compact JWT issued by an OATR-registered operator. Claims should include `iss`, `sub`, `aud`, `scope`, `constraints`, `iat`, `exp`. |
| `attestation_issuer` | `string` | Shortcut identifier for the OATR issuer (matches `issuer_id` inside the manifest). Used to speed up manifest lookups without decoding the JWT. |

If the attestation fields are present, the harness performs the full OATR verification chain: resolve manifest → find issuer → check key status → validate JWT signature → enforce scope, constraints, expiry, and intended audience.

## JSON schema fragment
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://red-team-blue-team-agent-fabric.dev/schemas/extensions/agent-trust.json",
  "type": "object",
  "required": ["agent_did", "trust_score"],
  "properties": {
    "agent_did": {
      "type": "string",
      "pattern": "^did:[a-z0-9]+:.+$"
    },
    "trust_score": {
      "type": "integer",
      "minimum": 0,
      "maximum": 100
    },
    "score_breakdown": {
      "type": "object",
      "additionalProperties": {
        "type": ["number", "integer"]
      },
      "properties": {
        "action_reliability": {"type": "number", "minimum": 0, "maximum": 1},
        "selector_stability": {"type": "number", "minimum": 0, "maximum": 1},
        "interaction_count": {"type": "integer", "minimum": 0},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1}
      }
    },
    "attestation": {"type": "string"},
    "attestation_issuer": {"type": "string"}
  },
  "additionalProperties": true
}
```

## Sample payload
```json
{
  "agent_did": "did:key:z6MkpaCcbS7mNgSTfmvAqb2E2JtLX73Yb2pcZvLwRY2d2ZNG",
  "trust_score": 82,
  "score_breakdown": {
    "action_reliability": 0.91,
    "selector_stability": 0.78,
    "interaction_count": 214,
    "confidence": 0.93
  },
  "attestation": "HEADER.PAYLOAD.SIGNATURE",
  "attestation_issuer": "agentinternetruntime"
}
```
The fixtures added in `protocol_tests/fixtures/oatr` mirror this structure so test harnesses can replay the scenarios referenced in the `agent-trust` GitHub discussion.

## DID method support
- **`did:key`** – supported out of the box. No external network calls required.
- **`did:web`** – supported: the harness fetches `https://<domain>/.well-known/did.json` and validates the returned document.
- **Other methods (e.g., `did:agentnexus`)** – allowed by schema (`^did:[a-z]+:.+$`). Until native resolvers are published, the recommended approach is to provide a `did:web` alias that points at the same key material. Custom resolver hooks (`--did-resolver`) are planned so operators can register additional DID methods without modifying the harness.

When using custom DIDs, ensure the corresponding DID Document exposes at least one Ed25519 verification method and (optionally) an X25519 method for key agreement. Service entries should include `type: "x402"` with the target endpoint URL.

## Versioning and metadata
Include the `agent-trust` object inside the `extensions` block:
```json
{
  "type": "payment_required",
  "payment": { "amount": "2500000", "currency": "USDC" },
  "extensions": {
    "agent-trust": {
      "agent_did": "did:key:z6Mk...",
      "trust_score": 82
    }
  }
}
```
If the extension is absent, the harness falls back to signature-only validation and records that no trust snapshot was provided.

Questions or change requests: open an issue tagged `extension:agent-trust` or comment on coinbase/x402#1777.
