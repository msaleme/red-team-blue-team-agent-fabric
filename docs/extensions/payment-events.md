# Operator-Facing Payment Event Schema

_Last updated: 2026-03-27_

The x402 harness emits operator-facing events so humans (or automated policy engines) see the same trust context the agent used **before** funds move. The event stream is intentionally small and composable with the `agent-trust` extension.

## Event pipeline
1. **`payment_required`** – raised immediately after the x402 endpoint returns a valid challenge **and** the trust graph clears (identity, behavioral score, wallet attestation).
2. **`payment_approval`** – optional human or policy-engine approval. If no approval arrives for the correlation ID, the harness never submits the `PaymentPayload`.
3. **`payment_receipt`** – emitted after settlement completes. Freezes the exact trust snapshot + wallet attestation used at approval time.

## `payment_required`
| Field | Type | Description |
| --- | --- | --- |
| `event` | string | Literal `"payment_required"`. |
| `correlation_id` | string | Unique ID shared across all three events. |
| `amount` | object | `{ "value": "2500000", "currency": "USDC", "network": "base-sepolia" }` – mirrors the x402 challenge. |
| `payee_endpoint` | string | URL being paid (after redirects). |
| `agent_did` | string | DID from the trust snapshot (`extensions.agent-trust.agent_did`). |
| `trust_snapshot` | object | The exact `agent-trust` payload (agent DID, trust score, breakdown, attestation metadata). |
| `wallet_trust` | object | Optional attestation summary from Insumer/other wallet-proof providers. Includes attestation ID, signing key (`kid`), chain coverage, and pass/fail counts. |
| `attestation_ref` | string | Reference to the OATR issuer + manifest version (e.g., `oatr:FransDevelopment:v1.2.1`). |
| `challenge_headers` | object | Raw `X-Payment-*` headers returned by the endpoint (audit trail). |

### Example
```json
{
  "event": "payment_required",
  "correlation_id": "tx_abc123",
  "timestamp": "2026-03-27T10:58:12Z",
  "amount": {
    "value": "2500000",
    "currency": "USDC",
    "network": "base-sepolia"
  },
  "payee_endpoint": "https://claw-net.org/api/search",
  "agent_did": "did:agentnexus:z84Dp...",
  "trust_snapshot": {
    "agent_did": "did:agentnexus:z84Dp...",
    "trust_score": 82,
    "score_breakdown": {
      "action_reliability": 0.91,
      "selector_stability": 0.78,
      "interaction_count": 214,
      "confidence": 0.93
    },
    "attestation": "HEADER.PAYLOAD.SIGNATURE",
    "attestation_issuer": "agentinternetruntime"
  },
  "wallet_trust": {
    "id": "TRST-59EAB",
    "total_checks": 36,
    "passed": 18,
    "dimensions_with_activity": 3,
    "signed": true,
    "kid": "insumer-attest-v1"
  },
  "attestation_ref": "oatr:FransDevelopment:v1.2.1",
  "challenge_headers": {
    "x-payment-amount": "2500000",
    "x-payment-currency": "USDC",
    "x-payment-recipient": "0xfeed...",
    "x-payment-network": "base-sepolia"
  }
}
```

## `payment_approval`
| Field | Type | Description |
| --- | --- | --- |
| `event` | string | `"payment_approval"`. |
| `correlation_id` | string | Matches the prior `payment_required`. |
| `approved` | boolean | `true` to approve, `false` to veto. |
| `approved_by` | string | `operator`, `policy-engine`, or other identifier. |
| `notes` | string (optional) | Free-form reason, ticket number, etc. |
| `expires_at` | string (optional) | ISO timestamp after which approval is invalid (forces re-check). |

### Example
```json
{
  "event": "payment_approval",
  "correlation_id": "tx_abc123",
  "timestamp": "2026-03-27T10:58:25Z",
  "approved": true,
  "approved_by": "operator",
  "notes": "Under $1, approve automatically"
}
```

## `payment_receipt`
| Field | Type | Description |
| --- | --- | --- |
| `event` | string | `"payment_receipt"`. |
| `correlation_id` | string | Same ID for traceability. |
| `payment_hash` | string | Facilitator receipt or on-chain reference. |
| `trust_score_at_payment` | integer | Copy of the trust score used at approval time. |
| `wallet_trust` | object | Snapshot of the wallet attestation that cleared the payment. |
| `challenge_headers` | object | Final challenge that was satisfied (if it changed between approval and settlement). |
| `status` | string | `"succeeded"`, `"failed"`, or `"cancelled"`. |

### Example
```json
{
  "event": "payment_receipt",
  "correlation_id": "tx_abc123",
  "timestamp": "2026-03-27T10:58:31Z",
  "payment_hash": "pay_0x934b...",
  "status": "succeeded",
  "trust_score_at_payment": 82,
  "wallet_trust": {
    "id": "TRST-59EAB",
    "signed": true,
    "kid": "insumer-attest-v1"
  },
  "challenge_headers": {
    "x-payment-amount": "2500000",
    "x-payment-network": "base-sepolia"
  }
}
```

## Implementation notes
- **Correlation IDs** – the harness generates UUIDv4 values and persists them alongside the JSON reports so events can be linked back to specific findings.
- **Transport** – events can be emitted via stdout, Kafka, or HTTP webhook. The schema is transport-agnostic JSON.
- **Policy hooks** – teams can plug a rules engine between `payment_required` and `payment_approval` to codify spend limits (`trust_score >= 80`, `amount_usd < 5`, wallet attestation signature present, etc.).
- **Audit trail** – `payment_receipt` freezes every field auditors need: DID, trust score, attestation reference, wallet proof, and the facilitator receipt hash.

These events, combined with the `agent-trust` contract, ensure the machine layer (autonomous agent) and operator layer share the same context before money moves.
