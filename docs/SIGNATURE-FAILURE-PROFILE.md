# Signature-failure profile: which tests still mean something when identity is compromised

Agent systems rest identity on signatures: OAuth and JWT bearer tokens, A2A Agent Cards, AP2 mandates, card-network cryptograms, x402 payment authorizations. This page sorts existing tests by **what their control depends on**, so a reader can answer one question for a deployment:

> If an agent's credential is stolen, or a signature can be forged, which actions are still bounded?

**What this page does not claim.** It makes no claim that any cryptosystem is broken, or about post-quantum readiness or resistance to cryptanalysis. The harness tests authorization behaviour. It does not test cryptography. The page is a reading guide to existing results, not a new test, and it changes no verdict.

## Two different failures

They break different controls, so they are kept apart.

- **Stolen valid credential.** The attacker holds a real, correctly issued credential: a leaked token, a compromised agent key, a captured mandate. Signatures verify, because they are genuine.
- **Forged credential.** The attacker can mint new credentials that verify, because a signing key or the signature scheme itself is compromised. New identities, new token ids and new expiry claims all verify.

## Three classes

| Class | The control depends on | Stolen valid credential | Forged credential |
|---|---|---|---|
| **S: server-state enforced** | Records the server keeps and checks at execution: use counts, cumulative totals, seen ids, revocation status or epochs, approval records, declared policy | **Still bounds it** | Bounds it **only where the server checks the credential against its own issuance or status records**. A replay set does not stop a credential minted fresh |
| **C: credential-integrity dependent** | Claims carried inside a signed object: holder key, audience, expiry, network, hash links between signed objects | Mostly still bounds it, because the claims are genuine and scoped | **Void.** A forger writes whatever claims pass |
| **M: mixed** | A state check guarding a cryptographic value | The state half bounds replay of a captured value | The state half survives; the cryptographic half does not |

Each classification below comes from the test's own definition in its module, at `main` when this page was written. It is a reading of what the control checks, not a new measurement.

## Class S: server-state enforced

| Test | What the server checks |
|---|---|
| `APB-001` Approval Bound to Its Arguments | The approval record is keyed to the exact arguments; the oracle is what the runtime executed |
| `APB-002` Single-Use Approval Executes Once | An execution record shown append-only; a second call does not execute |
| `APB-003` Declared Deny Rule Enforced at Execution | Declared policy consulted at execution, even over an approval |
| `AP2-011` Payment Mandate Replay (jti) | A set of seen `jti` values |
| `AP2-013` Double-Spend on Open Mandate | Use state of one open mandate |
| `CTK-004` Cumulative Velocity Cap | A cumulative total across transactions |
| `CTK-008` Token Revocation / Suspension | Token status, checked even when the token is otherwise well-formed |
| `DCA-005` Replayed Effect Request | One effect per request (the effect counter is the assertion) |
| `DCA-007` Pass Used After Revocation Epoch | The issuer's revocation epoch, which voids passes already issued |
| `DCA-008` Tool Acts Under Ambient Credentials | The tool refuses to act on its own authority when no chain is presented |
| `CR-004` Capability honoured after revocation | Revocation shown to take effect, with a matched pair that proves the capability worked first |
| `MEM-013` Revoked Policy Still Presented As In Force | A revoked record is not returned |
| `FB-012` Velocity / Window Budget Limit | A window budget across individually legal payments |
| `FB-014` Batch Voucher Replay / Monotonicity | A seen-nonce set and a monotonic cumulative amount |
| `X4-045` Replay Same Payment Hash | Deduplication of a payment hash |
| `X4-057` Delegated Allowance Overdraft via Verify/Settle Race | Allowance accounting across concurrent verify and settle |

`FB-013` (Approval Quorum Above Threshold) is class S for counting: distinct, eligible, bound approvers. But **who an approver is** still rests on how approvers authenticate. A forger who can mint approver credentials can mint a quorum. And no current test checks that the requester is excluded from approving its own request: that is gap #739.

## Class C: credential-integrity dependent

| Test | The claim that a forger controls |
|---|---|
| `AP2-007` Mandate Chain Link (transaction_id) | The hash link between signed mandates |
| `AP2-008` Open-Mandate Substitution (sd_hash) | The `sd_hash` binding between signed mandates |
| `AP2-009` Agent Key Forgery (cnf mismatch) | Which key may sign, as stated in the `cnf` claim |
| `AP2-012` Expired Payment Mandate | The `exp` claim |
| `CTK-001` Agent Holder-Key Binding | The holder key bound into the token |
| `CTK-012` Cross-Network Token Substitution | The network carried by the credential |
| `DCA-004` Valid Pass Presented to the Wrong Tool Audience | The audience named in the pass |
| `DCA-006` Pass Used After Expiry | Expiry carried in the pass |
| `MCP-022` Bearer Token Audience Binding | The audience carried by the bearer token |
| `X4-025` Forged Attestation Injection (OATR) | Signature verification against a key registry, the integrity check itself |

These tests remain the right check against **a stolen credential used outside its scope**: the wrong audience, an expired pass, another network. They are not evidence of anything once signatures can be forged.

## Class M: mixed

| Test | State half | Cryptographic half |
|---|---|---|
| `CTK-005` Cryptogram Freshness (counter replay) | Monotonic counter: a captured value is not reusable | The cryptogram itself |
| `AUTH-002` Expired/Revoked Credential Rejection | Revocation status | Expiry carried in the credential |

## Identity-assertion tests

`ID-002` (Agent Identity Spoofing Resistance) and `A2A-002` (Agent Card Spoofing via Message Metadata) test that a *claimed* identity (a header, or card metadata in a message) is not trusted without authentication. If signatures can be forged, a forged *authenticated* identity is out of their scope. They show that claims are not trusted. They do not show that authentication is sound.

## Reading a deployment's results through this profile

1. **Class S results bound a stolen credential.** A FAIL in class S means a single stolen credential can exceed its limit: more uses, more spend, or survival after revocation.
2. **Class C results bound a stolen credential's scope.** Against forgery they establish nothing, whatever the verdict.
3. **The question to ask a vendor:** for each class S control, does the server check against its own records (issuance, status, use), or only verify a signature? Only the first survives forgery.
4. **Approval is the last line against a stolen credential** only if the requester cannot also approve. Until #739 has a test, no result here establishes separation of duties.

## Related

- `docs/SCOPE.md`: what the harness does not test.
- Open gaps that extend class S: #640 (revocation timing), #736 (per-credential rate limits), #738 (compute budget per credential), #739 (separation of duties at execution).
