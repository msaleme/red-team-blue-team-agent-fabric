# VS-R01 Doc/UX Findings (D-class) — D2 through D9

Updated after a two-hour live walkthrough of the documented happy-path for AWS Bedrock AgentCore Payments + Coinbase CDP integration on Base Sepolia testnet.

All eight findings are observation-class (E1: descriptive, reproducible). None are vulnerabilities. They are documentation, error-string, API-enum, product-surface, and form-validation gaps that an integration tester encounters when walking the published setup path.

## Disclosure routing

- **AWS Bedrock AgentCore Payments team** receives D2, D3, D4, D5 (AgentCore-side surfaces and the docs they own)
- **Coinbase Developer Platform team** receives D6, D7, D8, D9 (CDP Portal policy creation form and the public policy docs they own)
- **Meta-finding for both:** the integration path documented as a happy-path cannot be completed end-to-end without a Coinbase-side preview-allowlist intervention (see D2's revised form)

## D2 — AWS error string is misleading; the actual gate is not in CDP project policies

**Observation:** `ProcessPayment` returns `AccessDeniedException: Delegated signing is not enabled for your Coinbase project. Please enable delegated signing in your Coinbase project policies.`

The error string instructs the developer to enable delegated signing in the CDP project policies. A developer follows the instruction and creates a maximally permissive CDP project policy (accepts `signEndUserEvmTransaction`, `sendEndUserEvmTransaction`, `signEvmTransaction`, `sendEvmTransaction`, all with `ethValue <= 1 ETH` criteria on `base-sepolia`). The wall persists with identical error text.

Empirically: project-level CDP policy contents do not affect the AgentCore-side `Delegated signing is not enabled` check. The actual gate is a CDP project-level preview-feature flag that requires Coinbase Developer Support to enable per-project. The docs do not surface this requirement.

**Why this matters:** the error directs developers to a surface that does not control the outcome. Time-to-resolution for a first-time integrator is dominated by debugging the wrong surface.

**Suggested fix:** either (a) reframe the error string to point at the actual gate (e.g., `Delegated signing is not enabled for project {projectId}. Contact Coinbase Developer Support to enable the AgentCore Payments preview feature flag for your project.`), or (b) surface a project-level feature-flag check that returns a more specific error when the flag is unset versus when policies are missing or restrictive.

**Evidence class:** E1 (reproducible error-string defect; root-caused by exhaustive elimination of project-policy contents as the controlling variable).

## D3 — CreatePaymentInstrument network enum lacks BASE_SEPOLIA while balance query supports it

**Observation:** `CreatePaymentInstrument.paymentInstrumentDetails.embeddedCryptoWallet.network` enum accepts only `SOLANA` and `ETHEREUM`. The sibling operation `GetPaymentInstrumentBalance.chain` enum accepts `BASE`, `BASE_SEPOLIA`, `ETHEREUM`, `SOLANA`, `SOLANA_DEVNET`.

Same integration, same wallet, two operations, two divergent enums. A developer wiring a Base Sepolia CDP connector cannot name the network at instrument-creation time but can query its balance by name.

**Why this matters:** the enum gap forces developers to guess that `ETHEREUM` at instrument-creation will resolve to the connector's bound network. The fallback works but is undocumented.

**Suggested fix:** add `BASE`, `BASE_SEPOLIA`, `ETHEREUM_SEPOLIA`, `SOLANA_DEVNET` to the `CreatePaymentInstrument` network enum so it matches `GetPaymentInstrumentBalance.chain`. Alternatively, document the connector-binding fallback in the `CreatePaymentInstrument` API reference.

**Evidence class:** E1 (API surface inconsistency, reproducible).

## D4 — WalletHub asset labels do not distinguish mainnet from testnet

**Observation:** WalletHub UI displays asset rows labeled `ETH on Base` and `USDC on Base` without indicating whether the underlying network is Base mainnet or Base Sepolia testnet. The label is identical for both. After funding the wallet with Base Sepolia USDC via the CDP Faucet (verified at chain level via direct RPC: `1.0 USDC` on Sepolia), the WalletHub display continues to show `0 USDC` because WalletHub queries Base mainnet only.

**Why this matters:** an integration tester cannot visually confirm chain context from the WalletHub UI. The same UI is shown regardless of testnet versus mainnet binding, and the displayed balance reflects mainnet state even when the underlying wallet is being used for testnet operations.

**Suggested fix:** append the chain identifier to the asset label whenever the wallet is bound to a testnet network (e.g., `USDC on Base Sepolia`). Surface a network-context badge near the wallet selector.

**Evidence class:** E1 (UX labeling defect, reproducible).

## D5 — WalletHub funding flow is mainnet-only; the documented end-user flow is not completable on testnet

**Observation:** the WalletHub `Fund` dropdown for an embedded wallet exposes exactly two options: `External wallet` (send crypto via QR) and `Fiat` (buy crypto via fiat onramp). The `Receive USDC` modal displays `On Base` with a QR code targeting Base mainnet. There is no testnet option, no faucet link, no Sepolia mode toggle in the funding surface.

AWS AgentCore Payments documentation (`payments-how-it-works.html` → `Funding the wallet → Coinbase`) instructs integration developers to direct end users through the WalletHub flow to top up the wallet and grant agent permission. For testnet integration validation, this flow is not completable end-to-end: the end user cannot fund the wallet from inside WalletHub on testnet.

**Why this matters:** the documented integration path is mainnet-only. Standard pre-production validation practice requires a testnet-completable equivalent. Currently, an integrator must either (a) bypass WalletHub and fund via external Base Sepolia faucet (the chain receives the funds but WalletHub continues to display `0`, see D4), (b) validate only on mainnet with real USDC, or (c) lack a documented testnet end-user flow.

**Suggested fix:** either expose a testnet mode in WalletHub for projects bound to testnet connectors (with CDP Faucet integration), or document the testnet workaround explicitly in `payments-how-it-works.html` so implementers know the WalletHub UI flow does not apply to testnet validation.

**Evidence class:** E1 (product-surface gap, reproducible).

## D6 — Policy creation form error pointer mis-attributes missing required fields

**Observation:** the CDP Portal `Create new project policy` form returns `Invalid value at description` when the missing field is actually `scope`. Submitting JSON without a top-level `scope` field produces an error message that points at the description field.

When `scope: "project"` is added, the description-field error clears and a different error surfaces (e.g., empty `criteria` array, missing operation discriminator).

**Why this matters:** the error pointer adds debugging iterations for developers who would otherwise correct the actual missing field on the first pass.

**Suggested fix:** surface the actual missing-required-field name in the error response. A composite schema error response that lists all missing required fields at once would eliminate the iteration loop.

**Evidence class:** E1 (form validation error-pointer defect, reproducible).

## D7 — Policy form validator surfaces schema constraints one iteration at a time

**Observation:** creating a single valid project policy required eight sequential submission attempts to walk the live schema, each iteration revealing one additional constraint:

1. Description with em-dash `—` → `Invalid value at description` (rejected non-ASCII character without naming it)
2. Description as a slug with digits and dashes → `Invalid value at description` (rejected slug-form without naming the constraint)
3. Empty description → `Required value, expected "string" at description` (description is required)
4. Missing top-level `scope` field → `Invalid value at description` (mis-attributed pointer, see D6)
5. Missing closing brace → `Expected ',' or '}' after property value` (JSON structural error)
6. Empty `criteria` array → `Array must contain at least 1 element(s) at rules[0].criteria`
7. Invalid operation `signEndUserEvmTransaction` → discriminator error listing 17 valid operation names (later observation: this operation IS valid; the rejection cause was a different rule in the same submission)
8. Invalid criteria type `evmNetwork` → discriminator error listing valid types: `ethValue`, `evmAddress`, `evmData`, `netUSDChange`
9. Missing field `changeCents` for `netUSDChange` criterion
10. Bad control character introduced by copy-paste of long single-line JSON

**Why this matters:** ten sequential validator interactions to reach a valid policy. Each interaction returns one schema constraint. A composite validation response that surfaces all violations in a single pass would eliminate most of these iterations.

**Suggested fix:** return an error response that lists every schema violation in the submitted document. The existing per-error response pattern is the bottleneck.

**Evidence class:** E1 (form validation UX defect, reproducible).

## D8 — Policy description string validation is undocumented

**Observation:** the policy `description` field rejects valid-looking strings without surfacing the constraint:

- `VS-R01 — Base Sepolia testnet allow delegated signing` (71 chars, contains em-dash) → rejected
- `VS-R01 Base Sepolia testnet allow delegated signing for AgentCore Payments` (74 chars, ASCII) → rejected
- `vs-r01-sepolia-testnet` (22 chars, slug form, lowercase + dashes + digits) → rejected
- `Allow signing on Base Sepolia testnet` (37 chars, sentence form, ASCII letters + spaces, no digits, no dashes) → accepted

The accepted-versus-rejected boundary appears to require natural-language form (sentence case, ASCII letters, spaces, no digits, no special characters). This constraint is not surfaced in the form, the validator error, or the public docs.

**Why this matters:** developers cannot predict valid description strings without iterative trial. Slug-form descriptions (a common convention for machine-readable identifiers) are silently rejected.

**Suggested fix:** document the description-field character constraints in the policy reference. Surface the actual constraint in the validator error message (e.g., `Description must use natural-language form: letters and spaces only`).

**Evidence class:** E1 (form validation constraint not documented, reproducible).

## D9 — Live policy validator schema diverges from public documentation

**Observation:** the published CDP docs ([evm-policies](https://docs.cdp.coinbase.com/wallets/security-and-policies/policy-engine/evm-policies)) show example policies that the live form rejects:

- Docs example uses `criteria.type: "evmNetwork"` with a `networks` array. The live validator rejects this type, listing valid criteria types as `ethValue`, `evmAddress`, `evmData`, `netUSDChange`. No `evmNetwork` type exists in the live schema.
- Docs example uses `signEndUserEvmTransaction` as a sample operation. The live validator initially rejected this operation in one submission, then accepted it in a later submission with corrected criteria. The operation IS valid; the first rejection was driven by a different rule in the same multi-rule submission.

**Why this matters:** developers consulting the public docs cannot rely on the examples to produce a valid policy. The drift between docs and live schema doubles the debugging surface.

**Suggested fix:** verify all policy examples in the public docs against the current production validator schema. Add a CI gate that re-validates example policies on every docs publish.

**Evidence class:** E1 (docs/runtime drift, reproducible against the live form on 2026-05-27).

## Aggregate observation

D2 through D9 are individually small. Together they describe a documented integration happy-path that cannot be completed end-to-end without out-of-band intervention from Coinbase Developer Support. An integration tester following the public docs precisely will:

1. Hit the WalletHub mainnet-only funding gap (D4, D5)
2. Discover the chain enum inconsistency at instrument creation (D3)
3. Spend an hour fighting CDP policy form validation (D6, D7, D8, D9) on the assumption that the AWS error message is accurate (D2)
4. Discover empirically that the CDP project policy is not the controlling surface (D2)
5. Escalate to Coinbase support for the actual fix

The integration tester's first-success path is dominated by debugging surfaces that do not control the outcome. This is the meta-finding worth surfacing to both teams: the documented setup procedure does not produce a working integration on testnet without a Coinbase-side preview-allowlist toggle the docs do not mention.

## Reproducibility

All findings reproduce against the live AWS Bedrock AgentCore Payments preview and the live CDP Portal as of 2026-05-27. Recovery requires no special privileges beyond a standard CDP project and a standard AWS account with Bedrock AgentCore Payments preview enabled. The PaymentManager, PaymentConnector, CredentialProvider, PaymentInstrument, and PaymentSession resources used during this walkthrough are listed in `~/clawd/red-team-blue-team-agent-fabric/scripts/vs-r01-env.sh` and the active CDP project policy is `fa4712b5-7283-4dd7-9c7f-3ea04c97488e`.

## Re-validation footer — 2026-06-06

Ten days after the initial walkthrough, the integration state was re-probed against the same resources:

- `ProcessPayment` still returns `AccessDeniedException: Delegated signing is not enabled for your Coinbase project. Please enable delegated signing in your Coinbase project policies.` — identical error string. The wall is still up.
- The CDP project policy `fa4712b5-7283-4dd7-9c7f-3ea04c97488e` remains active with permissive ethValue criteria. Policy contents continue to have no effect on the wall, confirming D2.
- `GetPaymentInstrumentBalance` against the Base Sepolia chain returns `4.0 USDC` (up from `1.0` and `2.0` during the initial walkthrough, consistent with additional faucet drops). The chain-level integration remains functional.
- A Coinbase Developer Support contact was opened via the CDP Discord channel on 2026-06-06. Pending acknowledgment.

**Relevant external signal in the intervening 10 days:**

- AWS blog post 2026-06-01: ["Enable safe agentic payments with built-in guardrails using Amazon Bedrock AgentCore payments"](https://aws.amazon.com/blogs/machine-learning/enable-safe-agentic-payments-with-built-in-guardrails-using-amazon-bedrock-agentcore-payments/) — frames the integration's five-safety-risk model and four-role IAM separation. Does not mention delegated signing, the Coinbase project preview flag, the WalletHub mainnet-only constraint, or any of the D-findings. Orthogonal scope; the gaps documented here remain unaddressed.
- CDP public changelog: last entry remains 2026-04-14 (delegated signing announcement). No updates in May or June, including no fixes for any D-finding.

**Aggregate state:** ten days post initial diagnosis, the documented integration path remains incomplete for any developer attempting testnet validation of AgentCore Payments + CDP. No CDP or AWS docs revision has surfaced the project-allowlist requirement or any of the D2-D9 gaps. Disclosure remains appropriate.

## Restraint

No public claims about these findings until disclosure has been acknowledged by both AWS Bedrock security and Coinbase Developer Platform support. The findings are observation-class (E1) and pose no security risk to end users; the disclosure routing reflects coordinated-disclosure norms, not embargo on a vulnerability.
