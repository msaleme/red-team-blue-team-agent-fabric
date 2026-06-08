# VS-R01 Doc/UX Findings (D-class) — D2 through D9

Updated after a two-hour live walkthrough of the documented happy-path for AWS Bedrock AgentCore Payments + Coinbase CDP integration on Base Sepolia testnet.

All eight findings are observation-class (E1: descriptive, reproducible). None are vulnerabilities. They are documentation, error-string, API-enum, product-surface, and form-validation gaps that an integration tester encounters when walking the published setup path.

## Disclosure routing

- **AWS Bedrock AgentCore Payments team** receives D2, D3, D4, D5 (AgentCore-side surfaces and the docs they own)
- **Coinbase Developer Platform team** receives D6, D7, D8, D9 (CDP Portal policy creation form and the public policy docs they own)
- **Meta-finding for both:** the integration path documented as a happy-path cannot be completed end-to-end without a Coinbase-side preview-allowlist intervention (see D2's revised form)

## D2 — Misleading AWS error string + UI-flag-gated CDP toggle: documented setup path is not completable in the default Portal UI

**Observation:** `ProcessPayment` returns `AccessDeniedException: Delegated signing is not enabled for your Coinbase project. Please enable delegated signing in your Coinbase project policies.`

The error directs developers to a CDP **project policies** surface (Server Wallet → Policies). A developer who follows that instruction and creates a maximally permissive CDP project policy (accepting `signEndUserEvmTransaction`, `sendEndUserEvmTransaction`, `signEvmTransaction`, `sendEvmTransaction` with permissive `ethValue` criteria on `base-sepolia`) finds the wall persists with identical error text. Project-policy contents have no effect on this gate.

**The actual mechanism, verified 2026-06-08:** delegated signing is gated by a two-step end-user-consent flow that lives on different product surfaces than the error string indicates:

1. **CDP project-level toggle** at `Non-custodial Wallet → Security → Delegated signing`. The toggle is **only visible in the "Try new experience" UI flag** of the CDP Portal. In the default Portal UI the toggle does not render — the Non-custodial Wallet → Security page shows only a "Client configuration" panel for Web/Mobile domain authorization. The toggle becomes reachable only after enabling the new-experience UI via the link at the bottom of the left sidebar. (Terminology note: docs call the product "Non-custodial Wallets"; current Portal UI labels the same product "Embedded Wallets" in the default UI and "Non-custodial Wallet" in the new-experience UI.)

2. **WalletHub per-wallet permission grant** by the end user. After step 1, the WalletHub UI accessed via `paymentInstrumentDetails.embeddedCryptoWallet.redirectUrl` renders a Permissions section at the bottom that did not exist before the toggle was on. The end user clicks "Grant permission" with an automatic 30-day expiry. Without this per-wallet grant, ProcessPayment still fails — but with a different error message: `Delegated signing grant is not active for the end user wallet. Please redirect end user to the WalletHub to grant the permissions.`

**The error-string asymmetry:** before step 1, the error misleadingly points at "project policies" (a surface that does not control the outcome). After step 1 but before step 2, the error correctly points at WalletHub. The error string's quality depends on how far the operator has progressed through the gates — not on the actual gate's nature.

**Why this matters:** the docs at `docs.cdp.coinbase.com/wallets/using-wallets/delegated-signing` reference the Non-custodial Wallet → Security navigation path but do not state that the toggle is only visible in the new-experience UI flag. A first-time integrator who reads the docs, navigates to Non-custodial Wallet → Security in the default UI, and sees only a Client configuration section concludes the toggle does not exist for their project. Coinbase support correctly cites the path; the path renders only in the new-experience UI; the docs do not state this precondition.

**Suggested fix (three parts):**

1. **Reframe the pre-toggle error string** to match the post-toggle error: `Delegated signing grant is not active for the end user wallet. Project may also require the project-level Delegated Signing toggle at Non-custodial Wallet → Security (currently in the new-experience UI).` This eliminates the misdirection toward project policies.
2. **Make the Delegated Signing toggle visible in the default Portal UI** for any project that has an AgentCore Payments connector provisioned, or at minimum surface a banner in the default UI pointing at the new-experience UI when an AgentCore connector is detected.
3. **Update the docs at `docs.cdp.coinbase.com/wallets/using-wallets/delegated-signing`** to state the new-experience UI precondition explicitly, and align the product terminology (Non-custodial Wallet vs Embedded Wallets) between docs and live Portal UI.

**Evidence class:** E1 (reproducible error-string defect + UI-discoverability defect + docs-precondition defect; root-caused by the diagnostic chain 2026-05-27 through 2026-06-08, with Coinbase Developer Support engagement on 2026-06-08 09:02 UTC as the unblock signal).

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

## D11 — WalletHub permission grant UX does not surface agent identity, scope, or spend limit

**Observation:** when the end user clicks "Grant permission ▼" on the WalletHub Permissions panel and approves, the grant is recorded with a 30-day automatic expiry. The pre-grant UI message reads: *"The app that sent you here can't trade or make payments from this wallet. You can grant permission for a limited time if you trust this app."*

The end user is NOT shown:

- **The agent's name** (e.g., `vs-r01-cdp-grant-probe`) — they do not see which agent they are granting access to
- **The asset scope** — is the grant for ETH, USDC, or both?
- **A spend limit** — is there a per-transaction cap, a session cap, an aggregate cap?
- **An option to set a custom expiry** — the 30-day default appears to be the only option

After granting, the WalletHub UI displays only: *"This app can pay on your behalf from this wallet. Permission expires on July 8, 2026."* No agent name, no scope, no limit, no list of which apps currently hold delegations against this wallet.

**Why this matters:** for testnet integration testing this works (single integrator, known agent). For production user-consent flow this is a meaningful UX gap. A user who has authorized multiple agents from different applications cannot review what they have authorized, has no way to scope grants to specific assets or transaction limits, and cannot distinguish a malicious agent from a legitimate one because no agent identity is surfaced at grant time.

**Suggested fix:** surface the agent name, asset scope, and spend limit in the grant flow. Allow user-selected expiry from a list (1h, 24h, 7d, 30d, custom). Replace the single "Revoke permission" button with a per-wallet "Active permissions" panel that lists all current delegations by agent name with per-delegation revoke buttons.

**Evidence class:** E1 (UX defect, reproducible 2026-06-08; not a security vulnerability but a meaningful gap for any production deployment involving multiple agent providers).

## Aggregate observation

D2 through D11 are individually small. Together they describe a documented integration happy-path that is not completable in the default Portal UI and is not completable on testnet through the documented flows. An integration tester following the public docs precisely will:

1. Hit the WalletHub mainnet-only funding gap (D4, D5)
2. Discover the chain enum inconsistency at instrument creation (D3)
3. Spend an hour fighting CDP policy form validation (D6, D7, D8, D9) on the assumption that the AWS error message is accurate (D2)
4. Discover empirically that the CDP project policy is not the controlling surface (D2)
5. Open a Coinbase support ticket, receive a navigation path that does not render in the default Portal UI (D2 — the new-experience UI gate)
6. Enable the new-experience UI flag, find and enable the Delegated Signing toggle
7. Discover the WalletHub Permissions section has now appeared (it was silently absent before the toggle was on)
8. Grant the per-wallet permission via a UI that surfaces no agent identity, scope, or spend limit (D11)
9. Re-test ProcessPayment and succeed

That is a 12-day diagnostic chain across 5+ navigation paths to complete what the docs describe as a standard setup. The meta-finding worth surfacing to both teams: the documented setup procedure has multiple seam-points where developers can get stuck, and several of those seams are silently empty in the default Portal UI — they require either the new-experience flag, a Coinbase-side toggle response, or an end-user grant action that the operator must guide.

## Reproducibility

All findings reproduce against the live AWS Bedrock AgentCore Payments preview and the live CDP Portal as of 2026-05-27. Recovery requires no special privileges beyond a standard CDP project and a standard AWS account with Bedrock AgentCore Payments preview enabled. The PaymentManager, PaymentConnector, CredentialProvider, PaymentInstrument, and PaymentSession resources used during this walkthrough are listed in `~/clawd/red-team-blue-team-agent-fabric/scripts/vs-r01-env.sh` and the active CDP project policy is `fa4712b5-7283-4dd7-9c7f-3ea04c97488e`.

## Re-validation footer — 2026-06-08 (wall dropped, integration verified end-to-end)

Twelve days after the initial walkthrough, the documented happy-path was completed end-to-end after engaging Coinbase Developer Support. The full diagnostic chain on disclosure-send day:

- **2026-06-08 08:24 UTC:** Coinbase support case opened with subject *"AgentCore Payments: Delegated signing error despite CDP project policy configuration"* via the CDP Portal support widget. Body included project ID `fdc6d46c-a5e3-49b2-8fae-0e1c42569ba7`, policy ID `fa4712b5-7283-4dd7-9c7f-3ea04c97488e`, wallet address, the verbatim error, and a precise question about whether server-side delegation grant exists or if browser-only via `createDelegationForAccount` is the only path.
- **2026-06-08 09:02 UTC:** Coinbase support responded with the navigation path `Products → Wallets → Non-custodial Wallet → Security → Delegated Signing toggle` and a link to the docs at `docs.cdp.coinbase.com/wallets/using-wallets/delegated-signing`.
- **2026-06-08 09:54-09:58 UTC:** the cited nav path was unreachable in the default Portal UI. Both Server Wallet and Embedded Wallet products' Security tabs showed no Delegated Signing toggle. Authentication and Policies tabs on Embedded Wallets also did not contain the toggle. Three screenshots saved.
- **2026-06-08 10:01 UTC:** the "Try new experience" UI flag was enabled via the bottom-left sidebar link. The Non-custodial Wallet product surface then rendered with a Security tab containing the Delegated Signing toggle (plus Generate Wallet Secret + Project policies preview). Toggle was clicked to enable.
- **2026-06-08 15:02 UTC:** ProcessPayment re-probed. Error changed from `Delegated signing is not enabled for your Coinbase project. Please enable delegated signing in your Coinbase project policies.` to `Delegated signing grant is not active for the end user wallet. Please redirect end user to the WalletHub to grant the permissions.` Project-level gate cleared.
- **2026-06-08 15:05 UTC:** WalletHub URL `https://hub.cdp.coinbase.com/5e6b880c1f09` revisited. The Permissions section now rendered (it had been silently absent in the 2026-05-27 walkthrough) with the message *"The app that sent you here can't trade or make payments from this wallet. You can grant permission for a limited time if you trust this app."* "Grant permission" approved with the default 30-day expiry (expires 2026-07-08).
- **2026-06-08 15:07 UTC:** ProcessPayment re-probed. **Status: `PROOF_GENERATED`.** End-to-end x402 payment signing flow verified. Real EIP-3009 USDC transfer authorization returned with `from=0x7889454DF1EB44B2fA0878179A1845F5b4649286`, `to=0x000000000000000000000000000000000000dEaD`, `value=10000` (0.01 USDC), `validBefore=1780931609`, `nonce=0x000...01440`, `signature=0x393bae...956d911b`. Request ID `2520a0d5-b121-4ece-ba27-b457367fd091`. ProcessPayment ID `3ffb5e2f-4d1f-40c4-a8bc-ffabd1533e50`.

**Net diagnostic-chain length:** 12 days, 5+ navigation paths attempted in the default UI, 1 Coinbase support ticket, 1 UI flag toggle, 1 project-level toggle, 1 WalletHub end-user grant — to complete what the docs describe as the standard setup procedure for AgentCore Payments + CDP integration.

**External signal in the resolution window:**

- AWS blog post 2026-06-01: ["Enable safe agentic payments with built-in guardrails using Amazon Bedrock AgentCore payments"](https://aws.amazon.com/blogs/machine-learning/enable-safe-agentic-payments-with-built-in-guardrails-using-amazon-bedrock-agentcore-payments/) — orthogonal scope; the gaps documented here remain unaddressed by AWS as of disclosure send.
- CDP public changelog: last entry remains 2026-04-14. The new-experience-UI precondition for the Delegated Signing toggle is not in the changelog.
- Coinbase Developer Support (2026-06-08): engaged and responsive within ~24h of case creation; correctly cited the docs path; the path renders only in the new-experience UI.

**Aggregate state at disclosure send:** the wall has dropped, the integration is verified working end-to-end, and VS-R02 settlement-time tests are now unblocked. All eleven findings (D2-D11) reproduce against the live integration and document the path from `default Portal UI + AWS docs` to `working integration`. The findings are no longer blocking VS-R01 evaluation execution, but the documentation/UX gaps remain for any subsequent integrator.

## Restraint

The findings are observation-class (E1) and pose no security risk to end users. The disclosure timing reflects coordinated-disclosure norms rather than vulnerability embargo:

- **Coinbase Developer Support** has been engaged via support channel (case opened 2026-06-08 08:24 UTC, response received 09:02 UTC, integration unblocked by 15:07 UTC).
- **AWS Bedrock security** disclosure is sent in parallel with this artifact going live (commit hash and timestamp in `vs-r01/disclosure` branch HEAD).
- No public posts, social media, or blog content referencing these findings until both AWS and Coinbase have had a reasonable window (suggested 30 days) to act on the documentation, UX, and error-string fixes outlined here.

Branch `vs-r01/skeleton @ 7515831` remains the cite-from-here state for the underlying VS-R01 evaluation. This `vs-r01/disclosure` branch is the public artifact for the disclosure correspondence.
