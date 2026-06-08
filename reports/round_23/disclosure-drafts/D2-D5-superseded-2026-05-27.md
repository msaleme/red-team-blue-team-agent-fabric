# VS-R01 Candidate Doc/UX Findings (D-class) — added 2026-05-27

These four findings surfaced during the second-attempt walkthrough of the documented "delegated signing via Coinbase WalletHub" flow, after the initial CreatePaymentInstrument was missing the redirectUrl-handling step.

All four are observation-class (E1: descriptive only). None are vulnerabilities; they are documentation, error-string, API-enum, and product-surface gaps that an integration tester encounters in the first hour of the documented happy-path flow.

## D2 — Misleading AWS error string

**Observation:** `ProcessPayment` returns `AccessDeniedException: Delegated signing is not enabled for your Coinbase project` when the actual condition is that the end-user has not completed the per-instrument WalletHub authorization grant.

**Why misleading:** The string suggests a CDP project-level feature toggle that does not exist. A developer reading the error will look for a Portal toggle, fail to find one, and may file a support ticket asking CDP to enable a feature that is already enabled.

**Suggested fix:** Reframe the error to point at the actual gate. Example: `AccessDeniedException: PaymentInstrument has no active end-user authorization. Direct the end user to the WalletHub URL in paymentInstrumentDetails.embeddedCryptoWallet.redirectUrl to grant agent permission.`

**Evidence class:** E1 (reproducible error-string defect).

## D3 — Network enum gap

**Observation:** `embeddedCryptoWallet.network` enum accepts only `SOLANA` and `ETHEREUM`. There is no `BASE_SEPOLIA`, `BASE`, or `ETHEREUM_SEPOLIA` value.

**Why surprising:** The Coinbase CDP connector itself is provisioned with Base Sepolia credentials in our integration. A developer wiring a testnet CDP wallet expects a corresponding enum value at the PaymentInstrument layer. Using `ETHEREUM` and relying on connector-level network binding is not documented.

**Suggested fix:** Add `BASE`, `BASE_SEPOLIA`, and `ETHEREUM_SEPOLIA` to the enum, or document the connector-binding fallback explicitly in `CreatePaymentInstrument` API reference.

**Evidence class:** E1 (API/doc mismatch, reproducible).

## D4 — WalletHub asset labels do not distinguish mainnet from testnet

**Observation:** WalletHub UI displays asset rows labeled "ETH on Base" and "USDC on Base" without indicating whether the underlying network is Base mainnet or Base Sepolia testnet.

**Why this matters:** Integration testers cannot visually confirm they are operating on the expected chain. A misconfiguration could route a test transaction onto mainnet without an obvious warning surface.

**Suggested fix:** Append the chain identifier to the asset label (e.g. "USDC on Base Sepolia") whenever the wallet is bound to a testnet network.

**Evidence class:** E1 (UX/labeling defect, reproducible).

## D5 — WalletHub funding flow is mainnet-only

**Observation:** The WalletHub `Fund ▼` dropdown for an embedded wallet exposes exactly two options: **External wallet** (send crypto via QR — implicitly mainnet) and **Fiat** (buy crypto via fiat onramp — mainnet only). There is no testnet option, no faucet link, no Sepolia mode toggle anywhere in the funding surface.

**Why this matters:** AWS AgentCore Payments documentation (payments-how-it-works.html → "Funding the wallet → Coinbase") instructs integration developers to direct end users through the WalletHub flow to top up and grant agent permission. For testnet integration validation, this flow is not completable: the end user cannot fund the wallet from inside WalletHub. The documented happy-path is mainnet-only.

**Implications for testnet integration testing:** Implementers either (a) bypass WalletHub entirely and fund via external Base Sepolia faucet (which may or may not display in WalletHub, see D4), (b) test only on mainnet with real USDC, or (c) lack a documented testnet end-user flow at all.

**Suggested fix:** Either expose a testnet mode in WalletHub (with faucet integration) for projects bound to testnet connectors, OR document the testnet workaround in `payments-how-it-works.html` so implementers know the WalletHub UI flow does not apply to testnet validation.

**Evidence class:** E1 (product-surface gap, reproducible).

## Note on aggregation

D2–D5 are individually small. Together they describe the documented happy-path flow being incomplete for any developer attempting testnet integration validation of AgentCore Payments + CDP. The integration is currently testable end-to-end on mainnet only, which conflicts with standard pre-production validation practice.
