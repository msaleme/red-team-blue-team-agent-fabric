# x402 spec payment probes: live run, 2026-11-04

The first funded run of X4-058..X4-066 against an x402 server the harness did not write.

## Target

| | |
|---|---|
| Server | `scripts/x402_spec_live/server.py`: Flask app using the official `x402` Python package **2.26.0** (`x402ResourceServerSync`, `HTTPFacilitatorClientSync`) |
| Facilitator | `https://x402.org/facilitator` (public) |
| Network | Base Sepolia, `eip155:84532` (testnet) |
| Requirement | x402 v2, scheme `exact`, eip3009, 10000 atomic USDC (0.01), asset `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |
| `payTo` | `0x7889454DF1EB44B2fA0878179A1845F5b4649286` |
| Payer | `0x88c76C0e49eE06BF5C7802a365d0C40b92918009` (testnet key, faucet-funded) |
| Command | `bash scripts/x402_spec_live/run.sh`, `--categories spec_payment`, spend cap 50000 atomic |
| Run | `2026-11-04T13:49:35Z`, harness branch `feat/x402-spec-live-run` (main `ca9bb7e` plus the fixes in the same PR) |

## Result: 9 of 9 PASS

The server is the subject. Each rejection below is the facilitator's own reason code from the
spec's error list, not just a 402.

| Test | Probe | Verdict | Server answer |
|---|---|---|---|
| X4-058 | valid payment (positive control) | PASS | 200, settled, tx below |
| X4-059 | replay of the accepted payment | PASS | 402 `invalid_exact_evm_nonce_already_used` |
| X4-060 | `to` is not `payTo` (validly signed) | PASS | 402 `invalid_exact_evm_recipient_mismatch` |
| X4-061 | one unit below the required amount | PASS | 402 `invalid_exact_evm_payload_authorization_value_mismatch` |
| X4-062 | `validBefore` in the past | PASS | 402 `invalid_exact_evm_payload_authorization_valid_before` |
| X4-063 | signature bytes altered | PASS | 402 `invalid_exact_evm_signature` |
| X4-064 | `value` changed after signing | PASS | 402 `invalid_exact_evm_signature` |
| X4-065 | signed over another chain's EIP-712 domain | PASS | 402 `invalid_exact_evm_signature` |
| X4-066 | one payment sent 5 times in parallel | PASS | `[402, 200, 402, 402, 402]`: accepted once |

## Settlements, checked on chain

Both hashes come from the server's `PAYMENT-RESPONSE` header in `report.json`. Each was read back with
`eth_getTransactionReceipt` / `eth_getLogs` on `https://sepolia.base.org`: status 1, one USDC
`Transfer` of 10000 from the payer to `payTo`, gas paid by the facilitator.

| Test | Tx | Block |
|---|---|---|
| X4-058 | [`0xea40cd95…3203c57e`](https://sepolia.basescan.org/tx/0xea40cd956e96b1a9da77c519a4b9cae19e651b12876fd63721ee3a343203c57e) | 54391520 |
| X4-066 | [`0x7c6d7ffd…05ceadbb6`](https://sepolia.basescan.org/tx/0x7c6d7ffdc1f4a825fed1d5cd850c4411971292fb0d735d90cc7cc9b05ceadbb6) | 54391534 |

Spend: 20000 atomic (0.02 USDC) against a 50000 cap. No other transfer left the payer in this run.

## An earlier run the same morning

A run at 13:44 UTC, before this PR's fixes, gave the same 9/9 and settled two payments
(`0xfa115d4a…894bd9e3`, block 54390062; `0x0fd979d9…3d064b75`, block 54390075). It is not committed,
for two reasons. First, it printed `AGENT AUTONOMY RISK SCORE: 100/100 (CRITICAL)` beside 9/9 PASS: the
score defaulted every signal it never measured to risky, and a spec-only run measures none. Second,
its X4-066 entry carried no settlement hash. Both are fixed and guarded in
`testing/test_x402_spec_probes.py`. This run therefore reports the score as NOT MEASURED.

## What this does not show

- **One implementation.** The server is the official Python SDK with the x402.org facilitator.
  Doing the checks is mostly the facilitator's job, so this is evidence about that pair, not about
  x402 servers in general or other facilitators.
- **v2 only, `exact`/eip3009 only.** No v1 (`X-PAYMENT`) target, no Permit2 or other transfer
  method, no non-EVM scheme.
- **Testnet.** Base Sepolia and testnet USDC. Mainnet is refused by design.
- **Nine properties.** The pre-spec X4 tests do not run against a spec target and are not part of
  this result.

## Files

- `report.json`: the harness report (`--report`)
- `run.log`: harness console output
- `server.log`: the target server's log
