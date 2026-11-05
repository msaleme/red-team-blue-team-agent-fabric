# x402 client-set terms (X4-067, X4-068): live run, 2026-11-05

Two new spec payment probes, run against the official x402 server and against a deliberately
broken copy of it, on Base Sepolia through the public x402.org facilitator.

## The question

X4-060 and X4-061 change the signed payload and send the server's own requirement back in
`accepted`. The facilitator therefore always compares a wrong payment with the right terms,
and refuses it. X4-067 and X4-068 instead rewrite `accepted` to the client's own terms and sign
the payment to match:

| Test | `accepted` | Signed authorization |
|---|---|---|
| X4-067 | `amount` one unit below the price | `value` one unit below the price |
| X4-068 | `payTo` another address | `to` that same address |

Payload and `accepted` agree with each other, and both disagree with what the server offered.
A facilitator checks a payment against the requirements the server passes it. If the server
passes along the client's `accepted`, nothing else refuses. The case was raised by a reader
(bloqarl) on the dev.to post about the x402 spec probes, 2026-11-03.

## Targets

| | Official | Negative control |
|---|---|---|
| Server | `scripts/x402_spec_live/server.py`: official `x402` Python package **2.26.0** | same file with `TRUST_CLIENT_ACCEPTED=1` |
| Difference | matches `accepted` against its own `accepts[]` (`find_matching_requirements`) and verifies against the match | `find_matching_requirements` replaced by one line that returns the client's `accepted` |
| Facilitator | `https://x402.org/facilitator` (public) | same |
| Network | Base Sepolia, `eip155:84532` (testnet) | same |
| Requirement | x402 v2, `exact`, eip3009, 10000 atomic USDC, asset `0x036CbD53842c5426634e7929541eC2318f3dCF7e`, `payTo` `0x7889454DF1EB44B2fA0878179A1845F5b4649286` | same |
| Payer | `0x88c76C0e49eE06BF5C7802a365d0C40b92918009` (testnet key) | same |
| Command | `bash scripts/x402_spec_live/run.sh <out>` (cap 60000 atomic) | `TRUST_CLIENT_ACCEPTED=1 bash scripts/x402_spec_live/run.sh <out>` |

## Result

| Test | Official | Negative control |
|---|---|---|
| X4-058..X4-066 | 9 of 9 PASS | 9 of 9 PASS |
| X4-067 client-set price | **PASS**: 402 `No matching payment requirements` | **FAIL**: 200, settled 9999 of 10000 |
| X4-068 client-set recipient | **PASS**: 402 `No matching payment requirements` | **FAIL**: 200, settled to `0x…dEaD` |

The probes pass where the server does its own comparison and fail where it does not. X4-060 and
X4-061 pass against both servers, which is why they cannot see this defect.

On the negative control, the public facilitator verified and settled both payments. With the
client's terms in hand, it had nothing to compare them against.

## Settlements, checked on chain

Read back with `eth_getTransactionReceipt` on `https://sepolia.base.org`: status 1, and the one
USDC `Transfer` log listed.

| Run | Test | Tx | Block | Transfer |
|---|---|---|---|---|
| official | X4-058 | [`0x8e9d3b96…2ee6405f`](https://sepolia.basescan.org/tx/0x8e9d3b9646db6fec7bc36be57d2bc689faf10a0d1de95764d50af44c2ee6405f) | 54871622 | 10000 to `payTo` |
| official | X4-066 | [`0x98148186…5f038595cd`](https://sepolia.basescan.org/tx/0x98148186ee37d7b192628ab3cd735da508f765c47f3078cbcefebe5f038595cd) | 54871633 | 10000 to `payTo` |
| negative control | X4-058 | [`0xbbea003a…683ab9c6a`](https://sepolia.basescan.org/tx/0xbbea003a26dfb95da4dee1b8dde98ccaa37a191cd5f9ff4b9fb864d683ab9c6a) | 54871648 | 10000 to `payTo` |
| negative control | X4-066 | [`0xab99c4a3…683387dee`](https://sepolia.basescan.org/tx/0xab99c4a329d519b93f5e966741d6edbdf06ddafde251f3510d2f823683387dee) | 54871659 | 10000 to `payTo` |
| negative control | **X4-067** | [`0x297dd6c7…5f04146`](https://sepolia.basescan.org/tx/0x297dd6c79fd0c0564bb219bfaad83fa2f6b95f7d839cc6a2f1b6abea05f04146) | 54871663 | **9999** to `payTo` |
| negative control | **X4-068** | [`0xb792612d…58473e31a`](https://sepolia.basescan.org/tx/0xb792612d8689eb20dd2648d7950a6cd51ddc0762239e605dd470dee58473e31a) | 54871668 | 10000 to **`0x…dEaD`** |

Spend: 0.02 USDC (official) and 0.039999 USDC (negative control), testnet.

## Earlier runs today, not committed

1. **Cap.** The first official run stopped X4-068 before signing: `spend cap: 49998 + 10000 would
   exceed 50000`. The cap counts every payment that could settle, refused or not, and eleven
   probes need 59998. `run.sh` now passes `--x402-max-spend 60000`. The cap was right to stop it.
2. **A PASS for the wrong reason.** The first negative-control run graded X4-068 **PASS**. The
   payment went to the payer's own address. The facilitator verified it, then the RPC rejected
   the broadcast, and the server answered 402 with a failed settlement
   (`invalid_exact_evm_transaction_failed`). A server that matches `accepted` refuses before
   verify, so a refusal that carries a failed settlement means the server took the client's
   terms, and in the default `verify → resource → settle` flow its handler had already run.
   X4-067/068 now grade that as FAIL (`_spec_grade_client_terms`). The recipient is now neither
   `payTo` nor the payer. Both changes are guarded in `testing/test_x402_spec_probes.py`
   (`test_a_failed_settlement_is_not_a_refusal`,
   `test_client_set_recipient_is_neither_payto_nor_payer`).

## What this does not show

- **Not a defect in any official SDK.** Reading x402-foundation/x402 @ `6a773db`: the Python
  (`find_matching_requirements`), TypeScript (`findMatchingRequirements`) and Go
  (`FindMatchingRequirements`) resource servers all match `accepted` against their own
  `accepts[]` before verify, and the Java server (v1) builds its own requirements. The negative
  control was broken on purpose, by replacing that one function.
- **What it does show** is that the protocol leaves this check to the resource server: the
  facilitator settled client-set terms when the server handed them over. Spec v2 (same commit)
  defines `accepted` as the requirement "indicating the payment method chosen" and lists the
  facilitator's checks against the requirements it receives. It does not state that the server
  must match `accepted` against what it offered. A server written to the spec text rather than
  from the SDKs can omit it.
- **One facilitator, one SDK.** x402.org with the Python package 2.26.0. Other facilitators may
  check differently.
- **v2, `exact`/eip3009, testnet.** v1 payments carry no `accepted`, so X4-067/068 report
  INCONCLUSIVE on a v1 target.

## Files

- `official/`, `trusts-accepted/`: `report.json` (the harness report), `run.log` (harness
  console output), `server.log` (the target server's log; the negative control's first line
  names it as such)
