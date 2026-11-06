# x402 client-set asset (X4-069): live run, 2026-11-06

The twelve spec payment probes (X4-058..X4-069), run against the official x402 server and against
a deliberately broken copy of it, on Base Sepolia through the public x402.org facilitator. New
since 2026-11-05: X4-069, and a client-controlled token for it to name.

## The question

X4-067 and X4-068 rewrite `accepted` to the client's own price or recipient and sign to match
(`reports/x402-spec-live-2026-11-05/`). X4-069 rewrites the third term, the token:

| Test | `accepted` | Signed authorization |
|---|---|---|
| X4-069 | `asset` a token the client deployed; `extra.name`/`extra.version` that token's EIP-712 domain | over that token's domain; `to` and `value` the server's own |

Amount and recipient are correct, so the logs read as a correct payment, in a token worth nothing.
Raised by a reader (bloqarl) on the dev.to x402 post, 2026-11-06, who read in `eip3009.ts` that the
facilitator takes the asset from the requirements it is given and checks only that the address
holds bytecode, and asked whether x402.org keeps an asset list of its own. The Python SDK
(`mechanisms/evm/asset_cache.py`, x402 2.26.0) does the same. Only a live run could show what the
hosted facilitator does.

## The client token

`scripts/x402_spec_live/ClientTestToken.sol`: a plain EIP-3009 token, nothing else in it (no
owner, no hooks, no external calls). It implements what the stock eip3009 facilitator reads and
calls: `name()`, `version()`, `balanceOf()`, `authorizationState()` and the v/r/s
`transferWithAuthorization()`. Tested first on a local Anvil chain with the harness's own signer
(settled; nonce marked used; replay refused).

| | |
|---|---|
| Address | [`0x391D9443237f16CBCa7EE005e553B2fA8ee92F79`](https://sepolia.basescan.org/address/0x391D9443237f16CBCa7EE005e553B2fA8ee92F79) (Base Sepolia) |
| Deploy tx | [`0xac923068…5da7a06`](https://sepolia.basescan.org/tx/0xac92306820fcbae0761d32acbf373e5af8d013fa4c05b5135ed6ce28e5da7a06), status 1 |
| Domain | name `Client Test Token`, version `1` (read back on chain) |
| Supply | 1,000 CTT (6 decimals), all minted to the payer at deploy |
| Built with | Foundry `ghcr.io/foundry-rs/foundry:v1.3.5`, solc 0.8.24 |

## Targets

| | Official | Negative control |
|---|---|---|
| Server | `scripts/x402_spec_live/server.py`: official `x402` Python package **2.26.0** | same file with `TRUST_CLIENT_ACCEPTED=1` |
| Difference | matches `accepted` against its own `accepts[]` (`find_matching_requirements`, which compares `asset` and `extra`) and verifies against the match | `find_matching_requirements` replaced by one line that returns the client's `accepted` |
| Facilitator | `https://x402.org/facilitator` (public) | same |
| Network | Base Sepolia, `eip155:84532` (testnet) | same |
| Requirement | x402 v2, `exact`, eip3009, 10000 atomic USDC, asset `0x036CbD53842c5426634e7929541eC2318f3dCF7e`, `payTo` `0x7889454DF1EB44B2fA0878179A1845F5b4649286` | same |
| Payer | `0x88c76C0e49eE06BF5C7802a365d0C40b92918009` (testnet key) | same |
| Command | `X402_CLIENT_ASSET="0x391D…2F79,Client Test Token,1" bash scripts/x402_spec_live/run.sh <out>` (cap 70000 atomic) | the same with `TRUST_CLIENT_ACCEPTED=1` |

## Result

| Test | Official | Negative control |
|---|---|---|
| X4-058..X4-066 | 9 of 9 PASS | 9 of 9 PASS |
| X4-067 client-set price | **PASS**: 402 `No matching payment requirements` | **FAIL**: 200, settled 9999 of 10000 |
| X4-068 client-set recipient | **PASS**: 402 `No matching payment requirements` | **FAIL**: 200, settled to `0x…dEaD` |
| X4-069 client-set asset | **PASS**: 402 `No matching payment requirements` | **FAIL**: 200, settled 10000 **CTT** to `payTo` |

X4-067 and X4-068 reproduce the 2026-11-05 result.

On the negative control, the public facilitator verified and settled the X4-069 payment in the
client's token. Its wallet sent the `transferWithAuthorization` call to the contract the client
named. On this testnet facilitator, on this date, no asset list stood between a server that
forwards the client's `accepted` and settlement in any EIP-3009 token the client deploys. That
answers bloqarl's question for the hosted testnet facilitator. Nothing here was run against
mainnet, and nothing here says what a mainnet facilitator does.

Against the official server the same probe is refused before verify. The official SDK does not
have this defect. What the run shows is that the server's match is the only check on the token.

## Settlements, checked on chain

Read back with `eth_getTransactionReceipt` on `https://sepolia.base.org`: status 1, and the one
`Transfer` log listed. Every settlement was sent by the facilitator's wallet
`0xd407e409e34e0b9afb99ecceb609bdbcd5e7f1bf`.

| Run | Test | Tx | Block | Contract called | Transfer |
|---|---|---|---|---|---|
| official | X4-058 | [`0x86f6053c…55b464fc`](https://sepolia.basescan.org/tx/0x86f6053ca29f65926979366ba55eb3cbff431ea7763b8222ac367fb655b464fc) | 55373842 | USDC | 10000 USDC to `payTo` |
| official | X4-066 | [`0xe5d94f67…cd10a439c`](https://sepolia.basescan.org/tx/0xe5d94f67832e7cb40c0178ea579750fa4241bbd6d1f3fddf60d0825cd10a439c) | 55373852 | USDC | 10000 USDC to `payTo` |
| negative control | X4-058 | [`0x27f4053b…d0f99f95`](https://sepolia.basescan.org/tx/0x27f4053be713267cfdc8ed6661af7a6817fff9a045430f53f2b7fd86d0f99f95) | 55373902 | USDC | 10000 USDC to `payTo` |
| negative control | X4-066 | [`0x66cf179b…b3d3a41a`](https://sepolia.basescan.org/tx/0x66cf179bb9d5dbc78a3643c521cfc34aae3c59a40cce2efb9240601ab3d3a41a) | 55373911 | USDC | 10000 USDC to `payTo` |
| negative control | X4-067 | [`0x64d2e386…9e67027c`](https://sepolia.basescan.org/tx/0x64d2e3863dd85ff33bdc7765a9921a43af9265a4c1d31887b1723cba9e67027c) | 55373918 | USDC | **9999** USDC to `payTo` |
| negative control | X4-068 | [`0xe0903146…a198bccae`](https://sepolia.basescan.org/tx/0xe09031465f161d8c984f73366ccde6b70f3c26e696391f485ffdcd1a198bccae) | 55373924 | USDC | 10000 USDC to **`0x…dEaD`** |
| negative control | **X4-069** | [`0xa070452b…0dc01bd9`](https://sepolia.basescan.org/tx/0xa070452bc50c7bcd88f550630006c512a1f5926e15876ab7af8692ee0dc01bd9) | 55373930 | **CTT (client token)** | 10000 **CTT** to `payTo` |

## Scope

What this run supports, and nothing beyond it:

- One server implementation (official Python `x402` 2.26.0) and one facilitator (x402.org, its
  Base Sepolia endpoint), v2 `exact`/eip3009, on 2026-11-06.
- The official server refuses all three client-set terms by matching. The negative control is a
  server we broke on purpose, not a server anyone ships.
- The facilitator settled a payment in a token it had never seen. That is consistent with the
  open-source facilitator code. It is not a claim about any mainnet deployment or any other
  facilitator.

## Files

`official/` and `trusts-accepted/`: `report.json` (harness JSON report), `run.log` (console),
`server.log` (the resource server's output).
