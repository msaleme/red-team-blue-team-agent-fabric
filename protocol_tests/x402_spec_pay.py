"""Signed payments in the published x402 format, for the spec probes in x402_harness.

The x402 module's original probes send a pre-spec format (`X-Payment-Authorization`), which a
server built to the published transport never reads (see `spec_challenge` in x402_harness and
testing/test_x402_spec_target.py). This module builds what such a server does read:

    v2: `PAYMENT-SIGNATURE` header, base64 JSON
        {"x402Version": 2, "resource": {...}, "accepted": {...},
         "payload": {"signature": "0x...", "authorization": {...}}}
    v1: `X-PAYMENT` header, base64 JSON
        {"x402Version": 1, "scheme": "exact", "network": "base-sepolia", "payload": {...}}

The `exact` scheme on EVM with the default `eip3009` transfer method: the client signs an
EIP-712 `TransferWithAuthorization` over the token contract's domain (`extra.name`,
`extra.version`, the chain ID, the `asset` address). Sources: x402-foundation/x402 @ 58e667f,
specs/schemes/exact/scheme_exact_evm.md, specs/x402-specification-v2.md §5.2,
specs/x402-specification-v1.md, specs/transports-v{1,2}/http.md.

Guards, each failing closed with a reason the caller reports as INCONCLUSIVE:
  - testnet chain IDs only; a mainnet or unknown network is never signed for;
  - a per-run cap on the total value of authorizations that could settle;
  - no key, or no `eth-account` installed (`pip install agent-security-harness[x402-pay]`).
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
from pathlib import Path

#: Chain IDs this module will sign for. Testnets only: a signed EIP-3009 authorization is a
#: bearer instrument for its value, and the probes hand authorizations to the target.
TESTNET_CHAIN_IDS = frozenset({
    84532,      # Base Sepolia
    11155111,   # Ethereum Sepolia
    43113,      # Avalanche Fuji
    80002,      # Polygon Amoy
    421614,     # Arbitrum Sepolia
    11155420,   # OP Sepolia
})

#: v1 network names (specs/x402-specification-v1.md uses names, not CAIP-2 IDs). Mainnets are
#: listed so they are recognised and refused, not mistaken for unknown.
V1_NETWORKS = {
    "base-sepolia": 84532, "sepolia": 11155111, "ethereum-sepolia": 11155111,
    "avalanche-fuji": 43113, "polygon-amoy": 80002, "arbitrum-sepolia": 421614,
    "optimism-sepolia": 11155420,
    "base": 8453, "ethereum": 1, "ethereum-mainnet": 1, "avalanche": 43114, "polygon": 137,
    "arbitrum": 42161, "optimism": 10,
}

#: Default cap on the total value, in the asset's atomic units, of authorizations this payer
#: signs that could settle on chain. 50000 = 0.05 USDC (6 decimals).
DEFAULT_MAX_SPEND_ATOMIC = 50_000

TRANSFER_WITH_AUTHORIZATION = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]

KEY_INSTALL_HINT = "pip install 'agent-security-harness[x402-pay]'"


class PaymentRefused(Exception):
    """This module declined to sign. The message is the reason, for an INCONCLUSIVE row."""


def chain_id(network: str) -> int | None:
    """The EVM chain ID for a v2 CAIP-2 id (`eip155:84532`) or a v1 network name."""
    if not isinstance(network, str):
        return None
    if network.startswith("eip155:"):
        tail = network.split(":", 1)[1]
        return int(tail) if tail.isdigit() else None
    return V1_NETWORKS.get(network)


def amount_of(accept: dict, version: int) -> str | None:
    value = accept.get("amount" if version == 2 else "maxAmountRequired")
    return str(value) if value is not None and str(value).isdigit() else None


def typed_data(domain_name: str, domain_version: str, chain: int, asset: str,
               message: dict) -> dict:
    """The full EIP-712 structure for one TransferWithAuthorization."""
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": TRANSFER_WITH_AUTHORIZATION,
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {"name": domain_name, "version": domain_version, "chainId": chain,
                   "verifyingContract": asset},
        "message": {
            "from": message["from"], "to": message["to"], "value": int(message["value"]),
            "validAfter": int(message["validAfter"]), "validBefore": int(message["validBefore"]),
            "nonce": bytes.fromhex(message["nonce"][2:]),
        },
    }


def encode_header(doc: dict) -> str:
    return base64.b64encode(json.dumps(doc, separators=(",", ":")).encode()).decode()


def decode_header(value: str) -> dict | None:
    try:
        doc = json.loads(base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, TypeError):
        return None
    return doc if isinstance(doc, dict) else None


def payment_header_name(version: int) -> str:
    return "PAYMENT-SIGNATURE" if version == 2 else "X-PAYMENT"


def settlement_header_name(version: int) -> str:
    return "payment-response" if version == 2 else "x-payment-response"


class SignedPayment:
    """One payment payload, its header, and whether it could settle on chain."""

    def __init__(self, version: int, document: dict, settleable: bool):
        self.version = version
        self.document = document
        self.settleable = settleable

    @property
    def header(self) -> dict:
        return {payment_header_name(self.version): encode_header(self.document)}

    @property
    def authorization(self) -> dict:
        return self.document["payload"]["authorization"]

    def edited(self, **authorization_fields) -> SignedPayment:
        """A copy with authorization fields changed AFTER signing (the signature is kept)."""
        doc = json.loads(json.dumps(self.document))
        doc["payload"]["authorization"].update(
            {k: v if k in ("from", "to") else str(v) for k, v in authorization_fields.items()})
        return SignedPayment(self.version, doc, settleable=False)

    def with_signature(self, signature: str) -> SignedPayment:
        doc = json.loads(json.dumps(self.document))
        doc["payload"]["signature"] = signature
        return SignedPayment(self.version, doc, settleable=False)


class SpecPayer:
    """Signs `exact`/`eip3009` payments with one testnet key, under a spend cap."""

    def __init__(self, private_key: str, max_spend_atomic: int = DEFAULT_MAX_SPEND_ATOMIC):
        try:
            from eth_account import Account
        except ImportError as e:  # pragma: no cover - exercised only without the extra
            raise PaymentRefused(f"eth-account is not installed ({KEY_INSTALL_HINT})") from e
        self._account = Account.from_key(private_key)
        self.max_spend_atomic = int(max_spend_atomic)
        self.committed_atomic = 0
        self._lock = threading.Lock()

    @property
    def address(self) -> str:
        return self._account.address

    def pay(self, version: int, accept: dict, resource: dict | None = None, *,
            to: str | None = None, value: int | None = None,
            valid_after: int | None = None, valid_before: int | None = None,
            sign_chain_id: int | None = None, altered_before_sending: bool = False
            ) -> SignedPayment:
        """A signed payment for *accept*, with any one property overridden by the caller.

        *altered_before_sending*: the caller will corrupt or edit the payload before it
        leaves the harness, so as sent it cannot settle and is not counted against the cap.

        Raises PaymentRefused when the requirement names a network that is not a known
        testnet, gives no EIP-712 domain, or would push the run past its spend cap.
        """
        from eth_account import Account

        if accept.get("scheme") != "exact":
            raise PaymentRefused(f"scheme {accept.get('scheme')!r} is not `exact`")
        chain = chain_id(accept.get("network", ""))
        if chain is None:
            raise PaymentRefused(f"network {accept.get('network')!r} is not a known EVM network")
        if chain not in TESTNET_CHAIN_IDS:
            raise PaymentRefused(f"network {accept.get('network')!r} (chain {chain}) is not a "
                                 "testnet; the harness signs payments on testnets only")
        extra = accept.get("extra") or {}
        method = extra.get("assetTransferMethod", "eip3009")
        if method != "eip3009":
            raise PaymentRefused(f"assetTransferMethod {method!r} is not supported (eip3009 only)")
        if not extra.get("name") or not extra.get("version"):
            raise PaymentRefused("the requirement gives no EIP-712 domain (extra.name / extra.version)")
        required = amount_of(accept, version)
        if required is None:
            raise PaymentRefused("the requirement has no integer amount")

        now = int(time.time())
        message = {
            "from": self.address,
            "to": to if to is not None else accept["payTo"],
            "value": str(value if value is not None else int(required)),
            "validAfter": str(valid_after if valid_after is not None else now - 600),
            "validBefore": str(valid_before if valid_before is not None
                               else now + int(accept.get("maxTimeoutSeconds") or 60)),
            "nonce": "0x" + secrets.token_hex(32),
        }
        signing_chain = sign_chain_id if sign_chain_id is not None else chain
        if signing_chain not in TESTNET_CHAIN_IDS:
            raise PaymentRefused(f"chain {signing_chain} is not a testnet")
        # Could this authorization move funds on the target chain? Count it against the cap.
        settleable = (signing_chain == chain and int(message["validBefore"]) > now
                      and not altered_before_sending)
        if settleable:
            with self._lock:
                if self.committed_atomic + int(message["value"]) > self.max_spend_atomic:
                    raise PaymentRefused(
                        f"spend cap: {self.committed_atomic} + {message['value']} would exceed "
                        f"{self.max_spend_atomic} atomic units for this run")
                self.committed_atomic += int(message["value"])

        signed = Account.sign_typed_data(
            self._account.key,
            full_message=typed_data(extra["name"], extra["version"], signing_chain,
                                    accept["asset"], message))
        payload = {"signature": "0x" + bytes(signed.signature).hex(), "authorization": message}
        if version == 2:
            doc = {"x402Version": 2, "accepted": accept, "payload": payload}
            if resource:
                doc["resource"] = resource
        else:
            doc = {"x402Version": 1, "scheme": "exact", "network": accept["network"],
                   "payload": payload}
        return SignedPayment(version, doc, settleable)


def recover_signer(document: dict, accept: dict, sign_chain_id: int | None = None) -> str | None:
    """The address that signed *document*'s authorization, under *accept*'s domain."""
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    extra = accept.get("extra") or {}
    chain = sign_chain_id if sign_chain_id is not None else chain_id(accept.get("network", ""))
    try:
        auth = document["payload"]["authorization"]
        data = typed_data(extra["name"], extra["version"], chain, accept["asset"], auth)
        return Account.recover_message(encode_typed_data(full_message=data),
                                       signature=document["payload"]["signature"])
    except Exception:  # noqa: BLE001 - any failure to recover is "no signer"
        return None


def load_payer(key_file: str | None = None, max_spend_atomic: int = DEFAULT_MAX_SPEND_ATOMIC,
               environ: dict | None = None) -> SpecPayer | str:
    """A payer from a key file, or from X402_PAYER_KEY_FILE / X402_PAYER_PRIVATE_KEY.

    Returns the reason string instead of a payer when none is configured, so the probes can
    report it. The key itself is never printed or logged.
    """
    env = os.environ if environ is None else environ
    path = key_file or env.get("X402_PAYER_KEY_FILE")
    key = None
    if path:
        try:
            key = Path(path).expanduser().read_text().strip()
        except OSError as e:
            return f"payer key file could not be read ({e.__class__.__name__})"
    elif env.get("X402_PAYER_PRIVATE_KEY"):
        key = env["X402_PAYER_PRIVATE_KEY"].strip()
    if not key:
        return ("no payer key: the spec probes need a funded testnet key "
                "(--x402-payer-key-file or X402_PAYER_KEY_FILE)")
    try:
        return SpecPayer(key, max_spend_atomic)
    except PaymentRefused as e:
        return str(e)
    except Exception as e:  # noqa: BLE001 - reported as a reason, never raised
        return f"payer key is not a valid secp256k1 key ({e.__class__.__name__})"
