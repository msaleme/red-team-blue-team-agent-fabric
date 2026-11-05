"""An x402 v2 resource server built with the official `x402` Python package, for the live run.

Adapted from x402-foundation/x402 @ 58e667f, examples/python/servers/flask/main.py: EVM only
(Base Sepolia), one route at 0.01 USDC, settlement through the public x402.org facilitator.
It is an independent implementation of the spec; the harness's own code is not used here.

    PAY_TO=0x... python server.py          # serves GET /premium/content on 127.0.0.1:4021

TRUST_CLIENT_ACCEPTED=1 makes it a deliberately broken server: the negative control for
X4-067/068. The official server matches the client's `accepted` against its own `accepts[]`
and verifies against the match. This one verifies and settles against whatever `accepted`
the client sent, so the client sets the price and the recipient. Testnet only; never deploy.
"""
import os

from flask import Flask, jsonify
from x402.http import FacilitatorConfig, HTTPFacilitatorClientSync, PaymentOption
from x402.http.middleware.flask import payment_middleware
from x402.http.types import RouteConfig
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.schemas import AssetAmount, Network
from x402.server import x402ResourceServerSync

PAY_TO = os.environ["PAY_TO"]
NETWORK: Network = "eip155:84532"  # Base Sepolia
FACILITATOR_URL = os.getenv("FACILITATOR_URL", "https://x402.org/facilitator")
PORT = int(os.getenv("PORT", "4021"))

app = Flask(__name__)
server = x402ResourceServerSync(HTTPFacilitatorClientSync(FacilitatorConfig(url=FACILITATOR_URL)))
server.register(NETWORK, ExactEvmServerScheme())
if os.getenv("TRUST_CLIENT_ACCEPTED") == "1":
    print("NEGATIVE CONTROL: this server trusts the client's `accepted` (X4-067/068 must FAIL)",
          flush=True)
    server.find_matching_requirements = lambda available, payload: payload.accepted
payment_middleware(app, server=server, routes={
    "GET /premium/*": RouteConfig(
        accepts=[PaymentOption(
            scheme="exact", pay_to=PAY_TO, network=NETWORK,
            price=AssetAmount(amount="10000",  # 0.01 USDC
                              asset="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                              extra={"name": "USDC", "version": "2"}))],
        mime_type="application/json", description="harness live-run resource"),
})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/premium/content")
def premium():
    return jsonify({"content": "paid"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
