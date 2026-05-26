#!/usr/bin/env bash
# VS-R01 environment setup — source this before running VS-R01 stubs.
# Updated 2026-05-25.

# -- Python venv (created with: python3 -m venv ~/venvs/harness) --
source ~/venvs/harness/bin/activate

# -- AWS profile --
export AWS_PROFILE=harness-testnet
export AWS_DEFAULT_REGION=us-east-1

# -- Surface 2 (AWS Bedrock AgentCore Payments) safety guards --
export AGENTCORE_LIVE_NET_OK=1
export AGENTCORE_ALLOW_TESTNET=1
# CDP Server Wallet EVM account on Base Sepolia (created 2026-05-25)
# Name: vsr01testnet — secret material in /home/mikes/CDP/cdp_wallet_secret.txt
export AGENTCORE_TESTNET_WALLET="0x0E88cF39132336a4A9a7C0D37C1253Fa321F557B"

# -- AgentCore PaymentManager (created 2026-05-25 via scripts/vs-r01-env.sh setup) --
export AGENTCORE_PAYMENT_MANAGER_ID="vsr01testmanager-5wnc0eppzd"
export AGENTCORE_PAYMENT_MANAGER_ARN="arn:aws:bedrock-agentcore:us-east-1:447134825007:payment-manager/vsr01testmanager-5wnc0eppzd"
export AGENTCORE_PAYMENT_ROLE_ARN="arn:aws:iam::447134825007:role/BedrockAgentCorePaymentRole"

# -- AgentCore CoinbaseCDP CredentialProvider (created 2026-05-25) --
export AGENTCORE_CRED_PROVIDER_NAME="vsr01cdpcreds"
export AGENTCORE_CRED_PROVIDER_ARN="arn:aws:bedrock-agentcore:us-east-1:447134825007:token-vault/default/paymentcredentialprovider/vsr01cdpcreds"

# -- AgentCore PaymentConnector (created 2026-05-25, status READY) --
export AGENTCORE_PAYMENT_CONNECTOR_ID="vsr01cdpconnector-35v7gsfbtn"

# -- CDP credential file paths (read by harness via env, never echoed) --
export CDP_API_KEY_FILE="/home/mikes/CDP/cdp_api_key.json"
export CDP_WALLET_SECRET_FILE="/home/mikes/CDP/cdp_wallet_secret.txt"

# -- Surface 1 (Anthropic MCP Tunnels + Self-Hosted Sandboxes) safety guards --
# Only set these when you have research-preview access AND have read the safety
# scope in protocol_tests/mcp_tunnel_harness.py docstring.
# export MCP_TUNNEL_PREVIEW_OK=1
# export SANDBOX_TEST_OK=1

# -- Optional payment provider credentials (TODO: set when provider chosen) --
# Coinbase CDP testnet:
# export AGENTCORE_CDP_API_KEY=...
# export AGENTCORE_CDP_API_SECRET=...
# Stripe Privy testnet:
# export AGENTCORE_PRIVY_TESTNET_KEY=...

echo "VS-R01 environment ready."
echo "  venv:           $(which python)"
echo "  aws profile:    $AWS_PROFILE ($AWS_DEFAULT_REGION)"
echo "  agentcore:      live=$AGENTCORE_LIVE_NET_OK testnet=$AGENTCORE_ALLOW_TESTNET wallet=${AGENTCORE_TESTNET_WALLET:0:10}..."
echo
echo "Next: pytest --collect-only -q protocol_tests/agentcore_payments_harness.py"
