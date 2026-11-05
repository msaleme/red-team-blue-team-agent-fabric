#!/usr/bin/env bash
# Live run of the x402 spec payment probes (X4-058..068) on Base Sepolia. Manual, never CI.
#
#   PAY_TO=0x...  X402_PAYER_KEY_FILE=~/path/to/testnet.key  scripts/x402_spec_live/run.sh [out_dir]
#
# Starts server.py (the official `x402` package, in its own venv so the harness gains no
# dependency on it), runs the spec_payment category against it, and writes the JSON report.
# Spend: a correct server settles 2 payments of 0.01 USDC (X4-058 and one of X4-066's sends).
# The harness's cap (--x402-max-spend) bounds the worst case. It counts every payment that
# COULD settle, refused or not: six of the eleven probes sign one, 59998 atomic units in all,
# so this script sets X402_MAX_SPEND=60000 (0.06 USDC) rather than the harness default of
# 50000, which stops X4-068 before it is signed (seen live 2026-11-05).
#
# TRUST_CLIENT_ACCEPTED=1 runs the negative control instead (see server.py): X4-067 and X4-068
# must FAIL, and each settles one payment on the client's terms, so the run spends up to
# 0.0399 USDC (0.0001 less than four full payments; X4-068's goes back to the payer).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${1:-$REPO/reports/x402-spec-live-$(date -u +%F)}"
VENV="${X402_LIVE_VENV:-$HOME/.cache/agent-security-harness/x402-live-venv}"
PORT="${PORT:-4021}"
: "${PAY_TO:?set PAY_TO to the address that receives the test payments}"
: "${X402_PAYER_KEY_FILE:?set X402_PAYER_KEY_FILE to a funded testnet key file}"
PY="${HARNESS_PYTHON:-python3}"

[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
# httpx: the facilitator client imports it lazily, and without it every request is a 500.
"$VENV/bin/pip" install -q "x402[flask,evm,httpx]==2.26.0"
mkdir -p "$OUT"
PAY_TO="$PAY_TO" PORT="$PORT" TRUST_CLIENT_ACCEPTED="${TRUST_CLIENT_ACCEPTED:-0}" "$VENV/bin/python" "$HERE/server.py" > "$OUT/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break
  "$PY" -c 'import time; time.sleep(1)'
done
curl -sf "http://127.0.0.1:$PORT/health" >/dev/null || { echo "server did not start; see $OUT/server.log" >&2; exit 2; }

cd "$REPO"
set +e
"$PY" -m protocol_tests.x402_harness --url "http://127.0.0.1:$PORT" --paid-path /premium/content \
  --categories spec_payment --x402-max-spend "${X402_MAX_SPEND:-60000}" \
  --report "$OUT/report.json" 2>&1 | tee "$OUT/run.log"
rc=${PIPESTATUS[0]}
set -e
echo "exit $rc; report $OUT/report.json"
exit "$rc"
