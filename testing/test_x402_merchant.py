"""Unit tests for the synthetic x402 merchant (VS-R02 Tier B infra).

All tests use the MockFacilitator — no network, no gas. They exercise the same
flows the live ACP-012 (replay) and ACP-016 (aggregate spend) tests will use.
"""

import json
import threading
import urllib.request

from protocol_tests.x402_merchant import (
    PaymentRequirements,
    SyntheticMerchant,
    MockFacilitator,
    parse_x_payment,
    encode_x_payment,
    serve,
)

PAY_TO = "0x7889454DF1EB44B2fA0878179A1845F5b4649286"


def _req():
    return PaymentRequirements(pay_to=PAY_TO, max_amount_required="10000", resource="/paid")


def _payment(nonce="0x01", value="10000", to=PAY_TO):
    return encode_x_payment({"from": "0xAgent", "to": to, "value": value,
                             "nonce": nonce, "validAfter": "0", "validBefore": "9999999999"})


# --- 402 challenge ----------------------------------------------------------

def test_402_challenge_shape():
    m = SyntheticMerchant(_req())
    status, body = m.handle("/paid", None)
    assert status == 402
    assert body["x402Version"] == 1
    accepts = body["accepts"][0]
    assert accepts["payTo"] == PAY_TO
    assert accepts["network"] == "base-sepolia"
    assert accepts["scheme"] == "exact"
    assert accepts["asset"].startswith("0x")


def test_wrong_path_404():
    m = SyntheticMerchant(_req())
    assert m.handle("/other", _payment())[0] == 404


# --- successful settle ------------------------------------------------------

def test_successful_settlement():
    m = SyntheticMerchant(_req())
    status, body = m.handle("/paid", _payment(nonce="0xAA"))
    assert status == 200
    assert body["paid"] is True
    assert body["settlement"]["txHash"].startswith("0x")
    assert len(m.settlements) == 1 and m.settlements[0].success


# --- ACP-012 shape: receipt nonce reuse / replay ----------------------------

def test_replay_same_nonce_refused():
    m = SyntheticMerchant(_req())
    first = m.handle("/paid", _payment(nonce="0xBEEF"))
    second = m.handle("/paid", _payment(nonce="0xBEEF"))  # same nonce again
    assert first[0] == 200
    assert second[0] == 402
    assert "replay" in second[1]["error"].lower() or "nonce" in second[1]["error"].lower()
    # one successful settlement, one refused
    assert sum(1 for s in m.settlements if s.success) == 1


# --- ACP-016 shape: settled-spend aggregation -------------------------------

def test_aggregate_settled_spend():
    m = SyntheticMerchant(_req())
    for i in range(5):
        status, _ = m.handle("/paid", _payment(nonce=f"0x{i:02x}", value="10000"))
        assert status == 200
    # 5 distinct-nonce settlements of 0.01 USDC each = 0.05 USDC
    assert m.total_settled == 50000
    assert sum(1 for s in m.settlements if s.success) == 5


# --- verify-layer rejections ------------------------------------------------

def test_amount_over_max_rejected():
    m = SyntheticMerchant(_req())
    status, body = m.handle("/paid", _payment(nonce="0x10", value="999999"))
    assert status == 402
    assert "amount" in body["error"].lower()
    assert not m.settlements[0].success


def test_undecodable_payment_rejected():
    m = SyntheticMerchant(_req())
    status, _ = m.handle("/paid", "!!!not-base64-json!!!")
    assert status == 402


def test_forced_verify_failure():
    m = SyntheticMerchant(_req(), MockFacilitator(fail_verify=True))
    assert m.handle("/paid", _payment())[0] == 402


# --- payload codec ----------------------------------------------------------

def test_encode_parse_roundtrip():
    p = parse_x_payment(_payment(nonce="0x2a", value="500"))
    assert p.decode_error == ""
    assert p.nonce == "0x2a"
    assert p.value == "500"
    assert p.pay_to == PAY_TO


# --- HTTP wrapper smoke -----------------------------------------------------

def test_http_server_serves_402():
    m = SyntheticMerchant(_req())
    httpd = serve(m, 0)  # ephemeral port
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/paid", timeout=5) as r:
            # 402 is raised as HTTPError by urllib; reaching here would be a 200.
            raise AssertionError("expected 402")
    except urllib.error.HTTPError as e:
        assert e.code == 402
        body = json.loads(e.read())
        assert body["accepts"][0]["payTo"] == PAY_TO
    finally:
        httpd.shutdown()


# --- concurrency: replay guarantee holds under threads (Bugbot #217) --------

def test_concurrent_same_nonce_settles_once():
    # serve() is threaded; without a lock the check-then-add nonce dedup races
    # and the same nonce can settle twice. Fire many threads at one nonce,
    # gated by a barrier to maximize contention, and assert exactly one wins.
    m = SyntheticMerchant(_req())
    n = 50
    barrier = threading.Barrier(n)
    results = []
    lock = threading.Lock()

    def hit():
        barrier.wait()
        status, _ = m.handle("/paid", _payment(nonce="0xRACE", value="10000"))
        with lock:
            results.append(status)

    threads = [threading.Thread(target=hit) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(200) == 1, f"exactly one settle expected, got {results.count(200)}"
    assert results.count(402) == n - 1
    assert sum(1 for s in m.settlements if s.success) == 1
    assert m.total_settled == 10000
