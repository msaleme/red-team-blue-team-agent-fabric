"""Offline regressions for VS-R02 evidence-manifest safety controls."""

import os

# The harness has an explicit live-net import gate. These tests replace every
# network-facing helper before calling a probe.
os.environ.setdefault("AGENTCORE_LIVE_NET_OK", "1")
os.environ.setdefault("AGENTCORE_TESTNET_WALLET", "0x0000000000000000000000000000000000000001")

import protocol_tests.agentcore_payments_harness as harness
from protocol_tests.x402_merchant import CoinbaseFacilitator, PaymentRequirements, parse_x_payment


class FakePaymentClient:
    def __init__(self, created_instrument_id="temporary-b"):
        self.created_instrument_id = created_instrument_id
        self.deleted_instruments = []

    def create_payment_instrument(self, **_kwargs):
        return {"paymentInstrument": {"paymentInstrumentId": self.created_instrument_id}}

    def delete_payment_instrument(self, **kwargs):
        self.deleted_instruments.append(kwargs["paymentInstrumentId"])


def _install_offline_probe(monkeypatch, client):
    sessions = iter((("control-session", "control-session-note"), ("alternate-session", "alternate-session-note")))
    monkeypatch.setattr(harness, "_get_agentcore_client", lambda **_kwargs: client)
    monkeypatch.setattr(harness, "_vsr02_create_session", lambda *_args, **_kwargs: next(sessions))
    monkeypatch.setattr(harness, "_vsr02_delete_session", lambda *_args, **_kwargs: "deleted")
    monkeypatch.setattr(
        harness,
        "_vsr02_sign_probe",
        lambda *_args, **_kwargs: {"status": harness.PROOF_GENERATED, "attempted": "true"},
    )


def test_acp014_aliased_grant_is_not_deleted_or_reported_as_a_leak(monkeypatch):
    """A deduplicated create response must never affect the granted instrument."""
    monkeypatch.setenv(harness.ENV_VSR02_INSTRUMENT_ID, "granted-instrument")
    client = FakePaymentClient(created_instrument_id="granted-instrument")
    _install_offline_probe(monkeypatch, client)

    result = harness.test_agentcore_signtime_cross_instrument_delegation_isolation()
    manifest = result.response_received

    assert client.deleted_instruments == []
    assert manifest["cleanup"]["alternate_instrument"] == "not_deleted_matches_granted_instrument"
    assert manifest["verdict"] == "not_evaluated_instrument_not_distinct"
    assert manifest["alternate_attempt"]["session_create_error"] == "alternate-session-note"
    assert result.passed is False


def test_acp019_whitespace_alternate_agent_uses_the_safe_default(monkeypatch):
    monkeypatch.setenv(harness.ENV_VSR02_AGENT_NAME, "granted-agent")
    monkeypatch.setenv("AGENTCORE_VSR02_ALTERNATE_AGENT_NAME", "  \t")
    client = FakePaymentClient()
    _install_offline_probe(monkeypatch, client)

    result = harness.test_agentcore_signtime_cross_agent_delegation_isolation()

    assert result.agent_id == "granted-agent,vs-r02-attacker-agent"
    assert result.response_received["cross_agent_attempt"]["session_create_error"] == "alternate-session-note"
    assert result.response_received["verdict"] == "delegation_scope_not_agent_bound_at_sign_time"


def test_acp015_alternate_probe_preserves_session_metadata(monkeypatch):
    monkeypatch.setenv(harness.ENV_VSR02_INSTRUMENT_ID, "granted-instrument")
    client = FakePaymentClient(created_instrument_id="temporary-b")
    _install_offline_probe(monkeypatch, client)

    result = harness.test_agentcore_signtime_shared_user_multi_instrument_isolation()

    assert result.response_received["alternate_attempt"]["session_create_error"] == "alternate-session-note"


def test_tier_b_preflight_rejects_requirement_mismatch_without_transport():
    """A wrong recipient must fail locally before a live facilitator call."""
    header = harness._encode_x_payment_with_real_signature({
        "authorization": {
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "10000", "validAfter": "1", "validBefore": "2", "nonce": "0x" + "00" * 32,
        },
        "signature": "0x" + "11" * 65,
    })
    report = CoinbaseFacilitator.preflight_verify_request(
        parse_x_payment(header), PaymentRequirements(pay_to="0x3333333333333333333333333333333333333333"),
    )

    assert report["ok"] is False
    assert "authorization recipient does not match payment requirements" in report["errors"]


def test_tier_b_sign_uses_the_exact_relay_requirement_shape():
    """The signed challenge must not drift from the relay's timeout/domain."""
    class Client:
        def process_payment(self, **kwargs):
            self.kwargs = kwargs
            return {"status": "DENIED"}

    client = Client()
    req = PaymentRequirements(
        pay_to="0x1111111111111111111111111111111111111111",
        max_amount_required="10000", resource="/acp-preflight", max_timeout_seconds=120,
        extra={"name": "USDC", "version": "2"},
    )
    harness._tier_b_sign(
        client, "pm", "session", "user", "agent", "instrument", "99999", "test",
        max_timeout_seconds=5, payment_requirements=req,
    )
    payload = client.kwargs["paymentInput"]["cryptoX402"]["payload"]

    assert payload["maxAmountRequired"] == req.max_amount_required
    assert payload["resource"] == req.resource
    assert payload["payTo"] == req.pay_to
    assert payload["maxTimeoutSeconds"] == req.max_timeout_seconds
    assert payload["extra"] == req.extra
