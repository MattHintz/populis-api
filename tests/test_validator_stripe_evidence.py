from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32

from solslot_api.validator_service import (
    ValidatorEvidenceError,
    _verify_stripe_provider_evidence,
)
from solslot_api.validator_settings import ValidatorSettings
from solslot_puzzles.payment_artifacts_v3 import (
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    build_stripe_purchase_artifact_v3,
    purchase_artifact_v3_to_json,
    stripe_settlement_evidence_to_json,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


def _hex32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def _settings(tmp_path) -> ValidatorSettings:
    restricted_key = tmp_path / "stripe.read.key"
    restricted_key.write_text("rk_test_" + "a" * 24, encoding="ascii")
    restricted_key.chmod(0o600)
    keys = tuple(
        AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1()
        for index in (1, 2, 3)
    )
    return ValidatorSettings(
        signer_index=0,
        seed_file=str(tmp_path / "unused.seed"),
        evm_rpc_url="https://sepolia.example",
        bridge_policy_hash="0x" + "01" * 32,
        roster_pubkeys=["0x" + bytes(key).hex() for key in keys],
        evm_forwarder_address="0x" + "02" * 20,
        evm_verifier_adapter_address="0x" + "03" * 20,
        evm_attestation_emitter_address="0x" + "04" * 20,
        stripe_settlement_enabled=True,
        stripe_account_id="acct_test_solslot",
        stripe_mode="test",
        stripe_restricted_key_file=str(restricted_key),
    )


def _purchase_and_evidence(now: int):
    vault = _hex32(10)
    purchase = build_stripe_purchase_artifact_v3(
        network="testnet11",
        collection_id=_hex32(11),
        deed_launcher_id=_hex32(12),
        metadata_root=_hex32(13),
        metadata_anchor_id=_hex32(14),
        share_ppm=50_000,
        base_usd_amount_minor=10_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=_hex32(15),
        zkpassport_root=_hex32(16),
        vault_launcher_id=vault,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault),
        authorization_nonce=_hex32(17),
        authorization_expires_at=now + 600,
        quote_expires_at=now + 300,
    )
    evidence = StripeSettlementEvidenceV1(
        stripe_account_id="acct_test_solslot",
        livemode=False,
        payment_intent_id="pi_exact_purchase",
        event_id="evt_exact_purchase",
        amount_minor=purchase.subtotal_minor,
        currency="usd",
        method_family=StripeMethodFamily.US_BANK_ACCOUNT,
        funding_type=StripeFundingType.BANK_ACCOUNT,
        processing_charge_minor=0,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=now + 20,
    )
    return purchase, evidence


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self.payload


class _StripeClient:
    responses: dict[str, dict[str, object]] = {}

    def __init__(self, **_kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def get(self, path: str, **_kwargs) -> _Response:
        return _Response(self.responses[path])


def test_validator_requires_exact_purchase_artifact_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    now = int(time.time())
    settings = _settings(tmp_path)
    purchase, evidence = _purchase_and_evidence(now)
    purchase_json = purchase_artifact_v3_to_json(purchase)
    evidence_json = stripe_settlement_evidence_to_json(evidence)
    metadata = {
        "protocol_purchase_id": "0x" + purchase.purchase_id.hex(),
        "purchase_artifact_hash": "0x" + purchase.artifact_hash.hex(),
        "protocol_artifact_hash": "0x" + "ff" * 32,
    }
    _StripeClient.responses = {
        f"/v1/payment_intents/{evidence.payment_intent_id}": {
            "id": evidence.payment_intent_id,
            "livemode": False,
            "status": "succeeded",
            "created": now + 10,
            "currency": "usd",
            "amount_received": evidence.amount_minor,
            "metadata": metadata,
            "latest_charge": {
                "payment_method_details": {"type": "us_bank_account"},
                "refunded": False,
                "amount_refunded": 0,
                "disputed": False,
            },
        },
        f"/v1/events/{evidence.event_id}": {
            "id": evidence.event_id,
            "type": "payment_intent.succeeded",
            "livemode": False,
            "data": {"object": {"id": evidence.payment_intent_id}},
        },
    }
    monkeypatch.setattr(
        "solslot_api.validator_service.httpx.Client", _StripeClient
    )
    claim = SimpleNamespace(
        purchase_artifact=purchase_json,
        stripe_evidence=evidence_json,
    )

    _verify_stripe_provider_evidence(settings, claim)

    del metadata["purchase_artifact_hash"]
    with pytest.raises(
        ValidatorEvidenceError,
        match="differs from the purchase receipt",
    ):
        _verify_stripe_provider_evidence(settings, claim)
