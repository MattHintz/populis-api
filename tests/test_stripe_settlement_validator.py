from __future__ import annotations

import pytest
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.release_metadata import ReleaseMetadata
from solslot_api.validator_quorum import StripeSettlementClaim
from solslot_api.validator_service import (
    ValidatorEvidenceError,
    _validate_stripe_purchase_method,
    verify_stripe_settlement_claim,
)
from solslot_api.validator_settings import ValidatorSettings
from solslot_puzzles.mint_publish_driver import deed_singleton_struct
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentAttestationV1,
    PaymentResolution,
    PaymentTransition,
)
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseKind,
    STRIPE_PAYMENT_PROVIDER_ID,
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    StripeSettlementReceiptV1,
    build_stripe_purchase_artifact,
    build_stripe_pending_attestation,
    payment_attestation_to_json,
    stripe_receipt_to_json,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PrimaryMintTermsV3,
    build_stripe_primary_offer_v5,
    build_stripe_receipt_spend,
    make_mint_offer_v5_inner,
    make_stripe_receipt_puzzle,
    prepare_stripe_receipt_offer,
    validator_roster_root,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


class _PurchaseKindOnlyArtifact:
    def __init__(self, purchase_kind: PurchaseKind) -> None:
        self.purchase_kind = purchase_kind


def test_validator_rejects_direct_ach_even_if_upstream_is_bypassed() -> None:
    with pytest.raises(
        ValidatorEvidenceError,
        match="only for refundable presales",
    ):
        _validate_stripe_purchase_method(
            artifact=_PurchaseKindOnlyArtifact(PurchaseKind.DIRECT),
            method_family=StripeMethodFamily.US_BANK_ACCOUNT,
        )
    _validate_stripe_purchase_method(
        artifact=_PurchaseKindOnlyArtifact(PurchaseKind.PRESALE),
        method_family=StripeMethodFamily.US_BANK_ACCOUNT,
    )


def _b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def _fixture():
    validator_keys = tuple(
        AugSchemeMPL.key_gen(bytes([value]) * 32)
        for value in (81, 82, 83)
    )
    validator_pubkeys = tuple(
        bytes(key.get_g1()) for key in validator_keys
    )
    settings = ValidatorSettings(
        signer_index=0,
        seed_file="/run/credentials/unused-test-seed",
        network="testnet11",
        evm_rpc_url="https://sepolia.example.invalid",
        bridge_policy_hash="0x" + "91" * 32,
        roster_pubkeys=[
            "0x" + value.hex() for value in validator_pubkeys
        ],
        evm_forwarder_address="0x" + "92" * 20,
        evm_verifier_adapter_address="0x" + "93" * 20,
        evm_attestation_emitter_address="0x" + "94" * 20,
        stripe_read_only_key_file="/run/credentials/stripe-validator-key",
        stripe_account_id="acct_rc24",
        stripe_api_version="2026-02-25.clover",
        stripe_livemode=False,
    )
    now = 2_000_000_000
    vault_launcher = _b32(7)
    treasury = _b32(8)
    purchase = build_stripe_purchase_artifact(
        network="testnet11",
        collection_id=_b32(1),
        deed_launcher_id=_b32(2),
        metadata_root=_b32(3),
        metadata_anchor_id=_b32(4),
        share_ppm=40_000,
        base_amount_minor=22_900,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=treasury,
        zkpassport_root=_b32(6),
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        authorization_nonce=_b32(9),
        authorization_expires_at=now + 500_000,
        quote_expires_at=now + 400_000,
    )
    evidence = StripeSettlementEvidenceV1(
        stripe_account_id="acct_rc24",
        livemode=False,
        payment_intent_id="pi_rc24",
        event_id="evt_rc24",
        amount_minor=purchase.subtotal_minor,
        currency="usd",
        method_family=StripeMethodFamily.CARD,
        funding_type=StripeFundingType.DEBIT,
        processing_charge_minor=0,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=now - 60,
    )
    pending = build_stripe_pending_attestation(
        artifact=purchase,
        evidence=evidence,
        observed_at=evidence.observed_at - 1,
    )
    succeeded = PaymentAttestationV1(
        purchase_id=purchase.purchase_id,
        artifact_hash=purchase.artifact_hash,
        transition=PaymentTransition.SUCCEEDED,
        resolution=PaymentResolution.DELIVER,
        provider_id=STRIPE_PAYMENT_PROVIDER_ID,
        external_reference_hash=evidence.payment_reference_hash,
        evidence_hash=evidence.evidence_hash,
        previous_attestation_hash=pending.attestation_hash,
        observed_at=evidence.observed_at,
    )
    receipt = StripeSettlementReceiptV1(
        artifact=purchase,
        evidence=evidence,
        attestation=succeeded,
        validator_roster_root=validator_roster_root(validator_pubkeys),
        validator_threshold=2,
        receipt_nonce=_b32(11),
        expires_at=now + 100_000,
    )
    reservation = InventoryReservationV1(
        artifact=purchase,
        expires_at=now + 200_000,
    )
    smart_deed_inner_hash = _b32(12)
    terms = PrimaryMintTermsV3.for_artifact(
        artifact=purchase,
        smart_deed_inner_hash=smart_deed_inner_hash,
        protocol_puzhash=treasury,
        validator_pubkeys=validator_pubkeys,
    )
    did_launcher = _b32(13)
    deed_struct = deed_singleton_struct(
        deed_launcher_id=purchase.deed_launcher_id,
        protocol_did_singleton_struct=singleton_struct(did_launcher),
    )
    reserved_inner = make_mint_offer_v5_inner(terms, reservation)
    deed_puzzle = SINGLETON_MOD.curry(deed_struct, reserved_inner)
    deed_coin = Coin(
        _b32(14),
        bytes32(deed_puzzle.get_tree_hash()),
        uint64(1),
    )
    deed_lineage = LineageProof(
        _b32(15),
        bytes32(reserved_inner.get_tree_hash()),
        uint64(1),
    )
    receipt_puzzle = make_stripe_receipt_puzzle(
        receipt=receipt,
        validator_pubkeys=validator_pubkeys,
    )
    receipt_coin = Coin(
        _b32(16),
        bytes32(receipt_puzzle.get_tree_hash()),
        uint64(1),
    )
    receipt_spend = build_stripe_receipt_spend(
        receipt_coin=receipt_coin,
        receipt=receipt,
        validator_pubkeys=validator_pubkeys,
        signer_indices=(0, 1),
    )
    receipt_offer = prepare_stripe_receipt_offer(
        receipt_spend=receipt_spend,
        receipt=receipt,
        terms=terms,
    )
    settlement = build_stripe_primary_offer_v5(
        receipt_offer=receipt_offer,
        receipt_coin=receipt_coin,
        receipt=receipt,
        deed_coin=deed_coin,
        deed_singleton_struct=deed_struct,
        lineage_proof=deed_lineage,
        terms=terms,
        reservation=reservation,
    )
    output = compute_additions(settlement.deed_spend)[0]
    owner_key = AugSchemeMPL.key_gen(b"o" * 32).get_g1()
    genesis_hash = "0x" + "a1" * 32
    claim = StripeSettlementClaim(
        network="testnet11",
        genesis_artifact_hash=genesis_hash,
        stripe_receipt=stripe_receipt_to_json(receipt),
        pending_attestation=payment_attestation_to_json(pending),
        reservation_expires_at=reservation.expires_at,
        receipt_coin_id="0x" + bytes(receipt_coin.name()).hex(),
        receipt_puzzle_hash="0x" + bytes(receipt_coin.puzzle_hash).hex(),
        deed_coin_id="0x" + bytes(deed_coin.name()).hex(),
        deed_puzzle_hash="0x" + bytes(deed_coin.puzzle_hash).hex(),
        expected_deed_output_coin_id="0x" + bytes(output.name()).hex(),
        expected_deed_output_puzzle_hash=(
            "0x" + bytes(output.puzzle_hash).hex()
        ),
        smart_deed_inner_hash="0x" + bytes(smart_deed_inner_hash).hex(),
        protocol_puzzle_hash="0x" + bytes(treasury).hex(),
        credential_vault_coin_id="0x" + "b1" * 32,
        credential_identity_root="0x"
        + bytes(purchase.zkpassport_root).hex(),
        credential_policy_version=2,
        credential_bridge_policy_hash="0x" + "b2" * 32,
        credential_owner_auth_type=1,
        credential_owner_key="0x" + bytes(owner_key).hex(),
    )
    artifact = {
        "artifactHash": genesis_hash,
        "bridgePolicy": {"policyHash": claim.credential_bridge_policy_hash},
        "validatorSet": {
            "threshold": 2,
            "pubkeys": settings.roster_pubkeys,
        },
        "launcherIds": {
            "did": "0x" + bytes(did_launcher).hex(),
            "pool": "0x" + "c1" * 32,
        },
        "puzzleHashes": {
            "protocolTreasuryPuzzleHash": "0x" + bytes(treasury).hex(),
        },
    }
    release = ReleaseMetadata(
        apiCommit="a" * 40,
        protocolCommit="b" * 40,
        builtAtUtc="2026-07-30T00:00:00Z",
        packageName="solslot-api",
        appModule="solslot_api.app:app",
    )
    receipt_record = {
        "coin": {
            "parent_coin_info": "0x"
            + bytes(receipt_coin.parent_coin_info).hex(),
            "puzzle_hash": "0x" + bytes(receipt_coin.puzzle_hash).hex(),
            "amount": 1,
        },
        "confirmed_block_index": 100,
        "spent_block_index": 0,
        "spent": False,
    }
    return (
        settings,
        claim,
        artifact,
        release,
        deed_coin,
        deed_lineage,
        receipt_record,
        receipt,
        now,
    )


def test_stripe_settlement_rederives_reserved_deed_and_output(
    monkeypatch,
) -> None:
    (
        settings,
        claim,
        artifact,
        release,
        deed_coin,
        deed_lineage,
        receipt_record,
        receipt,
        now,
    ) = _fixture()
    monkeypatch.setattr(
        "solslot_api.validator_service.time.time",
        lambda: now,
    )
    monkeypatch.setattr(
        "solslot_api.validator_service.load_validator_artifact",
        lambda _settings: (artifact, release),
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._verify_purchase_credential",
        lambda *_args, **_kwargs: (
            artifact["launcherIds"],
            artifact["puzzleHashes"],
            tuple(
                bytes.fromhex(value[2:])
                for value in settings.roster_pubkeys
            ),
        ),
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._confirmed_coin_and_lineage",
        lambda *_args, **_kwargs: (deed_coin, deed_lineage),
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._fetch_coin",
        lambda *_args, **_kwargs: receipt_record,
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._stripe_retrieved_evidence",
        lambda *_args, **_kwargs: receipt.evidence,
    )

    verify_stripe_settlement_claim(
        settings,
        claim,
        claim.canonical_hash(),
    )

    redirected = claim.model_copy(
        update={"expected_deed_output_coin_id": "0x" + "ff" * 32}
    )
    with pytest.raises(ValidatorEvidenceError, match="not canonical"):
        verify_stripe_settlement_claim(
            settings,
            redirected,
            redirected.canonical_hash(),
        )


def test_stripe_settlement_rejects_a_different_reservation(
    monkeypatch,
) -> None:
    (
        settings,
        claim,
        artifact,
        release,
        deed_coin,
        deed_lineage,
        _receipt_record,
        _receipt,
        now,
    ) = _fixture()
    monkeypatch.setattr(
        "solslot_api.validator_service.time.time",
        lambda: now,
    )
    monkeypatch.setattr(
        "solslot_api.validator_service.load_validator_artifact",
        lambda _settings: (artifact, release),
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._verify_purchase_credential",
        lambda *_args, **_kwargs: (
            artifact["launcherIds"],
            artifact["puzzleHashes"],
            tuple(
                bytes.fromhex(value[2:])
                for value in settings.roster_pubkeys
            ),
        ),
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._confirmed_coin_and_lineage",
        lambda *_args, **_kwargs: (deed_coin, deed_lineage),
    )
    altered = claim.model_copy(
        update={"reservation_expires_at": claim.reservation_expires_at + 1}
    )
    with pytest.raises(
        ValidatorEvidenceError,
        match="puzzle does not match",
    ):
        verify_stripe_settlement_claim(
            settings,
            altered,
            altered.canonical_hash(),
        )
