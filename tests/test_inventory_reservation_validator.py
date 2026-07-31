from __future__ import annotations

import pytest
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia_rs import AugSchemeMPL, Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.release_metadata import ReleaseMetadata
from solslot_api.validator_quorum import InventoryReservationClaim
from solslot_api.validator_service import (
    ValidatorEvidenceError,
    verify_inventory_reservation_claim,
)
from solslot_api.validator_settings import ValidatorSettings
from solslot_puzzles.mint_publish_driver import deed_singleton_struct
from solslot_puzzles.payment_artifacts_v3 import (
    build_stripe_purchase_artifact,
    purchase_artifact_to_json,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PrimaryMintTermsV3,
    build_inventory_reservation_spend,
    make_inventory_available_inner,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


def _fixture():
    validator_keys = tuple(
        AugSchemeMPL.key_gen(bytes([value]) * 32)
        for value in (71, 72, 73)
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
    )
    vault_launcher = bytes32(b"v" * 32)
    treasury = bytes32(b"t" * 32)
    purchase = build_stripe_purchase_artifact(
        network="testnet11",
        collection_id=bytes32(b"c" * 32),
        deed_launcher_id=bytes32(b"d" * 32),
        metadata_root=bytes32(b"m" * 32),
        metadata_anchor_id=bytes32.zeros,
        share_ppm=40_000,
        base_amount_minor=10_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=treasury,
        zkpassport_root=bytes32(b"z" * 32),
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        authorization_nonce=bytes32(b"n" * 32),
        authorization_expires_at=2_000_000_100,
        quote_expires_at=2_000_000_000,
    )
    smart_deed_inner_hash = bytes32(b"s" * 32)
    terms = PrimaryMintTermsV3.for_artifact(
        artifact=purchase,
        smart_deed_inner_hash=smart_deed_inner_hash,
        protocol_puzhash=treasury,
        validator_pubkeys=validator_pubkeys,
    )
    did_launcher = bytes32(b"i" * 32)
    deed_struct = deed_singleton_struct(
        deed_launcher_id=purchase.deed_launcher_id,
        protocol_did_singleton_struct=singleton_struct(did_launcher),
    )
    available_puzzle = SINGLETON_MOD.curry(
        deed_struct,
        make_inventory_available_inner(terms),
    )
    available_coin = Coin(
        bytes32(b"p" * 32),
        bytes32(available_puzzle.get_tree_hash()),
        uint64(1),
    )
    reservation = InventoryReservationV1(
        artifact=purchase,
        expires_at=1_999_999_900,
    )
    derived = build_inventory_reservation_spend(
        available_coin=available_coin,
        deed_singleton_struct=deed_struct,
        lineage_proof=LineageProof(),
        reservation=reservation,
        signer_indices=(0, 1),
        terms=terms,
    )
    owner_key = AugSchemeMPL.key_gen(b"o" * 32).get_g1()
    genesis_hash = "0x" + "a1" * 32
    claim = InventoryReservationClaim(
        network="testnet11",
        genesis_artifact_hash=genesis_hash,
        purchase_artifact=purchase_artifact_to_json(purchase),
        reservation_expires_at=reservation.expires_at,
        available_coin_id="0x" + bytes(available_coin.name()).hex(),
        available_puzzle_hash="0x"
        + bytes(available_coin.puzzle_hash).hex(),
        reserved_coin_id="0x" + bytes(derived.reserved_coin.name()).hex(),
        reserved_puzzle_hash="0x"
        + bytes(derived.reserved_coin.puzzle_hash).hex(),
        smart_deed_inner_hash="0x" + bytes(smart_deed_inner_hash).hex(),
        protocol_puzzle_hash="0x" + bytes(treasury).hex(),
        credential_vault_coin_id="0x" + "b1" * 32,
        credential_identity_root="0x"
        + bytes(purchase.zkpassport_root).hex(),
        credential_policy_version=2,
        credential_bridge_policy_hash="0x" + "b2" * 32,
        credential_owner_auth_type=1,
        credential_owner_key="0x" + bytes(owner_key).hex(),
        validator_message="0x"
        + bytes(derived.validator_message).hex(),
    )
    artifact = {
        "artifactHash": genesis_hash,
        "launcherIds": {
            "did": "0x" + bytes(did_launcher).hex(),
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
    return (
        settings,
        claim,
        artifact,
        release,
        available_coin,
        validator_pubkeys,
    )


def test_inventory_reservation_is_fully_rederived(monkeypatch) -> None:
    (
        settings,
        claim,
        artifact,
        release,
        available_coin,
        validator_pubkeys,
    ) = _fixture()
    monkeypatch.setattr(
        "solslot_api.validator_service.time.time",
        lambda: 1_999_999_000,
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
            validator_pubkeys,
        ),
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._confirmed_coin_and_lineage",
        lambda *_args, **_kwargs: (available_coin, LineageProof()),
    )

    verify_inventory_reservation_claim(
        settings,
        claim,
        claim.canonical_hash(),
    )

    redirected = claim.model_copy(
        update={"reserved_coin_id": "0x" + "ff" * 32}
    )
    with pytest.raises(
        ValidatorEvidenceError,
        match="output or validator message",
    ):
        verify_inventory_reservation_claim(
            settings,
            redirected,
            redirected.canonical_hash(),
        )


def test_inventory_reservation_rejects_expired_authorization(
    monkeypatch,
) -> None:
    settings, claim, artifact, release, *_rest = _fixture()
    monkeypatch.setattr(
        "solslot_api.validator_service.time.time",
        lambda: claim.reservation_expires_at,
    )
    monkeypatch.setattr(
        "solslot_api.validator_service.load_validator_artifact",
        lambda _settings: (artifact, release),
    )

    with pytest.raises(ValidatorEvidenceError, match="expiry"):
        verify_inventory_reservation_claim(
            settings,
            claim,
            claim.canonical_hash(),
        )
