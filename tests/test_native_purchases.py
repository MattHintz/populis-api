from __future__ import annotations

import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
    puzzle_for_pk,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.trading.offer import Offer
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.config import Settings
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.native_purchases import (
    CompleteNativePurchaseRequest,
    NativePurchaseContext,
    NativePurchaseGroup,
    PrepareNativePurchaseRequest,
    complete_native_purchase,
    prepare_native_purchase,
    _proposal_rejection_reasons,
)
from solslot_api.payment_purchase_store import StoredPaymentPurchase
from solslot_api.protocol_submission import ProtocolBundleSubmitter
from solslot_api.validator_quorum import ValidatorQuorumResult
from solslot_puzzles.mint_publish_driver import (
    deed_launcher_puzzle_hash,
    deed_singleton_struct,
)
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseBatchV1,
    PurchaseArtifactV3,
    PurchaseDeliveryKind,
    purchase_batch_to_json,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PRIMARY_PURCHASE_PROVIDER_ID,
    PrimaryMintTermsV3,
    make_inventory_available_inner,
    make_mint_offer_v5_inner,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.vault_driver import puzzle_for_p2_vault


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


class FakeNode:
    def __init__(self, payment_coin: Coin) -> None:
        self.payment_coin = payment_coin
    async def get_coin_records_by_puzzle_hash(self, puzzle_hash, include_spent=False):
        assert puzzle_hash == "0x" + self.payment_coin.puzzle_hash.hex()
        assert include_spent is False
        return [self.payment_record()]

    async def get_coin_record_by_name(self, coin_id):
        if coin_id == "0x" + self.payment_coin.name().hex():
            return self.payment_record()
        return None

    def payment_record(self):
        return {
            "coin": {
                "parent_coin_info": "0x" + self.payment_coin.parent_coin_info.hex(),
                "puzzle_hash": "0x" + self.payment_coin.puzzle_hash.hex(),
                "amount": int(self.payment_coin.amount),
            },
            "confirmed_block_index": 123,
            "spent_block_index": 0,
            "spent": False,
        }


class FakeProtocolSubmitter(ProtocolBundleSubmitter):
    def __init__(self) -> None:
        self.submitted = None

    async def submit(self, bundle):
        self.submitted = bundle
        return {
            "status": "MEMPOOL",
            "spendBundleId": "0x" + "99" * 32,
            "feeMojos": "420",
            "feeTargetSeconds": 300,
            "submissionProvider": "primary",
            "mempoolObservedAt": "2026-07-27T14:30:00Z",
        }


def _context(
    payment_key,
    validator_keys,
    *,
    deed_parent_seed: int = 22,
) -> tuple[NativePurchaseContext, Coin]:
    now = int(time.time())
    vault_launcher = _b32(8)
    protocol_did = singleton_struct(_b32(17))
    deed_launcher_parent = _b32(deed_parent_seed)
    deed_launcher_coin = Coin(
        deed_launcher_parent,
        deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=protocol_did,
        ),
        uint64(1),
    )

    artifact = PurchaseArtifactV3(
        network="testnet11",
        collection_id=_b32(10),
        deed_launcher_id=bytes32(deed_launcher_coin.name()),
        metadata_root=_b32(12),
        metadata_anchor_id=_b32(13),
        share_ppm=250_000,
        base_amount_minor=125_000,
        technology_fee_bps=100,
        technology_fee_minor=1_250,
        subtotal_minor=126_250,
        protocol_treasury_puzzle_hash=_b32(19),
        zkpassport_root=_b32(25),
        rail=PaymentRail.CHIA_XCH,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=12,
        rail_amount=50_500_000_000_000,
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=bytes32(
            puzzle_for_p2_vault(vault_launcher).get_tree_hash()
        ),
        authorization_nonce=_b32(14),
        authorization_expires_at=now + 600,
        quote_expires_at=now + 300,
        delivery_kind=PurchaseDeliveryKind.SMARTDEED,
        delivery_asset_id=bytes32(deed_launcher_coin.name()),
        delivery_amount=1,
        delivery_context_hash=_b32(10),
        oracle_round_hash=_b32(15),
        oracle_price_usd_minor_per_asset=2_500,
        source_evidence_root=_b32(16),
    )
    deed_struct = deed_singleton_struct(
        deed_launcher_id=artifact.deed_launcher_id,
        protocol_did_singleton_struct=protocol_did,
    )
    terms = PrimaryMintTermsV3.for_artifact(
        artifact=artifact,
        smart_deed_inner_hash=_b32(18),
        protocol_puzhash=artifact.protocol_treasury_puzzle_hash,
        validator_pubkeys=tuple(bytes(key.get_g1()) for key in validator_keys),
        provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
    )
    reservation = InventoryReservationV1(
        artifact=artifact,
        expires_at=min(
            artifact.quote_expires_at,
            artifact.authorization_expires_at,
        ),
    )
    available_inner = make_inventory_available_inner(terms)
    available_puzzle = SINGLETON_MOD.curry(deed_struct, available_inner)
    available_coin = Coin(
        artifact.deed_launcher_id,
        available_puzzle.get_tree_hash(),
        uint64(1),
    )
    deed_puzzle = SINGLETON_MOD.curry(
        deed_struct,
        make_mint_offer_v5_inner(terms, reservation),
    )
    deed_coin = Coin(
        available_coin.name(),
        deed_puzzle.get_tree_hash(),
        uint64(1),
    )
    payment_puzzle = puzzle_for_pk(payment_key.get_g1())
    payment_coin = Coin(
        _b32(20),
        payment_puzzle.get_tree_hash(),
        uint64(75_000_000_000_000),
    )
    stored = StoredPaymentPurchase(
        purchase_id="0x" + artifact.purchase_id.hex(),
        artifact_hash="0x" + artifact.artifact_hash.hex(),
        purchase_intent_id="pi_native",
        rail="chia_xch",
        quote_expires_at=artifact.quote_expires_at,
        offer_artifact_hash="sha256:" + "21" * 32,
        offer_artifact={},
        purchase_artifact={},
        external_message=None,
        deed_launcher_id="0x" + artifact.deed_launcher_id.hex(),
        inventory_state="CONFIRMED",
        inventory_available_coin_id="0x" + available_coin.name().hex(),
        inventory_reserved_coin_id="0x" + deed_coin.name().hex(),
        inventory_reserved_puzzle_hash="0x" + deed_coin.puzzle_hash.hex(),
        inventory_expires_at=reservation.expires_at,
        inventory_confirmation_height=124,
    )
    return (
        NativePurchaseContext(
            stored=stored,
            purchase=artifact,
            terms=terms,
            deed_coin=deed_coin,
            deed_struct=deed_struct,
            deed_lineage=LineageProof(
                parent_name=available_coin.parent_coin_info,
                inner_puzzle_hash=bytes32(available_inner.get_tree_hash()),
                amount=uint64(1),
            ),
            genesis_artifact={"artifactHash": "0x" + "23" * 32},
            credential_receipt={
                "chiaVaultCoinId": "0x" + "24" * 32,
                "identityAttestRoot": "0x" + "25" * 32,
                "policyVersion": 2,
                "bridgePolicyHash": "0x" + "26" * 32,
            },
            credential_owner_auth_type=1,
            credential_owner_key=bytes(payment_key.get_g1()),
            reservation=reservation,
        ),
        payment_coin,
    )


def test_purchase_terms_must_match_the_governed_proposal() -> None:
    payment_key = AugSchemeMPL.key_gen(b"q" * 32)
    validator_keys = tuple(
        AugSchemeMPL.key_gen(bytes([seed]) * 32) for seed in (41, 42, 43)
    )
    context, _coin = _context(payment_key, validator_keys)
    deed = {"deedId": "US-TX-AUSTIN-001"}
    proposal = SimpleNamespace(
        deed_launcher_id=bytes(context.purchase.deed_launcher_id),
        collection_id="SOL-LOT-AUSTIN-ALPHA",
        property_id=deed["deedId"],
        share_ppm=context.purchase.share_ppm,
    )
    from solslot_puzzles.property_registry_driver import canonicalise_property_id

    collection_id = bytes32(canonicalise_property_id(proposal.collection_id))
    purchase = replace(
        context.purchase,
        collection_id=collection_id,
        delivery_context_hash=collection_id,
    )
    assert _proposal_rejection_reasons(proposal, deed, purchase) == []

    proposal.deed_launcher_id = bytes(_b32(91))
    proposal.property_id = "US-TX-AUSTIN-002"
    proposal.share_ppm += 1
    proposal.collection_id = "SOL-LOT-OTHER"
    assert _proposal_rejection_reasons(proposal, deed, purchase) == [
        "deed launcher",
        "collection",
        "deed identifier",
        "share allocation",
    ]


@pytest.mark.asyncio
async def test_one_prompt_native_purchase_builds_and_submits_atomic_offer(monkeypatch):
    payment_key = AugSchemeMPL.key_gen(b"p" * 32)
    validator_keys = tuple(
        AugSchemeMPL.key_gen(bytes([seed]) * 32) for seed in (31, 32, 33)
    )
    context, payment_coin = _context(payment_key, validator_keys)
    node = FakeNode(payment_coin)
    submitter = FakeProtocolSubmitter()
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                coinset=node,
                protocol_submitter=submitter,
            )
        )
    )
    settings = Settings(
        _env_file=None,
        runtime_environment="test",
        network="testnet11",
        alpha_writes_enabled=True,
        minting_enabled=True,
        protocol_artifact_api_token="test-token",
    )

    async def load_context_group(*_args, **_kwargs):
        return NativePurchaseGroup(
            stored=context.stored,
            contexts=(context,),
            batch=None,
        )

    monkeypatch.setattr(
        "solslot_api.native_purchases._load_context_group",
        load_context_group,
    )
    prepared = await prepare_native_purchase(
        PrepareNativePurchaseRequest(
            purchaseId="0x" + context.purchase.purchase_id.hex(),
            paymentPublicKeys=["0x" + bytes(payment_key.get_g1()).hex()],
        ),
        request,
        settings,
        "Bearer test-token",
    )
    assert len(prepared.coin_spends) == 1
    assert prepared.amount == context.purchase.rail_amount

    unsigned = Offer.from_bech32(prepared.buyer_offer)
    pairs = []
    for spend in unsigned.coin_spends():
        conditions = conditions_dict_for_solution(
            spend.puzzle_reveal,
            spend.solution,
            INFINITE_COST,
        )
        pairs.extend(
            pkm_pairs_for_conditions_dict(
                conditions,
                spend.coin,
                AGG_SIG_ME_DATA["testnet11"],
            )
        )
    synthetic_key = calculate_synthetic_secret_key(
        payment_key,
        DEFAULT_HIDDEN_PUZZLE_HASH,
    )
    assert pairs and all(
        public_key == synthetic_key.get_g1() for public_key, _ in pairs
    )
    buyer_signature = AugSchemeMPL.aggregate(
        [AugSchemeMPL.sign(synthetic_key, message) for _public_key, message in pairs]
    )
    validator_message = (
        bytes(context.purchase.artifact_hash)
        + bytes(context.deed_coin.name())
        + AGG_SIG_ME_DATA["testnet11"]
    )
    quorum_signature = AugSchemeMPL.aggregate(
        [AugSchemeMPL.sign(validator_keys[index], validator_message) for index in (0, 1)]
    )

    async def collect_quorum(_settings, claim, **_kwargs):
        assert claim.credential_owner_auth_type == 1
        assert claim.credential_owner_key == "0x" + bytes(payment_key.get_g1()).hex()
        assert claim.reservation_expires_at == context.reservation.expires_at
        return ValidatorQuorumResult(
            signer_indices=(0, 1),
            aggregated_signature=quorum_signature,
            claim_hash="0x" + "27" * 32,
        )

    monkeypatch.setattr(
        "solslot_api.native_purchases.collect_primary_purchase_quorum",
        collect_quorum,
    )
    completed = await complete_native_purchase(
        CompleteNativePurchaseRequest(
            purchaseId="0x" + context.purchase.purchase_id.hex(),
            buyerOffer=prepared.buyer_offer,
            aggregatedSignature="0x" + bytes(buyer_signature).hex(),
        ),
        request,
        settings,
        "Bearer test-token",
    )

    assert completed.status == "MEMPOOL"
    assert completed.signer_indices == [0, 1]
    assert completed.transaction_id == "0x" + "99" * 32
    assert completed.fee_mojos == 420
    assert completed.fee_target_seconds == 300
    assert completed.submission_provider == "primary"
    assert completed.mempool_observed_at == "2026-07-27T14:30:00Z"
    assert submitter.submitted is not None


@pytest.mark.asyncio
async def test_quantity_two_submits_one_atomic_multi_deed_purchase(monkeypatch):
    payment_key = AugSchemeMPL.key_gen(b"r" * 32)
    validator_keys = tuple(
        AugSchemeMPL.key_gen(bytes([seed]) * 32) for seed in (51, 52, 53)
    )
    first, _ = _context(
        payment_key,
        validator_keys,
        deed_parent_seed=61,
    )
    second, _ = _context(
        payment_key,
        validator_keys,
        deed_parent_seed=62,
    )
    contexts = tuple(
        sorted(
            (first, second),
            key=lambda item: bytes(item.purchase.deed_launcher_id),
        )
    )
    batch = PurchaseBatchV1(
        batch_nonce=_b32(63),
        artifacts=tuple(item.purchase for item in contexts),
    )
    batch_json = purchase_batch_to_json(batch)
    parent = replace(
        contexts[0].stored,
        purchase_id="0x" + batch.purchase_id.hex(),
        artifact_hash="0x" + batch.batch_hash.hex(),
        purchase_artifact=batch_json,
        deed_launcher_id="0x" + contexts[0].purchase.deed_launcher_id.hex(),
        deed_launcher_ids=tuple(
            "0x" + item.purchase.deed_launcher_id.hex() for item in contexts
        ),
    )
    contexts = tuple(replace(item, stored=parent) for item in contexts)
    payment_puzzle = puzzle_for_pk(payment_key.get_g1())
    payment_coin = Coin(
        _b32(64),
        payment_puzzle.get_tree_hash(),
        uint64(batch.total_rail_amount + 1_000),
    )
    node = FakeNode(payment_coin)
    submitter = FakeProtocolSubmitter()
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                coinset=node,
                protocol_submitter=submitter,
            )
        )
    )
    settings = Settings(
        _env_file=None,
        runtime_environment="test",
        network="testnet11",
        alpha_writes_enabled=True,
        minting_enabled=True,
        protocol_artifact_api_token="test-token",
    )

    async def load_context_group(*_args, **_kwargs):
        return NativePurchaseGroup(
            stored=parent,
            contexts=contexts,
            batch=batch,
        )

    monkeypatch.setattr(
        "solslot_api.native_purchases._load_context_group",
        load_context_group,
    )
    prepared = await prepare_native_purchase(
        PrepareNativePurchaseRequest(
            purchaseId=parent.purchase_id,
            paymentPublicKeys=["0x" + bytes(payment_key.get_g1()).hex()],
        ),
        request,
        settings,
        "Bearer test-token",
    )
    assert prepared.quantity == 2
    assert prepared.amount == batch.total_rail_amount
    assert prepared.deed_launcher_ids == [
        "0x" + item.purchase.deed_launcher_id.hex() for item in contexts
    ]

    unsigned = Offer.from_bech32(prepared.buyer_offer)
    pairs = []
    for spend in unsigned.coin_spends():
        conditions = conditions_dict_for_solution(
            spend.puzzle_reveal,
            spend.solution,
            INFINITE_COST,
        )
        pairs.extend(
            pkm_pairs_for_conditions_dict(
                conditions,
                spend.coin,
                AGG_SIG_ME_DATA["testnet11"],
            )
        )
    synthetic_key = calculate_synthetic_secret_key(
        payment_key,
        DEFAULT_HIDDEN_PUZZLE_HASH,
    )
    buyer_signature = AugSchemeMPL.aggregate(
        [AugSchemeMPL.sign(synthetic_key, message) for _key, message in pairs]
    )
    quorum_calls = 0

    async def collect_quorum(_settings, claim, **_kwargs):
        nonlocal quorum_calls
        quorum_calls += 1
        assert claim.purchase_artifact == batch_json
        assert len(claim.deed_items) == 2
        messages = claim.signature_messages()
        assert len(messages) == 2
        return ValidatorQuorumResult(
            signer_indices=(0, 1),
            aggregated_signature=AugSchemeMPL.aggregate(
                [
                    AugSchemeMPL.sign(validator_keys[index], message)
                    for index in (0, 1)
                    for message in messages
                ]
            ),
            claim_hash=claim.canonical_hash(),
        )

    monkeypatch.setattr(
        "solslot_api.native_purchases.collect_primary_purchase_quorum",
        collect_quorum,
    )
    completed = await complete_native_purchase(
        CompleteNativePurchaseRequest(
            purchaseId=parent.purchase_id,
            buyerOffer=prepared.buyer_offer,
            aggregatedSignature="0x" + bytes(buyer_signature).hex(),
        ),
        request,
        settings,
        "Bearer test-token",
    )

    assert quorum_calls == 1
    assert completed.quantity == 2
    assert completed.deed_launcher_ids == prepared.deed_launcher_ids
    assert completed.transaction_id == "0x" + "99" * 32
    assert submitter.submitted is not None
