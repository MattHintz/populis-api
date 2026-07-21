from __future__ import annotations

import time
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
    PrepareNativePurchaseRequest,
    complete_native_purchase,
    prepare_native_purchase,
)
from solslot_api.payment_purchase_store import StoredPaymentPurchase
from solslot_api.validator_quorum import ValidatorQuorumResult
from solslot_puzzles.mint_publish_driver import (
    deed_launcher_puzzle_hash,
    deed_singleton_struct,
)
from solslot_puzzles.payment_artifacts_v2 import PaymentRail, PurchaseArtifactV2
from solslot_puzzles.primary_purchase_v2_driver import (
    PRIMARY_PURCHASE_PROVIDER_ID,
    PrimaryMintTermsV2,
    make_mint_offer_v2_inner,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.vault_driver import puzzle_for_p2_vault


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


class FakeNode:
    def __init__(self, payment_coin: Coin) -> None:
        self.payment_coin = payment_coin
        self.submitted = None

    async def get_coin_records_by_puzzle_hash(self, puzzle_hash, include_spent=False):
        assert puzzle_hash == "0x" + self.payment_coin.puzzle_hash.hex()
        assert include_spent is False
        return [self.payment_record()]

    async def get_coin_record_by_name(self, coin_id):
        if coin_id == "0x" + self.payment_coin.name().hex():
            return self.payment_record()
        return None

    async def push_tx(self, bundle):
        self.submitted = bundle
        return {"success": True, "status": "SUCCESS"}

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


def _context(payment_key, validator_keys) -> tuple[NativePurchaseContext, Coin]:
    now = int(time.time())
    vault_launcher = _b32(8)
    protocol_did = singleton_struct(_b32(17))
    deed_launcher_parent = _b32(22)
    deed_launcher_coin = Coin(
        deed_launcher_parent,
        deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=protocol_did,
        ),
        uint64(1),
    )
    artifact = PurchaseArtifactV2(
        network="testnet11",
        collection_id=_b32(10),
        deed_launcher_id=bytes32(deed_launcher_coin.name()),
        metadata_root=_b32(12),
        metadata_anchor_id=_b32(13),
        share_ppm=250_000,
        usd_amount_minor=125_000,
        rail=PaymentRail.CHIA_XCH,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=12,
        rail_amount=50_000_000_000_000,
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=bytes32(
            puzzle_for_p2_vault(vault_launcher).get_tree_hash()
        ),
        authorization_nonce=_b32(14),
        authorization_expires_at=now + 600,
        quote_expires_at=now + 300,
        oracle_round_hash=_b32(15),
        oracle_price_usd_minor_per_asset=2_500,
        source_evidence_root=_b32(16),
    )
    deed_struct = deed_singleton_struct(
        deed_launcher_id=artifact.deed_launcher_id,
        protocol_did_singleton_struct=protocol_did,
    )
    terms = PrimaryMintTermsV2(
        network="testnet11",
        smart_deed_inner_hash=_b32(18),
        deed_launcher_id=artifact.deed_launcher_id,
        collection_id=artifact.collection_id,
        metadata_root=artifact.metadata_root,
        metadata_anchor_id=artifact.metadata_anchor_id,
        share_ppm=artifact.share_ppm,
        usd_amount_minor=artifact.usd_amount_minor,
        protocol_puzhash=_b32(19),
        validator_pubkeys=tuple(bytes(key.get_g1()) for key in validator_keys),
        provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
    )
    deed_puzzle = SINGLETON_MOD.curry(deed_struct, make_mint_offer_v2_inner(terms))
    deed_coin = Coin(
        artifact.deed_launcher_id,
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
    )
    return (
        NativePurchaseContext(
            stored=stored,
            purchase=artifact,
            terms=terms,
            deed_coin=deed_coin,
            deed_struct=deed_struct,
            deed_lineage=LineageProof(
                parent_name=deed_launcher_parent,
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
        ),
        payment_coin,
    )


@pytest.mark.asyncio
async def test_one_prompt_native_purchase_builds_and_submits_atomic_offer(monkeypatch):
    payment_key = AugSchemeMPL.key_gen(b"p" * 32)
    validator_keys = tuple(
        AugSchemeMPL.key_gen(bytes([seed]) * 32) for seed in (31, 32, 33)
    )
    context, payment_coin = _context(payment_key, validator_keys)
    node = FakeNode(payment_coin)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=node)))
    settings = Settings(
        _env_file=None,
        runtime_environment="test",
        network="testnet11",
        alpha_writes_enabled=True,
        minting_enabled=True,
        protocol_artifact_api_token="test-token",
    )

    async def load_context(*_args, **_kwargs):
        return context

    monkeypatch.setattr("solslot_api.native_purchases._load_context", load_context)
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

    assert completed.status == "SUCCESS"
    assert completed.signer_indices == [0, 1]
    assert completed.transaction_id.startswith("0x")
    assert node.submitted is not None
