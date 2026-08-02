"""Chain-authoritative publication and monitoring for governed SGT sales."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping

from chia.types.blockchain_format.coin import Coin
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import sgt_free_inner_puzzle, sgt_locked_inner_mod
from solslot_puzzles.sgt_reserve_driver import (
    SGTAllocationRail,
    SGTSaleTermsV1,
    prepare_sgt_sale_offer,
    sgt_cat_puzzle,
    sgt_reserve_inner_puzzle,
    sgt_sale_terms_from_bill,
    sgt_sale_inner_puzzle,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault

from .admin_key_changes import _verified_evidence_context
from .governance_execution import _b32, _coin, _hex32, _mapping, _program
from .governance_queue import GovernanceQueueRecord, SaleOfferStatus


@dataclass(frozen=True)
class GovernedSaleOfferSnapshot:
    offer_id: str
    offer_bech32: str
    sale_coin_id: str
    status: SaleOfferStatus
    confirmed_height: int
    spent_height: int | None


@dataclass(frozen=True)
class GovernedSaleCoinSnapshot:
    sale_coin: Coin
    terms: SGTSaleTermsV1
    tracker_struct: Any
    sgt_tail_hash: bytes32
    reserve_owner_inner_hash: bytes32
    confirmed_height: int
    spent_height: int | None


async def reconstruct_governed_sale_lineage(
    *,
    context: GovernedSaleCoinSnapshot,
    provider: Any,
) -> LineageProof:
    """Prove the sale allocation descended from the governed SGT reserve."""

    allocation_record = await provider.get_coin_record_by_name(
        _hex32(context.sale_coin.parent_coin_info)
    )
    allocation_coin = (
        _coin(allocation_record)
        if isinstance(allocation_record, Mapping)
        else None
    )
    reserve_free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        context.tracker_struct,
        context.reserve_owner_inner_hash,
    )
    expected_allocation_full = construct_cat_puzzle(
        CAT_MOD,
        context.sgt_tail_hash,
        reserve_free_inner,
    )
    if (
        allocation_coin is None
        or allocation_coin.puzzle_hash
        != expected_allocation_full.get_tree_hash()
        or int((allocation_record or {}).get("spent_block_index") or 0) <= 0
    ):
        raise ValueError("governed SGT sale lineage is unavailable")
    return LineageProof(
        allocation_coin.parent_coin_info,
        bytes32(reserve_free_inner.get_tree_hash()),
        allocation_coin.amount,
    )


async def reconstruct_governed_sale_coin(
    *,
    record: GovernanceQueueRecord,
    provider: Any,
    settings: Any,
) -> GovernedSaleCoinSnapshot:
    """Rebuild one exact governed sale coin from release and chain evidence."""
    if record.kind != "SGT_SALE" or not record.expected_output_coin_ids:
        raise ValueError("confirmed SGT sale output evidence is unavailable")

    artifact, _evidence, _coordinator = await _verified_evidence_context(settings)
    plan = _mapping(artifact.get("genesisPlan", artifact), "genesisPlan")
    launchers = _mapping(plan.get("launcherIds"), "launcherIds")
    puzzles = _mapping(plan.get("puzzleHashes"), "puzzleHashes")
    tracker_struct = singleton_struct(
        _b32(launchers.get("governance"), "governance launcher")
    )
    admin_struct = singleton_struct(
        _b32(launchers.get("adminAuthority"), "authority launcher")
    )
    sgt_tail = _b32(
        artifact.get("sgtTailHash")
        or _mapping(plan.get("permanentRules"), "permanentRules").get(
            "sgtTailHash"
        ),
        "SGT tail hash",
    )
    treasury = _b32(
        _mapping(plan.get("trustedDestinations"), "trustedDestinations").get(
            "companySgtSaleTreasuryPuzzleHash"
        ),
        "company SGT treasury",
    )
    wusdc_b_asset_id = _b32(
        _mapping(plan.get("trustedAssets"), "trustedAssets").get(
            "wusdcBAssetId"
        ),
        "trusted wUSDC.b asset ID",
    )
    reserve_inner = sgt_reserve_inner_puzzle(
        proposal_tracker_struct=tracker_struct,
        admin_authority_struct=admin_struct,
        sgt_tail_hash=sgt_tail,
        wusdc_b_asset_id=wusdc_b_asset_id,
        company_treasury_puzzle_hash=treasury,
    )
    reserve_owner = bytes32(reserve_inner.get_tree_hash())
    if reserve_owner != _b32(puzzles.get("sgtReserveInner"), "SGT reserve inner"):
        raise ValueError("SGT reserve does not match signed release evidence")

    bill = _program(record.bill_clvm_hex, "queued governance bill")
    if _hex32(bill.get_tree_hash()) != record.proposal_hash.lower():
        raise ValueError("queued proposal hash does not match its bill")
    terms = sgt_sale_terms_from_bill(
        bill,
        reserve_owner_inner_hash=reserve_owner,
    )
    if terms.company_treasury_puzzle_hash != treasury:
        raise ValueError("SGT sale treasury does not match signed release evidence")

    sale_inner = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=reserve_owner,
        sgt_tail_hash=sgt_tail,
        terms=terms,
    )
    sale_full = sgt_cat_puzzle(
        proposal_tracker_struct=tracker_struct,
        sgt_tail_hash=sgt_tail,
        owner_inner_puzzle=sale_inner,
    )
    candidates: list[tuple[Any, Mapping[str, Any]]] = []
    for output_id in record.expected_output_coin_ids:
        output_record = await provider.get_coin_record_by_name(output_id)
        if not isinstance(output_record, Mapping):
            continue
        output_coin = _coin(output_record)
        if (
            output_coin is not None
            and output_coin.puzzle_hash == sale_full.get_tree_hash()
            and int(output_coin.amount) == terms.sgt_amount
            and int(output_record.get("confirmed_block_index") or 0) > 0
        ):
            candidates.append((output_coin, output_record))
    if len(candidates) != 1:
        raise ValueError("confirmed governed SGT sale coin is missing or ambiguous")
    sale_coin, sale_record = candidates[0]
    spent_height = int(sale_record.get("spent_block_index") or 0)
    return GovernedSaleCoinSnapshot(
        sale_coin=sale_coin,
        terms=terms,
        tracker_struct=tracker_struct,
        sgt_tail_hash=sgt_tail,
        reserve_owner_inner_hash=reserve_owner,
        confirmed_height=int(sale_record.get("confirmed_block_index") or 0),
        spent_height=spent_height if spent_height > 0 else None,
    )


async def reconstruct_governed_sale_offer(
    *,
    record: GovernanceQueueRecord,
    provider: Any,
    settings: Any,
    now: int | None = None,
) -> GovernedSaleOfferSnapshot:
    """Rebuild a native XCH/CAT offer from one governed sale coin."""
    context = await reconstruct_governed_sale_coin(
        record=record,
        provider=provider,
        settings=settings,
    )
    terms = context.terms
    if terms.payment_rail not in {
        SGTAllocationRail.XCH,
        SGTAllocationRail.CAT,
    }:
        raise ValueError("external SGT sales do not publish Chia offer files")
    sale_coin = context.sale_coin
    tracker_struct = context.tracker_struct
    sgt_tail = context.sgt_tail_hash
    reserve_owner = context.reserve_owner_inner_hash

    reserve_free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        tracker_struct,
        reserve_owner,
    )
    lineage = await reconstruct_governed_sale_lineage(
        context=context,
        provider=provider,
    )
    offer = prepare_sgt_sale_offer(
        sale_coin=sale_coin,
        sale_lineage_proof=lineage,
        proposal_tracker_struct=tracker_struct,
        reserve_owner_inner_hash=reserve_owner,
        sgt_tail_hash=sgt_tail,
        terms=terms,
    )

    spent_height = int(context.spent_height or 0)
    if spent_height > 0:
        recipient_free = sgt_free_inner_puzzle(
            bytes32(sgt_locked_inner_mod().get_tree_hash()),
            tracker_struct,
            puzzle_hash_for_p2_vault(terms.recipient_vault_launcher_id),
        )
        recipient_full = construct_cat_puzzle(CAT_MOD, sgt_tail, recipient_free)
        reserve_full = construct_cat_puzzle(CAT_MOD, sgt_tail, reserve_free_inner)
        if recipient_full.get_tree_hash() == reserve_full.get_tree_hash():
            raise ValueError("SGT sale recipient cannot be the governed reserve")
        children = await provider.get_coin_records_by_parent_ids(
            [_hex32(sale_coin.name())], include_spent=True
        )
        recipient_outputs = []
        reserve_outputs = []
        for child in children:
            if not isinstance(child, Mapping):
                continue
            coin = _coin(child)
            if (
                coin is None
                or int(coin.amount) != terms.sgt_amount
                or int(child.get("confirmed_block_index") or 0) <= 0
            ):
                continue
            if coin.puzzle_hash == recipient_full.get_tree_hash():
                recipient_outputs.append(coin)
            if coin.puzzle_hash == reserve_full.get_tree_hash():
                reserve_outputs.append(coin)
        if len(recipient_outputs) == 1 and not reserve_outputs:
            status: SaleOfferStatus = "TAKEN"
        elif len(reserve_outputs) == 1 and not recipient_outputs:
            status = "RETURNED"
        else:
            raise ValueError("spent SGT sale has no canonical settlement output")
        normalized_spent_height: int | None = spent_height
    else:
        mempool = await provider.get_mempool_items_by_coin_name(
            _hex32(sale_coin.name())
        )
        if mempool:
            status = "PENDING"
        else:
            timestamp = int(time.time()) if now is None else now
            status = "EXPIRED" if timestamp >= terms.expires_at else "AVAILABLE"
        normalized_spent_height = None

    return GovernedSaleOfferSnapshot(
        offer_id=_hex32(offer.name()),
        offer_bech32=offer.to_bech32(),
        sale_coin_id=_hex32(sale_coin.name()),
        status=status,
        confirmed_height=context.confirmed_height,
        spent_height=normalized_spent_height,
    )


__all__ = [
    "GovernedSaleCoinSnapshot",
    "GovernedSaleOfferSnapshot",
    "reconstruct_governed_sale_coin",
    "reconstruct_governed_sale_lineage",
    "reconstruct_governed_sale_offer",
]
