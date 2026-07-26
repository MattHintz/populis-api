"""One-approval native XCH/CAT primary SmartDeed purchases."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Annotated, Any, Mapping

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, match_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.trading.offer import Offer
from chia.wallet.uncurried_puzzle import uncurry_puzzle
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.mint_publish_driver import (
    deed_launcher_puzzle_hash,
    deed_singleton_struct,
)
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentRail,
    PurchaseArtifactV2,
    purchase_artifact_from_json,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    PRIMARY_PURCHASE_PROVIDER_ID,
    PrimaryMintTermsV2,
    build_universal_primary_offer_v4,
    make_mint_offer_v4_inner,
    prepare_chia_buyer_offer,
    validate_chia_buyer_offer,
)
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.protocol_deployment import singleton_struct

from .collection_store import CollectionNotFound, get_collection_store
from .config import Settings, get_settings
from .credential_auth import require_minting_writes
from .faucet import AGG_SIG_ME_DATA
from .mint_endpoints import get_mint_proposal_store
from .launch_gates import require_operation_gate
from .payment_purchase_store import (
    PaymentPurchaseNotFound,
    StoredPaymentPurchase,
    get_payment_purchase_store,
)
from .protocol_artifacts import (
    _artifact_rejection_reasons,
    _require_server_to_server_token,
)
from .public_artifact import PublicArtifactError, load_signed_public_artifact
from .state import get_registry
from .validator_quorum import (
    PrimaryPurchaseClaim,
    ValidatorQuorumError,
    collect_primary_purchase_quorum,
    configured_validator_pubkeys,
)


router = APIRouter(prefix="/protocol/native-purchases", tags=["native-purchases"])


class NativePurchaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class PrepareNativePurchaseRequest(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId", min_length=66, max_length=66)
    payment_public_keys: list[str] = Field(
        alias="paymentPublicKeys",
        min_length=1,
        max_length=100,
    )

    @field_validator("payment_public_keys")
    @classmethod
    def validate_public_keys(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            raw = _hex_bytes(value, 48, "paymentPublicKeys")
            G1Element.from_bytes(raw)
            item = "0x" + raw.hex()
            if item not in normalized:
                normalized.append(item)
        if not normalized:
            raise ValueError("at least one unique payment public key is required")
        return normalized


class PrepareNativePurchaseResponse(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId")
    buyer_offer: str = Field(alias="buyerOffer")
    coin_spends: list[dict[str, Any]] = Field(alias="coinSpends")
    rail: str
    amount: int
    asset_id: str = Field(alias="assetId")
    quote_expires_at: int = Field(alias="quoteExpiresAt")


class CompleteNativePurchaseRequest(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId", min_length=66, max_length=66)
    buyer_offer: str = Field(alias="buyerOffer", min_length=16, max_length=2_000_000)
    aggregated_signature: str = Field(
        alias="aggregatedSignature",
        min_length=194,
        max_length=194,
    )


class CompleteNativePurchaseResponse(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId")
    transaction_id: str = Field(alias="transactionId")
    status: str
    signer_indices: list[int] = Field(alias="signerIndices")


@dataclass(frozen=True)
class NativePurchaseContext:
    stored: StoredPaymentPurchase
    purchase: PurchaseArtifactV2
    terms: PrimaryMintTermsV2
    deed_coin: Coin
    deed_struct: Program
    deed_lineage: LineageProof
    genesis_artifact: dict[str, Any]
    credential_receipt: dict[str, Any]
    credential_owner_auth_type: int
    credential_owner_key: bytes


@router.post("/prepare", response_model=PrepareNativePurchaseResponse)
async def prepare_native_purchase(
    body: PrepareNativePurchaseRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> PrepareNativePurchaseResponse:
    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    _require_server_to_server_token(settings, authorization)
    context = await _load_context(
        settings,
        request.app.state.coinset,
        body.purchase_id,
    )
    selected: tuple[Coin, bytes, LineageProof | None] | None = None
    for key_hex in body.payment_public_keys:
        key = _hex_bytes(key_hex, 48, "paymentPublicKeys")
        candidate = await _select_payment_coin(
            request.app.state.coinset,
            context.purchase,
            key,
        )
        if candidate is not None and (
            selected is None
            or int(candidate[0].amount) < int(selected[0].amount)
        ):
            selected = candidate
    if selected is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "No single confirmed wallet coin can cover the current "
                "H-system quote. Consolidate the selected asset and retry."
            ),
        )
    try:
        prepared = prepare_chia_buyer_offer(
            payment_coin=selected[0],
            payment_public_key=selected[1],
            artifact=context.purchase,
            terms=context.terms,
            cat_lineage_proof=selected[2],
        )
    except PaymentArtifactError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return PrepareNativePurchaseResponse(
        purchaseId=_hex32(context.purchase.purchase_id),
        buyerOffer=prepared.offer.to_bech32(),
        coinSpends=[_coin_spend_json(spend) for spend in prepared.offer.coin_spends()],
        rail=(
            "chia_xch"
            if context.purchase.rail == PaymentRail.CHIA_XCH
            else "chia_cat"
        ),
        amount=context.purchase.rail_amount,
        assetId=_hex32(context.purchase.rail_asset_id),
        quoteExpiresAt=context.purchase.quote_expires_at,
    )


@router.post("/complete", response_model=CompleteNativePurchaseResponse)
async def complete_native_purchase(
    body: CompleteNativePurchaseRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> CompleteNativePurchaseResponse:
    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    _require_server_to_server_token(settings, authorization)
    context = await _load_context(
        settings,
        request.app.state.coinset,
        body.purchase_id,
    )
    try:
        unsigned = Offer.from_bech32(body.buyer_offer)
        if unsigned.aggregated_signature() != G2Element():
            raise PaymentArtifactError("prepared buyer offer must be unsigned")
        signature = G2Element.from_bytes(
            _hex_bytes(body.aggregated_signature, 96, "aggregatedSignature")
        )
        buyer_offer = Offer(
            unsigned.requested_payments,
            WalletSpendBundle(unsigned.coin_spends(), signature),
            unsigned.driver_dict,
        )
        validate_chia_buyer_offer(
            buyer_offer=buyer_offer,
            artifact=context.purchase,
            terms=context.terms,
        )
        _verify_buyer_signature(buyer_offer, settings.network)
        if len(buyer_offer.coin_spends()) != 1 or buyer_offer.fees() != 0:
            raise PaymentArtifactError(
                "buyer offer must use one zero-fee payment coin"
            )
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    payment_coin = buyer_offer.coin_spends()[0].coin
    payment_record = await request.app.state.coinset.get_coin_record_by_name(
        _hex32(payment_coin.name())
    )
    if not _record_is_unspent_coin(payment_record, payment_coin):
        raise HTTPException(
            status_code=409,
            detail="The wallet payment coin is no longer confirmed and unspent.",
        )

    claim = PrimaryPurchaseClaim(
        network=settings.network,
        genesis_artifact_hash=str(context.genesis_artifact["artifactHash"]),
        purchase_artifact=context.stored.purchase_artifact,
        buyer_offer=buyer_offer.to_bech32(),
        deed_coin_id=_hex32(context.deed_coin.name()),
        deed_puzzle_hash=_hex32(context.deed_coin.puzzle_hash),
        smart_deed_inner_hash=_hex32(context.terms.smart_deed_inner_hash),
        protocol_puzzle_hash=_hex32(context.terms.protocol_puzhash),
        credential_vault_coin_id=str(
            context.credential_receipt["chiaVaultCoinId"]
        ),
        credential_identity_root=str(
            context.credential_receipt["identityAttestRoot"]
        ),
        credential_policy_version=int(
            context.credential_receipt["policyVersion"]
        ),
        credential_bridge_policy_hash=str(
            context.credential_receipt["bridgePolicyHash"]
        ),
        credential_owner_auth_type=context.credential_owner_auth_type,
        credential_owner_key="0x" + context.credential_owner_key.hex(),
    )
    try:
        quorum = await collect_primary_purchase_quorum(settings, claim)
        primary = build_universal_primary_offer_v4(
            buyer_offer=buyer_offer,
            deed_coin=context.deed_coin,
            deed_singleton_struct=context.deed_struct,
            lineage_proof=context.deed_lineage,
            artifact=context.purchase,
            signer_indices=quorum.signer_indices,
            terms=context.terms,
        )
    except (PaymentArtifactError, ValidatorQuorumError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    valid_spend = primary.aggregate_offer.to_valid_spend()
    signed_spend = WalletSpendBundle(
        valid_spend.coin_spends,
        AugSchemeMPL.aggregate(
            [valid_spend.aggregated_signature, quorum.aggregated_signature]
        ),
    )
    result = await request.app.state.coinset.push_tx(
        signed_spend.to_json_dict()
    )
    network_status = str(result.get("status") or "").upper()
    if not result.get("success") and network_status not in {
        "SUCCESS",
        "PENDING",
    }:
        raise HTTPException(
            status_code=502,
            detail="The atomic purchase was rejected by the Chia node.",
        )
    return CompleteNativePurchaseResponse(
        purchaseId=_hex32(context.purchase.purchase_id),
        transactionId=_hex32(signed_spend.name()),
        status=network_status or "SUCCESS",
        signerIndices=list(quorum.signer_indices),
    )


async def _load_context(
    settings: Settings,
    coinset: Any,
    purchase_id: str,
    *,
    require_live: bool = True,
) -> NativePurchaseContext:
    normalized_purchase_id = "0x" + _hex_bytes(
        purchase_id,
        32,
        "purchaseId",
    ).hex()
    try:
        stored = get_payment_purchase_store(
            settings.payment_purchase_db_path
        ).get(normalized_purchase_id)
        purchase = purchase_artifact_from_json(stored.purchase_artifact)
        if require_live:
            purchase.assert_live(int(time.time()))
    except (PaymentPurchaseNotFound, PaymentArtifactError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail="The native purchase quote is missing, invalid, or expired.",
        ) from exc
    if purchase.rail not in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise HTTPException(status_code=409, detail="Purchase is not XCH or CAT.")
    if require_live:
        reasons = _artifact_rejection_reasons(
            stored.offer_artifact,
            stored.offer_artifact_hash,
            now=int(time.time()),
            settings=settings,
        )
        if reasons:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Purchase authorization is no longer current: "
                    + ", ".join(reasons)
                ),
            )

    from .zkpassport_enrollments import _sync_chia_stamp

    try:
        enrollment = _sync_chia_stamp(
            settings,
            _hex32(purchase.vault_launcher_id),
        )
    except HTTPException as exc:
        raise HTTPException(
            status_code=409,
            detail="The zkPassport vault credential is no longer current.",
        ) from exc
    receipt = enrollment.receipt
    if (
        enrollment.status != "chia_confirmed"
        or receipt is None
        or receipt.vaultLauncherId != _hex32(purchase.vault_launcher_id)
        or receipt.policyVersion != settings.zkpassport_policy_version
        or receipt.network != settings.network
        or receipt.bridgePolicyHash != settings.zkpassport_bridge_policy_hash
        or receipt.confirmedBlockIndex is None
    ):
        raise HTTPException(
            status_code=409,
            detail="A current chain-confirmed zkPassport vault credential is required.",
        )
    if require_live:
        stored_receipt = stored.offer_artifact.get("vaultCredentialReceipt")
        if (
            not isinstance(stored_receipt, Mapping)
            or receipt.chiaVaultCoinId != stored_receipt.get("chiaVaultCoinId")
            or receipt.identityAttestRoot != stored_receipt.get("identityAttestRoot")
        ):
            raise HTTPException(
                status_code=409,
                detail="Purchase authorization is no longer current.",
            )
    vault_record = get_registry().get(purchase.vault_launcher_id)
    if vault_record is None:
        raise HTTPException(
            status_code=409,
            detail="The zkPassport vault owner record is unavailable.",
        )

    protocol = stored.offer_artifact.get("protocol")
    if not isinstance(protocol, Mapping):
        raise HTTPException(status_code=409, detail="Purchase protocol context is missing.")
    workspace_id = protocol.get("collectionWorkspaceId")
    if not isinstance(workspace_id, str):
        raise HTTPException(status_code=409, detail="Purchase collection is missing.")
    try:
        collection = get_collection_store(settings).get(workspace_id)
    except CollectionNotFound as exc:
        raise HTTPException(status_code=409, detail="Purchase collection was not found.") from exc
    deed = next(
        (
            item
            for item in collection.get("deeds", [])
            if str(item.get("deedLauncherId") or "").lower()
            == _hex32(purchase.deed_launcher_id)
        ),
        None,
    )
    if not isinstance(deed, Mapping) or not deed.get("proposalId"):
        raise HTTPException(status_code=409, detail="Purchase SmartDeed is not published.")
    proposal = get_mint_proposal_store(settings).get(str(deed["proposalId"]))
    if (
        proposal is None
        or proposal.state not in {"EXECUTED", "MINTED"}
        or proposal.executed_bundle_id is None
        or proposal.smart_deed_inner_puzhash is None
        or deed.get("confirmationHeight") is None
        or not deed.get("outputCoinId")
    ):
        raise HTTPException(
            status_code=409,
            detail="Purchase SmartDeed is not executed and chain-confirmed.",
        )
    proposal_mismatches = _proposal_rejection_reasons(
        proposal,
        deed,
        purchase,
    )
    if proposal_mismatches:
        raise HTTPException(
            status_code=409,
            detail=(
                "Purchase SmartDeed no longer matches its governed proposal: "
                + ", ".join(proposal_mismatches)
            ),
        )
    try:
        genesis = load_signed_public_artifact(settings)
        validator_pubkeys = configured_validator_pubkeys(settings)
        launchers = genesis["launcherIds"]
        puzzle_hashes = genesis["puzzleHashes"]
        did_struct = singleton_struct(
            bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
        )
        terms = PrimaryMintTermsV2(
            network=settings.network,
            smart_deed_inner_hash=bytes32(
                _hex_bytes(
                    str(proposal.smart_deed_inner_puzhash),
                    32,
                    "smartDeedInnerPuzzleHash",
                )
            ),
            deed_launcher_id=purchase.deed_launcher_id,
            collection_id=purchase.collection_id,
            metadata_root=purchase.metadata_root,
            metadata_anchor_id=purchase.metadata_anchor_id,
            share_ppm=purchase.share_ppm,
            usd_amount_minor=purchase.usd_amount_minor,
            protocol_puzhash=bytes32.fromhex(
                str(puzzle_hashes["protocolTreasuryPuzzleHash"]).removeprefix("0x")
            ),
            validator_pubkeys=validator_pubkeys,
            provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
        )
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=did_struct,
        )
        expected_puzzle = SINGLETON_MOD.curry(
            deed_struct,
            make_mint_offer_v4_inner(terms),
        )
    except (KeyError, PublicArtifactError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="The signed primary-purchase coordinates are unavailable.",
        ) from exc
    deed_record = await coinset.get_coin_record_by_name(str(deed["outputCoinId"]))
    deed_coin = _coin_from_record(deed_record)
    if (
        deed_coin is None
        or not _record_is_unspent_coin(deed_record, deed_coin)
        or deed_coin.parent_coin_info != purchase.deed_launcher_id
        or deed_coin.puzzle_hash != expected_puzzle.get_tree_hash()
        or int(deed_coin.amount) != 1
        or _hex32(deed_coin.name()) != str(deed["outputCoinId"]).lower()
    ):
        raise HTTPException(
            status_code=409,
            detail="The governed SmartDeed coin is not available for delivery.",
        )
    launcher_record = await coinset.get_coin_record_by_name(
        _hex32(purchase.deed_launcher_id)
    )
    launcher_coin = _coin_from_record(launcher_record)
    expected_launcher_puzzle_hash = deed_launcher_puzzle_hash(
        protocol_did_singleton_struct=did_struct,
    )
    if (
        launcher_coin is None
        or launcher_coin.name() != purchase.deed_launcher_id
        or launcher_coin.puzzle_hash != expected_launcher_puzzle_hash
        or int(launcher_coin.amount) != 1
    ):
        raise HTTPException(status_code=409, detail="SmartDeed launcher lineage is unavailable.")
    return NativePurchaseContext(
        stored=stored,
        purchase=purchase,
        terms=terms,
        deed_coin=deed_coin,
        deed_struct=deed_struct,
        deed_lineage=LineageProof(
            parent_name=launcher_coin.parent_coin_info,
            amount=launcher_coin.amount,
        ),
        genesis_artifact=genesis,
        credential_receipt=receipt.model_dump(),
        credential_owner_auth_type=vault_record.auth_type,
        credential_owner_key=bytes(vault_record.owner_pubkey),
    )


def _proposal_rejection_reasons(
    proposal: Any,
    deed: Mapping[str, Any],
    purchase: PurchaseArtifactV2,
) -> list[str]:
    reasons: list[str] = []
    if proposal.deed_launcher_id != bytes(purchase.deed_launcher_id):
        reasons.append("deed launcher")
    try:
        proposal_collection_id = bytes32(
            canonicalise_property_id(proposal.collection_id)
        )
    except (TypeError, ValueError):
        proposal_collection_id = bytes32.zeros
    if proposal_collection_id != purchase.collection_id:
        reasons.append("collection")
    if proposal.property_id.casefold() != str(deed.get("deedId") or "").casefold():
        reasons.append("deed identifier")
    if proposal.share_ppm != purchase.share_ppm:
        reasons.append("share allocation")
    return reasons


async def _select_payment_coin(
    coinset: Any,
    purchase: PurchaseArtifactV2,
    payment_public_key: bytes,
    *,
    minimum_amount: int | None = None,
) -> tuple[Coin, bytes, LineageProof | None] | None:
    from chia.wallet.cat_wallet.cat_utils import construct_cat_puzzle
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk

    inner = puzzle_for_pk(G1Element.from_bytes(payment_public_key))
    if purchase.rail == PaymentRail.CHIA_XCH:
        puzzle = inner
    else:
        puzzle = construct_cat_puzzle(
            CAT_MOD,
            purchase.rail_asset_id,
            inner,
        )
    records = await coinset.get_coin_records_by_puzzle_hash(
        _hex32(puzzle.get_tree_hash()),
        include_spent=False,
    )
    required_amount = (
        purchase.rail_amount if minimum_amount is None else minimum_amount
    )
    if required_amount < purchase.rail_amount:
        raise PaymentArtifactError(
            "payment coin minimum cannot be below the authorized rail amount"
        )
    candidates: list[tuple[Coin, Mapping[str, Any]]] = []
    for record in records:
        coin = _coin_from_record(record)
        if (
            coin is not None
            and _record_is_unspent_coin(record, coin)
            and int(coin.amount) >= required_amount
        ):
            candidates.append((coin, record))
    for coin, _record in sorted(candidates, key=lambda item: int(item[0].amount)):
        if purchase.rail == PaymentRail.CHIA_XCH:
            return coin, payment_public_key, None
        parent_record = await coinset.get_coin_record_by_name(
            _hex32(coin.parent_coin_info)
        )
        parent_coin = _coin_from_record(parent_record)
        if parent_coin is None:
            continue
        height = int((parent_record or {}).get("spent_block_index") or 0)
        if height <= 0:
            continue
        solution = await coinset.get_puzzle_and_solution(
            _hex32(parent_coin.name()),
            height,
        )
        reveal_hex = (solution or {}).get("puzzle_reveal")
        if not isinstance(reveal_hex, str):
            continue
        try:
            args = match_cat_puzzle(
                uncurry_puzzle(
                    Program.from_bytes(
                        bytes.fromhex(reveal_hex.removeprefix("0x"))
                    )
                )
            )
            if args is None:
                continue
            _mod_hash, tail_hash, parent_inner = args
            if bytes32(tail_hash.as_atom()) != purchase.rail_asset_id:
                continue
            lineage = LineageProof(
                parent_name=parent_coin.parent_coin_info,
                inner_puzzle_hash=bytes32(parent_inner.get_tree_hash()),
                amount=parent_coin.amount,
            )
        except (TypeError, ValueError):
            continue
        return coin, payment_public_key, lineage
    return None


def _verify_buyer_signature(offer: Offer, network: str) -> None:
    additional_data = AGG_SIG_ME_DATA.get(network)
    if additional_data is None:
        raise PaymentArtifactError("unsupported Chia network")
    pairs: list[tuple[G1Element, bytes]] = []
    for spend in offer.coin_spends():
        conditions = conditions_dict_for_solution(
            spend.puzzle_reveal,
            spend.solution,
            INFINITE_COST,
        )
        pairs.extend(
            pkm_pairs_for_conditions_dict(
                conditions,
                spend.coin,
                additional_data,
            )
        )
    if not pairs or not AugSchemeMPL.aggregate_verify(
        [pair[0] for pair in pairs],
        [pair[1] for pair in pairs],
        offer.aggregated_signature(),
    ):
        raise PaymentArtifactError("wallet signature does not authorize this offer")


def _coin_from_record(record: Any) -> Coin | None:
    if not isinstance(record, Mapping):
        return None
    value = record.get("coin")
    if not isinstance(value, Mapping):
        return None
    try:
        return Coin(
            bytes32.fromhex(str(value["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(value["puzzle_hash"]).removeprefix("0x")),
            uint64(int(value["amount"])),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _record_is_unspent_coin(record: Any, coin: Coin) -> bool:
    return (
        isinstance(record, Mapping)
        and int(record.get("confirmed_block_index") or 0) > 0
        and not bool(record.get("spent"))
        and int(record.get("spent_block_index") or 0) == 0
        and _coin_from_record(record) == coin
    )


def _coin_spend_json(spend: Any) -> dict[str, Any]:
    return {
        "coin": {
            "parent_coin_info": _hex32(spend.coin.parent_coin_info),
            "puzzle_hash": _hex32(spend.coin.puzzle_hash),
            "amount": int(spend.coin.amount),
        },
        "puzzle_reveal": "0x" + bytes(spend.puzzle_reveal).hex(),
        "solution": "0x" + bytes(spend.solution).hex(),
    }


def _hex_bytes(value: str, size: int, field: str) -> bytes:
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{field} is not valid hex") from exc
    if len(raw) != size:
        raise ValueError(f"{field} must be {size} bytes")
    return raw


def _hex32(value: Any) -> str:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError("value must be bytes32")
    return "0x" + raw.hex()


__all__ = ["router"]
