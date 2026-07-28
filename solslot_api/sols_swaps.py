"""Authenticated RC22 Sols-to-SmartDeed swap execution.

The protocol package owns offer construction. This module only reconstructs
the live chain inputs, binds them to a zkPassport-approved vault, collects the
wallet authorization, and submits the exact atomic bundle through the existing
fountain fee till.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import time
from typing import Annotated, Any, Mapping, Optional

from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    lineage_proof_for_coinsol,
)
from chia.wallet.trading.offer import Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from solslot_puzzles.pool_v4_driver import (
    PoolV4Config,
)
from solslot_puzzles.protocol_statutes_v1 import (
    CollectionStatute,
    PermanentRules,
    ScopedPause,
)
from solslot_puzzles.sols_economics_v3 import SolsEconomicState
from solslot_puzzles.sols_pool_v4 import (
    PoolInventoryRecord,
    SolsPoolStateV4,
    inventory_root,
    prepare_sols_to_deed,
)
from solslot_puzzles.sols_swap_v4_driver import (
    SolsSwapOfferError,
    aggregate_sols_to_deed_swap,
    build_sols_to_deed_protocol_offer,
    prepare_sols_buyer_offer,
    validate_sols_buyer_offer,
)
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    compact_signature_from_evm,
    one_leaf_merkle_root,
    puzzle_hash_for_p2_vault,
)
from solslot_puzzles.vault_v2_driver import (
    eip712_typed_data_for_sols_swap,
    puzzle_for_vault_v2_full,
)

from .chia_provider import ChiaProvider, ChiaProviderError
from .config import Settings, get_settings
from .credential_auth import (
    require_alpha_writes,
    require_vault_record,
    verify_vault_session,
)
from .evm_auth import recover_evm_signer
from .faucet import AGG_SIG_ME_DATA
from .launch_gates import require_operation_gate
from .protocol_submission import (
    ProtocolBundleSubmitter,
    ProtocolSubmissionError,
)
from .public_artifact import (
    PublicArtifactError,
    load_signed_public_artifact,
)
from .sols_market import (
    PoolState,
    SingletonTip,
    StatutesSnapshot,
    _artifact_permanent_rules,
    _decode_pool_state,
    _initial_pool_state,
    _latest_solution,
    _program,
    _singleton_struct,
    _singleton_tip,
    _statutes_snapshot,
)
from .state import VaultRecord
from .vault_eligibility import ApprovedVault, require_current_approved_vault


router = APIRouter(prefix="/sols", tags=["sols-secondary-swaps"])

SOLS_SWAP_QUOTE_TTL_SECONDS = 600
MAX_WALLET_PUBLIC_KEYS = 100


class SolsSwapModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class PrepareSolsSwapRequest(SolsSwapModel):
    deed_launcher_id: str = Field(
        alias="deedLauncherId",
        min_length=66,
        max_length=66,
    )
    payment_public_keys: list[str] = Field(
        alias="paymentPublicKeys",
        min_length=1,
        max_length=MAX_WALLET_PUBLIC_KEYS,
    )

    @field_validator("deed_launcher_id")
    @classmethod
    def validate_deed_launcher_id(cls, value: str) -> str:
        return _hex32_text(value, "deedLauncherId")

    @field_validator("payment_public_keys")
    @classmethod
    def validate_payment_public_keys(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            raw = _hex_bytes(value, 48, "paymentPublicKeys")
            G1Element.from_bytes(raw)
            encoded = "0x" + raw.hex()
            if encoded not in normalized:
                normalized.append(encoded)
        if not normalized:
            raise ValueError("at least one unique BLS payment key is required")
        return normalized


class PrepareSolsSwapResponse(SolsSwapModel):
    operation_hash: str = Field(alias="operationHash")
    deed_launcher_id: str = Field(alias="deedLauncherId")
    vault_launcher_id: str = Field(alias="vaultLauncherId")
    buyer_offer: str = Field(alias="buyerOffer")
    signing_coin_spends: list[dict[str, Any]] = Field(alias="signingCoinSpends")
    selected_payment_public_key: str = Field(alias="selectedPaymentPublicKey")
    selected_payment_coin_id: str = Field(alias="selectedPaymentCoinId")
    quote_expires_at: int = Field(alias="quoteExpiresAt")
    principal_sols_mojos: int = Field(alias="principalSolsMojos")
    protocol_fee_sols_mojos: int = Field(alias="protocolFeeSolsMojos")
    sgt_rewards_fee_sols_mojos: int = Field(alias="sgtRewardsFeeSolsMojos")
    total_sols_mojos: int = Field(alias="totalSolsMojos")
    destination_p2_vault_hash: str = Field(alias="destinationP2VaultHash")
    vault_auth_type: str = Field(alias="vaultAuthType")
    vault_typed_data: Optional[dict[str, Any]] = Field(
        default=None,
        alias="vaultTypedData",
    )
    review: dict[str, Any]


class CompleteSolsSwapRequest(SolsSwapModel):
    deed_launcher_id: str = Field(
        alias="deedLauncherId",
        min_length=66,
        max_length=66,
    )
    operation_hash: str = Field(
        alias="operationHash",
        min_length=66,
        max_length=66,
    )
    quote_expires_at: int = Field(alias="quoteExpiresAt", gt=0)
    buyer_offer: str = Field(
        alias="buyerOffer",
        min_length=16,
        max_length=2_000_000,
    )
    aggregated_signature: str = Field(
        alias="aggregatedSignature",
        min_length=194,
        max_length=194,
    )
    vault_owner_authorization: Optional[str] = Field(
        default=None,
        alias="vaultOwnerAuthorization",
        min_length=132,
        max_length=132,
    )

    @field_validator("deed_launcher_id", "operation_hash")
    @classmethod
    def validate_bytes32_fields(cls, value: str, info: Any) -> str:
        return _hex32_text(value, info.field_name)


class CompleteSolsSwapResponse(SolsSwapModel):
    operation_hash: str = Field(alias="operationHash")
    deed_launcher_id: str = Field(alias="deedLauncherId")
    destination_p2_vault_hash: str = Field(alias="destinationP2VaultHash")
    transaction_id: str = Field(alias="transactionId")
    status: str
    fee_mojos: int = Field(alias="feeMojos")
    fee_target_seconds: int = Field(alias="feeTargetSeconds")
    submission_provider: str = Field(alias="submissionProvider")
    mempool_observed_at: str = Field(alias="mempoolObservedAt")


@dataclass(frozen=True)
class SolsPaymentCoin:
    coin: Coin
    public_key: bytes
    lineage: LineageProof


@dataclass(frozen=True)
class SolsSwapContext:
    artifact: dict[str, Any]
    config: PoolV4Config
    pool_state: SolsPoolStateV4
    pool_inventory: tuple[PoolInventoryRecord, ...]
    pool_coin: Coin
    pool_lineage: LineageProof
    statutes: StatutesSnapshot
    statutes_coin: Coin
    statutes_lineage: LineageProof
    collection: CollectionStatute
    pause: ScopedPause | None
    approved_vault: ApprovedVault
    vault_record: VaultRecord
    vault_coin: Coin
    vault_lineage: LineageProof
    custody_coin: Coin
    custody_lineage: LineageProof
    receipt: Any


@router.post(
    "/vaults/{vault_launcher_id}/swaps/prepare",
    response_model=PrepareSolsSwapResponse,
)
async def prepare_sols_swap(
    vault_launcher_id: str,
    body: PrepareSolsSwapRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> PrepareSolsSwapResponse:
    _authorize_swap(settings, request, vault_launcher_id)
    try:
        context = await _load_swap_context(
            settings=settings,
            provider=request.app.state.coinset,
            vault_launcher_id=vault_launcher_id,
            deed_launcher_id=body.deed_launcher_id,
            quote_expires_at=None,
        )
        quote = context.receipt.sols_to_deed_quote
        if quote is None:
            raise SolsSwapOfferError("Sols-to-deed quote is unavailable")
        payment = await _select_sols_payment_coin(
            request.app.state.coinset,
            context.config.permanent_rules.sols_tail_hash,
            body.payment_public_keys,
            quote.buyer_total_sols_mojos,
        )
        if payment is None:
            raise SolsSwapOfferError(
                "No single confirmed Sols coin can cover this swap."
            )
        buyer = prepare_sols_buyer_offer(
            payment_coin=payment.coin,
            payment_public_key=payment.public_key,
            payment_lineage_proof=payment.lineage,
            receipt=context.receipt,
            config=context.config,
            vault_launcher_id=context.vault_record.launcher_id,
        )
        signing_spends = list(buyer.offer.coin_spends())
        vault_typed_data: dict[str, Any] | None = None
        if context.vault_record.auth_type == AUTH_TYPE_BLS:
            protocol = _build_protocol_offer(context, signature_data=None)
            signing_spends.append(protocol.vault_spend)
            vault_auth_type = "chia_bls"
        else:
            vault_typed_data = eip712_typed_data_for_sols_swap(
                context.receipt.operation_hash,
                context.vault_coin.name(),
            )
            vault_auth_type = "evm"
    except HTTPException:
        raise
    except (ChiaProviderError, PublicArtifactError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sols swap coordinates are unavailable: {exc}",
        ) from exc
    except (KeyError, TypeError, ValueError, SolsSwapOfferError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    destination = puzzle_hash_for_p2_vault(context.vault_record.launcher_id)
    return PrepareSolsSwapResponse(
        operationHash=_hex32(context.receipt.operation_hash),
        deedLauncherId=_hex32(context.receipt.record.deed_launcher_id),
        vaultLauncherId=_hex32(context.vault_record.launcher_id),
        buyerOffer=buyer.offer.to_bech32(),
        signingCoinSpends=[_coin_spend_json(item) for item in signing_spends],
        selectedPaymentPublicKey="0x" + payment.public_key.hex(),
        selectedPaymentCoinId=_hex32(payment.coin.name()),
        quoteExpiresAt=context.receipt.quote_expires_at,
        principalSolsMojos=quote.principal_sols_mojos,
        protocolFeeSolsMojos=quote.fee_split.protocol_fee_sols_mojos,
        sgtRewardsFeeSolsMojos=quote.fee_split.sgt_rewards_fee_sols_mojos,
        totalSolsMojos=quote.buyer_total_sols_mojos,
        destinationP2VaultHash=_hex32(destination),
        vaultAuthType=vault_auth_type,
        vaultTypedData=vault_typed_data,
        review={
            "network": settings.network,
            "asset": "SOLS",
            "deedLauncherId": _hex32(context.receipt.record.deed_launcher_id),
            "vaultLauncherId": _hex32(context.vault_record.launcher_id),
            "principalSolsMojos": str(quote.principal_sols_mojos),
            "protocolFeeSolsMojos": str(
                quote.fee_split.protocol_fee_sols_mojos
            ),
            "sgtRewardsFeeSolsMojos": str(
                quote.fee_split.sgt_rewards_fee_sols_mojos
            ),
            "totalSolsMojos": str(quote.buyer_total_sols_mojos),
            "quoteExpiresAt": context.receipt.quote_expires_at,
            "atomic": True,
            "reversibleAfterSubmission": False,
        },
    )


@router.post(
    "/vaults/{vault_launcher_id}/swaps/complete",
    response_model=CompleteSolsSwapResponse,
)
async def complete_sols_swap(
    vault_launcher_id: str,
    body: CompleteSolsSwapRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> CompleteSolsSwapResponse:
    _authorize_swap(settings, request, vault_launcher_id)
    lock = _swap_lock(request)
    async with lock:
        try:
            context = await _load_swap_context(
                settings=settings,
                provider=request.app.state.coinset,
                vault_launcher_id=vault_launcher_id,
                deed_launcher_id=body.deed_launcher_id,
                quote_expires_at=body.quote_expires_at,
            )
            if _hex32(context.receipt.operation_hash) != body.operation_hash:
                raise SolsSwapOfferError(
                    "Swap operation no longer matches current chain state."
                )
            unsigned = Offer.from_bech32(body.buyer_offer)
            if unsigned.aggregated_signature() != G2Element():
                raise SolsSwapOfferError("Prepared buyer offer must be unsigned.")
            validate_sols_buyer_offer(
                buyer_offer=unsigned,
                receipt=context.receipt,
                config=context.config,
                vault_launcher_id=context.vault_record.launcher_id,
            )
            signature_data = _vault_signature_data(context, body)
            protocol = _build_protocol_offer(
                context,
                signature_data=signature_data,
            )
            wallet_signature = G2Element.from_bytes(
                _hex_bytes(
                    body.aggregated_signature,
                    96,
                    "aggregatedSignature",
                )
            )
            signed_buyer = Offer(
                unsigned.requested_payments,
                WalletSpendBundle(unsigned.coin_spends(), wallet_signature),
                unsigned.driver_dict,
            )
            atomic = aggregate_sols_to_deed_swap(
                buyer_offer=signed_buyer,
                protocol_offer=protocol,
                receipt=context.receipt,
                config=context.config,
                vault_launcher_id=context.vault_record.launcher_id,
            )
            valid_spend = atomic.aggregate_offer.to_valid_spend()
            _verify_aggregate_signature(valid_spend, settings.network)
            inputs = (
                context.pool_coin,
                context.statutes_coin,
                context.vault_coin,
                context.custody_coin,
                *tuple(spend.coin for spend in unsigned.coin_spends()),
            )
            await _require_inputs_clear(request.app.state.coinset, inputs)
            submitter = getattr(
                request.app.state,
                "protocol_submitter",
                None,
            )
            if not isinstance(submitter, ProtocolBundleSubmitter):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        "Protocol fee funding is unavailable. The swap was "
                        "not submitted."
                    ),
                )
            result = await submitter.submit(valid_spend.to_json_dict())
        except HTTPException:
            raise
        except (ChiaProviderError, PublicArtifactError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Sols swap coordinates are unavailable: {exc}",
            ) from exc
        except ProtocolSubmissionError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    "The atomic Sols swap was not accepted into the local "
                    f"mempool: {exc}"
                ),
            ) from exc
        except (KeyError, TypeError, ValueError, SolsSwapOfferError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    return CompleteSolsSwapResponse(
        operationHash=_hex32(context.receipt.operation_hash),
        deedLauncherId=_hex32(context.receipt.record.deed_launcher_id),
        destinationP2VaultHash=_hex32(
            context.receipt.counterparty_puzzle_hash
        ),
        transactionId=str(result["spendBundleId"]),
        status=str(result["status"]),
        feeMojos=int(result["feeMojos"]),
        feeTargetSeconds=int(result["feeTargetSeconds"]),
        submissionProvider=str(result["submissionProvider"]),
        mempoolObservedAt=str(result["mempoolObservedAt"]),
    )


def _authorize_swap(
    settings: Settings,
    request: Request,
    vault_launcher_id: str,
) -> None:
    require_alpha_writes(settings)
    if settings.network != "testnet11":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sols secondary swaps are restricted to Testnet Alpha.",
        )
    require_operation_gate(settings, "purchases")
    session = verify_vault_session(settings, request, vault_launcher_id)
    if session.vault_launcher_id != _hex32_text(
        vault_launcher_id,
        "vaultLauncherId",
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault session does not own this swap.",
        )


async def _load_swap_context(
    *,
    settings: Settings,
    provider: ChiaProvider,
    vault_launcher_id: str,
    deed_launcher_id: str,
    quote_expires_at: int | None,
) -> SolsSwapContext:
    now = int(time())
    if quote_expires_at is not None and (
        quote_expires_at <= now
        or quote_expires_at > now + SOLS_SWAP_QUOTE_TTL_SECONDS
    ):
        raise SolsSwapOfferError("Sols swap quote is expired or too far ahead.")
    artifact = load_signed_public_artifact(settings)
    launchers = artifact["launcherIds"]
    pool_tip = await _required_singleton_tip(
        provider,
        str(launchers["pool"]),
        "Pool V4",
    )
    statutes_tip = await _required_singleton_tip(
        provider,
        str(launchers["statutes"]),
        "protocol statutes",
    )
    pool_solution = await _latest_solution(provider, pool_tip)
    if pool_solution is None:
        pool = _initial_pool_state(pool_tip, artifact)
        raise SolsSwapOfferError("Pool V4 has no SmartDeed inventory.")
    pool = _decode_pool_state(pool_solution, pool_tip)
    statutes = await _statutes_snapshot(provider, statutes_tip, artifact)
    pool_state = _pool_protocol_state(pool)
    config = _pool_config(
        pool_solution,
        artifact,
        pool_tip,
    )
    deed_id = _b32(deed_launcher_id, "deedLauncherId")
    records = [
        item for item in pool.inventory if item.deed_launcher_id == deed_id
    ]
    if len(records) != 1:
        raise SolsSwapOfferError(
            "SmartDeed is not available in current Pool V4 inventory."
        )
    record = records[0]
    collections = [
        item
        for item in statutes.collections
        if item.collection_id == record.collection_id
    ]
    if len(collections) != 1:
        raise SolsSwapOfferError(
            "SmartDeed collection has no current governed statute."
        )
    collection = collections[0]
    pauses = [
        item
        for item in statutes.pauses
        if item.scope_id == record.collection_id
    ]
    if len(pauses) > 1:
        raise SolsSwapOfferError("Collection has ambiguous pause state.")
    pause = pauses[0] if pauses else None
    if quote_expires_at is None:
        quote_expires_at = min(
            now + SOLS_SWAP_QUOTE_TTL_SECONDS,
            collection.valid_until,
        )
        if quote_expires_at <= now:
            raise SolsSwapOfferError("Governed NAV is expired.")
    if quote_expires_at > collection.valid_until:
        raise SolsSwapOfferError("Sols swap quote outlives governed NAV.")

    approved = require_current_approved_vault(
        settings,
        vault_launcher_id,
    )
    vault_record = require_vault_record(approved.launcher_id)
    if vault_record.auth_type not in (AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1):
        raise SolsSwapOfferError("Vault owner authorization is unsupported.")
    vault_coin, vault_lineage = await _confirmed_coin_and_lineage(
        provider,
        approved.current_coin_id,
        "approved vault coin",
    )
    pool_coin, pool_lineage = await _confirmed_coin_and_lineage(
        provider,
        pool_tip.live.coin_id,
        "Pool V4 coin",
    )
    statutes_coin, statutes_lineage = await _confirmed_coin_and_lineage(
        provider,
        statutes_tip.live.coin_id,
        "statutes coin",
    )
    custody_coin, custody_lineage = await _confirmed_coin_and_lineage(
        provider,
        _hex32(record.custody_coin_id),
        "SmartDeed custody coin",
    )
    members_root = one_leaf_merkle_root(bytes(vault_record.owner_pubkey))
    identity_root = _b32(
        approved.identity_attest_root,
        "identityAttestRoot",
    )
    expected_vault = puzzle_for_vault_v2_full(
        vault_launcher_id=vault_record.launcher_id,
        owner_pubkey=bytes(vault_record.owner_pubkey),
        auth_type=vault_record.auth_type,
        members_merkle_root=members_root,
        pool_launcher_id=config.pool_launcher_id,
        identity_attest_root=identity_root,
        zkpassport_bridge_policy_hash=(
            config.permanent_rules.zkpassport_policy_hash
        ),
    )
    if (
        vault_coin.puzzle_hash != expected_vault.get_tree_hash()
        or int(vault_coin.amount) != 1
    ):
        raise SolsSwapOfferError(
            "Approved vault coin does not match registered RC22 ownership."
        )
    receipt = prepare_sols_to_deed(
        pool_coin_id=pool_coin.name(),
        state=pool_state,
        inventory=pool.inventory,
        deed_launcher_id=record.deed_launcher_id,
        collection=collection,
        parameters=statutes.parameters,
        statutes_state=statutes.state,
        pause=pause,
        vault_launcher_id=vault_record.launcher_id,
        vault_coin_id=vault_coin.name(),
        destination_p2_vault_hash=puzzle_hash_for_p2_vault(
            vault_record.launcher_id
        ),
        quote_expires_at=quote_expires_at,
    )
    return SolsSwapContext(
        artifact=artifact,
        config=config,
        pool_state=pool_state,
        pool_inventory=pool.inventory,
        pool_coin=pool_coin,
        pool_lineage=pool_lineage,
        statutes=statutes,
        statutes_coin=statutes_coin,
        statutes_lineage=statutes_lineage,
        collection=collection,
        pause=pause,
        approved_vault=approved,
        vault_record=vault_record,
        vault_coin=vault_coin,
        vault_lineage=vault_lineage,
        custody_coin=custody_coin,
        custody_lineage=custody_lineage,
        receipt=receipt,
    )


def _build_protocol_offer(
    context: SolsSwapContext,
    *,
    signature_data: bytes | None,
) -> Any:
    return build_sols_to_deed_protocol_offer(
        receipt=context.receipt,
        config=context.config,
        parameters=context.statutes.parameters,
        collection=context.collection,
        pause=context.pause,
        statutes_state=context.statutes.state,
        statutes_coin=context.statutes_coin,
        statutes_launcher_id=_b32(
            context.artifact["launcherIds"]["statutes"],
            "statutesLauncherId",
        ),
        statutes_lineage_proof=context.statutes_lineage,
        collections=context.statutes.collections,
        pauses=context.statutes.pauses,
        vault_coin=context.vault_coin,
        vault_launcher_id=context.vault_record.launcher_id,
        vault_lineage_proof=context.vault_lineage,
        vault_owner_pubkey=bytes(context.vault_record.owner_pubkey),
        vault_auth_type=context.vault_record.auth_type,
        vault_members_merkle_root=one_leaf_merkle_root(
            bytes(context.vault_record.owner_pubkey)
        ),
        identity_attest_root=_b32(
            context.approved_vault.identity_attest_root,
            "identityAttestRoot",
        ),
        zkpassport_bridge_policy_hash=(
            context.config.permanent_rules.zkpassport_policy_hash
        ),
        vault_signature_data=signature_data,
        pool_coin=context.pool_coin,
        pool_lineage_proof=context.pool_lineage,
        custody_coin=context.custody_coin,
        custody_lineage_proof=context.custody_lineage,
        quote_expires_at=context.receipt.quote_expires_at,
    )


def _vault_signature_data(
    context: SolsSwapContext,
    body: CompleteSolsSwapRequest,
) -> bytes | None:
    record = context.vault_record
    if record.auth_type == AUTH_TYPE_BLS:
        if body.vault_owner_authorization is not None:
            raise SolsSwapOfferError(
                "BLS vault authorization belongs in the aggregate signature."
            )
        return None
    if not body.vault_owner_authorization or not record.owner_evm_address:
        raise SolsSwapOfferError("EVM vault owner authorization is required.")
    typed_data = eip712_typed_data_for_sols_swap(
        context.receipt.operation_hash,
        context.vault_coin.name(),
    )
    recovered = recover_evm_signer(
        typed_data,
        body.vault_owner_authorization,
    )
    if recovered.address.lower() != record.owner_evm_address.lower():
        raise SolsSwapOfferError(
            "EVM signature does not belong to this vault owner."
        )
    return compact_signature_from_evm(body.vault_owner_authorization)


async def _select_sols_payment_coin(
    provider: ChiaProvider,
    sols_tail_hash: bytes32,
    payment_public_keys: list[str],
    required_amount: int,
) -> SolsPaymentCoin | None:
    candidates: list[tuple[Coin, bytes]] = []
    for encoded in payment_public_keys:
        key = _hex_bytes(encoded, 48, "paymentPublicKeys")
        inner = puzzle_for_pk(G1Element.from_bytes(key))
        cat = construct_cat_puzzle(CAT_MOD, sols_tail_hash, inner)
        records = await provider.get_coin_records_by_puzzle_hash(
            _hex32(cat.get_tree_hash()),
            include_spent=False,
        )
        for record in records:
            coin = _coin_from_record(record)
            if (
                coin is not None
                and _record_is_unspent_coin(record, coin)
                and int(coin.amount) >= required_amount
            ):
                candidates.append((coin, key))
    for coin, key in sorted(
        candidates,
        key=lambda item: (int(item[0].amount), bytes(item[0].name())),
    ):
        if await provider.get_mempool_items_by_coin_name(_hex32(coin.name())):
            continue
        try:
            confirmed, lineage = await _confirmed_coin_and_lineage(
                provider,
                _hex32(coin.name()),
                "Sols payment coin",
            )
        except ValueError:
            continue
        return SolsPaymentCoin(
            coin=confirmed,
            public_key=key,
            lineage=lineage,
        )
    return None


async def _confirmed_coin_and_lineage(
    provider: ChiaProvider,
    coin_id: str,
    label: str,
) -> tuple[Coin, LineageProof]:
    normalized = _hex32_text(coin_id, label)
    record = await provider.get_coin_record_by_name(normalized)
    coin = _coin_from_record(record)
    if (
        coin is None
        or not _record_is_unspent_coin(record, coin)
        or _hex32(coin.name()) != normalized
    ):
        raise ValueError(f"{label} is not confirmed and unspent")
    parent_id = _hex32(coin.parent_coin_info)
    parent_record = await provider.get_coin_record_by_name(parent_id)
    parent_coin = _coin_from_record(parent_record)
    child_height = int((record or {}).get("confirmed_block_index") or 0)
    parent_height = int((parent_record or {}).get("spent_block_index") or 0)
    if (
        parent_coin is None
        or parent_coin.name() != coin.parent_coin_info
        or child_height <= 0
        or parent_height != child_height
    ):
        raise ValueError(f"{label} lineage is not atomic")
    parent_solution = await provider.get_puzzle_and_solution(
        parent_id,
        parent_height,
    )
    if not isinstance(parent_solution, Mapping):
        raise ValueError(f"{label} parent spend is unavailable")
    try:
        parent_spend = make_spend(
            parent_coin,
            _program(str(parent_solution["puzzle_reveal"])),
            _program(str(parent_solution["solution"])),
        )
        lineage = lineage_proof_for_coinsol(parent_spend)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} parent spend is malformed") from exc
    return coin, lineage


def _pool_config(
    pool_solution: Mapping[str, Any],
    artifact: Mapping[str, Any],
    tip: SingletonTip,
) -> PoolV4Config:
    full = _program(str(pool_solution["puzzle_reveal"]))
    full_uncurried = full.uncurry()
    if full_uncurried is None:
        raise SolsSwapOfferError("Pool V4 puzzle is not curried.")
    _full_mod, full_args_program = full_uncurried
    full_args = list(full_args_program.as_iter())
    if len(full_args) != 2:
        raise SolsSwapOfferError("Pool V4 singleton arguments are malformed.")
    inner_uncurried = full_args[1].uncurry()
    if inner_uncurried is None:
        raise SolsSwapOfferError("Pool V4 inner puzzle is not curried.")
    _inner_mod, inner_args_program = inner_uncurried
    inner_args = list(inner_args_program.as_iter())
    if len(inner_args) != 13:
        raise SolsSwapOfferError("Pool V4 inner arguments are malformed.")
    statutes_values = list(inner_args[2].as_iter())
    market_values = list(inner_args[3].as_iter())
    if len(statutes_values) != 9 or len(market_values) != 7:
        raise SolsSwapOfferError("Pool V4 immutable configuration is malformed.")
    permanent = PermanentRules(
        sgt_tail_hash=_node_b32(statutes_values[3], "SGT tail"),
        sgt_total_supply=int(statutes_values[4].as_int()),
        sols_tail_hash=_node_b32(statutes_values[5], "Sols tail"),
        zkpassport_policy_hash=_node_b32(
            statutes_values[6],
            "zkPassport policy",
        ),
        protocol_treasury_puzzle_hash=_node_b32(
            statutes_values[7],
            "protocol treasury",
        ),
        network_id=_node_b32(statutes_values[8], "network ID"),
    ).validate()
    if permanent != _artifact_permanent_rules(artifact):
        raise SolsSwapOfferError(
            "Pool V4 permanent rules do not match signed genesis."
        )
    pool_launcher = _b32(tip.launcher_id, "poolLauncherId")
    if bytes(inner_args[1]) != bytes(_singleton_struct(tip.launcher_id)):
        raise SolsSwapOfferError("Pool V4 singleton binding is invalid.")
    statutes_launcher = str(artifact["launcherIds"]["statutes"])
    governance_launcher = str(artifact["launcherIds"]["governance"])
    if (
        bytes(statutes_values[1]) != bytes(_singleton_struct(statutes_launcher))
        or bytes(statutes_values[2])
        != bytes(_singleton_struct(governance_launcher))
    ):
        raise SolsSwapOfferError(
            "Pool V4 statutes or governance binding is invalid."
        )
    return PoolV4Config(
        pool_launcher_id=pool_launcher,
        statutes_inner_mod_hash=_node_b32(
            statutes_values[0],
            "statutes module",
        ),
        statutes_singleton_struct=statutes_values[1],
        governance_singleton_struct=statutes_values[2],
        permanent_rules=permanent,
        cat_mod_hash=_node_b32(market_values[0], "CAT module"),
        offer_mod_hash=_node_b32(market_values[1], "offer module"),
        p2_vault_mod_hash=_node_b32(market_values[2], "p2 vault module"),
        vault_v2_mod_hash=_node_b32(market_values[3], "vault module"),
        p2_pool_v2_mod_hash=_node_b32(market_values[4], "p2 pool module"),
        reserve_puzzle_hash=_node_b32(market_values[5], "reserve puzzle"),
        sgt_rewards_puzzle_hash=_node_b32(
            market_values[6],
            "SGT rewards puzzle",
        ),
    )


def _pool_protocol_state(pool: PoolState) -> SolsPoolStateV4:
    return SolsPoolStateV4(
        inventory_root=inventory_root(pool.inventory),
        economics=SolsEconomicState(
            bootstrap_complete=pool.bootstrap_complete,
            inventory_nav_micro_usd=pool.inventory_nav_micro_usd,
            treasury_assets_micro_usd=pool.treasury_assets_micro_usd,
            proven_liabilities_micro_usd=pool.proven_liabilities_micro_usd,
            deed_count=pool.deed_count,
            total_sols_mojos=pool.total_sols_mojos,
            reserve_sols_mojos=pool.reserve_sols_mojos,
        ),
        state_version=pool.state_version,
    ).validate(pool.inventory)


def _verify_aggregate_signature(
    bundle: WalletSpendBundle,
    network: str,
) -> None:
    additional_data = AGG_SIG_ME_DATA.get(network)
    if additional_data is None:
        raise SolsSwapOfferError("Unsupported Chia network.")
    pairs: list[tuple[G1Element, bytes]] = []
    for spend in bundle.coin_spends:
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
        [item[0] for item in pairs],
        [item[1] for item in pairs],
        bundle.aggregated_signature,
    ):
        raise SolsSwapOfferError(
            "Wallet signature does not authorize the complete atomic swap."
        )


async def _require_inputs_clear(
    provider: ChiaProvider,
    coins: tuple[Coin, ...],
) -> None:
    seen: set[bytes32] = set()
    for coin in coins:
        coin_id = bytes32(coin.name())
        if coin_id in seen:
            raise SolsSwapOfferError("Atomic swap contains duplicate inputs.")
        seen.add(coin_id)
        pending = await provider.get_mempool_items_by_coin_name(
            _hex32(coin_id)
        )
        if pending:
            raise SolsSwapOfferError(
                "A swap input is already pending in the mempool."
            )


def _swap_lock(request: Request) -> asyncio.Lock:
    lock = getattr(request.app.state, "sols_swap_lock", None)
    if not isinstance(lock, asyncio.Lock):
        lock = asyncio.Lock()
        request.app.state.sols_swap_lock = lock
    return lock


async def _required_singleton_tip(
    provider: ChiaProvider,
    launcher_id: str,
    label: str,
) -> SingletonTip:
    tip = await _singleton_tip(provider, launcher_id)
    if tip is None:
        raise SolsSwapOfferError(f"{label} is not confirmed.")
    return tip


def _node_b32(node: Program, label: str) -> bytes32:
    raw = node.as_atom()
    if len(raw) != 32:
        raise SolsSwapOfferError(f"{label} must be 32 bytes.")
    return bytes32(raw)


def _b32(value: object, label: str) -> bytes32:
    return bytes32.fromhex(
        _hex32_text(value, label).removeprefix("0x")
    )


def _hex32(value: bytes | bytes32) -> str:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError("value must be 32 bytes")
    return "0x" + raw.hex()


def _hex32_text(value: object, label: str) -> str:
    text = str(value or "").strip().lower().removeprefix("0x")
    if len(text) != 64:
        raise ValueError(f"{label} must be exactly 32 bytes")
    bytes.fromhex(text)
    return "0x" + text


def _hex_bytes(value: object, size: int, label: str) -> bytes:
    text = str(value or "").strip().lower().removeprefix("0x")
    if len(text) != size * 2:
        raise ValueError(f"{label} must be exactly {size} bytes")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{label} must be hexadecimal") from exc


def _coin_from_record(record: Any) -> Coin | None:
    if not isinstance(record, Mapping):
        return None
    value = record.get("coin")
    if not isinstance(value, Mapping):
        return None
    try:
        return Coin(
            bytes32.fromhex(
                str(value["parent_coin_info"]).removeprefix("0x")
            ),
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


def _coin_spend_json(spend: CoinSpend) -> dict[str, Any]:
    return {
        "coin": {
            "parent_coin_info": _hex32(spend.coin.parent_coin_info),
            "puzzle_hash": _hex32(spend.coin.puzzle_hash),
            "amount": int(spend.coin.amount),
        },
        "puzzle_reveal": "0x" + bytes(spend.puzzle_reveal).hex(),
        "solution": "0x" + bytes(spend.solution).hex(),
    }


__all__ = [
    "CompleteSolsSwapRequest",
    "CompleteSolsSwapResponse",
    "PrepareSolsSwapRequest",
    "PrepareSolsSwapResponse",
    "SolsSwapContext",
    "complete_sols_swap",
    "prepare_sols_swap",
    "router",
]
