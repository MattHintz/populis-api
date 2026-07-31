"""Chain-authoritative Stripe inventory reservation and fulfillment."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time
from typing import Annotated, Any, Mapping

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.mint_publish_driver import (
    deed_launcher_puzzle_hash,
    deed_singleton_struct,
)
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentRail,
    PaymentAttestationV1,
    PaymentResolution,
    PaymentTransition,
)
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseArtifactV3,
    PurchaseKind,
    STRIPE_PAYMENT_PROVIDER_ID,
    STRIPE_RECEIPT_TTL_SECONDS,
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    StripeSettlementReceiptV1,
    build_stripe_pending_attestation,
    payment_attestation_from_json,
    payment_attestation_to_json,
    purchase_artifact_from_json,
    stripe_evidence_to_json,
    stripe_receipt_from_json,
    stripe_receipt_to_json,
)
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PrimaryMintTermsV3,
    build_inventory_extension_spend,
    build_inventory_release_spend,
    build_inventory_reservation_spend,
    build_stripe_primary_offer_v5,
    build_stripe_receipt_spend,
    make_inventory_available_inner,
    make_mint_offer_v5_inner,
    make_stripe_receipt_puzzle,
    prepare_stripe_receipt_offer,
    validator_roster_root,
)
from solslot_puzzles.voucher_presale_v3 import stripe_original_payer

from .collection_store import CollectionNotFound, get_collection_store
from .config import Settings, get_settings
from .credential_auth import require_minting_writes
from .kos_exact_execution import (
    ExactExecutionAction,
    ExactExecutionRequest,
    KeyOfSolomonExactExecutor,
)
from .launch_gates import require_operation_gate
from .mint_endpoints import get_mint_proposal_store
from .payment_purchase_store import (
    PaymentPurchaseConflict,
    PaymentPurchaseNotFound,
    PaymentPurchaseStore,
    PurchaseOperationState,
    StoredChainExecution,
    StoredPaymentPurchase,
    StoredPurchaseOperation,
    get_payment_purchase_store,
)
from .protocol_artifacts import (
    _artifact_rejection_reasons,
    _require_server_to_server_token,
)
from .protocol_submission import (
    PreparedProtocolBundle,
    ProtocolBundleSubmitter,
    ProtocolSubmissionError,
)
from .presale_endpoints import PresaleStore, get_presale_store
from .public_artifact import (
    PublicArtifactError,
    load_signed_public_artifact,
)
from .state import get_registry
from .validator_quorum import (
    InventoryExtensionClaim,
    InventoryReleaseClaim,
    InventoryReservationClaim,
    StripeSettlementClaim,
    ValidatorQuorumError,
    collect_inventory_extension_quorum,
    collect_inventory_release_quorum,
    collect_inventory_reservation_quorum,
    collect_stripe_settlement_quorum,
    configured_validator_pubkeys,
)


router = APIRouter(
    prefix="/protocol/stripe",
    tags=["stripe-fulfillment"],
)


class StripeFulfillmentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ReserveStripePurchaseRequest(StripeFulfillmentModel):
    expected_revision: int = Field(alias="expectedRevision", ge=1)


class RequestStripePresaleRefund(StripeFulfillmentModel):
    expected_revision: int = Field(alias="expectedRevision", ge=1)


@dataclass(frozen=True)
class StripeReservationContext:
    stored: StoredPaymentPurchase
    operation: StoredPurchaseOperation
    purchase: PurchaseArtifactV3
    terms: PrimaryMintTermsV3
    available_coin: Coin
    deed_struct: Any
    available_lineage: LineageProof
    genesis_artifact: dict[str, Any]
    credential_receipt: dict[str, Any]
    credential_owner_auth_type: int
    credential_owner_key: bytes


@dataclass(frozen=True)
class StripeReservedContext:
    stored: StoredPaymentPurchase
    operation: StoredPurchaseOperation
    purchase: PurchaseArtifactV3
    terms: PrimaryMintTermsV3
    reserved_coin: Coin
    deed_struct: Any
    reserved_lineage: LineageProof
    genesis_artifact: dict[str, Any]
    credential_receipt: dict[str, Any]
    credential_owner_auth_type: int
    credential_owner_key: bytes


@dataclass(frozen=True)
class StripeCommonContext:
    stored: StoredPaymentPurchase
    operation: StoredPurchaseOperation
    purchase: PurchaseArtifactV3
    terms: PrimaryMintTermsV3
    deed_struct: Any
    did_struct: Any
    deed_output_coin_id: str
    genesis_artifact: dict[str, Any]
    credential_receipt: dict[str, Any]
    credential_owner_auth_type: int
    credential_owner_key: bytes


@router.post("/purchases/{purchase_id}/reserve")
async def reserve_stripe_purchase(
    purchase_id: str,
    body: ReserveStripePurchaseRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    _require_server_to_server_token(settings, authorization)
    _require_stripe_fulfillment(settings)
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        operation = store.get_operation(purchase_id)
        if operation.rail.lower() != "stripe":
            raise PaymentPurchaseConflict(
                "purchase is not a Stripe operation"
            )
        if operation.state == PurchaseOperationState.ARTIFACT_READY:
            operation = store.begin_soft_hold(
                purchase_id,
                expected_revision=body.expected_revision,
                expires_at=int(time.time()) + 15 * 60,
                actor="customer-checkout",
            )
        elif operation.revision != body.expected_revision:
            raise PaymentPurchaseConflict(
                "purchase operation revision changed"
            )
        if operation.state == PurchaseOperationState.SOFT_HELD:
            operation = store.transition_operation(
                purchase_id,
                expected_revision=operation.revision,
                to_state=PurchaseOperationState.RESERVING,
                actor="stripe-coordinator",
                reason="exact SmartDeed reservation requested",
            )
        if operation.state == PurchaseOperationState.RESERVING:
            context = await _load_reservation_context(
                settings,
                request.app.state.coinset,
                store,
                purchase_id,
            )
            operation = await _dispatch_reservation(
                request=request,
                settings=settings,
                store=store,
                context=context,
            )
        if operation.state == PurchaseOperationState.RESERVATION_MEMPOOL:
            operation = await reconcile_stripe_reservation(
                request.app.state.coinset,
                store,
                operation,
            )
        if operation.state not in {
            PurchaseOperationState.RESERVATION_MEMPOOL,
            PurchaseOperationState.RESERVED,
            PurchaseOperationState.PAYMENT_METHOD_READY,
            PurchaseOperationState.PAYMENT_PROCESSING,
            PurchaseOperationState.PAYMENT_SUCCEEDED,
            PurchaseOperationState.RECEIPT_MEMPOOL,
            PurchaseOperationState.RECEIPT_READY,
            PurchaseOperationState.DELIVERY_SUBMITTED,
            PurchaseOperationState.MEMPOOL_OBSERVED,
            PurchaseOperationState.CHAIN_CONFIRMED,
            PurchaseOperationState.FINALIZED,
        }:
            raise PaymentPurchaseConflict(
                "Stripe purchase cannot reserve inventory from its current state"
            )
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (
        PaymentArtifactError,
        PaymentPurchaseConflict,
        ProtocolSubmissionError,
        ValidatorQuorumError,
        ValueError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "ok": True,
        "paymentMayBegin": (
            operation.state.value
            not in {
                PurchaseOperationState.RESERVATION_MEMPOOL.value,
            }
        ),
        "operation": _reservation_operation_json(operation),
    }


@router.post("/purchases/{purchase_id}/request-refund")
async def request_stripe_presale_refund(
    purchase_id: str,
    body: RequestStripePresaleRefund,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Request the exact full refund for an undelivered presale purchase."""

    require_minting_writes(settings)
    _require_server_to_server_token(settings, authorization)
    _require_stripe_fulfillment(settings)
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        operation = store.get_operation(purchase_id)
        if operation.rail.lower() != "stripe":
            raise PaymentPurchaseConflict(
                "purchase is not a Stripe operation"
            )
        if operation.purchase_kind != "PRESALE":
            raise PaymentPurchaseConflict(
                "buyer-choice refunds are limited to refundable presales"
            )
        if operation.revision != body.expected_revision:
            raise PaymentPurchaseConflict(
                "purchase operation revision changed"
            )
        if (
            operation.state != PurchaseOperationState.REFUND_PENDING
            or operation.refund_request_hash is None
            or operation.refund_requested_at is None
        ):
            raise PaymentPurchaseConflict(
                "the vault-approved voucher refund is not chain-confirmed"
            )
        operation = await ensure_stripe_inventory_release(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
            reason="PRESALE_REFUND",
        )
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (
        PaymentArtifactError,
        PaymentPurchaseConflict,
        ProtocolSubmissionError,
        ValidatorQuorumError,
        ValueError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "ok": True,
        "inventoryReleased": (
            operation.inventory_release_confirmation_height is not None
        ),
        "stripeRefundRequired": (
            operation.state == PurchaseOperationState.REFUND_PENDING
            and operation.inventory_release_confirmation_height is not None
            and operation.refund_id is None
        ),
        "operation": _reservation_operation_json(operation),
    }


async def _dispatch_reservation(
    *,
    request: Request,
    settings: Settings,
    store: PaymentPurchaseStore,
    context: StripeReservationContext,
) -> StoredPurchaseOperation:
    now = int(time.time())
    expires_at = min(
        now + 15 * 60,
        context.purchase.quote_expires_at,
        context.purchase.authorization_expires_at,
    )
    if expires_at <= now + 30:
        raise PaymentPurchaseConflict(
            "Stripe purchase authorization expires too soon to reserve"
        )
    reservation = InventoryReservationV1(
        artifact=context.purchase,
        expires_at=expires_at,
    )
    preview = build_inventory_reservation_spend(
        available_coin=context.available_coin,
        deed_singleton_struct=context.deed_struct,
        lineage_proof=context.available_lineage,
        reservation=reservation,
        signer_indices=(0, 1),
        terms=context.terms,
    )
    claim = InventoryReservationClaim(
        network=settings.network,
        genesis_artifact_hash=str(
            context.genesis_artifact["artifactHash"]
        ),
        purchase_artifact=context.stored.purchase_artifact,
        reservation_expires_at=reservation.expires_at,
        available_coin_id=_hex32(context.available_coin.name()),
        available_puzzle_hash=_hex32(
            context.available_coin.puzzle_hash
        ),
        reserved_coin_id=_hex32(preview.reserved_coin.name()),
        reserved_puzzle_hash=_hex32(
            preview.reserved_coin.puzzle_hash
        ),
        smart_deed_inner_hash=_hex32(
            context.terms.smart_deed_inner_hash
        ),
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
        validator_message=_hex32(preview.validator_message),
    )
    quorum = await collect_inventory_reservation_quorum(settings, claim)
    derived = build_inventory_reservation_spend(
        available_coin=context.available_coin,
        deed_singleton_struct=context.deed_struct,
        lineage_proof=context.available_lineage,
        reservation=reservation,
        signer_indices=quorum.signer_indices,
        terms=context.terms,
    )
    if (
        derived.reserved_coin != preview.reserved_coin
        or derived.validator_message != preview.validator_message
    ):
        raise PaymentPurchaseConflict(
            "validator quorum changed the canonical reservation"
        )
    unsigned = WalletSpendBundle(
        [derived.spend],
        quorum.aggregated_signature,
    )
    exact_request = ExactExecutionRequest(
        action=ExactExecutionAction.RESERVE,
        purchase_id=context.purchase.purchase_id,
        artifact_hash=context.purchase.artifact_hash,
        claim_hash=_bytes32(claim.canonical_hash(), "claim hash"),
        expected_output_coin_id=bytes32(derived.reserved_coin.name()),
        expected_output_puzzle_hash=bytes32(
            derived.reserved_coin.puzzle_hash
        ),
    )
    executor = getattr(request.app.state, "kos_exact_executor", None)
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(executor, KeyOfSolomonExactExecutor):
        raise PaymentPurchaseConflict(
            "Key of Solomon exact execution is unavailable"
        )
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise PaymentPurchaseConflict(
            "bounded protocol fee funding is unavailable"
        )

    try:
        existing = store.get_chain_execution(
            context.operation.purchase_id,
            "RESERVE",
        )
    except PaymentPurchaseNotFound:
        existing = None

    if existing is None:
        async def persist_and_dispatch(
            prepared: PreparedProtocolBundle,
        ) -> Mapping[str, Any]:
            execution = _save_prepared_execution(
                store,
                context.operation.purchase_id,
                "RESERVE",
                claim.canonical_hash(),
                prepared,
                derived.reserved_coin,
            )
            _assert_execution_matches_request(execution, exact_request)
            return await executor.dispatch(exact_request, prepared)

        result = await submitter.prepare_and_dispatch(
            unsigned.to_json_dict(),
            persist_and_dispatch,
        )
        execution = store.get_chain_execution(
            context.operation.purchase_id,
            "RESERVE",
        )
    else:
        _assert_execution_matches_request(existing, exact_request)
        prepared = _prepared_from_execution(existing)
        await executor.dispatch(exact_request, prepared)
        result = {
            "spendBundleId": existing.spend_bundle_id,
            "feeMojos": str(existing.fee_mojos),
        }

    current = store.get_operation(context.operation.purchase_id)
    if current.state == PurchaseOperationState.RESERVING:
        return store.transition_operation(
            current.purchase_id,
            expected_revision=current.revision,
            to_state=PurchaseOperationState.RESERVATION_MEMPOOL,
            actor="key-of-solomon",
            reason="exact reservation observed in local mempool",
            evidence={
                "claimHash": claim.canonical_hash(),
                "signerIndices": list(quorum.signer_indices),
            },
            changes={
                "reservation_coin_id": execution.expected_output_coin_id,
                "reservation_bundle_id": str(result["spendBundleId"]),
                "reservation_expires_at": reservation.expires_at,
                "fee_mojos": execution.fee_mojos,
            },
        )
    return current


async def reconcile_stripe_reservation(
    coinset: Any,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    if operation.state != PurchaseOperationState.RESERVATION_MEMPOOL:
        return operation
    if not operation.reservation_coin_id:
        raise PaymentPurchaseConflict(
            "reservation state is missing its output coin"
        )
    record = await coinset.get_coin_record_by_name(
        operation.reservation_coin_id
    )
    coin = _coin_from_record(record)
    confirmation_height = int(
        (record or {}).get("confirmed_block_index") or 0
    )
    if confirmation_height <= 0:
        return operation
    execution = store.get_chain_execution(
        operation.purchase_id,
        "RESERVE",
    )
    if (
        coin is None
        or _hex32(coin.name()) != execution.expected_output_coin_id
        or _hex32(coin.puzzle_hash)
        != execution.expected_output_puzzle_hash
        or int(coin.amount) != 1
    ):
        raise PaymentPurchaseConflict(
            "confirmed reservation coin does not match exact execution"
        )
    return store.transition_operation(
        operation.purchase_id,
        expected_revision=operation.revision,
        to_state=PurchaseOperationState.RESERVED,
        actor="chain-reconciler",
        reason="SmartDeed reservation confirmed on Testnet11",
        evidence={
            "confirmationHeight": confirmation_height,
            "reservationCoinId": operation.reservation_coin_id,
        },
        changes={
            "reservation_confirmation_height": confirmation_height,
        },
    )


async def ensure_stripe_reservation_extension(
    *,
    request: Request,
    settings: Settings,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
    phase: str,
) -> StoredPurchaseOperation:
    if phase not in {"PROCESSING", "SETTLEMENT"}:
        raise PaymentPurchaseConflict(
            "Stripe reservation extension phase is unsupported"
        )
    expected_state = (
        PurchaseOperationState.PAYMENT_PROCESSING
        if phase == "PROCESSING"
        else PurchaseOperationState.PAYMENT_SUCCEEDED
    )
    if operation.state != expected_state:
        return operation
    action = (
        "EXTEND_PROCESSING"
        if phase == "PROCESSING"
        else "EXTEND_SETTLEMENT"
    )
    exact_action = (
        ExactExecutionAction.EXTEND_PROCESSING
        if phase == "PROCESSING"
        else ExactExecutionAction.EXTEND_SETTLEMENT
    )
    try:
        existing = store.get_chain_execution(operation.purchase_id, action)
    except PaymentPurchaseNotFound:
        existing = None
    if existing is not None:
        if operation.reservation_coin_id == existing.expected_output_coin_id:
            return operation
        return await reconcile_stripe_reservation_extension(
            request.app.state.coinset,
            store,
            operation,
            phase=phase,
        )

    context = await _load_reserved_context(
        settings,
        request.app.state.coinset,
        store,
        operation.purchase_id,
    )
    if context.operation.reservation_expires_at is None:
        raise PaymentPurchaseConflict(
            "Stripe reservation expiry is unavailable"
        )
    current_expiry = context.operation.reservation_expires_at
    if phase == "SETTLEMENT" and current_expiry >= int(time.time()) + 49 * 60 * 60:
        return context.operation
    next_expiry = current_expiry + 11 * 24 * 60 * 60
    event_type = (
        "payment_intent.processing"
        if phase == "PROCESSING"
        else "payment_intent.succeeded"
    )
    event = store.get_stripe_event_for_type(
        operation.purchase_id,
        event_type,
    )
    stripe_evidence = _stripe_evidence_from_event(event, phase=phase)
    reservation = InventoryReservationV1(
        artifact=context.purchase,
        expires_at=current_expiry,
    )
    preview = build_inventory_extension_spend(
        reserved_coin=context.reserved_coin,
        deed_singleton_struct=context.deed_struct,
        lineage_proof=context.reserved_lineage,
        reservation=reservation,
        next_expires_at=next_expiry,
        signer_indices=(0, 1),
        terms=context.terms,
    )
    if preview.validator_message is None:
        raise PaymentPurchaseConflict(
            "Stripe reservation extension has no validator message"
        )
    claim = InventoryExtensionClaim(
        phase=phase,
        network=settings.network,
        genesis_artifact_hash=str(
            context.genesis_artifact["artifactHash"]
        ),
        purchase_artifact=context.stored.purchase_artifact,
        stripe_evidence=stripe_evidence_to_json(stripe_evidence),
        current_expires_at=current_expiry,
        next_expires_at=next_expiry,
        current_coin_id=_hex32(context.reserved_coin.name()),
        current_puzzle_hash=_hex32(context.reserved_coin.puzzle_hash),
        next_coin_id=_hex32(preview.next_coin.name()),
        next_puzzle_hash=_hex32(preview.next_coin.puzzle_hash),
        smart_deed_inner_hash=_hex32(
            context.terms.smart_deed_inner_hash
        ),
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
        credential_owner_auth_type=(
            context.credential_owner_auth_type
        ),
        credential_owner_key=(
            "0x" + context.credential_owner_key.hex()
        ),
        validator_message=_hex32(preview.validator_message),
    )
    quorum = await collect_inventory_extension_quorum(settings, claim)
    derived = build_inventory_extension_spend(
        reserved_coin=context.reserved_coin,
        deed_singleton_struct=context.deed_struct,
        lineage_proof=context.reserved_lineage,
        reservation=reservation,
        next_expires_at=next_expiry,
        signer_indices=quorum.signer_indices,
        terms=context.terms,
    )
    if (
        derived.next_coin != preview.next_coin
        or derived.validator_message != preview.validator_message
    ):
        raise PaymentPurchaseConflict(
            "validator quorum changed the canonical extension"
        )
    unsigned = WalletSpendBundle(
        [derived.spend],
        quorum.aggregated_signature,
    )
    exact_request = ExactExecutionRequest(
        action=exact_action,
        purchase_id=context.purchase.purchase_id,
        artifact_hash=context.purchase.artifact_hash,
        claim_hash=_bytes32(claim.canonical_hash(), "claim hash"),
        expected_output_coin_id=bytes32(derived.next_coin.name()),
        expected_output_puzzle_hash=bytes32(
            derived.next_coin.puzzle_hash
        ),
    )
    executor = getattr(request.app.state, "kos_exact_executor", None)
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(executor, KeyOfSolomonExactExecutor):
        raise PaymentPurchaseConflict(
            "Key of Solomon exact execution is unavailable"
        )
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise PaymentPurchaseConflict(
            "bounded protocol fee funding is unavailable"
        )

    async def persist_and_dispatch(
        prepared: PreparedProtocolBundle,
    ) -> Mapping[str, Any]:
        execution = _save_prepared_execution(
            store,
            context.operation.purchase_id,
            action,
            claim.canonical_hash(),
            prepared,
            derived.next_coin,
        )
        _assert_execution_matches_request(execution, exact_request)
        return await executor.dispatch(exact_request, prepared)

    await submitter.prepare_and_dispatch(
        unsigned.to_json_dict(),
        persist_and_dispatch,
    )
    return await reconcile_stripe_reservation_extension(
        request.app.state.coinset,
        store,
        context.operation,
        phase=phase,
    )


def _inventory_release_event(
    store: PaymentPurchaseStore,
    purchase_id: str,
    reason: str,
) -> tuple[str, Mapping[str, Any], StripeSettlementEvidenceV1]:
    if reason == "PAYMENT_FAILED":
        event: Mapping[str, Any] | None = None
        event_type = ""
        for candidate in (
            "payment_intent.payment_failed",
            "payment_intent.canceled",
        ):
            try:
                event = store.get_stripe_event_for_type(
                    purchase_id,
                    candidate,
                )
            except PaymentPurchaseNotFound:
                continue
            event_type = candidate
            break
        if event is None:
            raise PaymentPurchaseConflict(
                "terminal Stripe payment evidence is unavailable"
            )
        return (
            event_type,
            event,
            _stripe_evidence_from_event(event, phase="FAILED"),
        )
    event_type = "payment_intent.succeeded"
    event = store.get_stripe_event_for_type(purchase_id, event_type)
    return (
        event_type,
        event,
        _stripe_evidence_from_event(event, phase="SETTLEMENT"),
    )


def _requires_terminal_presale_voucher(
    *,
    purchase_kind: str,
    reason: str,
) -> bool:
    # A voucher exists only after final Stripe success. A failed or abandoned
    # payment must release its exact deed reservation without inventing one.
    return (
        purchase_kind == PurchaseKind.PRESALE.name
        and reason != "PAYMENT_FAILED"
    )


def stripe_timeout_release_claim_hash(
    *,
    purchase_id: bytes32,
    artifact_hash: bytes32,
    reservation_coin_id: bytes32,
    reservation_expires_at: int,
    output_coin_id: bytes32,
    output_puzzle_hash: bytes32,
) -> bytes32:
    """Bind a permissionless timeout release to one exact reservation."""

    if reservation_expires_at <= 0 or reservation_expires_at > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("reservation expiry must be uint64")
    digest = hashlib.sha256()
    digest.update(b"SOLSLOT_STRIPE_RESERVATION_TIMEOUT_RELEASE_V1")
    digest.update(bytes(purchase_id))
    digest.update(bytes(artifact_hash))
    digest.update(bytes(reservation_coin_id))
    digest.update(reservation_expires_at.to_bytes(8, "big"))
    digest.update(bytes(output_coin_id))
    digest.update(bytes(output_puzzle_hash))
    return bytes32(digest.digest())


async def ensure_stripe_timeout_release(
    *,
    request: Request,
    settings: Settings,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    """Return an unpaid expired reservation to canonical inventory."""

    if operation.state != PurchaseOperationState.RESERVED:
        return operation
    if operation.payment_intent_id is not None:
        raise PaymentPurchaseConflict(
            "a Stripe-bound reservation requires authenticated cancellation evidence"
        )
    expires_at = operation.reservation_expires_at
    if expires_at is None or int(time.time()) < expires_at:
        return operation
    try:
        existing = store.get_chain_execution(operation.purchase_id, "RELEASE")
    except PaymentPurchaseNotFound:
        existing = None
    if existing is not None:
        return await reconcile_stripe_inventory_release(
            request.app.state.coinset,
            store,
            operation,
        )
    context = await _load_reserved_context(
        settings,
        request.app.state.coinset,
        store,
        operation.purchase_id,
        require_credential=False,
    )
    reservation = InventoryReservationV1(
        artifact=context.purchase,
        expires_at=expires_at,
    )
    released = build_inventory_release_spend(
        reserved_coin=context.reserved_coin,
        deed_singleton_struct=context.deed_struct,
        lineage_proof=context.reserved_lineage,
        reservation=reservation,
        terms=context.terms,
        timed_out=True,
    )
    claim_hash = stripe_timeout_release_claim_hash(
        purchase_id=context.purchase.purchase_id,
        artifact_hash=context.purchase.artifact_hash,
        reservation_coin_id=bytes32(context.reserved_coin.name()),
        reservation_expires_at=expires_at,
        output_coin_id=bytes32(released.next_coin.name()),
        output_puzzle_hash=bytes32(released.next_coin.puzzle_hash),
    )
    unsigned = WalletSpendBundle([released.spend], G2Element())
    exact_request = ExactExecutionRequest(
        action=ExactExecutionAction.RELEASE,
        purchase_id=context.purchase.purchase_id,
        artifact_hash=context.purchase.artifact_hash,
        claim_hash=claim_hash,
        expected_output_coin_id=bytes32(released.next_coin.name()),
        expected_output_puzzle_hash=bytes32(released.next_coin.puzzle_hash),
    )
    executor = getattr(request.app.state, "kos_exact_executor", None)
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(executor, KeyOfSolomonExactExecutor):
        raise PaymentPurchaseConflict(
            "Key of Solomon exact execution is unavailable"
        )
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise PaymentPurchaseConflict(
            "bounded protocol fee funding is unavailable"
        )

    async def persist_and_dispatch(
        prepared: PreparedProtocolBundle,
    ) -> Mapping[str, Any]:
        execution = _save_prepared_execution(
            store,
            operation.purchase_id,
            "RELEASE",
            _hex32(claim_hash),
            prepared,
            released.next_coin,
        )
        _assert_execution_matches_request(execution, exact_request)
        return await executor.dispatch(exact_request, prepared)

    await submitter.prepare_and_dispatch(
        unsigned.to_json_dict(),
        persist_and_dispatch,
    )
    return await reconcile_stripe_inventory_release(
        request.app.state.coinset,
        store,
        operation,
    )


async def ensure_stripe_inventory_release(
    *,
    request: Request,
    settings: Settings,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
    reason: str,
) -> StoredPurchaseOperation:
    if reason not in {
        "PAYMENT_FAILED",
        "DELIVERY_TIMEOUT",
        "PRESALE_REFUND",
    }:
        raise PaymentPurchaseConflict(
            "Stripe inventory release reason is unsupported"
        )
    if operation.inventory_release_confirmation_height is not None:
        return operation
    try:
        existing = store.get_chain_execution(operation.purchase_id, "RELEASE")
    except PaymentPurchaseNotFound:
        existing = None
    if existing is not None:
        return await reconcile_stripe_inventory_release(
            request.app.state.coinset,
            store,
            operation,
        )
    if reason == "PAYMENT_FAILED" and (
        operation.state != PurchaseOperationState.PAYMENT_FAILED
    ):
        raise PaymentPurchaseConflict(
            "failed-payment release requires terminal payment state"
        )
    if reason in {"DELIVERY_TIMEOUT", "PRESALE_REFUND"} and (
        operation.state != PurchaseOperationState.REFUND_PENDING
    ):
        raise PaymentPurchaseConflict(
            "paid inventory release requires pending refund state"
        )
    if reason == "PRESALE_REFUND" and (
        operation.purchase_kind != "PRESALE"
        or operation.refund_request_hash is None
        or operation.refund_requested_at is None
    ):
        raise PaymentPurchaseConflict(
            "presale refund request is not immutably bound"
        )
    if _requires_terminal_presale_voucher(
        purchase_kind=operation.purchase_kind,
        reason=reason,
    ):
        try:
            voucher = get_presale_store(settings).stripe_voucher_by_purchase(
                operation.purchase_id
            )
        except KeyError as exc:
            raise PaymentPurchaseConflict(
                "presale inventory cannot release without its Stripe voucher"
            ) from exc
        if (
            voucher.get("state") != "REFUNDED"
            or int(voucher.get("terminalConfirmedHeight") or 0) <= 0
        ):
            raise PaymentPurchaseConflict(
                "presale voucher must be terminally refunded on Chia first"
            )
    context = await _load_reserved_context(
        settings,
        request.app.state.coinset,
        store,
        operation.purchase_id,
        require_credential=False,
    )
    if context.operation.reservation_expires_at is None:
        raise PaymentPurchaseConflict(
            "Stripe reservation expiry is unavailable"
        )
    event_type, _event, stripe_evidence = _inventory_release_event(
        store,
        operation.purchase_id,
        reason,
    )
    if (
        reason == "DELIVERY_TIMEOUT"
        and int(time.time())
        < stripe_evidence.observed_at + 48 * 60 * 60
    ):
        raise PaymentPurchaseConflict(
            "SmartDeed delivery has not exceeded forty-eight hours"
        )
    reservation = InventoryReservationV1(
        artifact=context.purchase,
        expires_at=context.operation.reservation_expires_at,
    )
    preview = build_inventory_release_spend(
        reserved_coin=context.reserved_coin,
        deed_singleton_struct=context.deed_struct,
        lineage_proof=context.reserved_lineage,
        reservation=reservation,
        terms=context.terms,
        timed_out=False,
        signer_indices=(0, 1),
    )
    if preview.validator_message is None:
        raise PaymentPurchaseConflict(
            "Stripe inventory release has no validator message"
        )
    expected_delivery = Coin(
        context.reserved_coin.name(),
        context.purchase.vault_p2_puzzle_hash,
        uint64(1),
    )
    claim = InventoryReleaseClaim(
        reason=reason,
        event_type=event_type,
        network=settings.network,
        genesis_artifact_hash=str(
            context.genesis_artifact["artifactHash"]
        ),
        purchase_artifact=context.stored.purchase_artifact,
        stripe_evidence=stripe_evidence_to_json(stripe_evidence),
        current_expires_at=reservation.expires_at,
        current_coin_id=_hex32(context.reserved_coin.name()),
        current_puzzle_hash=_hex32(context.reserved_coin.puzzle_hash),
        next_coin_id=_hex32(preview.next_coin.name()),
        next_puzzle_hash=_hex32(preview.next_coin.puzzle_hash),
        expected_delivery_coin_id=_hex32(expected_delivery.name()),
        smart_deed_inner_hash=_hex32(
            context.terms.smart_deed_inner_hash
        ),
        protocol_puzzle_hash=_hex32(context.terms.protocol_puzhash),
        request_hash=(
            operation.refund_request_hash
            if reason == "PRESALE_REFUND"
            else None
        ),
        requested_at=(
            operation.refund_requested_at
            if reason == "PRESALE_REFUND"
            else None
        ),
        validator_message=_hex32(preview.validator_message),
    )
    quorum = await collect_inventory_release_quorum(settings, claim)
    derived = build_inventory_release_spend(
        reserved_coin=context.reserved_coin,
        deed_singleton_struct=context.deed_struct,
        lineage_proof=context.reserved_lineage,
        reservation=reservation,
        terms=context.terms,
        timed_out=False,
        signer_indices=quorum.signer_indices,
    )
    if (
        derived.next_coin != preview.next_coin
        or derived.validator_message != preview.validator_message
    ):
        raise PaymentPurchaseConflict(
            "validator quorum changed the canonical inventory release"
        )
    unsigned = WalletSpendBundle(
        [derived.spend],
        quorum.aggregated_signature,
    )
    exact_request = ExactExecutionRequest(
        action=ExactExecutionAction.RELEASE,
        purchase_id=context.purchase.purchase_id,
        artifact_hash=context.purchase.artifact_hash,
        claim_hash=_bytes32(claim.canonical_hash(), "claim hash"),
        expected_output_coin_id=bytes32(derived.next_coin.name()),
        expected_output_puzzle_hash=bytes32(
            derived.next_coin.puzzle_hash
        ),
    )
    executor = getattr(request.app.state, "kos_exact_executor", None)
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(executor, KeyOfSolomonExactExecutor):
        raise PaymentPurchaseConflict(
            "Key of Solomon exact execution is unavailable"
        )
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise PaymentPurchaseConflict(
            "bounded protocol fee funding is unavailable"
        )

    async def persist_and_dispatch(
        prepared: PreparedProtocolBundle,
    ) -> Mapping[str, Any]:
        execution = _save_prepared_execution(
            store,
            context.operation.purchase_id,
            "RELEASE",
            claim.canonical_hash(),
            prepared,
            derived.next_coin,
        )
        _assert_execution_matches_request(execution, exact_request)
        return await executor.dispatch(exact_request, prepared)

    await submitter.prepare_and_dispatch(
        unsigned.to_json_dict(),
        persist_and_dispatch,
    )
    return await reconcile_stripe_inventory_release(
        request.app.state.coinset,
        store,
        context.operation,
    )


async def reconcile_stripe_inventory_release(
    coinset: Any,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    if operation.inventory_release_confirmation_height is not None:
        return operation
    execution = store.get_chain_execution(operation.purchase_id, "RELEASE")
    if (
        not operation.reservation_coin_id
        or operation.reservation_coin_id
        not in execution.required_input_coin_ids
    ):
        raise PaymentPurchaseConflict(
            "inventory release does not spend the exact reservation"
        )
    record = await coinset.get_coin_record_by_name(
        execution.expected_output_coin_id
    )
    coin = _coin_from_record(record)
    confirmation_height = int(
        (record or {}).get("confirmed_block_index") or 0
    )
    if confirmation_height <= 0:
        return operation
    if (
        coin is None
        or _hex32(coin.name()) != execution.expected_output_coin_id
        or _hex32(coin.puzzle_hash)
        != execution.expected_output_puzzle_hash
        or int(coin.amount) != 1
    ):
        raise PaymentPurchaseConflict(
            "confirmed inventory release does not match exact execution"
        )
    return store.record_inventory_release(
        operation.purchase_id,
        expected_revision=operation.revision,
        release_bundle_id=execution.spend_bundle_id,
        release_output_coin_id=execution.expected_output_coin_id,
        confirmation_height=confirmation_height,
        actor="chain-reconciler",
        evidence={
            "claimHash": execution.claim_hash,
            "confirmationHeight": confirmation_height,
        },
    )


async def advance_stripe_fulfillment(
    *,
    request: Request,
    settings: Settings,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    """Advance only the deterministic chain step allowed by current state."""

    require_minting_writes(settings)
    # The dynamic purchase window controls admission. Once an authenticated
    # payment is accepted, exact receipt-bound delivery or refund must converge
    # even if that window closes while card/ACH settlement is pending.
    _require_stripe_fulfillment(settings)
    if operation.state == PurchaseOperationState.RESERVED:
        return await ensure_stripe_timeout_release(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
        )
    if operation.state == PurchaseOperationState.PAYMENT_FAILED:
        return await ensure_stripe_inventory_release(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
            reason="PAYMENT_FAILED",
        )
    if operation.state in {
        PurchaseOperationState.PAYMENT_SUCCEEDED,
        PurchaseOperationState.RECEIPT_MEMPOOL,
        PurchaseOperationState.RECEIPT_READY,
        PurchaseOperationState.DELIVERY_SUBMITTED,
    }:
        try:
            succeeded_event = store.get_stripe_event_for_type(
                operation.purchase_id,
                "payment_intent.succeeded",
            )
            succeeded_evidence = _stripe_evidence_from_event(
                succeeded_event,
                phase="SETTLEMENT",
            )
        except PaymentPurchaseNotFound:
            succeeded_evidence = None
        if (
            succeeded_evidence is not None
            and int(time.time())
            >= succeeded_evidence.observed_at + 48 * 60 * 60
        ):
            operation = store.transition_operation(
                operation.purchase_id,
                expected_revision=operation.revision,
                to_state=PurchaseOperationState.REFUND_PENDING,
                actor="stripe-reconciler",
                reason="SmartDeed delivery exceeded forty-eight hours",
                changes={
                    "last_error": (
                        "delivery window expired; returning inventory before refund"
                    )
                },
            )
    if operation.state == PurchaseOperationState.REFUND_PENDING:
        return await ensure_stripe_inventory_release(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
            reason=(
                "PRESALE_REFUND"
                if operation.refund_request_hash is not None
                else "DELIVERY_TIMEOUT"
            ),
        )
    if operation.state == PurchaseOperationState.PAYMENT_PROCESSING:
        if (
            operation.payment_method_family == "us_bank_account"
            and operation.payment_method_ready_at is not None
            and int(time.time())
            >= operation.payment_method_ready_at + 10 * 24 * 60 * 60
        ):
            return store.transition_operation(
                operation.purchase_id,
                expected_revision=operation.revision,
                to_state=PurchaseOperationState.REVIEW_REQUIRED,
                actor="stripe-reconciler",
                reason="ACH remained unresolved for ten days",
                changes={
                    "last_error": (
                        "Bank payment is still unresolved; inventory remains "
                        "reserved for administrator review"
                    )
                },
            )
        return await ensure_stripe_reservation_extension(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
            phase="PROCESSING",
        )
    if operation.state == PurchaseOperationState.PAYMENT_SUCCEEDED:
        try:
            processing = store.get_chain_execution(
                operation.purchase_id,
                "EXTEND_PROCESSING",
            )
        except PaymentPurchaseNotFound:
            processing = None
        if (
            processing is not None
            and operation.reservation_coin_id
            != processing.expected_output_coin_id
        ):
            operation = await reconcile_stripe_reservation_extension(
                request.app.state.coinset,
                store,
                operation,
                phase="PROCESSING",
            )
            if (
                operation.reservation_coin_id
                != processing.expected_output_coin_id
            ):
                return operation
        operation = await ensure_stripe_reservation_extension(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
            phase="SETTLEMENT",
        )
        if (
            operation.reservation_expires_at is None
            or operation.reservation_expires_at
            < int(time.time()) + 49 * 60 * 60
        ):
            return operation
        if operation.purchase_kind == PurchaseKind.PRESALE.name:
            return await ensure_stripe_presale_voucher(
                request=request,
                settings=settings,
                store=store,
                operation=operation,
            )
        if operation.purchase_kind != PurchaseKind.DIRECT.name:
            raise PaymentPurchaseConflict(
                "Stripe purchase kind is unsupported"
            )
        return await ensure_stripe_receipt_coin(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
        )
    if operation.state in {
        PurchaseOperationState.VOUCHER_PENDING,
        PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
        PurchaseOperationState.VOUCHER_ESCROWED,
    }:
        return await ensure_stripe_presale_voucher(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
        )
    if operation.state == PurchaseOperationState.RECEIPT_MEMPOOL:
        operation = await reconcile_stripe_receipt_coin(
            request.app.state.coinset,
            store,
            operation,
        )
    if operation.state == PurchaseOperationState.RECEIPT_READY:
        return await ensure_stripe_delivery(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
        )
    if operation.state in {
        PurchaseOperationState.DELIVERY_SUBMITTED,
        PurchaseOperationState.MEMPOOL_OBSERVED,
        PurchaseOperationState.CHAIN_CONFIRMED,
    }:
        return await reconcile_stripe_delivery(
            request.app.state.coinset,
            store,
            operation,
        )
    return operation


async def reconcile_existing_stripe_chain_steps(
    *,
    coinset: Any,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
    presales: PresaleStore | None = None,
) -> StoredPurchaseOperation:
    try:
        store.get_chain_execution(operation.purchase_id, "RELEASE")
    except PaymentPurchaseNotFound:
        pass
    else:
        operation = await reconcile_stripe_inventory_release(
            coinset,
            store,
            operation,
        )
    for phase, action in (
        ("PROCESSING", "EXTEND_PROCESSING"),
        ("SETTLEMENT", "EXTEND_SETTLEMENT"),
    ):
        try:
            execution = store.get_chain_execution(
                operation.purchase_id,
                action,
            )
        except PaymentPurchaseNotFound:
            continue
        if operation.reservation_coin_id != execution.expected_output_coin_id:
            operation = await reconcile_stripe_reservation_extension(
                coinset,
                store,
                operation,
                phase=phase,
            )
    if operation.state == PurchaseOperationState.RECEIPT_MEMPOOL:
        operation = await reconcile_stripe_receipt_coin(
            coinset,
            store,
            operation,
        )
    if operation.state in {
        PurchaseOperationState.VOUCHER_PENDING,
        PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
        PurchaseOperationState.VOUCHER_ESCROWED,
    }:
        if presales is None:
            raise PaymentPurchaseConflict(
                "Stripe presale reconciliation store is unavailable"
            )
        try:
            voucher = presales.stripe_voucher_by_purchase(
                operation.purchase_id
            )
        except KeyError as exc:
            raise PaymentPurchaseConflict(
                "Stripe presale operation has no voucher record"
            ) from exc
        operation = _sync_stripe_voucher_operation(
            store,
            operation,
            voucher,
        )
    if operation.state in {
        PurchaseOperationState.DELIVERY_SUBMITTED,
        PurchaseOperationState.MEMPOOL_OBSERVED,
        PurchaseOperationState.CHAIN_CONFIRMED,
    }:
        operation = await reconcile_stripe_delivery(
            coinset,
            store,
            operation,
        )
    return operation


async def reconcile_stripe_reservation_extension(
    coinset: Any,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
    *,
    phase: str,
) -> StoredPurchaseOperation:
    action = (
        "EXTEND_PROCESSING"
        if phase == "PROCESSING"
        else "EXTEND_SETTLEMENT"
    )
    execution = store.get_chain_execution(operation.purchase_id, action)
    if operation.reservation_coin_id == execution.expected_output_coin_id:
        return operation
    if (
        not operation.reservation_coin_id
        or not operation.reservation_expires_at
        or operation.reservation_coin_id
        not in execution.required_input_coin_ids
    ):
        raise PaymentPurchaseConflict(
            "extension execution does not spend the current reservation"
        )
    record = await coinset.get_coin_record_by_name(
        execution.expected_output_coin_id
    )
    coin = _coin_from_record(record)
    confirmation_height = int(
        (record or {}).get("confirmed_block_index") or 0
    )
    if confirmation_height <= 0:
        return operation
    if (
        coin is None
        or _hex32(coin.name()) != execution.expected_output_coin_id
        or _hex32(coin.puzzle_hash)
        != execution.expected_output_puzzle_hash
        or int(coin.amount) != 1
    ):
        raise PaymentPurchaseConflict(
            "confirmed extension coin does not match exact execution"
        )
    return store.record_reservation_extension(
        operation.purchase_id,
        expected_revision=operation.revision,
        expected_current_coin_id=operation.reservation_coin_id,
        expected_current_expires_at=operation.reservation_expires_at,
        action=action,
        next_coin_id=execution.expected_output_coin_id,
        next_bundle_id=execution.spend_bundle_id,
        next_expires_at=(
            operation.reservation_expires_at + 11 * 24 * 60 * 60
        ),
        confirmation_height=confirmation_height,
        fee_mojos=execution.fee_mojos,
        actor="chain-reconciler",
        evidence={
            "confirmationHeight": confirmation_height,
            "claimHash": execution.claim_hash,
        },
    )


def _stripe_evidence_from_event(
    event: Mapping[str, Any],
    *,
    phase: str,
) -> StripeSettlementEvidenceV1:
    evidence = event.get("evidence")
    stripe = evidence.get("stripe") if isinstance(evidence, Mapping) else None
    if not isinstance(stripe, Mapping):
        raise PaymentPurchaseConflict(
            "durable Stripe event evidence is malformed"
        )
    method = {
        "card": StripeMethodFamily.CARD,
        "us_bank_account": StripeMethodFamily.US_BANK_ACCOUNT,
    }.get(str(stripe.get("paymentMethodFamily") or ""))
    funding = {
        "credit": StripeFundingType.CREDIT,
        "debit": StripeFundingType.DEBIT,
        "prepaid": StripeFundingType.PREPAID,
        "unknown": StripeFundingType.UNKNOWN,
        "bank_account": StripeFundingType.BANK_ACCOUNT,
    }.get(str(stripe.get("fundingType") or ""))
    if method is None or funding is None:
        raise PaymentPurchaseConflict(
            "Stripe payment method evidence is unsupported"
        )
    if phase == "PROCESSING":
        status_value = StripePaymentStatus.PROCESSING
    elif phase == "SETTLEMENT":
        status_value = StripePaymentStatus.SUCCEEDED
    elif phase == "FAILED":
        status_value = {
            "requires_payment_method": (
                StripePaymentStatus.REQUIRES_PAYMENT_METHOD
            ),
            "canceled": StripePaymentStatus.CANCELED,
        }.get(str(stripe.get("paymentStatus") or ""))
        if status_value is None:
            raise PaymentPurchaseConflict(
                "Stripe failure evidence is not terminal"
            )
    else:
        raise PaymentPurchaseConflict(
            "Stripe evidence phase is unsupported"
        )
    amount_field = (
        "amountReceivedMinor"
        if phase == "SETTLEMENT"
        else "amountMinor"
    )
    refunded = int(stripe.get("refundedMinor") or "0")
    amount = int(stripe.get(amount_field) or "0")
    refund_state = (
        StripeRefundState.NONE
        if refunded == 0
        else (
            StripeRefundState.FULL
            if refunded >= amount
            else StripeRefundState.PARTIAL
        )
    )
    return StripeSettlementEvidenceV1(
        stripe_account_id=str(stripe.get("accountId") or ""),
        livemode=bool(stripe.get("livemode")),
        payment_intent_id=str(stripe.get("paymentIntentId") or ""),
        event_id=str(stripe.get("eventId") or ""),
        amount_minor=amount,
        currency=str(stripe.get("currency") or ""),
        method_family=method,
        funding_type=funding,
        processing_charge_minor=int(
            stripe.get("processingChargeMinor") or "0"
        ),
        status=status_value,
        refunded_minor=refunded,
        refund_state=refund_state,
        dispute_state=(
            StripeDisputeState.OPEN
            if stripe.get("disputed") is True
            else StripeDisputeState.NONE
        ),
        observed_at=int(stripe.get("receivedAt") or event["receivedAt"]),
    )


def _load_or_create_stripe_receipt(
    store: PaymentPurchaseStore,
    context: StripeReservedContext,
) -> tuple[PaymentAttestationV1, StripeSettlementReceiptV1]:
    try:
        stored = store.get_settlement_receipt(
            context.operation.purchase_id
        )
    except PaymentPurchaseNotFound:
        stored = None
    if stored is not None:
        pending = payment_attestation_from_json(
            stored["pendingAttestation"]
        )
        receipt = stripe_receipt_from_json(stored["receipt"])
        if _hex32(receipt.receipt_hash) != stored["receiptHash"]:
            raise PaymentPurchaseConflict(
                "stored Stripe receipt hash is inconsistent"
            )
        return pending, receipt

    operation = context.operation
    if (
        operation.state != PurchaseOperationState.PAYMENT_SUCCEEDED
        or operation.payment_method_ready_at is None
        or operation.stripe_event_id is None
        or operation.reservation_expires_at is None
    ):
        raise PaymentPurchaseConflict(
            "Stripe payment is not ready for a settlement receipt"
        )
    event = store.get_stripe_event(operation.stripe_event_id)
    evidence = _stripe_evidence_from_event(event, phase="SETTLEMENT")
    if (
        evidence.method_family == StripeMethodFamily.US_BANK_ACCOUNT
        and operation.purchase_kind != PurchaseKind.PRESALE.name
    ):
        raise PaymentPurchaseConflict(
            "ACH settlement is permitted only for refundable presales"
        )
    if (
        evidence.payment_intent_id != operation.payment_intent_id
        or evidence.amount_minor != operation.total_amount_minor
        or evidence.processing_charge_minor
        != operation.processing_charge_minor
    ):
        raise PaymentPurchaseConflict(
            "Stripe settlement evidence changed after payment"
        )
    pending = build_stripe_pending_attestation(
        artifact=context.purchase,
        evidence=evidence,
        observed_at=operation.payment_method_ready_at,
    )
    succeeded = PaymentAttestationV1(
        purchase_id=context.purchase.purchase_id,
        artifact_hash=context.purchase.artifact_hash,
        transition=PaymentTransition.SUCCEEDED,
        resolution=PaymentResolution.DELIVER,
        provider_id=STRIPE_PAYMENT_PROVIDER_ID,
        external_reference_hash=evidence.payment_reference_hash,
        evidence_hash=evidence.evidence_hash,
        previous_attestation_hash=pending.attestation_hash,
        observed_at=evidence.observed_at,
    )
    expires_at = min(
        evidence.observed_at + STRIPE_RECEIPT_TTL_SECONDS,
        operation.reservation_expires_at,
    )
    if expires_at <= int(time.time()) + 5 * 60:
        raise PaymentPurchaseConflict(
            "Stripe reservation must be extended before receipt creation"
        )
    receipt_nonce = bytes32(
        Program.to(
            [
                b"SOLSLOT_STRIPE_RECEIPT_NONCE_V1",
                context.purchase.purchase_id,
                context.purchase.artifact_hash,
                evidence.payment_reference_hash,
                evidence.event_id.encode("ascii"),
            ]
        ).get_tree_hash()
    )
    receipt = StripeSettlementReceiptV1(
        artifact=context.purchase,
        evidence=evidence,
        attestation=succeeded,
        validator_roster_root=validator_roster_root(
            context.terms.validator_pubkeys
        ),
        validator_threshold=2,
        receipt_nonce=receipt_nonce,
        expires_at=expires_at,
    )
    store.save_settlement_receipt(
        operation.purchase_id,
        receipt_hash=_hex32(receipt.receipt_hash),
        pending_attestation=payment_attestation_to_json(pending),
        receipt=stripe_receipt_to_json(receipt),
    )
    return pending, receipt


async def ensure_stripe_presale_voucher(
    *,
    request: Request,
    settings: Settings,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    """Create and reconcile Voucher V3 instead of direct deed delivery."""

    if operation.purchase_kind != PurchaseKind.PRESALE.name:
        raise PaymentPurchaseConflict(
            "only a presale purchase can enter Stripe voucher issuance"
        )
    if operation.state not in {
        PurchaseOperationState.PAYMENT_SUCCEEDED,
        PurchaseOperationState.VOUCHER_PENDING,
        PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
        PurchaseOperationState.VOUCHER_ESCROWED,
    }:
        return operation
    context = await _load_reserved_context(
        settings,
        request.app.state.coinset,
        store,
        operation.purchase_id,
    )
    _pending, receipt = _load_or_create_stripe_receipt(store, context)
    presales = get_presale_store(settings)
    try:
        voucher = presales.stripe_voucher_by_purchase(operation.purchase_id)
    except KeyError:
        if operation.state != PurchaseOperationState.PAYMENT_SUCCEEDED:
            raise PaymentPurchaseConflict(
                "Stripe voucher operation has no durable voucher record"
            )
        voucher = presales.prepare_stripe_voucher(
            operation.presale_terms_hash,
            artifact=context.purchase,
            receipt=receipt,
            original_payer=stripe_original_payer(context.purchase),
            smart_deed_inner_hash=context.terms.smart_deed_inner_hash,
            payment_evidence_id=receipt.evidence.event_id,
        )
        operation = store.transition_operation(
            operation.purchase_id,
            expected_revision=operation.revision,
            to_state=PurchaseOperationState.VOUCHER_PENDING,
            actor="stripe-voucher-coordinator",
            reason="exact refundable Stripe voucher prepared",
            evidence={
                "voucherCommitmentHash": voucher["commitmentHash"],
                "seriesTermsHash": voucher["termsHash"],
            },
            changes={
                "receipt_hash": _hex32(receipt.receipt_hash),
                "last_error": None,
            },
        )

    worker = getattr(request.app.state, "voucher_issuance_worker", None)
    if worker is not None and voucher["state"] in {
        "PENDING_ISSUANCE",
        "ISSUANCE_SUBMITTED",
        "ESCROWED",
        "REFUNDING",
        "REDEEMING",
    }:
        await worker.reconcile_once()
        voucher = presales.stripe_voucher_by_purchase(operation.purchase_id)
    return _sync_stripe_voucher_operation(store, operation, voucher)


def _sync_stripe_voucher_operation(
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
    voucher: Mapping[str, Any],
) -> StoredPurchaseOperation:
    if voucher.get("purchaseId") != operation.purchase_id:
        raise PaymentPurchaseConflict(
            "Stripe voucher belongs to another purchase"
        )
    if voucher.get("commitment", {}).get("purchaseArtifactHash") != (
        store.get(operation.purchase_id).artifact_hash
    ):
        raise PaymentPurchaseConflict(
            "Stripe voucher artifact commitment changed"
        )
    state = str(voucher.get("state") or "")
    receipt_hash = str(voucher.get("stripeReceiptHash") or "").lower()
    if operation.receipt_hash not in {None, receipt_hash}:
        raise PaymentPurchaseConflict("Stripe voucher receipt hash changed")
    if state == "PENDING_ISSUANCE":
        return operation
    if state == "ISSUANCE_SUBMITTED":
        receipt_coin_id = str(voucher.get("receiptCoinId") or "").lower()
        bundle_id = str(voucher.get("issuanceBundleId") or "").lower()
        _bytes32(receipt_coin_id, "Stripe voucher receipt coin")
        _bytes32(bundle_id, "Stripe voucher issuance bundle")
        if operation.state == PurchaseOperationState.VOUCHER_PENDING:
            return store.transition_operation(
                operation.purchase_id,
                expected_revision=operation.revision,
                to_state=PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
                actor="voucher-issuance-worker",
                reason="refundable Stripe voucher observed in local mempool",
                evidence={
                    "voucherCommitmentHash": voucher["commitmentHash"],
                    "voucherLauncherId": voucher["voucherLauncherId"],
                },
                changes={
                    "receipt_hash": receipt_hash,
                    "receipt_coin_id": receipt_coin_id,
                    "receipt_bundle_id": bundle_id,
                },
            )
        return operation
    if state == "ESCROWED":
        receipt_coin_id = str(voucher.get("receiptCoinId") or "").lower()
        bundle_id = str(voucher.get("issuanceBundleId") or "").lower()
        confirmed_height = int(voucher.get("issuanceConfirmedHeight") or 0)
        if confirmed_height <= 0:
            raise PaymentPurchaseConflict(
                "escrowed Stripe voucher has no chain confirmation"
            )
        if operation.state in {
            PurchaseOperationState.VOUCHER_PENDING,
            PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
        }:
            return store.transition_operation(
                operation.purchase_id,
                expected_revision=operation.revision,
                to_state=PurchaseOperationState.VOUCHER_ESCROWED,
                actor="chain-reconciler",
                reason="refundable Stripe voucher confirmed on Testnet11",
                evidence={
                    "voucherCommitmentHash": voucher["commitmentHash"],
                    "voucherLauncherId": voucher["voucherLauncherId"],
                    "confirmationHeight": confirmed_height,
                },
                changes={
                    "receipt_hash": receipt_hash,
                    "receipt_coin_id": receipt_coin_id,
                    "receipt_bundle_id": bundle_id,
                    "receipt_confirmation_height": confirmed_height,
                    "last_error": None,
                },
            )
        return operation
    if state in {"REFUNDING", "REFUNDED", "REDEEMING", "REDEEMED"}:
        return operation
    raise PaymentPurchaseConflict("Stripe voucher state is unsupported")


async def ensure_stripe_receipt_coin(
    *,
    request: Request,
    settings: Settings,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    if operation.state != PurchaseOperationState.PAYMENT_SUCCEEDED:
        return operation
    context = await _load_reserved_context(
        settings,
        request.app.state.coinset,
        store,
        operation.purchase_id,
    )
    _pending, receipt = _load_or_create_stripe_receipt(store, context)
    receipt_puzzle = make_stripe_receipt_puzzle(
        receipt=receipt,
        validator_pubkeys=context.terms.validator_pubkeys,
    )
    executor = getattr(request.app.state, "kos_exact_executor", None)
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(executor, KeyOfSolomonExactExecutor):
        raise PaymentPurchaseConflict(
            "Key of Solomon exact execution is unavailable"
        )
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise PaymentPurchaseConflict(
            "bounded protocol fee funding is unavailable"
        )
    try:
        execution = store.get_chain_execution(
            operation.purchase_id,
            "RECEIPT",
        )
    except PaymentPurchaseNotFound:
        execution = None
    if execution is None:
        async def persist_and_dispatch(
            prepared: PreparedProtocolBundle,
            receipt_coin: Coin,
        ) -> Mapping[str, Any]:
            exact_request = ExactExecutionRequest(
                action=ExactExecutionAction.RECEIPT,
                purchase_id=context.purchase.purchase_id,
                artifact_hash=context.purchase.artifact_hash,
                claim_hash=receipt.receipt_hash,
                expected_output_coin_id=bytes32(receipt_coin.name()),
                expected_output_puzzle_hash=bytes32(
                    receipt_coin.puzzle_hash
                ),
            )
            saved = _save_prepared_execution(
                store,
                operation.purchase_id,
                "RECEIPT",
                _hex32(receipt.receipt_hash),
                prepared,
                receipt_coin,
            )
            _assert_execution_matches_request(saved, exact_request)
            return await executor.dispatch(exact_request, prepared)

        await submitter.prepare_funded_output_and_dispatch(
            output_puzzle_hash=bytes32(receipt_puzzle.get_tree_hash()),
            amount=1,
            dispatcher=persist_and_dispatch,
        )
        execution = store.get_chain_execution(
            operation.purchase_id,
            "RECEIPT",
        )
    else:
        if execution.expected_output_puzzle_hash != _hex32(
            receipt_puzzle.get_tree_hash()
        ):
            raise PaymentPurchaseConflict(
                "stored receipt execution uses another receipt puzzle"
            )
        exact_request = ExactExecutionRequest(
            action=ExactExecutionAction.RECEIPT,
            purchase_id=context.purchase.purchase_id,
            artifact_hash=context.purchase.artifact_hash,
            claim_hash=receipt.receipt_hash,
            expected_output_coin_id=_bytes32(
                execution.expected_output_coin_id,
                "receipt output coin",
            ),
            expected_output_puzzle_hash=_bytes32(
                execution.expected_output_puzzle_hash,
                "receipt output puzzle",
            ),
        )
        _assert_execution_matches_request(execution, exact_request)
        await executor.dispatch(
            exact_request,
            _prepared_from_execution(execution),
        )
    current = store.get_operation(operation.purchase_id)
    if current.state == PurchaseOperationState.PAYMENT_SUCCEEDED:
        current = store.transition_operation(
            current.purchase_id,
            expected_revision=current.revision,
            to_state=PurchaseOperationState.RECEIPT_MEMPOOL,
            actor="key-of-solomon",
            reason="authenticated Stripe receipt observed in local mempool",
            evidence={"receiptHash": _hex32(receipt.receipt_hash)},
            changes={
                "receipt_hash": _hex32(receipt.receipt_hash),
                "receipt_coin_id": execution.expected_output_coin_id,
                "receipt_bundle_id": execution.spend_bundle_id,
                "fee_mojos": execution.fee_mojos,
            },
        )
    return await reconcile_stripe_receipt_coin(
        request.app.state.coinset,
        store,
        current,
    )


async def reconcile_stripe_receipt_coin(
    coinset: Any,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    if operation.state != PurchaseOperationState.RECEIPT_MEMPOOL:
        return operation
    if not operation.receipt_coin_id:
        raise PaymentPurchaseConflict(
            "receipt mempool state has no expected output coin"
        )
    execution = store.get_chain_execution(operation.purchase_id, "RECEIPT")
    record = await coinset.get_coin_record_by_name(
        operation.receipt_coin_id
    )
    coin = _coin_from_record(record)
    confirmation_height = int(
        (record or {}).get("confirmed_block_index") or 0
    )
    if confirmation_height <= 0:
        return operation
    if (
        coin is None
        or _hex32(coin.name()) != execution.expected_output_coin_id
        or _hex32(coin.puzzle_hash)
        != execution.expected_output_puzzle_hash
        or int(coin.amount) != 1
    ):
        raise PaymentPurchaseConflict(
            "confirmed Stripe receipt coin does not match exact execution"
        )
    return store.transition_operation(
        operation.purchase_id,
        expected_revision=operation.revision,
        to_state=PurchaseOperationState.RECEIPT_READY,
        actor="chain-reconciler",
        reason="authenticated Stripe receipt confirmed on Testnet11",
        evidence={"confirmationHeight": confirmation_height},
        changes={
            "receipt_confirmation_height": confirmation_height,
        },
    )


async def ensure_stripe_delivery(
    *,
    request: Request,
    settings: Settings,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    if operation.state != PurchaseOperationState.RECEIPT_READY:
        return operation
    context = await _load_reserved_context(
        settings,
        request.app.state.coinset,
        store,
        operation.purchase_id,
    )
    pending, receipt = _load_or_create_stripe_receipt(store, context)
    if (
        operation.receipt_coin_id is None
        or operation.reservation_expires_at is None
    ):
        raise PaymentPurchaseConflict(
            "Stripe delivery evidence is incomplete"
        )
    receipt_record = await request.app.state.coinset.get_coin_record_by_name(
        operation.receipt_coin_id
    )
    receipt_coin = _coin_from_record(receipt_record)
    if (
        receipt_coin is None
        or not _record_is_unspent_coin(receipt_record, receipt_coin)
        or int(receipt_coin.amount) != 1
    ):
        raise PaymentPurchaseConflict(
            "authenticated Stripe receipt coin is unavailable"
        )
    reservation = InventoryReservationV1(
        artifact=context.purchase,
        expires_at=operation.reservation_expires_at,
    )
    preview_receipt_spend = build_stripe_receipt_spend(
        receipt_coin=receipt_coin,
        receipt=receipt,
        validator_pubkeys=context.terms.validator_pubkeys,
        signer_indices=(0, 1),
    )
    preview_receipt_offer = prepare_stripe_receipt_offer(
        receipt_spend=preview_receipt_spend,
        receipt=receipt,
        terms=context.terms,
    )
    preview = build_stripe_primary_offer_v5(
        receipt_offer=preview_receipt_offer,
        receipt_coin=receipt_coin,
        receipt=receipt,
        deed_coin=context.reserved_coin,
        deed_singleton_struct=context.deed_struct,
        lineage_proof=context.reserved_lineage,
        terms=context.terms,
        reservation=reservation,
    )
    outputs = compute_additions(preview.deed_spend)
    if len(outputs) != 1:
        raise PaymentPurchaseConflict(
            "Stripe delivery must create one SmartDeed successor"
        )
    expected_output = outputs[0]
    try:
        execution = store.get_chain_execution(
            operation.purchase_id,
            "DELIVER",
        )
    except PaymentPurchaseNotFound:
        execution = None
    executor = getattr(request.app.state, "kos_exact_executor", None)
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(executor, KeyOfSolomonExactExecutor):
        raise PaymentPurchaseConflict(
            "Key of Solomon exact execution is unavailable"
        )
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise PaymentPurchaseConflict(
            "bounded protocol fee funding is unavailable"
        )
    if execution is None:
        claim = StripeSettlementClaim(
            network=settings.network,
            genesis_artifact_hash=str(
                context.genesis_artifact["artifactHash"]
            ),
            pending_attestation=payment_attestation_to_json(pending),
            stripe_receipt=stripe_receipt_to_json(receipt),
            reservation_expires_at=operation.reservation_expires_at,
            receipt_coin_id=_hex32(receipt_coin.name()),
            receipt_puzzle_hash=_hex32(receipt_coin.puzzle_hash),
            deed_coin_id=_hex32(context.reserved_coin.name()),
            deed_puzzle_hash=_hex32(context.reserved_coin.puzzle_hash),
            expected_deed_output_coin_id=_hex32(expected_output.name()),
            expected_deed_output_puzzle_hash=_hex32(
                expected_output.puzzle_hash
            ),
            smart_deed_inner_hash=_hex32(
                context.terms.smart_deed_inner_hash
            ),
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
            credential_owner_auth_type=(
                context.credential_owner_auth_type
            ),
            credential_owner_key=(
                "0x" + context.credential_owner_key.hex()
            ),
        )
        quorum = await collect_stripe_settlement_quorum(settings, claim)
        receipt_spend = build_stripe_receipt_spend(
            receipt_coin=receipt_coin,
            receipt=receipt,
            validator_pubkeys=context.terms.validator_pubkeys,
            signer_indices=quorum.signer_indices,
        )
        receipt_offer = prepare_stripe_receipt_offer(
            receipt_spend=receipt_spend,
            receipt=receipt,
            terms=context.terms,
        )
        settlement = build_stripe_primary_offer_v5(
            receipt_offer=receipt_offer,
            receipt_coin=receipt_coin,
            receipt=receipt,
            deed_coin=context.reserved_coin,
            deed_singleton_struct=context.deed_struct,
            lineage_proof=context.reserved_lineage,
            terms=context.terms,
            reservation=reservation,
        )
        valid_spend = settlement.aggregate_offer.to_valid_spend()
        unsigned = WalletSpendBundle(
            list(valid_spend.coin_spends),
            quorum.aggregated_signature,
        )
        exact_request = ExactExecutionRequest(
            action=ExactExecutionAction.DELIVER,
            purchase_id=context.purchase.purchase_id,
            artifact_hash=context.purchase.artifact_hash,
            claim_hash=_bytes32(claim.canonical_hash(), "claim hash"),
            expected_output_coin_id=bytes32(expected_output.name()),
            expected_output_puzzle_hash=bytes32(
                expected_output.puzzle_hash
            ),
        )

        async def persist_and_dispatch(
            prepared: PreparedProtocolBundle,
        ) -> Mapping[str, Any]:
            saved = _save_prepared_execution(
                store,
                operation.purchase_id,
                "DELIVER",
                claim.canonical_hash(),
                prepared,
                expected_output,
            )
            _assert_execution_matches_request(saved, exact_request)
            return await executor.dispatch(exact_request, prepared)

        await submitter.prepare_and_dispatch(
            unsigned.to_json_dict(),
            persist_and_dispatch,
        )
        execution = store.get_chain_execution(
            operation.purchase_id,
            "DELIVER",
        )
    else:
        if (
            execution.expected_output_coin_id != _hex32(expected_output.name())
            or execution.expected_output_puzzle_hash
            != _hex32(expected_output.puzzle_hash)
        ):
            raise PaymentPurchaseConflict(
                "stored delivery execution targets another SmartDeed output"
            )
        exact_request = ExactExecutionRequest(
            action=ExactExecutionAction.DELIVER,
            purchase_id=context.purchase.purchase_id,
            artifact_hash=context.purchase.artifact_hash,
            claim_hash=_bytes32(execution.claim_hash, "claim hash"),
            expected_output_coin_id=bytes32(expected_output.name()),
            expected_output_puzzle_hash=bytes32(
                expected_output.puzzle_hash
            ),
        )
        await executor.dispatch(
            exact_request,
            _prepared_from_execution(execution),
        )
    current = store.get_operation(operation.purchase_id)
    if current.state == PurchaseOperationState.RECEIPT_READY:
        current = store.transition_operation(
            current.purchase_id,
            expected_revision=current.revision,
            to_state=PurchaseOperationState.DELIVERY_SUBMITTED,
            actor="key-of-solomon",
            reason="exact receipt-bound SmartDeed delivery submitted",
            evidence={"claimHash": execution.claim_hash},
            changes={
                "delivery_bundle_id": execution.spend_bundle_id,
                "expected_output_coin_id": (
                    execution.expected_output_coin_id
                ),
                "fee_mojos": execution.fee_mojos,
            },
        )
    if current.state == PurchaseOperationState.DELIVERY_SUBMITTED:
        current = store.transition_operation(
            current.purchase_id,
            expected_revision=current.revision,
            to_state=PurchaseOperationState.MEMPOOL_OBSERVED,
            actor="key-of-solomon",
            reason="SmartDeed delivery observed in the local mempool",
            evidence={"spendBundleId": execution.spend_bundle_id},
            changes={"mempool_observed_at": int(time.time())},
        )
    return await reconcile_stripe_delivery(
        request.app.state.coinset,
        store,
        current,
    )


async def reconcile_stripe_delivery(
    coinset: Any,
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    if operation.state not in {
        PurchaseOperationState.DELIVERY_SUBMITTED,
        PurchaseOperationState.MEMPOOL_OBSERVED,
        PurchaseOperationState.CHAIN_CONFIRMED,
    }:
        return operation
    if not operation.expected_output_coin_id:
        raise PaymentPurchaseConflict(
            "delivery state has no expected SmartDeed output"
        )
    execution = store.get_chain_execution(operation.purchase_id, "DELIVER")
    record = await coinset.get_coin_record_by_name(
        operation.expected_output_coin_id
    )
    output = _coin_from_record(record)
    confirmation_height = int(
        (record or {}).get("confirmed_block_index") or 0
    )
    if confirmation_height <= 0:
        return operation
    if (
        output is None
        or _hex32(output.name()) != execution.expected_output_coin_id
        or _hex32(output.puzzle_hash)
        != execution.expected_output_puzzle_hash
        or int(output.amount) != 1
    ):
        raise PaymentPurchaseConflict(
            "confirmed SmartDeed delivery does not match exact execution"
        )
    current = operation
    if current.state in {
        PurchaseOperationState.DELIVERY_SUBMITTED,
        PurchaseOperationState.MEMPOOL_OBSERVED,
    }:
        current = store.transition_operation(
            current.purchase_id,
            expected_revision=current.revision,
            to_state=PurchaseOperationState.CHAIN_CONFIRMED,
            actor="chain-reconciler",
            reason="SmartDeed delivery confirmed on Testnet11",
            evidence={"confirmationHeight": confirmation_height},
            changes={"confirmation_height": confirmation_height},
        )
    if current.state == PurchaseOperationState.CHAIN_CONFIRMED:
        current = store.transition_operation(
            current.purchase_id,
            expected_revision=current.revision,
            to_state=PurchaseOperationState.FINALIZED,
            actor="stripe-coordinator",
            reason="Stripe purchase and SmartDeed delivery finalized",
            evidence={
                "expectedOutputCoinId": execution.expected_output_coin_id,
                "confirmationHeight": confirmation_height,
            },
        )
    return current


async def _load_reservation_context(
    settings: Settings,
    coinset: Any,
    store: PaymentPurchaseStore,
    purchase_id: str,
) -> StripeReservationContext:
    common = await _load_common_stripe_context(
        settings,
        store,
        purchase_id,
        require_live=True,
    )
    expected_puzzle = SINGLETON_MOD.curry(
        common.deed_struct,
        make_inventory_available_inner(common.terms),
    )
    deed_record = await coinset.get_coin_record_by_name(
        common.deed_output_coin_id
    )
    deed_coin = _coin_from_record(deed_record)
    if (
        deed_coin is None
        or not _record_is_unspent_coin(deed_record, deed_coin)
        or deed_coin.parent_coin_info != common.purchase.deed_launcher_id
        or deed_coin.puzzle_hash != expected_puzzle.get_tree_hash()
        or int(deed_coin.amount) != 1
        or _hex32(deed_coin.name()) != common.deed_output_coin_id
    ):
        raise PaymentPurchaseConflict(
            "Governed SmartDeed inventory is not available"
        )
    launcher_record = await coinset.get_coin_record_by_name(
        _hex32(common.purchase.deed_launcher_id)
    )
    launcher_coin = _coin_from_record(launcher_record)
    if (
        launcher_coin is None
        or launcher_coin.name() != common.purchase.deed_launcher_id
        or launcher_coin.puzzle_hash
        != deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=common.did_struct
        )
        or int(launcher_coin.amount) != 1
    ):
        raise PaymentPurchaseConflict(
            "SmartDeed launcher lineage is unavailable"
        )
    return StripeReservationContext(
        stored=common.stored,
        operation=common.operation,
        purchase=common.purchase,
        terms=common.terms,
        available_coin=deed_coin,
        deed_struct=common.deed_struct,
        available_lineage=LineageProof(
            parent_name=launcher_coin.parent_coin_info,
            amount=launcher_coin.amount,
        ),
        genesis_artifact=common.genesis_artifact,
        credential_receipt=common.credential_receipt,
        credential_owner_auth_type=common.credential_owner_auth_type,
        credential_owner_key=common.credential_owner_key,
    )


async def _load_reserved_context(
    settings: Settings,
    coinset: Any,
    store: PaymentPurchaseStore,
    purchase_id: str,
    *,
    require_credential: bool = True,
) -> StripeReservedContext:
    common = await _load_common_stripe_context(
        settings,
        store,
        purchase_id,
        require_live=False,
        require_credential=require_credential,
    )
    operation = common.operation
    if (
        operation.reservation_coin_id is None
        or operation.reservation_expires_at is None
        or operation.reservation_confirmation_height is None
    ):
        raise PaymentPurchaseConflict(
            "confirmed Stripe reservation evidence is incomplete"
        )
    reservation = InventoryReservationV1(
        artifact=common.purchase,
        expires_at=operation.reservation_expires_at,
    )
    expected_puzzle = SINGLETON_MOD.curry(
        common.deed_struct,
        make_mint_offer_v5_inner(common.terms, reservation),
    )
    current_record = await coinset.get_coin_record_by_name(
        operation.reservation_coin_id
    )
    current_coin = _coin_from_record(current_record)
    if (
        current_coin is None
        or not _record_is_unspent_coin(current_record, current_coin)
        or int(current_coin.amount) != 1
        or current_coin.puzzle_hash != expected_puzzle.get_tree_hash()
        or _hex32(current_coin.name()) != operation.reservation_coin_id
    ):
        raise PaymentPurchaseConflict(
            "current Stripe reservation coin is unavailable"
        )
    parent_record = await coinset.get_coin_record_by_name(
        _hex32(current_coin.parent_coin_info)
    )
    parent_coin = _coin_from_record(parent_record)
    if (
        parent_coin is None
        or parent_coin.name() != current_coin.parent_coin_info
        or int(parent_coin.amount) != 1
    ):
        raise PaymentPurchaseConflict(
            "Stripe reservation lineage parent is unavailable"
        )
    if operation.reservation_parent_expires_at is None:
        parent_inner = make_inventory_available_inner(common.terms)
    else:
        parent_inner = make_mint_offer_v5_inner(
            common.terms,
            InventoryReservationV1(
                artifact=common.purchase,
                expires_at=operation.reservation_parent_expires_at,
            ),
        )
    parent_puzzle = SINGLETON_MOD.curry(common.deed_struct, parent_inner)
    if parent_coin.puzzle_hash != parent_puzzle.get_tree_hash():
        raise PaymentPurchaseConflict(
            "Stripe reservation lineage does not match governed inventory"
        )
    return StripeReservedContext(
        stored=common.stored,
        operation=operation,
        purchase=common.purchase,
        terms=common.terms,
        reserved_coin=current_coin,
        deed_struct=common.deed_struct,
        reserved_lineage=LineageProof(
            parent_name=parent_coin.parent_coin_info,
            inner_puzzle_hash=bytes32(parent_inner.get_tree_hash()),
            amount=parent_coin.amount,
        ),
        genesis_artifact=common.genesis_artifact,
        credential_receipt=common.credential_receipt,
        credential_owner_auth_type=common.credential_owner_auth_type,
        credential_owner_key=common.credential_owner_key,
    )


async def _load_common_stripe_context(
    settings: Settings,
    store: PaymentPurchaseStore,
    purchase_id: str,
    *,
    require_live: bool,
    require_credential: bool = True,
) -> StripeCommonContext:
    try:
        stored = store.get(purchase_id)
        operation = store.get_operation(purchase_id)
        purchase = purchase_artifact_from_json(stored.purchase_artifact)
        if require_live:
            purchase.assert_live(int(time.time()))
    except (
        PaymentPurchaseNotFound,
        PaymentArtifactError,
        ValueError,
    ) as exc:
        raise PaymentPurchaseConflict(
            "Stripe purchase artifact is missing, invalid, or expired"
        ) from exc
    if purchase.rail != PaymentRail.STRIPE:
        raise PaymentPurchaseConflict(
            "purchase artifact is not the Stripe rail"
        )
    if require_live:
        reasons = _artifact_rejection_reasons(
            stored.offer_artifact,
            stored.offer_artifact_hash,
            now=int(time.time()),
            settings=settings,
        )
        if reasons:
            raise PaymentPurchaseConflict(
                "Stripe purchase authorization is no longer current: "
                + ", ".join(reasons)
            )

    receipt_payload: dict[str, Any] = {}
    credential_owner_auth_type = 0
    credential_owner_key = b""
    if require_credential:
        from .zkpassport_enrollments import _sync_chia_stamp

        try:
            enrollment = _sync_chia_stamp(
                settings,
                _hex32(purchase.vault_launcher_id),
            )
        except HTTPException as exc:
            raise PaymentPurchaseConflict(
                "The approved vault credential is no longer current"
            ) from exc
        receipt = enrollment.receipt
        if (
            enrollment.status != "chia_confirmed"
            or receipt is None
            or receipt.vaultLauncherId != _hex32(purchase.vault_launcher_id)
            or receipt.identityAttestRoot
            != _hex32(purchase.zkpassport_root)
            or receipt.policyVersion != settings.zkpassport_policy_version
            or receipt.network != settings.network
            or receipt.bridgePolicyHash
            != settings.zkpassport_bridge_policy_hash
            or receipt.confirmedBlockIndex is None
        ):
            raise PaymentPurchaseConflict(
                "A current chain-confirmed zkPassport vault is required"
            )
        vault_record = get_registry().get(purchase.vault_launcher_id)
        if vault_record is None:
            raise PaymentPurchaseConflict(
                "The approved vault owner record is unavailable"
            )
        receipt_payload = receipt.model_dump()
        credential_owner_auth_type = vault_record.auth_type
        credential_owner_key = bytes(vault_record.owner_pubkey)

    protocol = stored.offer_artifact.get("protocol")
    if not isinstance(protocol, Mapping):
        raise PaymentPurchaseConflict(
            "Stripe purchase protocol context is missing"
        )
    workspace_id = protocol.get("collectionWorkspaceId")
    if not isinstance(workspace_id, str):
        raise PaymentPurchaseConflict(
            "Stripe purchase collection is missing"
        )
    try:
        collection = get_collection_store(settings).get(workspace_id)
    except CollectionNotFound as exc:
        raise PaymentPurchaseConflict(
            "Stripe purchase collection was not found"
        ) from exc
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
        raise PaymentPurchaseConflict(
            "Stripe SmartDeed is not published"
        )
    proposal = get_mint_proposal_store(settings).get(str(deed["proposalId"]))
    if (
        proposal is None
        or proposal.state not in {"EXECUTED", "MINTED"}
        or proposal.executed_bundle_id is None
        or proposal.smart_deed_inner_puzhash is None
        or deed.get("confirmationHeight") is None
        or not deed.get("outputCoinId")
    ):
        raise PaymentPurchaseConflict(
            "Stripe SmartDeed is not executed and chain-confirmed"
        )
    if (
        proposal.deed_launcher_id != bytes(purchase.deed_launcher_id)
        or bytes32(canonicalise_property_id(proposal.collection_id))
        != purchase.collection_id
        or proposal.property_id.casefold()
        != str(deed.get("deedId") or "").casefold()
        or proposal.share_ppm != purchase.share_ppm
    ):
        raise PaymentPurchaseConflict(
            "Stripe SmartDeed no longer matches its governed proposal"
        )

    try:
        genesis = load_signed_public_artifact(settings)
        launchers = genesis["launcherIds"]
        puzzle_hashes = genesis["puzzleHashes"]
        treasury = bytes32.fromhex(
            str(
                puzzle_hashes["protocolTreasuryPuzzleHash"]
            ).removeprefix("0x")
        )
        if (
            purchase.protocol_treasury_puzzle_hash != treasury
        ):
            raise PaymentArtifactError(
                "purchase treasury is not the ceremony treasury"
            )
        validator_pubkeys = configured_validator_pubkeys(settings)
        terms = PrimaryMintTermsV3.for_artifact(
            artifact=purchase,
            smart_deed_inner_hash=bytes32(
                bytes(proposal.smart_deed_inner_puzhash)
            ),
            protocol_puzhash=treasury,
            validator_pubkeys=validator_pubkeys,
        )
        did_struct = singleton_struct(
            bytes32.fromhex(
                str(launchers["did"]).removeprefix("0x")
            )
        )
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=did_struct,
        )
    except (
        KeyError,
        PublicArtifactError,
        PaymentArtifactError,
        TypeError,
        ValueError,
    ) as exc:
        raise PaymentPurchaseConflict(
            "Signed Stripe inventory coordinates are unavailable"
        ) from exc

    return StripeCommonContext(
        stored=stored,
        operation=operation,
        purchase=purchase,
        terms=terms,
        deed_struct=deed_struct,
        did_struct=did_struct,
        deed_output_coin_id=str(deed["outputCoinId"]).lower(),
        genesis_artifact=genesis,
        credential_receipt=receipt_payload,
        credential_owner_auth_type=credential_owner_auth_type,
        credential_owner_key=credential_owner_key,
    )


def _save_prepared_execution(
    store: PaymentPurchaseStore,
    purchase_id: str,
    action: str,
    claim_hash: str,
    prepared: PreparedProtocolBundle,
    expected_output: Coin,
) -> StoredChainExecution:
    return store.save_chain_execution(
        purchase_id,
        action=action,
        claim_hash=claim_hash,
        spend_bundle_id=_hex32(prepared.bundle.name()),
        required_input_coin_ids=[
            _hex32(coin.name()) for coin in prepared.bundle.removals()
        ],
        expected_output_coin_id=_hex32(expected_output.name()),
        expected_output_puzzle_hash=_hex32(
            expected_output.puzzle_hash
        ),
        fee_mojos=prepared.fee_mojos,
        spend_bundle=prepared.bundle.to_json_dict(),
    )


def _prepared_from_execution(
    execution: StoredChainExecution,
) -> PreparedProtocolBundle:
    try:
        bundle = WalletSpendBundle.from_json_dict(execution.spend_bundle)
    except Exception as exc:
        raise PaymentPurchaseConflict(
            "stored exact execution bundle is malformed"
        ) from exc
    if _hex32(bundle.name()) != execution.spend_bundle_id:
        raise PaymentPurchaseConflict(
            "stored exact execution bundle ID is inconsistent"
        )
    return PreparedProtocolBundle(
        bundle=bundle,
        fee_mojos=execution.fee_mojos,
        fee_coin_id="",
    )


def _assert_execution_matches_request(
    execution: StoredChainExecution,
    request: ExactExecutionRequest,
) -> None:
    if (
        execution.claim_hash != _hex32(request.claim_hash)
        or execution.expected_output_coin_id
        != _hex32(request.expected_output_coin_id)
        or execution.expected_output_puzzle_hash
        != _hex32(request.expected_output_puzzle_hash)
    ):
        raise PaymentPurchaseConflict(
            "stored exact execution does not match the current claim"
        )


def _require_stripe_fulfillment(settings: Settings) -> None:
    if not settings.stripe_smartdeed_fulfillment_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe SmartDeed fulfillment is disabled",
        )


def _coin_from_record(record: Any) -> Coin | None:
    if not isinstance(record, Mapping):
        return None
    value = record.get("coin")
    if not isinstance(value, Mapping):
        return None
    try:
        return Coin(
            _bytes32(str(value["parent_coin_info"]), "parent coin"),
            _bytes32(str(value["puzzle_hash"]), "puzzle hash"),
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


def _bytes32(value: str, field: str) -> bytes32:
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{field} is not valid hex") from exc
    if len(raw) != 32:
        raise ValueError(f"{field} must be 32 bytes")
    return bytes32(raw)


def _hex32(value: Any) -> str:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError("value must be bytes32")
    return "0x" + raw.hex()


def _reservation_operation_json(
    operation: StoredPurchaseOperation,
) -> dict[str, Any]:
    return {
        "purchaseId": operation.purchase_id,
        "revision": operation.revision,
        "state": operation.state.value,
        "deedLauncherId": operation.deed_launcher_id,
        "reservationCoinId": operation.reservation_coin_id,
        "reservationBundleId": operation.reservation_bundle_id,
        "reservationExpiresAt": operation.reservation_expires_at,
        "reservationConfirmationHeight": (
            operation.reservation_confirmation_height
        ),
        "inventoryReleaseBundleId": (
            operation.inventory_release_bundle_id
        ),
        "inventoryReleaseOutputCoinId": (
            operation.inventory_release_output_coin_id
        ),
        "inventoryReleaseConfirmationHeight": (
            operation.inventory_release_confirmation_height
        ),
        "refundRequestHash": operation.refund_request_hash,
        "refundRequestedAt": operation.refund_requested_at,
        "feeMojos": (
            str(operation.fee_mojos)
            if operation.fee_mojos is not None
            else None
        ),
    }


__all__ = [
    "advance_stripe_fulfillment",
    "ensure_stripe_inventory_release",
    "reconcile_existing_stripe_chain_steps",
    "reconcile_stripe_inventory_release",
    "reconcile_stripe_reservation",
    "router",
]
