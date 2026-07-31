"""Durable Stripe event inbox and forward-only purchase reconciliation."""

from __future__ import annotations

import time
from typing import Annotated, Any, Literal, Mapping

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    status,
)
from pydantic import BaseModel, ConfigDict, Field

from .admin_auth import AdminClaims, require_admin_jwt
from .admin_operations import require_admin_operation
from .config import Settings, get_settings
from .payment_purchase_store import (
    PaymentPurchaseConflict,
    PaymentPurchaseNotFound,
    PaymentPurchaseStore,
    PurchaseOperationState,
    StoredPurchaseOperation,
    get_payment_purchase_store,
)
from .protocol_artifacts import _require_server_to_server_token


router = APIRouter(prefix="/protocol/stripe", tags=["stripe-purchases"])


class StripeEventModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class StripeEventSnapshotV1(StripeEventModel):
    account_id: str = Field(alias="accountId", min_length=6, max_length=128)
    api_version: str = Field(alias="apiVersion", min_length=1, max_length=64)
    livemode: bool
    event_id: str = Field(alias="eventId", min_length=5, max_length=128)
    event_type: str = Field(alias="eventType", min_length=3, max_length=128)
    event_created_at: int = Field(alias="eventCreatedAt", ge=1)
    received_at: int = Field(alias="receivedAt", ge=1)
    payload_sha256: str = Field(
        alias="payloadSha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    informational: bool
    payment_intent_id: str = Field(
        alias="paymentIntentId",
        min_length=5,
        max_length=128,
    )
    payment_status: str = Field(
        alias="paymentStatus",
        pattern=(
            r"^(requires_payment_method|processing|succeeded|canceled)$"
        ),
    )
    amount_minor: str = Field(alias="amountMinor", pattern=r"^[1-9][0-9]*$")
    amount_received_minor: str = Field(
        alias="amountReceivedMinor",
        pattern=r"^(0|[1-9][0-9]*)$",
    )
    currency: str = Field(pattern=r"^usd$")
    payment_method_family: str = Field(
        alias="paymentMethodFamily",
        pattern=r"^(card|us_bank_account)$",
    )
    funding_type: str = Field(
        alias="fundingType",
        pattern=r"^(credit|debit|prepaid|unknown|bank_account)$",
    )
    processing_charge_minor: str = Field(
        alias="processingChargeMinor",
        pattern=r"^(0|[1-9][0-9]*)$",
    )
    charge_id: str | None = Field(
        default=None,
        alias="chargeId",
        min_length=5,
        max_length=128,
    )
    refunded_minor: str = Field(
        alias="refundedMinor",
        pattern=r"^(0|[1-9][0-9]*)$",
    )
    refund_id: str | None = Field(
        default=None,
        alias="refundId",
        min_length=5,
        max_length=128,
    )
    dispute_id: str | None = Field(
        default=None,
        alias="disputeId",
        min_length=5,
        max_length=128,
    )
    dispute_status: str | None = Field(
        default=None,
        alias="disputeStatus",
        min_length=1,
        max_length=64,
    )
    disputed: bool


class IngestStripeEventV1(StripeEventModel):
    schema_name: str = Field(
        alias="schema",
        pattern=r"^solslot\.stripe-event\.v1$",
    )
    purchase_intent_id: str = Field(
        alias="purchaseIntentId",
        min_length=8,
        max_length=96,
    )
    purchase_id: str = Field(
        alias="purchaseId",
        pattern=r"^0x[a-f0-9]{64}$",
    )
    artifact_hash: str = Field(
        alias="artifactHash",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    stripe: StripeEventSnapshotV1


class StripePaymentMethodReadyV1(StripeEventModel):
    expected_revision: int = Field(alias="expectedRevision", ge=1)
    payment_intent_id: str = Field(
        alias="paymentIntentId",
        min_length=5,
        max_length=128,
    )
    payment_method_family: str = Field(
        alias="paymentMethodFamily",
        pattern=r"^(card|us_bank_account)$",
    )
    funding_type: str = Field(
        alias="fundingType",
        pattern=r"^(credit|debit|prepaid|unknown|bank_account)$",
    )
    processing_charge_minor: str = Field(
        alias="processingChargeMinor",
        pattern=r"^(0|[1-9][0-9]*)$",
    )
    total_amount_minor: str = Field(
        alias="totalAmountMinor",
        pattern=r"^[1-9][0-9]*$",
    )


class AdminStripeReconcileV1(StripeEventModel):
    expected_revision: int = Field(alias="expectedRevision", ge=1)


class AdminStripeDisputeResolutionV1(StripeEventModel):
    expected_revision: int = Field(alias="expectedRevision", ge=1)
    resolution: Literal[
        "RESTORE_AFTER_WIN",
        "ACCEPT_LOSS_AND_RESTORE",
    ]


@router.post("/purchases/{purchase_id}/payment-method-ready")
async def stripe_payment_method_ready(
    purchase_id: str,
    body: StripePaymentMethodReadyV1,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    _require_configured_server_token(settings, authorization)
    if not settings.stripe_smartdeed_fulfillment_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe SmartDeed fulfillment is disabled",
        )
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        ready_at = int(time.time())
        operation = store.get_operation(purchase_id)
        if operation.rail.lower() != "stripe":
            raise PaymentPurchaseConflict(
                "purchase is not a Stripe operation"
            )
        require_stripe_method_for_purchase_kind(
            purchase_kind=operation.purchase_kind,
            payment_method_family=body.payment_method_family,
        )
        expected_charge = stripe_processing_charge_minor(
            subtotal_minor=(
                operation.base_amount_minor
                + operation.technology_fee_minor
            ),
            payment_method_family=body.payment_method_family,
            funding_type=body.funding_type,
            settings=settings,
        )
        supplied_charge = int(body.processing_charge_minor)
        supplied_total = int(body.total_amount_minor)
        if (
            supplied_charge != expected_charge
            or supplied_total
            != operation.base_amount_minor
            + operation.technology_fee_minor
            + expected_charge
        ):
            raise PaymentPurchaseConflict(
                "Stripe amount does not match the reviewed surcharge policy"
            )
        operation = store.transition_operation(
            purchase_id,
            expected_revision=body.expected_revision,
            to_state=PurchaseOperationState.PAYMENT_METHOD_READY,
            actor="telonium",
            reason="Stripe payment method and exact total prepared",
            evidence={
                "paymentMethodFamily": body.payment_method_family,
                "fundingType": body.funding_type,
                "processingChargeMinor": body.processing_charge_minor,
            },
            changes={
                "payment_intent_id": body.payment_intent_id,
                "payment_method_family": body.payment_method_family,
                "funding_type": body.funding_type,
                "payment_method_ready_at": ready_at,
                "processing_charge_minor": supplied_charge,
                "total_amount_minor": supplied_total,
            },
            now=ready_at,
        )
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except PaymentPurchaseConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return {"ok": True, "operation": _operation_json(operation)}


@router.post("/events")
async def ingest_stripe_event(
    body: IngestStripeEventV1,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    _require_configured_server_token(settings, authorization)
    _validate_stripe_release_identity(body.stripe, settings)
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        purchase = store.get(body.purchase_id)
        operation = store.get_operation(body.purchase_id)
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    if (
        purchase.purchase_intent_id != body.purchase_intent_id
        or purchase.offer_artifact_hash != body.artifact_hash
        or purchase.rail.lower() != "stripe"
        or operation.rail.lower() != "stripe"
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stripe event does not match the sealed purchase artifact",
        )
    evidence = body.model_dump(mode="json", by_alias=True)
    try:
        inserted = store.append_stripe_event(
            body.purchase_id,
            event_id=body.stripe.event_id,
            event_type=body.stripe.event_type,
            payment_intent_id=body.stripe.payment_intent_id,
            payload_sha256=body.stripe.payload_sha256,
            event_created_at=body.stripe.event_created_at,
            received_at=body.stripe.received_at,
            evidence=evidence,
        )
        operation, pending = _reconcile_stripe_events(
            store,
            body.purchase_id,
        )
    except (PaymentPurchaseConflict, PaymentPurchaseNotFound) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    fulfillment_error: str | None = None
    try:
        from .stripe_fulfillment import advance_stripe_fulfillment

        operation = await advance_stripe_fulfillment(
            request=request,
            settings=settings,
            store=store,
            operation=operation,
        )
    except Exception as exc:  # noqa: BLE001
        # Telonium has already persisted and forwarded the authenticated event.
        # A transient chain/validator failure is resumed by reconciliation and
        # must not turn the Stripe webhook into an unsafe duplicate retry.
        fulfillment_error = str(exc)[:512]
    return {
        "ok": True,
        "durablyPersisted": True,
        "inserted": inserted,
        "purchaseIntentId": purchase.purchase_intent_id,
        "purchaseId": purchase.purchase_id,
        "operation": _operation_json(operation),
        "pendingEventCount": pending,
        "fulfillmentPendingReason": fulfillment_error,
    }


async def _reconcile_purchase_operation(
    *,
    request: Request,
    settings: Settings,
    store: PaymentPurchaseStore,
    purchase_id: str,
) -> tuple[StoredPurchaseOperation, int]:
    operation = store.get_operation(purchase_id)
    if operation.rail.lower() != "stripe":
        raise PaymentPurchaseConflict(
            "purchase is not a Stripe operation"
        )
    if operation.state == PurchaseOperationState.RESERVATION_MEMPOOL:
        from .stripe_fulfillment import reconcile_stripe_reservation

        await reconcile_stripe_reservation(
            request.app.state.coinset,
            store,
            operation,
        )
    operation, pending = _reconcile_stripe_events(store, purchase_id)
    from .stripe_fulfillment import advance_stripe_fulfillment

    operation = await advance_stripe_fulfillment(
        request=request,
        settings=settings,
        store=store,
        operation=operation,
    )
    return operation, pending


@router.post("/purchases/{purchase_id}/reconcile")
async def reconcile_stripe_purchase(
    purchase_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    _require_configured_server_token(settings, authorization)
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        operation, pending = await _reconcile_purchase_operation(
            request=request,
            settings=settings,
            store=store,
            purchase_id=purchase_id,
        )
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    return {
        "ok": True,
        "operation": _operation_json(operation),
        "pendingEventCount": pending,
    }


@router.get("/admin/purchases")
async def admin_stripe_purchases(
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    state: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List PII-free Stripe operations for the administrator desk."""

    del claims
    states: tuple[PurchaseOperationState, ...] = ()
    if state:
        try:
            states = (PurchaseOperationState(state),)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Stripe operation state is invalid",
            ) from exc
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        operations = store.list_operations(
            rail="stripe",
            states=states,
            limit=limit,
        )
    except PaymentPurchaseConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return {
        "ok": True,
        "operations": [_operation_json(operation) for operation in operations],
    }


@router.get("/admin/purchases/{purchase_id}")
async def admin_stripe_purchase_detail(
    purchase_id: str,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    del claims
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        operation = store.get_operation(purchase_id)
        if operation.rail.lower() != "stripe":
            raise PaymentPurchaseConflict(
                "purchase is not a Stripe operation"
            )
        history = store.operation_history(purchase_id)
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except PaymentPurchaseConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return {
        "ok": True,
        "operation": _operation_json(operation),
        "history": history,
    }


@router.post("/admin/purchases/{purchase_id}/reconcile")
async def admin_reconcile_stripe_purchase(
    purchase_id: str,
    body: AdminStripeReconcileV1,
    request: Request,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Retry only the exact chain/payment result already committed."""

    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        current = store.get_operation(purchase_id)
        if current.rail.lower() != "stripe":
            raise PaymentPurchaseConflict(
                "purchase is not a Stripe operation"
            )
        if current.revision != body.expected_revision:
            raise PaymentPurchaseConflict(
                "purchase operation revision changed"
            )
        operation, pending = await _reconcile_purchase_operation(
            request=request,
            settings=settings,
            store=store,
            purchase_id=purchase_id,
        )
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except PaymentPurchaseConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return {
        "ok": True,
        "operation": _operation_json(operation),
        "pendingEventCount": pending,
        "requestedBy": claims.sub,
    }


@router.post(
    "/admin/purchases/{purchase_id}/resolve-dispute",
    dependencies=[Depends(require_admin_operation("stripe.dispute.resolve"))],
)
async def admin_resolve_stripe_dispute(
    purchase_id: str,
    body: AdminStripeDisputeResolutionV1,
    request: Request,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Resolve only final post-delivery dispute evidence with owner-plus-one."""

    operation_id = request.headers.get("X-Solslot-Admin-Operation-Id")
    if operation_id is None:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="owner-plus-one operation ID is required",
        )
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        operation = store.resolve_post_delivery_stripe_dispute(
            purchase_id,
            expected_revision=body.expected_revision,
            resolution=body.resolution,
            admin_operation_id=operation_id,
            actor=claims.sub,
        )
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except PaymentPurchaseConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return {"ok": True, "operation": _operation_json(operation)}


@router.get("/purchases/{purchase_id}")
async def stripe_purchase_status(
    purchase_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    _require_configured_server_token(settings, authorization)
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        operation = store.get_operation(purchase_id)
        if operation.state == PurchaseOperationState.RESERVATION_MEMPOOL:
            from .stripe_fulfillment import (
                reconcile_stripe_reservation,
            )

            operation = await reconcile_stripe_reservation(
                request.app.state.coinset,
                store,
                operation,
            )
        from .stripe_fulfillment import (
            reconcile_existing_stripe_chain_steps,
        )
        from .presale_endpoints import get_presale_store

        operation = await reconcile_existing_stripe_chain_steps(
            coinset=request.app.state.coinset,
            store=store,
            operation=operation,
            presales=get_presale_store(settings),
        )
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    if operation.rail.lower() != "stripe":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="purchase is not a Stripe operation",
        )
    return {"ok": True, "operation": _operation_json(operation)}


def _reconcile_stripe_events(
    store: PaymentPurchaseStore,
    purchase_id: str,
) -> tuple[StoredPurchaseOperation, int]:
    for event in store.list_unprocessed_stripe_events(
        purchase_id=purchase_id,
        limit=100,
    ):
        try:
            _apply_stripe_event(store, event)
        except (PaymentPurchaseConflict, PaymentPurchaseNotFound) as exc:
            store.record_stripe_event_processing(
                event["eventId"],
                processed=False,
                error=str(exc),
            )
            break
        else:
            store.record_stripe_event_processing(
                event["eventId"],
                processed=True,
            )
    operation = store.get_operation(purchase_id)
    pending = len(
        store.list_unprocessed_stripe_events(
            purchase_id=purchase_id,
            limit=500,
        )
    )
    return operation, pending


def _apply_stripe_event(
    store: PaymentPurchaseStore,
    event: Mapping[str, Any],
) -> StoredPurchaseOperation:
    operation = store.get_operation(str(event["purchaseId"]))
    evidence = _mapping(event, "evidence")
    stripe = _mapping(evidence, "stripe")
    event_type = str(stripe.get("eventType") or "")
    if stripe.get("informational") is True:
        return operation

    _require_payment_binding(operation, stripe)
    if event_type.startswith("charge.dispute."):
        return _apply_dispute(store, operation, stripe)
    if event_type.startswith("refund.") or event_type == "charge.refunded":
        return _apply_refund(store, operation, stripe)

    status_value = str(stripe.get("paymentStatus") or "")
    common_changes = _payment_changes(stripe)
    if operation.payment_method_ready_at is None:
        common_changes["payment_method_ready_at"] = int(
            stripe.get("receivedAt") or int(time.time())
        )
    if event_type == "payment_intent.processing":
        if operation.state in _PAYMENT_PROCESSING_OR_LATER:
            return operation
        if status_value != "processing":
            raise PaymentPurchaseConflict(
                "processing event does not report a processing PaymentIntent"
            )
        return store.transition_operation(
            operation.purchase_id,
            expected_revision=operation.revision,
            to_state=PurchaseOperationState.PAYMENT_PROCESSING,
            actor="stripe-webhook",
            reason="Stripe reports payment processing",
            evidence=evidence,
            changes=common_changes,
        )
    if event_type == "payment_intent.succeeded":
        if operation.state in _PAYMENT_SUCCEEDED_OR_LATER:
            return operation
        if status_value != "succeeded":
            raise PaymentPurchaseConflict(
                "succeeded event does not report a successful PaymentIntent"
            )
        if int(stripe["amountReceivedMinor"]) != operation.total_amount_minor:
            raise PaymentPurchaseConflict(
                "Stripe did not collect the exact committed total"
            )
        return store.transition_operation(
            operation.purchase_id,
            expected_revision=operation.revision,
            to_state=PurchaseOperationState.PAYMENT_SUCCEEDED,
            actor="stripe-webhook",
            reason="Stripe payment succeeded",
            evidence=evidence,
            changes={
                **common_changes,
                "stripe_event_id": str(stripe["eventId"]),
            },
        )
    if event_type in {
        "payment_intent.payment_failed",
        "payment_intent.canceled",
    }:
        # Stripe does not guarantee webhook delivery order. Telonium retrieves
        # the current PaymentIntent before forwarding each event, so an older
        # failure can legitimately carry the now-authoritative `succeeded`
        # status. Treat that stale event as consumed instead of leaving it at
        # the head of the durable inbox and blocking later events.
        if (
            status_value == "succeeded"
            or operation.state in _PAYMENT_SUCCEEDED_OR_LATER
        ):
            return operation
        if operation.state in {
            PurchaseOperationState.PAYMENT_FAILED,
            PurchaseOperationState.CANCELED,
            PurchaseOperationState.REVIEW_REQUIRED,
        }:
            return operation
        if status_value not in {"requires_payment_method", "canceled"}:
            raise PaymentPurchaseConflict(
                "terminal payment event reports a non-terminal PaymentIntent"
            )
        return store.transition_operation(
            operation.purchase_id,
            expected_revision=operation.revision,
            to_state=PurchaseOperationState.PAYMENT_FAILED,
            actor="stripe-webhook",
            reason="Stripe payment failed or was canceled",
            evidence=evidence,
            changes={
                **common_changes,
                "last_error": "Stripe payment did not settle",
            },
        )
    raise PaymentPurchaseConflict(
        "Stripe event has no protocol purchase transition"
    )


def _apply_refund(
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
    stripe: Mapping[str, Any],
) -> StoredPurchaseOperation:
    refunded_minor = int(stripe.get("refundedMinor") or "0")
    if refunded_minor == 0:
        return operation
    if refunded_minor != operation.total_amount_minor:
        if operation.state == PurchaseOperationState.REVIEW_REQUIRED:
            return operation
        return store.transition_operation(
            operation.purchase_id,
            expected_revision=operation.revision,
            to_state=PurchaseOperationState.REVIEW_REQUIRED,
            actor="stripe-webhook",
            reason="Stripe reports a partial refund",
            evidence={"stripe": dict(stripe)},
            changes={"last_error": "partial Stripe refund requires review"},
        )
    refund_id = stripe.get("refundId")
    if not isinstance(refund_id, str) or not refund_id:
        raise PaymentPurchaseConflict(
            "full Stripe refund is waiting for its refund event ID"
        )
    if operation.state == PurchaseOperationState.REFUNDED:
        if operation.refund_id != refund_id:
            raise PaymentPurchaseConflict(
                "Stripe refund differs from the recorded refund"
            )
        return operation
    if operation.state in {
        PurchaseOperationState.MEMPOOL_OBSERVED,
        PurchaseOperationState.CHAIN_CONFIRMED,
        PurchaseOperationState.FINALIZED,
        PurchaseOperationState.DISPUTED,
    }:
        raise PaymentPurchaseConflict(
            "post-delivery Stripe refund requires an administrator incident"
        )
    if (
        operation.inventory_release_bundle_id is None
        or operation.inventory_release_output_coin_id is None
        or operation.inventory_release_confirmation_height is None
    ):
        raise PaymentPurchaseConflict(
            "full Stripe refund is blocked until inventory release confirms"
        )
    if operation.state != PurchaseOperationState.REFUND_PENDING:
        operation = store.transition_operation(
            operation.purchase_id,
            expected_revision=operation.revision,
            to_state=PurchaseOperationState.REFUND_PENDING,
            actor="stripe-webhook",
            reason="Stripe reports a full refund",
            evidence={"stripe": dict(stripe)},
            changes={"refund_id": refund_id},
        )
    return store.transition_operation(
        operation.purchase_id,
        expected_revision=operation.revision,
        to_state=PurchaseOperationState.REFUNDED,
        actor="stripe-webhook",
        reason="Stripe full refund completed",
        evidence={"stripe": dict(stripe)},
        changes={
            "refund_id": refund_id,
            "refunded_minor": refunded_minor,
        },
    )


def _apply_dispute(
    store: PaymentPurchaseStore,
    operation: StoredPurchaseOperation,
    stripe: Mapping[str, Any],
) -> StoredPurchaseOperation:
    dispute_id = stripe.get("disputeId")
    if not isinstance(dispute_id, str) or not dispute_id:
        raise PaymentPurchaseConflict("Stripe dispute ID is missing")
    dispute_status = str(stripe.get("disputeStatus") or "").lower()
    dispute_event_id = str(stripe.get("eventId") or "")
    event_type = str(stripe.get("eventType") or "")
    if operation.dispute_id is not None:
        if operation.dispute_id != dispute_id:
            if operation.dispute_resolved_at is not None:
                return store.reopen_for_new_stripe_dispute(
                    operation.purchase_id,
                    expected_revision=operation.revision,
                    dispute_id=dispute_id,
                    dispute_status=dispute_status,
                    dispute_event_id=dispute_event_id,
                    event_type=event_type,
                    evidence={"stripe": dict(stripe)},
                )
            raise PaymentPurchaseConflict(
                "Stripe dispute differs from the recorded incident"
            )
        if (
            operation.dispute_status == dispute_status
            and operation.dispute_event_id == dispute_event_id
        ):
            return operation
        return store.record_stripe_dispute_update(
            operation.purchase_id,
            expected_revision=operation.revision,
            dispute_id=dispute_id,
            dispute_status=dispute_status,
            dispute_event_id=dispute_event_id,
            event_type=event_type,
            evidence={"stripe": dict(stripe)},
        )
    return store.transition_operation(
        operation.purchase_id,
        expected_revision=operation.revision,
        to_state=PurchaseOperationState.DISPUTED,
        actor="stripe-webhook",
        reason="Stripe opened or updated a payment dispute",
        evidence={"stripe": dict(stripe)},
        changes={
            "dispute_id": dispute_id,
            "dispute_status": dispute_status,
            "dispute_event_id": dispute_event_id,
            "last_error": "Stripe dispute requires owner-plus-one review",
        },
    )


def _require_payment_binding(
    operation: StoredPurchaseOperation,
    stripe: Mapping[str, Any],
) -> None:
    payment_intent_id = str(stripe.get("paymentIntentId") or "")
    if (
        operation.payment_intent_id is not None
        and operation.payment_intent_id != payment_intent_id
    ):
        raise PaymentPurchaseConflict(
            "Stripe PaymentIntent does not match the purchase operation"
        )
    processing_charge = int(stripe.get("processingChargeMinor") or "0")
    if processing_charge != operation.processing_charge_minor:
        raise PaymentPurchaseConflict(
            "Stripe surcharge does not match the server quote"
        )
    amount_minor = int(stripe.get("amountMinor") or "0")
    if amount_minor != operation.total_amount_minor:
        raise PaymentPurchaseConflict(
            "Stripe amount does not match the purchase operation"
        )
    family = str(stripe.get("paymentMethodFamily") or "")
    funding = str(stripe.get("fundingType") or "")
    require_stripe_method_for_purchase_kind(
        purchase_kind=operation.purchase_kind,
        payment_method_family=family,
    )
    if operation.payment_method_family not in {None, family}:
        raise PaymentPurchaseConflict(
            "Stripe payment method family changed"
        )
    if operation.funding_type not in {None, funding}:
        raise PaymentPurchaseConflict("Stripe funding type changed")
    if family == "us_bank_account" and processing_charge:
        raise PaymentPurchaseConflict("ACH cannot carry a surcharge")
    if funding in {"debit", "prepaid", "unknown"} and processing_charge:
        raise PaymentPurchaseConflict(
            "non-credit cards cannot carry a surcharge"
        )


def _payment_changes(stripe: Mapping[str, Any]) -> dict[str, Any]:
    processing_charge = int(stripe.get("processingChargeMinor") or "0")
    amount = int(stripe.get("amountMinor") or "0")
    return {
        "payment_intent_id": str(stripe["paymentIntentId"]),
        "payment_method_family": str(stripe["paymentMethodFamily"]),
        "funding_type": str(stripe["fundingType"]),
        "processing_charge_minor": processing_charge,
        "total_amount_minor": amount,
    }


def _validate_stripe_release_identity(
    snapshot: StripeEventSnapshotV1,
    settings: Settings,
) -> None:
    if (
        not settings.payment_stripe_account_id
        or len(settings.payment_stripe_account_id) < 6
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe account evidence is not configured",
        )
    if (
        snapshot.account_id != settings.payment_stripe_account_id
        or snapshot.api_version != settings.payment_stripe_api_version
        or snapshot.livemode != settings.payment_stripe_livemode
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stripe event does not match the reviewed release identity",
        )
    now = int(time.time())
    if snapshot.received_at < snapshot.event_created_at:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stripe event timestamps are inconsistent",
        )
    if snapshot.received_at > now + 300:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stripe event receipt time is in the future",
        )


def stripe_processing_charge_minor(
    *,
    subtotal_minor: int,
    payment_method_family: str,
    funding_type: str,
    settings: Settings,
) -> int:
    if subtotal_minor < 1:
        raise PaymentPurchaseConflict("Stripe subtotal must be positive")
    if payment_method_family == "us_bank_account":
        if funding_type != "bank_account":
            raise PaymentPurchaseConflict(
                "ACH requires bank_account funding"
            )
        return 0
    if payment_method_family != "card":
        raise PaymentPurchaseConflict(
            "Stripe payment method is not enabled"
        )
    if funding_type not in {"credit", "debit", "prepaid", "unknown"}:
        raise PaymentPurchaseConflict("Stripe card funding type is invalid")
    if (
        funding_type != "credit"
        or not settings.payment_stripe_credit_surcharge_enabled
    ):
        return 0
    variable = (
        subtotal_minor * settings.payment_stripe_credit_surcharge_bps
        + 9_999
    ) // 10_000
    configured = (
        variable + settings.payment_stripe_credit_surcharge_fixed_minor
    )
    cap = (
        subtotal_minor * settings.payment_stripe_credit_surcharge_cap_bps
        + 9_999
    ) // 10_000
    return min(configured, cap)


def require_stripe_method_for_purchase_kind(
    *,
    purchase_kind: str,
    payment_method_family: str,
) -> None:
    if purchase_kind not in {"DIRECT", "PRESALE"}:
        raise PaymentPurchaseConflict("Stripe purchase kind is unsupported")
    if (
        payment_method_family == "us_bank_account"
        and purchase_kind != "PRESALE"
    ):
        raise PaymentPurchaseConflict(
            "ACH is available only for refundable presales"
        )


def _require_configured_server_token(
    settings: Settings,
    authorization: str | None,
) -> None:
    if (
        not settings.protocol_artifact_api_token
        or len(settings.protocol_artifact_api_token) < 32
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe event ingestion token is not configured",
        )
    _require_server_to_server_token(settings, authorization)


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    result = value.get(key)
    if not isinstance(result, Mapping):
        raise PaymentPurchaseConflict(f"{key} must be an object")
    return result


def _operation_json(operation: StoredPurchaseOperation) -> dict[str, Any]:
    return {
        "purchaseId": operation.purchase_id,
        "revision": operation.revision,
        "state": operation.state.value,
        "purchaseKind": operation.purchase_kind,
        "presaleTermsHash": operation.presale_terms_hash,
        "rail": operation.rail,
        "deedLauncherId": operation.deed_launcher_id,
        "approvedVaultLauncherId": operation.approved_vault_launcher_id,
        "baseAmountMinor": str(operation.base_amount_minor),
        "technologyFeeMinor": str(operation.technology_fee_minor),
        "processingChargeMinor": str(operation.processing_charge_minor),
        "totalAmountMinor": str(operation.total_amount_minor),
        "softHoldExpiresAt": operation.soft_hold_expires_at,
        "reservationCoinId": operation.reservation_coin_id,
        "reservationBundleId": operation.reservation_bundle_id,
        "reservationExpiresAt": operation.reservation_expires_at,
        "reservationParentExpiresAt": (
            operation.reservation_parent_expires_at
        ),
        "reservationConfirmationHeight": (
            operation.reservation_confirmation_height
        ),
        "paymentIntentId": operation.payment_intent_id,
        "paymentMethodFamily": operation.payment_method_family,
        "fundingType": operation.funding_type,
        "paymentMethodReadyAt": operation.payment_method_ready_at,
        "stripeEventId": operation.stripe_event_id,
        "receiptHash": operation.receipt_hash,
        "receiptCoinId": operation.receipt_coin_id,
        "receiptBundleId": operation.receipt_bundle_id,
        "receiptConfirmationHeight": operation.receipt_confirmation_height,
        "deliveryBundleId": operation.delivery_bundle_id,
        "expectedOutputCoinId": operation.expected_output_coin_id,
        "mempoolObservedAt": operation.mempool_observed_at,
        "confirmationHeight": operation.confirmation_height,
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
        "refundId": operation.refund_id,
        "refundedMinor": str(operation.refunded_minor),
        "disputeId": operation.dispute_id,
        "disputeStatus": operation.dispute_status,
        "disputeEventId": operation.dispute_event_id,
        "disputeResolution": operation.dispute_resolution,
        "disputeResolvedAt": operation.dispute_resolved_at,
        "disputeResolutionOperationId": (
            operation.dispute_resolution_operation_id
        ),
        "lastError": operation.last_error,
        "updatedAt": operation.updated_at,
    }


_PAYMENT_PROCESSING_OR_LATER = frozenset(
    {
        PurchaseOperationState.PAYMENT_PROCESSING,
        PurchaseOperationState.PAYMENT_SUCCEEDED,
        PurchaseOperationState.RECEIPT_MEMPOOL,
        PurchaseOperationState.RECEIPT_READY,
        PurchaseOperationState.DELIVERY_SUBMITTED,
        PurchaseOperationState.MEMPOOL_OBSERVED,
        PurchaseOperationState.CHAIN_CONFIRMED,
        PurchaseOperationState.FINALIZED,
        PurchaseOperationState.REFUND_PENDING,
        PurchaseOperationState.REFUNDED,
        PurchaseOperationState.REVIEW_REQUIRED,
        PurchaseOperationState.DISPUTED,
    }
)

_PAYMENT_SUCCEEDED_OR_LATER = _PAYMENT_PROCESSING_OR_LATER - {
    PurchaseOperationState.PAYMENT_PROCESSING,
}
