from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_api.payment_purchase_store import (
    PaymentPurchaseStore,
    PurchaseOperationState,
)
from solslot_api.stripe_payments import (
    _reconcile_stripe_events,
    require_stripe_method_for_purchase_kind,
    stripe_processing_charge_minor,
)
from solslot_api.stripe_fulfillment import (
    _requires_terminal_presale_voucher,
    advance_stripe_fulfillment,
    stripe_timeout_release_claim_hash,
)


def _save(
    store: PaymentPurchaseStore,
    *,
    purchase_kind: str = "DIRECT",
) -> tuple[str, int]:
    now = int(time.time())
    purchase_id = "0x" + "1" * 64
    vault_id = "0x" + "2" * 64
    presale_terms_hash = (
        "0x" + ("a" * 64 if purchase_kind == "PRESALE" else "00" * 32)
    )
    store.save(
        purchase_intent_id="pi_purchase_12345678",
        rail="stripe",
        offer_artifact_hash="sha256:" + "3" * 64,
        offer_artifact={
            "protocol": {
                "vaultLauncherId": vault_id,
                "purchaseKind": purchase_kind.lower(),
                "presaleTermsHash": presale_terms_hash,
            }
        },
        purchase_artifact={
            "schema": "solslot.purchase-artifact.v3",
            "purchaseKind": 1 if purchase_kind == "DIRECT" else 2,
            "presaleTermsHash": presale_terms_hash,
            "purchaseId": purchase_id,
            "artifactHash": "0x" + "4" * 64,
            "quoteExpiresAt": str(now + 3_600),
            "deedLauncherId": "0x" + "5" * 64,
            "vaultLauncherId": vault_id,
            "vaultP2PuzzleHash": "0x" + "6" * 64,
            "zkPassportRoot": "0x" + "7" * 64,
            "baseAmountMinor": "10000",
            "technologyFeeMinor": "100",
            "subtotalMinor": "10100",
        },
        created_at=now,
    )
    return purchase_id, now


def _reserve(
    store: PaymentPurchaseStore,
    purchase_id: str,
    now: int,
) -> None:
    held = store.begin_soft_hold(
        purchase_id,
        expected_revision=1,
        expires_at=now + 900,
        actor="customer",
        now=now,
    )
    reserving = store.transition_operation(
        purchase_id,
        expected_revision=held.revision,
        to_state=PurchaseOperationState.RESERVING,
        actor="coordinator",
        reason="reserve exact deed",
        now=now + 1,
    )
    submitted = store.transition_operation(
        purchase_id,
        expected_revision=reserving.revision,
        to_state=PurchaseOperationState.RESERVATION_MEMPOOL,
        actor="coordinator",
        reason="reservation observed in mempool",
        changes={
            "reservation_coin_id": "0x" + "8" * 64,
            "reservation_bundle_id": "0x" + "9" * 64,
            "reservation_expires_at": now + 172_800,
        },
        now=now + 2,
    )
    store.transition_operation(
        purchase_id,
        expected_revision=submitted.revision,
        to_state=PurchaseOperationState.RESERVED,
        actor="coordinator",
        reason="reservation confirmed",
        changes={"reservation_confirmation_height": 123},
        now=now + 3,
    )


def _record_release(
    store: PaymentPurchaseStore,
    purchase_id: str,
    now: int,
) -> None:
    operation = store.get_operation(purchase_id)
    pending = store.transition_operation(
        purchase_id,
        expected_revision=operation.revision,
        to_state=PurchaseOperationState.REFUND_PENDING,
        actor="coordinator",
        reason="buyer requested a presale refund",
        now=now + 20,
    )
    bundle_id = "0x" + "a" * 64
    output_coin_id = "0x" + "b" * 64
    store.save_chain_execution(
        purchase_id,
        action="RELEASE",
        claim_hash="0x" + "c" * 64,
        spend_bundle_id=bundle_id,
        required_input_coin_ids=[pending.reservation_coin_id or ""],
        expected_output_coin_id=output_coin_id,
        expected_output_puzzle_hash="0x" + "d" * 64,
        fee_mojos=0,
        spend_bundle={"coin_spends": [], "aggregated_signature": "00"},
        created_at=now + 21,
    )
    store.record_inventory_release(
        purchase_id,
        expected_revision=pending.revision,
        release_bundle_id=bundle_id,
        release_output_coin_id=output_coin_id,
        confirmation_height=124,
        actor="coordinator",
        evidence={"reason": "test release"},
        now=now + 22,
    )


def _event(
    purchase_id: str,
    now: int,
    *,
    event_id: str = "evt_succeeded",
    event_type: str = "payment_intent.succeeded",
    informational: bool = False,
    status: str = "succeeded",
    received: int = 10_100,
    refunded: int = 0,
    refund_id: str | None = None,
    dispute_id: str | None = None,
    dispute_status: str | None = None,
    disputed: bool = False,
) -> dict:
    return {
        "schema": "solslot.stripe-event.v1",
        "purchaseIntentId": "pi_purchase_12345678",
        "purchaseId": purchase_id,
        "artifactHash": "sha256:" + "3" * 64,
        "stripe": {
            "accountId": "acct_test",
            "apiVersion": "2026-02-25.clover",
            "livemode": False,
            "eventId": event_id,
            "eventType": event_type,
            "eventCreatedAt": now + 3,
            "receivedAt": now + 4,
            "payloadSha256": "a" * 64,
            "informational": informational,
            "paymentIntentId": "pi_stripe_123",
            "paymentStatus": status,
            "amountMinor": "10100",
            "amountReceivedMinor": str(received),
            "currency": "usd",
            "paymentMethodFamily": "card",
            "fundingType": "debit",
            "processingChargeMinor": "0",
            "chargeId": "ch_123",
            "refundedMinor": str(refunded),
            "refundId": refund_id,
            "disputeId": dispute_id,
            "disputeStatus": dispute_status,
            "disputed": disputed,
        },
    }


def _append(
    store: PaymentPurchaseStore,
    purchase_id: str,
    evidence: dict,
) -> None:
    stripe = evidence["stripe"]
    store.append_stripe_event(
        purchase_id,
        event_id=stripe["eventId"],
        event_type=stripe["eventType"],
        payment_intent_id=stripe["paymentIntentId"],
        payload_sha256=stripe["payloadSha256"],
        event_created_at=stripe["eventCreatedAt"],
        received_at=stripe["receivedAt"],
        evidence=evidence,
    )


def test_checkout_completion_is_persisted_but_never_marks_payment_paid(
    tmp_path,
) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "stripe.db"))
    purchase_id, now = _save(store)
    _reserve(store, purchase_id, now)
    evidence = _event(
        purchase_id,
        now,
        event_id="evt_checkout",
        event_type="checkout.session.completed",
        informational=True,
    )
    _append(store, purchase_id, evidence)

    operation, pending = _reconcile_stripe_events(store, purchase_id)

    assert operation.state == PurchaseOperationState.RESERVED
    assert pending == 0


def test_ach_is_presale_only_at_the_coordinator_boundary() -> None:
    with pytest.raises(ValueError, match="only for refundable presales"):
        require_stripe_method_for_purchase_kind(
            purchase_kind="DIRECT",
            payment_method_family="us_bank_account",
        )
    require_stripe_method_for_purchase_kind(
        purchase_kind="PRESALE",
        payment_method_family="us_bank_account",
    )
    require_stripe_method_for_purchase_kind(
        purchase_kind="DIRECT",
        payment_method_family="card",
    )


def test_only_exact_succeeded_payment_advances_to_payment_succeeded(
    tmp_path,
) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "stripe.db"))
    purchase_id, now = _save(store)
    _reserve(store, purchase_id, now)
    evidence = _event(purchase_id, now)
    _append(store, purchase_id, evidence)

    operation, pending = _reconcile_stripe_events(store, purchase_id)

    assert operation.state == PurchaseOperationState.PAYMENT_SUCCEEDED
    assert operation.payment_intent_id == "pi_stripe_123"
    assert operation.stripe_event_id == "evt_succeeded"
    assert pending == 0


def _finalize_direct_purchase(
    store: PaymentPurchaseStore,
    purchase_id: str,
    now: int,
):
    _append(store, purchase_id, _event(purchase_id, now))
    paid, _ = _reconcile_stripe_events(store, purchase_id)
    receipt = store.transition_operation(
        purchase_id,
        expected_revision=paid.revision,
        to_state=PurchaseOperationState.RECEIPT_MEMPOOL,
        actor="key-of-solomon",
        reason="receipt submitted",
        changes={
            "receipt_hash": "0x" + "a" * 64,
            "receipt_coin_id": "0x" + "b" * 64,
            "receipt_bundle_id": "0x" + "c" * 64,
        },
        now=now + 5,
    )
    ready = store.transition_operation(
        purchase_id,
        expected_revision=receipt.revision,
        to_state=PurchaseOperationState.RECEIPT_READY,
        actor="chain-reconciler",
        reason="receipt confirmed",
        changes={"receipt_confirmation_height": 124},
        now=now + 6,
    )
    submitted = store.transition_operation(
        purchase_id,
        expected_revision=ready.revision,
        to_state=PurchaseOperationState.DELIVERY_SUBMITTED,
        actor="key-of-solomon",
        reason="delivery submitted",
        changes={
            "delivery_bundle_id": "0x" + "d" * 64,
            "expected_output_coin_id": "0x" + "e" * 64,
            "fee_mojos": 420,
        },
        now=now + 7,
    )
    confirmed = store.transition_operation(
        purchase_id,
        expected_revision=submitted.revision,
        to_state=PurchaseOperationState.CHAIN_CONFIRMED,
        actor="chain-reconciler",
        reason="delivery confirmed",
        changes={"confirmation_height": 125},
        now=now + 8,
    )
    return store.transition_operation(
        purchase_id,
        expected_revision=confirmed.revision,
        to_state=PurchaseOperationState.FINALIZED,
        actor="coordinator",
        reason="delivery finalized",
        now=now + 9,
    )


def test_final_dispute_requires_owner_plus_one_resolution(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "stripe-dispute.db"))
    purchase_id, now = _save(store)
    _reserve(store, purchase_id, now)
    finalized = _finalize_direct_purchase(store, purchase_id, now)
    assert finalized.state == PurchaseOperationState.FINALIZED

    opened = _event(
        purchase_id,
        now + 20,
        event_id="evt_dispute_opened",
        event_type="charge.dispute.created",
        dispute_id="dp_test",
        dispute_status="needs_response",
        disputed=True,
    )
    opened["stripe"]["payloadSha256"] = "b" * 64
    _append(store, purchase_id, opened)
    disputed_operation, pending = _reconcile_stripe_events(
        store,
        purchase_id,
    )
    assert disputed_operation.state == PurchaseOperationState.DISPUTED
    assert disputed_operation.dispute_status == "needs_response"
    assert pending == 0

    closed = _event(
        purchase_id,
        now + 30,
        event_id="evt_dispute_closed",
        event_type="charge.dispute.closed",
        dispute_id="dp_test",
        dispute_status="won",
    )
    closed["stripe"]["payloadSha256"] = "c" * 64
    _append(store, purchase_id, closed)
    won, pending = _reconcile_stripe_events(store, purchase_id)
    assert won.state == PurchaseOperationState.DISPUTED
    assert won.dispute_status == "won"
    assert won.dispute_event_id == "evt_dispute_closed"
    assert pending == 0

    with pytest.raises(ValueError, match="status lost"):
        store.resolve_post_delivery_stripe_dispute(
            purchase_id,
            expected_revision=won.revision,
            resolution="ACCEPT_LOSS_AND_RESTORE",
            admin_operation_id="0x" + "f" * 64,
            actor="0x" + "1" * 40,
            now=now + 40,
        )
    resolved = store.resolve_post_delivery_stripe_dispute(
        purchase_id,
        expected_revision=won.revision,
        resolution="RESTORE_AFTER_WIN",
        admin_operation_id="0x" + "f" * 64,
        actor="0x" + "1" * 40,
        now=now + 40,
    )
    assert resolved.state == PurchaseOperationState.FINALIZED
    assert resolved.dispute_resolution == "RESTORE_AFTER_WIN"
    assert resolved.dispute_resolved_at == now + 40
    assert (
        store.get_stripe_dispute_for_deed(resolved.deed_launcher_id)
        is None
    )


def test_distinct_dispute_reopens_pause_after_prior_resolution(
    tmp_path,
) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "stripe-disputes.db"))
    purchase_id, now = _save(store)
    _reserve(store, purchase_id, now)
    _finalize_direct_purchase(store, purchase_id, now)

    opened = _event(
        purchase_id,
        now + 20,
        event_id="evt_dispute_one_opened",
        event_type="charge.dispute.created",
        dispute_id="dp_one",
        dispute_status="needs_response",
        disputed=True,
    )
    opened["stripe"]["payloadSha256"] = "b" * 64
    _append(store, purchase_id, opened)
    first, pending = _reconcile_stripe_events(store, purchase_id)
    assert first.state == PurchaseOperationState.DISPUTED
    assert pending == 0

    closed = _event(
        purchase_id,
        now + 30,
        event_id="evt_dispute_one_closed",
        event_type="charge.dispute.closed",
        dispute_id="dp_one",
        dispute_status="won",
    )
    closed["stripe"]["payloadSha256"] = "c" * 64
    _append(store, purchase_id, closed)
    won, pending = _reconcile_stripe_events(store, purchase_id)
    assert pending == 0
    resolved = store.resolve_post_delivery_stripe_dispute(
        purchase_id,
        expected_revision=won.revision,
        resolution="RESTORE_AFTER_WIN",
        admin_operation_id="0x" + "f" * 64,
        actor="0x" + "1" * 40,
        now=now + 40,
    )
    assert resolved.state == PurchaseOperationState.FINALIZED

    second_opened = _event(
        purchase_id,
        now + 50,
        event_id="evt_dispute_two_opened",
        event_type="charge.dispute.created",
        dispute_id="dp_two",
        dispute_status="needs_response",
        disputed=True,
    )
    second_opened["stripe"]["payloadSha256"] = "d" * 64
    _append(store, purchase_id, second_opened)
    reopened, pending = _reconcile_stripe_events(store, purchase_id)

    assert pending == 0
    assert reopened.state == PurchaseOperationState.DISPUTED
    assert reopened.dispute_id == "dp_two"
    assert reopened.dispute_status == "needs_response"
    assert reopened.dispute_resolution is None
    assert reopened.dispute_resolved_at is None
    assert reopened.dispute_resolution_operation_id is None
    assert (
        store.get_stripe_dispute_for_deed(reopened.deed_launcher_id)
        == reopened
    )


@pytest.mark.parametrize("stale_created_delta", [2, 4])
def test_stale_failure_cannot_block_authoritative_success(
    tmp_path,
    stale_created_delta: int,
) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "stripe.db"))
    purchase_id, now = _save(store)
    _reserve(store, purchase_id, now)
    stale = _event(
        purchase_id,
        now,
        event_id="evt_failed_stale",
        event_type="payment_intent.payment_failed",
        status="succeeded",
    )
    stale["stripe"]["eventCreatedAt"] = now + stale_created_delta
    stale["stripe"]["receivedAt"] = now + 5
    stale["stripe"]["payloadSha256"] = "b" * 64
    succeeded = _event(purchase_id, now)
    _append(store, purchase_id, stale)
    _append(store, purchase_id, succeeded)

    operation, pending = _reconcile_stripe_events(store, purchase_id)

    assert operation.state == PurchaseOperationState.PAYMENT_SUCCEEDED
    assert operation.stripe_event_id == "evt_succeeded"
    assert pending == 0


def test_success_before_chain_reservation_stays_in_durable_inbox(
    tmp_path,
) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "stripe.db"))
    purchase_id, now = _save(store)
    evidence = _event(purchase_id, now)
    _append(store, purchase_id, evidence)

    operation, pending = _reconcile_stripe_events(store, purchase_id)

    assert operation.state == PurchaseOperationState.ARTIFACT_READY
    assert pending == 1


def test_full_refund_moves_paid_purchase_to_refunded(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "stripe.db"))
    purchase_id, now = _save(store)
    _reserve(store, purchase_id, now)
    _append(store, purchase_id, _event(purchase_id, now))
    paid, _ = _reconcile_stripe_events(store, purchase_id)
    assert paid.state == PurchaseOperationState.PAYMENT_SUCCEEDED
    _record_release(store, purchase_id, now)
    refund = _event(
        purchase_id,
        now + 10,
        event_id="evt_refund",
        event_type="refund.updated",
        refunded=10_100,
        refund_id="re_123",
    )
    refund["stripe"]["payloadSha256"] = "b" * 64
    _append(store, purchase_id, refund)

    operation, pending = _reconcile_stripe_events(store, purchase_id)

    assert operation.state == PurchaseOperationState.REFUNDED
    assert operation.refund_id == "re_123"
    assert operation.refunded_minor == 10_100
    assert pending == 0


def test_unresolved_ach_moves_to_review_after_ten_days(
    tmp_path,
    monkeypatch,
) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "stripe.db"))
    purchase_id, now = _save(store, purchase_kind="PRESALE")
    _reserve(store, purchase_id, now)
    processing_event = _event(
        purchase_id,
        now,
        event_id="evt_processing",
        event_type="payment_intent.processing",
        status="processing",
        received=0,
    )
    processing_event["stripe"]["paymentMethodFamily"] = "us_bank_account"
    processing_event["stripe"]["fundingType"] = "bank_account"
    _append(store, purchase_id, processing_event)
    operation, _ = _reconcile_stripe_events(store, purchase_id)
    assert operation.state == PurchaseOperationState.PAYMENT_PROCESSING

    monkeypatch.setattr(
        "solslot_api.stripe_fulfillment.require_minting_writes",
        lambda settings: None,
    )
    monkeypatch.setattr(
        "solslot_api.stripe_fulfillment.require_operation_gate",
        lambda settings, operation: None,
    )
    monkeypatch.setattr(
        "solslot_api.stripe_fulfillment._require_stripe_fulfillment",
        lambda settings: None,
    )
    monkeypatch.setattr(
        "solslot_api.stripe_fulfillment.time.time",
        lambda: (operation.payment_method_ready_at or now) + 10 * 24 * 60 * 60,
    )

    reviewed = asyncio.run(
        advance_stripe_fulfillment(
            request=SimpleNamespace(),
            settings=SimpleNamespace(),
            store=store,
            operation=operation,
        )
    )

    assert reviewed.state == PurchaseOperationState.REVIEW_REQUIRED
    assert "inventory remains reserved" in str(reviewed.last_error)
    assert reviewed.reservation_coin_id == operation.reservation_coin_id


def test_coordinator_uses_the_same_bounded_credit_surcharge() -> None:
    settings = SimpleNamespace(
        payment_stripe_credit_surcharge_enabled=True,
        payment_stripe_credit_surcharge_bps=250,
        payment_stripe_credit_surcharge_fixed_minor=30,
        payment_stripe_credit_surcharge_cap_bps=300,
    )
    assert stripe_processing_charge_minor(
        subtotal_minor=10_100,
        payment_method_family="card",
        funding_type="credit",
        settings=settings,
    ) == 283
    assert stripe_processing_charge_minor(
        subtotal_minor=10_100,
        payment_method_family="card",
        funding_type="debit",
        settings=settings,
    ) == 0
    assert stripe_processing_charge_minor(
        subtotal_minor=10_100,
        payment_method_family="us_bank_account",
        funding_type="bank_account",
        settings=settings,
    ) == 0


def test_failed_presale_payment_releases_without_nonexistent_voucher() -> None:
    assert not _requires_terminal_presale_voucher(
        purchase_kind="PRESALE",
        reason="PAYMENT_FAILED",
    )
    assert _requires_terminal_presale_voucher(
        purchase_kind="PRESALE",
        reason="PRESALE_REFUND",
    )
    assert not _requires_terminal_presale_voucher(
        purchase_kind="DIRECT",
        reason="PAYMENT_FAILED",
    )


def test_timeout_release_claim_binds_every_exact_coordinate() -> None:
    values = {
        "purchase_id": bytes32(b"\x01" * 32),
        "artifact_hash": bytes32(b"\x02" * 32),
        "reservation_coin_id": bytes32(b"\x03" * 32),
        "reservation_expires_at": 123456,
        "output_coin_id": bytes32(b"\x04" * 32),
        "output_puzzle_hash": bytes32(b"\x05" * 32),
    }
    expected = stripe_timeout_release_claim_hash(**values)
    assert expected == stripe_timeout_release_claim_hash(**values)
    for field in (
        "purchase_id",
        "artifact_hash",
        "reservation_coin_id",
        "output_coin_id",
        "output_puzzle_hash",
    ):
        changed = dict(values)
        changed[field] = bytes32(b"\xff" * 32)
        assert stripe_timeout_release_claim_hash(**changed) != expected
    changed = dict(values)
    changed["reservation_expires_at"] += 1
    assert stripe_timeout_release_claim_hash(**changed) != expected


def test_confirmed_timeout_release_cancels_unpaid_reservation(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "stripe.db"))
    purchase_id, now = _save(store)
    _reserve(store, purchase_id, now)
    operation = store.get_operation(purchase_id)
    bundle_id = "0x" + "a" * 64
    output_coin_id = "0x" + "b" * 64
    store.save_chain_execution(
        purchase_id,
        action="RELEASE",
        claim_hash="0x" + "c" * 64,
        spend_bundle_id=bundle_id,
        required_input_coin_ids=[operation.reservation_coin_id or ""],
        expected_output_coin_id=output_coin_id,
        expected_output_puzzle_hash="0x" + "d" * 64,
        fee_mojos=0,
        spend_bundle={"coin_spends": [], "aggregated_signature": "00"},
        created_at=now + 172_801,
    )

    released = store.record_inventory_release(
        purchase_id,
        expected_revision=operation.revision,
        release_bundle_id=bundle_id,
        release_output_coin_id=output_coin_id,
        confirmation_height=125,
        actor="permissionless-timeout",
        evidence={"reservationExpiresAt": operation.reservation_expires_at},
        now=now + 172_802,
    )

    assert released.state == PurchaseOperationState.CANCELED
    assert released.inventory_release_confirmation_height == 125
