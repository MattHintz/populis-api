from __future__ import annotations

import pytest

from solslot_api.payment_purchase_store import (
    PaymentPurchaseConflict,
    PaymentPurchaseStore,
    PurchaseOperationState,
    StoredPurchaseOperation,
)


def _purchase(value: str) -> dict[str, object]:
    return {
        "purchaseId": "0x" + value * 32,
        "artifactHash": "0x" + chr(ord(value) + 1) * 64,
        "quoteExpiresAt": 2_000_000_000,
    }


def _message(purchase_id: str, payment: str, transaction: str) -> dict[str, object]:
    return {
        "globalPaymentId": "0x" + payment * 32,
        "source": {"transactionHash": "0x" + transaction * 32},
        "purchaseId": purchase_id,
    }


def _purchase_v3(value: str, *, deed: str = "a") -> dict[str, object]:
    return {
        "schema": "solslot.purchase-artifact.v3",
        "purchaseKind": 1,
        "presaleTermsHash": "0x" + "00" * 32,
        "purchaseId": "0x" + value * 64,
        "artifactHash": "0x" + chr(ord(value) + 1) * 64,
        "quoteExpiresAt": "2000000000",
        "deedLauncherId": "0x" + deed * 64,
        "vaultLauncherId": "0x" + "b" * 64,
        "vaultP2PuzzleHash": "0x" + "c" * 64,
        "zkPassportRoot": "0x" + "d" * 64,
        "baseAmountMinor": "10000",
        "technologyFeeMinor": "100",
        "subtotalMinor": "10100",
    }


def _save_v3(
    store: PaymentPurchaseStore,
    value: str,
    *,
    deed: str = "a",
) -> str:
    purchase = _purchase_v3(value, deed=deed)
    purchase_id = str(purchase["purchaseId"])
    store.save(
        purchase_intent_id=f"intent-{value}",
        rail="stripe",
        offer_artifact_hash="0x" + value * 64,
        offer_artifact={
            "protocol": {
                "instanceId": f"customer-{value}",
                "purchaseKind": "direct",
                "presaleTermsHash": "0x" + "00" * 32,
            }
        },
        purchase_artifact=purchase,
        created_at=1_000,
    )
    return purchase_id


def test_operation_kind_comes_from_canonical_artifact_not_outer_label(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "kind-binding.db"))
    purchase = _purchase_v3("1")
    with pytest.raises(PaymentPurchaseConflict, match="purchase kind"):
        store.save(
            purchase_intent_id="intent-kind-mismatch",
            rail="stripe",
            offer_artifact_hash="0x" + "9" * 64,
            offer_artifact={
                "protocol": {
                    "purchaseKind": "PRESALE",
                    "presaleTermsHash": "0x" + "00" * 32,
                }
            },
            purchase_artifact=purchase,
            created_at=1_000,
        )


def _reserve(
    store: PaymentPurchaseStore,
    purchase_id: str,
) -> StoredPurchaseOperation:
    held = store.begin_soft_hold(
        purchase_id,
        expected_revision=1,
        expires_at=1_800,
        actor="customer",
        now=1_000,
    )
    reserving = store.transition_operation(
        purchase_id,
        expected_revision=held.revision,
        to_state=PurchaseOperationState.RESERVING,
        actor="coordinator",
        reason="reservation requested",
        now=1_010,
    )
    submitted = store.transition_operation(
        purchase_id,
        expected_revision=reserving.revision,
        to_state=PurchaseOperationState.RESERVATION_MEMPOOL,
        actor="coordinator",
        reason="reservation observed in mempool",
        changes={
            "reservation_coin_id": "0x" + "4" * 64,
            "reservation_bundle_id": "0x" + "5" * 64,
            "reservation_expires_at": 2_000,
        },
        now=1_020,
    )
    return store.transition_operation(
        purchase_id,
        expected_revision=submitted.revision,
        to_state=PurchaseOperationState.RESERVED,
        actor="coordinator",
        reason="reservation confirmed",
        changes={"reservation_confirmation_height": 123},
        now=1_021,
    )


def _record_release(
    store: PaymentPurchaseStore,
    purchase_id: str,
    operation: StoredPurchaseOperation,
) -> StoredPurchaseOperation:
    bundle_id = "0x" + "a" * 64
    output_coin_id = "0x" + "6" * 64
    store.save_chain_execution(
        purchase_id,
        action="RELEASE",
        claim_hash="0x" + "f" * 64,
        spend_bundle_id=bundle_id,
        required_input_coin_ids=[operation.reservation_coin_id or ""],
        expected_output_coin_id=output_coin_id,
        expected_output_puzzle_hash="0x" + "7" * 64,
        fee_mojos=0,
        spend_bundle={"coin_spends": [], "aggregated_signature": "00"},
        created_at=1_061,
    )
    return store.record_inventory_release(
        purchase_id,
        expected_revision=operation.revision,
        release_bundle_id=bundle_id,
        release_output_coin_id=output_coin_id,
        confirmation_height=124,
        actor="coordinator",
        evidence={"reason": "test release"},
        now=1_062,
    )


def test_external_transaction_can_bind_only_one_purchase(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "purchases.db"))
    first = _purchase("1")
    second = _purchase("3")
    for index, purchase in enumerate((first, second), start=1):
        store.save(
            purchase_intent_id=f"intent-{index}",
            rail="base_usdc",
            offer_artifact_hash="0x" + str(index + 4) * 64,
            offer_artifact={},
            purchase_artifact=purchase,
            created_at=1,
        )

    transaction = "7"
    store.bind_external_message(
        str(first["purchaseId"]),
        _message(str(first["purchaseId"]), "8", transaction),
    )
    with pytest.raises(PaymentPurchaseConflict, match="another purchase"):
        store.bind_external_message(
            str(second["purchaseId"]),
            _message(str(second["purchaseId"]), "9", transaction),
        )


def test_only_one_purchase_can_hold_and_reserve_a_deed(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "operations.db"))
    first = _save_v3(store, "1")
    second = _save_v3(store, "3")

    held = store.begin_soft_hold(
        first,
        expected_revision=1,
        expires_at=1_800,
        actor="customer-1",
        now=1_000,
    )
    assert held.state == PurchaseOperationState.SOFT_HELD
    assert held.revision == 2
    with pytest.raises(
        PaymentPurchaseConflict,
        match="reserved by another purchase",
    ):
        store.begin_soft_hold(
            second,
            expected_revision=1,
            expires_at=1_800,
            actor="customer-3",
            now=1_000,
        )

    reserving = store.transition_operation(
        first,
        expected_revision=2,
        to_state=PurchaseOperationState.RESERVING,
        actor="coordinator",
        reason="reservation quorum prepared",
        now=1_010,
    )
    submitted = store.transition_operation(
        first,
        expected_revision=reserving.revision,
        to_state=PurchaseOperationState.RESERVATION_MEMPOOL,
        actor="coordinator",
        reason="reservation observed in mempool",
        changes={
            "reservation_coin_id": "0x" + "4" * 64,
            "reservation_bundle_id": "0x" + "5" * 64,
            "reservation_expires_at": 2_000,
        },
        now=1_020,
    )
    reserved = store.transition_operation(
        first,
        expected_revision=submitted.revision,
        to_state=PurchaseOperationState.RESERVED,
        actor="coordinator",
        reason="reservation confirmed",
        changes={"reservation_confirmation_height": 123},
        now=1_021,
    )
    assert reserved.state == PurchaseOperationState.RESERVED
    assert reserved.reservation_coin_id == "0x" + "4" * 64


def test_reserved_state_requires_chain_evidence(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "required.db"))
    purchase_id = _save_v3(store, "1", deed="e")
    held = store.begin_soft_hold(
        purchase_id,
        expected_revision=1,
        expires_at=1_800,
        actor="customer",
        now=1_000,
    )
    reserving = store.transition_operation(
        purchase_id,
        expected_revision=held.revision,
        to_state=PurchaseOperationState.RESERVING,
        actor="coordinator",
        reason="reservation requested",
        now=1_010,
    )
    with pytest.raises(PaymentPurchaseConflict, match="reservation_coin_id"):
        store.transition_operation(
            purchase_id,
            expected_revision=reserving.revision,
            to_state=PurchaseOperationState.RESERVATION_MEMPOOL,
            actor="coordinator",
            reason="missing chain evidence",
            now=1_020,
        )


def test_bound_evidence_cannot_be_replaced(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "binding.db"))
    purchase_id = _save_v3(store, "1", deed="e")
    reserved = _reserve(store, purchase_id)
    with pytest.raises(PaymentPurchaseConflict, match="already bound"):
        store.transition_operation(
            purchase_id,
            expected_revision=reserved.revision,
            to_state=PurchaseOperationState.PAYMENT_METHOD_READY,
            actor="coordinator",
            reason="attempted evidence replacement",
            changes={
                "reservation_coin_id": "0x" + "6" * 64,
                "payment_intent_id": "pi_test",
                "payment_method_family": "card",
                "funding_type": "credit",
            },
            now=1_030,
        )


def test_full_refund_requires_exact_total_and_refund_id(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "refund.db"))
    purchase_id = _save_v3(store, "1", deed="e")
    reserved = _reserve(store, purchase_id)
    quoted = store.transition_operation(
        purchase_id,
        expected_revision=reserved.revision,
        to_state=PurchaseOperationState.PAYMENT_METHOD_READY,
        actor="coordinator",
        reason="credit card quote accepted",
        changes={
            "payment_intent_id": "pi_test",
            "payment_method_family": "card",
            "funding_type": "credit",
            "processing_charge_minor": 300,
            "total_amount_minor": 10_400,
        },
        now=1_030,
    )
    processing = store.transition_operation(
        purchase_id,
        expected_revision=quoted.revision,
        to_state=PurchaseOperationState.PAYMENT_PROCESSING,
        actor="coordinator",
        reason="Stripe confirmation submitted",
        now=1_040,
    )
    paid = store.transition_operation(
        purchase_id,
        expected_revision=processing.revision,
        to_state=PurchaseOperationState.PAYMENT_SUCCEEDED,
        actor="telonium",
        reason="Stripe payment succeeded",
        changes={"stripe_event_id": "evt_succeeded"},
        now=1_050,
    )
    pending = store.transition_operation(
        purchase_id,
        expected_revision=paid.revision,
        to_state=PurchaseOperationState.REFUND_PENDING,
        actor="coordinator",
        reason="delivery failed before submission",
        now=1_060,
    )
    with pytest.raises(
        PaymentPurchaseConflict,
        match="inventory_release_bundle_id",
    ):
        store.transition_operation(
            purchase_id,
            expected_revision=pending.revision,
            to_state=PurchaseOperationState.REFUNDED,
            actor="coordinator",
            reason="refund before inventory release",
            changes={
                "refund_id": "re_test",
                "refunded_minor": 10_400,
            },
            now=1_061,
        )
    released = _record_release(store, purchase_id, pending)
    with pytest.raises(PaymentPurchaseConflict, match="full collected"):
        store.transition_operation(
            purchase_id,
            expected_revision=released.revision,
            to_state=PurchaseOperationState.REFUNDED,
            actor="coordinator",
            reason="partial refund",
            changes={
                "refund_id": "re_test",
                "refunded_minor": 10_100,
            },
            now=1_070,
        )
    refunded = store.transition_operation(
        purchase_id,
        expected_revision=released.revision,
        to_state=PurchaseOperationState.REFUNDED,
        actor="coordinator",
        reason="full refund",
        changes={
            "refund_id": "re_test",
            "refunded_minor": 10_400,
        },
        now=1_071,
    )
    assert refunded.refunded_minor == 10_400


def test_operation_rejects_stale_revision_and_invalid_transition(
    tmp_path,
) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "revisions.db"))
    purchase_id = _save_v3(store, "1", deed="e")
    held = store.begin_soft_hold(
        purchase_id,
        expected_revision=1,
        expires_at=1_800,
        actor="customer",
        now=1_000,
    )
    with pytest.raises(PaymentPurchaseConflict, match="revision changed"):
        store.transition_operation(
            purchase_id,
            expected_revision=1,
            to_state=PurchaseOperationState.RESERVING,
            actor="coordinator",
            reason="stale",
            now=1_001,
        )
    with pytest.raises(PaymentPurchaseConflict, match="invalid purchase"):
        store.transition_operation(
            purchase_id,
            expected_revision=held.revision,
            to_state=PurchaseOperationState.FINALIZED,
            actor="coordinator",
            reason="skip delivery",
            now=1_001,
        )


def test_stripe_events_are_idempotent_and_cannot_be_rebound(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "events.db"))
    first = _save_v3(store, "1", deed="e")
    second = _save_v3(store, "3", deed="f")
    event = dict(
        event_id="evt_123",
        event_type="payment_intent.succeeded",
        payment_intent_id="pi_123",
        payload_sha256="a" * 64,
        event_created_at=1_100,
        received_at=1_101,
    )
    assert store.append_stripe_event(first, **event) is True
    assert store.append_stripe_event(first, **event) is False
    with pytest.raises(PaymentPurchaseConflict, match="different evidence"):
        store.append_stripe_event(second, **event)


def test_stripe_dispute_remains_bound_to_deed_during_review(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "deed-dispute.db"))
    purchase_id = _save_v3(store, "1", deed="e")
    deed_launcher_id = "0x" + "e" * 64
    assert store.get_stripe_dispute_for_deed(deed_launcher_id) is None

    reserved = _reserve(store, purchase_id)
    ready = store.transition_operation(
        purchase_id,
        expected_revision=reserved.revision,
        to_state=PurchaseOperationState.PAYMENT_METHOD_READY,
        actor="coordinator",
        reason="card ready",
        changes={
            "payment_intent_id": "pi_disputed",
            "payment_method_family": "card",
            "funding_type": "credit",
        },
        now=1_030,
    )
    paid = store.transition_operation(
        purchase_id,
        expected_revision=ready.revision,
        to_state=PurchaseOperationState.PAYMENT_SUCCEEDED,
        actor="telonium",
        reason="payment succeeded",
        changes={"stripe_event_id": "evt_succeeded"},
        now=1_040,
    )
    disputed = store.transition_operation(
        purchase_id,
        expected_revision=paid.revision,
        to_state=PurchaseOperationState.DISPUTED,
        actor="telonium",
        reason="charge disputed",
        changes={
            "dispute_id": "dp_test",
            "dispute_status": "needs_response",
            "dispute_event_id": "evt_dispute_opened",
        },
        now=1_050,
    )
    assert (
        store.get_stripe_dispute_for_deed(deed_launcher_id).purchase_id
        == purchase_id
    )

    store.transition_operation(
        purchase_id,
        expected_revision=disputed.revision,
        to_state=PurchaseOperationState.REVIEW_REQUIRED,
        actor="coordinator",
        reason="owner-plus-one review required",
        now=1_060,
    )
    assert (
        store.get_stripe_dispute_for_deed(deed_launcher_id).dispute_id
        == "dp_test"
    )


def test_worker_lease_blocks_concurrent_fulfillment(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "leases.db"))
    purchase_id = _save_v3(store, "1", deed="e")
    leased = store.claim_lease(
        purchase_id,
        worker_id="kos-a",
        ttl_seconds=30,
        now=1_000,
    )
    assert leased.lease_owner == "kos-a"
    with pytest.raises(PaymentPurchaseConflict, match="another worker"):
        store.claim_lease(
            purchase_id,
            worker_id="kos-b",
            ttl_seconds=30,
            now=1_001,
        )
    reclaimed = store.claim_lease(
        purchase_id,
        worker_id="kos-b",
        ttl_seconds=30,
        now=1_031,
    )
    assert reclaimed.lease_owner == "kos-b"


def test_chain_executions_are_exact_and_action_scoped(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "executions.db"))
    purchase_id = _save_v3(store, "1", deed="e")
    reserve = store.save_chain_execution(
        purchase_id,
        action="reserve",
        claim_hash="0x" + "1" * 64,
        spend_bundle_id="0x" + "2" * 64,
        required_input_coin_ids=[
            "0x" + "4" * 64,
            "0x" + "3" * 64,
        ],
        expected_output_coin_id="0x" + "5" * 64,
        expected_output_puzzle_hash="0x" + "6" * 64,
        fee_mojos=123,
        spend_bundle={"coin_spends": [], "aggregated_signature": "00"},
        created_at=1_000,
    )
    assert reserve.action == "RESERVE"
    assert reserve.required_input_coin_ids == (
        "0x" + "3" * 64,
        "0x" + "4" * 64,
    )
    assert (
        store.save_chain_execution(
            purchase_id,
            action="RESERVE",
            claim_hash="0x" + "1" * 64,
            spend_bundle_id="0x" + "2" * 64,
            required_input_coin_ids=[
                "0x" + "4" * 64,
                "0x" + "3" * 64,
            ],
            expected_output_coin_id="0x" + "5" * 64,
            expected_output_puzzle_hash="0x" + "6" * 64,
            fee_mojos=123,
            spend_bundle={
                "coin_spends": [],
                "aggregated_signature": "00",
            },
            created_at=1_001,
        )
        == reserve
    )
    delivered = store.save_chain_execution(
        purchase_id,
        action="DELIVER",
        claim_hash="0x" + "7" * 64,
        spend_bundle_id="0x" + "8" * 64,
        required_input_coin_ids=["0x" + "9" * 64],
        expected_output_coin_id="0x" + "a" * 64,
        expected_output_puzzle_hash="0x" + "b" * 64,
        fee_mojos=99,
        spend_bundle={"coin_spends": [], "aggregated_signature": "11"},
        created_at=1_002,
    )
    assert delivered.action == "DELIVER"
    with pytest.raises(
        PaymentPurchaseConflict,
        match="another chain execution",
    ):
        store.save_chain_execution(
            purchase_id,
            action="RESERVE",
            claim_hash="0x" + "c" * 64,
            spend_bundle_id="0x" + "d" * 64,
            required_input_coin_ids=["0x" + "e" * 64],
            expected_output_coin_id="0x" + "f" * 64,
            expected_output_puzzle_hash="0x" + "1" * 64,
            fee_mojos=123,
            spend_bundle={"coin_spends": [], "aggregated_signature": "22"},
            created_at=1_003,
        )


def test_admin_operation_views_are_rail_scoped_and_auditable(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "admin-view.db"))
    purchase_id = _save_v3(store, "1", deed="e")
    _reserve(store, purchase_id)

    listed = store.list_operations(rail="stripe", limit=10)
    assert [operation.purchase_id for operation in listed] == [purchase_id]
    history = store.operation_history(purchase_id)
    assert history[0]["toState"] == "RESERVED"
    assert history[0]["actor"] == "coordinator"
    assert history[-1]["toState"] == "ARTIFACT_READY"
    with pytest.raises(PaymentPurchaseConflict, match="rail"):
        store.list_operations(rail="browser-supplied", limit=10)
