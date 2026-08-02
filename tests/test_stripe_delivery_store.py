from __future__ import annotations

import pytest

from solslot_api.stripe_deliveries import serialize_stripe_delivery

from solslot_api.stripe_delivery_store import (
    DELIVERY_PREPARED,
    DELIVERY_SUBMITTED,
    EXTERNAL_SETTLEMENT_PENDING,
    FINALIZED,
    PAYMENT_VERIFIED,
    PAYMENT_RAIL_BASE_USDC,
    RECEIPT_CONFIRMED,
    RECEIPT_FUNDING_PREPARED,
    RECEIPT_FUNDING_SUBMITTED,
    StripeDeliveryConflict,
    StripeDeliveryStore,
)


def _hex(seed: str) -> str:
    return "0x" + seed * 32


def test_delivery_state_is_idempotent_and_chain_bound(tmp_path) -> None:
    store = StripeDeliveryStore(str(tmp_path / "deliveries.db"))
    evidence = {"paymentIntentId": "pi_test", "evidenceHash": _hex("11")}
    queued = store.queue(
        purchase_id=_hex("01"),
        evidence=evidence,
        receipt_hash=_hex("02"),
        now=10,
    )
    assert queued.state == PAYMENT_VERIFIED
    assert store.queue(
        purchase_id=_hex("01"),
        evidence=evidence,
        receipt_hash=_hex("02"),
        now=11,
    ) == queued

    claimed = store.claim_next(owner="worker-a", lease_seconds=30, now=12)
    assert claimed is not None and claimed.attempt_count == 1
    prepared_receipt = store.record_receipt_prepared(
        _hex("01"),
        input_coin_id=_hex("09"),
        protocol_bundle={"coin_spends": [], "aggregated_signature": "c0"},
        receipt_coin_id=_hex("04"),
        receipt_puzzle_hash=_hex("05"),
    )
    assert prepared_receipt.state == RECEIPT_FUNDING_PREPARED
    assert prepared_receipt.receipt_funding_input_coin_id == _hex("09")
    assert prepared_receipt.receipt_funding_bundle == {
        "aggregated_signature": "c0",
        "coin_spends": [],
    }
    funded = store.record_receipt_funding(
        _hex("01"),
        bundle_id=_hex("03"),
        receipt_coin_id=_hex("04"),
        receipt_puzzle_hash=_hex("05"),
        fee_mojos=7,
        mempool_observed_at="2026-08-01T12:00:00Z",
    )
    assert funded.state == RECEIPT_FUNDING_SUBMITTED
    assert store.record_receipt_confirmed(_hex("01")).state == RECEIPT_CONFIRMED
    prepared_delivery = store.record_delivery_prepared(
        _hex("01"),
        protocol_bundle={"coin_spends": [{"coin": _hex("0a")}]},
        deed_output_coin_id=_hex("07"),
        treasury_output_coin_id=_hex("08"),
        signer_indices=(0, 2),
    )
    assert prepared_delivery.state == DELIVERY_PREPARED
    assert prepared_delivery.delivery_bundle == {
        "coin_spends": [{"coin": _hex("0a")}]
    }
    submitted = store.record_delivery_submission(
        _hex("01"),
        bundle_id=_hex("06"),
        deed_output_coin_id=_hex("07"),
        treasury_output_coin_id=_hex("08"),
        signer_indices=(0, 2),
        fee_mojos=9,
        mempool_observed_at="2026-08-01T12:01:00Z",
    )
    assert submitted.state == DELIVERY_SUBMITTED
    finalized = store.record_finalized(_hex("01"), confirmation_height=123)
    assert finalized.state == FINALIZED
    assert finalized.confirmation_height == 123
    assert finalized.signer_indices == (0, 2)


def test_delivery_rejects_rebinding_and_duplicate_receipt(tmp_path) -> None:
    store = StripeDeliveryStore(str(tmp_path / "deliveries.db"))
    store.queue(
        purchase_id=_hex("01"),
        evidence={"paymentIntentId": "pi_one"},
        receipt_hash=_hex("02"),
    )
    with pytest.raises(StripeDeliveryConflict, match="different settlement"):
        store.queue(
            purchase_id=_hex("01"),
            evidence={"paymentIntentId": "pi_changed"},
            receipt_hash=_hex("02"),
        )
    with pytest.raises(StripeDeliveryConflict, match="another purchase"):
        store.queue(
            purchase_id=_hex("03"),
            evidence={"paymentIntentId": "pi_two"},
            receipt_hash=_hex("02"),
        )


def test_exact_bundle_binding_is_immutable_and_keeps_worker_lease(tmp_path) -> None:
    store = StripeDeliveryStore(str(tmp_path / "exact-deliveries.db"))
    purchase_id = _hex("31")
    store.queue(
        purchase_id=purchase_id,
        evidence={"paymentIntentId": "pi_exact"},
        receipt_hash=_hex("32"),
        now=100,
    )
    store.record_receipt_prepared(
        purchase_id,
        input_coin_id=_hex("33"),
        protocol_bundle={"coin_spends": []},
        receipt_coin_id=_hex("34"),
        receipt_puzzle_hash=_hex("35"),
    )
    assert store.claim(
        purchase_id,
        owner="worker-a",
        lease_seconds=60,
        now=101,
    ) is not None
    exact = {
        "spendBundleId": _hex("36"),
        "feeMojos": "7",
        "feeCoinId": _hex("37"),
        "spendBundle": {"coin_spends": []},
    }
    bound = store.bind_receipt_exact_bundle(
        purchase_id,
        exact_bundle=exact,
    )
    assert bound.receipt_funding_exact_bundle == exact
    assert store.claim(
        purchase_id,
        owner="worker-b",
        lease_seconds=60,
        now=110,
    ) is None
    with pytest.raises(StripeDeliveryConflict, match="already bound"):
        store.bind_receipt_exact_bundle(
            purchase_id,
            exact_bundle={**exact, "feeMojos": "8"},
        )


def test_targeted_reconciliation_uses_the_same_cross_process_lease(tmp_path) -> None:
    store = StripeDeliveryStore(str(tmp_path / "deliveries.db"))
    queued = store.queue(
        purchase_id=_hex("01"),
        evidence={"paymentIntentId": "pi_test"},
        receipt_hash=_hex("02"),
        now=90,
    )

    first = store.claim(
        queued.purchase_id,
        owner="worker-a",
        lease_seconds=30,
        now=100,
    )
    assert first is not None
    assert first.attempt_count == 1
    assert (
        store.claim(
            queued.purchase_id,
            owner="worker-b",
            lease_seconds=30,
            now=110,
        )
        is None
    )

    recovered = store.claim(
        queued.purchase_id,
        owner="worker-b",
        lease_seconds=30,
        now=131,
    )
    assert recovered is not None
    assert recovered.attempt_count == 2


def test_base_delivery_requires_terminal_external_settlement(tmp_path) -> None:
    store = StripeDeliveryStore(str(tmp_path / "base-deliveries.db"))
    purchase_id = _hex("21")
    queued = store.queue(
        purchase_id=purchase_id,
        evidence={"globalPaymentId": _hex("22")},
        receipt_hash=_hex("23"),
        payment_rail=PAYMENT_RAIL_BASE_USDC,
    )
    assert queued.external_payment_id == _hex("22")
    store.record_receipt_prepared(
        purchase_id,
        input_coin_id=_hex("24"),
        protocol_bundle={"coin_spends": [], "aggregated_signature": "c0"},
        receipt_coin_id=_hex("25"),
        receipt_puzzle_hash=_hex("26"),
    )
    store.record_receipt_confirmed(purchase_id)
    store.record_delivery_prepared(
        purchase_id,
        protocol_bundle={"coin_spends": []},
        delivery_output_coin_id=_hex("27"),
        treasury_output_coin_id=_hex("28"),
        signer_indices=(0, 1),
    )
    pending = store.record_delivery_confirmed(
        purchase_id,
        confirmation_height=456,
    )
    assert pending.state == EXTERNAL_SETTLEMENT_PENDING
    serialized = serialize_stripe_delivery(pending)
    assert serialized["expectedTreasuryCoinId"] is None
    assert serialized["expectedResultAuthorizationCoinId"] == _hex("28")
    assert serialized["expectedCoordinationCoinId"] == _hex("28")
    with pytest.raises(
        StripeDeliveryConflict,
        match="requires confirmed external settlement",
    ):
        store.record_finalized(purchase_id, confirmation_height=456)
    authorized = store.record_external_settlement_authorization(
        purchase_id,
        authorization_id=_hex("29"),
        authorization={"schema": "solslot.base-direct-settlement-authorization.v1"},
    )
    assert authorized.state == EXTERNAL_SETTLEMENT_PENDING
    assert store.list_pending_external_settlements() == [authorized]
    finalized = store.record_external_settlement_finalized(
        purchase_id,
        evidence={"baseTransactionHash": _hex("2a")},
    )
    assert finalized.state == FINALIZED
    assert store.list_pending_external_settlements() == []
