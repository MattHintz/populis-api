from __future__ import annotations

import pytest

from solslot_api.payment_purchase_store import (
    PaymentPurchaseConflict,
    PaymentPurchaseStore,
)


def _hex32(byte: str) -> str:
    return "0x" + byte * 64


def _artifact(*, purchase: str, deed: str) -> dict[str, str]:
    return {
        "purchaseId": _hex32(purchase),
        "artifactHash": _hex32(chr(ord(purchase) + 1)),
        "deedLauncherId": _hex32(deed),
        "quoteExpiresAt": "2000000000",
    }


def _save(
    store: PaymentPurchaseStore,
    *,
    purchase: str,
    deed: str,
):
    artifact = _artifact(purchase=purchase, deed=deed)
    return store.save(
        purchase_intent_id=f"intent-{purchase}",
        rail="stripe",
        offer_artifact_hash=f"sha256:{purchase * 64}",
        offer_artifact={"purchase": purchase},
        purchase_artifact=artifact,
        created_at=1,
    )


def _message(
    purchase_id: str,
    payment: str,
    transaction: str,
) -> dict[str, object]:
    return {
        "globalPaymentId": _hex32(payment),
        "source": {"transactionHash": _hex32(transaction)},
        "purchaseId": purchase_id,
    }


def test_external_transaction_can_bind_only_one_purchase(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "purchases.db"))
    first = _save(store, purchase="1", deed="a")
    second = _save(store, purchase="3", deed="b")

    transaction = "7"
    store.bind_external_message(
        first.purchase_id,
        _message(first.purchase_id, "8", transaction),
    )
    with pytest.raises(PaymentPurchaseConflict, match="another purchase"):
        store.bind_external_message(
            second.purchase_id,
            _message(second.purchase_id, "9", transaction),
        )


def test_decimal_expiry_and_exact_reservation_transitions(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "purchases.db"))
    purchase = _save(store, purchase="1", deed="a")
    assert purchase.quote_expires_at == 2_000_000_000

    prepared = store.record_inventory_prepared(
        purchase.purchase_id,
        available_coin_id=_hex32("b"),
        reserved_coin_id=_hex32("c"),
        reserved_puzzle_hash=_hex32("d"),
        expires_at=1_999_999_000,
        bundle={"coinSpends": []},
        signer_indices=(0, 2),
        signature="0x" + "e" * 192,
    )
    assert prepared.inventory_state == "PREPARED"
    assert prepared.inventory_signer_indices == (0, 2)
    assert (
        store.record_inventory_prepared(
            purchase.purchase_id,
            available_coin_id=_hex32("b"),
            reserved_coin_id=_hex32("c"),
            reserved_puzzle_hash=_hex32("d"),
            expires_at=1_999_999_000,
            bundle={"coinSpends": []},
            signer_indices=(0, 2),
            signature="0x" + "e" * 192,
        ).inventory_state
        == "PREPARED"
    )

    submitted = store.record_inventory_submitted(
        purchase.purchase_id,
        bundle_id=_hex32("f"),
        mempool_observed_at="2026-08-02T12:00:00Z",
    )
    assert submitted.inventory_state == "SUBMITTED"
    confirmed = store.record_inventory_confirmed(
        purchase.purchase_id,
        confirmation_height=123,
    )
    assert confirmed.inventory_state == "CONFIRMED"
    assert confirmed.inventory_confirmation_height == 123


def test_one_active_reservation_per_smartdeed(tmp_path) -> None:
    store = PaymentPurchaseStore(str(tmp_path / "purchases.db"))
    first = _save(store, purchase="1", deed="a")
    second = _save(store, purchase="3", deed="a")
    store.record_inventory_prepared(
        first.purchase_id,
        available_coin_id=_hex32("b"),
        reserved_coin_id=_hex32("c"),
        reserved_puzzle_hash=_hex32("d"),
        expires_at=1_999_999_000,
        bundle={"coinSpends": []},
        signer_indices=(0, 1),
        signature="0x" + "e" * 192,
    )
    with pytest.raises(PaymentPurchaseConflict, match="already reserved"):
        store.record_inventory_prepared(
            second.purchase_id,
            available_coin_id=_hex32("4"),
            reserved_coin_id=_hex32("5"),
            reserved_puzzle_hash=_hex32("6"),
            expires_at=1_999_999_000,
            bundle={"coinSpends": []},
            signer_indices=(1, 2),
            signature="0x" + "7" * 192,
        )
