from __future__ import annotations

import pytest

from solslot_api.payment_purchase_store import (
    PaymentPurchaseConflict,
    PaymentPurchaseStore,
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
