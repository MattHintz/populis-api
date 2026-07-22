from __future__ import annotations

import time

import pytest

from solslot_api.presale_endpoints import (
    LaunchRequest,
    PresaleStore,
    PresaleTermsRequest,
    VoucherPurchaseRequest,
)


def b32(value: int) -> str:
    return "0x" + f"{value:02x}" * 32


def terms() -> PresaleTermsRequest:
    now = int(time.time())
    return PresaleTermsRequest(
        terms_hash=b32(1),
        series_id=b32(2),
        inventory_cap=2,
        xch_price_mojos=10,
        base_usdc_price_units=20,
        sale_open=now - 1,
        sale_close=now + 600,
        launch_deadline=now + 1200,
        identity_attest_root=b32(3),
        bridge_policy_hash=b32(4),
    )


def purchase() -> VoucherPurchaseRequest:
    return VoucherPurchaseRequest(
        serial=0,
        payment_rail="BASE_SEPOLIA_USDC",
        payment_principal=20,
        vault_launcher_id=b32(5),
        holder_member_hash=b32(6),
        base_depositor_commitment=b32(7),
        global_payment_id=b32(8),
    )


def test_purchase_remains_bound_to_purchasing_vault() -> None:
    store = PresaleStore(":memory:")
    series = store.create(terms())
    voucher = store.purchase(series["terms_hash"], purchase())
    assert voucher["vault_launcher_id"] == b32(5)
    assert voucher["holder_member_hash"] == b32(6)
    assert voucher["base_depositor_commitment"] == b32(7)
    assert voucher["global_payment_id"] == b32(8)


def test_purchase_rejects_wrong_principal_and_duplicate_serial() -> None:
    store = PresaleStore(":memory:")
    series = store.create(terms())
    wrong = purchase().model_copy(update={"payment_principal": 19})
    with pytest.raises(ValueError, match="terms"):
        store.purchase(series["terms_hash"], wrong)
    initial = store.purchase(series["terms_hash"], purchase(), "issuance-evidence-1")
    assert store.purchase(series["terms_hash"], purchase(), "issuance-evidence-1") == initial
    with pytest.raises(Exception):
        store.purchase(
            series["terms_hash"],
            purchase().model_copy(update={"global_payment_id": b32(9)}),
            "issuance-evidence-2",
        )


def test_launch_requires_quorum_request() -> None:
    store = PresaleStore(":memory:")
    series = store.create(terms())
    store.purchase(series["terms_hash"], purchase())
    live = store.launch(
        series["terms_hash"],
        LaunchRequest(admin_approval_hash=b32(11), governance_execution_id="chia-governance-exec-1", vote_tally=500_000),
    )
    assert live["phase"] == "LIVE"
