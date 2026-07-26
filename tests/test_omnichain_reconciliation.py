"""Tests for the omnichain reconciliation and relayer checkpoint."""
from __future__ import annotations

from solslot_api.omnichain_reconciliation import (
    ReconciliationStatus,
    reconcile_payment,
    run_reconciliation,
)


class TestReconcilePayment:
    def test_consistent_terminal_success(self) -> None:
        r = reconcile_payment("0x01", api_status="REDEEMED", spoke_status="SettledSuccess")
        assert r.status == ReconciliationStatus.CONSISTENT

    def test_consistent_terminal_refund(self) -> None:
        r = reconcile_payment("0x02", api_status="REFUNDED", spoke_status="VoucherRefunded")
        assert r.status == ReconciliationStatus.CONSISTENT

    def test_mismatch_terminal_states(self) -> None:
        r = reconcile_payment("0x03", api_status="REDEEMED", spoke_status="VoucherRefunded")
        assert r.status == ReconciliationStatus.MISMATCH

    def test_missing_api(self) -> None:
        r = reconcile_payment("0x04", api_status=None, spoke_status="RequestSent")
        assert r.status == ReconciliationStatus.MISSING_API

    def test_missing_spoke(self) -> None:
        r = reconcile_payment("0x05", api_status="ACTIVE", spoke_status=None)
        assert r.status == ReconciliationStatus.MISSING_SPOKE

    def test_both_missing(self) -> None:
        r = reconcile_payment("0x06", api_status=None, spoke_status=None)
        assert r.status == ReconciliationStatus.ERROR

    def test_amount_mismatch(self) -> None:
        r = reconcile_payment("0x07", api_status="ACTIVE", spoke_status="RequestSent", api_amount=100, spoke_amount=200)
        assert r.status == ReconciliationStatus.MISMATCH

    def test_in_progress_consistent(self) -> None:
        r = reconcile_payment("0x08", api_status="ACTIVE", spoke_status="VoucherIssued")
        assert r.status == ReconciliationStatus.CONSISTENT


class TestRunReconciliation:
    def test_empty_payments(self) -> None:
        cp = run_reconciliation({}, {})
        assert cp.total_checked == 0
        assert cp.total_mismatches == 0

    def test_mixed_payments(self) -> None:
        api = {
            "0x01": {"status": "REDEEMED", "amount": 100},
            "0x02": {"status": "ACTIVE", "amount": 200},
            "0x03": {"status": "REFUNDED", "amount": 300},
        }
        spoke = {
            "0x01": {"status": "SettledSuccess", "amount": 100},
            "0x02": {"status": "VoucherIssued", "amount": 200},
            "0x04": {"status": "RequestSent", "amount": 400},
        }
        cp = run_reconciliation(api, spoke)
        assert cp.total_checked == 4  # 0x01, 0x02, 0x03, 0x04
        statuses = {r.global_payment_id: r.status for r in cp.records}
        assert statuses["0x01"] == ReconciliationStatus.CONSISTENT
        assert statuses["0x02"] == ReconciliationStatus.CONSISTENT
        assert statuses["0x03"] == ReconciliationStatus.MISSING_SPOKE
        assert statuses["0x04"] == ReconciliationStatus.MISSING_API
        assert cp.total_mismatches == 2  # 0x03 missing spoke, 0x04 missing API
