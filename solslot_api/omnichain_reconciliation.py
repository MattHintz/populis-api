"""Omnichain payment reconciliation and relayer checkpoint.

Provides a non-signing relayer checkpoint that joins spoke/gateway/API
state by global payment ID, detects mismatches, and emits structured
reconciliation events.  Designed to run periodically (e.g. via cron or
background task) during the continuous Alpha.

The reconciliation job is read-only and never creates, modifies, or
reroutes payments.  Detected mismatches are logged as audit events and
surfaced through ``/alpha/metrics``.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ReconciliationStatus(str, Enum):
    CONSISTENT = "CONSISTENT"
    MISMATCH = "MISMATCH"
    STALE = "STALE"
    MISSING_SPOKE = "MISSING_SPOKE"
    MISSING_API = "MISSING_API"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ReconciliationRecord:
    global_payment_id: str
    status: ReconciliationStatus
    api_state: Optional[str] = None
    spoke_state: Optional[str] = None
    detail: str = ""
    checked_at: int = 0


@dataclass
class ReconciliationCheckpoint:
    """Tracks the last reconciled block/timestamp for incremental runs."""
    last_checked_at: int = 0
    last_block: int = 0
    total_checked: int = 0
    total_mismatches: int = 0
    records: list[ReconciliationRecord] = field(default_factory=list)

    def add(self, record: ReconciliationRecord) -> None:
        self.records.append(record)
        self.total_checked += 1
        if record.status != ReconciliationStatus.CONSISTENT:
            self.total_mismatches += 1


def reconcile_payment(
    global_payment_id: str,
    api_status: Optional[str],
    spoke_status: Optional[str],
    spoke_amount: Optional[int] = None,
    api_amount: Optional[int] = None,
) -> ReconciliationRecord:
    """Compare a single payment's API and spoke states.

    Returns a ReconciliationRecord with the detected status.
    This function is pure and side-effect free.
    """
    now = int(time.time())

    if api_status is None and spoke_status is None:
        return ReconciliationRecord(
            global_payment_id=global_payment_id,
            status=ReconciliationStatus.ERROR,
            detail="payment not found in either API or spoke",
            checked_at=now,
        )

    if api_status is None:
        return ReconciliationRecord(
            global_payment_id=global_payment_id,
            status=ReconciliationStatus.MISSING_API,
            spoke_state=spoke_status,
            detail="payment exists in spoke but not in API",
            checked_at=now,
        )

    if spoke_status is None:
        return ReconciliationRecord(
            global_payment_id=global_payment_id,
            status=ReconciliationStatus.MISSING_SPOKE,
            api_state=api_status,
            detail="payment exists in API but not in spoke",
            checked_at=now,
        )

    # State mapping: spoke terminal states vs API terminal states
    _TERMINAL_SPOKE = {"SettledSuccess", "SettledRefund", "EmergencyRefund", "VoucherRefunded"}
    _TERMINAL_API = {"REDEEMED", "REFUNDED"}

    # Both terminal — check agreement
    if spoke_status in _TERMINAL_SPOKE and api_status in _TERMINAL_API:
        if (spoke_status in ("SettledRefund", "EmergencyRefund", "VoucherRefunded")) == (api_status == "REFUNDED"):
            status = ReconciliationStatus.CONSISTENT
        else:
            status = ReconciliationStatus.MISMATCH
        return ReconciliationRecord(
            global_payment_id=global_payment_id,
            status=status,
            api_state=api_status,
            spoke_state=spoke_status,
            detail="terminal state comparison",
            checked_at=now,
        )

    # Amount mismatch
    if spoke_amount is not None and api_amount is not None and spoke_amount != api_amount:
        return ReconciliationRecord(
            global_payment_id=global_payment_id,
            status=ReconciliationStatus.MISMATCH,
            api_state=api_status,
            spoke_state=spoke_status,
            detail=f"amount mismatch: spoke={spoke_amount} api={api_amount}",
            checked_at=now,
        )

    # Non-terminal — consistent if both are in progress
    return ReconciliationRecord(
        global_payment_id=global_payment_id,
        status=ReconciliationStatus.CONSISTENT,
        api_state=api_status,
        spoke_state=spoke_status,
        detail="in-progress state comparison",
        checked_at=now,
    )


def run_reconciliation(
    api_payments: dict[str, dict],
    spoke_payments: dict[str, dict],
) -> ReconciliationCheckpoint:
    """Run a full reconciliation pass over all known payments.

    Args:
        api_payments: mapping of global_payment_id → {"status": str, "amount": int}
        spoke_payments: mapping of global_payment_id → {"status": str, "amount": int}

    Returns a checkpoint with all reconciliation records.
    """
    checkpoint = ReconciliationCheckpoint(last_checked_at=int(time.time()))
    all_ids = set(api_payments.keys()) | set(spoke_payments.keys())

    for gid in sorted(all_ids):
        api_entry = api_payments.get(gid)
        spoke_entry = spoke_payments.get(gid)
        record = reconcile_payment(
            global_payment_id=gid,
            api_status=api_entry.get("status") if api_entry else None,
            spoke_status=spoke_entry.get("status") if spoke_entry else None,
            api_amount=api_entry.get("amount") if api_entry else None,
            spoke_amount=spoke_entry.get("amount") if spoke_entry else None,
        )
        checkpoint.add(record)

    if checkpoint.total_mismatches > 0:
        logger.warning(
            "reconciliation found %d mismatches out of %d payments",
            checkpoint.total_mismatches,
            checkpoint.total_checked,
        )
    else:
        logger.info(
            "reconciliation passed: %d payments consistent",
            checkpoint.total_checked,
        )

    return checkpoint
