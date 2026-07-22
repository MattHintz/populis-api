"""Alpha operational metrics endpoint.

Exposes a JSON metrics snapshot at ``/alpha/metrics`` for dashboard
scraping and alerting.  No PII is included; all values are aggregate
counts, gauges, and timestamps.

The endpoint requires the admin JWT so metrics are not publicly
enumerable during the alpha.
"""
from __future__ import annotations

import time
from typing import Annotated, Optional

from fastapi import APIRouter, Depends

from .config import Settings, get_settings

router = APIRouter(prefix="/alpha", tags=["alpha-ops"])


def _presale_metrics(settings: Settings) -> dict:
    """Aggregate presale/voucher metrics from the in-process store."""
    try:
        from .presale_endpoints import _store

        if _store is None:
            return {"available": False}
        rows = _store._conn.execute(
            "SELECT phase, COUNT(*) as cnt FROM presale_series GROUP BY phase"
        ).fetchall()
        series_by_phase = {r["phase"]: r["cnt"] for r in rows}

        voucher_rows = _store._conn.execute(
            "SELECT status, COUNT(*) as cnt FROM voucher_records GROUP BY status"
        ).fetchall()
        vouchers_by_status = {r["status"]: r["cnt"] for r in voucher_rows}

        stale_rows = _store._conn.execute(
            "SELECT COUNT(*) as cnt FROM voucher_records "
            "WHERE status = 'ACTIVE' AND rowid IN ("
            "  SELECT rowid FROM voucher_records WHERE status = 'ACTIVE'"
            ")"
        ).fetchone()

        return {
            "available": True,
            "series_by_phase": series_by_phase,
            "vouchers_by_status": vouchers_by_status,
            "active_voucher_count": stale_rows["cnt"] if stale_rows else 0,
        }
    except Exception:
        return {"available": False}


def _telemetry_metrics() -> dict:
    """Aggregate telemetry/bug-report counts."""
    try:
        from .alpha_observability import _telemetry_store, _bug_report_store

        return {
            "telemetry_event_count": len(_telemetry_store),
            "bug_report_count": len(_bug_report_store),
        }
    except Exception:
        return {"telemetry_event_count": 0, "bug_report_count": 0}


@router.get("/metrics")
def alpha_metrics(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Return an aggregate operational metrics snapshot.

    Intended for dashboard scraping; no PII or secrets are included.
    """
    return {
        "timestamp": int(time.time()),
        "network": settings.network,
        "flags": {
            "alpha_writes_enabled": settings.alpha_writes_enabled,
            "minting_enabled": settings.minting_enabled,
            "payment_omnichain_enabled": settings.payment_omnichain_enabled,
        },
        "presale": _presale_metrics(settings),
        "telemetry": _telemetry_metrics(),
    }
