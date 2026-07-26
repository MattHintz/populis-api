from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from .config import Settings, get_settings
from .server_hardening import trusted_client_ip

router = APIRouter(prefix="/alpha", tags=["alpha-observability"])


class AlphaTelemetryRequest(BaseModel):
    event: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    correlation_id: str = Field(min_length=8, max_length=128)
    release_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    artifact_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    rail: Optional[Literal["XCH", "BASE_USDC", "VOUCHER_USDC"]] = None
    wallet_type: Optional[Literal["chia", "evm", "google", "passkey"]] = None
    latency_ms: Optional[int] = Field(default=None, ge=0, le=600_000)
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("details")
    @classmethod
    def bounded_details(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 4096:
            raise ValueError("details exceed 4096 bytes")
        return value


class AlphaBugReportRequest(BaseModel):
    category: Literal["PAYMENT", "VOUCHER", "WALLET", "IDENTITY", "UI", "OTHER"]
    summary: str = Field(min_length=4, max_length=240)
    description: str = Field(min_length=4, max_length=4000)
    correlation_id: Optional[str] = Field(default=None, min_length=8, max_length=128)
    transaction_id: Optional[str] = Field(default=None, pattern=r"^0x[0-9a-fA-F]{64}$")
    contact: Optional[str] = Field(default=None, max_length=254)
    diagnostics_opt_in: bool = False
    diagnostics: dict[str, Any] = Field(default_factory=dict)

    @field_validator("diagnostics")
    @classmethod
    def bounded_diagnostics(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 4096:
            raise ValueError("diagnostics exceed 4096 bytes")
        return value


class AlphaObservabilityStore:
    def __init__(self, path: str) -> None:
        self.path = ":memory:" if path == ":memory:" else str(Path(path))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alpha_telemetry_events (
                id TEXT PRIMARY KEY,
                occurred_at INTEGER NOT NULL,
                event TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                release_sha TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                rail TEXT,
                wallet_type TEXT,
                latency_ms INTEGER,
                source_ip_hash TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS alpha_telemetry_occurred_idx
                ON alpha_telemetry_events(occurred_at);
            CREATE TABLE IF NOT EXISTS alpha_bug_reports (
                id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                category TEXT NOT NULL,
                summary TEXT NOT NULL,
                description TEXT NOT NULL,
                correlation_id TEXT,
                transaction_id TEXT,
                contact TEXT,
                diagnostics_opt_in INTEGER NOT NULL,
                diagnostics_json TEXT NOT NULL,
                source_ip_hash TEXT NOT NULL,
                status TEXT NOT NULL
            );
            """
        )

    def telemetry(self, payload: AlphaTelemetryRequest, source_ip: str) -> str:
        event_id = "evt_" + uuid.uuid4().hex
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO alpha_telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id, int(time.time()), payload.event, payload.correlation_id,
                    payload.release_sha, payload.artifact_hash.lower(), payload.rail,
                    payload.wallet_type, payload.latency_ms, _ip_hash(source_ip),
                    json.dumps(payload.details, sort_keys=True, separators=(",", ":")),
                ),
            )
            self._conn.commit()
        return event_id

    def report(self, payload: AlphaBugReportRequest, source_ip: str) -> str:
        report_id = "bug_" + uuid.uuid4().hex
        diagnostics = payload.diagnostics if payload.diagnostics_opt_in else {}
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO alpha_bug_reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id, int(time.time()), payload.category, payload.summary.strip(),
                    payload.description.strip(), payload.correlation_id, payload.transaction_id,
                    payload.contact.strip() if payload.contact else None, int(payload.diagnostics_opt_in),
                    json.dumps(diagnostics, sort_keys=True, separators=(",", ":")),
                    _ip_hash(source_ip), "OPEN",
                ),
            )
            self._conn.commit()
        return report_id


_store: Optional[AlphaObservabilityStore] = None


def get_alpha_observability_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> AlphaObservabilityStore:
    global _store
    if _store is None:
        _store = AlphaObservabilityStore(settings.admin_db_path)
    return _store


def _ip_hash(source_ip: str) -> str:
    return hashlib.sha256(source_ip.encode("utf-8")).hexdigest()


@router.post("/telemetry", status_code=202)
def record_alpha_telemetry(
    payload: AlphaTelemetryRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[AlphaObservabilityStore, Depends(get_alpha_observability_store)],
) -> dict[str, str]:
    return {"id": store.telemetry(payload, trusted_client_ip(request.scope, settings))}


@router.post("/bug-reports", status_code=201)
def submit_alpha_bug_report(
    payload: AlphaBugReportRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[AlphaObservabilityStore, Depends(get_alpha_observability_store)],
) -> dict[str, str]:
    try:
        report_id = store.report(payload, trusted_client_ip(request.scope, settings))
    except sqlite3.Error as exc:
        raise HTTPException(status_code=503, detail="bug reporting is temporarily unavailable") from exc
    return {"id": report_id, "status": "OPEN"}
