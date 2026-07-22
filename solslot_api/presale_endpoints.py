from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Iterator, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field, model_validator

from .admin_operations import require_admin_operation
from .config import Settings, get_settings
from .credential_auth import require_minting_writes


router = APIRouter(prefix="/presales", tags=["presales"])


class PresaleTermsRequest(BaseModel):
    terms_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    series_id: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    inventory_cap: int = Field(gt=0)
    xch_price_mojos: int = Field(gt=0)
    base_usdc_price_units: int = Field(gt=0)
    sale_open: int = Field(gt=0)
    sale_close: int = Field(gt=0)
    launch_deadline: int = Field(gt=0)
    identity_attest_root: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    bridge_policy_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")

    @model_validator(mode="after")
    def validate_timing(self) -> "PresaleTermsRequest":
        if not self.sale_open < self.sale_close <= self.launch_deadline:
            raise ValueError("must satisfy sale_open < sale_close <= launch_deadline")
        return self


class VoucherPurchaseRequest(BaseModel):
    serial: int = Field(ge=0)
    payment_rail: Literal["BASE_SEPOLIA_USDC", "CHIA_XCH"]
    payment_principal: int = Field(gt=0)
    vault_launcher_id: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    holder_member_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    base_depositor_commitment: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    global_payment_id: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")


class VoucherIssuanceEvidenceRequest(BaseModel):
    voucher: VoucherPurchaseRequest
    evidence_id: str = Field(min_length=8, max_length=256)
    warp_nonce: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")


class LaunchRequest(BaseModel):
    admin_approval_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    governance_execution_id: str = Field(min_length=1, max_length=256)
    vote_tally: int = Field(ge=500_000)


class PresaleStore:
    def __init__(self, path: str) -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(":memory:" if path == ":memory:" else str(Path(path)), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS presale_series (
              terms_hash TEXT PRIMARY KEY NOT NULL,
              series_id TEXT NOT NULL UNIQUE,
              terms_json TEXT NOT NULL,
              phase TEXT NOT NULL CHECK (phase IN ('PRESALE','LIVE','CANCELED')),
              created_at INTEGER NOT NULL,
              admin_approval_hash TEXT,
              governance_execution_id TEXT
            );
            CREATE TABLE IF NOT EXISTS voucher_records (
              terms_hash TEXT NOT NULL REFERENCES presale_series(terms_hash),
              serial INTEGER NOT NULL,
              payment_rail TEXT NOT NULL,
              payment_principal INTEGER NOT NULL,
              vault_launcher_id TEXT NOT NULL,
              holder_member_hash TEXT NOT NULL,
              base_depositor_commitment TEXT NOT NULL,
              global_payment_id TEXT NOT NULL UNIQUE,
              status TEXT NOT NULL CHECK (status IN ('ACTIVE','REFUNDED','REDEEMED')),
              chain_evidence_id TEXT,
              PRIMARY KEY (terms_hash, serial)
            );
            """
        )

    @contextmanager
    def txn(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                cur.close()

    def create(self, terms: PresaleTermsRequest) -> dict:
        with self.txn() as cur:
            cur.execute(
                "INSERT INTO presale_series VALUES (?, ?, ?, 'PRESALE', ?, NULL, NULL)",
                (terms.terms_hash.lower(), terms.series_id.lower(), terms.model_dump_json(), int(time.time())),
            )
        return self.get(terms.terms_hash)

    def get(self, terms_hash: str) -> dict:
        row = self._conn.execute("SELECT * FROM presale_series WHERE terms_hash = ?", (terms_hash.lower(),)).fetchone()
        if row is None:
            raise KeyError(terms_hash)
        result = dict(row)
        result["terms"] = json.loads(result.pop("terms_json"))
        return result

    def list(self) -> list[dict]:
        return [self.get(row["terms_hash"]) for row in self._conn.execute("SELECT terms_hash FROM presale_series ORDER BY created_at DESC")]

    def purchase(
        self,
        terms_hash: str,
        request: VoucherPurchaseRequest,
        chain_evidence_id: Optional[str] = None,
    ) -> dict:
        series = self.get(terms_hash)
        terms = series["terms"]
        now = int(time.time())
        expected = terms["base_usdc_price_units"] if request.payment_rail == "BASE_SEPOLIA_USDC" else terms["xch_price_mojos"]
        if series["phase"] != "PRESALE" or not terms["sale_open"] <= now < terms["sale_close"]:
            raise ValueError("presale is not open")
        if request.serial >= terms["inventory_cap"] or request.payment_principal != expected:
            raise ValueError("purchase terms do not match")
        with self.txn() as cur:
            existing = cur.execute(
                "SELECT * FROM voucher_records WHERE global_payment_id=?",
                (request.global_payment_id.lower(),),
            ).fetchone()
            if existing is not None:
                if (
                    existing["terms_hash"] == terms_hash.lower() and
                    existing["serial"] == request.serial and
                    existing["chain_evidence_id"] == chain_evidence_id
                ):
                    return dict(existing)
                raise ValueError("global payment ID is already bound to different voucher evidence")
            cur.execute(
                "INSERT INTO voucher_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)",
                (terms_hash.lower(), request.serial, request.payment_rail, request.payment_principal, request.vault_launcher_id.lower(), request.holder_member_hash.lower(), request.base_depositor_commitment.lower(), request.global_payment_id.lower(), chain_evidence_id),
            )
        return self.voucher(terms_hash, request.serial)

    def voucher(self, terms_hash: str, serial: int) -> dict:
        row = self._conn.execute("SELECT * FROM voucher_records WHERE terms_hash = ? AND serial = ?", (terms_hash.lower(), serial)).fetchone()
        if row is None:
            raise KeyError(serial)
        return dict(row)

    def refund(self, terms_hash: str, serial: int, chain_evidence_id: str) -> dict:
        series = self.get(terms_hash)
        voucher = self.voucher(terms_hash, serial)
        if series["phase"] != "PRESALE" or voucher["status"] != "ACTIVE" or not chain_evidence_id:
            raise ValueError("voucher is not refundable")
        with self.txn() as cur:
            cur.execute(
                "UPDATE voucher_records SET status='REFUNDED', chain_evidence_id=? WHERE terms_hash=? AND serial=?",
                (chain_evidence_id, terms_hash.lower(), serial),
            )
        return self.voucher(terms_hash, serial)

    def launch(self, terms_hash: str, request: LaunchRequest) -> dict:
        series = self.get(terms_hash)
        if series["phase"] != "PRESALE":
            raise ValueError("presale is not launchable")
        if int(time.time()) > series["terms"]["launch_deadline"]:
            raise ValueError("launch deadline has passed")
        with self.txn() as cur:
            cur.execute("UPDATE presale_series SET phase='LIVE', admin_approval_hash=?, governance_execution_id=? WHERE terms_hash=?", (request.admin_approval_hash.lower(), request.governance_execution_id, terms_hash.lower()))
        return self.get(terms_hash)


_store: Optional[PresaleStore] = None


def get_presale_store(settings: Annotated[Settings, Depends(get_settings)]) -> PresaleStore:
    global _store
    if _store is None:
        _store = PresaleStore(settings.admin_db_path)
    return _store


def response_or_404(call):
    try:
        return call()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="presale or voucher not found") from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="duplicate presale series or voucher serial") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "",
    status_code=201,
    dependencies=[
        Depends(require_admin_operation("presale.create")),
        Depends(require_minting_writes),
    ],
)
def create_presale(terms: PresaleTermsRequest, store: Annotated[PresaleStore, Depends(get_presale_store)]) -> dict:
    return response_or_404(lambda: store.create(terms))


@router.get("")
def list_presales(store: Annotated[PresaleStore, Depends(get_presale_store)]) -> list[dict]:
    return store.list()


@router.get("/{terms_hash}")
def get_presale(terms_hash: str, store: Annotated[PresaleStore, Depends(get_presale_store)]) -> dict:
    return response_or_404(lambda: store.get(terms_hash))


@router.post("/{terms_hash}/vouchers", status_code=status.HTTP_410_GONE)
def purchase_voucher() -> None:
    raise HTTPException(status_code=status.HTTP_410_GONE, detail="voucher records are created only from authenticated unified-rail issuance evidence")


@router.post("/{terms_hash}/vouchers/evidence", status_code=status.HTTP_201_CREATED)
def ingest_voucher_issuance_evidence(
    terms_hash: str,
    evidence: VoucherIssuanceEvidenceRequest,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict:
    token = settings.payment_omnichain_ingest_token
    if not settings.payment_omnichain_enabled or not token:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="unified omnichain evidence ingestion is disabled")
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid omnichain evidence credential")
    return response_or_404(lambda: store.purchase(terms_hash, evidence.voucher, evidence.evidence_id))


@router.get("/{terms_hash}/vouchers/{serial}")
def get_voucher(terms_hash: str, serial: int, store: Annotated[PresaleStore, Depends(get_presale_store)]) -> dict:
    return response_or_404(lambda: store.voucher(terms_hash, serial))


@router.post("/{terms_hash}/vouchers/{serial}/refund")
def ingest_voucher_refund_evidence(
    terms_hash: str,
    serial: int,
    chain_evidence_id: str,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict:
    token = settings.payment_omnichain_ingest_token
    if not settings.payment_omnichain_enabled or not token:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="unified omnichain evidence ingestion is disabled")
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid omnichain evidence credential")
    return response_or_404(lambda: store.refund(terms_hash, serial, chain_evidence_id))


@router.post(
    "/{terms_hash}/launch",
    dependencies=[
        Depends(require_admin_operation("presale.launch")),
        Depends(require_minting_writes),
    ],
)
def launch_presale(terms_hash: str, request: LaunchRequest, store: Annotated[PresaleStore, Depends(get_presale_store)]) -> dict:
    return response_or_404(lambda: store.launch(terms_hash, request))
