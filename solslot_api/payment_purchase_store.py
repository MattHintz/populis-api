"""Persistent canonical purchase-artifact records.

The coordinator is the authority for the purchase artifact a buyer approved.
Bridge relayers look records up by the domain-separated purchase ID and bind
the first authenticated external payment message before fulfillment.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Mapping


class PaymentPurchaseNotFound(LookupError):
    pass


class PaymentPurchaseConflict(ValueError):
    pass


@dataclass(frozen=True)
class StoredPaymentPurchase:
    purchase_id: str
    artifact_hash: str
    purchase_intent_id: str
    rail: str
    quote_expires_at: int
    offer_artifact_hash: str
    offer_artifact: dict[str, Any]
    purchase_artifact: dict[str, Any]
    external_message: dict[str, Any] | None


class PaymentPurchaseStore:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS payment_purchases (
                    purchase_id TEXT PRIMARY KEY,
                    artifact_hash TEXT NOT NULL UNIQUE,
                    purchase_intent_id TEXT NOT NULL UNIQUE,
                    rail TEXT NOT NULL,
                    quote_expires_at INTEGER NOT NULL,
                    offer_artifact_hash TEXT NOT NULL,
                    offer_artifact_json TEXT NOT NULL,
                    purchase_artifact_json TEXT NOT NULL,
                    external_global_payment_id TEXT UNIQUE,
                    external_transaction_hash TEXT,
                    external_message_json TEXT,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS payment_purchases_expiry
                    ON payment_purchases(quote_expires_at);
                """
            )
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(payment_purchases)"
                ).fetchall()
            }
            if "external_transaction_hash" not in columns:
                connection.execute(
                    "ALTER TABLE payment_purchases "
                    "ADD COLUMN external_transaction_hash TEXT"
                )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchases_external_transaction "
                "ON payment_purchases(external_transaction_hash)"
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
        try:
            yield connection
        finally:
            connection.close()

    def save(
        self,
        *,
        purchase_intent_id: str,
        rail: str,
        offer_artifact_hash: str,
        offer_artifact: Mapping[str, Any],
        purchase_artifact: Mapping[str, Any],
        created_at: int,
    ) -> StoredPaymentPurchase:
        purchase_id = _required_string(purchase_artifact, "purchaseId")
        artifact_hash = _required_string(purchase_artifact, "artifactHash")
        quote_expires_at = _required_int(
            purchase_artifact,
            "quoteExpiresAt",
        )
        offer_json = _canonical_json(offer_artifact)
        purchase_json = _canonical_json(purchase_artifact)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT * FROM payment_purchases
                WHERE purchase_id = ? OR artifact_hash = ?
                   OR purchase_intent_id = ?
                """,
                (purchase_id, artifact_hash, purchase_intent_id),
            ).fetchone()
            if existing is not None:
                record = _record(existing)
                if (
                    record.purchase_id != purchase_id
                    or record.artifact_hash != artifact_hash
                    or record.purchase_intent_id != purchase_intent_id
                    or record.rail != rail
                    or _canonical_json(record.purchase_artifact)
                    != purchase_json
                ):
                    connection.execute("ROLLBACK")
                    raise PaymentPurchaseConflict(
                        "purchase intent is already bound to another artifact"
                    )
                connection.execute("COMMIT")
                return record
            connection.execute(
                """
                INSERT INTO payment_purchases (
                    purchase_id,
                    artifact_hash,
                    purchase_intent_id,
                    rail,
                    quote_expires_at,
                    offer_artifact_hash,
                    offer_artifact_json,
                    purchase_artifact_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    purchase_id,
                    artifact_hash,
                    purchase_intent_id,
                    rail,
                    quote_expires_at,
                    offer_artifact_hash,
                    offer_json,
                    purchase_json,
                    created_at,
                ),
            )
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)

    def get(self, purchase_id: str) -> StoredPaymentPurchase:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
        if row is None:
            raise PaymentPurchaseNotFound("purchase artifact was not found")
        return _record(row)

    def bind_external_message(
        self,
        purchase_id: str,
        message: Mapping[str, Any],
    ) -> StoredPaymentPurchase:
        message_json = _canonical_json(message)
        global_payment_id = _required_string(message, "globalPaymentId")
        source = _required_mapping(message, "source")
        transaction_hash = _required_string(source, "transactionHash")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase artifact was not found"
                )
            existing_json = row["external_message_json"]
            if existing_json is not None:
                if existing_json != message_json:
                    connection.execute("ROLLBACK")
                    raise PaymentPurchaseConflict(
                        "purchase is already bound to another external payment"
                    )
                connection.execute("COMMIT")
                return _record(row)
            try:
                connection.execute(
                    """
                    UPDATE payment_purchases
                    SET external_global_payment_id = ?,
                        external_transaction_hash = ?,
                        external_message_json = ?
                    WHERE purchase_id = ?
                    """,
                    (
                        global_payment_id,
                        transaction_hash,
                        message_json,
                        purchase_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "external payment is already bound to another purchase"
                ) from exc
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)


def _record(row: sqlite3.Row) -> StoredPaymentPurchase:
    external_json = row["external_message_json"]
    return StoredPaymentPurchase(
        purchase_id=row["purchase_id"],
        artifact_hash=row["artifact_hash"],
        purchase_intent_id=row["purchase_intent_id"],
        rail=row["rail"],
        quote_expires_at=int(row["quote_expires_at"]),
        offer_artifact_hash=row["offer_artifact_hash"],
        offer_artifact=json.loads(row["offer_artifact_json"]),
        purchase_artifact=json.loads(row["purchase_artifact_json"]),
        external_message=(
            json.loads(external_json) if external_json is not None else None
        ),
    )


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _required_string(value: Mapping[str, Any], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise PaymentPurchaseConflict(f"{field} is required")
    return result


def _required_int(value: Mapping[str, Any], field: str) -> int:
    result = value.get(field)
    if not isinstance(result, int) or isinstance(result, bool):
        raise PaymentPurchaseConflict(f"{field} must be an integer")
    return result


def _required_mapping(value: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    result = value.get(field)
    if not isinstance(result, Mapping):
        raise PaymentPurchaseConflict(f"{field} must be an object")
    return result


_cached_store: PaymentPurchaseStore | None = None
_cached_store_path: str | None = None


def get_payment_purchase_store(path: str) -> PaymentPurchaseStore:
    global _cached_store, _cached_store_path
    if _cached_store is None or _cached_store_path != path:
        _cached_store = PaymentPurchaseStore(path)
        _cached_store_path = path
    return _cached_store
