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
class StoredPaymentInventoryItem:
    ordinal: int
    deed_launcher_id: str
    child_purchase_id: str
    child_artifact_hash: str
    state: str
    available_coin_id: str | None
    reserved_coin_id: str | None
    reserved_puzzle_hash: str | None
    signer_indices: tuple[int, ...]
    signature: str | None


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
    deed_launcher_id: str | None = None
    deed_launcher_ids: tuple[str, ...] = ()
    inventory_state: str = "UNRESERVED"
    inventory_available_coin_id: str | None = None
    inventory_reserved_coin_id: str | None = None
    inventory_reserved_puzzle_hash: str | None = None
    inventory_expires_at: int | None = None
    inventory_bundle: dict[str, Any] | None = None
    inventory_bundle_id: str | None = None
    inventory_signer_indices: tuple[int, ...] = ()
    inventory_signature: str | None = None
    inventory_mempool_observed_at: str | None = None
    inventory_confirmation_height: int | None = None


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
                    deed_launcher_id TEXT,
                    deed_launcher_ids_json TEXT NOT NULL DEFAULT '[]',
                    inventory_state TEXT NOT NULL DEFAULT 'UNRESERVED',
                    inventory_available_coin_id TEXT,
                    inventory_reserved_coin_id TEXT UNIQUE,
                    inventory_reserved_puzzle_hash TEXT,
                    inventory_expires_at INTEGER,
                    inventory_bundle_json TEXT,
                    inventory_bundle_id TEXT UNIQUE,
                    inventory_signer_indices_json TEXT NOT NULL DEFAULT '[]',
                    inventory_signature TEXT,
                    inventory_mempool_observed_at TEXT,
                    inventory_confirmation_height INTEGER,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS payment_purchases_expiry
                    ON payment_purchases(quote_expires_at);
                CREATE TABLE IF NOT EXISTS payment_purchase_inventory_items (
                    purchase_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    deed_launcher_id TEXT NOT NULL,
                    child_purchase_id TEXT NOT NULL UNIQUE,
                    child_artifact_hash TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL DEFAULT 'UNRESERVED',
                    available_coin_id TEXT,
                    reserved_coin_id TEXT UNIQUE,
                    reserved_puzzle_hash TEXT,
                    signer_indices_json TEXT NOT NULL DEFAULT '[]',
                    signature TEXT,
                    PRIMARY KEY (purchase_id, ordinal),
                    UNIQUE (purchase_id, deed_launcher_id),
                    FOREIGN KEY (purchase_id) REFERENCES payment_purchases(purchase_id)
                        ON DELETE CASCADE
                );
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
            inventory_columns = {
                "deed_launcher_id": "TEXT",
                "deed_launcher_ids_json": "TEXT NOT NULL DEFAULT '[]'",
                "inventory_state": "TEXT NOT NULL DEFAULT 'UNRESERVED'",
                "inventory_available_coin_id": "TEXT",
                "inventory_reserved_coin_id": "TEXT",
                "inventory_reserved_puzzle_hash": "TEXT",
                "inventory_expires_at": "INTEGER",
                "inventory_bundle_json": "TEXT",
                "inventory_bundle_id": "TEXT",
                "inventory_signer_indices_json": "TEXT NOT NULL DEFAULT '[]'",
                "inventory_signature": "TEXT",
                "inventory_mempool_observed_at": "TEXT",
                "inventory_confirmation_height": "INTEGER",
            }
            for name, declaration in inventory_columns.items():
                if name not in columns:
                    cursor = connection.execute(
                        f"ALTER TABLE payment_purchases ADD COLUMN {name} {declaration}"
                    )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchases_external_transaction "
                "ON payment_purchases(external_transaction_hash)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchases_inventory_bundle "
                "ON payment_purchases(inventory_bundle_id) "
                "WHERE inventory_bundle_id IS NOT NULL"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchases_reserved_coin "
                "ON payment_purchases(inventory_reserved_coin_id) "
                "WHERE inventory_reserved_coin_id IS NOT NULL"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchases_active_deed_reservation "
                "ON payment_purchases(deed_launcher_id) "
                "WHERE deed_launcher_id IS NOT NULL AND inventory_state IN "
                "('PREPARED', 'SUBMITTED', 'CONFIRMED')"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchase_inventory_active_deed "
                "ON payment_purchase_inventory_items(deed_launcher_id) "
                "WHERE state IN ('PREPARED', 'SUBMITTED', 'CONFIRMED')"
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
        if purchase_artifact.get("schema") == "solslot.purchase-batch.v1":
            artifact_hash = _required_string(purchase_artifact, "batchHash")
            children = purchase_artifact.get("artifacts")
            if not isinstance(children, list) or not children:
                raise PaymentPurchaseConflict(
                    "purchase batch must contain canonical child artifacts"
                )
            quote_expires_at = min(
                _required_decimal(child, "quoteExpiresAt")
                for child in children
                if isinstance(child, Mapping)
            )
            deed_launcher_ids = tuple(
                value
                for value in (
                    _optional_nonzero_hex32(child.get("deedLauncherId"))
                    for child in children
                    if isinstance(child, Mapping)
                )
                if value is not None
            )
            if len(deed_launcher_ids) != len(children):
                raise PaymentPurchaseConflict(
                    "purchase batch child deed commitments are incomplete"
                )
            inventory_children = tuple(children)
        else:
            artifact_hash = _required_string(purchase_artifact, "artifactHash")
            quote_expires_at = _required_decimal(
                purchase_artifact,
                "quoteExpiresAt",
            )
            single_launcher = _optional_nonzero_hex32(
                purchase_artifact.get("deedLauncherId")
            )
            deed_launcher_ids = (
                (single_launcher,) if single_launcher is not None else ()
            )
            inventory_children = (
                (purchase_artifact,) if single_launcher is not None else ()
            )
        if len(set(deed_launcher_ids)) != len(deed_launcher_ids):
            raise PaymentPurchaseConflict(
                "purchase contains duplicate SmartDeed launchers"
            )
        deed_launcher_id = deed_launcher_ids[0] if deed_launcher_ids else None
        deed_launcher_ids_json = json.dumps(list(deed_launcher_ids))
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
                    deed_launcher_id,
                    deed_launcher_ids_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    deed_launcher_id,
                    deed_launcher_ids_json,
                    created_at,
                ),
            )
            for ordinal, child in enumerate(inventory_children):
                connection.execute(
                    """
                    INSERT INTO payment_purchase_inventory_items (
                        purchase_id, ordinal, deed_launcher_id,
                        child_purchase_id, child_artifact_hash
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        purchase_id,
                        ordinal,
                        deed_launcher_ids[ordinal],
                        _required_string(child, "purchaseId"),
                        _required_string(child, "artifactHash"),
                    ),
                )
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)

    def inventory_items(
        self,
        purchase_id: str,
    ) -> tuple[StoredPaymentInventoryItem, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM payment_purchase_inventory_items
                WHERE purchase_id = ? ORDER BY ordinal
                """,
                (purchase_id,),
            ).fetchall()
        return tuple(_inventory_item(row) for row in rows)

    def record_inventory_batch_prepared(
        self,
        purchase_id: str,
        *,
        items: tuple[Mapping[str, Any], ...],
        bundle: Mapping[str, Any],
    ) -> StoredPaymentPurchase:
        """Atomically bind every selected deed to one reservation bundle."""

        if not items:
            raise PaymentPurchaseConflict(
                "reservation manifest must contain at least one SmartDeed"
            )
        bundle_json = _canonical_json(bundle)
        normalized_items: list[dict[str, Any]] = []
        for item in items:
            try:
                signer_indices = tuple(int(value) for value in item["signer_indices"])
                normalized_items.append(
                    {
                        "deed_launcher_id": str(item["deed_launcher_id"]),
                        "available_coin_id": str(item["available_coin_id"]),
                        "reserved_coin_id": str(item["reserved_coin_id"]),
                        "reserved_puzzle_hash": str(item["reserved_puzzle_hash"]),
                        "expires_at": int(item["expires_at"]),
                        "signer_indices_json": json.dumps(list(signer_indices)),
                        "signature": str(item["signature"]),
                    }
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise PaymentPurchaseConflict(
                    "reservation manifest is incomplete"
                ) from exc
        expires_at = normalized_items[0]["expires_at"]
        if any(item["expires_at"] != expires_at for item in normalized_items):
            raise PaymentPurchaseConflict(
                "all SmartDeeds in a batch must share one reservation expiry"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            parent = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            rows = connection.execute(
                """SELECT * FROM payment_purchase_inventory_items
                   WHERE purchase_id = ? ORDER BY ordinal""",
                (purchase_id,),
            ).fetchall()
            if parent is None or not rows:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound("purchase inventory was not found")
            if len(rows) != len(normalized_items):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "reservation manifest does not match the purchase quantity"
                )
            try:
                for row, item in zip(rows, normalized_items, strict=True):
                    expected_launcher = str(row["deed_launcher_id"])
                    if item["deed_launcher_id"] != expected_launcher:
                        raise PaymentPurchaseConflict(
                            "reservation manifest changes a SmartDeed launcher"
                        )
                    expected_values = {
                        "available_coin_id": item["available_coin_id"],
                        "reserved_coin_id": item["reserved_coin_id"],
                        "reserved_puzzle_hash": item["reserved_puzzle_hash"],
                        "signer_indices_json": item["signer_indices_json"],
                        "signature": item["signature"],
                    }
                    if row["state"] == "PREPARED":
                        if any(row[name] != value for name, value in expected_values.items()):
                            raise PaymentPurchaseConflict(
                                "prepared reservation evidence cannot be changed"
                            )
                        continue
                    if row["state"] != "UNRESERVED":
                        raise PaymentPurchaseConflict(
                            "reservation item is not in a preparable state"
                        )
                    cursor = connection.execute(
                        """
                        UPDATE payment_purchase_inventory_items
                        SET state='PREPARED', available_coin_id=?,
                            reserved_coin_id=?, reserved_puzzle_hash=?,
                            signer_indices_json=?, signature=?
                        WHERE purchase_id=? AND ordinal=?
                          AND state IN ('UNRESERVED', 'PREPARED')
                        """,
                        (
                            item["available_coin_id"],
                            item["reserved_coin_id"],
                            item["reserved_puzzle_hash"],
                            item["signer_indices_json"],
                            item["signature"],
                            purchase_id,
                            int(row["ordinal"]),
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise PaymentPurchaseConflict(
                            "reservation item is not in a preparable state"
                        )
                first = normalized_items[0]
                parent_values = {
                    "inventory_available_coin_id": first["available_coin_id"],
                    "inventory_reserved_coin_id": first["reserved_coin_id"],
                    "inventory_reserved_puzzle_hash": first["reserved_puzzle_hash"],
                    "inventory_expires_at": expires_at,
                    "inventory_bundle_json": bundle_json,
                    "inventory_signer_indices_json": first["signer_indices_json"],
                    "inventory_signature": first["signature"],
                }
                if parent["inventory_state"] == "PREPARED":
                    if any(parent[name] != value for name, value in parent_values.items()):
                        raise PaymentPurchaseConflict(
                            "prepared batch evidence cannot be changed"
                        )
                elif parent["inventory_state"] == "UNRESERVED":
                    parent_cursor = connection.execute(
                        """
                        UPDATE payment_purchases
                        SET inventory_state='PREPARED',
                            inventory_available_coin_id=?,
                            inventory_reserved_coin_id=?,
                            inventory_reserved_puzzle_hash=?,
                            inventory_expires_at=?, inventory_bundle_json=?,
                            inventory_signer_indices_json=?, inventory_signature=?
                        WHERE purchase_id=? AND inventory_state='UNRESERVED'
                        """,
                        (
                            *parent_values.values(),
                            purchase_id,
                        ),
                    )
                    if parent_cursor.rowcount != 1:
                        raise PaymentPurchaseConflict(
                            "reservation batch is not in a preparable state"
                        )
                else:
                    raise PaymentPurchaseConflict(
                        "reservation batch is not in a preparable state"
                    )
            except (
                KeyError,
                TypeError,
                ValueError,
                sqlite3.IntegrityError,
                PaymentPurchaseConflict,
            ) as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "one or more SmartDeeds are already reserved"
                ) from exc
            result = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert result is not None
        return _record(result)

    def record_inventory_prepared(
        self,
        purchase_id: str,
        *,
        available_coin_id: str,
        reserved_coin_id: str,
        reserved_puzzle_hash: str,
        expires_at: int,
        bundle: Mapping[str, Any],
        signer_indices: tuple[int, ...],
        signature: str,
    ) -> StoredPaymentPurchase:
        record = self.get(purchase_id)
        if record.deed_launcher_id is None:
            raise PaymentPurchaseConflict(
                "purchase has no SmartDeed inventory commitment"
            )
        return self.record_inventory_batch_prepared(
            purchase_id,
            items=(
                {
                    "deed_launcher_id": record.deed_launcher_id,
                    "available_coin_id": available_coin_id,
                    "reserved_coin_id": reserved_coin_id,
                    "reserved_puzzle_hash": reserved_puzzle_hash,
                    "expires_at": expires_at,
                    "signer_indices": signer_indices,
                    "signature": signature,
                },
            ),
            bundle=bundle,
        )

    def record_inventory_submitted(
        self,
        purchase_id: str,
        *,
        bundle_id: str,
        mempool_observed_at: str,
    ) -> StoredPaymentPurchase:
        result = self._transition_inventory(
            purchase_id,
            expected_states=("PREPARED", "SUBMITTED"),
            next_state="SUBMITTED",
            values={
                "inventory_bundle_id": bundle_id,
                "inventory_mempool_observed_at": mempool_observed_at,
            },
        )
        return result

    def record_inventory_confirmed(
        self,
        purchase_id: str,
        *,
        confirmation_height: int,
    ) -> StoredPaymentPurchase:
        result = self._transition_inventory(
            purchase_id,
            expected_states=("SUBMITTED", "CONFIRMED"),
            next_state="CONFIRMED",
            values={"inventory_confirmation_height": confirmation_height},
        )
        return result

    def _transition_inventory(
        self,
        purchase_id: str,
        *,
        expected_states: tuple[str, ...],
        next_state: str,
        values: Mapping[str, Any],
    ) -> StoredPaymentPurchase:
        assignments = ["inventory_state = ?", *[f"{name} = ?" for name in values]]
        parameters = [next_state, *values.values(), purchase_id, *expected_states]
        placeholders = ", ".join("?" for _ in expected_states)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    f"UPDATE payment_purchases SET {', '.join(assignments)} "
                    f"WHERE purchase_id = ? AND inventory_state IN ({placeholders})",
                    parameters,
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "SmartDeed inventory is already reserved by another purchase"
                ) from exc
            if cursor.rowcount != 1:
                row = connection.execute(
                    "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                    (purchase_id,),
                ).fetchone()
                connection.execute("ROLLBACK")
                if row is None:
                    raise PaymentPurchaseNotFound("purchase artifact was not found")
                record = _record(row)
                if record.inventory_state == next_state and all(
                    row[name] == value for name, value in values.items()
                ):
                    return record
                raise PaymentPurchaseConflict(
                    f"inventory transition {record.inventory_state} -> {next_state} is not allowed"
                )
            item_cursor = connection.execute(
                f"UPDATE payment_purchase_inventory_items SET state=? "
                f"WHERE purchase_id=? AND state IN ({placeholders})",
                (next_state, purchase_id, *expected_states),
            )
            item_total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM payment_purchase_inventory_items "
                    "WHERE purchase_id=?",
                    (purchase_id,),
                ).fetchone()[0]
            )
            if item_total < 1 or item_cursor.rowcount != item_total:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "inventory item transition is incomplete"
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
    inventory_bundle_json = row["inventory_bundle_json"]
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
        deed_launcher_id=row["deed_launcher_id"],
        deed_launcher_ids=tuple(
            str(value) for value in json.loads(row["deed_launcher_ids_json"])
        ),
        inventory_state=row["inventory_state"],
        inventory_available_coin_id=row["inventory_available_coin_id"],
        inventory_reserved_coin_id=row["inventory_reserved_coin_id"],
        inventory_reserved_puzzle_hash=row["inventory_reserved_puzzle_hash"],
        inventory_expires_at=(
            int(row["inventory_expires_at"])
            if row["inventory_expires_at"] is not None
            else None
        ),
        inventory_bundle=(
            json.loads(inventory_bundle_json)
            if inventory_bundle_json is not None
            else None
        ),
        inventory_bundle_id=row["inventory_bundle_id"],
        inventory_signer_indices=tuple(
            int(value)
            for value in json.loads(row["inventory_signer_indices_json"])
        ),
        inventory_signature=row["inventory_signature"],
        inventory_mempool_observed_at=row["inventory_mempool_observed_at"],
        inventory_confirmation_height=(
            int(row["inventory_confirmation_height"])
            if row["inventory_confirmation_height"] is not None
            else None
        ),
    )


def _inventory_item(row: sqlite3.Row) -> StoredPaymentInventoryItem:
    return StoredPaymentInventoryItem(
        ordinal=int(row["ordinal"]),
        deed_launcher_id=str(row["deed_launcher_id"]),
        child_purchase_id=str(row["child_purchase_id"]),
        child_artifact_hash=str(row["child_artifact_hash"]),
        state=str(row["state"]),
        available_coin_id=row["available_coin_id"],
        reserved_coin_id=row["reserved_coin_id"],
        reserved_puzzle_hash=row["reserved_puzzle_hash"],
        signer_indices=tuple(
            int(value) for value in json.loads(row["signer_indices_json"])
        ),
        signature=row["signature"],
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


def _required_decimal(value: Mapping[str, Any], field: str) -> int:
    result = value.get(field)
    if isinstance(result, bool):
        raise PaymentPurchaseConflict(f"{field} must be a decimal integer")
    if isinstance(result, int):
        return result
    if isinstance(result, str) and result.isdecimal():
        return int(result)
    raise PaymentPurchaseConflict(f"{field} must be a decimal integer")


def _optional_nonzero_hex32(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise PaymentPurchaseConflict("deedLauncherId is not valid hex") from exc
    if len(raw) != 32:
        raise PaymentPurchaseConflict("deedLauncherId must be 32 bytes")
    return None if raw == bytes(32) else normalized


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
