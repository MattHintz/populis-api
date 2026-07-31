"""Persistent canonical purchase-artifact records.

The coordinator is the authority for the purchase artifact a buyer approved.
Bridge relayers look records up by the domain-separated purchase ID and bind
the first authenticated external payment message before fulfillment.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Iterator, Mapping


_ZERO_BYTES32 = "0x" + "00" * 32


class PaymentPurchaseNotFound(LookupError):
    pass


class PaymentPurchaseConflict(ValueError):
    pass


class PurchaseOperationState(StrEnum):
    ARTIFACT_READY = "ARTIFACT_READY"
    SOFT_HELD = "SOFT_HELD"
    RESERVING = "RESERVING"
    RESERVATION_MEMPOOL = "RESERVATION_MEMPOOL"
    RESERVED = "RESERVED"
    PAYMENT_METHOD_READY = "PAYMENT_METHOD_READY"
    PAYMENT_PROCESSING = "PAYMENT_PROCESSING"
    PAYMENT_SUCCEEDED = "PAYMENT_SUCCEEDED"
    VOUCHER_PENDING = "VOUCHER_PENDING"
    VOUCHER_ISSUANCE_MEMPOOL = "VOUCHER_ISSUANCE_MEMPOOL"
    VOUCHER_ESCROWED = "VOUCHER_ESCROWED"
    RECEIPT_MEMPOOL = "RECEIPT_MEMPOOL"
    RECEIPT_READY = "RECEIPT_READY"
    DELIVERY_SUBMITTED = "DELIVERY_SUBMITTED"
    MEMPOOL_OBSERVED = "MEMPOOL_OBSERVED"
    CHAIN_CONFIRMED = "CHAIN_CONFIRMED"
    FINALIZED = "FINALIZED"
    PAYMENT_FAILED = "PAYMENT_FAILED"
    CANCELED = "CANCELED"
    REFUND_PENDING = "REFUND_PENDING"
    REFUNDED = "REFUNDED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    DISPUTED = "DISPUTED"


_ALLOWED_TRANSITIONS: dict[
    PurchaseOperationState,
    frozenset[PurchaseOperationState],
] = {
    PurchaseOperationState.ARTIFACT_READY: frozenset(
        {
            PurchaseOperationState.SOFT_HELD,
            PurchaseOperationState.CANCELED,
        }
    ),
    PurchaseOperationState.SOFT_HELD: frozenset(
        {
            PurchaseOperationState.RESERVING,
            PurchaseOperationState.CANCELED,
        }
    ),
    PurchaseOperationState.RESERVING: frozenset(
        {
            PurchaseOperationState.RESERVATION_MEMPOOL,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.CANCELED,
        }
    ),
    PurchaseOperationState.RESERVATION_MEMPOOL: frozenset(
        {
            PurchaseOperationState.RESERVED,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.CANCELED,
        }
    ),
    PurchaseOperationState.RESERVED: frozenset(
        {
            PurchaseOperationState.PAYMENT_METHOD_READY,
            PurchaseOperationState.PAYMENT_PROCESSING,
            PurchaseOperationState.PAYMENT_SUCCEEDED,
            PurchaseOperationState.CANCELED,
            PurchaseOperationState.REVIEW_REQUIRED,
        }
    ),
    PurchaseOperationState.PAYMENT_METHOD_READY: frozenset(
        {
            PurchaseOperationState.PAYMENT_PROCESSING,
            PurchaseOperationState.PAYMENT_SUCCEEDED,
            PurchaseOperationState.PAYMENT_FAILED,
            PurchaseOperationState.CANCELED,
        }
    ),
    PurchaseOperationState.PAYMENT_PROCESSING: frozenset(
        {
            PurchaseOperationState.PAYMENT_SUCCEEDED,
            PurchaseOperationState.PAYMENT_FAILED,
            PurchaseOperationState.REVIEW_REQUIRED,
        }
    ),
    PurchaseOperationState.PAYMENT_SUCCEEDED: frozenset(
        {
            PurchaseOperationState.VOUCHER_PENDING,
            PurchaseOperationState.RECEIPT_MEMPOOL,
            PurchaseOperationState.REFUND_PENDING,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.VOUCHER_PENDING: frozenset(
        {
            PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
            PurchaseOperationState.VOUCHER_ESCROWED,
            PurchaseOperationState.REFUND_PENDING,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL: frozenset(
        {
            PurchaseOperationState.VOUCHER_ESCROWED,
            PurchaseOperationState.REFUND_PENDING,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.VOUCHER_ESCROWED: frozenset(
        {
            PurchaseOperationState.DELIVERY_SUBMITTED,
            PurchaseOperationState.REFUND_PENDING,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.RECEIPT_MEMPOOL: frozenset(
        {
            PurchaseOperationState.RECEIPT_READY,
            PurchaseOperationState.REFUND_PENDING,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.RECEIPT_READY: frozenset(
        {
            PurchaseOperationState.DELIVERY_SUBMITTED,
            PurchaseOperationState.REFUND_PENDING,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.DELIVERY_SUBMITTED: frozenset(
        {
            PurchaseOperationState.MEMPOOL_OBSERVED,
            PurchaseOperationState.CHAIN_CONFIRMED,
            PurchaseOperationState.REFUND_PENDING,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.MEMPOOL_OBSERVED: frozenset(
        {
            PurchaseOperationState.CHAIN_CONFIRMED,
            PurchaseOperationState.REVIEW_REQUIRED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.CHAIN_CONFIRMED: frozenset(
        {
            PurchaseOperationState.FINALIZED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.FINALIZED: frozenset(
        {PurchaseOperationState.DISPUTED}
    ),
    PurchaseOperationState.PAYMENT_FAILED: frozenset(
        {
            PurchaseOperationState.CANCELED,
            PurchaseOperationState.REFUND_PENDING,
            PurchaseOperationState.REVIEW_REQUIRED,
        }
    ),
    PurchaseOperationState.CANCELED: frozenset(),
    PurchaseOperationState.REFUND_PENDING: frozenset(
        {
            PurchaseOperationState.REFUNDED,
            PurchaseOperationState.REVIEW_REQUIRED,
        }
    ),
    PurchaseOperationState.REFUNDED: frozenset(),
    PurchaseOperationState.REVIEW_REQUIRED: frozenset(
        {
            PurchaseOperationState.RESERVING,
            PurchaseOperationState.DELIVERY_SUBMITTED,
            PurchaseOperationState.REFUND_PENDING,
            PurchaseOperationState.CANCELED,
            PurchaseOperationState.DISPUTED,
        }
    ),
    PurchaseOperationState.DISPUTED: frozenset(
        {PurchaseOperationState.REVIEW_REQUIRED}
    ),
}

_LOCK_TERMINAL_STATES = frozenset(
    {
        PurchaseOperationState.CANCELED,
        PurchaseOperationState.REFUNDED,
        PurchaseOperationState.FINALIZED,
    }
)

_BIND_ONCE_FIELDS = frozenset(
    {
        "reservation_coin_id",
        "reservation_bundle_id",
        "receipt_coin_id",
        "receipt_bundle_id",
        "payment_intent_id",
        "payment_method_ready_at",
        "stripe_event_id",
        "receipt_hash",
        "delivery_bundle_id",
        "expected_output_coin_id",
        "inventory_release_bundle_id",
        "inventory_release_output_coin_id",
        "refund_request_hash",
        "refund_id",
        "dispute_id",
    }
)


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


@dataclass(frozen=True)
class StoredPurchaseOperation:
    purchase_id: str
    revision: int
    state: PurchaseOperationState
    purchase_kind: str
    presale_terms_hash: str
    customer_subject: str
    rail: str
    deed_launcher_id: str
    approved_vault_launcher_id: str
    approved_vault_puzzle_hash: str
    zkpassport_root: str
    base_amount_minor: int
    technology_fee_minor: int
    processing_charge_minor: int
    total_amount_minor: int
    soft_hold_expires_at: int | None
    reservation_coin_id: str | None
    reservation_bundle_id: str | None
    reservation_expires_at: int | None
    reservation_parent_expires_at: int | None
    reservation_confirmation_height: int | None
    payment_intent_id: str | None
    payment_method_family: str | None
    funding_type: str | None
    payment_method_ready_at: int | None
    stripe_event_id: str | None
    receipt_hash: str | None
    receipt_coin_id: str | None
    receipt_bundle_id: str | None
    receipt_confirmation_height: int | None
    delivery_bundle_id: str | None
    expected_output_coin_id: str | None
    fee_mojos: int | None
    mempool_observed_at: int | None
    confirmation_height: int | None
    inventory_release_bundle_id: str | None
    inventory_release_output_coin_id: str | None
    inventory_release_confirmation_height: int | None
    refund_request_hash: str | None
    refund_requested_at: int | None
    refund_id: str | None
    refunded_minor: int
    dispute_id: str | None
    dispute_status: str | None
    dispute_event_id: str | None
    dispute_resolution: str | None
    dispute_resolved_at: int | None
    dispute_resolution_operation_id: str | None
    lease_owner: str | None
    lease_expires_at: int | None
    last_error: str | None
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class StoredChainExecution:
    purchase_id: str
    action: str
    claim_hash: str
    spend_bundle_id: str
    required_input_coin_ids: tuple[str, ...]
    expected_output_coin_id: str
    expected_output_puzzle_hash: str
    fee_mojos: int
    spend_bundle: dict[str, Any]
    created_at: int


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

                CREATE TABLE IF NOT EXISTS purchase_operations_v1 (
                    purchase_id TEXT PRIMARY KEY
                        REFERENCES payment_purchases(purchase_id),
                    revision INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    purchase_kind TEXT NOT NULL,
                    presale_terms_hash TEXT NOT NULL
                        DEFAULT '0x0000000000000000000000000000000000000000000000000000000000000000',
                    customer_subject TEXT NOT NULL,
                    rail TEXT NOT NULL,
                    deed_launcher_id TEXT NOT NULL,
                    approved_vault_launcher_id TEXT NOT NULL,
                    approved_vault_puzzle_hash TEXT NOT NULL,
                    zkpassport_root TEXT NOT NULL,
                    base_amount_minor INTEGER NOT NULL,
                    technology_fee_minor INTEGER NOT NULL,
                    processing_charge_minor INTEGER NOT NULL DEFAULT 0,
                    total_amount_minor INTEGER NOT NULL,
                    soft_hold_expires_at INTEGER,
                    reservation_coin_id TEXT UNIQUE,
                    reservation_bundle_id TEXT UNIQUE,
                    reservation_expires_at INTEGER,
                    reservation_parent_expires_at INTEGER,
                    reservation_confirmation_height INTEGER,
                    payment_intent_id TEXT UNIQUE,
                    payment_method_family TEXT,
                    funding_type TEXT,
                    payment_method_ready_at INTEGER,
                    stripe_event_id TEXT UNIQUE,
                    receipt_hash TEXT UNIQUE,
                    receipt_coin_id TEXT UNIQUE,
                    receipt_bundle_id TEXT UNIQUE,
                    receipt_confirmation_height INTEGER,
                    delivery_bundle_id TEXT UNIQUE,
                    expected_output_coin_id TEXT UNIQUE,
                    fee_mojos INTEGER,
                    mempool_observed_at INTEGER,
                    confirmation_height INTEGER,
                    inventory_release_bundle_id TEXT UNIQUE,
                    inventory_release_output_coin_id TEXT UNIQUE,
                    inventory_release_confirmation_height INTEGER,
                    refund_request_hash TEXT UNIQUE,
                    refund_requested_at INTEGER,
                    refund_id TEXT UNIQUE,
                    refunded_minor INTEGER NOT NULL DEFAULT 0,
                    dispute_id TEXT UNIQUE,
                    dispute_status TEXT,
                    dispute_event_id TEXT UNIQUE,
                    dispute_resolution TEXT,
                    dispute_resolved_at INTEGER,
                    dispute_resolution_operation_id TEXT UNIQUE,
                    lease_owner TEXT,
                    lease_expires_at INTEGER,
                    last_error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS purchase_operations_state
                    ON purchase_operations_v1(state, updated_at);
                CREATE INDEX IF NOT EXISTS purchase_operations_deed
                    ON purchase_operations_v1(deed_launcher_id, state);

                CREATE TABLE IF NOT EXISTS purchase_deed_locks_v1 (
                    deed_launcher_id TEXT PRIMARY KEY,
                    purchase_id TEXT NOT NULL UNIQUE
                        REFERENCES purchase_operations_v1(purchase_id),
                    expires_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS purchase_stripe_events_v1 (
                    event_id TEXT PRIMARY KEY,
                    purchase_id TEXT NOT NULL
                        REFERENCES purchase_operations_v1(purchase_id),
                    event_type TEXT NOT NULL,
                    payment_intent_id TEXT,
                    payload_sha256 TEXT NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    created_at INTEGER NOT NULL,
                    received_at INTEGER NOT NULL,
                    processed_at INTEGER,
                    processing_error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS purchase_stripe_events_purchase
                    ON purchase_stripe_events_v1(purchase_id, created_at);

                CREATE TABLE IF NOT EXISTS purchase_settlement_receipts_v1 (
                    purchase_id TEXT PRIMARY KEY
                        REFERENCES purchase_operations_v1(purchase_id),
                    receipt_hash TEXT NOT NULL UNIQUE,
                    pending_attestation_json TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS purchase_operation_history_v1 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    purchase_id TEXT NOT NULL
                        REFERENCES purchase_operations_v1(purchase_id),
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT,
                    evidence_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS purchase_operation_history_purchase
                    ON purchase_operation_history_v1(purchase_id, id);

                CREATE TABLE IF NOT EXISTS purchase_chain_executions_v1 (
                    purchase_id TEXT NOT NULL
                        REFERENCES purchase_operations_v1(purchase_id),
                    action TEXT NOT NULL,
                    claim_hash TEXT NOT NULL UNIQUE,
                    spend_bundle_id TEXT NOT NULL UNIQUE,
                    required_input_coin_ids_json TEXT NOT NULL,
                    expected_output_coin_id TEXT NOT NULL UNIQUE,
                    expected_output_puzzle_hash TEXT NOT NULL,
                    fee_mojos INTEGER NOT NULL,
                    spend_bundle_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (purchase_id, action),
                    CHECK (
                        action IN (
                            'RESERVE', 'DELIVER', 'RELEASE',
                            'RECEIPT', 'EXTEND_PROCESSING',
                            'EXTEND_SETTLEMENT', 'VOUCHER_TERMINAL'
                        )
                    ),
                    CHECK (fee_mojos >= 0)
                );
                """
            )
            chain_table = connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type='table' AND name='purchase_chain_executions_v1'"
            ).fetchone()
            chain_sql = str(chain_table[0] or "") if chain_table else ""
            if chain_sql and "VOUCHER_TERMINAL" not in chain_sql:
                connection.executescript(
                    """
                    ALTER TABLE purchase_chain_executions_v1
                        RENAME TO purchase_chain_executions_v1_legacy;
                    CREATE TABLE purchase_chain_executions_v1 (
                        purchase_id TEXT NOT NULL
                            REFERENCES purchase_operations_v1(purchase_id),
                        action TEXT NOT NULL,
                        claim_hash TEXT NOT NULL UNIQUE,
                        spend_bundle_id TEXT NOT NULL UNIQUE,
                        required_input_coin_ids_json TEXT NOT NULL,
                        expected_output_coin_id TEXT NOT NULL UNIQUE,
                        expected_output_puzzle_hash TEXT NOT NULL,
                        fee_mojos INTEGER NOT NULL,
                        spend_bundle_json TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        PRIMARY KEY (purchase_id, action),
                        CHECK (
                            action IN (
                                'RESERVE', 'DELIVER', 'RELEASE', 'RECEIPT',
                                'EXTEND_PROCESSING', 'EXTEND_SETTLEMENT',
                                'VOUCHER_TERMINAL'
                            )
                        ),
                        CHECK (fee_mojos >= 0)
                    );
                    INSERT INTO purchase_chain_executions_v1(
                        purchase_id, action, claim_hash, spend_bundle_id,
                        required_input_coin_ids_json, expected_output_coin_id,
                        expected_output_puzzle_hash, fee_mojos,
                        spend_bundle_json, created_at
                    )
                    SELECT purchase_id,
                           CASE action
                               WHEN 'EXTEND' THEN 'EXTEND_PROCESSING'
                               ELSE action
                           END,
                           claim_hash, spend_bundle_id,
                           required_input_coin_ids_json,
                           expected_output_coin_id,
                           expected_output_puzzle_hash, fee_mojos,
                           spend_bundle_json, created_at
                    FROM purchase_chain_executions_v1_legacy;
                    DROP TABLE purchase_chain_executions_v1_legacy;
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
            stripe_event_columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(purchase_stripe_events_v1)"
                ).fetchall()
            }
            stripe_event_additions = {
                "evidence_json": "TEXT NOT NULL DEFAULT '{}'",
                "processed_at": "INTEGER",
                "processing_error": "TEXT",
                "attempts": "INTEGER NOT NULL DEFAULT 0",
            }
            for column, declaration in stripe_event_additions.items():
                if column not in stripe_event_columns:
                    connection.execute(
                        "ALTER TABLE purchase_stripe_events_v1 "
                        f"ADD COLUMN {column} {declaration}"
                    )
            operation_columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(purchase_operations_v1)"
                ).fetchall()
            }
            operation_additions = {
                "presale_terms_hash": (
                    "TEXT NOT NULL DEFAULT "
                    "'0x0000000000000000000000000000000000000000000000000000000000000000'"
                ),
                "reservation_confirmation_height": "INTEGER",
                "reservation_parent_expires_at": "INTEGER",
                "payment_method_ready_at": "INTEGER",
                "receipt_coin_id": "TEXT",
                "receipt_bundle_id": "TEXT",
                "receipt_confirmation_height": "INTEGER",
                "inventory_release_bundle_id": "TEXT",
                "inventory_release_output_coin_id": "TEXT",
                "inventory_release_confirmation_height": "INTEGER",
                "refund_request_hash": "TEXT",
                "refund_requested_at": "INTEGER",
                "dispute_status": "TEXT",
                "dispute_event_id": "TEXT",
                "dispute_resolution": "TEXT",
                "dispute_resolved_at": "INTEGER",
                "dispute_resolution_operation_id": "TEXT",
            }
            for column, declaration in operation_additions.items():
                if column not in operation_columns:
                    connection.execute(
                        "ALTER TABLE purchase_operations_v1 "
                        f"ADD COLUMN {column} {declaration}"
                    )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "purchase_operations_receipt_coin "
                "ON purchase_operations_v1(receipt_coin_id)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "purchase_operations_receipt_bundle "
                "ON purchase_operations_v1(receipt_bundle_id)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "purchase_operations_inventory_release_bundle "
                "ON purchase_operations_v1(inventory_release_bundle_id)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "purchase_operations_inventory_release_output "
                "ON purchase_operations_v1(inventory_release_output_coin_id)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "purchase_operations_refund_request "
                "ON purchase_operations_v1(refund_request_hash)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "purchase_operations_dispute_event "
                "ON purchase_operations_v1(dispute_event_id)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "purchase_operations_dispute_resolution_operation "
                "ON purchase_operations_v1(dispute_resolution_operation_id)"
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
        quote_expires_at = _required_decimal_int(
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
                self._ensure_operation(
                    connection,
                    purchase_id=purchase_id,
                    purchase_intent_id=purchase_intent_id,
                    rail=rail,
                    offer_artifact=offer_artifact,
                    purchase_artifact=purchase_artifact,
                    created_at=created_at,
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
            self._ensure_operation(
                connection,
                purchase_id=purchase_id,
                purchase_intent_id=purchase_intent_id,
                rail=rail,
                offer_artifact=offer_artifact,
                purchase_artifact=purchase_artifact,
                created_at=created_at,
            )
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)

    @staticmethod
    def _ensure_operation(
        connection: sqlite3.Connection,
        *,
        purchase_id: str,
        purchase_intent_id: str,
        rail: str,
        offer_artifact: Mapping[str, Any],
        purchase_artifact: Mapping[str, Any],
        created_at: int,
    ) -> None:
        if purchase_artifact.get("schema") != "solslot.purchase-artifact.v3":
            # Historical test and read-only records remain readable. Fresh RC24
            # writes always carry the strict V3 schema and receive an operation.
            return
        existing = connection.execute(
            "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
            (purchase_id,),
        ).fetchone()
        protocol = _required_mapping(offer_artifact, "protocol")
        customer_subject = str(
            protocol.get("vaultLauncherId")
            or protocol.get("customerSubject")
            or purchase_intent_id
        )
        purchase_kind_value = _required_int(purchase_artifact, "purchaseKind")
        purchase_kind = {1: "DIRECT", 2: "PRESALE"}.get(purchase_kind_value)
        if purchase_kind is None:
            raise PaymentPurchaseConflict("purchaseKind is unsupported")
        presale_terms_hash = _require_bytes32(
            _required_string(purchase_artifact, "presaleTermsHash"),
            "presaleTermsHash",
        )
        if (
            purchase_kind == "DIRECT"
            and presale_terms_hash != _ZERO_BYTES32
        ) or (
            purchase_kind == "PRESALE"
            and presale_terms_hash == _ZERO_BYTES32
        ):
            raise PaymentPurchaseConflict(
                "purchase kind and presale terms commitment disagree"
            )
        outer_purchase_kind = str(protocol.get("purchaseKind") or "").upper()
        if outer_purchase_kind != purchase_kind:
            raise PaymentPurchaseConflict(
                "offer purchase kind does not match its canonical artifact"
            )
        if str(protocol.get("presaleTermsHash") or "").lower() != presale_terms_hash:
            raise PaymentPurchaseConflict(
                "offer presale terms do not match its canonical artifact"
            )
        values = {
            "purchase_kind": purchase_kind,
            "presale_terms_hash": presale_terms_hash,
            "customer_subject": customer_subject,
            "rail": rail,
            "deed_launcher_id": _required_string(
                purchase_artifact, "deedLauncherId"
            ).lower(),
            "approved_vault_launcher_id": _required_string(
                purchase_artifact, "vaultLauncherId"
            ).lower(),
            "approved_vault_puzzle_hash": _required_string(
                purchase_artifact, "vaultP2PuzzleHash"
            ).lower(),
            "zkpassport_root": _required_string(
                purchase_artifact, "zkPassportRoot"
            ).lower(),
            "base_amount_minor": _required_decimal_int(
                purchase_artifact, "baseAmountMinor"
            ),
            "technology_fee_minor": _required_decimal_int(
                purchase_artifact, "technologyFeeMinor"
            ),
            "total_amount_minor": _required_decimal_int(
                purchase_artifact, "subtotalMinor"
            ),
        }
        if (
            values["total_amount_minor"]
            != values["base_amount_minor"]
            + values["technology_fee_minor"]
        ):
            raise PaymentPurchaseConflict(
                "purchase subtotal must equal base and technology fee"
            )
        if (
            values["base_amount_minor"] <= 0
            or values["technology_fee_minor"] < 0
        ):
            raise PaymentPurchaseConflict(
                "purchase amounts must be non-negative with a positive base"
            )
        for field in (
            "deed_launcher_id",
            "approved_vault_launcher_id",
            "approved_vault_puzzle_hash",
            "zkpassport_root",
        ):
            _require_bytes32(values[field], field)
        if existing is not None:
            for field, expected in values.items():
                if existing[field] != expected:
                    raise PaymentPurchaseConflict(
                        f"purchase operation {field} is immutable"
                    )
            return
        connection.execute(
            """
            INSERT INTO purchase_operations_v1(
                purchase_id, revision, state, purchase_kind,
                presale_terms_hash,
                customer_subject, rail, deed_launcher_id,
                approved_vault_launcher_id, approved_vault_puzzle_hash,
                zkpassport_root, base_amount_minor,
                technology_fee_minor, processing_charge_minor,
                total_amount_minor, refunded_minor, created_at, updated_at
            ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?)
            """,
            (
                purchase_id,
                PurchaseOperationState.ARTIFACT_READY.value,
                values["purchase_kind"],
                values["presale_terms_hash"],
                values["customer_subject"],
                values["rail"],
                values["deed_launcher_id"],
                values["approved_vault_launcher_id"],
                values["approved_vault_puzzle_hash"],
                values["zkpassport_root"],
                values["base_amount_minor"],
                values["technology_fee_minor"],
                values["total_amount_minor"],
                created_at,
                created_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO purchase_operation_history_v1(
                purchase_id, from_state, to_state, revision, actor,
                reason, evidence_json, created_at
            ) VALUES (?, NULL, ?, 1, 'coordinator', 'artifact sealed', '{}', ?)
            """,
            (
                purchase_id,
                PurchaseOperationState.ARTIFACT_READY.value,
                created_at,
            ),
        )

    def get(self, purchase_id: str) -> StoredPaymentPurchase:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
        if row is None:
            raise PaymentPurchaseNotFound("purchase artifact was not found")
        return _record(row)

    def get_by_purchase_intent_id(
        self,
        purchase_intent_id: str,
    ) -> StoredPaymentPurchase:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_intent_id=?",
                (purchase_intent_id,),
            ).fetchone()
        if row is None:
            raise PaymentPurchaseNotFound("purchase artifact was not found")
        return _record(row)

    def get_operation(self, purchase_id: str) -> StoredPurchaseOperation:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
        if row is None:
            raise PaymentPurchaseNotFound("purchase operation was not found")
        return _operation_record(row)

    def get_stripe_dispute_for_deed(
        self,
        deed_launcher_id: str,
    ) -> StoredPurchaseOperation | None:
        normalized_deed = _require_bytes32(
            deed_launcher_id,
            "deed_launcher_id",
        )
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM purchase_operations_v1
                WHERE rail='stripe'
                  AND deed_launcher_id=?
                  AND dispute_id IS NOT NULL
                  AND dispute_resolved_at IS NULL
                ORDER BY updated_at DESC, purchase_id DESC
                LIMIT 1
                """,
                (normalized_deed,),
            ).fetchone()
        return None if row is None else _operation_record(row)

    def record_stripe_dispute_update(
        self,
        purchase_id: str,
        *,
        expected_revision: int,
        dispute_id: str,
        dispute_status: str,
        dispute_event_id: str,
        event_type: str,
        evidence: Mapping[str, Any],
        now: int | None = None,
    ) -> StoredPurchaseOperation:
        timestamp = int(time.time()) if now is None else now
        _require_short_text(dispute_id, "dispute_id")
        _require_short_text(dispute_event_id, "dispute_event_id")
        _require_short_text(event_type, "event_type")
        normalized_status = _require_stripe_dispute_status(dispute_status)
        if not event_type.startswith("charge.dispute."):
            raise PaymentPurchaseConflict(
                "Stripe dispute update requires a dispute event"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            operation = _operation_record(row)
            if operation.revision != expected_revision:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase operation revision changed"
                )
            if operation.rail.lower() != "stripe":
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "dispute evidence can bind only a Stripe purchase"
                )
            if operation.dispute_id != dispute_id:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "Stripe dispute differs from the recorded incident"
                )
            if operation.dispute_resolved_at is not None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "resolved Stripe dispute evidence is immutable"
                )
            revision = operation.revision + 1
            try:
                connection.execute(
                    """
                    UPDATE purchase_operations_v1
                    SET dispute_status=?, dispute_event_id=?, revision=?,
                        updated_at=?
                    WHERE purchase_id=?
                    """,
                    (
                        normalized_status,
                        dispute_event_id,
                        revision,
                        timestamp,
                        purchase_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "Stripe dispute event is already bound elsewhere"
                ) from exc
            connection.execute(
                """
                INSERT INTO purchase_operation_history_v1(
                    purchase_id, from_state, to_state, revision, actor,
                    reason, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, 'stripe-webhook', ?, ?, ?)
                """,
                (
                    purchase_id,
                    operation.state.value,
                    operation.state.value,
                    revision,
                    f"Stripe dispute status changed to {normalized_status}",
                    _canonical_json(dict(evidence)),
                    timestamp,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert updated is not None
        return _operation_record(updated)

    def reopen_for_new_stripe_dispute(
        self,
        purchase_id: str,
        *,
        expected_revision: int,
        dispute_id: str,
        dispute_status: str,
        dispute_event_id: str,
        event_type: str,
        evidence: Mapping[str, Any],
        now: int | None = None,
    ) -> StoredPurchaseOperation:
        """Open a distinct Stripe dispute after an earlier one was resolved."""

        timestamp = int(time.time()) if now is None else now
        _require_short_text(dispute_id, "dispute_id")
        _require_short_text(dispute_event_id, "dispute_event_id")
        _require_short_text(event_type, "event_type")
        normalized_status = _require_stripe_dispute_status(dispute_status)
        if not event_type.startswith("charge.dispute."):
            raise PaymentPurchaseConflict(
                "Stripe dispute update requires a dispute event"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            operation = _operation_record(row)
            if operation.revision != expected_revision:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase operation revision changed"
                )
            if operation.rail.lower() != "stripe":
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "dispute evidence can bind only a Stripe purchase"
                )
            if operation.dispute_id is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase has no prior Stripe dispute"
                )
            if operation.dispute_id == dispute_id:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "Stripe dispute is not a new incident"
                )
            if operation.dispute_resolved_at is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "the prior Stripe dispute is still unresolved"
                )
            if operation.state != PurchaseOperationState.FINALIZED:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "a new post-delivery dispute requires finalized delivery"
                )
            revision = operation.revision + 1
            try:
                connection.execute(
                    """
                    UPDATE purchase_operations_v1
                    SET state=?, dispute_id=?, dispute_status=?,
                        dispute_event_id=?, dispute_resolution=NULL,
                        dispute_resolved_at=NULL,
                        dispute_resolution_operation_id=NULL,
                        revision=?, updated_at=?,
                        last_error='Stripe dispute requires owner-plus-one review'
                    WHERE purchase_id=?
                    """,
                    (
                        PurchaseOperationState.DISPUTED.value,
                        dispute_id,
                        normalized_status,
                        dispute_event_id,
                        revision,
                        timestamp,
                        purchase_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "Stripe dispute evidence is already bound elsewhere"
                ) from exc
            connection.execute(
                """
                INSERT INTO purchase_operation_history_v1(
                    purchase_id, from_state, to_state, revision, actor,
                    reason, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, 'stripe-webhook', ?, ?, ?)
                """,
                (
                    purchase_id,
                    operation.state.value,
                    PurchaseOperationState.DISPUTED.value,
                    revision,
                    "Stripe opened a new dispute after a prior resolution",
                    _canonical_json(
                        {
                            "priorDisputeId": operation.dispute_id,
                            "priorResolution": operation.dispute_resolution,
                            "stripe": dict(evidence.get("stripe", evidence)),
                        }
                    ),
                    timestamp,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert updated is not None
        return _operation_record(updated)

    def resolve_post_delivery_stripe_dispute(
        self,
        purchase_id: str,
        *,
        expected_revision: int,
        resolution: str,
        admin_operation_id: str,
        actor: str,
        now: int | None = None,
    ) -> StoredPurchaseOperation:
        timestamp = int(time.time()) if now is None else now
        normalized_resolution = resolution.strip().upper()
        if normalized_resolution not in {
            "RESTORE_AFTER_WIN",
            "ACCEPT_LOSS_AND_RESTORE",
        }:
            raise PaymentPurchaseConflict(
                "Stripe dispute resolution is unsupported"
            )
        _require_bytes32(admin_operation_id, "admin_operation_id")
        _require_short_text(actor, "actor")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            operation = _operation_record(row)
            if operation.revision != expected_revision:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase operation revision changed"
                )
            if operation.rail.lower() != "stripe":
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "dispute resolution can bind only a Stripe purchase"
                )
            if operation.dispute_id is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase has no Stripe dispute"
                )
            if operation.dispute_resolved_at is not None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "Stripe dispute is already resolved"
                )
            if (
                operation.confirmation_height is None
                or operation.expected_output_coin_id is None
            ):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "only a confirmed post-delivery dispute can be resolved"
                )
            event = connection.execute(
                "SELECT event_type FROM purchase_stripe_events_v1 "
                "WHERE event_id=? AND purchase_id=? AND processed_at IS NOT NULL",
                (operation.dispute_event_id, purchase_id),
            ).fetchone()
            if event is None or event["event_type"] != "charge.dispute.closed":
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "Stripe dispute has no final closed webhook evidence"
                )
            status_value = _require_stripe_dispute_status(
                operation.dispute_status
            )
            if (
                normalized_resolution == "RESTORE_AFTER_WIN"
                and status_value not in {"won", "warning_closed"}
            ):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "Stripe has not closed this dispute in Solslot's favor"
                )
            if (
                normalized_resolution == "ACCEPT_LOSS_AND_RESTORE"
                and status_value != "lost"
            ):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "loss acceptance requires Stripe status lost"
                )
            revision = operation.revision + 1
            try:
                connection.execute(
                    """
                    UPDATE purchase_operations_v1
                    SET state=?, revision=?, dispute_resolution=?,
                        dispute_resolved_at=?,
                        dispute_resolution_operation_id=?, updated_at=?,
                        last_error=NULL
                    WHERE purchase_id=?
                    """,
                    (
                        PurchaseOperationState.FINALIZED.value,
                        revision,
                        normalized_resolution,
                        timestamp,
                        admin_operation_id.lower(),
                        timestamp,
                        purchase_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "admin dispute resolution is already bound elsewhere"
                ) from exc
            connection.execute(
                """
                INSERT INTO purchase_operation_history_v1(
                    purchase_id, from_state, to_state, revision, actor,
                    reason, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    purchase_id,
                    operation.state.value,
                    PurchaseOperationState.FINALIZED.value,
                    revision,
                    actor[:128],
                    "owner-plus-one resolved the final Stripe dispute",
                    _canonical_json(
                        {
                            "adminOperationId": admin_operation_id.lower(),
                            "disputeId": operation.dispute_id,
                            "disputeStatus": status_value,
                            "resolution": normalized_resolution,
                        }
                    ),
                    timestamp,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert updated is not None
        return _operation_record(updated)

    def save_chain_execution(
        self,
        purchase_id: str,
        *,
        action: str,
        claim_hash: str,
        spend_bundle_id: str,
        required_input_coin_ids: list[str] | tuple[str, ...],
        expected_output_coin_id: str,
        expected_output_puzzle_hash: str,
        fee_mojos: int,
        spend_bundle: Mapping[str, Any],
        created_at: int | None = None,
    ) -> StoredChainExecution:
        timestamp = int(time.time()) if created_at is None else created_at
        normalized_action = action.strip().upper()
        if normalized_action not in {
            "RESERVE",
            "DELIVER",
            "RELEASE",
            "RECEIPT",
            "EXTEND_PROCESSING",
            "EXTEND_SETTLEMENT",
            "VOUCHER_TERMINAL",
        }:
            raise PaymentPurchaseConflict(
                "chain execution action is unsupported"
            )
        normalized_claim = _require_bytes32(claim_hash, "claim_hash")
        normalized_bundle = _require_bytes32(
            spend_bundle_id,
            "spend_bundle_id",
        )
        normalized_output = _require_bytes32(
            expected_output_coin_id,
            "expected_output_coin_id",
        )
        normalized_output_puzzle = _require_bytes32(
            expected_output_puzzle_hash,
            "expected_output_puzzle_hash",
        )
        inputs = tuple(
            _require_bytes32(value, "required_input_coin_id")
            for value in required_input_coin_ids
        )
        if not inputs or len(inputs) > 100 or len(set(inputs)) != len(inputs):
            raise PaymentPurchaseConflict(
                "chain execution requires 1..100 unique input coins"
            )
        inputs = tuple(sorted(inputs))
        normalized_fee = _nonnegative_int(fee_mojos, "fee_mojos")
        bundle_json = _canonical_json(spend_bundle)
        if len(bundle_json.encode("utf-8")) > 2_000_000:
            raise PaymentPurchaseConflict(
                "chain execution spend bundle exceeds two megabytes"
            )
        inputs_json = json.dumps(
            inputs,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                "SELECT purchase_id FROM purchase_operations_v1 "
                "WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if operation is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            try:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO purchase_chain_executions_v1(
                        purchase_id, action, claim_hash, spend_bundle_id,
                        required_input_coin_ids_json,
                        expected_output_coin_id,
                        expected_output_puzzle_hash, fee_mojos,
                        spend_bundle_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        purchase_id,
                        normalized_action,
                        normalized_claim,
                        normalized_bundle,
                        inputs_json,
                        normalized_output,
                        normalized_output_puzzle,
                        normalized_fee,
                        bundle_json,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "chain execution evidence is already bound elsewhere"
                ) from exc
            row = connection.execute(
                "SELECT * FROM purchase_chain_executions_v1 "
                "WHERE purchase_id=? AND action=?",
                (purchase_id, normalized_action),
            ).fetchone()
            assert row is not None
            existing = _chain_execution_record(row)
            expected = (
                normalized_claim,
                normalized_bundle,
                inputs,
                normalized_output,
                normalized_output_puzzle,
                normalized_fee,
                bundle_json,
            )
            observed = (
                existing.claim_hash,
                existing.spend_bundle_id,
                existing.required_input_coin_ids,
                existing.expected_output_coin_id,
                existing.expected_output_puzzle_hash,
                existing.fee_mojos,
                _canonical_json(existing.spend_bundle),
            )
            if observed != expected:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase action is bound to another chain execution"
                )
            connection.execute("COMMIT")
            return existing

    def get_chain_execution(
        self,
        purchase_id: str,
        action: str,
    ) -> StoredChainExecution:
        normalized_action = action.strip().upper()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM purchase_chain_executions_v1 "
                "WHERE purchase_id=? AND action=?",
                (purchase_id, normalized_action),
            ).fetchone()
        if row is None:
            raise PaymentPurchaseNotFound(
                "chain execution was not found"
            )
        return _chain_execution_record(row)

    def list_operations(
        self,
        *,
        customer_subject: str | None = None,
        rail: str | None = None,
        states: tuple[PurchaseOperationState, ...] = (),
        limit: int = 100,
    ) -> list[StoredPurchaseOperation]:
        if limit < 1 or limit > 500:
            raise PaymentPurchaseConflict("operation limit must be 1..500")
        clauses: list[str] = []
        parameters: list[Any] = []
        if customer_subject is not None:
            clauses.append("customer_subject=?")
            parameters.append(customer_subject)
        if rail is not None:
            normalized_rail = rail.strip().lower()
            if normalized_rail not in {"stripe", "base_usdc"}:
                raise PaymentPurchaseConflict("operation rail is invalid")
            clauses.append("LOWER(rail)=?")
            parameters.append(normalized_rail)
        if states:
            clauses.append(
                "state IN (" + ",".join("?" for _ in states) + ")"
            )
            parameters.extend(state.value for state in states)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM purchase_operations_v1"
                + where
                + " ORDER BY updated_at DESC LIMIT ?",
                parameters,
            ).fetchall()
        return [_operation_record(row) for row in rows]

    def operation_history(
        self,
        purchase_id: str,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise PaymentPurchaseConflict("history limit must be 1..500")
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone() is None:
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            rows = connection.execute(
                "SELECT from_state,to_state,revision,actor,reason,"
                "evidence_json,created_at "
                "FROM purchase_operation_history_v1 WHERE purchase_id=? "
                "ORDER BY id DESC LIMIT ?",
                (purchase_id, limit),
            ).fetchall()
        return [
            {
                "fromState": row["from_state"],
                "toState": row["to_state"],
                "revision": int(row["revision"]),
                "actor": row["actor"],
                "reason": row["reason"],
                "evidence": json.loads(row["evidence_json"]),
                "createdAt": int(row["created_at"]),
            }
            for row in rows
        ]

    def begin_soft_hold(
        self,
        purchase_id: str,
        *,
        expected_revision: int,
        expires_at: int,
        actor: str,
        now: int | None = None,
    ) -> StoredPurchaseOperation:
        timestamp = int(time.time()) if now is None else now
        if expires_at <= timestamp or expires_at > timestamp + 15 * 60:
            raise PaymentPurchaseConflict(
                "soft hold must expire within fifteen minutes"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            operation = _operation_record(row)
            if operation.revision != expected_revision:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase operation revision changed"
                )
            if operation.state != PurchaseOperationState.ARTIFACT_READY:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase operation is not ready for a soft hold"
                )
            stale = connection.execute(
                """
                SELECT purchase_id, expires_at FROM purchase_deed_locks_v1
                WHERE deed_launcher_id=?
                """,
                (operation.deed_launcher_id,),
            ).fetchone()
            if stale is not None and int(stale["expires_at"]) <= timestamp:
                stale_operation = connection.execute(
                    """
                    SELECT state, revision FROM purchase_operations_v1
                    WHERE purchase_id=?
                    """,
                    (stale["purchase_id"],),
                ).fetchone()
                if (
                    stale_operation is not None
                    and PurchaseOperationState(stale_operation["state"])
                    in {
                        PurchaseOperationState.SOFT_HELD,
                        PurchaseOperationState.ARTIFACT_READY,
                    }
                ):
                    connection.execute(
                        """
                        UPDATE purchase_operations_v1
                        SET state=?, revision=revision+1,
                            last_error='soft hold expired', updated_at=?
                        WHERE purchase_id=?
                        """,
                        (
                            PurchaseOperationState.CANCELED.value,
                            timestamp,
                            stale["purchase_id"],
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO purchase_operation_history_v1(
                            purchase_id, from_state, to_state, revision,
                            actor, reason, evidence_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, '{}', ?)
                        """,
                        (
                            stale["purchase_id"],
                            stale_operation["state"],
                            PurchaseOperationState.CANCELED.value,
                            int(stale_operation["revision"]) + 1,
                            "coordinator",
                            "soft hold expired",
                            timestamp,
                        ),
                    )
                    connection.execute(
                        "DELETE FROM purchase_deed_locks_v1 "
                        "WHERE deed_launcher_id=?",
                        (operation.deed_launcher_id,),
                    )
                    stale = None
            if stale is not None and stale["purchase_id"] != purchase_id:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "SmartDeed is reserved by another purchase"
                )
            connection.execute(
                """
                INSERT INTO purchase_deed_locks_v1(
                    deed_launcher_id, purchase_id, expires_at, created_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(deed_launcher_id) DO UPDATE SET
                    purchase_id=excluded.purchase_id,
                    expires_at=excluded.expires_at
                WHERE purchase_deed_locks_v1.purchase_id=excluded.purchase_id
                """,
                (
                    operation.deed_launcher_id,
                    purchase_id,
                    expires_at,
                    timestamp,
                ),
            )
            result = self._transition_in_connection(
                connection,
                operation,
                PurchaseOperationState.SOFT_HELD,
                actor=actor,
                reason="buyer started checkout",
                evidence={"softHoldExpiresAt": expires_at},
                changes={"soft_hold_expires_at": expires_at},
                now=timestamp,
            )
            connection.execute("COMMIT")
            return result

    def transition_operation(
        self,
        purchase_id: str,
        *,
        expected_revision: int,
        to_state: PurchaseOperationState,
        actor: str,
        reason: str,
        evidence: Mapping[str, Any] | None = None,
        changes: Mapping[str, Any] | None = None,
        now: int | None = None,
    ) -> StoredPurchaseOperation:
        timestamp = int(time.time()) if now is None else now
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            operation = _operation_record(row)
            if operation.revision != expected_revision:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase operation revision changed"
                )
            result = self._transition_in_connection(
                connection,
                operation,
                to_state,
                actor=actor,
                reason=reason,
                evidence=evidence or {},
                changes=changes or {},
                now=timestamp,
            )
            if to_state in _LOCK_TERMINAL_STATES:
                connection.execute(
                    "DELETE FROM purchase_deed_locks_v1 WHERE purchase_id=?",
                    (purchase_id,),
                )
            elif result.reservation_expires_at is not None:
                connection.execute(
                    """
                    UPDATE purchase_deed_locks_v1 SET expires_at=?
                    WHERE purchase_id=?
                    """,
                    (result.reservation_expires_at, purchase_id),
                )
            connection.execute("COMMIT")
            return result

    def record_reservation_extension(
        self,
        purchase_id: str,
        *,
        expected_revision: int,
        expected_current_coin_id: str,
        expected_current_expires_at: int,
        action: str,
        next_coin_id: str,
        next_bundle_id: str,
        next_expires_at: int,
        confirmation_height: int,
        fee_mojos: int,
        actor: str,
        evidence: Mapping[str, Any],
        now: int | None = None,
    ) -> StoredPurchaseOperation:
        """Advance only the exact confirmed reservation successor.

        Reservation coin IDs are otherwise bind-once. This dedicated path
        permits the two reviewed Stripe extensions without allowing a generic
        state update to redirect inventory.
        """

        timestamp = int(time.time()) if now is None else now
        if action not in {"EXTEND_PROCESSING", "EXTEND_SETTLEMENT"}:
            raise PaymentPurchaseConflict(
                "reservation extension action is unsupported"
            )
        _require_bytes32(expected_current_coin_id, "current reservation coin")
        _require_bytes32(next_coin_id, "next reservation coin")
        _require_bytes32(next_bundle_id, "reservation extension bundle")
        _positive_int(expected_current_expires_at, "current reservation expiry")
        _positive_int(next_expires_at, "next reservation expiry")
        _positive_int(confirmation_height, "extension confirmation height")
        _nonnegative_int(fee_mojos, "fee_mojos")
        if (
            next_expires_at <= expected_current_expires_at
            or next_expires_at > expected_current_expires_at + 11 * 24 * 60 * 60
        ):
            raise PaymentPurchaseConflict(
                "reservation extension must advance by at most eleven days"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            operation = _operation_record(row)
            if operation.revision != expected_revision:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase operation revision changed"
                )
            if operation.state not in {
                PurchaseOperationState.PAYMENT_PROCESSING,
                PurchaseOperationState.PAYMENT_SUCCEEDED,
            }:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "reservation cannot be extended from its current state"
                )
            if (
                operation.reservation_coin_id != expected_current_coin_id
                or operation.reservation_expires_at
                != expected_current_expires_at
            ):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "reservation extension no longer matches current inventory"
                )
            revision = operation.revision + 1
            try:
                connection.execute(
                    """
                    UPDATE purchase_operations_v1
                    SET reservation_coin_id=?, reservation_bundle_id=?,
                        reservation_parent_expires_at=?,
                        reservation_expires_at=?,
                        reservation_confirmation_height=?, fee_mojos=?,
                        revision=?, updated_at=?
                    WHERE purchase_id=?
                    """,
                    (
                        next_coin_id,
                        next_bundle_id,
                        expected_current_expires_at,
                        next_expires_at,
                        confirmation_height,
                        fee_mojos,
                        revision,
                        timestamp,
                        purchase_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "reservation successor is already bound elsewhere"
                ) from exc
            connection.execute(
                "UPDATE purchase_deed_locks_v1 SET expires_at=? "
                "WHERE purchase_id=?",
                (next_expires_at, purchase_id),
            )
            connection.execute(
                """
                INSERT INTO purchase_operation_history_v1(
                    purchase_id, from_state, to_state, revision, actor,
                    reason, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    purchase_id,
                    operation.state.value,
                    operation.state.value,
                    revision,
                    actor[:128],
                    "confirmed Stripe inventory reservation extension",
                    _canonical_json({"action": action, **dict(evidence)}),
                    timestamp,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert updated is not None
        return _operation_record(updated)

    def record_inventory_release(
        self,
        purchase_id: str,
        *,
        expected_revision: int,
        release_bundle_id: str,
        release_output_coin_id: str,
        confirmation_height: int,
        actor: str,
        evidence: Mapping[str, Any],
        now: int | None = None,
    ) -> StoredPurchaseOperation:
        """Record the exact confirmed return to canonical inventory.

        Failed payments become canceled. Refunds remain pending until Stripe
        independently confirms the full refund, but the deed lock is removed
        only after this chain evidence is durable.
        """

        timestamp = int(time.time()) if now is None else now
        _require_bytes32(release_bundle_id, "inventory release bundle")
        _require_bytes32(release_output_coin_id, "inventory release output")
        _positive_int(confirmation_height, "inventory release height")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            operation = _operation_record(row)
            existing = (
                operation.inventory_release_bundle_id,
                operation.inventory_release_output_coin_id,
                operation.inventory_release_confirmation_height,
            )
            expected = (
                release_bundle_id,
                release_output_coin_id,
                confirmation_height,
            )
            if all(value is not None for value in existing):
                if existing != expected:
                    connection.execute("ROLLBACK")
                    raise PaymentPurchaseConflict(
                        "inventory release is already bound to different evidence"
                    )
                connection.execute("COMMIT")
                return operation
            if operation.revision != expected_revision:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase operation revision changed"
                )
            if operation.state not in {
                PurchaseOperationState.RESERVED,
                PurchaseOperationState.PAYMENT_FAILED,
                PurchaseOperationState.REFUND_PENDING,
                PurchaseOperationState.REVIEW_REQUIRED,
            }:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "inventory cannot be released from its current state"
                )
            execution = connection.execute(
                """
                SELECT spend_bundle_id, expected_output_coin_id
                FROM purchase_chain_executions_v1
                WHERE purchase_id=? AND action='RELEASE'
                """,
                (purchase_id,),
            ).fetchone()
            if (
                execution is None
                or execution["spend_bundle_id"] != release_bundle_id
                or execution["expected_output_coin_id"]
                != release_output_coin_id
            ):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "inventory release does not match the sealed chain execution"
                )
            next_state = (
                PurchaseOperationState.CANCELED
                if operation.state
                in {
                    PurchaseOperationState.RESERVED,
                    PurchaseOperationState.PAYMENT_FAILED,
                }
                else operation.state
            )
            revision = operation.revision + 1
            try:
                connection.execute(
                    """
                    UPDATE purchase_operations_v1
                    SET inventory_release_bundle_id=?,
                        inventory_release_output_coin_id=?,
                        inventory_release_confirmation_height=?,
                        state=?, revision=?, updated_at=?, last_error=NULL
                    WHERE purchase_id=?
                    """,
                    (
                        release_bundle_id,
                        release_output_coin_id,
                        confirmation_height,
                        next_state.value,
                        revision,
                        timestamp,
                        purchase_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "inventory release evidence is already used"
                ) from exc
            connection.execute(
                "DELETE FROM purchase_deed_locks_v1 WHERE purchase_id=?",
                (purchase_id,),
            )
            connection.execute(
                """
                INSERT INTO purchase_operation_history_v1(
                    purchase_id, from_state, to_state, revision, actor,
                    reason, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    purchase_id,
                    operation.state.value,
                    next_state.value,
                    revision,
                    actor[:128],
                    "confirmed return to canonical SmartDeed inventory",
                    _canonical_json(dict(evidence)),
                    timestamp,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert updated is not None
        return _operation_record(updated)

    @staticmethod
    def _transition_in_connection(
        connection: sqlite3.Connection,
        operation: StoredPurchaseOperation,
        to_state: PurchaseOperationState,
        *,
        actor: str,
        reason: str,
        evidence: Mapping[str, Any],
        changes: Mapping[str, Any],
        now: int,
    ) -> StoredPurchaseOperation:
        if to_state not in _ALLOWED_TRANSITIONS[operation.state]:
            raise PaymentPurchaseConflict(
                f"invalid purchase transition "
                f"{operation.state.value}->{to_state.value}"
            )
        allowed_changes = {
            "processing_charge_minor",
            "total_amount_minor",
            "soft_hold_expires_at",
            "reservation_coin_id",
            "reservation_bundle_id",
            "reservation_expires_at",
            "reservation_confirmation_height",
            "payment_intent_id",
            "payment_method_family",
            "funding_type",
            "payment_method_ready_at",
            "stripe_event_id",
            "receipt_hash",
            "receipt_coin_id",
            "receipt_bundle_id",
            "receipt_confirmation_height",
            "delivery_bundle_id",
            "expected_output_coin_id",
            "fee_mojos",
            "mempool_observed_at",
            "confirmation_height",
            "refund_request_hash",
            "refund_requested_at",
            "refund_id",
            "refunded_minor",
            "dispute_id",
            "dispute_status",
            "dispute_event_id",
            "last_error",
        }
        unknown = set(changes) - allowed_changes
        if unknown:
            raise PaymentPurchaseConflict(
                "unsupported purchase evidence fields: "
                + ", ".join(sorted(unknown))
            )
        normalized = dict(changes)
        for field in _BIND_ONCE_FIELDS:
            if field not in normalized:
                continue
            existing = getattr(operation, field)
            replacement = normalized[field]
            if (
                existing is not None
                and replacement is not None
                and replacement != existing
            ):
                raise PaymentPurchaseConflict(
                    f"{field} is already bound to different evidence"
                )
        processing_charge = _nonnegative_int(
            normalized.get(
                "processing_charge_minor",
                operation.processing_charge_minor,
            ),
            "processing_charge_minor",
        )
        expected_total = (
            operation.base_amount_minor
            + operation.technology_fee_minor
            + processing_charge
        )
        if (
            "total_amount_minor" in normalized
            and _nonnegative_int(
                normalized["total_amount_minor"],
                "total_amount_minor",
            )
            != expected_total
        ):
            raise PaymentPurchaseConflict(
                "purchase total must equal base, technology fee, and surcharge"
            )
        normalized["processing_charge_minor"] = processing_charge
        normalized["total_amount_minor"] = expected_total
        if (
            to_state == PurchaseOperationState.PAYMENT_METHOD_READY
            and normalized.get("payment_method_ready_at") is None
            and operation.payment_method_ready_at is None
        ):
            normalized["payment_method_ready_at"] = now
        refunded = _nonnegative_int(
            normalized.get("refunded_minor", operation.refunded_minor),
            "refunded_minor",
        )
        if refunded > expected_total:
            raise PaymentPurchaseConflict(
                "refunded amount is outside the collected total"
            )
        normalized["refunded_minor"] = refunded
        effective = {
            field: normalized.get(field, getattr(operation, field))
            for field in allowed_changes
        }
        effective.update(
            {
                "inventory_release_bundle_id": (
                    operation.inventory_release_bundle_id
                ),
                "inventory_release_output_coin_id": (
                    operation.inventory_release_output_coin_id
                ),
                "inventory_release_confirmation_height": (
                    operation.inventory_release_confirmation_height
                ),
            }
        )
        PaymentPurchaseStore._validate_state_evidence(
            to_state,
            effective,
            total_amount_minor=expected_total,
            rail=operation.rail,
            now=now,
        )
        revision = operation.revision + 1
        assignments = [
            "state=?",
            "revision=?",
            "updated_at=?",
            *(f"{field}=?" for field in normalized),
        ]
        parameters = [
            to_state.value,
            revision,
            now,
            *(normalized[field] for field in normalized),
            operation.purchase_id,
        ]
        try:
            connection.execute(
                "UPDATE purchase_operations_v1 SET "
                + ", ".join(assignments)
                + " WHERE purchase_id=?",
                parameters,
            )
        except sqlite3.IntegrityError as exc:
            raise PaymentPurchaseConflict(
                "purchase evidence is already bound to another operation"
            ) from exc
        connection.execute(
            """
            INSERT INTO purchase_operation_history_v1(
                purchase_id, from_state, to_state, revision, actor,
                reason, evidence_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                operation.purchase_id,
                operation.state.value,
                to_state.value,
                revision,
                actor[:128],
                reason[:512],
                _canonical_json(evidence),
                now,
            ),
        )
        row = connection.execute(
            "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
            (operation.purchase_id,),
        ).fetchone()
        assert row is not None
        return _operation_record(row)

    @staticmethod
    def _validate_state_evidence(
        state: PurchaseOperationState,
        evidence: Mapping[str, Any],
        *,
        total_amount_minor: int,
        rail: str,
        now: int,
    ) -> None:
        reserved_states = {
            PurchaseOperationState.RESERVATION_MEMPOOL,
            PurchaseOperationState.RESERVED,
            PurchaseOperationState.PAYMENT_METHOD_READY,
            PurchaseOperationState.PAYMENT_PROCESSING,
            PurchaseOperationState.PAYMENT_SUCCEEDED,
            PurchaseOperationState.VOUCHER_PENDING,
            PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
            PurchaseOperationState.VOUCHER_ESCROWED,
            PurchaseOperationState.RECEIPT_MEMPOOL,
            PurchaseOperationState.RECEIPT_READY,
            PurchaseOperationState.DELIVERY_SUBMITTED,
            PurchaseOperationState.MEMPOOL_OBSERVED,
            PurchaseOperationState.CHAIN_CONFIRMED,
            PurchaseOperationState.FINALIZED,
        }
        payment_states = reserved_states - {
            PurchaseOperationState.RESERVATION_MEMPOOL,
            PurchaseOperationState.RESERVED,
        }
        succeeded_states = {
            PurchaseOperationState.PAYMENT_SUCCEEDED,
            PurchaseOperationState.VOUCHER_PENDING,
            PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
            PurchaseOperationState.VOUCHER_ESCROWED,
            PurchaseOperationState.RECEIPT_MEMPOOL,
            PurchaseOperationState.RECEIPT_READY,
            PurchaseOperationState.DELIVERY_SUBMITTED,
            PurchaseOperationState.MEMPOOL_OBSERVED,
            PurchaseOperationState.CHAIN_CONFIRMED,
            PurchaseOperationState.FINALIZED,
        }
        receipt_states = succeeded_states - {
            PurchaseOperationState.PAYMENT_SUCCEEDED,
            PurchaseOperationState.VOUCHER_PENDING,
            PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
            PurchaseOperationState.VOUCHER_ESCROWED,
            PurchaseOperationState.RECEIPT_MEMPOOL,
        }
        delivery_states = {
            PurchaseOperationState.DELIVERY_SUBMITTED,
            PurchaseOperationState.MEMPOOL_OBSERVED,
            PurchaseOperationState.CHAIN_CONFIRMED,
            PurchaseOperationState.FINALIZED,
        }
        if state in reserved_states:
            _require_bytes32(
                evidence.get("reservation_coin_id"),
                "reservation_coin_id",
            )
            _require_bytes32(
                evidence.get("reservation_bundle_id"),
                "reservation_bundle_id",
            )
            reservation_expires_at = _positive_int(
                evidence.get("reservation_expires_at"),
                "reservation_expires_at",
            )
            if (
                state
                in {
                    PurchaseOperationState.RESERVATION_MEMPOOL,
                    PurchaseOperationState.RESERVED,
                }
                and reservation_expires_at <= now
            ):
                raise PaymentPurchaseConflict(
                    "reservation must be live when it is recorded"
                )
        if state in {
            PurchaseOperationState.RESERVED,
            PurchaseOperationState.PAYMENT_METHOD_READY,
            PurchaseOperationState.PAYMENT_PROCESSING,
            PurchaseOperationState.PAYMENT_SUCCEEDED,
            PurchaseOperationState.VOUCHER_PENDING,
            PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL,
            PurchaseOperationState.VOUCHER_ESCROWED,
            PurchaseOperationState.RECEIPT_MEMPOOL,
            PurchaseOperationState.RECEIPT_READY,
            PurchaseOperationState.DELIVERY_SUBMITTED,
            PurchaseOperationState.MEMPOOL_OBSERVED,
            PurchaseOperationState.CHAIN_CONFIRMED,
            PurchaseOperationState.FINALIZED,
        }:
            _positive_int(
                evidence.get("reservation_confirmation_height"),
                "reservation_confirmation_height",
            )
        if state in payment_states and rail.lower() == "stripe":
            _require_short_text(
                evidence.get("payment_intent_id"),
                "payment_intent_id",
            )
            _require_short_text(
                evidence.get("payment_method_family"),
                "payment_method_family",
            )
            _require_short_text(
                evidence.get("funding_type"),
                "funding_type",
            )
            _positive_int(
                evidence.get("payment_method_ready_at"),
                "payment_method_ready_at",
            )
        if state in succeeded_states and rail.lower() == "stripe":
            _require_short_text(
                evidence.get("stripe_event_id"),
                "stripe_event_id",
            )
        if state == PurchaseOperationState.RECEIPT_MEMPOOL:
            _require_bytes32(evidence.get("receipt_hash"), "receipt_hash")
            _require_bytes32(
                evidence.get("receipt_coin_id"),
                "receipt_coin_id",
            )
            _require_bytes32(
                evidence.get("receipt_bundle_id"),
                "receipt_bundle_id",
            )
        if state == PurchaseOperationState.VOUCHER_ISSUANCE_MEMPOOL:
            _require_bytes32(evidence.get("receipt_hash"), "receipt_hash")
            _require_bytes32(
                evidence.get("receipt_coin_id"),
                "receipt_coin_id",
            )
            _require_bytes32(
                evidence.get("receipt_bundle_id"),
                "receipt_bundle_id",
            )
        if state == PurchaseOperationState.VOUCHER_ESCROWED:
            _require_bytes32(evidence.get("receipt_hash"), "receipt_hash")
            _require_bytes32(
                evidence.get("receipt_coin_id"),
                "receipt_coin_id",
            )
            _require_bytes32(
                evidence.get("receipt_bundle_id"),
                "receipt_bundle_id",
            )
            _positive_int(
                evidence.get("receipt_confirmation_height"),
                "receipt_confirmation_height",
            )
        if state in receipt_states:
            _require_bytes32(evidence.get("receipt_hash"), "receipt_hash")
            _require_bytes32(
                evidence.get("receipt_coin_id"),
                "receipt_coin_id",
            )
            _require_bytes32(
                evidence.get("receipt_bundle_id"),
                "receipt_bundle_id",
            )
            _positive_int(
                evidence.get("receipt_confirmation_height"),
                "receipt_confirmation_height",
            )
        if state in delivery_states:
            _require_bytes32(
                evidence.get("delivery_bundle_id"),
                "delivery_bundle_id",
            )
            _require_bytes32(
                evidence.get("expected_output_coin_id"),
                "expected_output_coin_id",
            )
            fee_mojos = evidence.get("fee_mojos")
            if (
                isinstance(fee_mojos, bool)
                or not isinstance(fee_mojos, int)
                or fee_mojos < 0
            ):
                raise PaymentPurchaseConflict(
                    "fee_mojos must be a non-negative integer"
                )
        if state == PurchaseOperationState.MEMPOOL_OBSERVED:
            _positive_int(
                evidence.get("mempool_observed_at"),
                "mempool_observed_at",
            )
        if state in {
            PurchaseOperationState.CHAIN_CONFIRMED,
            PurchaseOperationState.FINALIZED,
        }:
            _positive_int(
                evidence.get("confirmation_height"),
                "confirmation_height",
            )
        if state == PurchaseOperationState.REFUNDED:
            _require_bytes32(
                evidence.get("inventory_release_bundle_id"),
                "inventory_release_bundle_id",
            )
            _require_bytes32(
                evidence.get("inventory_release_output_coin_id"),
                "inventory_release_output_coin_id",
            )
            _positive_int(
                evidence.get("inventory_release_confirmation_height"),
                "inventory_release_confirmation_height",
            )
        if state == PurchaseOperationState.REFUNDED:
            _require_short_text(evidence.get("refund_id"), "refund_id")
            if evidence.get("refunded_minor") != total_amount_minor:
                raise PaymentPurchaseConflict(
                    "Stripe refunds must return the full collected amount"
                )
        if state == PurchaseOperationState.DISPUTED:
            _require_short_text(evidence.get("dispute_id"), "dispute_id")
            _require_stripe_dispute_status(evidence.get("dispute_status"))
            _require_short_text(
                evidence.get("dispute_event_id"),
                "dispute_event_id",
            )

    def append_stripe_event(
        self,
        purchase_id: str,
        *,
        event_id: str,
        event_type: str,
        payment_intent_id: str | None,
        payload_sha256: str,
        event_created_at: int,
        received_at: int | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> bool:
        timestamp = int(time.time()) if received_at is None else received_at
        _require_short_text(event_id, "event_id")
        _require_short_text(event_type, "event_type")
        if payment_intent_id is not None:
            _require_short_text(payment_intent_id, "payment_intent_id")
        _require_hex32(payload_sha256, "payload_sha256")
        _positive_int(event_created_at, "event_created_at")
        _positive_int(timestamp, "received_at")
        evidence_json = _canonical_json(evidence or {})
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            operation_row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if operation_row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            operation = _operation_record(operation_row)
            if operation.rail.lower() != "stripe":
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "Stripe events can bind only Stripe purchases"
                )
            if (
                operation.payment_intent_id is not None
                and payment_intent_id != operation.payment_intent_id
            ):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "Stripe event PaymentIntent does not match the purchase"
                )
            existing = connection.execute(
                "SELECT * FROM purchase_stripe_events_v1 WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["purchase_id"] != purchase_id
                    or existing["event_type"] != event_type
                    or existing["payment_intent_id"] != payment_intent_id
                    or existing["payload_sha256"] != payload_sha256
                ):
                    connection.execute("ROLLBACK")
                    raise PaymentPurchaseConflict(
                        "Stripe event ID is already bound to different evidence"
                    )
                connection.execute("COMMIT")
                return False
            connection.execute(
                """
                INSERT INTO purchase_stripe_events_v1(
                    event_id, purchase_id, event_type, payment_intent_id,
                    payload_sha256, evidence_json, created_at, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    purchase_id,
                    event_type,
                    payment_intent_id,
                    payload_sha256,
                    evidence_json,
                    event_created_at,
                    timestamp,
                ),
            )
            connection.execute("COMMIT")
            return True

    def list_unprocessed_stripe_events(
        self,
        *,
        purchase_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise PaymentPurchaseConflict("event limit must be 1..500")
        where = "processed_at IS NULL"
        parameters: list[Any] = []
        if purchase_id is not None:
            where += " AND purchase_id=?"
            parameters.append(purchase_id)
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM purchase_stripe_events_v1 "
                f"WHERE {where} ORDER BY created_at, event_id LIMIT ?",
                parameters,
            ).fetchall()
        return [
            {
                "eventId": str(row["event_id"]),
                "purchaseId": str(row["purchase_id"]),
                "eventType": str(row["event_type"]),
                "paymentIntentId": row["payment_intent_id"],
                "payloadSha256": str(row["payload_sha256"]),
                "evidence": json.loads(str(row["evidence_json"])),
                "createdAt": int(row["created_at"]),
                "receivedAt": int(row["received_at"]),
                "attempts": int(row["attempts"]),
                "processingError": row["processing_error"],
            }
            for row in rows
        ]

    def get_stripe_event(self, event_id: str) -> dict[str, Any]:
        _require_short_text(event_id, "event_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM purchase_stripe_events_v1 WHERE event_id=?",
                (event_id,),
            ).fetchone()
        if row is None:
            raise PaymentPurchaseNotFound("Stripe event was not found")
        return {
            "eventId": str(row["event_id"]),
            "purchaseId": str(row["purchase_id"]),
            "eventType": str(row["event_type"]),
            "paymentIntentId": row["payment_intent_id"],
            "payloadSha256": str(row["payload_sha256"]),
            "evidence": json.loads(str(row["evidence_json"])),
            "createdAt": int(row["created_at"]),
            "receivedAt": int(row["received_at"]),
            "processedAt": _optional_int(row["processed_at"]),
        }

    def get_stripe_event_for_type(
        self,
        purchase_id: str,
        event_type: str,
    ) -> dict[str, Any]:
        _require_short_text(event_type, "event_type")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT event_id FROM purchase_stripe_events_v1
                WHERE purchase_id=? AND event_type=?
                ORDER BY created_at DESC, event_id DESC LIMIT 1
                """,
                (purchase_id, event_type),
            ).fetchone()
        if row is None:
            raise PaymentPurchaseNotFound(
                f"Stripe {event_type} event was not found"
            )
        return self.get_stripe_event(str(row["event_id"]))

    def save_settlement_receipt(
        self,
        purchase_id: str,
        *,
        receipt_hash: str,
        pending_attestation: Mapping[str, Any],
        receipt: Mapping[str, Any],
        now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        _require_bytes32(receipt_hash, "receipt_hash")
        pending_json = _canonical_json(pending_attestation)
        receipt_json = _canonical_json(receipt)
        if len(pending_json.encode("utf-8")) > 64 * 1024:
            raise PaymentPurchaseConflict("pending attestation is oversized")
        if len(receipt_json.encode("utf-8")) > 256 * 1024:
            raise PaymentPurchaseConflict("settlement receipt is oversized")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                "SELECT purchase_id FROM purchase_operations_v1 "
                "WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if operation is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO purchase_settlement_receipts_v1(
                    purchase_id, receipt_hash, pending_attestation_json,
                    receipt_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    purchase_id,
                    receipt_hash,
                    pending_json,
                    receipt_json,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM purchase_settlement_receipts_v1 "
                "WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if (
                row is None
                or row["receipt_hash"] != receipt_hash
                or row["pending_attestation_json"] != pending_json
                or row["receipt_json"] != receipt_json
            ):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase is already bound to another settlement receipt"
                )
            connection.execute("COMMIT")

    def get_settlement_receipt(self, purchase_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM purchase_settlement_receipts_v1 "
                "WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
        if row is None:
            raise PaymentPurchaseNotFound(
                "Stripe settlement receipt was not found"
            )
        return {
            "purchaseId": purchase_id,
            "receiptHash": str(row["receipt_hash"]),
            "pendingAttestation": json.loads(
                str(row["pending_attestation_json"])
            ),
            "receipt": json.loads(str(row["receipt_json"])),
            "createdAt": int(row["created_at"]),
        }

    def record_stripe_event_processing(
        self,
        event_id: str,
        *,
        processed: bool,
        error: str | None = None,
        now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        _require_short_text(event_id, "event_id")
        if processed and error:
            raise PaymentPurchaseConflict(
                "a processed Stripe event cannot retain an error"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT event_id FROM purchase_stripe_events_v1 "
                "WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound("Stripe event was not found")
            connection.execute(
                """
                UPDATE purchase_stripe_events_v1
                SET processed_at=?, processing_error=?, attempts=attempts+1
                WHERE event_id=?
                """,
                (
                    timestamp if processed else None,
                    None if error is None else error[:1024],
                    event_id,
                ),
            )
            connection.execute("COMMIT")

    def claim_lease(
        self,
        purchase_id: str,
        *,
        worker_id: str,
        ttl_seconds: int,
        now: int | None = None,
    ) -> StoredPurchaseOperation:
        timestamp = int(time.time()) if now is None else now
        if ttl_seconds < 5 or ttl_seconds > 300:
            raise PaymentPurchaseConflict("lease TTL must be 5..300 seconds")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase operation was not found"
                )
            operation = _operation_record(row)
            if (
                operation.lease_owner
                and operation.lease_owner != worker_id
                and (operation.lease_expires_at or 0) > timestamp
            ):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "purchase operation is leased by another worker"
                )
            connection.execute(
                """
                UPDATE purchase_operations_v1
                SET lease_owner=?, lease_expires_at=?, updated_at=?
                WHERE purchase_id=?
                """,
                (
                    worker_id[:128],
                    timestamp + ttl_seconds,
                    timestamp,
                    purchase_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM purchase_operations_v1 WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _operation_record(row)

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


def _operation_record(row: sqlite3.Row) -> StoredPurchaseOperation:
    return StoredPurchaseOperation(
        purchase_id=str(row["purchase_id"]),
        revision=int(row["revision"]),
        state=PurchaseOperationState(row["state"]),
        purchase_kind=str(row["purchase_kind"]),
        presale_terms_hash=str(row["presale_terms_hash"]),
        customer_subject=str(row["customer_subject"]),
        rail=str(row["rail"]),
        deed_launcher_id=str(row["deed_launcher_id"]),
        approved_vault_launcher_id=str(row["approved_vault_launcher_id"]),
        approved_vault_puzzle_hash=str(row["approved_vault_puzzle_hash"]),
        zkpassport_root=str(row["zkpassport_root"]),
        base_amount_minor=int(row["base_amount_minor"]),
        technology_fee_minor=int(row["technology_fee_minor"]),
        processing_charge_minor=int(row["processing_charge_minor"]),
        total_amount_minor=int(row["total_amount_minor"]),
        soft_hold_expires_at=_optional_int(row["soft_hold_expires_at"]),
        reservation_coin_id=row["reservation_coin_id"],
        reservation_bundle_id=row["reservation_bundle_id"],
        reservation_expires_at=_optional_int(
            row["reservation_expires_at"]
        ),
        reservation_parent_expires_at=_optional_int(
            row["reservation_parent_expires_at"]
        ),
        reservation_confirmation_height=_optional_int(
            row["reservation_confirmation_height"]
        ),
        payment_intent_id=row["payment_intent_id"],
        payment_method_family=row["payment_method_family"],
        funding_type=row["funding_type"],
        payment_method_ready_at=_optional_int(
            row["payment_method_ready_at"]
        ),
        stripe_event_id=row["stripe_event_id"],
        receipt_hash=row["receipt_hash"],
        receipt_coin_id=row["receipt_coin_id"],
        receipt_bundle_id=row["receipt_bundle_id"],
        receipt_confirmation_height=_optional_int(
            row["receipt_confirmation_height"]
        ),
        delivery_bundle_id=row["delivery_bundle_id"],
        expected_output_coin_id=row["expected_output_coin_id"],
        fee_mojos=_optional_int(row["fee_mojos"]),
        mempool_observed_at=_optional_int(row["mempool_observed_at"]),
        confirmation_height=_optional_int(row["confirmation_height"]),
        inventory_release_bundle_id=row["inventory_release_bundle_id"],
        inventory_release_output_coin_id=row[
            "inventory_release_output_coin_id"
        ],
        inventory_release_confirmation_height=_optional_int(
            row["inventory_release_confirmation_height"]
        ),
        refund_request_hash=row["refund_request_hash"],
        refund_requested_at=_optional_int(row["refund_requested_at"]),
        refund_id=row["refund_id"],
        refunded_minor=int(row["refunded_minor"]),
        dispute_id=row["dispute_id"],
        dispute_status=row["dispute_status"],
        dispute_event_id=row["dispute_event_id"],
        dispute_resolution=row["dispute_resolution"],
        dispute_resolved_at=_optional_int(row["dispute_resolved_at"]),
        dispute_resolution_operation_id=row[
            "dispute_resolution_operation_id"
        ],
        lease_owner=row["lease_owner"],
        lease_expires_at=_optional_int(row["lease_expires_at"]),
        last_error=row["last_error"],
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
    )


def _chain_execution_record(row: sqlite3.Row) -> StoredChainExecution:
    required = json.loads(str(row["required_input_coin_ids_json"]))
    bundle = json.loads(str(row["spend_bundle_json"]))
    if not isinstance(required, list) or not isinstance(bundle, dict):
        raise PaymentPurchaseConflict(
            "stored chain execution is malformed"
        )
    return StoredChainExecution(
        purchase_id=str(row["purchase_id"]),
        action=str(row["action"]),
        claim_hash=str(row["claim_hash"]),
        spend_bundle_id=str(row["spend_bundle_id"]),
        required_input_coin_ids=tuple(str(value) for value in required),
        expected_output_coin_id=str(row["expected_output_coin_id"]),
        expected_output_puzzle_hash=str(
            row["expected_output_puzzle_hash"]
        ),
        fee_mojos=int(row["fee_mojos"]),
        spend_bundle=bundle,
        created_at=int(row["created_at"]),
    )


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PaymentPurchaseConflict(f"{field} must be a positive integer")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PaymentPurchaseConflict(
            f"{field} must be a non-negative integer"
        )
    return value


def _require_bytes32(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 66
        or not value.startswith("0x")
    ):
        raise PaymentPurchaseConflict(f"{field} must be a 0x bytes32 value")
    try:
        bytes.fromhex(value[2:])
    except ValueError as exc:
        raise PaymentPurchaseConflict(
            f"{field} must be a 0x bytes32 value"
        ) from exc
    return value.lower()


def _require_hex32(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise PaymentPurchaseConflict(f"{field} must be 32-byte hex")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise PaymentPurchaseConflict(f"{field} must be 32-byte hex") from exc
    return value.lower()


def _require_short_text(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > 255
    ):
        raise PaymentPurchaseConflict(
            f"{field} must be non-empty bounded text"
        )
    return value


def _require_stripe_dispute_status(value: Any) -> str:
    normalized = _require_short_text(value, "dispute_status").lower()
    if normalized not in {
        "warning_needs_response",
        "warning_under_review",
        "warning_closed",
        "needs_response",
        "under_review",
        "won",
        "lost",
    }:
        raise PaymentPurchaseConflict(
            "Stripe dispute status is unsupported"
        )
    return normalized


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


def _required_decimal_int(value: Mapping[str, Any], field: str) -> int:
    result = value.get(field)
    if isinstance(result, bool):
        raise PaymentPurchaseConflict(
            f"{field} must be an integer or canonical decimal string"
        )
    if isinstance(result, int):
        return result
    if (
        isinstance(result, str)
        and result
        and result.isascii()
        and result.isdecimal()
        and (len(result) == 1 or not result.startswith("0"))
    ):
        return int(result)
    raise PaymentPurchaseConflict(
        f"{field} must be an integer or canonical decimal string"
    )


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
