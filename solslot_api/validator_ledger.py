"""One-time signature ledger for an isolated zkPassport validator."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path


SCHEMA_VERSION = 11


class ValidatorLedgerConflict(RuntimeError):
    """A claim attempted to reuse one-time credential evidence."""


class ValidatorLedger:
    def __init__(self, path: str | Path, timeout: float = 10.0) -> None:
        self.path = str(path) if path == ":memory:" else str(Path(path))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            self.path,
            timeout=timeout,
            isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._configure()
        self._migrate()

    def _configure(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA busy_timeout = 10000")
            self._conn.execute("PRAGMA synchronous = FULL")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")

    def _migrate(self) -> None:
        with self._lock:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Validator ledger schema {version} is newer than supported {SCHEMA_VERSION}."
                )
            if version < 1:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        scoped_nullifier TEXT NOT NULL UNIQUE,
                        bridge_coin_id TEXT NOT NULL UNIQUE,
                        vault_action TEXT NOT NULL UNIQUE,
                        evm_transaction_hash TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 1;
                    COMMIT;
                    """
                )
                version = 1
            if version < 2:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE primary_purchase_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        purchase_id TEXT NOT NULL UNIQUE,
                        deed_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 2;
                    COMMIT;
                    """
                )
                version = 2
            if version < 3:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE voucher_issuance_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        global_payment_id TEXT NOT NULL UNIQUE,
                        series_coin_id TEXT NOT NULL UNIQUE,
                        purchase_launcher_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 3;
                    COMMIT;
                    """
                )
                version = 3
            if version < 4:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE voucher_transition_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        global_payment_id TEXT NOT NULL UNIQUE,
                        series_coin_id TEXT NOT NULL UNIQUE,
                        voucher_coin_id TEXT NOT NULL UNIQUE,
                        payment_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 4;
                    COMMIT;
                    """
                )
                version = 4
            if version < 5:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE voucher_series_phase_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        series_coin_id TEXT NOT NULL UNIQUE,
                        transition INTEGER NOT NULL,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 5;
                    COMMIT;
                    """
                )
                version = 5
            if version < 6:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    ALTER TABLE voucher_transition_signatures
                        ADD COLUMN deed_coin_id TEXT;
                    CREATE UNIQUE INDEX voucher_transition_deed_once
                        ON voucher_transition_signatures(deed_coin_id)
                        WHERE deed_coin_id IS NOT NULL;
                    PRAGMA user_version = 6;
                    COMMIT;
                    """
                )
                version = 6
            if version < 7:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE stripe_settlement_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        purchase_id TEXT NOT NULL UNIQUE,
                        payment_intent_id TEXT NOT NULL UNIQUE,
                        event_id TEXT NOT NULL UNIQUE,
                        receipt_coin_id TEXT NOT NULL UNIQUE,
                        deed_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 7;
                    COMMIT;
                    """
                )
                version = 7
            if version < 8:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE inventory_reservation_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        purchase_id TEXT NOT NULL UNIQUE,
                        artifact_hash TEXT NOT NULL UNIQUE,
                        available_coin_id TEXT NOT NULL,
                        reserved_coin_id TEXT NOT NULL UNIQUE,
                        reservation_expires_at INTEGER NOT NULL,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    CREATE INDEX inventory_reservation_available
                        ON inventory_reservation_signatures(
                            available_coin_id, reservation_expires_at
                        );
                    PRAGMA user_version = 8;
                    COMMIT;
                    """
                )
                version = 8
            if version < 9:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    ALTER TABLE stripe_settlement_signatures
                        ADD COLUMN expected_deed_output_coin_id TEXT;
                    CREATE UNIQUE INDEX stripe_settlement_output_once
                        ON stripe_settlement_signatures(
                            expected_deed_output_coin_id
                        )
                        WHERE expected_deed_output_coin_id IS NOT NULL;
                    PRAGMA user_version = 9;
                    COMMIT;
                    """
                )
                version = 9
            if version < 10:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE inventory_extension_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        purchase_id TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        current_coin_id TEXT NOT NULL UNIQUE,
                        next_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL,
                        UNIQUE(purchase_id, phase),
                        CHECK (phase IN ('PROCESSING', 'SETTLEMENT'))
                    );
                    PRAGMA user_version = 10;
                    COMMIT;
                    """
                )
                version = 10
            if version < 11:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE inventory_release_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        purchase_id TEXT NOT NULL UNIQUE,
                        reason TEXT NOT NULL,
                        current_coin_id TEXT NOT NULL UNIQUE,
                        next_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL,
                        CHECK (
                            reason IN (
                                'PAYMENT_FAILED',
                                'DELIVERY_TIMEOUT',
                                'PRESALE_REFUND'
                            )
                        )
                    );
                    PRAGMA user_version = 11;
                    COMMIT;
                    """
                )
                version = 11

    def record_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        scoped_nullifier: str,
        bridge_coin_id: str,
        vault_action: str,
        evm_transaction_hash: str,
        signature: str,
    ) -> str:
        """Record one signature or recover an exact idempotent retry."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT canonical_claim, signature FROM signatures WHERE claim_hash = ?",
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict("Claim hash collides with different evidence.")
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO signatures(
                        claim_hash, canonical_claim, scoped_nullifier,
                        bridge_coin_id, vault_action, evm_transaction_hash,
                        signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        scoped_nullifier,
                        bridge_coin_id,
                        vault_action,
                        evm_transaction_hash,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Nullifier, bridge coin, EVM event, or vault action was already signed."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def healthcheck(self) -> bool:
        with self._lock:
            row = self._conn.execute("PRAGMA quick_check").fetchone()
        return bool(row and row[0] == "ok")

    def record_primary_purchase_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        purchase_id: str,
        deed_coin_id: str,
        signature: str,
    ) -> str:
        """Record one deed authorization or recover an exact retry."""

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM primary_purchase_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Purchase claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO primary_purchase_signatures(
                        claim_hash, canonical_claim, purchase_id,
                        deed_coin_id, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        purchase_id,
                        deed_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Purchase or SmartDeed coin was already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_inventory_reservation_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        purchase_id: str,
        artifact_hash: str,
        available_coin_id: str,
        reserved_coin_id: str,
        reservation_expires_at: int,
        signature: str,
    ) -> str:
        """Record one live reservation or recover an exact retry."""

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM inventory_reservation_signatures
                    WHERE claim_hash=?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Reservation claim hash collides with different "
                            "evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                active = self._conn.execute(
                    """
                    SELECT reservation_expires_at
                    FROM inventory_reservation_signatures
                    WHERE available_coin_id=?
                    ORDER BY reservation_expires_at DESC
                    LIMIT 1
                    """,
                    (available_coin_id,),
                ).fetchone()
                if (
                    active is not None
                    and int(active["reservation_expires_at"])
                    > int(time.time())
                ):
                    raise ValidatorLedgerConflict(
                        "Available SmartDeed coin already has a live "
                        "reservation authorization."
                    )
                self._conn.execute(
                    """
                    INSERT INTO inventory_reservation_signatures(
                        claim_hash, canonical_claim, purchase_id,
                        artifact_hash, available_coin_id, reserved_coin_id,
                        reservation_expires_at, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        purchase_id,
                        artifact_hash,
                        available_coin_id,
                        reserved_coin_id,
                        reservation_expires_at,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Purchase, artifact, or reserved SmartDeed coin was "
                    "already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_inventory_extension_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        purchase_id: str,
        phase: str,
        current_coin_id: str,
        next_coin_id: str,
        signature: str,
    ) -> str:
        """Record one exact extension phase or recover an exact retry."""

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM inventory_extension_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Extension claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO inventory_extension_signatures(
                        claim_hash, canonical_claim, purchase_id, phase,
                        current_coin_id, next_coin_id, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        purchase_id,
                        phase,
                        current_coin_id,
                        next_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Purchase, extension phase, or reservation coin was "
                    "already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_inventory_release_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        purchase_id: str,
        reason: str,
        current_coin_id: str,
        next_coin_id: str,
        signature: str,
    ) -> str:
        """Record one terminal inventory release or recover an exact retry."""

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM inventory_release_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Release claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO inventory_release_signatures(
                        claim_hash, canonical_claim, purchase_id, reason,
                        current_coin_id, next_coin_id, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        purchase_id,
                        reason,
                        current_coin_id,
                        next_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Purchase or reservation coin was already released."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_stripe_settlement_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        purchase_id: str,
        payment_intent_id: str,
        event_id: str,
        receipt_coin_id: str,
        deed_coin_id: str,
        expected_deed_output_coin_id: str,
        signature: str,
    ) -> str:
        """Record one receipt-bound Stripe delivery or recover an exact retry."""

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM stripe_settlement_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Stripe claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO stripe_settlement_signatures(
                        claim_hash, canonical_claim, purchase_id,
                        payment_intent_id, event_id, receipt_coin_id,
                        deed_coin_id, expected_deed_output_coin_id,
                        signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        purchase_id,
                        payment_intent_id,
                        event_id,
                        receipt_coin_id,
                        deed_coin_id,
                        expected_deed_output_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Stripe payment, event, receipt, purchase, or SmartDeed "
                    "was already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_voucher_issuance_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        global_payment_id: str,
        series_coin_id: str,
        purchase_launcher_coin_id: str,
        signature: str,
    ) -> str:
        """Record one series transition or recover an exact retry."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM voucher_issuance_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Voucher claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO voucher_issuance_signatures(
                        claim_hash, canonical_claim, global_payment_id,
                        series_coin_id, purchase_launcher_coin_id,
                        signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        global_payment_id,
                        series_coin_id,
                        purchase_launcher_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Payment, series coin, or purchase launcher was already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_voucher_transition_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        global_payment_id: str,
        series_coin_id: str,
        voucher_coin_id: str,
        payment_coin_id: str,
        signature: str,
        deed_coin_id: str | None = None,
    ) -> str:
        """Record one terminal voucher transition or recover an exact retry."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM voucher_transition_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Voucher transition hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO voucher_transition_signatures(
                        claim_hash, canonical_claim, global_payment_id,
                        series_coin_id, voucher_coin_id, payment_coin_id,
                        deed_coin_id, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        global_payment_id,
                        series_coin_id,
                        voucher_coin_id,
                        payment_coin_id,
                        deed_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Voucher, payment, series coin, or payment ID was already settled."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_voucher_series_phase_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        series_coin_id: str,
        transition: int,
        signature: str,
    ) -> str:
        """Record one phase advance or recover an exact idempotent retry."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM voucher_series_phase_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Series phase claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO voucher_series_phase_signatures(
                        claim_hash, canonical_claim, series_coin_id,
                        transition, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        series_coin_id,
                        transition,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Series coin was already authorized for a phase transition."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = ["ValidatorLedger", "ValidatorLedgerConflict"]
