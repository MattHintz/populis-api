"""One-time signature ledger for an isolated zkPassport validator."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path


SCHEMA_VERSION = 2


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

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = ["ValidatorLedger", "ValidatorLedgerConflict"]
