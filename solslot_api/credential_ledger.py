"""Persistent Solslot V2 credential and relayer ledger.

The ledger is deliberately separate from the vault registry. Vault ownership
is durable protocol metadata; this database tracks one-time credential actions,
bridge reservations, public receipts, and sponsored EVM submissions. SQLite
WAL plus ``BEGIN IMMEDIATE`` makes every replay-sensitive transition atomic
across threads and API worker processes.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


SCHEMA_VERSION = 1


class LedgerError(RuntimeError):
    """Base class for fail-closed ledger errors."""


class LedgerConflict(LedgerError):
    """A one-time value or state transition has already been consumed."""


class LedgerRateLimited(LedgerError):
    """A persistent relay budget has been exhausted."""


class LedgerCircuitOpen(LedgerError):
    """Sponsored relay submissions are temporarily disabled."""


@dataclass(frozen=True)
class OwnerChallenge:
    challenge_id: str
    vault_launcher_id: str
    action: str
    payload_hash: str
    nonce: str
    auth_type: str
    expires_at: int


class CredentialLedger:
    """SQLite-backed V2 credential state machine and replay ledger."""

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
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA busy_timeout = 10000")
            self._conn.execute("PRAGMA synchronous = FULL")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")

    def _migrate(self) -> None:
        with self._lock:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Credential ledger schema {version} is newer than supported {SCHEMA_VERSION}."
                )
            if version == SCHEMA_VERSION:
                return
            self._conn.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE enrollments (
                    vault_launcher_id TEXT PRIMARY KEY,
                    network TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    bridge_coin_id TEXT NOT NULL UNIQUE,
                    owner_key TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    CHECK (policy_version >= 2),
                    CHECK (status IN (
                        'reserved', 'evm_confirmed', 'stamp_pending',
                        'chia_confirmed', 'receipt_syncing'
                    ))
                );

                CREATE TABLE owner_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    vault_launcher_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    nonce TEXT NOT NULL UNIQUE,
                    auth_type TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER,
                    created_at INTEGER NOT NULL,
                    CHECK (auth_type IN ('evm', 'chia_bls'))
                );
                CREATE INDEX owner_challenges_vault_idx
                    ON owner_challenges(vault_launcher_id, created_at);

                CREATE TABLE evm_events (
                    transaction_hash TEXT PRIMARY KEY,
                    vault_launcher_id TEXT NOT NULL UNIQUE,
                    owner_key TEXT NOT NULL,
                    scoped_nullifier TEXT NOT NULL UNIQUE,
                    bridge_coin_id TEXT NOT NULL UNIQUE,
                    block_number INTEGER NOT NULL,
                    recorded_at INTEGER NOT NULL,
                    FOREIGN KEY (vault_launcher_id)
                        REFERENCES enrollments(vault_launcher_id)
                );

                CREATE TABLE relay_attempts (
                    request_digest TEXT PRIMARY KEY,
                    vault_launcher_id TEXT NOT NULL,
                    owner_key TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    bridge_coin_id TEXT NOT NULL UNIQUE,
                    forwarder_nonce TEXT NOT NULL,
                    inner_gas INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    tx_hash TEXT,
                    error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE (owner_key, forwarder_nonce),
                    FOREIGN KEY (vault_launcher_id)
                        REFERENCES enrollments(vault_launcher_id),
                    CHECK (status IN ('reserved', 'submitted', 'failed'))
                );
                CREATE INDEX relay_attempts_ip_idx
                    ON relay_attempts(source_ip, created_at);
                CREATE INDEX relay_attempts_owner_idx
                    ON relay_attempts(owner_key, created_at);
                CREATE INDEX relay_attempts_vault_idx
                    ON relay_attempts(vault_launcher_id, created_at);

                CREATE TABLE relay_circuit (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    open_until INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
                );
                INSERT INTO relay_circuit(singleton, updated_at) VALUES (1, 0);
                PRAGMA user_version = 1;
                COMMIT;
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def get_enrollment(self, vault_launcher_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT record_json FROM enrollments WHERE vault_launcher_id = ?",
                (vault_launcher_id,),
            ).fetchone()
        return json.loads(row["record_json"]) if row else None

    def all_enrollments(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT vault_launcher_id, record_json FROM enrollments"
            ).fetchall()
        return {
            str(row["vault_launcher_id"]): json.loads(row["record_json"])
            for row in rows
        }

    def enrollment_bridge_coin_ids(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute("SELECT bridge_coin_id FROM enrollments").fetchall()
        return {str(row["bridge_coin_id"]).lower() for row in rows}

    def reserve_enrollment(
        self,
        *,
        record: dict[str, Any],
        owner_key: str,
    ) -> tuple[dict[str, Any], bool]:
        vault = str(record["vaultLauncherId"]).lower()
        bridge_coin = str(record["bridgeCoinId"]).lower()
        now = int(time.time())
        encoded = _canonical_json(record)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT record_json FROM enrollments WHERE vault_launcher_id = ?",
                    (vault,),
                ).fetchone()
                if existing:
                    self._conn.execute("COMMIT")
                    return json.loads(existing["record_json"]), False
                self._conn.execute(
                    """
                    INSERT INTO enrollments(
                        vault_launcher_id, network, policy_version, status,
                        bridge_coin_id, owner_key, record_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vault,
                        str(record["network"]),
                        int(record["policyVersion"]),
                        str(record["status"]),
                        bridge_coin,
                        owner_key.lower(),
                        encoded,
                        now,
                        now,
                    ),
                )
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise LedgerConflict("The vault or bridge coin is already reserved.") from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return record, True

    def update_enrollment(
        self,
        record: dict[str, Any],
        *,
        expected_statuses: Optional[Iterable[str]] = None,
    ) -> dict[str, Any]:
        vault = str(record["vaultLauncherId"]).lower()
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT status FROM enrollments WHERE vault_launcher_id = ?",
                    (vault,),
                ).fetchone()
                if not row:
                    raise LedgerConflict("Enrollment not found.")
                allowed = set(expected_statuses or ())
                if allowed and str(row["status"]) not in allowed:
                    raise LedgerConflict(
                        f"Enrollment state changed from the expected state ({row['status']})."
                    )
                self._conn.execute(
                    """
                    UPDATE enrollments
                    SET status = ?, record_json = ?, revision = revision + 1,
                        updated_at = ?
                    WHERE vault_launcher_id = ?
                    """,
                    (str(record["status"]), _canonical_json(record), now, vault),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return record

    def record_evm_event(
        self,
        *,
        record: dict[str, Any],
        owner_key: str,
        transaction_hash: str,
        scoped_nullifier: str,
        bridge_coin_id: str,
        block_number: int,
    ) -> None:
        vault = str(record["vaultLauncherId"]).lower()
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT status, owner_key, bridge_coin_id FROM enrollments "
                    "WHERE vault_launcher_id = ?",
                    (vault,),
                ).fetchone()
                if not row or row["status"] != "reserved":
                    raise LedgerConflict("Enrollment is not awaiting an EVM proof.")
                if str(row["owner_key"]).lower() != owner_key.lower():
                    raise LedgerConflict("EVM event owner does not own this vault enrollment.")
                if str(row["bridge_coin_id"]).lower() != bridge_coin_id.lower():
                    raise LedgerConflict("EVM event bridge coin does not match the reservation.")
                self._conn.execute(
                    """
                    INSERT INTO evm_events(
                        transaction_hash, vault_launcher_id, owner_key,
                        scoped_nullifier, bridge_coin_id, block_number, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        transaction_hash.lower(),
                        vault,
                        owner_key.lower(),
                        scoped_nullifier.lower(),
                        bridge_coin_id.lower(),
                        int(block_number),
                        now,
                    ),
                )
                self._conn.execute(
                    """
                    UPDATE enrollments
                    SET status = ?, record_json = ?, revision = revision + 1,
                        updated_at = ?
                    WHERE vault_launcher_id = ?
                    """,
                    (str(record["status"]), _canonical_json(record), now, vault),
                )
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise LedgerConflict(
                    "The EVM transaction, vault, nullifier, or bridge coin was already consumed."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def issue_owner_challenge(
        self,
        *,
        vault_launcher_id: str,
        action: str,
        payload_hash: str,
        auth_type: str,
        ttl_seconds: int,
    ) -> OwnerChallenge:
        now = int(time.time())
        challenge = OwnerChallenge(
            challenge_id=secrets.token_hex(24),
            vault_launcher_id=vault_launcher_id.lower(),
            action=action,
            payload_hash=payload_hash.lower(),
            nonce="0x" + secrets.token_hex(32),
            auth_type=auth_type,
            expires_at=now + int(ttl_seconds),
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO owner_challenges(
                    challenge_id, vault_launcher_id, action, payload_hash,
                    nonce, auth_type, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge.challenge_id,
                    challenge.vault_launcher_id,
                    action,
                    challenge.payload_hash,
                    challenge.nonce,
                    auth_type,
                    challenge.expires_at,
                    now,
                ),
            )
        return challenge

    def consume_owner_challenge(
        self,
        *,
        challenge_id: str,
        vault_launcher_id: str,
        action: str,
        payload_hash: str,
    ) -> OwnerChallenge:
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM owner_challenges WHERE challenge_id = ?",
                    (challenge_id,),
                ).fetchone()
                if not row:
                    raise LedgerConflict("Owner challenge is unknown.")
                if row["consumed_at"] is not None:
                    raise LedgerConflict("Owner challenge was already consumed.")
                if int(row["expires_at"]) < now:
                    raise LedgerConflict("Owner challenge expired.")
                expected = (
                    vault_launcher_id.lower(),
                    action,
                    payload_hash.lower(),
                )
                observed = (
                    str(row["vault_launcher_id"]).lower(),
                    str(row["action"]),
                    str(row["payload_hash"]).lower(),
                )
                if observed != expected:
                    raise LedgerConflict("Owner challenge does not match this mutation.")
                self._conn.execute(
                    "UPDATE owner_challenges SET consumed_at = ? WHERE challenge_id = ?",
                    (now, challenge_id),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return OwnerChallenge(
            challenge_id=str(row["challenge_id"]),
            vault_launcher_id=str(row["vault_launcher_id"]),
            action=str(row["action"]),
            payload_hash=str(row["payload_hash"]),
            nonce=str(row["nonce"]),
            auth_type=str(row["auth_type"]),
            expires_at=int(row["expires_at"]),
        )

    def get_owner_challenge(self, challenge_id: str) -> Optional[OwnerChallenge]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM owner_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        if not row or row["consumed_at"] is not None:
            return None
        return OwnerChallenge(
            challenge_id=str(row["challenge_id"]),
            vault_launcher_id=str(row["vault_launcher_id"]),
            action=str(row["action"]),
            payload_hash=str(row["payload_hash"]),
            nonce=str(row["nonce"]),
            auth_type=str(row["auth_type"]),
            expires_at=int(row["expires_at"]),
        )

    def reserve_relay(
        self,
        *,
        request_digest: str,
        vault_launcher_id: str,
        owner_key: str,
        source_ip: str,
        bridge_coin_id: str,
        forwarder_nonce: int,
        inner_gas: int,
        per_ip_per_minute: int,
        per_owner_per_minute: int,
        per_vault_per_hour: int,
        global_gas_per_day: int,
    ) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                circuit = self._conn.execute(
                    "SELECT open_until FROM relay_circuit WHERE singleton = 1"
                ).fetchone()
                if circuit and int(circuit["open_until"]) > now:
                    raise LedgerCircuitOpen("The sponsored relay circuit is temporarily open.")

                enrollment = self._conn.execute(
                    "SELECT owner_key, bridge_coin_id, status FROM enrollments "
                    "WHERE vault_launcher_id = ?",
                    (vault_launcher_id.lower(),),
                ).fetchone()
                if not enrollment or enrollment["status"] != "reserved":
                    raise LedgerConflict("Enrollment is not eligible for a relay.")
                if str(enrollment["owner_key"]).lower() != owner_key.lower():
                    raise LedgerConflict("Relay signer does not own the enrollment.")
                if str(enrollment["bridge_coin_id"]).lower() != bridge_coin_id.lower():
                    raise LedgerConflict("Relay bridge coin does not match the enrollment.")

                limits = (
                    ("source_ip", source_ip, now - 60, per_ip_per_minute, "source IP"),
                    ("owner_key", owner_key.lower(), now - 60, per_owner_per_minute, "owner"),
                    (
                        "vault_launcher_id",
                        vault_launcher_id.lower(),
                        now - 3600,
                        per_vault_per_hour,
                        "vault",
                    ),
                )
                for column, value, since, maximum, label in limits:
                    count = int(
                        self._conn.execute(
                            f"SELECT COUNT(*) FROM relay_attempts WHERE {column} = ? "
                            "AND created_at >= ?",
                            (value, since),
                        ).fetchone()[0]
                    )
                    if count >= maximum:
                        raise LedgerRateLimited(f"Relay budget exhausted for this {label}.")

                gas_used = int(
                    self._conn.execute(
                        "SELECT COALESCE(SUM(inner_gas), 0) FROM relay_attempts "
                        "WHERE created_at >= ?",
                        (now - 86400,),
                    ).fetchone()[0]
                )
                if gas_used + int(inner_gas) > global_gas_per_day:
                    raise LedgerRateLimited("The global daily sponsored gas budget is exhausted.")

                self._conn.execute(
                    """
                    INSERT INTO relay_attempts(
                        request_digest, vault_launcher_id, owner_key, source_ip,
                        bridge_coin_id, forwarder_nonce, inner_gas, status,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                    """,
                    (
                        request_digest.lower(),
                        vault_launcher_id.lower(),
                        owner_key.lower(),
                        source_ip,
                        bridge_coin_id.lower(),
                        str(forwarder_nonce),
                        int(inner_gas),
                        now,
                        now,
                    ),
                )
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise LedgerConflict(
                    "This relay request, nonce, or bridge coin was already consumed."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def finish_relay(
        self,
        *,
        request_digest: str,
        tx_hash: Optional[str],
        error: Optional[str],
        failure_threshold: int,
        cooldown_seconds: int,
    ) -> None:
        now = int(time.time())
        failed = error is not None
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                updated = self._conn.execute(
                    """
                    UPDATE relay_attempts
                    SET status = ?, tx_hash = ?, error = ?, updated_at = ?
                    WHERE request_digest = ? AND status = 'reserved'
                    """,
                    (
                        "failed" if failed else "submitted",
                        tx_hash.lower() if tx_hash else None,
                        error,
                        now,
                        request_digest.lower(),
                    ),
                )
                if updated.rowcount != 1:
                    raise LedgerConflict(
                        "The relay reservation is missing or was already finalized."
                    )
                circuit = self._conn.execute(
                    "SELECT consecutive_failures FROM relay_circuit WHERE singleton = 1"
                ).fetchone()
                failures = int(circuit["consecutive_failures"]) if circuit else 0
                failures = failures + 1 if failed else 0
                open_until = now + cooldown_seconds if failures >= failure_threshold else 0
                self._conn.execute(
                    """
                    UPDATE relay_circuit
                    SET consecutive_failures = ?, open_until = ?, updated_at = ?
                    WHERE singleton = 1
                    """,
                    (failures, open_until, now),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def require_submitted_relay(
        self,
        *,
        transaction_hash: str,
        vault_launcher_id: str,
        owner_key: str,
        bridge_coin_id: str,
    ) -> None:
        """Require an API-authorized relay submission for a BLS attestation event."""

        with self._lock:
            rows = self._conn.execute(
                """
                SELECT vault_launcher_id, owner_key, bridge_coin_id
                FROM relay_attempts
                WHERE tx_hash = ? AND status = 'submitted'
                """,
                (transaction_hash.lower(),),
            ).fetchall()
        if len(rows) != 1:
            raise LedgerConflict(
                "The BLS attestation event is not bound to one submitted relay."
            )
        row = rows[0]
        expected = (
            vault_launcher_id.lower(),
            owner_key.lower(),
            bridge_coin_id.lower(),
        )
        observed = (
            str(row["vault_launcher_id"]).lower(),
            str(row["owner_key"]).lower(),
            str(row["bridge_coin_id"]).lower(),
        )
        if observed != expected:
            raise LedgerConflict(
                "The submitted BLS relay does not match this vault owner and bridge coin."
            )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


_LEDGERS: dict[str, CredentialLedger] = {}
_LEDGERS_LOCK = threading.Lock()


def get_credential_ledger(settings: Any) -> CredentialLedger:
    path = str(settings.zkpassport_ledger_db_path)
    with _LEDGERS_LOCK:
        ledger = _LEDGERS.get(path)
        if ledger is None:
            ledger = CredentialLedger(path)
            _LEDGERS[path] = ledger
        return ledger


def reset_credential_ledgers_for_tests() -> None:
    with _LEDGERS_LOCK:
        for ledger in _LEDGERS.values():
            ledger.close()
        _LEDGERS.clear()


__all__ = [
    "CredentialLedger",
    "LedgerCircuitOpen",
    "LedgerConflict",
    "LedgerError",
    "LedgerRateLimited",
    "OwnerChallenge",
    "get_credential_ledger",
    "reset_credential_ledgers_for_tests",
]
