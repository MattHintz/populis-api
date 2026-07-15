"""Persistent, fail-closed state machine for the Solslot V2 ceremony."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = 1
ADMIN_SLOTS = (1, 2, 3)
TERMINAL_STATES = frozenset({"locked", "abandoned"})


class GenesisStoreError(RuntimeError):
    """Base class for ceremony persistence errors."""


class GenesisNotFound(GenesisStoreError):
    """The requested ceremony or invitation does not exist."""


class GenesisConflict(GenesisStoreError):
    """A ceremony transition is stale, duplicated, or out of order."""


class GenesisExpired(GenesisStoreError):
    """An invitation or signed plan has expired."""


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class GenesisStore:
    """SQLite-WAL ledger shared by all API workers.

    Every mutation uses ``BEGIN IMMEDIATE``. State transitions and signature
    inserts therefore remain atomic even when administrators submit at the
    same time or the API process restarts between phases.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path) if str(path) == ":memory:" else str(Path(path))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._memory_connection: sqlite3.Connection | None = None
        if self.path == ":memory:":
            self._memory_connection = sqlite3.connect(
                ":memory:", isolation_level=None, check_same_thread=False
            )
            self._configure(self._memory_connection)
        self._migrate()

    @staticmethod
    def _configure(connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA synchronous = FULL")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if self._memory_connection is not None:
            yield self._memory_connection
            return
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self._configure(connection)
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except Exception:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")

    def _migrate(self) -> None:
        with self._connect() as connection:
            if self.path != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Genesis store schema {version} is newer than supported {SCHEMA_VERSION}."
                )
            if version == SCHEMA_VERSION:
                return
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE ceremonies (
                    ceremony_id TEXT PRIMARY KEY,
                    network TEXT NOT NULL,
                    state TEXT NOT NULL,
                    draft_json TEXT NOT NULL,
                    roster_hash TEXT,
                    plan_input_json TEXT,
                    plan_json TEXT,
                    plan_hash TEXT UNIQUE,
                    plan_expires_at INTEGER,
                    spend_bundle_id TEXT UNIQUE,
                    broadcast_json TEXT,
                    confirmed_block_index INTEGER,
                    artifact_json TEXT,
                    artifact_hash TEXT UNIQUE,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    CHECK (network = 'testnet11'),
                    CHECK (state IN (
                        'draft', 'roster_open', 'roster_frozen', 'planned',
                        'plan_approved', 'broadcast', 'confirmed',
                        'artifact_pending', 'artifact_signed', 'locked', 'abandoned'
                    ))
                );

                CREATE TABLE invitations (
                    ceremony_id TEXT NOT NULL,
                    slot INTEGER NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    nonce TEXT NOT NULL UNIQUE,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER,
                    wallet_address TEXT,
                    compressed_pubkey TEXT,
                    enrollment_signature TEXT,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (ceremony_id, slot),
                    FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                    CHECK (slot IN (1, 2, 3))
                );

                CREATE TABLE plan_signatures (
                    ceremony_id TEXT NOT NULL,
                    slot INTEGER NOT NULL,
                    plan_hash TEXT NOT NULL,
                    compressed_pubkey TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    submitted_at INTEGER NOT NULL,
                    PRIMARY KEY (ceremony_id, slot),
                    FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                    CHECK (slot IN (1, 2, 3))
                );

                CREATE TABLE artifact_signatures (
                    ceremony_id TEXT NOT NULL,
                    slot INTEGER NOT NULL,
                    artifact_hash TEXT NOT NULL,
                    compressed_pubkey TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    submitted_at INTEGER NOT NULL,
                    PRIMARY KEY (ceremony_id, slot),
                    FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                    CHECK (slot IN (1, 2, 3))
                );

                CREATE TABLE audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ceremony_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id)
                );
                CREATE INDEX audit_events_ceremony_idx
                    ON audit_events(ceremony_id, event_id);
                PRAGMA user_version = 1;
                COMMIT;
                """
            )

    def _event(
        self,
        connection: sqlite3.Connection,
        ceremony_id: str,
        event_type: str,
        payload: Any,
        now: int,
    ) -> None:
        connection.execute(
            "INSERT INTO audit_events(ceremony_id,event_type,event_json,created_at) "
            "VALUES(?,?,?,?)",
            (ceremony_id, event_type, canonical_json(payload), now),
        )

    @staticmethod
    def _require_ceremony(
        connection: sqlite3.Connection, ceremony_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM ceremonies WHERE ceremony_id = ?", (ceremony_id,)
        ).fetchone()
        if row is None:
            raise GenesisNotFound("ceremony not found")
        return row

    @staticmethod
    def _require_state(row: sqlite3.Row, *states: str) -> None:
        if row["state"] not in states:
            raise GenesisConflict(
                f"ceremony is {row['state']}; expected " + " or ".join(states)
            )

    def create_draft(
        self,
        ceremony_id: str,
        draft: dict[str, Any],
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        encoded = canonical_json(draft)
        with self._transaction() as connection:
            try:
                connection.execute(
                    "INSERT INTO ceremonies(ceremony_id,network,state,draft_json,created_at,updated_at) "
                    "VALUES(?, 'testnet11', 'draft', ?, ?, ?)",
                    (ceremony_id, encoded, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict("ceremony id already exists") from exc
            self._event(connection, ceremony_id, "draft_created", draft, timestamp)
        return self.get(ceremony_id)

    def issue_invitation(
        self,
        ceremony_id: str,
        *,
        slot: int,
        token_hash: str,
        nonce: str,
        expires_at: int,
        now: int | None = None,
    ) -> dict[str, Any]:
        if slot not in ADMIN_SLOTS:
            raise ValueError("slot must be 1, 2, or 3")
        timestamp = int(time.time()) if now is None else now
        if expires_at <= timestamp:
            raise GenesisExpired("invitation expiration must be in the future")
        with self._transaction() as connection:
            row = self._require_ceremony(connection, ceremony_id)
            self._require_state(row, "draft", "roster_open")
            existing = connection.execute(
                "SELECT consumed_at,expires_at FROM invitations "
                "WHERE ceremony_id = ? AND slot = ?",
                (ceremony_id, slot),
            ).fetchone()
            if existing and existing["consumed_at"] is not None:
                raise GenesisConflict("administrator slot is already enrolled")
            if existing and int(existing["expires_at"]) > timestamp:
                raise GenesisConflict("administrator slot already has a live invitation")
            connection.execute(
                "DELETE FROM invitations WHERE ceremony_id = ? AND slot = ?",
                (ceremony_id, slot),
            )
            try:
                connection.execute(
                    "INSERT INTO invitations(ceremony_id,slot,token_hash,nonce,expires_at,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (ceremony_id, slot, token_hash, nonce, expires_at, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict("invitation token or nonce was already used") from exc
            connection.execute(
                "UPDATE ceremonies SET state='roster_open',updated_at=? WHERE ceremony_id=?",
                (timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "invitation_issued",
                {"slot": slot, "expiresAt": expires_at},
                timestamp,
            )
        return self.get_invitation(ceremony_id, slot)

    def invitation_for_token(self, token_hash: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM invitations WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        if row is None:
            raise GenesisNotFound("invitation not found")
        return dict(row)

    def get_invitation(self, ceremony_id: str, slot: int) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM invitations WHERE ceremony_id = ? AND slot = ?",
                (ceremony_id, slot),
            ).fetchone()
        if row is None:
            raise GenesisNotFound("invitation not found")
        return dict(row)

    def consume_invitation(
        self,
        *,
        token_hash: str,
        wallet_address: str,
        compressed_pubkey: str,
        signature: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            invitation = connection.execute(
                "SELECT * FROM invitations WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if invitation is None:
                raise GenesisNotFound("invitation not found")
            ceremony_id = str(invitation["ceremony_id"])
            if invitation["consumed_at"] is not None:
                raise GenesisConflict("invitation was already consumed")
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "draft", "roster_open")
            if int(invitation["expires_at"]) < timestamp:
                raise GenesisExpired("invitation expired")
            duplicate = connection.execute(
                "SELECT slot FROM invitations WHERE ceremony_id=? AND consumed_at IS NOT NULL "
                "AND (wallet_address=? OR compressed_pubkey=?)",
                (ceremony_id, wallet_address, compressed_pubkey),
            ).fetchone()
            if duplicate:
                raise GenesisConflict("administrator wallet or key is already enrolled")
            connection.execute(
                "UPDATE invitations SET consumed_at=?,wallet_address=?,compressed_pubkey=?,"
                "enrollment_signature=? WHERE token_hash=? AND consumed_at IS NULL",
                (timestamp, wallet_address, compressed_pubkey, signature, token_hash),
            )
            self._event(
                connection,
                ceremony_id,
                "administrator_enrolled",
                {"slot": int(invitation["slot"]), "wallet": wallet_address},
                timestamp,
            )
        return self.get(ceremony_id)

    def freeze_roster(
        self,
        ceremony_id: str,
        roster_hash: str,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "roster_open")
            members = connection.execute(
                "SELECT slot,wallet_address,compressed_pubkey FROM invitations "
                "WHERE ceremony_id=? AND consumed_at IS NOT NULL ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
            if [int(member["slot"]) for member in members] != list(ADMIN_SLOTS):
                raise GenesisConflict("all three administrator slots must be enrolled")
            wallets = {str(member["wallet_address"]) for member in members}
            pubkeys = {str(member["compressed_pubkey"]) for member in members}
            if len(wallets) != 3 or len(pubkeys) != 3:
                raise GenesisConflict("administrator roster keys must be distinct")
            connection.execute(
                "UPDATE ceremonies SET state='roster_frozen',roster_hash=?,updated_at=? "
                "WHERE ceremony_id=?",
                (roster_hash, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "roster_frozen",
                {"rosterHash": roster_hash},
                timestamp,
            )
        return self.get(ceremony_id)

    def set_plan(
        self,
        ceremony_id: str,
        *,
        plan_input: dict[str, Any],
        plan: dict[str, Any],
        plan_hash: str,
        expires_at: int,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        if expires_at <= timestamp:
            raise GenesisExpired("plan must expire in the future")
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "roster_frozen")
            connection.execute(
                "UPDATE ceremonies SET state='planned',plan_input_json=?,plan_json=?,"
                "plan_hash=?,plan_expires_at=?,updated_at=? WHERE ceremony_id=?",
                (
                    canonical_json(plan_input),
                    canonical_json(plan),
                    plan_hash,
                    expires_at,
                    timestamp,
                    ceremony_id,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "plan_created",
                {"planHash": plan_hash, "expiresAt": expires_at},
                timestamp,
            )
        return self.get(ceremony_id)

    def add_plan_signature(
        self,
        ceremony_id: str,
        *,
        slot: int,
        plan_hash: str,
        compressed_pubkey: str,
        signature: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "planned", "plan_approved")
            if ceremony["plan_hash"] != plan_hash:
                raise GenesisConflict("signature does not match the current plan")
            if int(ceremony["plan_expires_at"] or 0) < timestamp:
                raise GenesisExpired("ceremony plan expired")
            member = connection.execute(
                "SELECT compressed_pubkey FROM invitations WHERE ceremony_id=? AND slot=? "
                "AND consumed_at IS NOT NULL",
                (ceremony_id, slot),
            ).fetchone()
            if member is None or member["compressed_pubkey"] != compressed_pubkey:
                raise GenesisConflict("signature key does not match frozen roster slot")
            try:
                connection.execute(
                    "INSERT INTO plan_signatures(ceremony_id,slot,plan_hash,compressed_pubkey,"
                    "signature,submitted_at) VALUES(?,?,?,?,?,?)",
                    (ceremony_id, slot, plan_hash, compressed_pubkey, signature, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict("roster slot already signed this plan") from exc
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM plan_signatures WHERE ceremony_id=? AND plan_hash=?",
                    (ceremony_id, plan_hash),
                ).fetchone()[0]
            )
            state = "plan_approved" if count >= 2 else "planned"
            connection.execute(
                "UPDATE ceremonies SET state=?,updated_at=? WHERE ceremony_id=?",
                (state, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "plan_signed",
                {"slot": slot, "planHash": plan_hash, "signatureCount": count},
                timestamp,
            )
        return self.get(ceremony_id)

    def mark_broadcast(
        self,
        ceremony_id: str,
        *,
        spend_bundle_id: str,
        response: dict[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "plan_approved")
            if int(ceremony["plan_expires_at"] or 0) < timestamp:
                raise GenesisExpired("ceremony plan expired before broadcast")
            connection.execute(
                "UPDATE ceremonies SET state='broadcast',spend_bundle_id=?,broadcast_json=?,"
                "updated_at=? WHERE ceremony_id=?",
                (spend_bundle_id, canonical_json(response), timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "bundle_broadcast",
                {"spendBundleId": spend_bundle_id, "response": response},
                timestamp,
            )
        return self.get(ceremony_id)

    def mark_confirmed(
        self,
        ceremony_id: str,
        *,
        confirmed_block_index: int,
        now: int | None = None,
    ) -> dict[str, Any]:
        if confirmed_block_index <= 0:
            raise ValueError("confirmed block index must be positive")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "broadcast")
            connection.execute(
                "UPDATE ceremonies SET state='confirmed',confirmed_block_index=?,updated_at=? "
                "WHERE ceremony_id=?",
                (confirmed_block_index, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "bundle_confirmed",
                {"confirmedBlockIndex": confirmed_block_index},
                timestamp,
            )
        return self.get(ceremony_id)

    def set_artifact(
        self,
        ceremony_id: str,
        *,
        artifact: dict[str, Any],
        artifact_hash: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "confirmed")
            connection.execute(
                "UPDATE ceremonies SET state='artifact_pending',artifact_json=?,artifact_hash=?,"
                "updated_at=? WHERE ceremony_id=?",
                (canonical_json(artifact), artifact_hash, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "artifact_created",
                {"artifactHash": artifact_hash},
                timestamp,
            )
        return self.get(ceremony_id)

    def add_artifact_signature(
        self,
        ceremony_id: str,
        *,
        slot: int,
        artifact_hash: str,
        compressed_pubkey: str,
        signature: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "artifact_pending", "artifact_signed")
            if ceremony["artifact_hash"] != artifact_hash:
                raise GenesisConflict("signature does not match the current artifact")
            member = connection.execute(
                "SELECT compressed_pubkey FROM invitations WHERE ceremony_id=? AND slot=? "
                "AND consumed_at IS NOT NULL",
                (ceremony_id, slot),
            ).fetchone()
            if member is None or member["compressed_pubkey"] != compressed_pubkey:
                raise GenesisConflict("signature key does not match frozen roster slot")
            try:
                connection.execute(
                    "INSERT INTO artifact_signatures(ceremony_id,slot,artifact_hash,"
                    "compressed_pubkey,signature,submitted_at) VALUES(?,?,?,?,?,?)",
                    (
                        ceremony_id,
                        slot,
                        artifact_hash,
                        compressed_pubkey,
                        signature,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict("roster slot already signed this artifact") from exc
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_signatures WHERE ceremony_id=? "
                    "AND artifact_hash=?",
                    (ceremony_id, artifact_hash),
                ).fetchone()[0]
            )
            state = "artifact_signed" if count >= 2 else "artifact_pending"
            connection.execute(
                "UPDATE ceremonies SET state=?,updated_at=? WHERE ceremony_id=?",
                (state, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "artifact_signed",
                {"slot": slot, "artifactHash": artifact_hash, "signatureCount": count},
                timestamp,
            )
        return self.get(ceremony_id)

    def mark_locked(
        self, ceremony_id: str, *, now: int | None = None
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "artifact_signed")
            connection.execute(
                "UPDATE ceremonies SET state='locked',updated_at=? WHERE ceremony_id=?",
                (timestamp, ceremony_id),
            )
            self._event(connection, ceremony_id, "bootstrap_locked", {}, timestamp)
        return self.get(ceremony_id)

    def abandon(
        self, ceremony_id: str, reason: str, *, now: int | None = None
    ) -> dict[str, Any]:
        if not reason.strip():
            raise ValueError("abandon reason is required")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            if ceremony["state"] in TERMINAL_STATES:
                raise GenesisConflict("ceremony is already terminal")
            connection.execute(
                "UPDATE ceremonies SET state='abandoned',updated_at=? WHERE ceremony_id=?",
                (timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "ceremony_abandoned",
                {"reason": reason},
                timestamp,
            )
        return self.get(ceremony_id)

    def get(self, ceremony_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            invitations = connection.execute(
                "SELECT slot,expires_at,consumed_at,wallet_address,compressed_pubkey "
                "FROM invitations WHERE ceremony_id=? ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
            plan_signatures = connection.execute(
                "SELECT slot,plan_hash,compressed_pubkey,signature,submitted_at "
                "FROM plan_signatures WHERE ceremony_id=? ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
            artifact_signatures = connection.execute(
                "SELECT slot,artifact_hash,compressed_pubkey,signature,submitted_at "
                "FROM artifact_signatures WHERE ceremony_id=? ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
        result = dict(ceremony)
        for key in ("draft_json", "plan_input_json", "plan_json", "broadcast_json", "artifact_json"):
            result[key.removesuffix("_json")] = (
                json.loads(result[key]) if result.get(key) else None
            )
            result.pop(key, None)
        result["invitations"] = [dict(row) for row in invitations]
        result["plan_signatures"] = [dict(row) for row in plan_signatures]
        result["artifact_signatures"] = [dict(row) for row in artifact_signatures]
        return result


__all__ = [
    "ADMIN_SLOTS",
    "GenesisStore",
    "GenesisStoreError",
    "GenesisNotFound",
    "GenesisConflict",
    "GenesisExpired",
    "canonical_json",
]
