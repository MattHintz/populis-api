"""Persistent, fail-closed state machine for the Solslot V2 ceremony."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = 3
ADMIN_SLOTS = (1, 2, 3)
TERMINAL_STATES = frozenset({"locked", "abandoned"})
OWNER_SLOT = 1
COADMIN_SLOTS = frozenset({2, 3})


def owner_plus_one_approved(slots: set[int]) -> bool:
    """Ceremony slots are one-based: slot 1 is the permanent owner."""
    return OWNER_SLOT in slots and bool(slots & COADMIN_SLOTS)


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
            if version < 1:
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
                version = 1
            if version < 2:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE launch_claims (
                        ceremony_id TEXT PRIMARY KEY,
                        token_hash TEXT NOT NULL UNIQUE,
                        consumed_at INTEGER NOT NULL,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id)
                    );

                    CREATE TABLE launch_profiles (
                        ceremony_id TEXT NOT NULL,
                        slot INTEGER NOT NULL,
                        display_name TEXT NOT NULL,
                        role_label TEXT NOT NULL,
                        email TEXT,
                        timezone TEXT NOT NULL,
                        reminders_enabled INTEGER NOT NULL DEFAULT 1,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (ceremony_id, slot),
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (slot IN (1, 2, 3)),
                        CHECK (reminders_enabled IN (0, 1))
                    );

                    CREATE TABLE launch_auth_challenges (
                        nonce_hash TEXT PRIMARY KEY,
                        ceremony_id TEXT NOT NULL,
                        slot INTEGER NOT NULL,
                        wallet_address TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (slot IN (1, 2, 3))
                    );
                    CREATE INDEX launch_auth_challenges_expiry_idx
                        ON launch_auth_challenges(expires_at, consumed_at);

                    CREATE TABLE launch_action_approvals (
                        ceremony_id TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        slot INTEGER NOT NULL,
                        signer_address TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        submitted_at INTEGER NOT NULL,
                        PRIMARY KEY (ceremony_id, action_id, slot),
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (slot IN (1, 2, 3))
                    );

                    CREATE TABLE launch_gates (
                        ceremony_id TEXT NOT NULL,
                        gate_name TEXT NOT NULL,
                        network TEXT NOT NULL,
                        opens_at INTEGER NOT NULL,
                        closes_at INTEGER NOT NULL,
                        payload_hash TEXT NOT NULL,
                        state TEXT NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (ceremony_id, gate_name),
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (network = 'testnet11'),
                        CHECK (state IN ('pending', 'open', 'closed', 'cancelled')),
                        CHECK (closes_at > opens_at)
                    );

                    CREATE TABLE genesis_funding_receipts (
                        ceremony_id TEXT PRIMARY KEY,
                        plan_json TEXT NOT NULL,
                        plan_hash TEXT NOT NULL UNIQUE,
                        spend_bundle_id TEXT UNIQUE,
                        response_json TEXT,
                        state TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (state IN (
                            'prepared', 'approved', 'broadcast', 'confirmed', 'ambiguous'
                        ))
                    );

                    PRAGMA user_version = 2;
                    COMMIT;
                    """
                )
                version = 2
            if version < 3:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE launch_action_intents (
                        ceremony_id TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        state TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (ceremony_id, action_id),
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (state IN ('prepared', 'executed', 'cancelled'))
                    );

                    CREATE TABLE launch_settlement_rehearsals (
                        ceremony_id TEXT PRIMARY KEY,
                        job_id TEXT NOT NULL UNIQUE,
                        config_hash TEXT NOT NULL,
                        state TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (state IN (
                            'PREPARED', 'AWAITING_WALLET', 'PAYMENT_SUBMITTED',
                            'VALIDATING', 'SUCCEEDED', 'FAILED'
                        ))
                    );

                    PRAGMA user_version = 3;
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
        replace_live: bool = False,
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
            if existing and int(existing["expires_at"]) > timestamp and not replace_live:
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
            rows = connection.execute(
                "SELECT slot FROM plan_signatures WHERE ceremony_id=? AND plan_hash=?",
                (ceremony_id, plan_hash),
            ).fetchall()
            signed_slots = {int(row["slot"]) for row in rows}
            count = len(signed_slots)
            approved = owner_plus_one_approved(signed_slots)
            state = "plan_approved" if approved else "planned"
            connection.execute(
                "UPDATE ceremonies SET state=?,updated_at=? WHERE ceremony_id=?",
                (state, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "plan_signed",
                {
                    "slot": slot,
                    "planHash": plan_hash,
                    "signatureCount": count,
                    "ownerPlusOneApproved": approved,
                },
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
            rows = connection.execute(
                "SELECT slot FROM artifact_signatures WHERE ceremony_id=? "
                "AND artifact_hash=?",
                (ceremony_id, artifact_hash),
            ).fetchall()
            signed_slots = {int(row["slot"]) for row in rows}
            count = len(signed_slots)
            approved = owner_plus_one_approved(signed_slots)
            state = "artifact_signed" if approved else "artifact_pending"
            connection.execute(
                "UPDATE ceremonies SET state=?,updated_at=? WHERE ceremony_id=?",
                (state, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "artifact_signed",
                {
                    "slot": slot,
                    "artifactHash": artifact_hash,
                    "signatureCount": count,
                    "ownerPlusOneApproved": approved,
                },
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

    def list_ceremonies(self, *, limit: int = 50) -> list[dict[str, Any]]:
        if limit < 1 or limit > 200:
            raise ValueError("limit must be between 1 and 200")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT ceremony_id FROM ceremonies ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self.get(str(row["ceremony_id"])) for row in rows]

    def active(self) -> dict[str, Any] | None:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT ceremony_id FROM ceremonies "
                "WHERE state NOT IN ('locked', 'abandoned') "
                "ORDER BY created_at DESC"
            ).fetchall()
        if len(rows) > 1:
            raise GenesisConflict(
                "more than one active ceremony exists; archive the stale launch first"
            )
        return self.get(str(rows[0]["ceremony_id"])) if rows else None

    def audit_events(
        self, ceremony_id: str, *, after_event_id: int = 0, limit: int = 250
    ) -> list[dict[str, Any]]:
        if after_event_id < 0 or limit < 1 or limit > 1000:
            raise ValueError("invalid audit event cursor")
        with self._connect() as connection:
            self._require_ceremony(connection, ceremony_id)
            rows = connection.execute(
                "SELECT event_id,event_type,event_json,created_at FROM audit_events "
                "WHERE ceremony_id=? AND event_id>? ORDER BY event_id LIMIT ?",
                (ceremony_id, after_event_id, limit),
            ).fetchall()
        return [
            {
                "eventId": int(row["event_id"]),
                "type": str(row["event_type"]),
                "details": json.loads(str(row["event_json"])),
                "createdAt": int(row["created_at"]),
            }
            for row in rows
        ]

    def consume_owner_claim(
        self,
        ceremony_id: str,
        *,
        token_hash: str,
        now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            existing = connection.execute(
                "SELECT ceremony_id FROM launch_claims WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
            if existing:
                raise GenesisConflict("owner launch link was already consumed")
            connection.execute(
                "INSERT INTO launch_claims(ceremony_id,token_hash,consumed_at,created_at) "
                "VALUES(?,?,?,?)",
                (ceremony_id, token_hash, timestamp, timestamp),
            )
            self._event(
                connection,
                ceremony_id,
                "owner_link_consumed",
                {"slot": OWNER_SLOT},
                timestamp,
            )

    def owner_claim_used(self, token_hash: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM launch_claims WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
        return row is not None

    def set_profile(
        self,
        ceremony_id: str,
        *,
        slot: int,
        display_name: str,
        role_label: str,
        email: str | None,
        timezone: str,
        reminders_enabled: bool,
        now: int | None = None,
    ) -> dict[str, Any]:
        if slot not in ADMIN_SLOTS:
            raise ValueError("slot must be 1, 2, or 3")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            connection.execute(
                """
                INSERT INTO launch_profiles(
                    ceremony_id,slot,display_name,role_label,email,timezone,
                    reminders_enabled,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(ceremony_id,slot) DO UPDATE SET
                    display_name=excluded.display_name,
                    role_label=excluded.role_label,
                    email=excluded.email,
                    timezone=excluded.timezone,
                    reminders_enabled=excluded.reminders_enabled,
                    updated_at=excluded.updated_at
                """,
                (
                    ceremony_id,
                    slot,
                    display_name,
                    role_label,
                    email,
                    timezone,
                    int(reminders_enabled),
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "administrator_profile_updated",
                {"slot": slot, "role": role_label},
                timestamp,
            )
        return self.profiles(ceremony_id)[slot]

    def profiles(self, ceremony_id: str) -> dict[int, dict[str, Any]]:
        with self._connect() as connection:
            self._require_ceremony(connection, ceremony_id)
            rows = connection.execute(
                "SELECT * FROM launch_profiles WHERE ceremony_id=? ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
        return {
            int(row["slot"]): {
                "slot": int(row["slot"]),
                "displayName": str(row["display_name"]),
                "role": str(row["role_label"]),
                "email": row["email"],
                "timezone": str(row["timezone"]),
                "remindersEnabled": bool(row["reminders_enabled"]),
                "updatedAt": int(row["updated_at"]),
            }
            for row in rows
        }

    def create_auth_challenge(
        self,
        ceremony_id: str,
        *,
        slot: int,
        wallet_address: str,
        nonce_hash: str,
        expires_at: int,
        now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        if expires_at <= timestamp:
            raise GenesisExpired("authentication challenge must expire in the future")
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            member = connection.execute(
                "SELECT wallet_address FROM invitations WHERE ceremony_id=? AND slot=? "
                "AND consumed_at IS NOT NULL",
                (ceremony_id, slot),
            ).fetchone()
            if member is None or str(member["wallet_address"]).lower() != wallet_address.lower():
                raise GenesisConflict("wallet is not enrolled in this administrator slot")
            connection.execute(
                "DELETE FROM launch_auth_challenges WHERE expires_at<? OR consumed_at IS NOT NULL",
                (timestamp,),
            )
            connection.execute(
                "INSERT INTO launch_auth_challenges("
                "nonce_hash,ceremony_id,slot,wallet_address,expires_at,created_at"
                ") VALUES(?,?,?,?,?,?)",
                (
                    nonce_hash,
                    ceremony_id,
                    slot,
                    wallet_address.lower(),
                    expires_at,
                    timestamp,
                ),
            )

    def consume_auth_challenge(
        self,
        *,
        nonce_hash: str,
        wallet_address: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM launch_auth_challenges WHERE nonce_hash=?",
                (nonce_hash,),
            ).fetchone()
            if row is None:
                raise GenesisNotFound("administrator challenge not found")
            if row["consumed_at"] is not None:
                raise GenesisConflict("administrator challenge was already used")
            if int(row["expires_at"]) < timestamp:
                raise GenesisExpired("administrator challenge expired")
            if str(row["wallet_address"]).lower() != wallet_address.lower():
                raise GenesisConflict("administrator challenge wallet changed")
            connection.execute(
                "UPDATE launch_auth_challenges SET consumed_at=? WHERE nonce_hash=?",
                (timestamp, nonce_hash),
            )
            self._event(
                connection,
                str(row["ceremony_id"]),
                "administrator_session_started",
                {"slot": int(row["slot"]), "wallet": wallet_address.lower()},
                timestamp,
            )
        return dict(row)

    def auth_challenge(self, nonce_hash: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM launch_auth_challenges WHERE nonce_hash=?",
                (nonce_hash,),
            ).fetchone()
        if row is None:
            raise GenesisNotFound("administrator challenge not found")
        return dict(row)

    def add_action_approval(
        self,
        ceremony_id: str,
        *,
        action_id: str,
        action_type: str,
        payload_hash: str,
        slot: int,
        signer_address: str,
        signature: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            member = connection.execute(
                "SELECT wallet_address FROM invitations WHERE ceremony_id=? AND slot=? "
                "AND consumed_at IS NOT NULL",
                (ceremony_id, slot),
            ).fetchone()
            if member is None or str(member["wallet_address"]).lower() != signer_address.lower():
                raise GenesisConflict("action signer is not the enrolled administrator")
            existing = connection.execute(
                "SELECT payload_hash,signature FROM launch_action_approvals "
                "WHERE ceremony_id=? AND action_id=? AND slot=?",
                (ceremony_id, action_id, slot),
            ).fetchone()
            if existing:
                if (
                    str(existing["payload_hash"]).lower() == payload_hash.lower()
                    and str(existing["signature"]).lower() == signature.lower()
                ):
                    return self.action_approvals(ceremony_id, action_id)
                raise GenesisConflict("administrator slot already approved this action")
            connection.execute(
                "INSERT INTO launch_action_approvals("
                "ceremony_id,action_id,action_type,payload_hash,slot,signer_address,"
                "signature,submitted_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    ceremony_id,
                    action_id,
                    action_type,
                    payload_hash.lower(),
                    slot,
                    signer_address.lower(),
                    signature.lower(),
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "launch_action_approved",
                {
                    "actionId": action_id,
                    "actionType": action_type,
                    "payloadHash": payload_hash.lower(),
                    "slot": slot,
                },
                timestamp,
            )
        return self.action_approvals(ceremony_id, action_id)

    def action_approvals(
        self, ceremony_id: str, action_id: str
    ) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM launch_action_approvals "
                "WHERE ceremony_id=? AND action_id=? ORDER BY slot",
                (ceremony_id, action_id),
            ).fetchall()
        slots = {int(row["slot"]) for row in rows}
        return {
            "actionId": action_id,
            "approved": owner_plus_one_approved(slots),
            "slots": sorted(slots),
            "approvals": [
                {
                    "slot": int(row["slot"]),
                    "signer": str(row["signer_address"]),
                    "submittedAt": int(row["submitted_at"]),
                }
                for row in rows
            ],
        }

    def upsert_gate(
        self,
        ceremony_id: str,
        *,
        gate_name: str,
        opens_at: int,
        closes_at: int,
        payload_hash: str,
        state: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        if state not in {"pending", "open", "closed", "cancelled"}:
            raise ValueError("invalid launch gate state")
        if closes_at <= opens_at:
            raise ValueError("gate close must be after gate open")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            connection.execute(
                """
                INSERT INTO launch_gates(
                    ceremony_id,gate_name,network,opens_at,closes_at,
                    payload_hash,state,updated_at
                ) VALUES(?,?,'testnet11',?,?,?,?,?)
                ON CONFLICT(ceremony_id,gate_name) DO UPDATE SET
                    opens_at=excluded.opens_at,
                    closes_at=excluded.closes_at,
                    payload_hash=excluded.payload_hash,
                    state=excluded.state,
                    updated_at=excluded.updated_at
                """,
                (
                    ceremony_id,
                    gate_name,
                    opens_at,
                    closes_at,
                    payload_hash.lower(),
                    state,
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "launch_gate_updated",
                {
                    "gate": gate_name,
                    "opensAt": opens_at,
                    "closesAt": closes_at,
                    "state": state,
                },
                timestamp,
            )
        return self.gates(ceremony_id)[gate_name]

    def gates(
        self, ceremony_id: str, *, now: int | None = None
    ) -> dict[str, dict[str, Any]]:
        timestamp = int(time.time()) if now is None else now
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM launch_gates WHERE ceremony_id=? ORDER BY gate_name",
                (ceremony_id,),
            ).fetchall()
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            stored_state = str(row["state"])
            effective_state = stored_state
            if stored_state == "open" and timestamp >= int(row["closes_at"]):
                effective_state = "closed"
            elif stored_state == "pending" and int(row["opens_at"]) <= timestamp < int(
                row["closes_at"]
            ):
                effective_state = "open"
            result[str(row["gate_name"])] = {
                "name": str(row["gate_name"]),
                "network": str(row["network"]),
                "opensAt": int(row["opens_at"]),
                "closesAt": int(row["closes_at"]),
                "state": effective_state,
                "configuredState": stored_state,
                "payloadHash": str(row["payload_hash"]),
                "updatedAt": int(row["updated_at"]),
            }
        return result

    def set_funding_receipt(
        self,
        ceremony_id: str,
        *,
        plan: dict[str, Any],
        plan_hash: str,
        state: str = "prepared",
        spend_bundle_id: str | None = None,
        response: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        if state not in {"prepared", "approved", "broadcast", "confirmed", "ambiguous"}:
            raise ValueError("invalid funding receipt state")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            existing = connection.execute(
                "SELECT plan_hash FROM genesis_funding_receipts WHERE ceremony_id=?",
                (ceremony_id,),
            ).fetchone()
            if existing and str(existing["plan_hash"]).lower() != plan_hash.lower():
                raise GenesisConflict("ceremony funding plan is already sealed")
            connection.execute(
                """
                INSERT INTO genesis_funding_receipts(
                    ceremony_id,plan_json,plan_hash,spend_bundle_id,response_json,
                    state,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(ceremony_id) DO UPDATE SET
                    spend_bundle_id=COALESCE(excluded.spend_bundle_id,spend_bundle_id),
                    response_json=COALESCE(excluded.response_json,response_json),
                    state=excluded.state,
                    updated_at=excluded.updated_at
                """,
                (
                    ceremony_id,
                    canonical_json(plan),
                    plan_hash.lower(),
                    spend_bundle_id,
                    canonical_json(response) if response is not None else None,
                    state,
                    timestamp,
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "genesis_funding_updated",
                {
                    "planHash": plan_hash.lower(),
                    "state": state,
                    "spendBundleId": spend_bundle_id,
                },
                timestamp,
            )
        receipt = self.funding_receipt(ceremony_id)
        assert receipt is not None
        return receipt

    def funding_receipt(self, ceremony_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM genesis_funding_receipts WHERE ceremony_id=?",
                (ceremony_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "plan": json.loads(str(row["plan_json"])),
            "planHash": str(row["plan_hash"]),
            "spendBundleId": row["spend_bundle_id"],
            "response": (
                json.loads(str(row["response_json"])) if row["response_json"] else None
            ),
            "state": str(row["state"]),
            "createdAt": int(row["created_at"]),
            "updatedAt": int(row["updated_at"]),
        }

    def set_action_intent(
        self,
        ceremony_id: str,
        *,
        action_id: str,
        action_type: str,
        payload_hash: str,
        payload: dict[str, Any],
        state: str = "prepared",
        now: int | None = None,
    ) -> dict[str, Any]:
        if state not in {"prepared", "executed", "cancelled"}:
            raise ValueError("invalid launch action intent state")
        timestamp = int(time.time()) if now is None else now
        encoded = canonical_json(payload)
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            existing = connection.execute(
                "SELECT action_type,payload_hash,payload_json FROM launch_action_intents "
                "WHERE ceremony_id=? AND action_id=?",
                (ceremony_id, action_id),
            ).fetchone()
            if existing and (
                str(existing["action_type"]) != action_type
                or str(existing["payload_hash"]).lower() != payload_hash.lower()
                or str(existing["payload_json"]) != encoded
            ):
                raise GenesisConflict("launch action intent changed after preparation")
            connection.execute(
                """
                INSERT INTO launch_action_intents(
                    ceremony_id,action_id,action_type,payload_hash,payload_json,
                    state,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(ceremony_id,action_id) DO UPDATE SET
                    state=excluded.state,
                    updated_at=excluded.updated_at
                """,
                (
                    ceremony_id,
                    action_id,
                    action_type,
                    payload_hash.lower(),
                    encoded,
                    state,
                    timestamp,
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "launch_action_intent_updated",
                {
                    "actionId": action_id,
                    "actionType": action_type,
                    "payloadHash": payload_hash.lower(),
                    "state": state,
                },
                timestamp,
            )
        intent = self.action_intent(ceremony_id, action_id)
        assert intent is not None
        return intent

    def action_intent(
        self, ceremony_id: str, action_id: str
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM launch_action_intents WHERE ceremony_id=? AND action_id=?",
                (ceremony_id, action_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "actionId": str(row["action_id"]),
            "actionType": str(row["action_type"]),
            "payloadHash": str(row["payload_hash"]),
            "payload": json.loads(str(row["payload_json"])),
            "state": str(row["state"]),
            "createdAt": int(row["created_at"]),
            "updatedAt": int(row["updated_at"]),
        }

    def latest_action_intent(
        self, ceremony_id: str, action_type: str
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT action_id FROM launch_action_intents "
                "WHERE ceremony_id=? AND action_type=? ORDER BY created_at DESC LIMIT 1",
                (ceremony_id, action_type),
            ).fetchone()
        return (
            self.action_intent(ceremony_id, str(row["action_id"]))
            if row is not None
            else None
        )

    def set_settlement_rehearsal(
        self,
        ceremony_id: str,
        *,
        job_id: str,
        config_hash: str,
        state: str,
        payload: dict[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "PREPARED",
            "AWAITING_WALLET",
            "PAYMENT_SUBMITTED",
            "VALIDATING",
            "SUCCEEDED",
            "FAILED",
        }
        state_order = {
            "PREPARED": 0,
            "AWAITING_WALLET": 1,
            "PAYMENT_SUBMITTED": 2,
            "VALIDATING": 3,
            "SUCCEEDED": 4,
        }
        if state not in allowed:
            raise ValueError("invalid settlement rehearsal state")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            existing = connection.execute(
                "SELECT job_id,config_hash,state FROM launch_settlement_rehearsals "
                "WHERE ceremony_id=?",
                (ceremony_id,),
            ).fetchone()
            if existing and (
                str(existing["job_id"]) != job_id
                or str(existing["config_hash"]).lower() != config_hash.lower()
            ):
                if str(existing["state"]) != "FAILED" or state != "PREPARED":
                    raise GenesisConflict("settlement rehearsal job is already sealed")
                connection.execute(
                    "DELETE FROM launch_settlement_rehearsals WHERE ceremony_id=?",
                    (ceremony_id,),
                )
                existing = None
            if existing:
                existing_state = str(existing["state"])
                if existing_state in {"SUCCEEDED", "FAILED"} and state != existing_state:
                    raise GenesisConflict("completed settlement rehearsal cannot be replaced")
                if (
                    existing_state in state_order
                    and state in state_order
                    and state_order[state] < state_order[existing_state]
                ):
                    raise GenesisConflict("settlement rehearsal cannot move backwards")
            connection.execute(
                """
                INSERT INTO launch_settlement_rehearsals(
                    ceremony_id,job_id,config_hash,state,payload_json,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(ceremony_id) DO UPDATE SET
                    state=excluded.state,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    ceremony_id,
                    job_id,
                    config_hash.lower(),
                    state,
                    canonical_json(payload),
                    timestamp,
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "settlement_rehearsal_updated",
                {"jobId": job_id, "state": state, "configHash": config_hash.lower()},
                timestamp,
            )
        result = self.settlement_rehearsal(ceremony_id)
        assert result is not None
        return result

    def settlement_rehearsal(self, ceremony_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM launch_settlement_rehearsals WHERE ceremony_id=?",
                (ceremony_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "jobId": str(row["job_id"]),
            "configHash": str(row["config_hash"]),
            "state": str(row["state"]),
            "payload": json.loads(str(row["payload_json"])),
            "createdAt": int(row["created_at"]),
            "updatedAt": int(row["updated_at"]),
        }

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
    "OWNER_SLOT",
    "COADMIN_SLOTS",
    "canonical_json",
    "owner_plus_one_approved",
]
