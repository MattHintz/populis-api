"""Export a Safe owner roster from public genesis ceremony identities."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from eth_keys import keys


_CEREMONY_ID = re.compile(r"^0x[0-9a-fA-F]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_PUBKEY = re.compile(r"^0x(?:02|03)[0-9a-fA-F]{64}$")


class SafeOwnerRosterError(RuntimeError):
    """The ceremony cannot produce a trustworthy three-owner roster."""


def _canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def address_from_compressed_pubkey(value: str) -> str:
    if not _PUBKEY.fullmatch(value):
        raise SafeOwnerRosterError("administrator compressed public key is invalid")
    try:
        return keys.PublicKey.from_compressed_bytes(bytes.fromhex(value[2:])).to_checksum_address()
    except (ValueError, TypeError) as exc:
        raise SafeOwnerRosterError("administrator compressed public key is invalid") from exc


def export_safe_owner_roster(
    database_path: str | Path,
    *,
    ceremony_id: str | None = None,
) -> dict[str, Any]:
    path = Path(database_path).resolve()
    if not path.is_file() or path.is_symlink():
        raise SafeOwnerRosterError("genesis ceremony database is unavailable")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        if ceremony_id is not None:
            if not _CEREMONY_ID.fullmatch(ceremony_id):
                raise SafeOwnerRosterError("ceremony id is invalid")
            ceremony = connection.execute(
                "SELECT ceremony_id,network,state,updated_at FROM ceremonies "
                "WHERE ceremony_id=?",
                (ceremony_id.lower(),),
            ).fetchone()
        else:
            ceremony = connection.execute(
                "SELECT c.ceremony_id,c.network,c.state,c.updated_at "
                "FROM ceremonies c JOIN invitations i ON i.ceremony_id=c.ceremony_id "
                "WHERE i.consumed_at IS NOT NULL GROUP BY c.ceremony_id "
                "HAVING COUNT(*)=3 ORDER BY c.updated_at DESC LIMIT 1"
            ).fetchone()
        if ceremony is None:
            raise SafeOwnerRosterError("no ceremony with three enrolled administrators exists")
        members = connection.execute(
            "SELECT slot,wallet_address,compressed_pubkey FROM invitations "
            "WHERE ceremony_id=? AND consumed_at IS NOT NULL ORDER BY slot",
            (ceremony["ceremony_id"],),
        ).fetchall()
    except sqlite3.Error as exc:
        raise SafeOwnerRosterError("genesis ceremony database is invalid") from exc
    finally:
        connection.close()

    if [int(member["slot"]) for member in members] != [1, 2, 3]:
        raise SafeOwnerRosterError("exactly three ordered administrator slots are required")
    owners: list[dict[str, Any]] = []
    for member in members:
        wallet = str(member["wallet_address"] or "")
        pubkey = str(member["compressed_pubkey"] or "")
        if not _ADDRESS.fullmatch(wallet):
            raise SafeOwnerRosterError("administrator wallet address is invalid")
        derived = address_from_compressed_pubkey(pubkey)
        if derived.lower() != wallet.lower():
            raise SafeOwnerRosterError("administrator wallet does not match its public key")
        owners.append(
            {
                "slot": int(member["slot"]),
                "address": derived,
                "compressedPubkey": pubkey.lower(),
            }
        )
    if len({owner["address"].lower() for owner in owners}) != 3:
        raise SafeOwnerRosterError("Safe owner addresses must be unique")

    evidence = {
        "schemaVersion": 1,
        "kind": "solslot-alpha-safe-owner-roster",
        "ceremonyId": str(ceremony["ceremony_id"]).lower(),
        "network": str(ceremony["network"]),
        "ceremonyState": str(ceremony["state"]),
        "threshold": 2,
        "owners": owners,
    }
    return {**evidence, "artifactHash": _canonical_hash(evidence)}


__all__ = [
    "SafeOwnerRosterError",
    "address_from_compressed_pubkey",
    "export_safe_owner_roster",
]
