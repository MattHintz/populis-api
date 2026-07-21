from __future__ import annotations

import sqlite3

import pytest
from eth_keys import keys

from solslot_api.genesis_store import GenesisStore
from solslot_api.safe_owner_roster import SafeOwnerRosterError, export_safe_owner_roster


CEREMONY_ID = "0x" + "ab" * 32


def _database(tmp_path):
    path = tmp_path / "genesis.db"
    store = GenesisStore(path)
    store.create_draft(CEREMONY_ID, {"network": "testnet11"}, now=100)
    for slot in (1, 2, 3):
        private_key = keys.PrivateKey(slot.to_bytes(32, "big"))
        public_key = private_key.public_key
        token = f"token-{slot}"
        store.issue_invitation(
            CEREMONY_ID,
            slot=slot,
            token_hash=token,
            nonce=f"nonce-{slot}",
            expires_at=1000,
            now=100,
        )
        store.consume_invitation(
            token_hash=token,
            wallet_address=public_key.to_checksum_address(),
            compressed_pubkey="0x" + public_key.to_compressed_bytes().hex(),
            signature="0x" + "11" * 65,
            now=200,
        )
    return path


def test_exports_exact_verified_two_of_three_roster(tmp_path):
    evidence = export_safe_owner_roster(_database(tmp_path))
    assert evidence["kind"] == "solslot-alpha-safe-owner-roster"
    assert evidence["ceremonyId"] == CEREMONY_ID
    assert evidence["threshold"] == 2
    assert [owner["slot"] for owner in evidence["owners"]] == [1, 2, 3]
    assert evidence["artifactHash"].startswith("0x")


def test_rejects_public_key_wallet_mismatch(tmp_path):
    path = _database(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE invitations SET wallet_address=? WHERE ceremony_id=? AND slot=2",
            ("0x" + "12" * 20, CEREMONY_ID),
        )
    with pytest.raises(SafeOwnerRosterError, match="does not match"):
        export_safe_owner_roster(path)


def test_rejects_database_without_three_enrolled_admins(tmp_path):
    path = tmp_path / "empty.db"
    GenesisStore(path).create_draft(CEREMONY_ID, {"network": "testnet11"}, now=100)
    with pytest.raises(SafeOwnerRosterError, match="three enrolled"):
        export_safe_owner_roster(path)
