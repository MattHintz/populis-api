from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from eth_keys import keys
from eth_utils import keccak

from solslot_api.authority_v3_roster import (
    AuthorityV3RosterError,
    export_authority_v3_roster,
)
from solslot_api.genesis_store import GenesisStore


CEREMONY_ID = "0x" + "ab" * 32
SOURCE_MANIFEST_HASH = "0x" + "90" * 32
AUTHORITY_LAUNCHER_ID = "0x" + "80" * 32
IDENTITY_LAUNCHER_IDS = [
    "0x" + "81" * 32,
    "0x" + "82" * 32,
    "0x" + "83" * 32,
]


def _canonical_hash(value: dict) -> str:
    unsigned = {key: item for key, item in value.items() if key != "artifactHash"}
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _planned_database(tmp_path):
    path = tmp_path / "genesis.db"
    store = GenesisStore(path)
    store.create_draft(CEREMONY_ID, {"network": "testnet11"}, now=100)
    daily_keys = [keys.PrivateKey(slot.to_bytes(32, "big")) for slot in (1, 2, 3)]
    guardians = [
        keys.PrivateKey(slot.to_bytes(32, "big")).public_key.to_checksum_address()
        for slot in (11, 12, 13)
    ]
    recovery_pubkeys = [
        "0x" + (bytes([30 + slot]) * 48).hex() for slot in (1, 2, 3)
    ]
    recovery_commitments = [
        "0x" + keccak(bytes.fromhex(value[2:])).hex()
        for value in recovery_pubkeys
    ]
    drill_hashes = ["0x" + f"{40 + slot:02x}" * 32 for slot in (1, 2, 3)]

    for slot, private_key in enumerate(daily_keys, start=1):
        token = f"token-{slot}"
        store.issue_invitation(
            CEREMONY_ID,
            slot=slot,
            token_hash=token,
            nonce=f"nonce-{slot}",
            expires_at=1_000,
            now=100,
        )
        store.consume_invitation(
            token_hash=token,
            wallet_address=private_key.public_key.to_checksum_address(),
            compressed_pubkey=(
                "0x" + private_key.public_key.to_compressed_bytes().hex()
            ),
            signature="0x" + "11" * 65,
            now=200,
        )
    store.freeze_roster(CEREMONY_ID, "0x" + "70" * 32, now=250)
    for slot in (1, 2, 3):
        store.create_recovery_drill(
            CEREMONY_ID,
            challenge_id="0x" + f"{50 + slot:02x}" * 32,
            slot=slot,
            challenge_hash=drill_hashes[slot - 1],
            public_payload={
                "revision": 1,
                "evmGuardian": guardians[slot - 1],
                "recoveryBlsPubkey": recovery_pubkeys[slot - 1],
                "recoveryBlsCommitment": recovery_commitments[slot - 1],
            },
            expires_at=1_000,
            now=300,
        )
        store.complete_recovery_drill(
            "0x" + f"{50 + slot:02x}" * 32,
            expected_challenge_hash=drill_hashes[slot - 1],
            backup_status="NOT_CONFIGURED",
            backup_revision=None,
            backup_ciphertext_hash=None,
            now=400 + slot,
        )

    plan = {
        "ceremonyId": CEREMONY_ID,
        "network": "testnet11",
        "launcherIds": {
            "adminAuthority": AUTHORITY_LAUNCHER_ID,
            **{
                f"adminIdentity{slot}": IDENTITY_LAUNCHER_IDS[slot]
                for slot in range(3)
            },
        },
        "adminAuthority": {
            "version": 3,
            "adminsHash": "0x" + "70" * 32,
            "sourceManifestHash": SOURCE_MANIFEST_HASH,
            "compressedPubkeys": [
                "0x" + private_key.public_key.to_compressed_bytes().hex()
                for private_key in daily_keys
            ],
            "identityVaults": [
                {
                    "slot": slot,
                    "launcherId": IDENTITY_LAUNCHER_IDS[slot],
                    "dailyCompressedPubkey": (
                        "0x"
                        + daily_keys[slot].public_key.to_compressed_bytes().hex()
                    ),
                    "recoveryBlsPubkey": recovery_pubkeys[slot],
                }
                for slot in range(3)
            ],
        },
        "adminRecoveryKits": [
            {
                "slot": slot,
                "revision": 1,
                "evmGuardian": guardians[slot],
                "recoveryBlsPubkey": recovery_pubkeys[slot],
                "recoveryBlsCommitment": recovery_commitments[slot],
                "drillChallengeHash": drill_hashes[slot],
            }
            for slot in range(3)
        ],
    }
    store.set_plan(
        CEREMONY_ID,
        plan_input={},
        plan=plan,
        plan_hash="0x" + "71" * 32,
        expires_at=2_000_000_000,
        now=500,
    )
    return path, store, daily_keys


def test_exports_deployment_ready_authority_v3_roster(tmp_path) -> None:
    path, _store, daily_keys = _planned_database(tmp_path)

    evidence = export_authority_v3_roster(path, now=1_000)

    assert evidence["schemaVersion"] == 2
    assert evidence["kind"] == "solslot-alpha-authority-v3-roster"
    assert evidence["ceremonyId"] == CEREMONY_ID
    assert evidence["ceremonyState"] == "planned"
    assert evidence["authorityRule"] == "slot0_and_one_of_slot1_slot2"
    assert evidence["sourceManifestHash"] == SOURCE_MANIFEST_HASH
    assert evidence["authorityLauncherId"] == AUTHORITY_LAUNCHER_ID
    assert evidence["identityLauncherIds"] == IDENTITY_LAUNCHER_IDS
    assert [item["slot"] for item in evidence["administrators"]] == [0, 1, 2]
    assert [item["address"] for item in evidence["administrators"]] == [
        private_key.public_key.to_checksum_address() for private_key in daily_keys
    ]
    assert evidence["administrators"][0]["recovery"]["drillVerifiedAt"] == (
        "1970-01-01T00:06:41.000Z"
    )
    assert evidence["artifactHash"] == _canonical_hash(evidence)


def test_maps_plan_approval_to_deployer_supported_state(tmp_path) -> None:
    path, store, daily_keys = _planned_database(tmp_path)
    for slot in (1, 2):
        store.add_plan_signature(
            CEREMONY_ID,
            slot=slot,
            plan_hash="0x" + "71" * 32,
            compressed_pubkey=(
                "0x"
                + daily_keys[slot - 1].public_key.to_compressed_bytes().hex()
            ),
            signature="0x" + "12" * 65,
            now=600 + slot,
        )

    evidence = export_authority_v3_roster(path, now=1_000)

    assert evidence["ceremonyState"] == "approved"


def test_rejects_plan_that_differs_from_completed_recovery_drill(tmp_path) -> None:
    path, _store, _daily_keys = _planned_database(tmp_path)
    with sqlite3.connect(path) as connection:
        plan = json.loads(
            connection.execute(
                "SELECT plan_json FROM ceremonies WHERE ceremony_id=?",
                (CEREMONY_ID,),
            ).fetchone()[0]
        )
        plan["adminRecoveryKits"][1]["evmGuardian"] = "0x" + "ff" * 20
        connection.execute(
            "UPDATE ceremonies SET plan_json=? WHERE ceremony_id=?",
            (json.dumps(plan), CEREMONY_ID),
        )

    with pytest.raises(AuthorityV3RosterError, match="differs from"):
        export_authority_v3_roster(path, now=1_000)


def test_rejects_enrollment_without_deterministic_plan(tmp_path) -> None:
    path = tmp_path / "genesis.db"
    store = GenesisStore(path)
    store.create_draft(CEREMONY_ID, {"network": "testnet11"}, now=100)

    with pytest.raises(AuthorityV3RosterError, match="no planned ceremony"):
        export_authority_v3_roster(path, now=1_000)


def test_rejects_expired_planned_ceremony(tmp_path) -> None:
    path, _store, _daily_keys = _planned_database(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE ceremonies SET plan_expires_at=? WHERE ceremony_id=?",
            (999, CEREMONY_ID),
        )

    with pytest.raises(AuthorityV3RosterError, match="plan has expired"):
        export_authority_v3_roster(path, now=1_000)


def test_rejects_symlinked_ceremony_database(tmp_path) -> None:
    path, _store, _daily_keys = _planned_database(tmp_path)
    link = tmp_path / "linked-genesis.db"
    link.symlink_to(path)

    with pytest.raises(AuthorityV3RosterError, match="database is unavailable"):
        export_authority_v3_roster(link, now=1_000)


def test_cli_writes_private_evidence_and_refuses_overwrite(tmp_path) -> None:
    database, _store, _daily_keys = _planned_database(tmp_path)
    output = tmp_path / "authority-v3-roster.json"
    repository = Path(__file__).resolve().parents[1]
    environment = {**os.environ, "PYTHONPATH": str(repository)}
    command = [
        sys.executable,
        str(repository / "scripts" / "export_authority_v3_roster.py"),
        "--database",
        str(database),
        "--output",
        str(output),
        "--ceremony-id",
        CEREMONY_ID,
    ]

    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    result = json.loads(completed.stdout)

    assert result["artifactHash"] == json.loads(output.read_text())["artifactHash"]
    assert output.stat().st_mode & 0o777 == 0o600
    refused = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert refused.returncode != 0
    assert "refusing to overwrite" in refused.stderr
