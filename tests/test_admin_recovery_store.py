from __future__ import annotations

import pytest

from solslot_api.genesis_store import (
    SCHEMA_VERSION,
    GenesisConflict,
    GenesisStore,
)


CEREMONY_ID = "0x" + "11" * 32
CHALLENGE_HASH = "0x" + "22" * 32
INTENT_HASH = "0x" + "33" * 32


def _store() -> GenesisStore:
    store = GenesisStore(":memory:")
    store.create_draft(CEREMONY_ID, {"network": "testnet11"}, now=100)
    return store


def _public_kit(revision: int = 1) -> dict:
    return {
        "schemaVersion": 1,
        "revision": revision,
        "evmGuardian": "0x" + "44" * 20,
        "recoveryBlsPubkey": "0x" + "55" * 48,
        "recoveryBlsCommitment": "0x" + "66" * 32,
    }


def _complete_kit(
    store: GenesisStore,
    *,
    challenge_id: str = "drill-1",
    revision: int = 1,
    now: int = 101,
) -> dict:
    store.create_recovery_drill(
        CEREMONY_ID,
        challenge_id=challenge_id,
        slot=1,
        challenge_hash=CHALLENGE_HASH,
        public_payload=_public_kit(revision),
        expires_at=now + 900,
        now=now,
    )
    return store.complete_recovery_drill(
        challenge_id,
        expected_challenge_hash=CHALLENGE_HASH,
        backup_status="VERIFIED",
        backup_revision=revision,
        backup_ciphertext_hash="0x" + "77" * 32,
        now=now + 1,
    )


def test_schema_four_keeps_only_public_recovery_evidence() -> None:
    store = _store()
    with store._connect() as connection:  # noqa: SLF001 - migration assertion
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == (
            SCHEMA_VERSION
        )

    kit = _complete_kit(store)
    assert kit["slot"] == 0
    assert kit["revision"] == 1
    assert kit["backupStatus"] == "VERIFIED"
    assert set(kit).isdisjoint(
        {"mnemonic", "password", "privateKey", "googleEmail", "oauthToken"}
    )


def test_drill_is_single_use_and_recovery_revision_cannot_roll_back() -> None:
    store = _store()
    _complete_kit(store)
    with pytest.raises(GenesisConflict, match="already used"):
        store.complete_recovery_drill(
            "drill-1",
            expected_challenge_hash=CHALLENGE_HASH,
            backup_status="NOT_CONFIGURED",
            backup_revision=None,
            backup_ciphertext_hash=None,
            now=104,
        )

    store.create_recovery_drill(
        CEREMONY_ID,
        challenge_id="drill-2",
        slot=1,
        challenge_hash="0x" + "88" * 32,
        public_payload=_public_kit(1),
        expires_at=1_100,
        now=200,
    )
    with pytest.raises(GenesisConflict, match="increase monotonically"):
        store.complete_recovery_drill(
            "drill-2",
            expected_challenge_hash="0x" + "88" * 32,
            backup_status="NOT_CONFIGURED",
            backup_revision=None,
            backup_ciphertext_hash=None,
            now=201,
        )


def test_only_one_key_change_can_be_active_and_receipts_are_append_only() -> None:
    store = _store()
    case = store.create_recovery_case(
        CEREMONY_ID,
        case_id="case-1",
        authority_slot=0,
        kind="ROUTINE",
        intent_hash=INTENT_HASH,
        intent={"schemaVersion": 1, "slot": 0},
        execute_after=86_500,
        expires_at=173_000,
        prepared_by="0x" + "99" * 20,
        now=100,
    )
    assert case["state"] == "AWAITING_APPROVALS"

    with pytest.raises(GenesisConflict, match="another administrator"):
        store.create_recovery_case(
            CEREMONY_ID,
            case_id="case-2",
            authority_slot=1,
            kind="LOST",
            intent_hash="0x" + "aa" * 32,
            intent={"schemaVersion": 1, "slot": 1},
            execute_after=604_900,
            expires_at=700_000,
            prepared_by="0x" + "bb" * 20,
            now=101,
        )

    store.add_recovery_approval(
        "case-1",
        actor_role="AUTHORITY",
        actor_id="slot-0",
        signer_slot=0,
        signer_address="0x" + "99" * 20,
        signature="0x" + "cc" * 65,
        message_hash=INTENT_HASH,
        now=102,
    )
    store.add_recovery_receipt(
        "case-1",
        chain="CHIA",
        transaction_id="0x" + "dd" * 32,
        receipt_hash="0x" + "ee" * 32,
        receipt={"confirmed": True},
        now=103,
    )
    with pytest.raises(GenesisConflict, match="already recorded"):
        store.add_recovery_receipt(
            "case-1",
            chain="CHIA",
            transaction_id="0x" + "ff" * 32,
            receipt_hash="0x" + "00" * 32,
            receipt={"confirmed": True},
            now=104,
        )
