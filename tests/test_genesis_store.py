from __future__ import annotations

import pytest

from solslot_api.genesis_store import (
    GenesisConflict,
    GenesisExpired,
    GenesisStore,
)


CEREMONY = "0x" + "11" * 32
ROSTER = "0x" + "22" * 32
PLAN = "0x" + "33" * 32
ARTIFACT = "0x" + "44" * 32


def _enroll(store: GenesisStore, slot: int, now: int = 100) -> None:
    token_hash = f"token-{slot}"
    store.issue_invitation(
        CEREMONY,
        slot=slot,
        token_hash=token_hash,
        nonce=f"nonce-{slot}",
        expires_at=now + 1800,
        now=now,
    )
    store.consume_invitation(
        token_hash=token_hash,
        wallet_address="0x" + f"{slot:02x}" * 20,
        compressed_pubkey="0x" + f"{slot:02x}" * 33,
        signature="0x" + f"{slot:02x}" * 65,
        now=now + 1,
    )


def _planned_store(tmp_path) -> GenesisStore:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    for slot in (1, 2, 3):
        _enroll(store, slot)
    store.freeze_roster(CEREMONY, ROSTER, now=110)
    store.set_plan(
        CEREMONY,
        plan_input={"funding": []},
        plan={"planHash": PLAN},
        plan_hash=PLAN,
        expires_at=1000,
        now=120,
    )
    return store


def test_three_single_use_invitations_freeze_roster(tmp_path) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    for slot in (1, 2, 3):
        _enroll(store, slot)
    frozen = store.freeze_roster(CEREMONY, ROSTER, now=110)
    assert frozen["state"] == "roster_frozen"
    assert frozen["roster_hash"] == ROSTER
    with pytest.raises(GenesisConflict, match="already consumed"):
        store.consume_invitation(
            token_hash="token-1",
            wallet_address="0x" + "01" * 20,
            compressed_pubkey="0x" + "01" * 33,
            signature="0x" + "01" * 65,
            now=111,
        )


def test_roster_cannot_freeze_early_or_reuse_wallet(tmp_path) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {}, now=100)
    _enroll(store, 1)
    with pytest.raises(GenesisConflict, match="all three"):
        store.freeze_roster(CEREMONY, ROSTER, now=110)
    store.issue_invitation(
        CEREMONY,
        slot=2,
        token_hash="token-2",
        nonce="nonce-2",
        expires_at=1000,
        now=100,
    )
    with pytest.raises(GenesisConflict, match="already enrolled"):
        store.consume_invitation(
            token_hash="token-2",
            wallet_address="0x" + "01" * 20,
            compressed_pubkey="0x" + "02" * 33,
            signature="0x" + "02" * 65,
            now=101,
        )


def test_owner_plus_one_plan_signatures_unlock_broadcast(tmp_path) -> None:
    store = _planned_store(tmp_path)
    one = store.add_plan_signature(
        CEREMONY,
        slot=1,
        plan_hash=PLAN,
        compressed_pubkey="0x" + "01" * 33,
        signature="0x" + "01" * 65,
        now=130,
    )
    assert one["state"] == "planned"
    with pytest.raises(GenesisConflict, match="already signed"):
        store.add_plan_signature(
            CEREMONY,
            slot=1,
            plan_hash=PLAN,
            compressed_pubkey="0x" + "01" * 33,
            signature="0x" + "01" * 65,
            now=131,
        )
    two = store.add_plan_signature(
        CEREMONY,
        slot=2,
        plan_hash=PLAN,
        compressed_pubkey="0x" + "02" * 33,
        signature="0x" + "02" * 65,
        now=132,
    )
    assert two["state"] == "plan_approved"
    broadcast = store.mark_broadcast(
        CEREMONY,
        spend_bundle_id="0x" + "55" * 32,
        response={"success": True},
        now=133,
    )
    assert broadcast["state"] == "broadcast"


def test_two_coadmins_cannot_approve_plan_without_owner(tmp_path) -> None:
    store = _planned_store(tmp_path)
    for slot in (2, 3):
        result = store.add_plan_signature(
            CEREMONY,
            slot=slot,
            plan_hash=PLAN,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=130 + slot,
        )
    assert result["state"] == "planned"
    with pytest.raises(GenesisConflict, match="expected plan_approved"):
        store.mark_broadcast(
            CEREMONY,
            spend_bundle_id="0x" + "55" * 32,
            response={"success": True},
            now=140,
        )


def test_expired_plan_and_mutated_hash_fail_closed(tmp_path) -> None:
    store = _planned_store(tmp_path)
    with pytest.raises(GenesisConflict, match="current plan"):
        store.add_plan_signature(
            CEREMONY,
            slot=1,
            plan_hash="0x" + "99" * 32,
            compressed_pubkey="0x" + "01" * 33,
            signature="0x" + "01" * 65,
            now=130,
        )
    with pytest.raises(GenesisExpired, match="expired"):
        store.add_plan_signature(
            CEREMONY,
            slot=1,
            plan_hash=PLAN,
            compressed_pubkey="0x" + "01" * 33,
            signature="0x" + "01" * 65,
            now=1001,
        )


def test_artifact_requires_two_roster_signatures_before_lock(tmp_path) -> None:
    store = _planned_store(tmp_path)
    for slot in (1, 2):
        store.add_plan_signature(
            CEREMONY,
            slot=slot,
            plan_hash=PLAN,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=130 + slot,
        )
    store.mark_broadcast(
        CEREMONY,
        spend_bundle_id="0x" + "55" * 32,
        response={"success": True},
        now=140,
    )
    store.mark_confirmed(CEREMONY, confirmed_block_index=500, now=150)
    store.set_artifact(
        CEREMONY,
        artifact={"artifactHash": ARTIFACT},
        artifact_hash=ARTIFACT,
        now=160,
    )
    first = store.add_artifact_signature(
        CEREMONY,
        slot=1,
        artifact_hash=ARTIFACT,
        compressed_pubkey="0x" + "01" * 33,
        signature="0x" + "01" * 65,
        now=170,
    )
    assert first["state"] == "artifact_pending"
    with pytest.raises(GenesisConflict, match="expected artifact_signed"):
        store.mark_locked(CEREMONY, now=171)
    store.add_artifact_signature(
        CEREMONY,
        slot=3,
        artifact_hash=ARTIFACT,
        compressed_pubkey="0x" + "03" * 33,
        signature="0x" + "03" * 65,
        now=172,
    )
    assert store.mark_locked(CEREMONY, now=173)["state"] == "locked"


def test_two_coadmins_cannot_sign_artifact_without_owner(tmp_path) -> None:
    store = _planned_store(tmp_path)
    for slot in (1, 2):
        store.add_plan_signature(
            CEREMONY,
            slot=slot,
            plan_hash=PLAN,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=130 + slot,
        )
    store.mark_broadcast(
        CEREMONY,
        spend_bundle_id="0x" + "55" * 32,
        response={"success": True},
        now=140,
    )
    store.mark_confirmed(CEREMONY, confirmed_block_index=500, now=150)
    store.set_artifact(
        CEREMONY,
        artifact={"artifactHash": ARTIFACT},
        artifact_hash=ARTIFACT,
        now=160,
    )
    for slot in (2, 3):
        result = store.add_artifact_signature(
            CEREMONY,
            slot=slot,
            artifact_hash=ARTIFACT,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=170 + slot,
        )
    assert result["state"] == "artifact_pending"
    with pytest.raises(GenesisConflict, match="expected artifact_signed"):
        store.mark_locked(CEREMONY, now=180)
