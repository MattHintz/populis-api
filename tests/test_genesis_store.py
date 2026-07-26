from __future__ import annotations

import pytest

from solslot_api.genesis_store import (
    GenesisConflict,
    GenesisExpired,
    GenesisStore,
    owner_plus_one_approved,
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


def test_settlement_rehearsal_state_is_forward_only_and_payload_is_readable(
    tmp_path,
) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    prepared = store.set_settlement_rehearsal(
        CEREMONY,
        job_id="rehearsal_job_0001",
        config_hash="0x" + "aa" * 32,
        state="AWAITING_WALLET",
        payload={"step": "Review the test purchase"},
        now=110,
    )
    assert prepared["payload"]["step"] == "Review the test purchase"

    validating = store.set_settlement_rehearsal(
        CEREMONY,
        job_id="rehearsal_job_0001",
        config_hash="0x" + "aa" * 32,
        state="VALIDATING",
        payload={"step": "Validators are checking delivery"},
        now=120,
    )
    assert validating["state"] == "VALIDATING"

    with pytest.raises(GenesisConflict, match="move backwards"):
        store.set_settlement_rehearsal(
            CEREMONY,
            job_id="rehearsal_job_0001",
            config_hash="0x" + "aa" * 32,
            state="PAYMENT_SUBMITTED",
            payload={"step": "Stale response"},
            now=121,
        )
def test_guided_launch_owner_claim_profiles_and_wallet_resume_are_persistent(
    tmp_path,
) -> None:
    path = tmp_path / "genesis.db"
    store = GenesisStore(path)
    store.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    store.consume_owner_claim(CEREMONY, token_hash="owner-link", now=101)
    assert store.owner_claim_used("owner-link") is True
    with pytest.raises(GenesisConflict, match="already consumed"):
        store.consume_owner_claim(CEREMONY, token_hash="owner-link", now=102)

    store.set_profile(
        CEREMONY,
        slot=1,
        display_name="Owner",
        role_label="Owner",
        email="owner@example.com",
        timezone="America/Chicago",
        reminders_enabled=True,
        now=103,
    )
    _enroll(store, 1, now=110)
    nonce_hash = "resume-nonce"
    store.create_auth_challenge(
        CEREMONY,
        slot=1,
        wallet_address="0x" + "01" * 20,
        nonce_hash=nonce_hash,
        expires_at=1000,
        now=120,
    )
    reopened = GenesisStore(path)
    challenge = reopened.consume_auth_challenge(
        nonce_hash=nonce_hash,
        wallet_address="0x" + "01" * 20,
        now=121,
    )
    assert challenge["slot"] == 1
    assert reopened.profiles(CEREMONY)[1]["displayName"] == "Owner"
    with pytest.raises(GenesisConflict, match="already used"):
        reopened.consume_auth_challenge(
            nonce_hash=nonce_hash,
            wallet_address="0x" + "01" * 20,
            now=122,
        )


def test_guided_action_requires_owner_plus_one_and_rejects_changed_payload(
    tmp_path,
) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {}, now=100)
    for slot in (1, 2, 3):
        _enroll(store, slot)
    action_id = "0x" + "91" * 32
    payload_hash = "0x" + "92" * 32
    one = store.add_action_approval(
        CEREMONY,
        action_id=action_id,
        action_type="funding",
        payload_hash=payload_hash,
        slot=1,
        signer_address="0x" + "01" * 20,
        signature="0x" + "01" * 65,
        now=130,
    )
    assert one["approved"] is False
    assert owner_plus_one_approved(set(one["slots"])) is False
    two = store.add_action_approval(
        CEREMONY,
        action_id=action_id,
        action_type="funding",
        payload_hash=payload_hash,
        slot=3,
        signer_address="0x" + "03" * 20,
        signature="0x" + "03" * 65,
        now=131,
    )
    assert two["approved"] is True
    with pytest.raises(GenesisConflict, match="already approved"):
        store.add_action_approval(
            CEREMONY,
            action_id=action_id,
            action_type="funding",
            payload_hash="0x" + "99" * 32,
            slot=1,
            signer_address="0x" + "01" * 20,
            signature="0x" + "04" * 65,
            now=132,
        )


def test_guided_gate_expires_fail_closed_and_funding_plan_is_immutable(tmp_path) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {}, now=100)
    payload_hash = "0x" + "82" * 32
    store.upsert_gate(
        CEREMONY,
        gate_name="ceremonyBroadcast",
        opens_at=200,
        closes_at=300,
        payload_hash=payload_hash,
        state="open",
        now=150,
    )
    assert store.gates(CEREMONY, now=250)["ceremonyBroadcast"]["state"] == "open"
    assert store.gates(CEREMONY, now=300)["ceremonyBroadcast"]["state"] == "closed"

    plan = {"sourceCoinId": "0x" + "a1" * 32, "outputs": []}
    store.set_funding_receipt(
        CEREMONY,
        plan=plan,
        plan_hash="0x" + "83" * 32,
        now=160,
    )
    with pytest.raises(GenesisConflict, match="already sealed"):
        store.set_funding_receipt(
            CEREMONY,
            plan={"sourceCoinId": "0x" + "a2" * 32, "outputs": []},
            plan_hash="0x" + "84" * 32,
            now=161,
        )


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
