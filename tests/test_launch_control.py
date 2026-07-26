from __future__ import annotations

import json

from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI
from fastapi.testclient import TestClient

import solslot_api.launch_control as launch_control_module
from solslot_api.config import Settings, get_settings
from solslot_api.genesis import get_genesis_store
from solslot_api.genesis_store import GenesisStore
from solslot_api.launch_control import router


ADMIN_TOKEN = "deployment-owner-link-token-that-is-long-enough"
SOURCE_KEYS = (
    "protocol",
    "evm",
    "omnichain",
    "api",
    "legacyBackend",
    "keyOfSolomon",
    "samuel",
    "customerWeb",
    "adminPortal",
)


def _sign(account, typed_data: dict) -> str:
    signed = account.sign_message(encode_typed_data(full_message=typed_data))
    return "0x" + bytes(signed.signature).hex()


def _client(tmp_path) -> tuple[TestClient, GenesisStore, Settings]:
    evidence = {
        "schemaVersion": 8,
        "network": "testnet11",
        "testOnly": True,
        "completeReleaseManifest": True,
        "releaseTag": "solslot-v2-alpha-rc21-20260725",
        "manifestHash": "0x" + "aa" * 32,
        "sourceManifest": {
            "sourceShas": {
                name: f"{index:x}" * 40
                for index, name in enumerate(SOURCE_KEYS, start=1)
            }
        },
    }
    evidence_path = tmp_path / "source-freeze.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        launch_control_enabled=True,
        launch_source_evidence_path=str(evidence_path),
        launch_source_evidence_sha256=None,
        launch_session_secret="launch-session-secret-for-tests!",
        launch_cookie_path="/admin/launch",
        bootstrap_cookie_secure=False,
        admin_token=ADMIN_TOKEN,
        genesis_db_path=str(tmp_path / "genesis.db"),
        genesis_output_dir=str(tmp_path / "ceremonies"),
    )
    store = GenesisStore(settings.genesis_db_path)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_genesis_store] = lambda: store
    return TestClient(app), store, settings


def _claim_and_enroll_owner(client: TestClient):
    owner = Account.create("launch-owner")
    claimed = client.post(
        "/admin/launch/claim",
        json={
            "token": ADMIN_TOKEN,
            "displayName": "Owner Admin",
            "email": "owner@example.com",
            "timezone": "America/Chicago",
        },
    )
    assert claimed.status_code == 200, claimed.text
    token = claimed.json()["ownerEnrollmentToken"]
    prepared = client.post(
        "/admin/launch/invitations/prepare",
        json={"token": token, "wallet": owner.address},
    )
    assert prepared.status_code == 200, prepared.text
    accepted = client.post(
        "/admin/launch/invitations/accept",
        json={
            "token": token,
            "wallet": owner.address,
            "signature": _sign(owner, prepared.json()["typedData"]),
        },
    )
    assert accepted.status_code == 200, accepted.text
    challenge = client.post(
        "/admin/launch/auth/challenge", json={"wallet": owner.address}
    )
    assert challenge.status_code == 200, challenge.text
    login = client.post(
        "/admin/launch/auth/login",
        json={
            "wallet": owner.address,
            "nonce": challenge.json()["nonce"],
            "signature": _sign(owner, challenge.json()["typedData"]),
        },
    )
    assert login.status_code == 200, login.text
    return owner, claimed.json()["ceremonyId"]


def _enroll_coadmin(client: TestClient, slot: int = 2):
    coadmin = Account.create(f"launch-coadmin-{slot}")
    invited = client.post(
        f"/admin/launch/invitations/{slot}",
        json={
            "displayName": f"Coadministrator {slot}",
            "timezone": "America/Chicago",
            "remindersEnabled": True,
        },
    )
    assert invited.status_code == 200, invited.text
    token = invited.json()["invitationFragment"].split("=", 1)[1]
    prepared = client.post(
        "/admin/launch/invitations/prepare",
        json={"token": token, "wallet": coadmin.address},
    )
    assert prepared.status_code == 200, prepared.text
    accepted = client.post(
        "/admin/launch/invitations/accept",
        json={
            "token": token,
            "wallet": coadmin.address,
            "signature": _sign(coadmin, prepared.json()["typedData"]),
        },
    )
    assert accepted.status_code == 200, accepted.text
    challenge = client.post(
        "/admin/launch/auth/challenge", json={"wallet": coadmin.address}
    )
    assert challenge.status_code == 200, challenge.text
    login = client.post(
        "/admin/launch/auth/login",
        json={
            "wallet": coadmin.address,
            "nonce": challenge.json()["nonce"],
            "signature": _sign(coadmin, challenge.json()["typedData"]),
        },
    )
    assert login.status_code == 200, login.text
    return coadmin


def test_owner_link_is_single_use_and_scrubbed_into_http_only_session(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    claimed = client.post(
        "/admin/launch/claim",
        json={"token": ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert claimed.status_code == 200, claimed.text
    cookie = claimed.headers["set-cookie"]
    assert "solslot_launch_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/admin/launch" in cookie
    assert ADMIN_TOKEN not in cookie
    assert store.active()["invitations"][0]["slot"] == 1

    repeated = client.post(
        "/admin/launch/claim",
        json={"token": ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert repeated.status_code == 409
    assert "already consumed" in repeated.json()["detail"]


def test_enrolled_wallet_resumes_without_token_or_ceremony_id(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    owner, ceremony_id = _claim_and_enroll_owner(client)
    workspace = client.get("/admin/launch/workspace")
    assert workspace.status_code == 200, workspace.text
    body = workspace.json()
    assert body["session"]["slot"] == 1
    assert body["session"]["role"] == "owner"
    assert body["launch"]["ceremonyId"] == ceremony_id
    assert body["launch"]["administrators"][0]["enrolled"] is True
    assert body["notice"] == "TESTNET, NO REAL INVESTMENT OR LEGAL RIGHT."

    attacker = Account.create("wrong-wallet")
    rejected = client.post(
        "/admin/launch/auth/challenge", json={"wallet": attacker.address}
    )
    assert rejected.status_code == 403
    assert owner.address.lower() not in rejected.text.lower()


def test_owner_creates_named_coadmin_link_without_exposing_stored_secret(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    _, ceremony_id = _claim_and_enroll_owner(client)
    invited = client.post(
        "/admin/launch/invitations/2",
        json={
            "displayName": "Technical Admin",
            "email": "technical@example.com",
            "timezone": "America/New_York",
            "remindersEnabled": True,
        },
    )
    assert invited.status_code == 200, invited.text
    body = invited.json()
    assert body["slot"] == 2
    assert body["invitationFragment"].startswith("#launch-invite=")
    assert body["profile"]["displayName"] == "Technical Admin"
    persisted = store.get(ceremony_id)
    serialized = json.dumps(persisted)
    assert body["invitationFragment"].split("=", 1)[1] not in serialized


def test_setup_cookie_cannot_issue_coadmin_invites_before_owner_wallet_enrollment(
    tmp_path,
) -> None:
    client, _, _ = _client(tmp_path)
    claimed = client.post(
        "/admin/launch/claim",
        json={"token": ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert claimed.status_code == 200
    rejected = client.post(
        "/admin/launch/invitations/2",
        json={"displayName": "Admin 2"},
    )
    assert rejected.status_code == 401
    assert "Finish owner enrollment" in rejected.json()["detail"]


def test_owner_setup_cookie_can_replace_a_lost_enrollment_secret(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    claimed = client.post(
        "/admin/launch/claim",
        json={"token": ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert claimed.status_code == 200
    original = claimed.json()["ownerEnrollmentToken"]

    replacement = client.post("/admin/launch/owner/enrollment")

    assert replacement.status_code == 200, replacement.text
    new_token = replacement.json()["ownerEnrollmentToken"]
    assert new_token != original
    persisted = json.dumps(store.active())
    assert original not in persisted
    assert new_token not in persisted
    rejected = client.post(
        "/admin/launch/invitations/prepare",
        json={"token": original, "wallet": Account.create().address},
    )
    assert rejected.status_code == 404


def test_settlement_rehearsal_is_coadmin_only_and_exposes_fixed_transaction(
    tmp_path, monkeypatch
) -> None:
    client, store, _ = _client(tmp_path)
    _, ceremony_id = _claim_and_enroll_owner(client)
    rejected = client.post("/admin/launch/settlement-rehearsal/start")
    assert rejected.status_code == 403
    assert "coadministrator" in rejected.json()["detail"]

    _enroll_coadmin(client)

    async def fake_start(_settings, *, ceremony_id, release_evidence_hash):
        assert ceremony_id
        assert release_evidence_hash.startswith("0x")
        return {
            "jobId": "rehearsal_job_0001",
            "state": "AWAITING_WALLET",
            "configHash": "0x" + "ab" * 32,
            "step": "Review the fixed test purchase",
            "message": "No real funds move.",
            "walletTransaction": {
                "chainId": 84532,
                "to": "0x" + "12" * 20,
                "value": "0x0",
                "data": "0x1234",
            },
        }

    monkeypatch.setattr(launch_control_module, "start_rehearsal", fake_start)
    started = client.post("/admin/launch/settlement-rehearsal/start")
    assert started.status_code == 200, started.text
    result = started.json()
    assert result["status"]["state"] == "AWAITING_WALLET"
    assert result["status"]["walletTransaction"]["chainId"] == 84532
    assert result["decisionReceipt"]["requiredApprovers"].startswith("One enrolled")
    assert store.settlement_rehearsal(ceremony_id)["state"] == "AWAITING_WALLET"


def test_settlement_rehearsal_submission_is_bound_to_persisted_job(
    tmp_path, monkeypatch
) -> None:
    client, store, _ = _client(tmp_path)
    _, ceremony_id = _claim_and_enroll_owner(client)
    _enroll_coadmin(client)
    store.set_settlement_rehearsal(
        ceremony_id,
        job_id="rehearsal_job_0001",
        config_hash="0x" + "ab" * 32,
        state="AWAITING_WALLET",
        payload={"state": "AWAITING_WALLET"},
    )

    async def fake_submit(_settings, *, job_id, transaction_hash):
        assert job_id == "rehearsal_job_0001"
        assert transaction_hash == "0x" + "cd" * 32
        return {
            "jobId": job_id,
            "state": "VALIDATING",
            "configHash": "0x" + "ab" * 32,
            "step": "Validators are checking delivery and refund",
            "message": "",
            "walletTransaction": None,
        }

    monkeypatch.setattr(
        launch_control_module, "submit_rehearsal_transaction", fake_submit
    )
    submitted = client.post(
        "/admin/launch/settlement-rehearsal/transaction",
        json={"transactionHash": "0x" + "cd" * 32},
    )
    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["status"]["state"] == "VALIDATING"
    assert store.settlement_rehearsal(ceremony_id)["state"] == "VALIDATING"
