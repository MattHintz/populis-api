from __future__ import annotations

import json

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI
from fastapi.testclient import TestClient
from chia_rs import AugSchemeMPL

import solslot_api.launch_control as launch_control_module
from solslot_api.config import Settings, get_settings
from solslot_api.genesis import get_genesis_store
from solslot_api.genesis_store import GenesisStore
from solslot_api.launch_control import router


ADMIN_TOKEN = "deployment-owner-link-token-that-is-long-enough"
LEGACY_ADMIN_TOKEN = "legacy-operator-token-that-is-also-long-enough"
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
    release_tag = "solslot-v2-alpha-rc24-20260730"
    release_branch = "release/testnet-alpha-rc24-20260730"
    source_shas = {
        name: f"{index:x}" * 40
        for index, name in enumerate(SOURCE_KEYS, start=1)
    }
    source_manifest = {
        "schemaVersion": 4,
        "kind": "solslot-release-source-manifest",
        "releaseId": release_tag,
        "network": "testnet11",
        "testOnly": True,
        "sourceShas": source_shas,
        "dependencies": {
            "administratorRecovery": {
                "repository": (
                    launch_control_module.PINNED_CNI_WALLET_SDK_REPOSITORY
                ),
                "commit": (
                    launch_control_module.PINNED_CNI_WALLET_SDK_COMMIT
                ),
                "license": (
                    launch_control_module.PINNED_CNI_WALLET_SDK_LICENSE
                ),
                "manifestHash": (
                    launch_control_module
                    .RECOVERY_DEPENDENCY_MANIFEST_HASH_HEX
                ),
            }
        },
        "authoritySourceCommitment": (
            launch_control_module._authority_source_commitment(
                source_shas
            )
        ),
        "sources": {
            name: {
                "repository": f"https://github.com/solslot/{name}",
                "branch": release_branch,
                "commit": source_shas[name],
            }
            for name in SOURCE_KEYS
        },
    }
    source_manifest["manifestHash"] = (
        launch_control_module._source_manifest_hash(source_manifest)
    )
    evidence = {
        "schemaVersion": 5,
        "kind": "solslot-rc24-launch-source-evidence",
        "network": "testnet11",
        "testOnly": True,
        "completeReleaseManifest": True,
        "releaseRefsVerified": True,
        "releaseTag": release_tag,
        "releaseId": release_tag,
        "manifestHash": source_manifest["manifestHash"],
        "sourceManifest": source_manifest,
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
        launch_owner_claim_token=ADMIN_TOKEN,
        launch_cookie_path="/admin/launch",
        bootstrap_cookie_secure=False,
        admin_token=LEGACY_ADMIN_TOKEN,
        genesis_db_path=str(tmp_path / "genesis.db"),
        genesis_output_dir=str(tmp_path / "ceremonies"),
    )
    store = GenesisStore(settings.genesis_db_path)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_genesis_store] = lambda: store
    return TestClient(app), store, settings


def _plan_template(kos_pubkey: bytes) -> dict:
    validator_pubkeys = [
        bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1())
        for index in (21, 22, 23)
    ]
    governance_pubkey = bytes(AugSchemeMPL.key_gen(b"g" * 32).get_g1())
    return {
        "evmAddresses": {
            "forwarder": "0x" + "a1" * 20,
            "verifierAdapter": "0x" + "a2" * 20,
            "attestationEmitter": "0x" + "a3" * 20,
        },
        "faucetPuzzleHash": "0x" + "31" * 32,
        "governanceBlsPubkey": "0x" + governance_pubkey.hex(),
        "kosMintExecutePubkey": "0x" + kos_pubkey.hex(),
        "validatorPubkeys": ["0x" + value.hex() for value in validator_pubkeys],
        "trustedTreasuryReservePuzzleHash": "0x" + "41" * 32,
        "trustedProtocolTreasuryPuzzleHash": "0x" + "42" * 32,
        "trustedGovernanceRewardsPuzzleHash": "0x" + "43" * 32,
        "trustedGovernanceRewardsRoot": "0x" + "44" * 32,
        "retiredCoordinates": ["0x" + "51" * 32],
        "protocolParameters": {
            "votingWindowSeconds": 300,
            "quorumBps": 5000,
            "minProposalStake": 10_000,
            "navValiditySeconds": 86_400,
            "oracleMaxAgeSeconds": 600,
            "exchangeFeeBps": 100,
            "protocolFeeBps": 30,
            "sgtRewardsFeeBps": 70,
            "rewardEpochSeconds": 86_400,
        },
    }


def test_release_evidence_binds_recovery_sdk_and_authority_source(
    tmp_path,
) -> None:
    _, _, settings = _client(tmp_path)
    loaded = launch_control_module._load_release_evidence(settings)
    assert loaded["recoveryDependencyManifestHash"] == (
        launch_control_module.RECOVERY_DEPENDENCY_MANIFEST_HASH_HEX
    )

    path = settings.launch_source_evidence_path
    assert path is not None
    payload = json.loads(open(path, encoding="utf-8").read())
    manifest = payload["sourceManifest"]
    manifest["dependencies"]["administratorRecovery"]["commit"] = (
        "f" * 40
    )
    manifest["manifestHash"] = (
        launch_control_module._source_manifest_hash(manifest)
    )
    payload["manifestHash"] = manifest["manifestHash"]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)

    with pytest.raises(Exception, match="pinned recovery SDK"):
        launch_control_module._load_release_evidence(settings)


def test_release_evidence_rejects_authority_commitment_drift(
    tmp_path,
) -> None:
    _, _, settings = _client(tmp_path)
    path = settings.launch_source_evidence_path
    assert path is not None
    payload = json.loads(open(path, encoding="utf-8").read())
    manifest = payload["sourceManifest"]
    manifest["authoritySourceCommitment"] = "0x" + "ff" * 32
    manifest["manifestHash"] = (
        launch_control_module._source_manifest_hash(manifest)
    )
    payload["manifestHash"] = manifest["manifestHash"]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)

    with pytest.raises(Exception, match="source commitment"):
        launch_control_module._load_release_evidence(settings)


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


def _login(client: TestClient, account) -> None:
    challenge = client.post(
        "/admin/launch/auth/challenge", json={"wallet": account.address}
    )
    assert challenge.status_code == 200, challenge.text
    login = client.post(
        "/admin/launch/auth/login",
        json={
            "wallet": account.address,
            "nonce": challenge.json()["nonce"],
            "signature": _sign(account, challenge.json()["typedData"]),
        },
    )
    assert login.status_code == 200, login.text


def _mark_launch_locked(store: GenesisStore, ceremony_id: str) -> None:
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET state='locked' WHERE ceremony_id=?",
            (ceremony_id,),
        )


def test_owner_link_is_single_use_and_scrubbed_into_http_only_session(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    legacy_credential = client.post(
        "/admin/launch/claim",
        json={"token": LEGACY_ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert legacy_credential.status_code == 403

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
    plan_readiness = next(
        item for item in body["readiness"] if item["id"] == "planInputs"
    )
    assert plan_readiness["status"] == "Blocked"
    assert plan_readiness["action"] == "replacePlanEvidence"
    assert "browser" in plan_readiness["impact"]
    assert "plan-input-template" not in plan_readiness["impact"]

    evm_readiness = next(
        item for item in body["readiness"] if item["id"] == "evmEvidence"
    )
    assert evm_readiness["status"] == "Blocked"
    assert evm_readiness["action"] == "installEvmEvidence"
    assert evm_readiness["evidence"]["deploymentEvidenceInstalled"] is False
    assert evm_readiness["evidence"]["auditApprovalInstalled"] is False

    validator_readiness = next(
        item for item in body["readiness"] if item["id"] == "validators"
    )
    assert validator_readiness["status"] == "Blocked"
    assert validator_readiness["action"] == "configureValidators"
    assert validator_readiness["evidence"]["requiredValidators"] == 3
    assert validator_readiness["evidence"]["configuredValidators"] == 0
    assert body["nextTask"]["action"] == "enrollment"
    assert body["nextTask"]["title"] == "Finish administrator enrollment"

    attacker = Account.create("wrong-wallet")
    rejected = client.post(
        "/admin/launch/auth/challenge", json={"wallet": attacker.address}
    )
    assert rejected.status_code == 403
    assert owner.address.lower() not in rejected.text.lower()


def test_plan_template_rejects_fixture_kos_key_and_accepts_release_key(tmp_path) -> None:
    _, _, settings = _client(tmp_path)
    plan_path = tmp_path / "plan.json"
    settings.launch_plan_template_path = str(plan_path)

    plan_path.write_text(
        json.dumps(
            _plan_template(launch_control_module.TEST_KOS_MINT_EXECUTE_PUBKEY)
        ),
        encoding="utf-8",
    )
    try:
        launch_control_module._plan_template_evidence(settings)
    except Exception as exc:  # noqa: BLE001
        assert "public test fixture key" in str(exc)
    else:
        raise AssertionError("fixture KoS key must not pass release readiness")

    release_key = bytes(AugSchemeMPL.key_gen(b"release-kos-key" * 3).get_g1())
    plan_path.write_text(
        json.dumps(_plan_template(release_key)),
        encoding="utf-8",
    )
    evidence = launch_control_module._plan_template_evidence(settings)
    assert evidence["kosMintExecutePubkey"] == "0x" + release_key.hex()
    assert evidence["validatorCount"] == 3


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

    coadmin = _enroll_coadmin(client)
    before_genesis = client.post("/admin/launch/settlement-rehearsal/start")
    assert before_genesis.status_code == 409
    assert "Complete genesis first" in before_genesis.json()["detail"]
    _mark_launch_locked(store, ceremony_id)

    async def fake_start(
        _settings,
        *,
        ceremony_id,
        release_evidence_hash,
        wallet_address,
    ):
        assert ceremony_id
        assert release_evidence_hash.startswith("0x")
        assert wallet_address == coadmin.address.lower()
        return {
            "jobId": "rehearsal_job_0001",
            "state": "AWAITING_WALLET",
            "configHash": "0x" + "ab" * 32,
            "phase": "APPROVE_DELIVERY",
            "completedSteps": 0,
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
    assert result["status"]["phase"] == "APPROVE_DELIVERY"
    assert result["status"]["walletTransaction"]["chainId"] == 84532
    assert result["decisionReceipt"]["requiredApprovers"].startswith("One enrolled")
    assert store.settlement_rehearsal(ceremony_id)["state"] == "AWAITING_WALLET"


def test_purchase_gate_stays_locked_until_delivery_and_refund_are_proven(
    tmp_path,
) -> None:
    client, store, _ = _client(tmp_path)
    owner, ceremony_id = _claim_and_enroll_owner(client)
    coadmin = _enroll_coadmin(client)
    _mark_launch_locked(store, ceremony_id)
    now = 2_000_000_000
    payload_hash = "0x" + "ab" * 32
    store.upsert_gate(
        ceremony_id,
        gate_name="purchases",
        opens_at=now - 60,
        closes_at=now + 600,
        payload_hash=payload_hash,
        state="pending",
        now=now - 120,
    )
    action_id, _ = launch_control_module._gate_payload(
        store, ceremony_id, "purchases"
    )
    for slot, account in ((1, owner), (2, coadmin)):
        store.add_action_approval(
            ceremony_id,
            action_id=action_id,
            action_type="gate:purchases",
            payload_hash=payload_hash,
            slot=slot,
            signer_address=account.address,
            signature="0x" + f"{slot:02x}" * 65,
            now=now - 100 + slot,
        )
    _login(client, owner)

    activated = client.post("/admin/launch/gates/purchases/activate")

    assert activated.status_code == 409
    assert "delivery and exact-refund test" in activated.json()["detail"]
    assert (
        store.gates(ceremony_id, now=now)["purchases"]["configuredState"]
        == "pending"
    )


def test_settlement_rehearsal_submission_is_bound_to_persisted_job(
    tmp_path, monkeypatch
) -> None:
    client, store, _ = _client(tmp_path)
    _, ceremony_id = _claim_and_enroll_owner(client)
    _enroll_coadmin(client)
    _mark_launch_locked(store, ceremony_id)
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


def test_post_genesis_settlement_does_not_block_ceremony_task_selection() -> None:
    readiness = [
        {
            "id": "settlement",
            "title": "Customer payment test follows launch",
            "status": "Waiting",
            "impact": "Run after genesis.",
            "assignedRole": "technical-coadmin",
            "blocksCeremony": False,
        }
    ]
    before_genesis = launch_control_module._task_for(
        {"state": "roster_frozen", "invitations": [{"consumed_at": 1}] * 3},
        readiness,
    )
    assert before_genesis["action"] == "buildPlan"

    after_genesis = launch_control_module._task_for(
        {"state": "locked", "invitations": [{"consumed_at": 1}] * 3},
        readiness,
    )
    assert after_genesis["title"] == "Customer payment test follows launch"
