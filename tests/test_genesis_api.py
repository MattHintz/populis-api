from __future__ import annotations

import hashlib
import json

from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI
from fastapi.testclient import TestClient
from chia_rs import AugSchemeMPL

import solslot_api.genesis as genesis_module
from solslot_api.config import Settings, get_settings
from solslot_api.genesis import get_genesis_store, router
from solslot_api.genesis_store import GenesisStore


ADMIN_TOKEN = "test-ceremony-operator-token"
SOURCE_NAMES = (
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


def _source_shas() -> dict[str, str]:
    return {
        name: f"{index:x}" * 40
        for index, name in enumerate(SOURCE_NAMES, start=1)
    }


def _signature(account, typed_data: dict) -> str:
    signed = account.sign_message(encode_typed_data(full_message=typed_data))
    return "0x" + bytes(signed.signature).hex()


def _client(tmp_path) -> tuple[TestClient, GenesisStore, Settings]:
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        alpha_writes_enabled=True,
        minting_enabled=False,
        ceremony_mode_enabled=True,
        admin_token=ADMIN_TOKEN,
        genesis_db_path=str(tmp_path / "genesis.db"),
        genesis_output_dir=str(tmp_path / "ceremonies"),
        genesis_audit_approval_path=str(tmp_path / "approval.json"),
        cors_origins="",
    )
    store = GenesisStore(settings.genesis_db_path)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_genesis_store] = lambda: store
    return TestClient(app), store, settings


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def _create_and_enroll(client: TestClient) -> tuple[str, list]:
    commits = _source_shas()
    response = client.post(
        "/admin/genesis/drafts",
        json={
            "sourceShas": commits,
            "reviewClass": "internal-engineering-testnet",
        },
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    ceremony_id = response.json()["ceremony_id"]
    assert response.json()["draft"]["reviewClass"] == "internal-engineering-testnet"
    assert response.json()["draft"]["sourceManifestVersion"] == 3
    accounts = [Account.create(f"admin-{slot}") for slot in (1, 2, 3)]
    for slot, account in enumerate(accounts, start=1):
        issued = client.post(
            f"/admin/genesis/{ceremony_id}/invitations/{slot}",
            headers=_headers(),
        )
        assert issued.status_code == 200, issued.text
        token = issued.json()["invitationFragment"].split("=", 1)[1]
        prepared = client.post(
            "/admin/genesis/invitations/prepare",
            json={"token": token, "wallet": account.address},
        )
        assert prepared.status_code == 200, prepared.text
        accepted = client.post(
            "/admin/genesis/invitations/accept",
            json={
                "token": token,
                "wallet": account.address,
                "signature": _signature(account, prepared.json()["typedData"]),
            },
        )
        assert accepted.status_code == 200, accepted.text
    frozen = client.post(
        f"/admin/genesis/{ceremony_id}/roster/freeze", headers=_headers()
    )
    assert frozen.status_code == 200, frozen.text
    assert frozen.json()["state"] == "roster_frozen"
    return ceremony_id, accounts


def _plan_body() -> dict:
    funding_names = (
        "sgt",
        "pool",
        "did",
        "governance",
        "statutes",
        "protocolConfig",
        "adminAuthority",
        "vaultVersionRegistry",
        "bridgeBatch",
    )
    validators = [
        bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1()).hex()
        for index in (21, 22, 23)
    ]
    governance = bytes(AugSchemeMPL.key_gen(b"g" * 32).get_g1()).hex()
    kos_mint_execute = bytes(AugSchemeMPL.key_gen(b"k" * 32).get_g1()).hex()
    return {
        "evmAddresses": {
            "forwarder": "0x" + "a1" * 20,
            "verifierAdapter": "0x" + "a2" * 20,
            "attestationEmitter": "0x" + "a3" * 20,
        },
        "fundingCoinIds": {
            name: "0x" + f"{index:02x}" * 32
            for index, name in enumerate(funding_names, start=1)
        },
        "faucetPuzzleHash": "0x" + "31" * 32,
        "governanceBlsPubkey": "0x" + governance,
        "kosMintExecutePubkey": "0x" + kos_mint_execute,
        "validatorPubkeys": ["0x" + value for value in validators],
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


def _approve_plan(
    client: TestClient,
    ceremony_id: str,
    accounts: list,
) -> None:
    created = client.post(
        f"/admin/genesis/{ceremony_id}/plan",
        json=_plan_body(),
        headers=_headers(),
    )
    assert created.status_code == 200, created.text
    typed_data = created.json()["typedData"]
    assert typed_data["primaryType"] == "SolslotGenesisPlan"
    for slot, account in enumerate(accounts[:2], start=1):
        prepared = client.post(
            f"/admin/genesis/{ceremony_id}/plan/signatures/prepare",
            json={"slot": slot},
        )
        assert prepared.status_code == 200, prepared.text
        assert prepared.json()["typedData"] == typed_data
        assert prepared.json()["slot"] == slot
        signed = client.post(
            f"/admin/genesis/{ceremony_id}/plan/signatures",
            json={
                "slot": slot,
                "signature": _signature(account, prepared.json()["typedData"]),
            },
        )
        assert signed.status_code == 200, signed.text


def test_three_admin_http_flow_reaches_plan_approval(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    ceremony_id, accounts = _create_and_enroll(client)
    _approve_plan(client, ceremony_id, accounts)
    final = store.get(ceremony_id)
    assert final["state"] == "plan_approved"
    assert len(final["plan_signatures"]) == 2
    assert final["plan"]["schema"] == "solslot-genesis-plan-v3"
    assert final["plan"]["protocolVersion"] == "solslot-v2-rc22"
    assert "statutes" in final["plan"]["launcherIds"]
    assert "navRegistry" not in final["plan"]["launcherIds"]
    assert final["plan"]["bridgeBatch"]["fundingAmount"] == 529


def test_plan_rejects_retired_nav_registry_and_rc21_parameters(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    ceremony_id, _ = _create_and_enroll(client)
    body = _plan_body()
    body["fundingCoinIds"]["navRegistry"] = body["fundingCoinIds"].pop(
        "statutes"
    )
    body["protocolParameters"]["minNavRegistryVersion"] = 1

    response = client.post(
        f"/admin/genesis/{ceremony_id}/plan",
        json=body,
        headers=_headers(),
    )

    assert response.status_code == 422
    assert "statutes" in response.text
    assert "navRegistry" in response.text


def test_broadcast_requires_fee_funded_local_mempool_submission(
    tmp_path, monkeypatch
) -> None:
    client, store, _ = _client(tmp_path)
    ceremony_id, accounts = _create_and_enroll(client)
    _approve_plan(client, ceremony_id, accounts)
    protocol_bundle = {
        "coin_spends": [{"coin": {"amount": 529}}],
        "aggregated_signature": "0xc0",
    }

    async def fake_prepare_bundle(_settings, record):
        return (
            record["plan"],
            {
                "spendBundleId": "0x" + "aa" * 32,
                "spendCount": 49,
                "spendBundle": protocol_bundle,
            },
            {"reviewClass": "internal-engineering-testnet"},
            (),
        )

    monkeypatch.setattr(genesis_module, "_prepare_bundle", fake_prepare_bundle)
    missing = client.post(
        f"/admin/genesis/{ceremony_id}/broadcast",
        headers=_headers(),
    )
    assert missing.status_code == 409
    assert "local-node medium-fee funding" in missing.text
    assert store.get(ceremony_id)["state"] == "plan_approved"

    class FakeSubmitter:
        submitted: dict | None = None

        async def submit(self, bundle):
            self.submitted = bundle
            return {
                "schemaVersion": 1,
                "status": "MEMPOOL",
                "network": "testnet11",
                "spendBundleId": "0x" + "bb" * 32,
                "feeMojos": "7",
                "feeTargetSeconds": 300,
                "feeCoinId": "0x" + "cc" * 32,
                "feeTillPuzzleHash": "0x" + "dd" * 32,
                "submissionProvider": "local-full-node",
                "mempoolObservedAt": "2026-07-27T12:00:00+00:00",
                "ambiguousPushRecovered": False,
                "spendBundle": {
                    "coin_spends": [
                        *protocol_bundle["coin_spends"],
                        {"coin": {"amount": 100}},
                    ],
                    "aggregated_signature": "0xc1",
                },
            }

    submitter = FakeSubmitter()
    client.app.state.protocol_submitter = submitter
    accepted = client.post(
        f"/admin/genesis/{ceremony_id}/broadcast",
        headers=_headers(),
    )

    assert accepted.status_code == 200, accepted.text
    assert submitter.submitted == protocol_bundle
    assert accepted.json()["state"] == "broadcast"
    assert accepted.json()["spend_bundle_id"] == "0x" + "bb" * 32
    assert "spendBundle" not in accepted.json()["broadcast"]
    assert store.get(ceremony_id)["broadcast"]["spendBundle"]
    output = (
        tmp_path
        / "ceremonies"
        / ceremony_id.removeprefix("0x")
    )
    archived_bundle = json.loads(
        (output / "spend_bundle.json").read_text(encoding="utf-8")
    )
    assert len(archived_bundle["coin_spends"]) == 2
    fee_receipt = json.loads(
        (output / "fee_receipt.json").read_text(encoding="utf-8")
    )
    assert fee_receipt["feeMojos"] == "7"
    assert "spendBundle" not in fee_receipt


def test_preflight_returns_canonical_review_approval_for_offline_gate(
    tmp_path, monkeypatch
) -> None:
    client, store, _ = _client(tmp_path)
    ceremony_id, accounts = _create_and_enroll(client)
    created = client.post(
        f"/admin/genesis/{ceremony_id}/plan",
        json=_plan_body(),
        headers=_headers(),
    )
    assert created.status_code == 200, created.text
    for slot, account in enumerate(accounts[:2], start=1):
        prepared = client.post(
            f"/admin/genesis/{ceremony_id}/plan/signatures/prepare",
            json={"slot": slot},
        )
        signed = client.post(
            f"/admin/genesis/{ceremony_id}/plan/signatures",
            json={
                "slot": slot,
                "signature": _signature(account, prepared.json()["typedData"]),
            },
        )
        assert signed.status_code == 200, signed.text

    approval = {
        "schemaVersion": 2,
        "sourceManifestVersion": 3,
        "reviewClass": "internal-engineering-testnet",
        "auditStatus": "unaudited",
        "testOnly": True,
        "ceremonyId": ceremony_id,
    }
    spend_bundle_id = "0x" + "ab" * 32

    async def fake_prepare_bundle(settings, record):
        del settings
        return (
            record["plan"],
            {"spendBundleId": spend_bundle_id, "spendCount": 9},
            approval,
            (),
        )

    monkeypatch.setattr(genesis_module, "_prepare_bundle", fake_prepare_bundle)
    response = client.post(
        f"/admin/genesis/{ceremony_id}/preflight",
        headers=_headers(),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ready"] is True
    assert body["reviewApproval"] == approval
    assert body["auditApprovalHash"] == "0x" + hashlib.sha256(
        json.dumps(approval, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_wrong_admin_cannot_sign_frozen_plan(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    ceremony_id, _ = _create_and_enroll(client)
    created = client.post(
        f"/admin/genesis/{ceremony_id}/plan",
        json=_plan_body(),
        headers=_headers(),
    )
    typed_data = created.json()["typedData"]
    attacker = Account.create("not-an-admin")
    response = client.post(
        f"/admin/genesis/{ceremony_id}/plan/signatures",
        json={"slot": 1, "signature": _signature(attacker, typed_data)},
    )
    assert response.status_code == 403


def test_operator_routes_require_ceremony_token(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    response = client.post(
        "/admin/genesis/drafts",
        json={
            "sourceShas": _source_shas()
        },
    )
    assert response.status_code == 401


def test_draft_rejects_unknown_review_class(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    response = client.post(
        "/admin/genesis/drafts",
        json={
            "sourceShas": _source_shas(),
            "reviewClass": "self-approved-mainnet",
        },
        headers=_headers(),
    )
    assert response.status_code == 422


def test_draft_rejects_retired_six_repository_source_set(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    retired = {
        key: value
        for key, value in _source_shas().items()
        if key not in {"omnichain", "keyOfSolomon", "samuel"}
    }
    response = client.post(
        "/admin/genesis/drafts",
        json={"sourceShas": retired},
        headers=_headers(),
    )
    assert response.status_code == 422
    assert "all nine frozen release commits" in response.text
