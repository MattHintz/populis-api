from __future__ import annotations

from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi.testclient import TestClient

from populis_api.app import app
from populis_api import zkpassport_enrollments


VAULT_A = "0x" + "11" * 32
VAULT_B = "0x" + "22" * 32
VAULT_C = "0x" + "33" * 32
PARENT_A = "0x" + "aa" * 32
PARENT_B = "0x" + "bb" * 32
POLICY_HASH = "0x" + "c1" * 32
ROOT = "0x" + "44" * 32
LEAF = "0x" + "55" * 32
TX = "0x" + "66" * 32
VALIDATOR_MESSAGE = "0x" + "88" * 32
VALIDATOR_SEED_HEX = "bd15624be42c1cd1c51dd4a440bff40a4a3466f716f9e13149d3422767876ad7"
VAULT_COIN_PARENT = "0x" + "99" * 32
VAULT_COIN_PUZZLE = "0x" + "d1" * 32


def _coin_id(parent: str, policy_hash: str, amount: int = 1) -> str:
    return "0x" + Coin(
        bytes32.fromhex(parent.removeprefix("0x")),
        bytes32.fromhex(policy_hash.removeprefix("0x")),
        uint64(amount),
    ).name().hex()


def _client(monkeypatch, tmp_path, parents: str = "") -> TestClient:
    monkeypatch.setenv("POPULIS_ZKPASSPORT_ENROLLMENT_STORE_PATH", str(tmp_path / "enrollments.json"))
    monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_PARENT_IDS", parents)
    monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_POLICY_HASH", POLICY_HASH)
    monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_AMOUNT", "1")
    return TestClient(app)


def test_create_enrollment_fails_closed_without_bridge_pool(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, parents="") as client:
        resp = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})

    assert resp.status_code == 503
    assert "bridge coin pool" in resp.json()["detail"]


def test_create_enrollment_reserves_bridge_coin_and_gets_same_record(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, parents=f"{PARENT_A},{PARENT_B}") as client:
        created = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
        again = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
        fetched = client.get(f"/zkpassport/enrollments/{VAULT_A}")

    assert created.status_code == 200
    body = created.json()
    assert body["status"] == "reserved"
    assert body["bridgeParentId"] == PARENT_A
    assert body["bridgePolicyHash"] == POLICY_HASH
    assert body["bridgeCoinId"] == _coin_id(PARENT_A, POLICY_HASH)
    assert again.json()["bridgeParentId"] == PARENT_A
    assert fetched.json()["vaultLauncherId"] == VAULT_A


def test_bridge_coin_pool_is_single_use(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, parents=f"{PARENT_A},{PARENT_B}") as client:
        first = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
        second = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_B})
        third = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_C})

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["bridgeParentId"] == PARENT_B
    assert third.status_code == 409


def test_record_proof_and_chia_confirmation(monkeypatch, tmp_path):
    vault_coin_id = _coin_id(VAULT_COIN_PARENT, VAULT_COIN_PUZZLE)
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_expected_stamped_vault_puzzle_hash",
        lambda _settings, **_kwargs: VAULT_COIN_PUZZLE,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_coin_record_by_name",
        lambda _settings, coin_id: {
            "coin": {
                "parent_coin_info": VAULT_COIN_PARENT,
                "puzzle_hash": VAULT_COIN_PUZZLE,
                "amount": 1,
            },
            "confirmed_block_index": 123,
            "spent_block_index": 0,
        }
        if coin_id == vault_coin_id
        else None,
    )
    with _client(monkeypatch, tmp_path, parents=PARENT_A) as client:
        enrollment = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}).json()
        proof = client.post(
            f"/zkpassport/enrollments/{VAULT_A}/proof",
            json={
                "vaultLauncherId": VAULT_A,
                "policyVersion": 1,
                "identityAttestRoot": ROOT,
                "attestationLeafHash": LEAF,
                "attestationProof": {"bitpath": 0, "siblings": []},
                "bridgePolicyHash": enrollment["bridgePolicyHash"],
                "bridgeParentId": enrollment["bridgeParentId"],
                "bridgeAmount": enrollment["bridgeAmount"],
                "bridgeCoinId": enrollment["bridgeCoinId"],
                "bridgeMessage": "0x" + "99" * 32,
                "validatorMessage": VALIDATOR_MESSAGE,
                "evmTxHash": TX,
            },
        )
        confirmed = client.post(
            f"/zkpassport/enrollments/{VAULT_A}/chia-confirmation",
            json={
                "chiaVaultCoinId": vault_coin_id,
                "confirmedBlockIndex": 123,
            },
        )

    assert proof.status_code == 200
    assert proof.json()["status"] == "evm_confirmed"
    assert proof.json()["receipt"]["identityAttestRoot"] == ROOT
    assert proof.json()["receipt"]["validatorMessage"] == VALIDATOR_MESSAGE
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "chia_confirmed"
    assert confirmed.json()["receipt"]["confirmedBlockIndex"] == 123


def test_chia_confirmation_rejects_client_only_coin_claim(monkeypatch, tmp_path):
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_expected_stamped_vault_puzzle_hash",
        lambda _settings, **_kwargs: VAULT_COIN_PUZZLE,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_coin_record_by_name",
        lambda _settings, _coin_id: None,
    )
    with _client(monkeypatch, tmp_path, parents=PARENT_A) as client:
        enrollment = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}).json()
        client.post(
            f"/zkpassport/enrollments/{VAULT_A}/proof",
            json={
                "vaultLauncherId": VAULT_A,
                "policyVersion": 1,
                "identityAttestRoot": ROOT,
                "attestationLeafHash": LEAF,
                "attestationProof": {"bitpath": 0, "siblings": []},
                "bridgePolicyHash": enrollment["bridgePolicyHash"],
                "bridgeParentId": enrollment["bridgeParentId"],
                "bridgeAmount": enrollment["bridgeAmount"],
                "bridgeCoinId": enrollment["bridgeCoinId"],
                "bridgeMessage": "0x" + "99" * 32,
                "validatorMessage": VALIDATOR_MESSAGE,
                "evmTxHash": TX,
            },
        )
        confirmed = client.post(
            f"/zkpassport/enrollments/{VAULT_A}/chia-confirmation",
            json={
                "chiaVaultCoinId": "0x" + "77" * 32,
                "confirmedBlockIndex": 123,
            },
        )

    assert confirmed.status_code == 409
    assert "Coinset" in confirmed.json()["detail"]


def test_validator_signing_can_be_bound_to_indexed_vault_proof(monkeypatch, tmp_path):
    monkeypatch.setenv("POPULIS_ZKPASSPORT_VALIDATOR_SEED_HEX", VALIDATOR_SEED_HEX)
    with _client(monkeypatch, tmp_path, parents=PARENT_A) as client:
        enrollment = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}).json()
        client.post(
            f"/zkpassport/enrollments/{VAULT_A}/proof",
            json={
                "vaultLauncherId": VAULT_A,
                "policyVersion": 1,
                "identityAttestRoot": ROOT,
                "attestationLeafHash": LEAF,
                "attestationProof": {"bitpath": 0, "siblings": []},
                "bridgePolicyHash": enrollment["bridgePolicyHash"],
                "bridgeParentId": enrollment["bridgeParentId"],
                "bridgeAmount": enrollment["bridgeAmount"],
                "bridgeCoinId": enrollment["bridgeCoinId"],
                "bridgeMessage": "0x" + "99" * 32,
                "validatorMessage": VALIDATOR_MESSAGE,
                "evmTxHash": TX,
            },
        )
        ok = client.post(
            "/zkpassport/sign",
            json={
                "validator_message_hex": VALIDATOR_MESSAGE,
                "vault_launcher_id": VAULT_A,
            },
        )
        bad = client.post(
            "/zkpassport/sign",
            json={
                "validator_message_hex": "0x" + "89" * 32,
                "vault_launcher_id": VAULT_A,
            },
        )

    assert ok.status_code == 200
    assert bad.status_code == 409


def test_record_proof_rejects_wrong_reserved_bridge_coin(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, parents=PARENT_A) as client:
        enrollment = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}).json()
        resp = client.post(
            f"/zkpassport/enrollments/{VAULT_A}/proof",
            json={
                "vaultLauncherId": VAULT_A,
                "policyVersion": 1,
                "identityAttestRoot": ROOT,
                "attestationLeafHash": LEAF,
                "attestationProof": {"bitpath": 0, "siblings": []},
                "bridgePolicyHash": enrollment["bridgePolicyHash"],
                "bridgeParentId": PARENT_B,
                "bridgeAmount": enrollment["bridgeAmount"],
                "bridgeCoinId": _coin_id(PARENT_B, POLICY_HASH),
                "bridgeMessage": "0x" + "99" * 32,
                "validatorMessage": VALIDATOR_MESSAGE,
                "evmTxHash": TX,
            },
        )

    assert resp.status_code == 409
