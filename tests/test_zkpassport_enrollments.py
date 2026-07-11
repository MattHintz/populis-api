from __future__ import annotations

import asyncio

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys as eth_keys
from chia_rs import Coin, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi.testclient import TestClient

from populis_api import admin
from populis_api.app import app
from populis_api import zkpassport_enrollments
from populis_api.config import Settings
from populis_api.state import reset_registry_for_tests


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
EVM_SENDER = "0x1111111111111111111111111111111111111111"


def _coin_id(parent: str, policy_hash: str, amount: int = 1) -> str:
    return "0x" + Coin(
        bytes32.fromhex(parent.removeprefix("0x")),
        bytes32.fromhex(policy_hash.removeprefix("0x")),
        uint64(amount),
    ).name().hex()


def _bridge_record(parent: str = PARENT_A, *, amount: int = 1, puzzle_hash: str = POLICY_HASH) -> dict:
    return {
        "coin": {
            "parent_coin_info": parent,
            "puzzle_hash": puzzle_hash,
            "amount": amount,
        },
        "confirmed_block_index": 123,
        "spent_block_index": 0,
    }


def _indexed_event(
    *,
    vault_launcher_id: str = VAULT_A,
    bridge_parent_id: str = PARENT_A,
    bridge_policy_hash: str = POLICY_HASH,
    bridge_amount: int = 1,
) -> zkpassport_enrollments.IndexedEvmAttestation:
    return zkpassport_enrollments.IndexedEvmAttestation(
        sender=EVM_SENDER,
        vault_launcher_id=vault_launcher_id,
        scoped_nullifier="0x" + "12" * 32,
        nullifier_type=1,
        service_scope_hash="0x" + "13" * 32,
        service_subscope_hash="0x" + "14" * 32,
        proof_timestamp=1_700_000_000,
        attestation_leaf_hash=LEAF,
        identity_attest_root=ROOT,
        bridge_parent_id=bridge_parent_id,
        bridge_amount=bridge_amount,
        bridge_coin_id=_coin_id(bridge_parent_id, bridge_policy_hash, bridge_amount),
        bridge_message="0x" + "99" * 32,
        bridge_policy_hash=bridge_policy_hash,
        policy_version=1,
        validator_message=VALIDATOR_MESSAGE,
        transaction_hash=TX,
        block_number=456,
    )


def _client(
    monkeypatch,
    tmp_path,
    parents: str = "",
    bridge_records: list[dict] | None = None,
    auto_topup: bool = False,
) -> TestClient:
    monkeypatch.setenv("POPULIS_ZKPASSPORT_ENROLLMENT_STORE_PATH", str(tmp_path / "enrollments.json"))
    monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_PARENT_IDS", parents)
    monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_POLICY_HASH", POLICY_HASH)
    monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_AMOUNT", "1")
    if auto_topup:
        monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_AUTO_TOPUP_ENABLED", "true")
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_bridge_coin_records",
        lambda _settings, _bridge_policy_hash: list(bridge_records or []),
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_verified_evm_attestation",
        lambda _settings, **kwargs: _indexed_event(
            vault_launcher_id=kwargs["expected_vault_launcher_id"]
        ),
    )
    reset_registry_for_tests(tmp_path / "vault_registry.db")
    return TestClient(app)


def test_create_enrollment_fails_closed_without_bridge_pool(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, parents="") as client:
        resp = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})

    assert resp.status_code == 503
    assert "bridge coins" in resp.json()["detail"]


def test_create_enrollment_discovers_unspent_bridge_coins(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, parents="", bridge_records=[_bridge_record(amount=2)]) as client:
        created = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})

    assert created.status_code == 200
    body = created.json()
    assert body["bridgeParentId"] == PARENT_A
    assert body["bridgeAmount"] == 2
    assert body["bridgeCoinId"] == _coin_id(PARENT_A, POLICY_HASH, 2)


def test_create_enrollment_auto_topups_when_pool_is_empty(monkeypatch, tmp_path):
    async def fake_topup(_settings):
        return [
            zkpassport_enrollments.BridgeCoinCandidate(
                parent_id=PARENT_B,
                amount=3,
                coin_id=_coin_id(PARENT_B, POLICY_HASH, 3),
            )
        ]

    monkeypatch.setattr(zkpassport_enrollments, "_auto_top_up_bridge_pool", fake_topup)
    with _client(monkeypatch, tmp_path, parents="", bridge_records=[], auto_topup=True) as client:
        created = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})

    assert created.status_code == 200
    body = created.json()
    assert body["bridgeParentId"] == PARENT_B
    assert body["bridgeAmount"] == 3
    assert body["bridgeCoinId"] == _coin_id(PARENT_B, POLICY_HASH, 3)


@pytest.mark.asyncio
async def test_auto_top_up_converts_admin_bridge_pool_response(monkeypatch):
    bridge_coin_id = _coin_id(PARENT_B, POLICY_HASH, 3)

    async def fake_top_up(_request, _settings):
        return admin.BridgePoolTopUpResponse(
            pushed=True,
            spend_bundle_id="0x" + "77" * 32,
            source_coin_id="0x" + "99" * 32,
            bridgePolicyHash=POLICY_HASH,
            coins=[
                admin.BridgePoolCoin(
                    parentId=PARENT_B,
                    bridgeAmount=3,
                    bridgeCoinId=bridge_coin_id,
                )
            ],
        )

    monkeypatch.setattr(admin, "top_up_zkpassport_bridge_pool", fake_top_up)
    settings = Settings(
        network="testnet11",
        zkpassport_bridge_auto_topup_enabled=True,
        zkpassport_bridge_policy_hash=POLICY_HASH,
    )

    candidates = await zkpassport_enrollments._auto_top_up_bridge_pool(settings)

    assert candidates == [
        zkpassport_enrollments.BridgeCoinCandidate(
            parent_id=PARENT_B,
            amount=3,
            coin_id=bridge_coin_id,
        )
    ]


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


def test_evm_proof_builds_and_confirms_atomic_chia_vault_stamp(monkeypatch, tmp_path):
    from populis_puzzles.vault_driver import (
        AUTH_TYPE_SECP256K1,
        DEFAULT_IDENTITY_ATTEST_ROOT,
        one_leaf_merkle_root,
        puzzle_for_vault_full,
    )
    from populis_puzzles.zkpassport_attestation import (
        ZkPassportAttestation,
        compute_attestation_bridge_message,
        compute_attestation_root,
        compute_validator_bridge_message,
    )
    from populis_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash

    private_key = bytes.fromhex("01" * 32)
    account = Account.from_key(private_key)
    owner_pubkey = eth_keys.PrivateKey(private_key).public_key.to_compressed_bytes()
    validator_sk = zkpassport_enrollments.AugSchemeMPL.key_gen(
        bytes.fromhex(VALIDATOR_SEED_HEX)
    )
    policy_hash = make_bridge_policy_hash([bytes(validator_sk.get_g1())], 1)
    policy_hex = "0x" + policy_hash.hex()
    launcher = bytes32.fromhex(VAULT_A.removeprefix("0x"))
    pool_launcher = bytes32(b"\x70" * 32)
    current_puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        AUTH_TYPE_SECP256K1,
        one_leaf_merkle_root(owner_pubkey),
        pool_launcher,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=policy_hash,
    )
    current_coin = Coin(launcher, bytes32(current_puzzle.get_tree_hash()), uint64(1))
    bridge_parent = bytes32.fromhex(PARENT_A.removeprefix("0x"))
    bridge_coin = Coin(bridge_parent, policy_hash, uint64(1))
    attestation = ZkPassportAttestation(
        vault_launcher_id=launcher,
        scoped_nullifier=bytes32(b"\x12" * 32),
        nullifier_type=1,
        service_scope_hash=bytes32(b"\x13" * 32),
        service_subscope_hash=bytes32(b"\x14" * 32),
        proof_timestamp=1_700_000_000,
        policy_version=1,
    )
    root = compute_attestation_root([attestation.leaf_hash])
    bridge_message = compute_attestation_bridge_message(
        vault_launcher_id=launcher,
        attestation_root=root,
        bridge_policy_hash=policy_hash,
        policy_version=1,
    )
    validator_message = compute_validator_bridge_message(
        vault_launcher_id=launcher,
        attestation_root=root,
        bridge_policy_hash=policy_hash,
        bridge_coin_id=bridge_coin.name(),
        bridge_message=bridge_message,
        attestation_leaf_hash=attestation.leaf_hash,
        scoped_nullifier=attestation.scoped_nullifier,
        nullifier_type=attestation.nullifier_type,
        service_scope_hash=attestation.service_scope_hash,
        service_subscope_hash=attestation.service_subscope_hash,
        proof_timestamp=attestation.proof_timestamp,
        policy_version=1,
    )
    event = zkpassport_enrollments.IndexedEvmAttestation(
        sender=account.address,
        vault_launcher_id=VAULT_A,
        scoped_nullifier="0x" + attestation.scoped_nullifier.hex(),
        nullifier_type=attestation.nullifier_type,
        service_scope_hash="0x" + attestation.service_scope_hash.hex(),
        service_subscope_hash="0x" + attestation.service_subscope_hash.hex(),
        proof_timestamp=attestation.proof_timestamp,
        attestation_leaf_hash="0x" + attestation.leaf_hash.hex(),
        identity_attest_root="0x" + root.hex(),
        bridge_parent_id=PARENT_A,
        bridge_amount=1,
        bridge_coin_id="0x" + bridge_coin.name().hex(),
        bridge_message="0x" + bridge_message.hex(),
        bridge_policy_hash=policy_hex,
        policy_version=1,
        validator_message="0x" + validator_message.hex(),
        transaction_hash=TX,
        block_number=456,
    )

    monkeypatch.setenv(
        "POPULIS_ZKPASSPORT_ENROLLMENT_STORE_PATH",
        str(tmp_path / "enrollments.json"),
    )
    monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_PARENT_IDS", PARENT_A)
    monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_POLICY_HASH", policy_hex)
    monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_AMOUNT", "1")
    monkeypatch.setenv("POPULIS_ZKPASSPORT_VALIDATOR_SEED_HEX", VALIDATOR_SEED_HEX)
    monkeypatch.setenv("POPULIS_POOL_LAUNCHER_ID", "0x" + pool_launcher.hex())
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_bridge_coin_records",
        lambda _settings, _policy: [_bridge_record(puzzle_hash=policy_hex)],
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_verified_evm_attestation",
        lambda _settings, **_kwargs: event,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_find_initial_vault_coin",
        lambda _settings, _launcher: current_coin,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_verify_reserved_bridge_coin",
        lambda _settings, _record: bridge_coin,
    )
    pushed: list[dict] = []

    class FakeCoinsetClient:
        def __init__(self, _base_url):
            pass

        async def push_tx(self, spend_bundle_json):
            pushed.append(spend_bundle_json)
            return {"success": True, "status": "SUCCESS"}

        async def close(self):
            pass

    monkeypatch.setattr(zkpassport_enrollments, "CoinsetClient", FakeCoinsetClient)
    reset_registry_for_tests(tmp_path / "vault_registry.db")

    enrollment = asyncio.run(
        zkpassport_enrollments.create_enrollment(
            zkpassport_enrollments.CreateEnrollmentRequest(vaultLauncherId=VAULT_A)
        )
    )
    proof = zkpassport_enrollments.record_evm_proof(
        VAULT_A,
        zkpassport_enrollments.RecordProofRequest(
            vaultLauncherId=VAULT_A,
            policyVersion=1,
            identityAttestRoot=event.identity_attest_root,
            attestationLeafHash=event.attestation_leaf_hash,
            attestationProof={"bitpath": 0, "siblings": []},
            bridgePolicyHash=enrollment.bridgePolicyHash,
            bridgeParentId=enrollment.bridgeParentId,
            bridgeAmount=enrollment.bridgeAmount,
            bridgeCoinId=enrollment.bridgeCoinId,
            bridgeMessage=event.bridge_message,
            validatorMessage=event.validator_message,
            evmTxHash=TX,
        ),
    )
    prepared = zkpassport_enrollments.prepare_chia_stamp(VAULT_A)
    signature = Account.sign_message(
        encode_typed_data(full_message=prepared.typedData),
        private_key,
    ).signature.hex()
    submitted = asyncio.run(
        zkpassport_enrollments.submit_evm_chia_stamp(
            VAULT_A,
            zkpassport_enrollments.SubmitEvmChiaStampRequest(
                signature="0x" + signature
            ),
        )
    )

    assert proof.status == "evm_confirmed"
    assert prepared.authType == "evm"
    assert submitted.enrollment.status == "stamp_pending"
    assert len(pushed) == 1
    assert len(pushed[0]["coin_spends"]) == 2
    submitted_bundle = SpendBundle.from_json_dict(pushed[0])
    assert zkpassport_enrollments.AugSchemeMPL.verify(
        validator_sk.get_g1(),
        bytes(validator_message)
        + bytes(bridge_coin.name())
        + zkpassport_enrollments.AGG_SIG_ME_DATA["testnet11"],
        submitted_bundle.aggregated_signature,
    )

    expected_coin_id = submitted.expectedVaultCoinId
    expected_puzzle_hash = zkpassport_enrollments._expected_stamped_vault_puzzle_hash(
        Settings(),
        vault_launcher_id=VAULT_A,
        identity_attest_root=event.identity_attest_root,
    )
    expected_parent = "0x" + current_coin.name().hex()
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_coin_record_by_name",
        lambda _settings, coin_id: {
            "coin": {
                "parent_coin_info": expected_parent,
                "puzzle_hash": expected_puzzle_hash,
                "amount": 1,
            },
            "confirmed_block_index": 789,
            "spent_block_index": 0,
        }
        if coin_id == expected_coin_id
        else None,
    )
    synced = zkpassport_enrollments.sync_chia_stamp(VAULT_A)

    assert synced.confirmed is True
    assert synced.enrollment.status == "chia_confirmed"
    assert synced.enrollment.receipt is not None
    assert synced.enrollment.receipt.confirmedBlockIndex == 789
