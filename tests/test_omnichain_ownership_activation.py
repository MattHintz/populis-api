from __future__ import annotations

import json
from pathlib import Path

from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from fastapi import FastAPI
from fastapi.testclient import TestClient

from solslot_api.admin_auth import require_admin_jwt
from solslot_api.config import Settings, get_settings
from solslot_api.omnichain_ownership_activation import (
    ChainState,
    OwnershipActivationError,
    OwnershipActivationStore,
    _build_exec_transaction,
    _canonical_hash,
    _typed_data_digest,
    _verify_broadcast,
    get_ownership_activation_store,
    load_authority_operation,
    router,
)


ROOT_SAFE = "0xb7e02C216A2B3aF0cC4Ad8808fA169f2F0B19724"
TIMELOCK = "0x5eC98d5a9C24C2a80957AB04630812C36807aad3"
OWNER_SAFE = "0x73a282e829dF5b7E12824a53F54c2FB6f07D13a5"
COADMIN_SAFE = "0x428700faA2b6Ebc613435994C84dB27908964A88"
GATEWAY = "0x4A467fd9137D8aC807E3CD7E109AB4d56f9Dfa9e"
SPOKE = "0xbbEEa9bd3E8a8becdef7FC21503C295b32C62d3f"


def _schedule_calldata(
    *,
    payloads: list[bytes] | None = None,
) -> tuple[str, str]:
    targets = [GATEWAY, SPOKE]
    values = [0, 0]
    actions = payloads or [keccak(text="acceptOwnership()")[:4]] * 2
    predecessor = bytes(32)
    salt = bytes.fromhex("44" * 32)
    operation_id = "0x" + keccak(
        abi_encode(
            ["address[]", "uint256[]", "bytes[]", "bytes32", "bytes32"],
            [targets, values, actions, predecessor, salt],
        )
    ).hex()
    data = "0x" + (
        keccak(
            text=(
                "scheduleBatch(address[],uint256[],bytes[],bytes32,bytes32,"
                "uint256)"
            )
        )[:4]
        + abi_encode(
            [
                "address[]",
                "uint256[]",
                "bytes[]",
                "bytes32",
                "bytes32",
                "uint256",
            ],
            [targets, values, actions, predecessor, salt, 86_400],
        )
    ).hex()
    return data, operation_id


def _execute_calldata() -> str:
    targets = [GATEWAY, SPOKE]
    values = [0, 0]
    actions = [keccak(text="acceptOwnership()")[:4]] * 2
    predecessor = bytes(32)
    salt = bytes.fromhex("44" * 32)
    return "0x" + (
        keccak(
            text="executeBatch(address[],uint256[],bytes[],bytes32,bytes32)"
        )[:4]
        + abi_encode(
            ["address[]", "uint256[]", "bytes[]", "bytes32", "bytes32"],
            [targets, values, actions, predecessor, salt],
        )
    ).hex()


def _safe_message(safe: str, message: str) -> dict:
    return {
        "domain": {"chainId": 84532, "verifyingContract": safe},
        "types": {"SafeMessage": [{"name": "message", "type": "bytes"}]},
        "primaryType": "SafeMessage",
        "message": {"message": message},
    }


def _write_package(
    path: Path,
    *,
    owner_address: str,
    coadmin_addresses: list[str],
) -> dict:
    transaction_data = "0x1901" + "11" * 64
    schedule_data, operation_id = _schedule_calldata()
    approvals = []
    for role, safe, allowed in (
        ("owner_identity", OWNER_SAFE, [owner_address]),
        ("coadmin", COADMIN_SAFE, coadmin_addresses),
    ):
        typed_data = _safe_message(safe, transaction_data)
        approvals.append(
            {
                "role": role,
                "safe": safe,
                "allowedSigners": allowed,
                "messageHash": _typed_data_digest(typed_data),
                "typedData": typed_data,
            }
        )
    package = {
        "schemaVersion": 1,
        "kind": "solslot-safe-authority-operation",
        "deploymentArtifactHash": "0x" + "21" * 32,
        "ownershipIntentArtifactHash": "0x" + "22" * 32,
        "governanceArtifactHash": "0x" + "23" * 32,
        "sourceSha": "1" * 40,
        "network": "baseSepolia",
        "chainId": 84532,
        "operationId": operation_id,
        "phase": "schedule",
        "rootSafe": ROOT_SAFE,
        "timelock": TIMELOCK,
        "operationTimestamp": "0",
        "operationReady": False,
        "observedAtBlock": 1,
        "observedAtTimestamp": 1,
        "authorityOperation": {
            "phase": "schedule",
            "rootSafe": ROOT_SAFE,
            "transaction": {
                "to": TIMELOCK,
                "value": "0",
                "data": schedule_data,
                "operation": 0,
                "safeTxGas": "0",
                "baseGas": "0",
                "gasPrice": "0",
                "gasToken": "0x" + "00" * 20,
                "refundReceiver": "0x" + "00" * 20,
                "nonce": "0",
            },
            "transactionHash": "0x" + "25" * 32,
            "transactionData": transaction_data,
            "approvals": approvals,
        },
        "createdAt": "2026-07-24T00:00:00.000Z",
    }
    package["artifactHash"] = _canonical_hash(package)
    path.write_text(json.dumps(package), encoding="utf-8")
    return package


def _write_execute_package(
    path: Path,
    *,
    schedule: dict,
    owner_address: str,
    coadmin_addresses: list[str],
) -> dict:
    transaction_data = "0x1901" + "33" * 64
    approvals = []
    for role, safe, allowed in (
        ("owner_identity", OWNER_SAFE, [owner_address]),
        ("coadmin", COADMIN_SAFE, coadmin_addresses),
    ):
        typed_data = _safe_message(safe, transaction_data)
        approvals.append(
            {
                "role": role,
                "safe": safe,
                "allowedSigners": allowed,
                "messageHash": _typed_data_digest(typed_data),
                "typedData": typed_data,
            }
        )
    package = {
        **{
            key: schedule[key]
            for key in (
                "schemaVersion",
                "kind",
                "deploymentArtifactHash",
                "ownershipIntentArtifactHash",
                "governanceArtifactHash",
                "sourceSha",
                "network",
                "chainId",
                "operationId",
                "rootSafe",
                "timelock",
            )
        },
        "phase": "execute",
        "operationTimestamp": "2000000000",
        "operationReady": True,
        "observedAtBlock": 100,
        "observedAtTimestamp": 2000000000,
        "authorityOperation": {
            "phase": "execute",
            "rootSafe": ROOT_SAFE,
            "transaction": {
                "to": TIMELOCK,
                "value": "0",
                "data": _execute_calldata(),
                "operation": 0,
                "safeTxGas": "0",
                "baseGas": "0",
                "gasPrice": "0",
                "gasToken": "0x" + "00" * 20,
                "refundReceiver": "0x" + "00" * 20,
                "nonce": "1",
            },
            "transactionHash": "0x" + "35" * 32,
            "transactionData": transaction_data,
            "approvals": approvals,
        },
        "createdAt": "2026-07-25T00:00:00.000Z",
    }
    package["artifactHash"] = _canonical_hash(package)
    path.write_text(json.dumps(package), encoding="utf-8")
    return package


def _signature(account, typed_data: dict) -> str:
    signed = Account.sign_message(
        encode_typed_data(full_message=typed_data),
        account.key,
    )
    return "0x" + signed.signature.hex()


def _current_chain_state() -> ChainState:
    return ChainState(
        operation_exists=False,
        operation_ready=False,
        operation_done=False,
        operation_timestamp=0,
        live_nonce=0,
        live_transaction_hash="0x" + "25" * 32,
        latest_block=100,
    )


def _scheduled_chain_state() -> ChainState:
    return ChainState(
        operation_exists=True,
        operation_ready=False,
        operation_done=False,
        operation_timestamp=2_000_000_000,
        live_nonce=1,
        live_transaction_hash="0x" + "25" * 32,
        latest_block=112,
    )


def _ready_chain_state() -> ChainState:
    return ChainState(
        operation_exists=True,
        operation_ready=True,
        operation_done=False,
        operation_timestamp=2_000_000_000,
        live_nonce=1,
        live_transaction_hash="0x" + "35" * 32,
        latest_block=200,
    )


def _done_chain_state() -> ChainState:
    return ChainState(
        operation_exists=True,
        operation_ready=False,
        operation_done=True,
        operation_timestamp=1,
        live_nonce=2,
        live_transaction_hash="0x" + "35" * 32,
        latest_block=212,
    )


def _test_app(settings: Settings, store: OwnershipActivationStore) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_ownership_activation_store] = lambda: store
    app.dependency_overrides[require_admin_jwt] = lambda: object()
    return app


def test_standalone_ownership_routes_require_admin_authentication(tmp_path) -> None:
    settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_activation_enabled=True,
        admin_db_path=str(tmp_path / "admin.db"),
    )
    store = OwnershipActivationStore(settings.admin_db_path)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_ownership_activation_store] = lambda: store

    response = TestClient(app).get("/admin/omnichain/ownership-activation")

    assert response.status_code in {401, 503}
    assert "Admin desk" in response.text or "authentication" in response.text


def test_real_safe_signatures_are_the_only_approvals(
    tmp_path, monkeypatch
) -> None:
    owner = Account.create()
    coadmin = Account.create()
    other_coadmin = Account.create()
    package_path = tmp_path / "operation.json"
    raw = _write_package(
        package_path,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address, other_coadmin.address],
    )
    settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_activation_enabled=True,
        payment_omnichain_ownership_safe_operation_path=str(package_path),
        payment_omnichain_ownership_safe_operation_hash=raw["artifactHash"],
        payment_omnichain_rpc_url="https://base-sepolia.example.invalid",
        admin_db_path=str(tmp_path / "admin.db"),
    )
    store = OwnershipActivationStore(settings.admin_db_path)
    app = _test_app(settings, store)
    client = TestClient(app)
    monkeypatch.setattr(
        "solslot_api.omnichain_ownership_activation._chain_state",
        lambda *_args, **_kwargs: _current_chain_state(),
    )
    package = load_authority_operation(settings)
    descriptors = {
        value["role"]: value for value in package["authorityOperation"]["approvals"]
    }

    response = client.get("/admin/omnichain/ownership-activation")
    assert response.status_code == 200
    assert response.json()["state"] == "AWAITING_APPROVALS"
    assert response.json()["broadcastTransaction"] is None
    assert response.json()["schemaVersion"] == 2
    assert response.json()["review"] == {
        "action": "acceptOwnership",
        "targets": [GATEWAY, SPOKE],
        "delaySeconds": 86_400,
        "operationId": raw["operationId"],
    }

    response = client.post(
        "/admin/omnichain/ownership-activation/sign",
        json={"signature": _signature(owner, descriptors["owner_identity"]["typedData"])},
    )
    assert response.status_code == 200
    assert response.json()["state"] == "AWAITING_APPROVALS"

    response = client.post(
        "/admin/omnichain/ownership-activation/sign",
        json={"signature": _signature(coadmin, descriptors["coadmin"]["typedData"])},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "READY_TO_BROADCAST"
    assert body["broadcastTransaction"]["chainId"] == "84532"
    assert body["broadcastTransaction"]["to"].lower() == ROOT_SAFE.lower()
    assert body["broadcastTransaction"]["data"].startswith("0x6a761202")
    assert len(store.approvals(raw["artifactHash"])) == 2


def test_signature_must_match_one_authorized_safe_role(
    tmp_path, monkeypatch
) -> None:
    owner = Account.create()
    coadmin = Account.create()
    package_path = tmp_path / "operation.json"
    raw = _write_package(
        package_path,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address],
    )
    settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_activation_enabled=True,
        payment_omnichain_ownership_safe_operation_path=str(package_path),
        payment_omnichain_ownership_safe_operation_hash=raw["artifactHash"],
        payment_omnichain_rpc_url="https://base-sepolia.example.invalid",
        admin_db_path=str(tmp_path / "admin.db"),
    )
    store = OwnershipActivationStore(settings.admin_db_path)
    app = _test_app(settings, store)
    client = TestClient(app)
    monkeypatch.setattr(
        "solslot_api.omnichain_ownership_activation._chain_state",
        lambda *_args, **_kwargs: _current_chain_state(),
    )
    package = load_authority_operation(settings)
    outsider = Account.create()
    owner_typed_data = next(
        value["typedData"]
        for value in package["authorityOperation"]["approvals"]
        if value["role"] == "owner_identity"
    )

    response = client.post(
        "/admin/omnichain/ownership-activation/sign",
        json={"signature": _signature(outsider, owner_typed_data)},
    )
    assert response.status_code == 409
    assert "does not match one unique authorized Safe role" in response.json()["detail"]
    assert store.approvals(raw["artifactHash"]) == {}


def test_broadcast_receipt_is_recorded_only_after_timelock_schedule(
    tmp_path, monkeypatch
) -> None:
    owner = Account.create()
    coadmin = Account.create()
    package_path = tmp_path / "operation.json"
    raw = _write_package(
        package_path,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address],
    )
    settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_activation_enabled=True,
        payment_omnichain_ownership_safe_operation_path=str(package_path),
        payment_omnichain_ownership_safe_operation_hash=raw["artifactHash"],
        payment_omnichain_rpc_url="https://base-sepolia.example.invalid",
        admin_db_path=str(tmp_path / "admin.db"),
    )
    store = OwnershipActivationStore(settings.admin_db_path)
    package = load_authority_operation(settings)
    descriptors = {
        value["role"]: value for value in package["authorityOperation"]["approvals"]
    }
    store.add_approval(
        package_hash=raw["artifactHash"],
        role="owner_identity",
        signer_address=owner.address,
        signature=_signature(owner, descriptors["owner_identity"]["typedData"]),
        now=1,
    )
    store.add_approval(
        package_hash=raw["artifactHash"],
        role="coadmin",
        signer_address=coadmin.address,
        signature=_signature(coadmin, descriptors["coadmin"]["typedData"]),
        now=2,
    )
    app = _test_app(settings, store)
    client = TestClient(app)
    monkeypatch.setattr(
        "solslot_api.omnichain_ownership_activation._verify_broadcast",
        lambda **_kwargs: (101, 12, owner.address),
    )
    monkeypatch.setattr(
        "solslot_api.omnichain_ownership_activation._chain_state",
        lambda *_args, **_kwargs: _scheduled_chain_state(),
    )

    transaction_hash = "0x" + "99" * 32
    response = client.post(
        "/admin/omnichain/ownership-activation/broadcast",
        json={"transactionHash": transaction_hash},
    )
    assert response.status_code == 200
    assert response.json()["state"] == "SCHEDULED"
    assert response.json()["scheduledFor"] == 2_000_000_000
    assert response.json()["broadcast"]["transactionHash"] == transaction_hash
    assert response.json()["broadcast"]["confirmations"] == 12


def test_package_hash_and_feature_flag_fail_closed(tmp_path) -> None:
    owner = Account.create()
    coadmin = Account.create()
    package_path = tmp_path / "operation.json"
    raw = _write_package(
        package_path,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address],
    )
    bad_settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_safe_operation_path=str(package_path),
        payment_omnichain_ownership_safe_operation_hash="0x" + "ff" * 32,
    )
    try:
        load_authority_operation(bad_settings)
    except OwnershipActivationError as exc:
        assert "hash mismatches" in str(exc)
    else:
        raise AssertionError("altered package hash was accepted")

    disabled_settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_activation_enabled=False,
        payment_omnichain_ownership_safe_operation_path=str(package_path),
        payment_omnichain_ownership_safe_operation_hash=raw["artifactHash"],
        admin_db_path=str(tmp_path / "admin.db"),
    )
    app = _test_app(
        disabled_settings,
        OwnershipActivationStore(disabled_settings.admin_db_path),
    )
    response = TestClient(app).get("/admin/omnichain/ownership-activation")
    assert response.status_code == 503


def test_execute_phase_requires_fresh_approvals_after_24_hour_delay(
    tmp_path, monkeypatch
) -> None:
    owner = Account.create()
    coadmin = Account.create()
    schedule_path = tmp_path / "schedule.json"
    schedule = _write_package(
        schedule_path,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address],
    )
    execute_path = tmp_path / "execute.json"
    execute = _write_execute_package(
        execute_path,
        schedule=schedule,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address],
    )
    settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_activation_enabled=True,
        payment_omnichain_ownership_safe_operation_path=str(schedule_path),
        payment_omnichain_ownership_safe_operation_hash=schedule["artifactHash"],
        payment_omnichain_ownership_execute_operation_path=str(execute_path),
        payment_omnichain_ownership_execute_operation_hash=execute["artifactHash"],
        payment_omnichain_rpc_url="https://base-sepolia.example.invalid",
        admin_db_path=str(tmp_path / "admin.db"),
    )
    store = OwnershipActivationStore(settings.admin_db_path)
    app = _test_app(settings, store)
    client = TestClient(app)
    monkeypatch.setattr(
        "solslot_api.omnichain_ownership_activation._chain_state",
        lambda *_args, **_kwargs: _ready_chain_state(),
    )
    package = load_authority_operation(settings, phase="execute")
    descriptors = {
        value["role"]: value for value in package["authorityOperation"]["approvals"]
    }
    initial = client.get("/admin/omnichain/ownership-activation/execute")
    assert initial.status_code == 200, initial.text
    assert initial.json()["state"] == "AWAITING_APPROVALS"
    assert initial.json()["review"]["action"] == "executeAcceptOwnership"

    for role, account in (("owner_identity", owner), ("coadmin", coadmin)):
        signed = client.post(
            "/admin/omnichain/ownership-activation/execute/sign",
            json={
                "signature": _signature(
                    account, descriptors[role]["typedData"]
                )
            },
        )
        assert signed.status_code == 200, signed.text
    assert signed.json()["state"] == "READY_TO_BROADCAST"
    assert len(store.approvals(execute["artifactHash"])) == 2
    assert store.approvals(schedule["artifactHash"]) == {}


def test_execute_package_cannot_change_the_scheduled_batch(tmp_path) -> None:
    owner = Account.create()
    coadmin = Account.create()
    schedule_path = tmp_path / "schedule.json"
    schedule = _write_package(
        schedule_path,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address],
    )
    execute_path = tmp_path / "execute.json"
    execute = _write_execute_package(
        execute_path,
        schedule=schedule,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address],
    )
    execute["authorityOperation"]["transaction"]["data"] = "0x1234"
    execute.pop("artifactHash")
    execute["artifactHash"] = _canonical_hash(execute)
    execute_path.write_text(json.dumps(execute), encoding="utf-8")
    settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_safe_operation_path=str(schedule_path),
        payment_omnichain_ownership_safe_operation_hash=schedule["artifactHash"],
        payment_omnichain_ownership_execute_operation_path=str(execute_path),
        payment_omnichain_ownership_execute_operation_hash=execute["artifactHash"],
    )
    try:
        load_authority_operation(settings, phase="execute")
    except OwnershipActivationError as exc:
        assert "ownership execute data is invalid" in str(exc)
    else:
        raise AssertionError("altered execute package was accepted")


def test_package_rejects_non_ownership_timelock_actions(tmp_path) -> None:
    owner = Account.create()
    coadmin = Account.create()
    package_path = tmp_path / "operation.json"
    raw = _write_package(
        package_path,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address],
    )
    altered_data, altered_operation_id = _schedule_calldata(
        payloads=[bytes.fromhex("deadbeef"), bytes.fromhex("deadbeef")]
    )
    raw["operationId"] = altered_operation_id
    raw["authorityOperation"]["transaction"]["data"] = altered_data
    raw.pop("artifactHash")
    raw["artifactHash"] = _canonical_hash(raw)
    package_path.write_text(json.dumps(raw), encoding="utf-8")
    settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_safe_operation_path=str(package_path),
        payment_omnichain_ownership_safe_operation_hash=raw["artifactHash"],
    )

    try:
        load_authority_operation(settings)
    except OwnershipActivationError as exc:
        assert "schedule terms mismatch" in str(exc)
    else:
        raise AssertionError("non-ownership timelock actions were accepted")


def test_broadcast_verifier_compares_exact_root_safe_calldata(
    tmp_path, monkeypatch
) -> None:
    owner = Account.create()
    coadmin = Account.create()
    package_path = tmp_path / "operation.json"
    raw = _write_package(
        package_path,
        owner_address=owner.address,
        coadmin_addresses=[coadmin.address],
    )
    settings = Settings(
        runtime_environment="test",
        payment_omnichain_ownership_safe_operation_path=str(package_path),
        payment_omnichain_ownership_safe_operation_hash=raw["artifactHash"],
        payment_omnichain_rpc_url="https://base-sepolia.example.invalid",
    )
    package = load_authority_operation(settings)
    descriptors = {
        value["role"]: value for value in package["authorityOperation"]["approvals"]
    }
    approvals = {
        "owner_identity": {
            "signature": _signature(owner, descriptors["owner_identity"]["typedData"])
        },
        "coadmin": {
            "signature": _signature(coadmin, descriptors["coadmin"]["typedData"])
        },
    }
    expected = _build_exec_transaction(package, approvals)

    class FakeEth:
        block_number = 112

        @staticmethod
        def get_transaction(_transaction_hash):
            return {
                "from": owner.address,
                "to": package["rootSafe"],
                "value": 0,
                "input": expected["data"],
            }

        @staticmethod
        def get_transaction_receipt(_transaction_hash):
            return {"status": 1, "blockNumber": 101}

    class FakeWeb3:
        eth = FakeEth()

    monkeypatch.setattr(
        "solslot_api.omnichain_ownership_activation._web3",
        lambda _settings: FakeWeb3(),
    )

    assert _verify_broadcast(
        settings=settings,
        package=package,
        approvals=approvals,
        transaction_hash="0x" + "99" * 32,
    ) == (101, 12, owner.address)

    FakeEth.get_transaction = staticmethod(
        lambda _transaction_hash: {
            "from": owner.address,
            "to": package["rootSafe"],
            "value": 0,
            "input": expected["data"][:-2]
            + ("ff" if expected["data"][-2:].lower() != "ff" else "00"),
        }
    )
    try:
        _verify_broadcast(
            settings=settings,
            package=package,
            approvals=approvals,
            transaction_hash="0x" + "99" * 32,
        )
    except OwnershipActivationError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("altered Root Safe calldata was accepted")
