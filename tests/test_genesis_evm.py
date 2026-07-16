from __future__ import annotations

import hashlib
import json

import pytest
from web3 import Web3 as RealWeb3

from solslot_api import genesis_evm
from solslot_api.config import Settings
from solslot_api.genesis_evm import (
    GenesisEvmEvidenceError,
    verify_genesis_evm_deployment,
)


def _canonical_hash(payload: dict) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _fixture(tmp_path):
    addresses = {
        "forwarder": "0x" + "11" * 20,
        "verifierAdapter": "0x" + "22" * 20,
        "attestationEmitter": "0x" + "33" * 20,
    }
    transactions = {
        name: {
            "hash": "0x" + bytes([index]).hex() * 32,
            "blockNumber": 100 + index,
        }
        for index, name in enumerate(addresses, start=1)
    }
    code = {
        addresses["forwarder"]: b"forwarder-runtime",
        addresses["verifierAdapter"]: b"adapter-runtime",
        addresses["attestationEmitter"]: b"emitter-runtime",
        "0x" + "44" * 20: b"root-runtime",
    }
    deployment = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "credentialPolicyVersion": 2,
        "network": "ethSepolia",
        "chainId": 11155111,
        "confirmations": 12,
        "createdAt": "2026-07-16T00:00:00.000Z",
        "sourceShas": {"evm": "2" * 40, "protocol": "1" * 40},
        "deployer": "0x" + "55" * 20,
        "forwarderAddress": addresses["forwarder"],
        "verifierAdapterAddress": addresses["verifierAdapter"],
        "attestationEmitterAddress": addresses["attestationEmitter"],
        "trustedDirectRelayerAddress": "0x" + "66" * 20,
        "bridgePolicyHash": "0x" + "77" * 32,
        "zkPassportRootVerifierAddress": "0x" + "44" * 20,
        "zkPassportDomain": "staging.solslot.com",
        "zkPassportDevMode": True,
        "deploymentTransactions": transactions,
        "runtimeCodeHashes": {
            "forwarder": RealWeb3.keccak(code[addresses["forwarder"]]).hex(),
            "verifierAdapter": RealWeb3.keccak(code[addresses["verifierAdapter"]]).hex(),
            "attestationEmitter": RealWeb3.keccak(
                code[addresses["attestationEmitter"]]
            ).hex(),
            "zkPassportRootVerifier": RealWeb3.keccak(code["0x" + "44" * 20]).hex(),
        },
    }
    deployment["artifactHash"] = _canonical_hash(deployment)
    path = tmp_path / "evm-deployment.json"
    path.write_text(json.dumps(deployment), encoding="ascii")
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        genesis_evm_deployment_path=str(path),
        zkpassport_evm_rpc_url="https://rpc.invalid",
        cors_origins="",
    )
    record = {
        "draft": {
            "sourceShas": {
                "protocol": "1" * 40,
                "evm": "2" * 40,
                "api": "3" * 40,
                "customerWeb": "4" * 40,
                "adminPortal": "5" * 40,
            }
        }
    }
    plan = {
        "evmAddresses": addresses,
        "puzzleHashes": {"bridgePolicy": "0x" + "77" * 32},
    }
    return settings, record, plan, deployment, code


def _install_fake_web3(monkeypatch, deployment, code, *, peak=120):
    receipts = {
        item["hash"].lower(): {
            "status": 1,
            "blockNumber": item["blockNumber"],
            "contractAddress": deployment[
                {
                    "forwarder": "forwarderAddress",
                    "verifierAdapter": "verifierAdapterAddress",
                    "attestationEmitter": "attestationEmitterAddress",
                }[name]
            ],
        }
        for name, item in deployment["deploymentTransactions"].items()
    }

    class FakeEth:
        chain_id = 11155111
        block_number = peak

        @staticmethod
        def get_transaction_receipt(transaction_hash):
            return receipts[str(transaction_hash).lower()]

        @staticmethod
        def get_code(address):
            return code[str(address).lower()]

    class FakeWeb3:
        HTTPProvider = staticmethod(lambda *_args, **_kwargs: object())
        keccak = staticmethod(RealWeb3.keccak)

        def __init__(self, _provider):
            self.eth = FakeEth()

        @staticmethod
        def is_connected():
            return True

    monkeypatch.setattr(genesis_evm, "Web3", FakeWeb3)


def test_live_evm_deployment_verification_accepts_immutable_confirmed_evidence(
    tmp_path, monkeypatch
) -> None:
    settings, record, plan, deployment, code = _fixture(tmp_path)
    _install_fake_web3(monkeypatch, deployment, code)

    result = verify_genesis_evm_deployment(settings, record, plan)

    assert result["manifestArtifactHash"] == deployment["artifactHash"]
    assert result["checkedAtBlock"] == 120
    assert set(result["contracts"]) == {
        "forwarder",
        "verifierAdapter",
        "attestationEmitter",
    }
    assert min(item["confirmations"] for item in result["contracts"].values()) >= 12


def test_live_evm_deployment_verification_rejects_insufficient_confirmations(
    tmp_path, monkeypatch
) -> None:
    settings, record, plan, deployment, code = _fixture(tmp_path)
    _install_fake_web3(monkeypatch, deployment, code, peak=111)

    with pytest.raises(GenesisEvmEvidenceError, match="12 are required"):
        verify_genesis_evm_deployment(settings, record, plan)


def test_live_evm_deployment_verification_rejects_source_or_manifest_drift(
    tmp_path, monkeypatch
) -> None:
    settings, record, plan, deployment, code = _fixture(tmp_path)
    _install_fake_web3(monkeypatch, deployment, code)

    record["draft"]["sourceShas"]["evm"] = "f" * 40
    with pytest.raises(GenesisEvmEvidenceError, match="source SHA"):
        verify_genesis_evm_deployment(settings, record, plan)

    record["draft"]["sourceShas"]["evm"] = "2" * 40
    deployment["forwarderAddress"] = "0x" + "99" * 20
    path = settings.genesis_evm_deployment_path
    with open(path, "w", encoding="ascii") as stream:
        json.dump(deployment, stream)
    with pytest.raises(GenesisEvmEvidenceError, match="artifactHash"):
        verify_genesis_evm_deployment(settings, record, plan)
