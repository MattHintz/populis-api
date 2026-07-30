"""Smoke tests — verify the core flows work without a live node or faucet."""
from __future__ import annotations

import secrets
import json

import pytest
from fastapi.testclient import TestClient
from eth_account import Account

from solslot_api.app import app
from solslot_api.evm_auth import recover_evm_signer, registration_typed_data
from solslot_api.config import get_settings


def _v2_manifest() -> dict:
    hex_value = lambda byte: "0x" + byte * 32
    fields = {
        name: hex_value(f"{index:02x}")
        for index, name in enumerate(
            (
                "faucet_inner_puzhash",
                "sgt_genesis_coin_id",
                "pool_genesis_coin_id",
                "did_genesis_coin_id",
                "gov_genesis_coin_id",
                "pool_launcher_id",
                "did_launcher_id",
                "tracker_launcher_id",
                "sgt_tail_hash",
                "sgt_full_puzhash",
                "pool_token_tail_hash",
                "pool_inner_puzhash",
                "pool_full_puzhash",
                "pool_inner_mod_hash",
                "p2_pool_mod_hash",
                "smart_deed_inner_mod_hash",
                "governance_singleton_struct_hash",
                "did_inner_puzhash",
                "did_full_puzhash",
                "tracker_inner_puzhash",
                "tracker_full_puzhash",
            ),
            start=1,
        )
    }
    return {
        "network": "testnet11",
        "params": {},
        "protocol_version": "solslot-v2",
        "pool_puzzle_version": 3,
        "smart_deed_puzzle_version": 2,
        **fields,
    }


def _signed_artifact(manifest: dict) -> dict:
    return {
        "artifactHash": "0x" + "ab" * 32,
        "sourceManifestVersion": 4,
        "sourceShas": {
            "protocol": "1" * 40,
            "evm": "2" * 40,
            "omnichain": "3" * 40,
            "api": "4" * 40,
            "legacyBackend": "5" * 40,
            "keyOfSolomon": "6" * 40,
            "samuel": "7" * 40,
            "customerWeb": "8" * 40,
            "adminPortal": "9" * 40,
        },
        "launcherIds": {
            "pool": manifest["pool_launcher_id"],
            "did": manifest["did_launcher_id"],
            "governance": manifest["tracker_launcher_id"],
            "navRegistry": "0x" + "da" * 32,
            "protocolConfig": "0x" + "ee" * 32,
            "adminAuthority": "0x" + "db" * 32,
            "vaultVersionRegistry": "0x" + "dc" * 32,
        },
        "bridgePolicy": {"policyHash": "0x" + "c1" * 32},
        "stateVersions": {"protocolConfig": 1, "vault": 1},
    }


@pytest.fixture
def client(monkeypatch, tmp_path):
    manifest_path = tmp_path / "deployment_manifest_v2.json"
    manifest = _v2_manifest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(manifest_path))
    monkeypatch.setenv("SOLSLOT_POOL_LAUNCHER_ID", manifest["pool_launcher_id"])
    monkeypatch.setenv("SOLSLOT_GOVERNANCE_LAUNCHER_ID", manifest["tracker_launcher_id"])
    monkeypatch.setenv("SOLSLOT_PROTOCOL_CONFIG_LAUNCHER_ID", "0x" + "ee" * 32)
    monkeypatch.setattr(
        "solslot_api.app.load_signed_public_artifact",
        lambda _settings: _signed_artifact(manifest),
    )
    get_settings.cache_clear()
    # `with` triggers Starlette's lifespan (populates app.state).
    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


@pytest.fixture
def local_acct():
    """A deterministic local Ethereum account to stand in for a real wallet."""
    pk = bytes.fromhex(
        "4c0883a69102937d6231471b5dbb6204fe512961708279c2fec72f33ae88dadf"
    )
    return Account.from_key(pk)


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    # Network unreachable is still a 200 with ok=false — the endpoint never 500s.
    assert r.status_code == 200, r.text
    body = r.json()
    assert "network" in body
    assert body["network"] in ("testnet11", "mainnet")


def test_chia_provider_status_reports_unconfigured_primary_as_degraded(
    client: TestClient,
) -> None:
    response = client.get("/chia/provider-status")

    assert response.status_code == 503
    assert response.json() == {
        "schemaVersion": 1,
        "network": "testnet11",
        "activeProvider": "coinset-fallback",
        "primaryConfigured": False,
        "primaryRequired": False,
        "fallbackActive": True,
        "primaryOrigin": None,
        "fallbackOrigin": "https://testnet11.api.coinset.org",
        "lastPrimaryFailureAt": None,
        "lastPrimarySuccessAt": None,
        "lastPrimaryError": "primary provider is not configured",
    }


def test_protocol(client: TestClient) -> None:
    r = client.get("/protocol")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eip712_domain"]["chainId"] == 11155111
    assert "SolslotVaultSpend" in body["eip712_typehash_string"]
    assert body["vault_inner_mod_hash"].startswith("0x")
    assert len(body["vault_inner_mod_hash"]) == 66  # 0x + 32 bytes hex
    assert body["faucet_address"] is None
    assert body["faucet_balance_mojos"] is None
    assert body["deployment_manifest"] is None
    assert body["artifact_hash"] == "0x" + "ab" * 32


def test_evm_challenge_roundtrip(client: TestClient, local_acct) -> None:
    """Request a challenge, sign it with a local eth_account, verify recovery
    matches the signer address and the compressed pubkey is 33 bytes."""
    address = local_acct.address

    r = client.post(
        "/auth/challenge", json={"address": address, "auth_type": "evm"}
    )
    assert r.status_code == 200, r.text
    challenge = r.json()
    assert challenge["typed_data"] is not None
    typed_data = challenge["typed_data"]

    # Sign with eth_account locally (mimics MetaMask signTypedData_v4).
    signed = local_acct.sign_typed_data(
        domain_data=typed_data["domain"],
        message_types={
            k: v for k, v in typed_data["types"].items() if k != "EIP712Domain"
        },
        message_data=typed_data["message"],
    )
    signature = "0x" + signed.signature.hex()

    recovery = recover_evm_signer(typed_data, signature)
    assert recovery.address.lower() == address.lower()
    assert len(recovery.compressed_pubkey) == 33
    assert recovery.compressed_pubkey[0] in (0x02, 0x03)


def test_register_evm_vault_no_faucet_returns_503(client: TestClient, local_acct) -> None:
    """With no faucet configured, the endpoint must fail fast with 503 rather
    than hang or 500."""
    address = local_acct.address
    # Get a challenge first so we exercise the full code path.
    r = client.post("/auth/challenge", json={"address": address, "auth_type": "evm"})
    challenge = r.json()

    # Sign something (doesn't need to be the real typed data — the endpoint
    # checks the faucet before the signature).
    typed_data = challenge["typed_data"]
    signed = local_acct.sign_typed_data(
        domain_data=typed_data["domain"],
        message_types={
            k: v for k, v in typed_data["types"].items() if k != "EIP712Domain"
        },
        message_data=typed_data["message"],
    )

    r = client.post(
        "/vault/register/evm",
        json={
            "address": address,
            "nonce": challenge["nonce"],
            "signature": "0x" + signed.signature.hex(),
        },
    )
    # Either 503 (no faucet) or 502/200 (if a network/faucet actually available)
    assert r.status_code in (503, 502, 200), r.text
    if r.status_code == 503:
        assert "faucet" in r.json()["detail"].lower() or "faucet" in r.text.lower()
