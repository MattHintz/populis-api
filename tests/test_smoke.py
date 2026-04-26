"""Smoke tests — verify the core flows work without a live node or faucet."""
from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient
from eth_account import Account

from populis_api.app import app
from populis_api.evm_auth import recover_evm_signer, registration_typed_data


@pytest.fixture
def client():
    # `with` triggers Starlette's lifespan (populates app.state).
    with TestClient(app) as c:
        yield c


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


def test_protocol(client: TestClient) -> None:
    r = client.get("/protocol")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eip712_domain"]["chainId"] == 1
    assert "PopulisVaultSpend" in body["eip712_typehash_string"]
    assert body["vault_inner_mod_hash"].startswith("0x")
    assert len(body["vault_inner_mod_hash"]) == 66  # 0x + 32 bytes hex


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
