from __future__ import annotations

import json

import httpx
import pytest
from chia_rs import AugSchemeMPL, G1Element

from solslot_api import validator_quorum
from solslot_api.config import Settings
from solslot_api.validator_quorum import (
    ValidatorClaim,
    ValidatorQuorumError,
    collect_validator_quorum,
    probe_validator_health,
)
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash


def _keys():
    return tuple(AugSchemeMPL.key_gen(bytes([index]) * 32) for index in (1, 2, 3))


def _settings(keys) -> Settings:
    return Settings(
        runtime_environment="test",
        network="testnet11",
        zkpassport_validator_urls=[
            "https://validator-0.test",
            "https://validator-1.test",
            "https://validator-2.test",
        ],
        zkpassport_validator_pubkeys=["0x" + bytes(key.get_g1()).hex() for key in keys],
        zkpassport_validator_threshold=2,
    )


def _claim(keys) -> ValidatorClaim:
    policy_hash = make_bridge_policy_hash(
        [bytes(key.get_g1()) for key in keys],
        2,
    )
    return ValidatorClaim(
        network="testnet11",
        artifact_hash="0x" + "01" * 32,
        vault_launcher_id="0x" + "02" * 32,
        current_vault_coin_id="0x" + "03" * 32,
        owner_key="0x" + "04" * 20,
        owner_auth_type=3,
        owner_authorization="0x" + "05" * 65,
        owner_authorization_hash="0x" + "06" * 32,
        current_timestamp=1_800_000_000,
        evm_transaction_hash="0x" + "07" * 32,
        evm_block_number=123,
        emitter_address="0x" + "08" * 20,
        policy_version=2,
        identity_attest_root="0x" + "09" * 32,
        attestation_leaf_hash="0x" + "0a" * 32,
        scoped_nullifier="0x" + "0b" * 32,
        nullifier_type=1,
        service_scope_hash="0x" + "0c" * 32,
        service_subscope_hash="0x" + "0d" * 32,
        proof_timestamp=1_799_999_900,
        bridge_policy_hash="0x" + bytes(policy_hash).hex(),
        bridge_parent_id="0x" + "0e" * 32,
        bridge_amount=1,
        bridge_coin_id="0x" + "0f" * 32,
        validator_message="0x" + "10" * 32,
    )


def test_private_validator_client_loads_mtls_chain_into_ssl_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
):
    ca_path = tmp_path / "ca.crt"
    cert_path = tmp_path / "coordinator.crt"
    key_path = tmp_path / "coordinator.key"
    for path in (ca_path, cert_path, key_path):
        path.write_text("test", encoding="ascii")

    loaded_chain: list[tuple[str, str]] = []

    class FakeSslContext:
        def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
            loaded_chain.append((certfile, keyfile))

    ssl_context = FakeSslContext()
    monkeypatch.setattr(
        validator_quorum.ssl,
        "create_default_context",
        lambda *, cafile: ssl_context if cafile == str(ca_path) else None,
    )

    client_kwargs: dict[str, object] = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs) -> None:
            client_kwargs.update(kwargs)

    monkeypatch.setattr(validator_quorum.httpx, "AsyncClient", FakeAsyncClient)

    settings = Settings(
        runtime_environment="test",
        zkpassport_validator_mtls_ca_path=str(ca_path),
        zkpassport_validator_mtls_cert_path=str(cert_path),
        zkpassport_validator_mtls_key_path=str(key_path),
    )
    validator_quorum._private_validator_client(settings)

    assert loaded_chain == [(str(cert_path), str(key_path))]
    assert client_kwargs["verify"] is ssl_context
    assert client_kwargs["trust_env"] is False
    assert "cert" not in client_kwargs


def _client(keys, claim, failures: set[int], forged: set[int] = set()):
    async def handler(request: httpx.Request) -> httpx.Response:
        index = int(request.url.host.split("-")[1].split(".")[0])
        if index in failures:
            return httpx.Response(503, json={"detail": "offline"})
        body = json.loads(request.content)
        assert body["claim"] == claim.model_dump(mode="json")
        signature_key = keys[(index + 1) % 3] if index in forged else keys[index]
        signature = AugSchemeMPL.sign(signature_key, claim.signature_message())
        return httpx.Response(
            200,
            json={
                "claimHash": claim.canonical_hash(),
                "signerIndex": index,
                "validatorPubkey": "0x" + bytes(keys[index].get_g1()).hex(),
                "signature": "0x" + bytes(signature).hex(),
            },
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_any_two_independent_signers_reach_quorum():
    keys = _keys()
    claim = _claim(keys)
    async with _client(keys, claim, failures={1}) as client:
        result = await collect_validator_quorum(_settings(keys), claim, client=client)

    assert result.signer_indices == (0, 2)
    public_keys = [G1Element.from_bytes(bytes(keys[index].get_g1())) for index in (0, 2)]
    assert AugSchemeMPL.aggregate_verify(
        public_keys,
        [claim.signature_message(), claim.signature_message()],
        result.aggregated_signature,
    )


@pytest.mark.asyncio
async def test_one_validator_cannot_authorize_a_stamp():
    keys = _keys()
    claim = _claim(keys)
    async with _client(keys, claim, failures={1, 2}) as client:
        with pytest.raises(ValidatorQuorumError, match="received 1 of 2"):
            await collect_validator_quorum(_settings(keys), claim, client=client)


@pytest.mark.asyncio
async def test_forged_signature_does_not_count_toward_quorum():
    keys = _keys()
    claim = _claim(keys)
    async with _client(keys, claim, failures={2}, forged={1}) as client:
        with pytest.raises(ValidatorQuorumError, match="received 1 of 2"):
            await collect_validator_quorum(_settings(keys), claim, client=client)


@pytest.mark.asyncio
async def test_claim_policy_must_match_ordered_validator_set():
    keys = _keys()
    claim = _claim(keys).model_copy(update={"bridge_policy_hash": "0x" + "ff" * 32})
    async with _client(keys, claim, failures=set()) as client:
        with pytest.raises(ValidatorQuorumError, match="bridge policy"):
            await collect_validator_quorum(_settings(keys), claim, client=client)


def _health_client(keys, *, wrong_api_index: int | None = None):
    policy_hash = "0x" + bytes(
        make_bridge_policy_hash([bytes(key.get_g1()) for key in keys], 2)
    ).hex()

    async def handler(request: httpx.Request) -> httpx.Response:
        index = int(request.url.host.split("-")[1].split(".")[0])
        return httpx.Response(
            200,
            json={
                "status": "healthy",
                "signerIndex": index,
                "validatorPubkey": "0x" + bytes(keys[index].get_g1()).hex(),
                "apiCommit": "f" * 40 if index == wrong_api_index else "a" * 40,
                "protocolCommit": "b" * 40,
                "network": "testnet11",
                "bridgePolicyHash": policy_hash,
                "evmAddresses": {
                    "forwarder": "0x" + "11" * 20,
                    "verifierAdapter": "0x" + "22" * 20,
                    "attestationEmitter": "0x" + "33" * 20,
                },
                "artifactHash": None,
                "artifactReady": False,
                "ledgerReady": True,
            },
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_live_health_binds_all_signers_to_ceremony_release_and_addresses():
    keys = _keys()
    policy_hash = "0x" + bytes(
        make_bridge_policy_hash([bytes(key.get_g1()) for key in keys], 2)
    ).hex()
    async with _health_client(keys) as client:
        health = await probe_validator_health(
            _settings(keys),
            expected_api_commit="a" * 40,
            expected_protocol_commit="b" * 40,
            expected_network="testnet11",
            expected_bridge_policy_hash=policy_hash,
            expected_evm_addresses={
                "forwarder": "0x" + "11" * 20,
                "verifierAdapter": "0x" + "22" * 20,
                "attestationEmitter": "0x" + "33" * 20,
            },
            client=client,
        )
    assert [item.signerIndex for item in health] == [0, 1, 2]


@pytest.mark.asyncio
async def test_uploaded_healthy_flags_cannot_hide_stale_live_signer_release():
    keys = _keys()
    policy_hash = "0x" + bytes(
        make_bridge_policy_hash([bytes(key.get_g1()) for key in keys], 2)
    ).hex()
    async with _health_client(keys, wrong_api_index=1) as client:
        with pytest.raises(ValidatorQuorumError, match="API commit"):
            await probe_validator_health(
                _settings(keys),
                expected_api_commit="a" * 40,
                expected_protocol_commit="b" * 40,
                expected_network="testnet11",
                expected_bridge_policy_hash=policy_hash,
                expected_evm_addresses={
                    "forwarder": "0x" + "11" * 20,
                    "verifierAdapter": "0x" + "22" * 20,
                    "attestationEmitter": "0x" + "33" * 20,
                },
                client=client,
            )
