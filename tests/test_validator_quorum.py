from __future__ import annotations

import json

import httpx
import pytest
from chia_rs import AugSchemeMPL, G1Element
from chia_rs.sized_bytes import bytes32

from solslot_api import validator_quorum
from solslot_api.config import Settings
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.validator_quorum import (
    InventoryReservationClaim,
    PrimaryPurchaseClaim,
    ValidatorClaim,
    ValidatorQuorumError,
    VoucherSeriesPhaseClaim,
    VoucherTransitionClaim,
    collect_inventory_reservation_quorum,
    collect_primary_purchase_quorum,
    collect_validator_quorum,
    collect_voucher_series_phase_quorum,
    collect_voucher_transition_quorum,
    probe_validator_health,
)
from solslot_puzzles.payment_artifacts_v3 import (
    build_stripe_purchase_artifact,
    purchase_artifact_to_json,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault
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


def _primary_claim() -> PrimaryPurchaseClaim:
    owner_key = AugSchemeMPL.key_gen(b"o" * 32).get_g1()
    return PrimaryPurchaseClaim(
        network="testnet11",
        genesis_artifact_hash="0x" + "21" * 32,
        purchase_artifact={
            "purchaseId": "0x" + "22" * 32,
            "artifactHash": "0x" + "23" * 32,
        },
        buyer_offer="offer1test-primary-purchase",
        deed_coin_id="0x" + "24" * 32,
        deed_puzzle_hash="0x" + "25" * 32,
        smart_deed_inner_hash="0x" + "26" * 32,
        protocol_puzzle_hash="0x" + "27" * 32,
        credential_vault_coin_id="0x" + "28" * 32,
        credential_identity_root="0x" + "29" * 32,
        credential_policy_version=2,
        credential_bridge_policy_hash="0x" + "2a" * 32,
        credential_owner_auth_type=1,
        credential_owner_key="0x" + bytes(owner_key).hex(),
    )


def _inventory_claim() -> InventoryReservationClaim:
    owner_key = AugSchemeMPL.key_gen(b"r" * 32).get_g1()
    vault_launcher = bytes32(b"v" * 32)
    purchase = build_stripe_purchase_artifact(
        network="testnet11",
        collection_id=bytes32(b"c" * 32),
        deed_launcher_id=bytes32(b"d" * 32),
        metadata_root=bytes32(b"m" * 32),
        metadata_anchor_id=bytes32.zeros,
        share_ppm=40_000,
        base_amount_minor=10_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=bytes32(b"t" * 32),
        zkpassport_root=bytes32(b"z" * 32),
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        authorization_nonce=bytes32(b"n" * 32),
        authorization_expires_at=2_000_000_100,
        quote_expires_at=2_000_000_000,
    )
    return InventoryReservationClaim(
        network="testnet11",
        genesis_artifact_hash="0x" + "51" * 32,
        purchase_artifact=purchase_artifact_to_json(purchase),
        reservation_expires_at=1_999_999_900,
        available_coin_id="0x" + "52" * 32,
        available_puzzle_hash="0x" + "53" * 32,
        reserved_coin_id="0x" + "54" * 32,
        reserved_puzzle_hash="0x" + "55" * 32,
        smart_deed_inner_hash="0x" + "56" * 32,
        protocol_puzzle_hash="0x" + "57" * 32,
        credential_vault_coin_id="0x" + "58" * 32,
        credential_identity_root="0x" + "59" * 32,
        credential_policy_version=2,
        credential_bridge_policy_hash="0x" + "5a" * 32,
        credential_owner_auth_type=1,
        credential_owner_key="0x" + bytes(owner_key).hex(),
        validator_message="0x" + "5b" * 32,
    )


def _voucher_transition_claim() -> VoucherTransitionClaim:
    owner_key = AugSchemeMPL.key_gen(b"v" * 32).get_g1()
    return VoucherTransitionClaim(
        network="testnet11",
        genesis_artifact_hash="0x" + "31" * 32,
        series_terms={"seriesId": "0x" + "32" * 32},
        voucher_commitment={"globalPaymentId": "0x" + "33" * 32},
        purchase_artifact={"artifactHash": "0x" + "34" * 32},
        series_coin_id="0x" + "35" * 32,
        series_sold_count=1,
        series_redeemed_count=0,
        series_refunded_count=0,
        series_phase=1,
        series_launched_at=0,
        voucher_launcher_id="0x" + "36" * 32,
        voucher_coin_id="0x" + "37" * 32,
        payment_coin_id="0x" + "38" * 32,
        vault_launcher_id="0x" + "39" * 32,
        vault_coin_id="0x" + "3a" * 32,
        vault_identity_attest_root="0x" + "3b" * 32,
        vault_owner_auth_type=1,
        vault_owner_key="0x" + bytes(owner_key).hex(),
        owner_authorization="0x" + "3c" * 96,
        current_timestamp=1_800_000_000,
        action=1,
        validator_message="0x" + "3d" * 32,
    )


def _voucher_series_phase_claim() -> VoucherSeriesPhaseClaim:
    return VoucherSeriesPhaseClaim(
        network="testnet11",
        genesis_artifact_hash="0x" + "41" * 32,
        series_terms={"seriesId": "0x" + "42" * 32},
        series_coin_id="0x" + "43" * 32,
        series_sold_count=2,
        series_redeemed_count=0,
        series_refunded_count=0,
        series_phase=1,
        series_launched_at=0,
        transition=2,
        launch_anchor=1_800_000_000,
        deed_launcher_ids=["0x" + "44" * 32, "0x" + "45" * 32],
        governance_execution_ids=["0x" + "46" * 32, "0x" + "47" * 32],
        validator_message="0x" + "48" * 32,
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
async def test_inventory_reservation_uses_two_independent_signers():
    keys = _keys()
    claim = _inventory_claim()
    async with _client(keys, claim, failures={1}) as client:
        result = await collect_inventory_reservation_quorum(
            _settings(keys),
            claim,
            client=client,
        )
    assert result.signer_indices == (0, 2)
    assert AugSchemeMPL.aggregate_verify(
        [keys[0].get_g1(), keys[2].get_g1()],
        [claim.signature_message(), claim.signature_message()],
        result.aggregated_signature,
    )
    assert claim.signature_message() == (
        bytes.fromhex(claim.validator_message[2:])
        + bytes.fromhex(claim.available_coin_id[2:])
        + AGG_SIG_ME_DATA["testnet11"]
    )


@pytest.mark.asyncio
async def test_primary_purchase_collects_two_signers_for_deed_coin_message():
    keys = _keys()
    claim = _primary_claim()

    async def handler(request: httpx.Request) -> httpx.Response:
        index = int(request.url.host.split("-")[1].split(".")[0])
        assert request.url.path == "/v1/primary-purchase/sign"
        body = json.loads(request.content)
        assert body["claim"] == claim.model_dump(mode="json")
        signature = AugSchemeMPL.sign(keys[index], claim.signature_message())
        return httpx.Response(
            200,
            json={
                "claimHash": claim.canonical_hash(),
                "signerIndex": index,
                "validatorPubkey": "0x" + bytes(keys[index].get_g1()).hex(),
                "signature": "0x" + bytes(signature).hex(),
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await collect_primary_purchase_quorum(
            _settings(keys),
            claim,
            client=client,
        )

    assert result.signer_indices == (0, 1)
    assert AugSchemeMPL.aggregate_verify(
        [keys[0].get_g1(), keys[1].get_g1()],
        [claim.signature_message(), claim.signature_message()],
        result.aggregated_signature,
    )


def test_voucher_transition_binds_three_distinct_coin_messages() -> None:
    claim = _voucher_transition_claim()
    messages = claim.signature_messages()

    assert len(messages) == 3
    assert len(set(messages)) == 3
    assert bytes.fromhex(claim.series_coin_id[2:]) in messages[0]
    assert bytes.fromhex(claim.voucher_coin_id[2:]) in messages[1]
    assert bytes.fromhex(claim.payment_coin_id[2:]) in messages[2]


def test_base_voucher_transition_uses_receipt_evidence_message() -> None:
    payload = _voucher_transition_claim().model_dump(mode="json")
    payload["voucher_commitment"] = {
        **payload["voucher_commitment"],
        "paymentRail": 1,
    }
    payload.update(
        payment_evidence={"source": {"chainId": 84532}},
        external_settlement_evidence_hash="0x" + "4a" * 32,
        external_validator_message="0x" + "4b" * 32,
    )
    claim = VoucherTransitionClaim.model_validate(payload)
    messages = claim.signature_messages()

    assert len(messages) == 3
    assert bytes.fromhex(claim.external_validator_message[2:]) in messages[2]
    assert bytes.fromhex(claim.validator_message[2:]) not in messages[2]
    assert bytes.fromhex(claim.payment_coin_id[2:]) in messages[2]

    with pytest.raises(ValueError, match="authenticated settlement evidence"):
        VoucherTransitionClaim.model_validate(
            {**payload, "external_validator_message": None}
        )


def test_voucher_redemption_binds_the_governed_deed_without_owner_signature() -> None:
    payload = _voucher_transition_claim().model_dump(mode="json")
    payload.update(
        action=3,
        owner_authorization="",
        deed_coin_id="0x" + "3e" * 32,
        deed_puzzle_hash="0x" + "3f" * 32,
        smart_deed_inner_hash="0x" + "40" * 32,
        protocol_puzzle_hash="0x" + "41" * 32,
        buyer_offer="offer1" + "42" * 16,
    )
    claim = VoucherTransitionClaim.model_validate(payload)
    messages = claim.signature_messages()

    assert len(messages) == 4
    assert len(set(messages)) == 4
    assert bytes.fromhex(claim.deed_coin_id[2:]) in messages[3]
    assert bytes.fromhex(payload["purchase_artifact"]["artifactHash"][2:]) in messages[3]

    with pytest.raises(ValueError, match="second owner signature"):
        VoucherTransitionClaim.model_validate(
            {**payload, "owner_authorization": "0x" + "43" * 96}
        )
    with pytest.raises(ValueError, match="exact deed evidence"):
        VoucherTransitionClaim.model_validate({**payload, "buyer_offer": None})


def test_stripe_v3_redemption_binds_receipt_deed_and_reservation_expiry() -> None:
    payload = _voucher_transition_claim().model_dump(mode="json")
    payload.update(
        voucher_commitment={
            **payload["voucher_commitment"],
            "schema": "solslot.voucher-commitment.v3",
            "paymentRail": 3,
        },
        action=3,
        owner_authorization="",
        deed_coin_id="0x" + "51" * 32,
        deed_puzzle_hash="0x" + "52" * 32,
        smart_deed_inner_hash="0x" + "53" * 32,
        protocol_puzzle_hash="0x" + "54" * 32,
        buyer_offer="offer1" + "55" * 16,
        payment_evidence={"schema": "solslot.stripe-settlement-evidence.v1"},
        external_settlement_evidence_hash="0x" + "56" * 32,
        external_validator_message="0x" + "57" * 32,
        reservation_expires_at=1_800_086_400,
    )
    claim = VoucherTransitionClaim.model_validate(payload)
    messages = claim.signature_messages()

    assert len(messages) == 4
    assert len(set(messages)) == 4
    assert bytes.fromhex(claim.external_validator_message[2:]) in messages[2]
    assert bytes.fromhex(claim.deed_coin_id[2:]) in messages[3]

    with pytest.raises(ValueError, match="exact reservation expiry"):
        VoucherTransitionClaim.model_validate(
            {**payload, "reservation_expires_at": None}
        )


def test_stripe_v3_refund_binds_receipt_without_deed_or_reservation() -> None:
    payload = _voucher_transition_claim().model_dump(mode="json")
    payload.update(
        voucher_commitment={
            **payload["voucher_commitment"],
            "schema": "solslot.voucher-commitment.v3",
            "paymentRail": 3,
        },
        payment_evidence={"schema": "solslot.stripe-settlement-evidence.v1"},
        external_settlement_evidence_hash="0x" + "58" * 32,
        external_validator_message="0x" + "59" * 32,
    )
    claim = VoucherTransitionClaim.model_validate(payload)

    assert len(claim.signature_messages()) == 3
    assert claim.deed_coin_id is None
    assert claim.reservation_expires_at is None


def test_expired_refund_forbids_owner_and_deed_evidence() -> None:
    payload = _voucher_transition_claim().model_dump(mode="json")
    payload.update(
        action=2,
        vault_coin_id=None,
        vault_identity_attest_root=None,
        vault_owner_auth_type=None,
        vault_owner_key=None,
        owner_authorization="",
    )
    claim = VoucherTransitionClaim.model_validate(payload)

    assert len(claim.signature_messages()) == 3
    assert claim.vault_coin_id is None
    with pytest.raises(ValueError, match="current vault ownership evidence"):
        VoucherTransitionClaim.model_validate(
            {**payload, "vault_coin_id": "0x" + "44" * 32}
        )
    with pytest.raises(ValueError, match="owner signature"):
        VoucherTransitionClaim.model_validate(
            {**payload, "owner_authorization": "0x" + "45" * 96}
        )
    with pytest.raises(ValueError, match="cannot carry deed evidence"):
        VoucherTransitionClaim.model_validate(
            {**payload, "deed_coin_id": "0x" + "46" * 32}
        )


@pytest.mark.asyncio
async def test_voucher_transition_collects_two_aggregate_signers() -> None:
    keys = _keys()
    claim = _voucher_transition_claim()
    messages = claim.signature_messages()

    async def handler(request: httpx.Request) -> httpx.Response:
        index = int(request.url.host.split("-")[1].split(".")[0])
        assert request.url.path == "/v1/voucher-transition/sign"
        body = json.loads(request.content)
        assert body["claim"] == claim.model_dump(mode="json")
        signature = AugSchemeMPL.aggregate(
            [AugSchemeMPL.sign(keys[index], message) for message in messages]
        )
        return httpx.Response(
            200,
            json={
                "claimHash": claim.canonical_hash(),
                "signerIndex": index,
                "validatorPubkey": "0x" + bytes(keys[index].get_g1()).hex(),
                "signature": "0x" + bytes(signature).hex(),
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await collect_voucher_transition_quorum(
            _settings(keys),
            claim,
            client=client,
        )

    assert result.signer_indices == (0, 1)
    assert AugSchemeMPL.aggregate_verify(
        [keys[0].get_g1()] * 3 + [keys[1].get_g1()] * 3,
        list(messages) + list(messages),
        result.aggregated_signature,
    )


@pytest.mark.asyncio
async def test_voucher_transition_rejects_partial_protocol_signature() -> None:
    keys = _keys()
    claim = _voucher_transition_claim()

    async def handler(request: httpx.Request) -> httpx.Response:
        index = int(request.url.host.split("-")[1].split(".")[0])
        signature = AugSchemeMPL.sign(keys[index], claim.signature_messages()[0])
        return httpx.Response(
            200,
            json={
                "claimHash": claim.canonical_hash(),
                "signerIndex": index,
                "validatorPubkey": "0x" + bytes(keys[index].get_g1()).hex(),
                "signature": "0x" + bytes(signature).hex(),
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValidatorQuorumError, match="received 0 of 2"):
            await collect_voucher_transition_quorum(
                _settings(keys),
                claim,
                client=client,
            )


@pytest.mark.asyncio
async def test_series_phase_collects_two_independent_signers() -> None:
    keys = _keys()
    claim = _voucher_series_phase_claim()

    async def handler(request: httpx.Request) -> httpx.Response:
        index = int(request.url.host.split("-")[1].split(".")[0])
        assert request.url.path == "/v1/voucher-series-phase/sign"
        signature = AugSchemeMPL.sign(keys[index], claim.signature_message())
        return httpx.Response(
            200,
            json={
                "claimHash": claim.canonical_hash(),
                "signerIndex": index,
                "validatorPubkey": "0x" + bytes(keys[index].get_g1()).hex(),
                "signature": "0x" + bytes(signature).hex(),
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await collect_voucher_series_phase_quorum(
            _settings(keys),
            claim,
            client=client,
        )

    assert result.signer_indices == (0, 1)
    assert AugSchemeMPL.aggregate_verify(
        [keys[0].get_g1(), keys[1].get_g1()],
        [claim.signature_message(), claim.signature_message()],
        result.aggregated_signature,
    )


def test_series_cancel_rejects_launch_evidence() -> None:
    with pytest.raises(ValueError, match="cancellation cannot carry"):
        VoucherSeriesPhaseClaim(
            **{
                **_voucher_series_phase_claim().model_dump(),
                "transition": 3,
                "launch_anchor": 0,
            }
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


def _health_client(
    keys,
    *,
    wrong_api_index: int | None = None,
    artifact_hash: str | None = None,
):
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
                "artifactHash": artifact_hash,
                "artifactReady": artifact_hash is not None,
                "ledgerReady": True,
                "stripeSettlementReady": True,
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
async def test_live_health_binds_pre_and_post_genesis_artifact_phase():
    keys = _keys()
    policy_hash = "0x" + bytes(
        make_bridge_policy_hash([bytes(key.get_g1()) for key in keys], 2)
    ).hex()
    kwargs = {
        "expected_api_commit": "a" * 40,
        "expected_protocol_commit": "b" * 40,
        "expected_network": "testnet11",
        "expected_bridge_policy_hash": policy_hash,
        "expected_evm_addresses": {
            "forwarder": "0x" + "11" * 20,
            "verifierAdapter": "0x" + "22" * 20,
            "attestationEmitter": "0x" + "33" * 20,
        },
    }
    async with _health_client(keys) as client:
        await probe_validator_health(
            _settings(keys),
            **kwargs,
            expected_artifact_ready=False,
            client=client,
        )
    artifact_hash = "0x" + "44" * 32
    async with _health_client(keys, artifact_hash=artifact_hash) as client:
        await probe_validator_health(
            _settings(keys),
            **kwargs,
            expected_artifact_ready=True,
            expected_artifact_hash=artifact_hash,
            client=client,
        )
    async with _health_client(keys) as client:
        with pytest.raises(ValidatorQuorumError, match="artifact readiness"):
            await probe_validator_health(
                _settings(keys),
                **kwargs,
                expected_artifact_ready=True,
                client=client,
            )


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
