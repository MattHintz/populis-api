from __future__ import annotations

import json
import hashlib
import time

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from fastapi import HTTPException
from fastapi.testclient import TestClient

from solslot_api.app import app
from solslot_api.config import get_settings, validate_server_hardening_at_startup
from solslot_api.payment_quotes import SNAPSHOT_SCHEMA
from solslot_puzzles.payment_artifacts_v2 import (
    OracleObservationV1,
    build_oracle_round,
    oracle_operator_set_root,
    oracle_round_signature_message,
    oracle_round_to_json,
    purchase_artifact_from_json,
)
from solslot_api.zkpassport_enrollments import (
    AttestationProof,
    EnrollmentRecord,
    VaultCredentialReceipt,
)


VAULT_ID = "0x" + "22" * 32
IDENTITY_ROOT = "0x" + "44" * 32
BRIDGE_POLICY = "0x" + "c1" * 32


def _active_genesis_artifact() -> dict:
    return {
        "artifactHash": "0x" + "d1" * 32,
        "launcherIds": {
            "pool": "0x" + "aa" * 32,
            "protocolConfig": "0x" + "bb" * 32,
            "vaultVersionRegistry": "0x" + "cc" * 32,
        },
        "bridgePolicy": {"policyHash": BRIDGE_POLICY},
        "retiredCoordinates": ["0x" + "e1" * 32],
    }


@pytest.fixture(autouse=True)
def isolate_protocol_artifact_env(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "SOLSLOT_DEPLOYMENT_MANIFEST_PATH",
        str(tmp_path / "missing.json"),
    )
    for name in (
        "SOLSLOT_ADMIN_PUBKEY_ALLOWLIST",
        "SOLSLOT_ADMIN_JWT_SECRET",
        "SOLSLOT_ADMIN_RECORDS_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SOLSLOT_POOL_LAUNCHER_ID", "0x" + "aa" * 32)
    monkeypatch.setenv("SOLSLOT_PROTOCOL_CONFIG_LAUNCHER_ID", "0x" + "bb" * 32)
    monkeypatch.setenv("SOLSLOT_VAULT_VERSION_REGISTRY_LAUNCHER_ID", "0x" + "cc" * 32)
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_BRIDGE_POLICY_HASH", BRIDGE_POLICY)
    monkeypatch.setenv(
        "SOLSLOT_PAYMENT_PURCHASE_DB_PATH",
        str(tmp_path / "payment-purchases.db"),
    )

    def confirmed_enrollment(_settings, vault_launcher_id):
        assert vault_launcher_id == VAULT_ID
        receipt = VaultCredentialReceipt(
            vaultLauncherId=VAULT_ID,
            network="testnet11",
            policyVersion=2,
            identityAttestRoot=IDENTITY_ROOT,
            attestationLeafHash=IDENTITY_ROOT,
            attestationProof=AttestationProof(bitpath=0, siblings=[]),
            bridgePolicyHash=BRIDGE_POLICY,
            bridgeParentId="0x" + "55" * 32,
            bridgeAmount=1,
            bridgeCoinId="0x" + "66" * 32,
            evmTxHash="0x" + "77" * 32,
            chiaVaultCoinId="0x" + "88" * 32,
            confirmedBlockIndex=12345,
            enrolledAt=int(time.time()) - 60,
        )
        now = int(time.time())
        return EnrollmentRecord(
            vaultLauncherId=VAULT_ID,
            network="testnet11",
            policyVersion=2,
            status="chia_confirmed",
            bridgePolicyHash=BRIDGE_POLICY,
            bridgeParentId=receipt.bridgeParentId,
            bridgeAmount=1,
            bridgeCoinId=receipt.bridgeCoinId,
            createdAt=now - 60,
            updatedAt=now,
            receipt=receipt,
        )

    monkeypatch.setattr(
        "solslot_api.zkpassport_enrollments._sync_chia_stamp",
        confirmed_enrollment,
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.load_signed_public_artifact",
        lambda _settings: _active_genesis_artifact(),
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _request(**overrides):
    base = {
        "protocol_version": "solslot-v2",
        "network": "testnet11",
        "genesis_artifact_hash": "0x" + "d1" * 32,
        "instance_id": "solslot-staging",
        "purchase_intent_id": "pi_test_001",
        "rail": "chia",
        "deed_launcher_id": "0x" + "11" * 32,
        "property_id": "US-TX-AUSTIN-001",
        "collection_id": "SOL-LOT-AUSTIN-ALPHA",
        "share_ppm": 25_000,
        "vault_launcher_id": VAULT_ID,
        "current_vault_coin_id": "0x" + "88" * 32,
        "identity_attest_root": IDENTITY_ROOT,
        "expires_at": int(time.time()) + 3600,
        "payment_terms": {
            "currency": "wUSDC",
            "amount": 125_000,
            "quantity": 1,
        },
    }
    base.update(overrides)
    return base


def _published_collection(
    *,
    offering_currency: str = "USD",
    target_raise_minor: str = "5000000",
) -> dict:
    return {
        "id": "SOL-LOT-AUSTIN-ALPHA",
        "state": "PUBLISHED",
        "allocationLocked": True,
        "metadataRoot": "0x" + "12" * 32,
        "metadataAnchorId": "0x" + "13" * 32,
        "dossier": {
            "offering": {
                "currency": offering_currency,
                "targetRaiseMinor": target_raise_minor,
            },
            "deedAllocation": [
                {
                    "deedId": "US-TX-AUSTIN-001",
                    "sharePpm": 25_000,
                    "parValueMojos": "250000000000",
                },
                {
                    "deedId": "US-TX-AUSTIN-002",
                    "sharePpm": 975_000,
                    "parValueMojos": "9750000000000",
                },
            ],
        },
        "deeds": [
            {
                "deedId": "US-TX-AUSTIN-001",
                "deedLauncherId": "0x" + "11" * 32,
                "sharePpm": 25_000,
                "parValueMojos": "250000000000",
                "executeBundleId": "0x" + "31" * 32,
                "confirmationHeight": 12346,
            }
        ],
    }


def _configure_native_quote(
    monkeypatch,
    tmp_path,
    now: int,
    *,
    offering_currency: str = "USD",
    target_raise_minor: str = "5000000",
) -> None:
    keys = tuple(
        AugSchemeMPL.key_gen(bytes([seed]) * 32)
        for seed in (81, 82, 83)
    )
    pubkeys = tuple(bytes(key.get_g1()) for key in keys)
    observations = tuple(
        OracleObservationV1(
            source_id=bytes32(bytes([index]) * 32),
            asset_id=bytes32.zeros,
            asset_decimals=12,
            price_usd_minor_per_asset=price,
            observed_at=now - 10 + index,
            valid_until=now + 300 + index,
            evidence_hash=bytes32(bytes([index + 20]) * 32),
        )
        for index, price in enumerate((2100, 2125, 2150), start=1)
    )
    round_ = build_oracle_round(
        network="testnet11",
        sequence=202,
        asset_id=bytes32.zeros,
        asset_decimals=12,
        operator_set_root=oracle_operator_set_root(pubkeys),
        observations=observations,
    )
    message = oracle_round_signature_message(round_.round_hash)
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "generatedAt": now,
        "rounds": [
            {
                "round": oracle_round_to_json(round_),
                "signatures": [
                    {
                        "signerIndex": index,
                        "signature": "0x"
                        + bytes(
                            AugSchemeMPL.sign(keys[index], message)
                        ).hex(),
                    }
                    for index in (0, 1)
                ],
            }
        ],
    }
    path = tmp_path / "native-quotes.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    monkeypatch.setenv("SOLSLOT_PAYMENT_ORACLE_ROUNDS_PATH", str(path))
    monkeypatch.setenv(
        "SOLSLOT_PAYMENT_ORACLE_OPERATOR_PUBKEYS",
        json.dumps(["0x" + value.hex() for value in pubkeys]),
    )
    monkeypatch.setenv("SOLSLOT_COLLECTION_METADATA_ENABLED", "true")

    class Store:
        @staticmethod
        def get(collection_id):
            assert collection_id == "SOL-LOT-AUSTIN-ALPHA"
            return _published_collection(
                offering_currency=offering_currency,
                target_raise_minor=target_raise_minor,
            )

    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.get_collection_store",
        lambda _settings: Store(),
    )
    get_settings.cache_clear()


def _configure_external_quote(
    monkeypatch,
    tmp_path,
    *,
    offering_currency: str = "USD",
    target_raise_minor: str = "5000000",
) -> None:
    monkeypatch.setenv("SOLSLOT_COLLECTION_METADATA_ENABLED", "true")
    evidence = {
        "schemaVersion": 1,
        "protocolVersion": "solslot-v2",
        "rail": "ccip-warp-escrow",
        "sourceSha": "a" * 40,
        "network": "baseSepolia",
        "chainId": 84532,
        "chainSelector": "10344971235874465080",
        "confirmations": 12,
        "contracts": {
            "ccipRouter": "0x" + "11" * 20,
            "gateway": "0x" + "12" * 20,
            "spoke": "0x" + "13" * 20,
            "usdc": "0x" + "ab" * 20,
            "usdt": "0x" + "ac" * 20,
        },
        "configuration": {
            "hubChainSelector": "10344971235874465080",
            "callbackGas": "500000",
            "emergencyDelay": "604800",
            "payoutAddress": "0x" + "14" * 20,
            "governance": "0x" + "15" * 20,
            "ownershipAccepted": False,
        },
        "deploymentTransactions": {
            "spoke": {"hash": "0x" + "21" * 32, "blockNumber": 1},
        },
        "runtimeCodeHashes": {
            name: "0x" + value * 32
            for name, value in {
                "ccipRouter": "31",
                "gateway": "32",
                "spoke": "33",
                "usdc": "34",
                "usdt": "35",
            }.items()
        },
        "createdAt": "2026-07-20T00:00:00.000Z",
    }
    canonical = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    evidence["artifactHash"] = "0x" + hashlib.sha256(canonical).hexdigest()
    deployment_path = tmp_path / "omnichain-deployment-evidence.json"
    deployment_path.write_text(json.dumps(evidence), encoding="utf-8")
    activation = {
        "schemaVersion": 1,
        "kind": "ccip-warp-escrow-activation",
        "deploymentArtifactHash": evidence["artifactHash"],
        "sourceSha": evidence["sourceSha"],
        "network": evidence["network"],
        "chainId": evidence["chainId"],
        "gatewayProfile": "bse",
        "contracts": {
            name: evidence["contracts"][name] for name in ("gateway", "spoke")
        },
        "runtimeCodeHashes": {
            name: evidence["runtimeCodeHashes"][name] for name in ("gateway", "spoke")
        },
        "governance": evidence["configuration"]["governance"],
        "observedOwners": {
            name: evidence["configuration"]["governance"] for name in ("gateway", "spoke")
        },
        "ownershipAccepted": True,
        "activatedAt": "2026-07-20T00:00:01.000Z",
    }
    activation_canonical = json.dumps(
        activation, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    activation["artifactHash"] = "0x" + hashlib.sha256(activation_canonical).hexdigest()
    activation_path = tmp_path / "omnichain-activation-evidence.json"
    activation_path.write_text(json.dumps(activation), encoding="utf-8")
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ENABLED", "true")
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_EVIDENCE_PATH", str(deployment_path))
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ACTIVATION_EVIDENCE_PATH", str(activation_path))
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_GATEWAY_PROFILE", "bse")
    monkeypatch.setenv(
        "SOLSLOT_PAYMENT_EVM_USDC_TOKENS",
        json.dumps(
            {
                "84532": "0x"
                + "ab" * 20,
            }
        ),
    )

    class Store:
        @staticmethod
        def get(collection_id):
            assert collection_id == "SOL-LOT-AUSTIN-ALPHA"
            return _published_collection(
                offering_currency=offering_currency,
                target_raise_minor=target_raise_minor,
            )

    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.get_collection_store",
        lambda _settings: Store(),
    )
    get_settings.cache_clear()


def test_evm_offer_requires_reviewed_omnichain_evidence(monkeypatch, tmp_path):
    _configure_external_quote(monkeypatch, tmp_path)
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ENABLED", "false")
    get_settings.cache_clear()
    now = int(time.time())
    with TestClient(app) as client:
        response = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="base_usdc",
                purchase_intent_id="pi_omnichain_disabled",
                expires_at=now + 900,
                authorization_nonce="0x" + "18" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={"currency": "USDC", "quantity": 1, "chain_id": 84532},
            ),
        )
    assert response.status_code == 503
    assert "Omnichain payments are disabled" in response.text


def test_evm_offer_requires_omnichain_activation_evidence(monkeypatch, tmp_path):
    _configure_external_quote(monkeypatch, tmp_path)
    monkeypatch.delenv("SOLSLOT_PAYMENT_OMNICHAIN_ACTIVATION_EVIDENCE_PATH")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="activation evidence is not configured"):
        validate_server_hardening_at_startup(get_settings())


def test_evm_offer_rejects_tampered_omnichain_evidence(monkeypatch, tmp_path):
    _configure_external_quote(monkeypatch, tmp_path)
    path = tmp_path / "omnichain-deployment-evidence.json"
    evidence = json.loads(path.read_text(encoding="utf-8"))
    evidence["sourceSha"] = "b" * 40
    path.write_text(json.dumps(evidence), encoding="utf-8")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="deployment evidence hash mismatches"):
        validate_server_hardening_at_startup(get_settings())


def test_builds_and_verifies_protocol_offer_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    with TestClient(app) as client:
        built = client.post("/protocol/offer-artifacts", json=_request())
        assert built.status_code == 200, built.text
        body = built.json()
        assert body["artifact_hash"].startswith("sha256:")
        assert body["protocol"]["zkPassportRequired"] is True
        assert body["protocol"]["artifactHash"] == body["artifact_hash"]

        verified = client.post(
            "/protocol/offer-artifacts/verify",
            json={
                "artifact": body["artifact"],
                "artifact_hash": body["artifact_hash"],
            },
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["valid"] is True


def test_builds_native_xch_offer_from_server_authorized_quote(
    monkeypatch,
    tmp_path,
):
    now = int(time.time())
    _configure_native_quote(monkeypatch, tmp_path, now)
    native_request = _request(
        rail="chia_xch",
        purchase_intent_id="pi_xch_native",
        expires_at=now + 240,
        payment_terms={
            "currency": "XCH",
            "quantity": 1,
        },
        authorization_nonce="0x" + "14" * 32,
        authorization_expires_at=now + 600,
    )
    native_request.pop("deed_launcher_id")
    native_request.pop("share_ppm")
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=native_request,
        )
        assert built.status_code == 200, built.text
        body = built.json()
        canonical = purchase_artifact_from_json(body["purchase_artifact"])
        assert canonical.usd_amount_minor == 125_000
        assert canonical.rail_amount > 0
        assert body["purchase_artifact_hash"] == (
            "0x" + bytes(canonical.artifact_hash).hex()
        )
        assert body["purchase_id"] == (
            "0x" + bytes(canonical.purchase_id).hex()
        )
        assert body["protocol"]["purchaseArtifactHash"] == (
            body["purchase_artifact_hash"]
        )

        verified = client.post(
            "/protocol/offer-artifacts/verify",
            json={
                "artifact": body["artifact"],
                "artifact_hash": body["artifact_hash"],
                "now": now,
            },
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["valid"] is True, verified.json()


def test_quote_price_uses_target_raise_share_not_chia_par_value(
    monkeypatch,
    tmp_path,
):
    _configure_external_quote(monkeypatch, tmp_path)
    now = int(time.time())
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="stripe",
                purchase_intent_id="pi_exact_dossier_price",
                expires_at=now + 900,
                authorization_nonce="0x" + "15" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={"currency": "USD", "quantity": 1},
            ),
        )
    assert built.status_code == 200, built.text
    purchase = built.json()["purchase_artifact"]
    assert purchase["usdAmountMinor"] == 125_000
    assert purchase["usdAmountMinor"] != 250_000_000_000


@pytest.mark.parametrize(
    ("currency", "target_raise", "message"),
    (
        (
            "EUR",
            "5000000",
            "USD-denominated sealed target raise",
        ),
        (
            "USD",
            "5000001",
            "fractional USD minor units",
        ),
    ),
)
def test_quote_rejects_ambiguous_sealed_usd_price(
    monkeypatch,
    tmp_path,
    currency,
    target_raise,
    message,
):
    _configure_external_quote(
        monkeypatch,
        tmp_path,
        offering_currency=currency,
        target_raise_minor=target_raise,
    )
    now = int(time.time())
    with TestClient(app) as client:
        response = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="stripe",
                purchase_intent_id=f"pi_reject_{currency}_{target_raise}",
                expires_at=now + 900,
                authorization_nonce="0x" + "16" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={"currency": "USD", "quantity": 1},
            ),
        )
    assert response.status_code == 409
    assert message in response.text


def test_verify_rejects_tampered_or_expired_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(expires_at=int(time.time()) - 1),
        ).json()
        artifact = built["artifact"]
        artifact["protocol"]["sharePpm"] = 50_000
        verified = client.post(
            "/protocol/offer-artifacts/verify",
            json={
                "artifact": artifact,
                "artifact_hash": built["artifact_hash"],
                "now": int(time.time()),
            },
        )
        assert verified.status_code == 200, verified.text
        reasons = verified.json()["reasons"]
        assert verified.json()["valid"] is False
        assert "artifact_hash_mismatch" in reasons
        assert "expired" in reasons


def test_evm_finalization_waits_for_authenticated_relay_message(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    _configure_external_quote(monkeypatch, tmp_path)
    now = int(time.time())
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="base_usdc",
                purchase_intent_id="pi_base",
                expires_at=now + 900,
                authorization_nonce="0x" + "19" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={
                    "currency": "USDC",
                    "quantity": 1,
                    "chain_id": 84532,
                },
            ),
        )
        assert built.status_code == 200, built.text
        built = built.json()
        assert built["purchase_artifact"]["railAmount"] == 1_250_000_000
        finalization = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "base_usdc",
                "purchase_intent_id": "pi_base",
                "payment_evidence": {"tx_hash": "0x" + "ab" * 32},
            },
        )
        assert finalization.status_code == 200, finalization.text
        assert finalization.json()["verified"] is False
        assert "external_message_not_verified" in (
            finalization.json()["reasons"]
        )


def test_external_escrow_message_is_exactly_verified_and_bound(
    monkeypatch,
    tmp_path,
):
    _configure_external_quote(monkeypatch, tmp_path)
    now = int(time.time())
    with TestClient(app) as client:
        built_response = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="base_usdc",
                purchase_intent_id="pi_bridge_bound",
                expires_at=now + 900,
                authorization_nonce="0x" + "1b" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={
                    "currency": "USDC",
                    "quantity": 1,
                    "chain_id": 84532,
                },
            ),
        )
        assert built_response.status_code == 200, built_response.text
        purchase = built_response.json()["purchase_artifact"]
        message = {
            "gatewayProfile": "bse",
            "globalPaymentId": "0x" + "90" * 32,
            "purchaseId": purchase["purchaseId"],
            "artifactHash": purchase["artifactHash"],
            "amount": purchase["railAmount"],
            "quantity": 1,
            "collectionId": purchase["collectionId"],
            "deedLauncherId": purchase["deedLauncherId"],
            "vaultLauncherId": purchase["vaultLauncherId"],
            "destinationPuzzle": purchase["vaultP2PuzzleHash"],
            "quoteExpiresAt": purchase["quoteExpiresAt"],
        }
        tampered = client.post(
            "/protocol/external-payments/verify",
            json={**message, "amount": message["amount"] - 1},
        )
        assert tampered.status_code == 409
        assert "amount" in tampered.text

        verified = client.post(
            "/protocol/external-payments/verify",
            json=message,
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["verified"] is True
        assert verified.json()["fulfillment"]["purchaseId"] == (
            purchase["purchaseId"]
        )
        built = built_response.json()
        finalized = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "base_usdc",
                "purchase_intent_id": "pi_bridge_bound",
                "payment_evidence": {
                    "tx_hash": "0x" + "ab" * 32,
                    "global_payment_id": message["globalPaymentId"],
                },
            },
        )
        assert finalized.status_code == 200, finalized.text
        assert finalized.json()["verified"] is True

        monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ENABLED", "false")
        get_settings.cache_clear()
        disabled = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "base_usdc",
                "purchase_intent_id": "pi_bridge_bound",
                "payment_evidence": {
                    "tx_hash": "0x" + "ab" * 32,
                    "global_payment_id": message["globalPaymentId"],
                },
            },
        )
        assert disabled.status_code == 200, disabled.text
        assert disabled.json()["verified"] is False
        assert "external_escrow_evidence_unavailable" in disabled.json()["reasons"]

        monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ENABLED", "true")
        get_settings.cache_clear()
        replay = client.post(
            "/protocol/external-payments/verify",
            json={
                **message,
                "globalPaymentId": "0x" + "91" * 32,
            },
        )
        assert replay.status_code == 409
        assert "another external payment" in replay.text


def test_finalization_accepts_stripe_checkout_or_payment_intent_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    _configure_external_quote(monkeypatch, tmp_path)
    now = int(time.time())
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="stripe",
                purchase_intent_id="pi_stripe",
                expires_at=now + 900,
                authorization_nonce="0x" + "1a" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={
                    "currency": "USD",
                    "quantity": 1,
                },
            ),
        )
        assert built.status_code == 200, built.text
        built = built.json()
        assert built["purchase_artifact"]["railAmount"] == 125_000
        finalization = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "stripe",
                "purchase_intent_id": "pi_stripe",
                "payment_evidence": {
                    "checkout_session_id": "cs_test_123",
                    "amount_total": 125_000,
                    "currency": "usd",
                },
            },
        )
        assert finalization.status_code == 200, finalization.text
        assert finalization.json()["verified"] is True
        assert finalization.json()["finalized_state"] == "protocol_verified"

        mismatched = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "stripe",
                "purchase_intent_id": "pi_stripe",
                "payment_evidence": {
                    "payment_intent_id": "pi_test_123",
                    "amount_received": 124_999,
                    "currency": "usd",
                },
            },
        )
        assert mismatched.status_code == 200
        assert mismatched.json()["verified"] is False
        assert "stripe_amount_mismatch" in mismatched.json()["reasons"]


def test_build_and_finalization_can_require_server_token(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    monkeypatch.setenv("SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN", "server-only-token")
    get_settings.cache_clear()
    with TestClient(app) as client:
        assert client.post("/protocol/offer-artifacts", json=_request()).status_code == 401
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(),
            headers={"Authorization": "Bearer server-only-token"},
        )
        assert built.status_code == 200, built.text
    monkeypatch.delenv("SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN", raising=False)
    get_settings.cache_clear()


def test_rejects_credential_markers_in_artifact_metadata(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(metadata={"mandrill": "do-not-ship"}),
        )
        assert built.status_code == 400
        assert "mandrill" in built.text.lower()


def test_build_fails_closed_without_server_confirmed_receipt(monkeypatch):
    def missing_receipt(_settings, _vault_launcher_id):
        raise HTTPException(status_code=404, detail="Enrollment not found.")

    monkeypatch.setattr(
        "solslot_api.zkpassport_enrollments._sync_chia_stamp",
        missing_receipt,
    )
    with TestClient(app) as client:
        response = client.post("/protocol/offer-artifacts", json=_request())
    assert response.status_code == 409
    assert "not chain-confirmed" in response.text


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        (
            "current_vault_coin_id",
            "0x" + "99" * 32,
            "vault coin or identity root is no longer current",
        ),
        (
            "identity_attest_root",
            "0x" + "99" * 32,
            "vault coin or identity root is no longer current",
        ),
        (
            "genesis_artifact_hash",
            "0x" + "99" * 32,
            "genesis artifact is not the active signed artifact",
        ),
    ),
)
def test_build_rejects_stale_client_trust_context(field, value, message):
    with TestClient(app) as client:
        response = client.post(
            "/protocol/offer-artifacts",
            json=_request(**{field: value}),
        )
    assert response.status_code == 409
    assert message in response.text


def test_verify_rejects_receipt_that_is_no_longer_current(monkeypatch):
    with TestClient(app) as client:
        built = client.post("/protocol/offer-artifacts", json=_request()).json()

        def stale_enrollment(_settings, _vault_launcher_id):
            raise HTTPException(status_code=409, detail="Current vault coin changed.")

        monkeypatch.setattr(
            "solslot_api.zkpassport_enrollments._sync_chia_stamp",
            stale_enrollment,
        )
        verified = client.post(
            "/protocol/offer-artifacts/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
            },
        )
    assert verified.status_code == 200
    assert verified.json()["valid"] is False
    assert "credential_not_current_on_chia" in verified.json()["reasons"]
