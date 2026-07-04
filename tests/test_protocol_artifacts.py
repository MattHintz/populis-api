from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from populis_api.app import app
from populis_api.config import get_settings


@pytest.fixture(autouse=True)
def isolate_protocol_artifact_env(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "POPULIS_DEPLOYMENT_MANIFEST_PATH",
        str(tmp_path / "missing.json"),
    )
    for name in (
        "POPULIS_ADMIN_PUBKEY_ALLOWLIST",
        "POPULIS_ADMIN_JWT_SECRET",
        "POPULIS_ADMIN_RECORDS_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _request(**overrides):
    base = {
        "instance_id": "solslot-staging",
        "purchase_intent_id": "pi_test_001",
        "rail": "chia",
        "deed_launcher_id": "0x" + "11" * 32,
        "property_id": "US-TX-AUSTIN-001",
        "collection_id": "SOL-LOT-AUSTIN-ALPHA",
        "share_ppm": 25_000,
        "vault_launcher_id": "0x" + "22" * 32,
        "expires_at": int(time.time()) + 3600,
        "payment_terms": {
            "currency": "wUSDC",
            "amount": 125_000,
            "quantity": 1,
        },
    }
    base.update(overrides)
    return base


def test_builds_and_verifies_protocol_offer_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("POPULIS_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
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


def test_verify_rejects_tampered_or_expired_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("POPULIS_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
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


def test_finalization_verifies_rail_bound_payment_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("POPULIS_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(rail="base_usdc", purchase_intent_id="pi_base"),
        ).json()
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
        assert finalization.json()["verified"] is True
        assert finalization.json()["finalized_state"] == "protocol_verified"


def test_finalization_accepts_stripe_checkout_or_payment_intent_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("POPULIS_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(rail="stripe", purchase_intent_id="pi_stripe"),
        ).json()
        finalization = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "stripe",
                "purchase_intent_id": "pi_stripe",
                "payment_evidence": {"checkout_session_id": "cs_test_123"},
            },
        )
        assert finalization.status_code == 200, finalization.text
        assert finalization.json()["verified"] is True
        assert finalization.json()["finalized_state"] == "protocol_verified"


def test_build_and_finalization_can_require_server_token(monkeypatch, tmp_path):
    monkeypatch.setenv("POPULIS_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    monkeypatch.setenv("POPULIS_PROTOCOL_ARTIFACT_API_TOKEN", "server-only-token")
    get_settings.cache_clear()
    with TestClient(app) as client:
        assert client.post("/protocol/offer-artifacts", json=_request()).status_code == 401
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(),
            headers={"Authorization": "Bearer server-only-token"},
        )
        assert built.status_code == 200, built.text
    monkeypatch.delenv("POPULIS_PROTOCOL_ARTIFACT_API_TOKEN", raising=False)
    get_settings.cache_clear()


def test_rejects_credential_markers_in_artifact_metadata(monkeypatch, tmp_path):
    monkeypatch.setenv("POPULIS_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(metadata={"mandrill": "do-not-ship"}),
        )
        assert built.status_code == 400
        assert "mandrill" in built.text.lower()
