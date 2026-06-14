"""Tests for the zkPassport validator signer endpoints."""

from __future__ import annotations

import secrets

import pytest
from chia_rs import AugSchemeMPL, G2Element
from fastapi.testclient import TestClient

from populis_api.app import app
from populis_api.zkpassport_validator import _validator_sk

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SEED_HEX = "bd15624be42c1cd1c51dd4a440bff40a4a3466f716f9e13149d3422767876ad7"
EXPECTED_PUBKEY_HEX = (
    "a8f9b0c1f992c49210fc726fc610885b966f84747126753659c6c3f8ae5bf3ba"
    "f5b6e1a399fc8a749daf45dd74efac4c"
)
VALIDATOR_MESSAGE_HEX = "0x" + "ab" * 32


@pytest.fixture()
def client_with_seed(monkeypatch):
    monkeypatch.setenv("POPULIS_ZKPASSPORT_VALIDATOR_SEED_HEX", SEED_HEX)
    _validator_sk.cache_clear()
    with TestClient(app) as c:
        yield c
    _validator_sk.cache_clear()


@pytest.fixture()
def client_no_seed(monkeypatch):
    monkeypatch.delenv("POPULIS_ZKPASSPORT_VALIDATOR_SEED_HEX", raising=False)
    _validator_sk.cache_clear()
    with TestClient(app) as c:
        yield c
    _validator_sk.cache_clear()


# ---------------------------------------------------------------------------
# GET /zkpassport/validator
# ---------------------------------------------------------------------------

class TestGetValidator:
    def test_returns_pubkey_when_configured(self, client_with_seed):
        resp = client_with_seed.get("/zkpassport/validator")
        assert resp.status_code == 200
        data = resp.json()
        assert data["pubkey_hex"] == EXPECTED_PUBKEY_HEX
        assert data["threshold"] == 1

    def test_pubkey_is_48_bytes(self, client_with_seed):
        resp = client_with_seed.get("/zkpassport/validator")
        pk_hex = resp.json()["pubkey_hex"]
        assert len(bytes.fromhex(pk_hex)) == 48

    def test_returns_503_when_unconfigured(self, client_no_seed):
        resp = client_no_seed.get("/zkpassport/validator")
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# POST /zkpassport/sign
# ---------------------------------------------------------------------------

class TestSign:
    def test_signs_valid_message(self, client_with_seed):
        resp = client_with_seed.post(
            "/zkpassport/sign",
            json={"validator_message_hex": VALIDATOR_MESSAGE_HEX},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["pubkey_hex"] == EXPECTED_PUBKEY_HEX
        assert data["validator_message_hex"] == VALIDATOR_MESSAGE_HEX
        sig_bytes = bytes.fromhex(data["signature_hex"])
        assert len(sig_bytes) == 96

    def test_signature_verifies(self, client_with_seed):
        resp = client_with_seed.post(
            "/zkpassport/sign",
            json={"validator_message_hex": VALIDATOR_MESSAGE_HEX},
        )
        data = resp.json()
        pk_bytes = bytes.fromhex(data["pubkey_hex"])
        sig_bytes = bytes.fromhex(data["signature_hex"])
        msg = bytes.fromhex(data["validator_message_hex"].removeprefix("0x"))
        from chia_rs import G1Element, G2Element
        pk = G1Element.from_bytes(pk_bytes)
        sig = G2Element.from_bytes(sig_bytes)
        assert AugSchemeMPL.verify(pk, msg, sig)

    def test_different_messages_give_different_signatures(self, client_with_seed):
        msg_a = "0x" + "aa" * 32
        msg_b = "0x" + "bb" * 32
        sig_a = client_with_seed.post("/zkpassport/sign", json={"validator_message_hex": msg_a}).json()["signature_hex"]
        sig_b = client_with_seed.post("/zkpassport/sign", json={"validator_message_hex": msg_b}).json()["signature_hex"]
        assert sig_a != sig_b

    def test_accepts_hex_without_0x_prefix(self, client_with_seed):
        raw = "ab" * 32
        resp = client_with_seed.post("/zkpassport/sign", json={"validator_message_hex": raw})
        assert resp.status_code == 200

    def test_rejects_short_message(self, client_with_seed):
        resp = client_with_seed.post(
            "/zkpassport/sign",
            json={"validator_message_hex": "0x" + "ab" * 16},
        )
        assert resp.status_code == 422

    def test_rejects_long_message(self, client_with_seed):
        resp = client_with_seed.post(
            "/zkpassport/sign",
            json={"validator_message_hex": "0x" + "ab" * 64},
        )
        assert resp.status_code == 422

    def test_rejects_non_hex(self, client_with_seed):
        resp = client_with_seed.post(
            "/zkpassport/sign",
            json={"validator_message_hex": "not-hex"},
        )
        assert resp.status_code == 422

    def test_returns_503_when_unconfigured(self, client_no_seed):
        resp = client_no_seed.post(
            "/zkpassport/sign",
            json={"validator_message_hex": VALIDATOR_MESSAGE_HEX},
        )
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Config-level: secret key is classified by the permissions guard
# ---------------------------------------------------------------------------

class TestSecretKeyInGuard:
    def test_validator_seed_is_in_secret_keys_set(self):
        from populis_api.config import SECRET_ENV_FILE_KEYS
        assert "POPULIS_ZKPASSPORT_VALIDATOR_SEED_HEX" in SECRET_ENV_FILE_KEYS
