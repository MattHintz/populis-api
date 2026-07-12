"""Tests for the public validator-info surface.

The validator private key is reachable only from the internal enrollment state
machine. A generic signing endpoint must never appear in OpenAPI.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from solslot_api import zkpassport_validator
from solslot_api.app import app
from solslot_api.config import SECRET_ENV_FILE_KEYS
from solslot_api.zkpassport_validator import _validator_sk


SEED_HEX = "bd15624be42c1cd1c51dd4a440bff40a4a3466f716f9e13149d3422767876ad7"
EXPECTED_PUBKEY_HEX = (
    "a8f9b0c1f992c49210fc726fc610885b966f84747126753659c6c3f8ae5bf3ba"
    "f5b6e1a399fc8a749daf45dd74efac4c"
)


@pytest.fixture()
def client_with_seed(monkeypatch):
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_VALIDATOR_SEED_HEX", SEED_HEX)
    _validator_sk.cache_clear()
    with TestClient(app) as client:
        yield client
    _validator_sk.cache_clear()


@pytest.fixture()
def client_no_seed(monkeypatch):
    monkeypatch.delenv("SOLSLOT_ZKPASSPORT_VALIDATOR_SEED_HEX", raising=False)
    _validator_sk.cache_clear()
    with TestClient(app) as client:
        yield client
    _validator_sk.cache_clear()


def test_validator_info_returns_only_public_key(client_with_seed):
    response = client_with_seed.get("/zkpassport/validator")
    assert response.status_code == 200
    assert response.json() == {
        "pubkey_hex": EXPECTED_PUBKEY_HEX,
        "threshold": 1,
    }


def test_validator_info_fails_closed_without_key(client_no_seed):
    response = client_no_seed.get("/zkpassport/validator")
    assert response.status_code == 503


def test_generic_validator_signing_route_does_not_exist(client_with_seed):
    response = client_with_seed.post(
        "/zkpassport/sign",
        json={"validator_message_hex": "0x" + "11" * 32},
    )
    assert response.status_code == 404
    assert "/zkpassport/sign" not in client_with_seed.get("/openapi.json").json()["paths"]


def test_validator_seed_is_classified_as_secret():
    assert "SOLSLOT_ZKPASSPORT_VALIDATOR_SEED_HEX" in SECRET_ENV_FILE_KEYS
