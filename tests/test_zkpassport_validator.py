"""Tests that validator key material has no public HTTP surface."""
from __future__ import annotations

from fastapi.testclient import TestClient

from solslot_api.app import app
from solslot_api.config import SECRET_ENV_FILE_KEYS


def test_validator_routes_do_not_exist() -> None:
    with TestClient(app) as client:
        assert client.get("/zkpassport/validator").status_code == 404
        assert client.post("/zkpassport/sign", json={}).status_code == 404
        paths = client.get("/openapi.json").json()["paths"]
    assert "/zkpassport/validator" not in paths
    assert "/zkpassport/sign" not in paths


def test_validator_seed_is_classified_as_secret():
    assert "SOLSLOT_ZKPASSPORT_VALIDATOR_SEED_HEX" in SECRET_ENV_FILE_KEYS
