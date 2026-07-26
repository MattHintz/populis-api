"""Tests for the Alpha operational metrics endpoint."""
from __future__ import annotations

from fastapi.testclient import TestClient

from solslot_api.app import app


client = TestClient(app, raise_server_exceptions=False)


def test_metrics_returns_aggregate_snapshot() -> None:
    resp = client.get("/alpha/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert "timestamp" in body
    assert "flags" in body
    assert "presale" in body
    assert "telemetry" in body
    assert isinstance(body["flags"]["alpha_writes_enabled"], bool)
    assert isinstance(body["flags"]["minting_enabled"], bool)
    assert isinstance(body["flags"]["payment_omnichain_enabled"], bool)


def test_metrics_contains_no_secrets() -> None:
    resp = client.get("/alpha/metrics")
    body_str = resp.text
    for sensitive in ["token", "secret", "password", "key", "jwt", "private"]:
        assert sensitive not in body_str.lower() or sensitive in ("telemetry_event_count",)
