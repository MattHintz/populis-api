"""Tests for ``solslot_api.singletons`` and the A.1 + A.4 fields on /protocol.

Phase 3 of the on-chain migration introduces the mint-proposal and
property-registry singletons.  This file regression-tests:

  * The off-chain helper module (``build_singletons_snapshot``).
  * The wiring on the ``/protocol`` endpoint.
  * The cross-repo contract: the API's published mod-hashes match what
    ``solslot_puzzles`` produces for the canonical .clsp files.

The matching Chialisp + driver tests live in
``solslot_protocol/tests/test_property_registry.py`` and
``solslot_protocol/tests/test_mint_proposal.py``.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from solslot_api.app import app
from solslot_api.config import get_settings
from solslot_api.singletons import build_singletons_snapshot
from solslot_puzzles.mint_proposal_v2_driver import mint_proposal_inner_v2_mod_hash
from solslot_puzzles.property_registry_driver import (
    property_registry_inner_mod_hash,
)


PROPERTY_REGISTRY_LAUNCHER = "0x" + ("ab" * 32)


@pytest.fixture
def fresh_settings(monkeypatch):
    """Reset env + cached settings for every test."""
    for key in (
        "SOLSLOT_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID",
    ):
        monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


# ── build_singletons_snapshot helper ────────────────────────────────────


class TestBuildSnapshot:
    def test_mod_hashes_present_when_disabled(self, fresh_settings):
        """Mod-hashes are static — published even when no launcher id is set."""
        snap = build_singletons_snapshot(fresh_settings)
        assert snap.property_registry_launcher_id_hex is None
        assert snap.property_registry_mod_hash_hex.startswith("0x")
        assert len(snap.property_registry_mod_hash_hex) == 2 + 64
        assert snap.mint_proposal_mod_hash_hex.startswith("0x")
        assert len(snap.mint_proposal_mod_hash_hex) == 2 + 64

    def test_property_registry_launcher_id_passes_through(
        self, fresh_settings, monkeypatch
    ):
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID",
            PROPERTY_REGISTRY_LAUNCHER,
        )
        get_settings.cache_clear()
        snap = build_singletons_snapshot(get_settings())
        assert snap.property_registry_launcher_id_hex == PROPERTY_REGISTRY_LAUNCHER

    def test_property_registry_mod_hash_matches_driver(self, fresh_settings):
        """Cross-repo contract: API helper matches solslot_puzzles driver."""
        snap = build_singletons_snapshot(fresh_settings)
        expected = "0x" + property_registry_inner_mod_hash().hex()
        assert snap.property_registry_mod_hash_hex == expected

    def test_mint_proposal_mod_hash_matches_driver(self, fresh_settings):
        """Cross-repo contract: API helper matches solslot_puzzles driver."""
        snap = build_singletons_snapshot(fresh_settings)
        expected = "0x" + mint_proposal_inner_v2_mod_hash().hex()
        assert snap.mint_proposal_mod_hash_hex == expected


# ── /protocol endpoint integration ─────────────────────────────────────


class TestProtocolEndpoint:
    def test_singletons_fields_present(self, fresh_settings):
        with TestClient(app) as client:
            resp = client.get("/protocol")
            assert resp.status_code == 200
            body = resp.json()
            # Mod-hashes are always present (static).
            assert body["property_registry_mod_hash"] is not None
            assert body["property_registry_mod_hash"].startswith("0x")
            assert body["mint_proposal_mod_hash"] is not None
            assert body["mint_proposal_mod_hash"].startswith("0x")
            # Launcher id is None when env unset.
            assert body["property_registry_launcher_id"] is None

    def test_property_registry_environment_launcher_is_ignored(
        self, fresh_settings, monkeypatch
    ):
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID",
            PROPERTY_REGISTRY_LAUNCHER,
        )
        get_settings.cache_clear()
        with TestClient(app) as client:
            resp = client.get("/protocol")
            body = resp.json()
            assert body["property_registry_launcher_id"] is None

    def test_mod_hashes_match_drivers(self, fresh_settings):
        """The /protocol response's mod-hashes match solslot_puzzles drivers."""
        with TestClient(app) as client:
            resp = client.get("/protocol")
            body = resp.json()
            assert body["property_registry_mod_hash"] == (
                "0x" + property_registry_inner_mod_hash().hex()
            )
            assert body["mint_proposal_mod_hash"] == (
                "0x" + mint_proposal_inner_v2_mod_hash().hex()
            )

    def test_mod_hashes_stable_across_calls(self, fresh_settings):
        """Mod-hashes shouldn't drift between requests."""
        with TestClient(app) as client:
            r1 = client.get("/protocol").json()
            r2 = client.get("/protocol").json()
            assert r1["property_registry_mod_hash"] == r2["property_registry_mod_hash"]
            assert r1["mint_proposal_mod_hash"] == r2["mint_proposal_mod_hash"]
