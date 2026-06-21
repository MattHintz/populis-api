"""Tests for ``populis_api.protocol_config`` and the ``/protocol`` integration.

Phase 1 of the on-chain protocol-config migration (A.3) introduces a
deterministic ``content_hash`` that the API surfaces alongside its
existing manifest data.  This file regression-tests both the helper
module and the wired-in ``/protocol`` endpoint.

The matching Chialisp + driver tests live in
``populis_protocol/tests/test_protocol_config.py``; the cross-repo
contract is that the off-chain ``compute_content_hash`` exactly equals
the on-chain ``content-hash`` defun.  Here we only need to assert that
the API's wiring threads the right values into the helper.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from populis_api.app import app
from populis_api.config import get_settings
from populis_api.protocol_config import (
    ProtocolConfigSnapshot,
    build_snapshot,
)
from populis_api.vault_version_registry import (
    VaultVersionRegistrySnapshot,
    build_vault_version_registry_snapshot,
)
from populis_puzzles.protocol_config_driver import (
    NETWORK_ID_TESTNET11,
    compute_content_hash,
)
from populis_puzzles.vault_version_registry_driver import (
    compute_canonical_params_hash as compute_vault_canonical_params_hash,
    compute_content_hash as compute_vault_registry_content_hash,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32


# Distinct sentinel values so a swapped-arg bug shows up immediately.
POOL_HEX = "0x" + ("aa" * 32)
GOV_HEX = "0x" + ("bb" * 32)
PCS_HEX = "0x" + ("cc" * 32)
VAULT_VERSION_REGISTRY_HEX = "0x" + ("dd" * 32)
BRIDGE_POLICY_HEX = "0x" + ("ee" * 32)


@pytest.fixture
def fresh_settings(monkeypatch):
    """Reset env + cached settings for every test."""
    for key in (
        "POPULIS_POOL_LAUNCHER_ID",
        "POPULIS_GOVERNANCE_LAUNCHER_ID",
        "POPULIS_PROTOCOL_CONFIG_LAUNCHER_ID",
        "POPULIS_PROTOCOL_CONFIG_VERSION",
        "POPULIS_NETWORK",
        "POPULIS_VAULT_VERSION_REGISTRY_VERSION",
        "POPULIS_ZKPASSPORT_BRIDGE_POLICY_HASH",
    ):
        monkeypatch.delenv(key, raising=False)
    # The operator's local ``.env`` pins the deployed registry launcher id;
    # ``delenv`` would let pydantic fall back to it.  Force the empty-string
    # mask (coerced to ``None`` by the Settings validator) for the
    # registry-less default path.  Tests that need it set use setenv.
    monkeypatch.setenv("POPULIS_VAULT_VERSION_REGISTRY_LAUNCHER_ID", "")
    monkeypatch.setenv("POPULIS_NETWORK", "testnet11")
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


# ── Helper: build_snapshot ──────────────────────────────────────────────


class TestBuildSnapshot:
    def test_returns_none_hash_when_pool_missing(self, fresh_settings):
        snap = build_snapshot(
            fresh_settings,
            pool_launcher_id_hex=None,
            governance_launcher_id_hex=GOV_HEX,
        )
        assert snap.content_hash_hex is None
        # Other fields still populated for the API to reflect.
        assert snap.governance_launcher_id_hex == GOV_HEX
        assert snap.chia_network == "testnet11"

    def test_returns_none_hash_when_gov_missing(self, fresh_settings):
        snap = build_snapshot(
            fresh_settings,
            pool_launcher_id_hex=POOL_HEX,
            governance_launcher_id_hex=None,
        )
        assert snap.content_hash_hex is None

    def test_computes_hash_when_both_set(self, fresh_settings):
        snap = build_snapshot(
            fresh_settings,
            pool_launcher_id_hex=POOL_HEX,
            governance_launcher_id_hex=GOV_HEX,
        )
        assert snap.content_hash_hex is not None
        assert snap.content_hash_hex.startswith("0x")
        assert len(snap.content_hash_hex) == 2 + 64  # 0x + 32 bytes hex

    def test_hash_matches_driver_directly(self, fresh_settings):
        """The API helper must produce the SAME hash as the populis_puzzles
        driver — that's the cross-repo contract.  If this fails, the
        EIP-712 binding has silently drifted from the on-chain puzzle.
        """
        snap = build_snapshot(
            fresh_settings,
            pool_launcher_id_hex=POOL_HEX,
            governance_launcher_id_hex=GOV_HEX,
        )
        expected = compute_content_hash(
            pool_launcher_id=bytes32.fromhex(POOL_HEX[2:]),
            gov_tracker_launcher_id=bytes32.fromhex(GOV_HEX[2:]),
            network_id=NETWORK_ID_TESTNET11,
            config_version=fresh_settings.protocol_config_version,
        )
        assert snap.content_hash_hex == "0x" + expected.hex()

    def test_version_change_changes_hash(self, fresh_settings, monkeypatch):
        snap_v1 = build_snapshot(
            fresh_settings,
            pool_launcher_id_hex=POOL_HEX,
            governance_launcher_id_hex=GOV_HEX,
        )
        monkeypatch.setenv("POPULIS_PROTOCOL_CONFIG_VERSION", "2")
        get_settings.cache_clear()
        snap_v2 = build_snapshot(
            get_settings(),
            pool_launcher_id_hex=POOL_HEX,
            governance_launcher_id_hex=GOV_HEX,
        )
        assert snap_v1.content_hash_hex != snap_v2.content_hash_hex

    def test_surfaces_singleton_launcher_id(self, fresh_settings, monkeypatch):
        monkeypatch.setenv("POPULIS_PROTOCOL_CONFIG_LAUNCHER_ID", PCS_HEX)
        get_settings.cache_clear()
        snap = build_snapshot(
            get_settings(),
            pool_launcher_id_hex=POOL_HEX,
            governance_launcher_id_hex=GOV_HEX,
        )
        assert snap.protocol_config_launcher_id_hex == PCS_HEX

    def test_unknown_network_raises(self, fresh_settings, monkeypatch):
        # Pydantic accepts only the literal values, but build_snapshot's
        # _network_id helper has its own guard for defence-in-depth.
        from populis_api.protocol_config import _network_id

        with pytest.raises(ValueError, match="unknown network"):
            _network_id("regtest")


# ── /protocol endpoint integration ──────────────────────────────────────


class TestProtocolEndpoint:
    """End-to-end: hit /protocol and assert the new fields land in the
    response payload with the right values.
    """

    def test_returns_none_hash_when_no_launchers_configured(self, fresh_settings):
        with TestClient(app) as client:
            resp = client.get("/protocol")
            assert resp.status_code == 200
            body = resp.json()
            assert "protocol_config_hash" in body
            # Without launchers configured, hash is None.
            assert body["protocol_config_hash"] is None
            assert body["protocol_config_version"] == 1
            assert body["protocol_config_launcher_id"] is None

    def test_returns_hash_when_launchers_configured(
        self, fresh_settings, monkeypatch
    ):
        monkeypatch.setenv("POPULIS_POOL_LAUNCHER_ID", POOL_HEX)
        monkeypatch.setenv("POPULIS_GOVERNANCE_LAUNCHER_ID", GOV_HEX)
        get_settings.cache_clear()
        with TestClient(app) as client:
            resp = client.get("/protocol")
            assert resp.status_code == 200
            body = resp.json()
            assert body["protocol_config_hash"] is not None
            assert body["protocol_config_hash"].startswith("0x")
            # Hash equals direct driver computation.
            expected = compute_content_hash(
                pool_launcher_id=bytes32.fromhex(POOL_HEX[2:]),
                gov_tracker_launcher_id=bytes32.fromhex(GOV_HEX[2:]),
                network_id=NETWORK_ID_TESTNET11,
                config_version=1,
            )
            assert body["protocol_config_hash"] == "0x" + expected.hex()

    def test_version_default_is_one(self, fresh_settings):
        with TestClient(app) as client:
            resp = client.get("/protocol")
            assert resp.json()["protocol_config_version"] == 1

    def test_version_override_via_env(self, fresh_settings, monkeypatch):
        monkeypatch.setenv("POPULIS_PROTOCOL_CONFIG_VERSION", "7")
        get_settings.cache_clear()
        with TestClient(app) as client:
            resp = client.get("/protocol")
            assert resp.json()["protocol_config_version"] == 7


# ── /protocol vault-version registry wiring (A.5) ───────────────────────


class TestVaultVersionRegistryEndpoint:
    """End-to-end: hit /protocol and assert the vault-version registry fields
    land with the correct deterministic values.
    """

    def test_registry_fields_present_when_not_deployed(self, fresh_settings):
        with TestClient(app) as client:
            resp = client.get("/protocol")
            assert resp.status_code == 200
            body = resp.json()
            assert "vault_version_registry_launcher_id" in body
            assert "vault_version_registry_mod_hash" in body
            assert "vault_version" in body
            assert "vault_canonical_params_hash" in body
            assert "vault_version_registry_content_hash" in body

    def test_registry_fields_null_without_pool_launcher(self, fresh_settings):
        with TestClient(app) as client:
            resp = client.get("/protocol")
            body = resp.json()
            assert body["vault_version_registry_launcher_id"] is None
            assert body["vault_canonical_params_hash"] is None
            assert body["vault_version_registry_content_hash"] is None

    def test_registry_content_hash_matches_driver(self, fresh_settings, monkeypatch):
        """The API helper must produce the SAME content hash as the populis_puzzles
        driver — that's the cross-repo contract for the on-chain registry.
        """
        monkeypatch.setenv("POPULIS_POOL_LAUNCHER_ID", POOL_HEX)
        monkeypatch.setenv("POPULIS_GOVERNANCE_LAUNCHER_ID", GOV_HEX)
        monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_POLICY_HASH", BRIDGE_POLICY_HEX)
        monkeypatch.setenv("POPULIS_VAULT_VERSION_REGISTRY_LAUNCHER_ID", VAULT_VERSION_REGISTRY_HEX)
        get_settings.cache_clear()

        with TestClient(app) as client:
            resp = client.get("/protocol")
            assert resp.status_code == 200
            body = resp.json()
            assert body["vault_version_registry_launcher_id"] == VAULT_VERSION_REGISTRY_HEX
            assert body["vault_version"] == 1
            assert body["vault_canonical_params_hash"] is not None
            assert body["vault_version_registry_content_hash"] is not None

            # Recompute the canonical params hash and content hash directly from
            # the driver to prove the API wiring matches the on-chain puzzle.
            canonical_params_hash = compute_vault_canonical_params_hash(
                pool_singleton_mod_hash=SINGLETON_MOD_HASH,
                pool_launcher_id=bytes32.fromhex(POOL_HEX[2:]),
                pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
                zkpassport_bridge_policy_hash=bytes32.fromhex(BRIDGE_POLICY_HEX[2:]),
            )
            assert body["vault_canonical_params_hash"] == "0x" + canonical_params_hash.hex()

            expected_content_hash = compute_vault_registry_content_hash(
                vault_inner_mod_hash=bytes32.fromhex(body["vault_inner_mod_hash"][2:]),
                canonical_params_hash=canonical_params_hash,
                vault_version=1,
            )
            assert body["vault_version_registry_content_hash"] == "0x" + expected_content_hash.hex()

    def test_registry_version_override_via_env(self, fresh_settings, monkeypatch):
        monkeypatch.setenv("POPULIS_POOL_LAUNCHER_ID", POOL_HEX)
        monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_POLICY_HASH", BRIDGE_POLICY_HEX)
        monkeypatch.setenv("POPULIS_VAULT_VERSION_REGISTRY_VERSION", "3")
        get_settings.cache_clear()

        with TestClient(app) as client:
            resp = client.get("/protocol")
            body = resp.json()
            assert body["vault_version"] == 3
