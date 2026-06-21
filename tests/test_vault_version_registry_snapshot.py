"""Tests for ``populis_api.vault_version_registry`` (vault upgrade Brick 4d).

This pure snapshot module is the API's off-chain reader for the on-chain
``vault_version_registry_inner.clsp`` singleton (populis_protocol Brick 2).
It mirrors :mod:`populis_api.protocol_config`: it re-derives the static
registry + vault mod-hashes from the compiled populis_puzzles bundle and
computes the deterministic ``canonical_params_hash`` / ``content_hash`` from
``Settings``.

The cross-repo contract — that the off-chain ``compute_content_hash`` /
``compute_canonical_params_hash`` here exactly equal the on-chain CLVM
behaviour — is enforced by
``populis_protocol/tests/test_vault_version_registry.py``.  Here we only
assert the API wiring threads the right values into those helpers.

NOTE: this brick is the pure snapshot module + Settings fields only; the
``/protocol`` endpoint wiring (and its integration tests) lands in the
follow-on brick, so there is no ``TestClient`` coverage here yet.
"""
from __future__ import annotations

import pytest
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from populis_api.config import get_settings
from populis_api.vault_version_registry import (
    VaultVersionRegistrySnapshot,
    build_vault_version_registry_snapshot,
)
from populis_puzzles.vault_driver import VAULT_INNER_MOD
from populis_puzzles.vault_version_registry_driver import (
    compute_canonical_params_hash,
    compute_content_hash,
    vault_version_registry_inner_mod_hash,
)


# Distinct sentinel values so a swapped-arg bug shows up immediately.
POOL_HEX = "0x" + ("aa" * 32)
REGISTRY_HEX = "0x" + ("cc" * 32)
# Matches the Settings default; pinned here so the expected-hash helpers below
# don't depend on importing the private default.
BRIDGE_HEX = "0xc87f45cd23d052c88256de8823a4a01f40da4e2066156f48f3b3dfc0a50350d7"


def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def _expected_canonical_params_hash(pool_hex: str, bridge_hex: str) -> bytes32:
    return compute_canonical_params_hash(
        pool_singleton_mod_hash=SINGLETON_MOD_HASH,
        pool_launcher_id=bytes32.fromhex(_strip0x(pool_hex)),
        pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
        zkpassport_bridge_policy_hash=bytes32.fromhex(_strip0x(bridge_hex)),
    )


def _expected_content_hash(pool_hex: str, bridge_hex: str, version: int) -> bytes32:
    return compute_content_hash(
        bytes32(VAULT_INNER_MOD.get_tree_hash()),
        _expected_canonical_params_hash(pool_hex, bridge_hex),
        version,
    )


@pytest.fixture
def fresh_settings(monkeypatch):
    """Reset env + cached settings for every test."""
    for key in (
        "POPULIS_POOL_LAUNCHER_ID",
        "POPULIS_VAULT_VERSION_REGISTRY_LAUNCHER_ID",
        "POPULIS_VAULT_VERSION_REGISTRY_VERSION",
        "POPULIS_ZKPASSPORT_BRIDGE_POLICY_HASH",
        "POPULIS_NETWORK",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("POPULIS_NETWORK", "testnet11")
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


class TestStaticModHashes:
    """The mod-hashes are derived from the compiled puzzle bundle and must
    match the driver helpers exactly — they are the on-chain identity of the
    registry and vault code."""

    def test_registry_mod_hash_matches_driver(self, fresh_settings):
        snap = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=None
        )
        assert snap.vault_version_registry_mod_hash_hex == (
            "0x" + vault_version_registry_inner_mod_hash().hex()
        )

    def test_vault_inner_mod_hash_matches_current_vault_code(self, fresh_settings):
        snap = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=None
        )
        assert snap.vault_inner_mod_hash_hex == (
            "0x" + VAULT_INNER_MOD.get_tree_hash().hex()
        )

    def test_mod_hashes_are_0x_prefixed_bytes32(self, fresh_settings):
        snap = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=None
        )
        for field in (
            snap.vault_version_registry_mod_hash_hex,
            snap.vault_inner_mod_hash_hex,
        ):
            assert field.startswith("0x")
            assert len(field) == 2 + 64


class TestBuildSnapshot:
    def test_returns_none_hashes_when_pool_missing(self, fresh_settings):
        snap = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=None
        )
        assert isinstance(snap, VaultVersionRegistrySnapshot)
        assert snap.canonical_params_hash_hex is None
        assert snap.content_hash_hex is None
        # Static descriptor fields are still populated.
        assert snap.vault_version == 1
        assert snap.vault_inner_mod_hash_hex.startswith("0x")

    def test_computes_hashes_when_pool_set(self, fresh_settings):
        snap = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=POOL_HEX
        )
        assert snap.canonical_params_hash_hex is not None
        assert snap.content_hash_hex is not None
        assert snap.content_hash_hex.startswith("0x")
        assert len(snap.content_hash_hex) == 2 + 64

    def test_canonical_params_hash_matches_driver(self, fresh_settings):
        snap = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=POOL_HEX
        )
        expected = _expected_canonical_params_hash(POOL_HEX, BRIDGE_HEX)
        assert snap.canonical_params_hash_hex == "0x" + expected.hex()

    def test_content_hash_matches_driver_directly(self, fresh_settings):
        """The API helper must produce the SAME content hash as the
        populis_puzzles driver — the cross-repo binding contract.  If this
        fails, the portal's "vault current" check has silently drifted from
        the on-chain registry puzzle.
        """
        snap = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=POOL_HEX
        )
        expected = _expected_content_hash(POOL_HEX, BRIDGE_HEX, 1)
        assert snap.content_hash_hex == "0x" + expected.hex()

    def test_version_change_changes_content_hash(self, fresh_settings, monkeypatch):
        snap_v1 = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=POOL_HEX
        )
        monkeypatch.setenv("POPULIS_VAULT_VERSION_REGISTRY_VERSION", "2")
        get_settings.cache_clear()
        snap_v2 = build_vault_version_registry_snapshot(
            get_settings(), pool_launcher_id_hex=POOL_HEX
        )
        assert snap_v2.vault_version == 2
        assert snap_v1.content_hash_hex != snap_v2.content_hash_hex
        # The canonical params hash does NOT depend on version.
        assert snap_v1.canonical_params_hash_hex == snap_v2.canonical_params_hash_hex

    def test_bridge_policy_hash_change_changes_params_hash(
        self, fresh_settings, monkeypatch
    ):
        snap_a = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=POOL_HEX
        )
        other_bridge = "0x" + ("dd" * 32)
        monkeypatch.setenv("POPULIS_ZKPASSPORT_BRIDGE_POLICY_HASH", other_bridge)
        get_settings.cache_clear()
        snap_b = build_vault_version_registry_snapshot(
            get_settings(), pool_launcher_id_hex=POOL_HEX
        )
        assert snap_a.canonical_params_hash_hex != snap_b.canonical_params_hash_hex
        assert snap_b.canonical_params_hash_hex == (
            "0x" + _expected_canonical_params_hash(POOL_HEX, other_bridge).hex()
        )

    def test_surfaces_registry_launcher_id(self, fresh_settings, monkeypatch):
        monkeypatch.setenv(
            "POPULIS_VAULT_VERSION_REGISTRY_LAUNCHER_ID", REGISTRY_HEX
        )
        get_settings.cache_clear()
        snap = build_vault_version_registry_snapshot(
            get_settings(), pool_launcher_id_hex=POOL_HEX
        )
        assert snap.vault_version_registry_launcher_id_hex == REGISTRY_HEX

    def test_launcher_id_none_by_default(self, fresh_settings):
        snap = build_vault_version_registry_snapshot(
            fresh_settings, pool_launcher_id_hex=POOL_HEX
        )
        assert snap.vault_version_registry_launcher_id_hex is None

    def test_empty_launcher_id_normalized_to_none(self, fresh_settings, monkeypatch):
        monkeypatch.setenv("POPULIS_VAULT_VERSION_REGISTRY_LAUNCHER_ID", "")
        get_settings.cache_clear()
        snap = build_vault_version_registry_snapshot(
            get_settings(), pool_launcher_id_hex=POOL_HEX
        )
        assert snap.vault_version_registry_launcher_id_hex is None


class TestSettingsDefaults:
    def test_version_default_is_one(self, fresh_settings):
        assert fresh_settings.vault_version_registry_version == 1

    def test_launcher_id_default_is_none(self, fresh_settings):
        assert fresh_settings.vault_version_registry_launcher_id is None
