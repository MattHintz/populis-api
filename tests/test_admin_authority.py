"""Tests for ``populis_api.admin_authority`` and ``/admin/auth/authority``.

Phase 2 of the on-chain migration (A.2) introduces a deterministic
``state_hash`` that the API surfaces alongside the existing admin
allowlist env var.  This file regression-tests both the helper module
and the wired-in endpoint.

The matching Chialisp + driver tests live in
``populis_protocol/tests/test_admin_authority.py``; the cross-repo
contract is that the off-chain ``compute_state_hash`` exactly equals
the on-chain ``state-hash`` defun.  Here we only need to assert that
the API's wiring threads the right values into the helper.
"""
from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from populis_api.admin_authority import (
    AdminAuthoritySnapshot,
    build_admin_authority_snapshot,
)
from populis_api.app import app
from populis_api.config import get_settings
from populis_puzzles.admin_authority_driver import compute_state_hash


# Distinct sentinel BLS G1 pubkeys (48 bytes each).
ADMIN_A = ("11" * 48)
ADMIN_B = ("22" * 48)
ADMIN_C = ("33" * 48)
ALL_ADMINS_HEX = f"0x{ADMIN_A},0x{ADMIN_B},0x{ADMIN_C}"
PCS_LAUNCHER = "0x" + ("ee" * 32)


@pytest.fixture
def fresh_settings(monkeypatch):
    """Reset env + cached settings for every test.

    Uses ``setenv("", "")`` (not ``delenv``) for string-typed keys so
    the conftest's module-level mask of ``.env`` survives — see
    ``conftest.py`` for why ``.env`` would otherwise leak through.
    Integer-typed keys still use ``delenv`` because empty strings fail
    Pydantic int validation.
    """
    for key in (
        "POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID",
        "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS",
    ):
        monkeypatch.setenv(key, "")
    for key in (
        "POPULIS_PROTOCOL_ADMIN_AUTHORITY_QUORUM_M",
        "POPULIS_PROTOCOL_ADMIN_AUTHORITY_VERSION",
    ):
        monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


# ── Settings.admin_authority_pubkeys_list parser ────────────────────────


class TestPubkeysListParser:
    def test_empty_default(self, fresh_settings):
        assert fresh_settings.admin_authority_pubkeys_list() == []

    def test_parses_comma_separated_hex(self, fresh_settings, monkeypatch):
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", ALL_ADMINS_HEX
        )
        get_settings.cache_clear()
        pubkeys = get_settings().admin_authority_pubkeys_list()
        assert len(pubkeys) == 3
        assert pubkeys[0] == bytes.fromhex(ADMIN_A)
        assert pubkeys[2] == bytes.fromhex(ADMIN_C)

    def test_strips_0x_prefix_optionally(self, fresh_settings, monkeypatch):
        # Mix of 0x-prefixed and bare hex.
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS",
            f"0x{ADMIN_A},{ADMIN_B}",
        )
        get_settings.cache_clear()
        pubkeys = get_settings().admin_authority_pubkeys_list()
        assert pubkeys == [bytes.fromhex(ADMIN_A), bytes.fromhex(ADMIN_B)]

    def test_rejects_invalid_hex(self, fresh_settings, monkeypatch):
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", "0xZZZZ"
        )
        get_settings.cache_clear()
        with pytest.raises(ValueError, match="not valid hex"):
            get_settings().admin_authority_pubkeys_list()

    def test_rejects_wrong_length(self, fresh_settings, monkeypatch):
        # 32 bytes — not 48.
        short = "0x" + ("aa" * 32)
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", short
        )
        get_settings.cache_clear()
        with pytest.raises(ValueError, match="48 bytes"):
            get_settings().admin_authority_pubkeys_list()

    def test_preserves_declaration_order(self, fresh_settings, monkeypatch):
        # Order matters — the on-chain singleton's signer_indices
        # references positions, so any reordering would invalidate
        # rotation signatures.
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS",
            f"0x{ADMIN_C},0x{ADMIN_A},0x{ADMIN_B}",
        )
        get_settings.cache_clear()
        pubkeys = get_settings().admin_authority_pubkeys_list()
        assert pubkeys[0] == bytes.fromhex(ADMIN_C)
        assert pubkeys[1] == bytes.fromhex(ADMIN_A)
        assert pubkeys[2] == bytes.fromhex(ADMIN_B)


# ── build_admin_authority_snapshot ──────────────────────────────────────


class TestBuildSnapshot:
    def test_disabled_when_no_config(self, fresh_settings):
        snap = build_admin_authority_snapshot(fresh_settings)
        assert snap.enabled is False
        assert snap.launcher_id_hex is None
        assert snap.allowlist_pubkey_hashes_hex == []
        assert snap.state_hash_hex is None

    def test_enabled_when_pubkeys_set(self, fresh_settings, monkeypatch):
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", ALL_ADMINS_HEX
        )
        get_settings.cache_clear()
        snap = build_admin_authority_snapshot(get_settings())
        assert snap.enabled is True
        assert len(snap.allowlist_pubkey_hashes_hex) == 3
        assert snap.state_hash_hex is not None
        assert snap.state_hash_hex.startswith("0x")
        assert len(snap.state_hash_hex) == 2 + 64

    def test_enabled_when_only_launcher_set(self, fresh_settings, monkeypatch):
        # Launcher id without pubkeys = "ready to deploy" diagnostic state.
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID", PCS_LAUNCHER
        )
        get_settings.cache_clear()
        snap = build_admin_authority_snapshot(get_settings())
        assert snap.enabled is True
        assert snap.launcher_id_hex == PCS_LAUNCHER
        assert snap.state_hash_hex is None  # no pubkeys → no hash

    def test_pubkey_hashes_use_sha256(self, fresh_settings, monkeypatch):
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", f"0x{ADMIN_A}"
        )
        get_settings.cache_clear()
        snap = build_admin_authority_snapshot(get_settings())
        expected = "0x" + hashlib.sha256(bytes.fromhex(ADMIN_A)).hexdigest()
        assert snap.allowlist_pubkey_hashes_hex == [expected]

    def test_pubkey_hashes_preserve_order(self, fresh_settings, monkeypatch):
        # Hashes must follow declaration order so on-chain signer
        # indices line up.
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS",
            f"0x{ADMIN_A},0x{ADMIN_B},0x{ADMIN_C}",
        )
        get_settings.cache_clear()
        snap = build_admin_authority_snapshot(get_settings())
        expected = [
            "0x" + hashlib.sha256(bytes.fromhex(h)).hexdigest()
            for h in (ADMIN_A, ADMIN_B, ADMIN_C)
        ]
        assert snap.allowlist_pubkey_hashes_hex == expected

    def test_state_hash_matches_driver(self, fresh_settings, monkeypatch):
        """Cross-repo contract: API helper output == populis_puzzles driver.

        If this fails, the on-chain rotation signatures will not validate
        against what the API thinks the state hash is.
        """
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", ALL_ADMINS_HEX
        )
        monkeypatch.setenv("POPULIS_PROTOCOL_ADMIN_AUTHORITY_QUORUM_M", "2")
        monkeypatch.setenv("POPULIS_PROTOCOL_ADMIN_AUTHORITY_VERSION", "5")
        get_settings.cache_clear()
        snap = build_admin_authority_snapshot(get_settings())
        expected = compute_state_hash(
            allowlist=[
                bytes.fromhex(ADMIN_A),
                bytes.fromhex(ADMIN_B),
                bytes.fromhex(ADMIN_C),
            ],
            quorum_m=2,
            authority_version=5,
        )
        assert snap.state_hash_hex == "0x" + expected.hex()

    def test_quorum_change_changes_state_hash(self, fresh_settings, monkeypatch):
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", ALL_ADMINS_HEX
        )
        get_settings.cache_clear()
        s1 = build_admin_authority_snapshot(get_settings())
        monkeypatch.setenv("POPULIS_PROTOCOL_ADMIN_AUTHORITY_QUORUM_M", "3")
        get_settings.cache_clear()
        s2 = build_admin_authority_snapshot(get_settings())
        assert s1.state_hash_hex != s2.state_hash_hex

    def test_version_change_changes_state_hash(self, fresh_settings, monkeypatch):
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", ALL_ADMINS_HEX
        )
        get_settings.cache_clear()
        s1 = build_admin_authority_snapshot(get_settings())
        monkeypatch.setenv("POPULIS_PROTOCOL_ADMIN_AUTHORITY_VERSION", "9")
        get_settings.cache_clear()
        s2 = build_admin_authority_snapshot(get_settings())
        assert s1.state_hash_hex != s2.state_hash_hex


# ── /admin/auth/authority endpoint ──────────────────────────────────────


class TestAuthorityEndpoint:
    def test_disabled_when_no_config(self, fresh_settings):
        with TestClient(app) as client:
            resp = client.get("/admin/auth/authority")
            assert resp.status_code == 200
            body = resp.json()
            assert body["enabled"] is False
            assert body["launcher_id"] is None
            assert body["allowlist_pubkey_hashes"] == []
            assert body["state_hash"] is None
            # Defaults present even when disabled — monitoring tools
            # can scrape consistently.
            assert body["quorum_m"] == 1
            assert body["authority_version"] == 1

    def test_returns_state_hash_when_pubkeys_set(self, fresh_settings, monkeypatch):
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", ALL_ADMINS_HEX
        )
        monkeypatch.setenv("POPULIS_PROTOCOL_ADMIN_AUTHORITY_QUORUM_M", "2")
        get_settings.cache_clear()
        with TestClient(app) as client:
            resp = client.get("/admin/auth/authority")
            assert resp.status_code == 200
            body = resp.json()
            assert body["enabled"] is True
            assert body["quorum_m"] == 2
            assert len(body["allowlist_pubkey_hashes"]) == 3
            assert body["state_hash"] is not None
            # Hash matches direct driver computation.
            expected = compute_state_hash(
                allowlist=[
                    bytes.fromhex(ADMIN_A),
                    bytes.fromhex(ADMIN_B),
                    bytes.fromhex(ADMIN_C),
                ],
                quorum_m=2,
                authority_version=1,
            )
            assert body["state_hash"] == "0x" + expected.hex()

    def test_endpoint_is_public_no_auth_required(self, fresh_settings):
        # No Authorization header → still 200.
        with TestClient(app) as client:
            resp = client.get("/admin/auth/authority")
            assert resp.status_code == 200

    def test_returns_launcher_id_when_set(self, fresh_settings, monkeypatch):
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID", PCS_LAUNCHER
        )
        get_settings.cache_clear()
        with TestClient(app) as client:
            resp = client.get("/admin/auth/authority")
            body = resp.json()
            assert body["launcher_id"] == PCS_LAUNCHER

    def test_500_on_malformed_pubkeys(self, fresh_settings, monkeypatch):
        # Malformed env var should bubble up as an ApplicationError;
        # FastAPI returns 500 in that case.
        monkeypatch.setenv(
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS", "0xZZZZ"
        )
        get_settings.cache_clear()
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/admin/auth/authority")
            assert resp.status_code == 500
