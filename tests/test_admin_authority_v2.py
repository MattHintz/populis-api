"""Tests for ``solslot_api.admin_authority_v2`` and ``/admin/auth/authority_v2``.

Phase 9-Hermes-C extends the on-chain admin-authority surface with v2
(MIPS-based, supports per-admin OneOfN of mixed auth methods). This file
regression-tests both the helper module and the wired-in endpoint.

The matching Chialisp + driver tests live in
``solslot_protocol/tests/test_admin_authority_v2.py``; the cross-repo
contract is that the off-chain ``compute_state_hash`` exactly equals
the on-chain ``state-hash`` defun. Here we only need to assert that the
API's wiring threads the right values into the helper.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from solslot_api.admin_authority_v2 import (
    AdminAuthorityV2Snapshot,
    build_admin_authority_v2_snapshot,
)
from solslot_api.app import app
from solslot_api.admin_auth import require_admin_jwt
from solslot_api.config import get_settings
from solslot_puzzles.admin_authority_v2_driver import (
    EMPTY_LIST_HASH,
    compute_state_hash,
)


# Sentinel 32-byte hashes (different bytes so we can verify field ordering).
LAUNCHER_HEX = "0x" + ("aa" * 32)
MIPS_ROOT_HEX = "0x" + ("bb" * 32)
ADMINS_HASH_HEX = "0x" + ("cc" * 32)
PENDING_OPS_HASH_HEX = "0x" + ("dd" * 32)


@pytest.fixture
def fresh_settings(monkeypatch):
    """Reset env + cached settings for every test."""
    # String-typed: setenv("") so conftest's .env mask survives.
    # Integer-typed: delenv so Pydantic falls back to model default.
    for key in (
        "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID",
        "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH",
        "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH",
        "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_PENDING_OPS_HASH",
        "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID",
        "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS",
    ):
        monkeypatch.setenv(key, "")
    for key in (
        "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_VERSION",
        "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_VERSION",
    ):
        monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    app.dependency_overrides[require_admin_jwt] = lambda: None
    yield get_settings()
    app.dependency_overrides.pop(require_admin_jwt, None)
    get_settings.cache_clear()


# ─────────────────────────────────────────────────────────────────────────
# build_admin_authority_v2_snapshot
# ─────────────────────────────────────────────────────────────────────────


class TestBuildV2Snapshot:
    def test_unconfigured_returns_disabled_snapshot(self, fresh_settings):
        """No env vars set → enabled=False, all hashes None, phase=
        '1-not-deployed'. The endpoint must remain responsive in this
        state so monitoring tools can scrape it consistently.
        """
        snap = build_admin_authority_v2_snapshot(fresh_settings)
        assert snap.enabled is False
        assert snap.launcher_id_hex is None
        assert snap.mips_root_hash_hex is None
        assert snap.admins_hash_hex is None
        assert snap.pending_ops_hash_hex is None
        assert snap.authority_version == 1  # default
        assert snap.state_hash_hex is None
        assert snap.phase == "not-deployed"
        assert snap.deployment_status == "not-configured"
        assert snap.chain_verifiable is False

    def test_only_launcher_set_marks_enabled_but_no_state_hash(
        self, fresh_settings, monkeypatch
    ):
        """Operator might have computed the launcher id ahead of
        actually deploying — UI should show 'enabled, but state_hash
        not yet computable' (no full state).
        """
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID", LAUNCHER_HEX
        )
        get_settings.cache_clear()
        snap = build_admin_authority_v2_snapshot(get_settings())
        assert snap.enabled is True
        assert snap.launcher_id_hex == LAUNCHER_HEX
        # Without mips_root + admins, state_hash is undefined.
        assert snap.state_hash_hex is None
        assert snap.deployment_status == "launcher-only"
        assert snap.chain_verifiable is False

    def test_full_config_computes_state_hash(self, fresh_settings, monkeypatch):
        """Happy path: all four hash fields + version → state_hash is
        populated and matches the off-chain compute_state_hash helper
        applied to the same inputs.
        """
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID", LAUNCHER_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH", MIPS_ROOT_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH", ADMINS_HASH_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_PENDING_OPS_HASH",
            PENDING_OPS_HASH_HEX,
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_VERSION", "5"
        )
        get_settings.cache_clear()
        snap = build_admin_authority_v2_snapshot(get_settings())

        assert snap.enabled is True
        assert snap.launcher_id_hex == LAUNCHER_HEX
        assert snap.mips_root_hash_hex == MIPS_ROOT_HEX
        assert snap.admins_hash_hex == ADMINS_HASH_HEX
        assert snap.pending_ops_hash_hex == PENDING_OPS_HASH_HEX
        assert snap.authority_version == 5
        assert snap.deployment_status == "deployed-configured"
        assert snap.chain_verifiable is True

        # state_hash should match what compute_state_hash produces with
        # the same inputs — this is the cross-repo binding point with
        # the on-chain puzzle.
        expected = compute_state_hash(
            mips_root_hash=bytes.fromhex(MIPS_ROOT_HEX[2:]),
            admins_hash=bytes.fromhex(ADMINS_HASH_HEX[2:]),
            pending_ops_hash=bytes.fromhex(PENDING_OPS_HASH_HEX[2:]),
            authority_version=5,
        )
        assert snap.state_hash_hex == "0x" + expected.hex()

    def test_pending_ops_defaults_to_empty_list_hash_when_unset(
        self, fresh_settings, monkeypatch
    ):
        """When PENDING_OPS_HASH env is unset but mips/admins are
        configured, the snapshot computes state_hash assuming an
        empty pending-ops list (matches a freshly-launched singleton).
        The ``pending_ops_hash_hex`` field stays None to reflect the
        env-var state, but state_hash uses EMPTY_LIST_HASH internally.
        """
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID", LAUNCHER_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH", MIPS_ROOT_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH", ADMINS_HASH_HEX
        )
        get_settings.cache_clear()
        snap = build_admin_authority_v2_snapshot(get_settings())

        assert snap.pending_ops_hash_hex is None
        assert snap.deployment_status == "deployed-configured"
        assert snap.chain_verifiable is True
        # state_hash should still be computed using EMPTY_LIST_HASH.
        expected = compute_state_hash(
            mips_root_hash=bytes.fromhex(MIPS_ROOT_HEX[2:]),
            admins_hash=bytes.fromhex(ADMINS_HASH_HEX[2:]),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=1,
        )
        assert snap.state_hash_hex == "0x" + expected.hex()

    def test_rejects_malformed_hash_setting(self, fresh_settings, monkeypatch):
        """Non-hex / wrong-length hash settings raise ValueError so
        misconfiguration surfaces as a 500 on the endpoint (operators
        see it immediately).
        """
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH",
            "0xnot-actually-hex",
        )
        get_settings.cache_clear()
        with pytest.raises(ValueError, match="not valid hex"):
            build_admin_authority_v2_snapshot(get_settings())

    def test_rejects_wrong_length_hash(self, fresh_settings, monkeypatch):
        """16-byte hash (half size) should be rejected with a clear error."""
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH",
            "0x" + ("ab" * 16),  # only 16 bytes, not 32
        )
        get_settings.cache_clear()
        with pytest.raises(ValueError, match="must be 32 bytes"):
            build_admin_authority_v2_snapshot(get_settings())

    def test_accepts_bare_hex_without_0x_prefix(self, fresh_settings, monkeypatch):
        """Operators might paste raw hex from logs without the 0x
        prefix; the parser tolerates both forms.
        """
        bare_hex = "ab" * 32
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH", bare_hex
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH", "0x" + ("cd" * 32)
        )
        get_settings.cache_clear()
        snap = build_admin_authority_v2_snapshot(get_settings())
        # Output is normalised to 0x-prefixed form regardless.
        assert snap.mips_root_hash_hex == "0x" + bare_hex

    def test_hash_only_config_is_not_enabled_or_chain_verifiable(
        self, fresh_settings, monkeypatch
    ):
        """Hash-only config may be useful diagnostics, but without a
        launcher id auditors cannot locate a singleton to verify.
        """
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH", MIPS_ROOT_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH", ADMINS_HASH_HEX
        )
        get_settings.cache_clear()
        snap = build_admin_authority_v2_snapshot(get_settings())
        assert snap.enabled is False
        assert snap.deployment_status == "hash-config-only"
        assert snap.chain_verifiable is False
        assert snap.phase == "not-deployed"
        assert snap.state_hash_hex is not None


# ─────────────────────────────────────────────────────────────────────────
# /admin/auth/authority_v2 endpoint
# ─────────────────────────────────────────────────────────────────────────


class TestAuthorityV2Endpoint:
    def _client(self) -> TestClient:
        return TestClient(app)

    def test_endpoint_returns_disabled_when_unconfigured(
        self, fresh_settings
    ):
        """No env config → endpoint returns 200 with enabled=false.
        Crucially does NOT 404 so monitoring tools can scrape it
        consistently across environments.
        """
        client = self._client()
        resp = client.get("/admin/auth/authority_v2")
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is False
        assert body["launcher_id"] is None
        assert body["mips_root_hash"] is None
        assert body["admins_hash"] is None
        assert body["pending_ops_hash"] is None
        assert body["state_hash"] is None
        assert body["phase"] == "not-deployed"
        assert body["deployment_status"] == "not-configured"
        assert body["chain_verifiable"] is False
        # Transparency disclaimer fields surface even when disabled.
        assert body["informational_only"] is True
        assert body["gating_source"] == "disabled"

    def test_endpoint_returns_full_state_when_configured(
        self, fresh_settings, monkeypatch
    ):
        """All env vars set → endpoint returns the same fields the
        snapshot helper produced, including the computed state_hash.
        """
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID", LAUNCHER_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH", MIPS_ROOT_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH", ADMINS_HASH_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_PENDING_OPS_HASH",
            PENDING_OPS_HASH_HEX,
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_VERSION", "7"
        )
        get_settings.cache_clear()

        client = self._client()
        resp = client.get("/admin/auth/authority_v2")
        assert resp.status_code == 200
        body = resp.json()

        assert body["enabled"] is True
        assert body["launcher_id"] == LAUNCHER_HEX
        assert body["mips_root_hash"] == MIPS_ROOT_HEX
        assert body["admins_hash"] == ADMINS_HASH_HEX
        assert body["pending_ops_hash"] == PENDING_OPS_HASH_HEX
        assert body["authority_version"] == 7
        assert body["state_hash"] is not None and body["state_hash"].startswith("0x")
        assert body["phase"] == "chain-published-not-gating"
        assert body["deployment_status"] == "deployed-configured"
        assert body["chain_verifiable"] is True
        assert body["informational_only"] is True

    def test_endpoint_reports_hash_only_config_as_not_enabled(
        self, fresh_settings, monkeypatch
    ):
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH", MIPS_ROOT_HEX
        )
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH", ADMINS_HASH_HEX
        )
        get_settings.cache_clear()
        client = self._client()
        resp = client.get("/admin/auth/authority_v2")
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is False
        assert body["deployment_status"] == "hash-config-only"
        assert body["chain_verifiable"] is False

    def test_endpoint_requires_authentication(self, fresh_settings):
        """Roster commitments are unavailable without an admin JWT."""
        app.dependency_overrides.pop(require_admin_jwt, None)
        client = self._client()
        resp = client.get("/admin/auth/authority_v2")
        assert resp.status_code in {401, 503}
        assert "mips_root_hash" not in resp.json()
        assert "authorization" not in resp.request.headers
        app.dependency_overrides[require_admin_jwt] = lambda: None

    def test_endpoint_500s_on_malformed_settings(
        self, fresh_settings, monkeypatch
    ):
        """A malformed hash env var should surface as a 500 rather
        than silently returning bogus data — operators need to see
        misconfiguration immediately.

        FastAPI's TestClient propagates uncaught exceptions by default
        (so test failures are easier to debug). We use
        ``raise_server_exceptions=False`` here to let the framework's
        exception middleware render the actual 500 response, which is
        what production traffic would see.
        """
        monkeypatch.setenv(
            "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH", "garbage"
        )
        get_settings.cache_clear()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/auth/authority_v2")
        # FastAPI surfaces uncaught ValueError as 500.
        assert resp.status_code == 500
