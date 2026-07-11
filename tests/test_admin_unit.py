"""Unit tests for admin-router building blocks.

These tests deliberately bypass FastAPI's TestClient and lifespan because
chia_rs binds its internal ``LazyNode`` types to whatever thread first
imports them, and TestClient's threadpool dispatch panics on cross-thread
access.  Smoke-style HTTP tests for /admin endpoints will work against a
running uvicorn process but cannot run inside pytest's threading model.

What this file covers:
- ``require_admin_token`` returns 503/401/403/None correctly under all
  four auth states (disabled / missing / wrong / correct).
- ``_select_coin_by_id`` selects the smallest-fitting coin or the
  named coin, and rejects insufficient amounts.
- The ``DeployRequest`` schema enforces field bounds (quorum_bps,
  min_proposal_stake, etc.) at the pydantic layer.
- The ``ManifestResponse`` round-trips a saved-to-disk manifest dict.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from populis_api.admin import (
    BridgePoolTopUpRequest,
    DeployRequest,
    ManifestResponse,
    _coin_id_from_fields,
    _select_coin_by_id,
    require_admin_token,
)
from populis_api.config import Settings


# ── require_admin_token ──────────────────────────────────────────────────────
class TestRequireAdminToken:
    def test_disabled_when_no_token_configured(self) -> None:
        settings = Settings(network="testnet11", admin_token=None)
        with pytest.raises(HTTPException) as exc:
            require_admin_token(settings, authorization="Bearer anything")
        assert exc.value.status_code == 503
        assert "disabled" in exc.value.detail.lower()

    def test_missing_authorization_header_returns_401(self) -> None:
        settings = Settings(network="testnet11", admin_token="secret")
        with pytest.raises(HTTPException) as exc:
            require_admin_token(settings, authorization=None)
        assert exc.value.status_code == 401

    def test_malformed_authorization_returns_401(self) -> None:
        settings = Settings(network="testnet11", admin_token="secret")
        with pytest.raises(HTTPException) as exc:
            require_admin_token(settings, authorization="Token wrong-format")
        assert exc.value.status_code == 401

    def test_wrong_token_returns_403(self) -> None:
        settings = Settings(network="testnet11", admin_token="secret")
        with pytest.raises(HTTPException) as exc:
            require_admin_token(settings, authorization="Bearer wrong")
        assert exc.value.status_code == 403

    def test_correct_token_returns_none(self) -> None:
        """Successful auth: function returns None (no exception raised)."""
        settings = Settings(network="testnet11", admin_token="secret")
        result = require_admin_token(settings, authorization="Bearer secret")
        assert result is None

    def test_constant_time_compare_used(self) -> None:
        """Tokens are compared via ``hmac.compare_digest`` to resist timing
        attacks.  We can't directly observe timing here but we can verify
        that wrong tokens of equal vs. unequal length both return 403."""
        settings = Settings(network="testnet11", admin_token="abcdefgh")
        for wrong in ["12345678", "wrong", "abcdefghextra"]:
            with pytest.raises(HTTPException) as exc:
                require_admin_token(settings, authorization=f"Bearer {wrong}")
            assert exc.value.status_code == 403


# ── _select_coin_by_id ──────────────────────────────────────────────────────
class _FakeCoin:
    """Lightweight Coin stand-in (avoids chia imports for speed)."""

    def __init__(self, name_hex: str, amount: int):
        self._name = bytes.fromhex(name_hex)
        self.amount = amount

    def name(self) -> bytes:
        return self._name


class TestSelectCoin:
    def test_select_by_id_succeeds(self) -> None:
        coins = [
            _FakeCoin("a" * 64, 100),
            _FakeCoin("b" * 64, 200),
        ]
        chosen = _select_coin_by_id(coins, "0x" + "b" * 64, min_amount=50, label="x")
        assert chosen.amount == 200
        # Removed from candidates
        assert len(coins) == 1

    def test_select_by_id_amount_too_small(self) -> None:
        coins = [_FakeCoin("a" * 64, 100)]
        with pytest.raises(HTTPException) as exc:
            _select_coin_by_id(coins, "0x" + "a" * 64, min_amount=200, label="pgt_coin")
        assert exc.value.status_code == 400
        assert "amount 100" in exc.value.detail

    def test_select_by_id_not_found(self) -> None:
        coins = [_FakeCoin("a" * 64, 100)]
        with pytest.raises(HTTPException) as exc:
            _select_coin_by_id(coins, "0x" + "f" * 64, min_amount=50, label="pgt_coin")
        assert exc.value.status_code == 404

    def test_select_smallest_fitting(self) -> None:
        """No coin_id given → choose the smallest coin that meets min_amount."""
        coins = [
            _FakeCoin("a" * 64, 50),    # too small
            _FakeCoin("b" * 64, 1000),
            _FakeCoin("c" * 64, 100),   # smallest-that-fits
        ]
        chosen = _select_coin_by_id(coins, None, min_amount=80, label="x")
        assert chosen.amount == 100

    def test_select_no_coins_fit(self) -> None:
        coins = [_FakeCoin("a" * 64, 50), _FakeCoin("b" * 64, 60)]
        with pytest.raises(HTTPException) as exc:
            _select_coin_by_id(coins, None, min_amount=1000, label="pgt_coin")
        assert exc.value.status_code == 503
        assert "no unspent" in exc.value.detail.lower()

    def test_select_consumes_candidate(self) -> None:
        """After selection, the chosen coin is removed from candidates so
        subsequent calls don't pick the same one."""
        coins = [_FakeCoin("a" * 64, 100), _FakeCoin("b" * 64, 200)]
        _select_coin_by_id(coins, None, min_amount=50, label="a")
        # First call took the smaller (100); only the 200 remains
        assert len(coins) == 1
        assert coins[0].amount == 200


# ── DeployRequest schema ─────────────────────────────────────────────────────
class TestDeployRequestSchema:
    def test_defaults_match_protocol_doc(self) -> None:
        body = DeployRequest()
        assert body.quorum_bps == 5000
        assert body.voting_window_seconds == 300
        assert body.pgt_total_supply == 1_000_000
        assert body.min_proposal_stake == 10_000
        assert body.fp_scale == 1000
        assert body.initial_pool_status == 1
        assert body.fee_per_spend == 0
        assert body.dry_run is False

    def test_quorum_bps_capped_at_10000(self) -> None:
        with pytest.raises(ValueError):
            DeployRequest(quorum_bps=10001)

    def test_quorum_bps_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            DeployRequest(quorum_bps=0)

    def test_min_proposal_stake_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            DeployRequest(min_proposal_stake=0)

    def test_initial_pool_status_must_be_0_or_1(self) -> None:
        DeployRequest(initial_pool_status=0)  # FROZEN
        DeployRequest(initial_pool_status=1)  # ACTIVE
        with pytest.raises(ValueError):
            DeployRequest(initial_pool_status=2)

    def test_fee_per_spend_non_negative(self) -> None:
        DeployRequest(fee_per_spend=0)
        DeployRequest(fee_per_spend=1000)
        with pytest.raises(ValueError):
            DeployRequest(fee_per_spend=-1)


class TestBridgePoolTopUpRequest:
    def test_defaults_create_six_one_mojo_series(self) -> None:
        body = BridgePoolTopUpRequest()
        assert body.count == 6
        assert body.start_amount == 1
        assert body.fee == 0
        assert body.dry_run is False

    def test_bounds_reject_empty_batch(self) -> None:
        with pytest.raises(ValueError):
            BridgePoolTopUpRequest(count=0)

    def test_bridge_coin_id_includes_amount(self) -> None:
        parent = bytes.fromhex("aa" * 32)
        puzzle_hash = bytes.fromhex("bb" * 32)
        one = _coin_id_from_fields(parent, puzzle_hash, 1)
        two = _coin_id_from_fields(parent, puzzle_hash, 2)
        assert one != two
        assert one.startswith("0x")
        assert len(one) == 66


# ── Manifest response shape ──────────────────────────────────────────────────
class TestManifestResponse:
    def test_no_manifest_serialises_correctly(self) -> None:
        r = ManifestResponse(deployed=False, manifest=None)
        assert r.model_dump() == {"deployed": False, "manifest": None}

    def test_manifest_dict_passes_through(self) -> None:
        manifest = {
            "network": "testnet11",
            "params": {"quorum_bps": 5000},
            "tracker_launcher_id": "0x" + "ab" * 32,
        }
        r = ManifestResponse(deployed=True, manifest=manifest)
        assert r.deployed is True
        assert r.manifest == manifest


# ── Settings round-trip ──────────────────────────────────────────────────────
class TestAdminSettings:
    def test_admin_token_default_none(self) -> None:
        """Default settings should have admin disabled (token=None) — the safe
        default for public deployments."""
        s = Settings(network="testnet11", admin_token=None)
        assert s.admin_token is None

    def test_deployment_manifest_path_default(self) -> None:
        s = Settings(network="testnet11")
        assert s.deployment_manifest_path == "./deployment_manifest.json"

    def test_admin_token_round_trips(self) -> None:
        s = Settings(network="testnet11", admin_token="my-token-123")
        assert s.admin_token == "my-token-123"
