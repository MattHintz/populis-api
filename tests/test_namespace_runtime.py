from __future__ import annotations

import hashlib

import pytest

from solslot_api import config


def test_solslot_environment_is_accepted(monkeypatch) -> None:
    monkeypatch.setenv("SOLSLOT_NETWORK", "testnet11")
    config.validate_runtime_environment_namespace()


def test_retired_environment_namespace_fails_startup(monkeypatch) -> None:
    synthetic_namespace = "SUNSETX"
    monkeypatch.setattr(
        config,
        "_RETIRED_NAMESPACE_DIGEST",
        hashlib.sha256(synthetic_namespace.lower().encode()).hexdigest(),
    )
    monkeypatch.setenv(f"{synthetic_namespace}_NETWORK", "testnet11")
    with pytest.raises(RuntimeError, match="Retired runtime namespace"):
        config.validate_runtime_environment_namespace()
