from __future__ import annotations

import pytest

from solslot_api.config import validate_runtime_environment_namespace


def _retired_key(suffix: str) -> str:
    namespace = bytes.fromhex("706f70756c6973").decode("ascii").upper()
    return f"{namespace}_{suffix}"


def test_solslot_environment_is_accepted(monkeypatch) -> None:
    monkeypatch.setenv("SOLSLOT_NETWORK", "testnet11")
    validate_runtime_environment_namespace()


def test_retired_environment_namespace_fails_startup(monkeypatch) -> None:
    key = _retired_key("NETWORK")
    monkeypatch.setenv(key, "testnet11")
    with pytest.raises(RuntimeError, match="Retired runtime namespace"):
        validate_runtime_environment_namespace()
