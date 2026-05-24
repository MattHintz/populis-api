from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

from populis_api.admin import _normalize_32_byte_hex, _upsert_env_assignment


def test_normalize_32_byte_hex_accepts_bare_and_prefixed() -> None:
    assert _normalize_32_byte_hex("ab" * 32, "launcher_id") == "0x" + "ab" * 32
    assert _normalize_32_byte_hex("0X" + "AB" * 32, "launcher_id") == "0x" + "ab" * 32


def test_normalize_32_byte_hex_rejects_wrong_length() -> None:
    with pytest.raises(HTTPException) as exc:
        _normalize_32_byte_hex("ab" * 31, "launcher_id")
    assert exc.value.status_code == 400
    assert "32-byte" in exc.value.detail


def test_upsert_env_assignment_adds_or_replaces_and_preserves_mode(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "POPULIS_NETWORK=testnet11\n"
        "export POPULIS_PROTOCOL_CONFIG_LAUNCHER_ID=0x" + "11" * 32 + "\n",
        encoding="utf-8",
    )
    env_file.chmod(0o664)

    _upsert_env_assignment(
        env_file,
        "POPULIS_PROTOCOL_CONFIG_LAUNCHER_ID",
        "0x" + "22" * 32,
    )

    text = env_file.read_text(encoding="utf-8")
    assert "POPULIS_NETWORK=testnet11" in text
    assert f"POPULIS_PROTOCOL_CONFIG_LAUNCHER_ID=0x{'22' * 32}" in text
    assert "11" * 32 not in text
    assert env_file.stat().st_mode & 0o777 == 0o600
