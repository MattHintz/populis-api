from __future__ import annotations

import pytest
from fastapi import HTTPException

from solslot_api.admin import _normalize_32_byte_hex


def test_normalize_32_byte_hex_accepts_bare_and_prefixed() -> None:
    assert _normalize_32_byte_hex("ab" * 32, "launcher_id") == "0x" + "ab" * 32
    assert _normalize_32_byte_hex("0X" + "AB" * 32, "launcher_id") == "0x" + "ab" * 32


def test_normalize_32_byte_hex_rejects_wrong_length() -> None:
    with pytest.raises(HTTPException) as exc:
        _normalize_32_byte_hex("ab" * 31, "launcher_id")
    assert exc.value.status_code == 400
    assert "32-byte" in exc.value.detail
