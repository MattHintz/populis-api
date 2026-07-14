from __future__ import annotations

import hashlib

from scripts import check_namespace


def test_namespace_gate_detects_hex_encoded_material(monkeypatch) -> None:
    synthetic_namespace = b"sunsetx"
    monkeypatch.setattr(
        check_namespace,
        "FORBIDDEN_DIGEST",
        hashlib.sha256(synthetic_namespace).hexdigest(),
    )

    assert check_namespace.contains_forbidden(synthetic_namespace.hex().encode())


def test_namespace_gate_allows_unrelated_hex(monkeypatch) -> None:
    synthetic_namespace = b"sunsetx"
    monkeypatch.setattr(
        check_namespace,
        "FORBIDDEN_DIGEST",
        hashlib.sha256(synthetic_namespace).hexdigest(),
    )

    assert not check_namespace.contains_forbidden(b"534f4c534c4f545f5632")
