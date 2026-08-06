from __future__ import annotations

import hashlib
import io
import tarfile

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


def test_namespace_gate_rejects_high_ratio_archive_before_expansion(tmp_path) -> None:
    archive_path = tmp_path / "bomb.tgz"
    content = b"\x00" * (1024 * 1024)
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("large-zero-file")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))

    violations = check_namespace.scan_file(archive_path)

    assert any("unsafe archive" in item for item in violations)
