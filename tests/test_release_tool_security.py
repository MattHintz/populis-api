from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.launch_vault_version_registry import _load_deployment_manifest


def test_registry_broadcast_requires_exact_manifest_digest(tmp_path: Path) -> None:
    manifest = tmp_path / "deployment.json"
    manifest.write_text(
        '{"pool_launcher_id":"0x01","tracker_launcher_id":"0x02"}\n',
        encoding="utf-8",
    )
    approved = hashlib.sha256(manifest.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="required for broadcast"):
        _load_deployment_manifest(
            str(manifest), expected_sha256=None, require_pin=True
        )
    with pytest.raises(ValueError, match="does not match"):
        _load_deployment_manifest(
            str(manifest), expected_sha256="00" * 32, require_pin=True
        )

    parsed, actual = _load_deployment_manifest(
        str(manifest), expected_sha256=approved, require_pin=True
    )
    assert actual == approved
    assert parsed["pool_launcher_id"] == "0x01"


def test_validator_installer_uses_effective_runtime_artifact_path() -> None:
    script = Path("scripts/install_validator_artifact.sh").read_text(
        encoding="utf-8"
    )

    assert "SOLSLOT_VALIDATOR_PUBLIC_ARTIFACT_PATH" in script
    assert "public_artifact_v2.json" not in script
    assert "/proc/{int(sys.argv[1])}/environ" in script
