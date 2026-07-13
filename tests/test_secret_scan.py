from __future__ import annotations

import io
import tarfile
from pathlib import Path

from scripts.check_secrets import violations_for_path


def test_clean_source_file_passes(tmp_path: Path) -> None:
    candidate = tmp_path / "config.py"
    candidate.write_text("RPC_URL = os.environ['SOLSLOT_RPC_URL']\n")
    assert violations_for_path(candidate) == []


def test_provider_credential_is_detected_without_echoing_value(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "config.js"
    candidate.write_text(
        "const rpc = 'https://eth-mainnet.g.alchemy.com/v2/"
        + "not-a-real-provider-credential';\n"
    )
    assert violations_for_path(candidate) == [str(candidate)]


def test_packaged_release_is_scanned(tmp_path: Path) -> None:
    archive_path = tmp_path / "release.tgz"
    content = b"STRIPE_" + b"SECRET_KEY=" + b"not-a-real-secret"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("release/.env")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    assert violations_for_path(archive_path) == [
        f"{archive_path}!release/.env"
    ]
