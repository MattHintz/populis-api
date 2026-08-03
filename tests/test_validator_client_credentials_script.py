from __future__ import annotations

from pathlib import Path
import subprocess


def test_normalizer_binds_credentials_to_the_selected_service(tmp_path: Path) -> None:
    credential_root = tmp_path / "credentials"
    credential_root.mkdir()
    for name in ("ca.crt", "coordinator.crt", "coordinator.key"):
        (credential_root / name).write_text(name, encoding="utf-8")
    drop_in = tmp_path / "20-validator-fleet.conf"
    drop_in.write_text(
        """[Service]
LoadCredential=validator-ca:/old/ca.crt
LoadCredential=validator-client-cert:/old/client.crt
LoadCredential=validator-client-key:/old/client.key
Environment=SOLSLOT_ZKPASSPORT_VALIDATOR_MTLS_CA_PATH=/run/credentials/solslot-api-staging.service/validator-ca
Environment=SOLSLOT_ZKPASSPORT_VALIDATOR_MTLS_CERT_PATH=/run/credentials/solslot-api-staging.service/validator-client-cert
Environment=SOLSLOT_ZKPASSPORT_VALIDATOR_MTLS_KEY_PATH=/run/credentials/solslot-api-staging.service/validator-client-key
Environment=SOLSLOT_ZKPASSPORT_VALIDATOR_THRESHOLD=2
""",
        encoding="utf-8",
    )

    script = Path(__file__).parents[1] / "scripts" / "normalize_validator_client_credentials.sh"
    subprocess.run(
        [
            "bash",
            str(script),
            "--service",
            "solslot-api-production.service",
            "--credential-root",
            str(credential_root),
            "--drop-in",
            str(drop_in),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    normalized = drop_in.read_text(encoding="utf-8")
    assert "solslot-api-staging.service" not in normalized
    assert (
        "Environment=SOLSLOT_ZKPASSPORT_VALIDATOR_MTLS_CA_PATH="
        "/run/credentials/solslot-api-production.service/validator-ca"
    ) in normalized
    assert f"LoadCredential=validator-ca:{credential_root}/ca.crt" in normalized
    assert "Environment=SOLSLOT_ZKPASSPORT_VALIDATOR_THRESHOLD=2" in normalized
    assert (credential_root / "coordinator.key").stat().st_mode & 0o777 == 0o600
