from __future__ import annotations

import json

from chia_rs import AugSchemeMPL
from fastapi.testclient import TestClient

from solslot_api.validator_app import create_validator_app
from solslot_api.validator_ledger import ValidatorLedger
from solslot_api.validator_service import ValidatorEvidenceError, load_validator_private_key
from solslot_api.validator_settings import ValidatorSettings
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash


def _settings(tmp_path) -> ValidatorSettings:
    keys = [AugSchemeMPL.key_gen(bytes([index]) * 32) for index in (31, 32, 33)]
    pubkeys = ["0x" + bytes(key.get_g1()).hex() for key in keys]
    seed_file = tmp_path / "validator.seed"
    seed_file.write_text((bytes([31]) * 32).hex() + "\n", encoding="ascii")
    seed_file.chmod(0o600)
    release = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "api_commit": "a" * 40,
        "protocol_commit": "b" * 40,
        "built_at_utc": "2026-07-14T00:00:00Z",
        "package_name": "solslot-api-test.tgz",
        "app_module": "solslot_api.app:app",
    }
    release_path = tmp_path / "release.json"
    release_path.write_text(json.dumps(release), encoding="utf-8")
    policy = make_bridge_policy_hash(
        [bytes(key.get_g1()) for key in keys],
        2,
    )
    return ValidatorSettings(
        signer_index=0,
        seed_file=str(seed_file),
        ledger_db_path=str(tmp_path / "ledger.db"),
        public_artifact_path=str(tmp_path / "artifact.json"),
        release_metadata_path=str(release_path),
        evm_rpc_url="https://sepolia.example.invalid",
        bridge_policy_hash="0x" + bytes(policy).hex(),
        roster_pubkeys=pubkeys,
        evm_forwarder_address="0x" + "11" * 20,
        evm_verifier_adapter_address="0x" + "22" * 20,
        evm_attestation_emitter_address="0x" + "33" * 20,
    )


def test_private_signer_health_exposes_public_fingerprints_only(tmp_path) -> None:
    settings = _settings(tmp_path)
    ledger = ValidatorLedger(":memory:")
    app = create_validator_app(settings=settings, ledger=ledger)
    try:
        with TestClient(app) as client:
            response = client.get("/health")
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["status"] == "healthy"
            assert body["signerIndex"] == 0
            assert body["validatorPubkey"] == settings.roster_pubkeys[0]
            assert body["artifactReady"] is False
            assert body["ledgerReady"] is True
            assert client.get("/openapi.json").status_code == 404
    finally:
        ledger.close()


def test_seed_file_permissions_fail_closed(tmp_path) -> None:
    settings = _settings(tmp_path)
    seed_file = tmp_path / "validator.seed"
    seed_file.chmod(0o644)
    try:
        load_validator_private_key(settings)
    except ValidatorEvidenceError as exc:
        assert "group/other" in str(exc)
    else:
        raise AssertionError("world-readable validator seed was accepted")
