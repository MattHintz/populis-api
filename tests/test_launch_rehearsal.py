from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from solslot_api.config import Settings
from solslot_api.genesis_store import GenesisConflict, GenesisStore
from solslot_api.launch_rehearsal import (
    LaunchRehearsalError,
    canonical_json,
    persist_evidence,
    require_completed_rehearsal,
    validate_status,
)
from solslot_api.service_urls import valid_internal_service_url


CONFIG_HASH = "0x" + "ab" * 32
EVIDENCE_SECRET = "settlement-evidence-secret-for-tests"


def _settings(tmp_path) -> Settings:
    return Settings(
        runtime_environment="test",
        network="testnet11",
        launch_rehearsal_service_url="https://rehearsal.example",
        launch_rehearsal_service_token="service-token-that-is-long-enough",
        launch_rehearsal_config_hash=CONFIG_HASH,
        launch_rehearsal_evidence_hmac_secret=EVIDENCE_SECRET,
        launch_settlement_rehearsal_path=str(tmp_path / "settlement.json"),
    )


def test_rehearsal_service_url_allows_only_tls_or_loopback() -> None:
    assert valid_internal_service_url("https://rehearsal.example/internal")
    assert valid_internal_service_url("http://127.0.0.1:8793")
    assert valid_internal_service_url("http://[::1]:8793")
    assert not valid_internal_service_url("http://rehearsal.example")
    assert not valid_internal_service_url("http://localhost:8793")
    assert not valid_internal_service_url("https://user:secret@rehearsal.example")


def _evidence() -> dict:
    return {
        "schemaVersion": 2,
        "kind": "solslot-rc22-settlement-rehearsal",
        "releaseTag": "solslot-v2-alpha-rc22.2-20260729",
        "configHash": CONFIG_HASH,
        "network": "testnet11-base-sepolia",
        "success": True,
        "validatorThreshold": 2,
        "validators": [
            {"id": "validator-1"},
            {"id": "validator-2"},
            {"id": "validator-3"},
        ],
        "lanes": {
            "delivery": {"success": True},
            "refund": {"success": True, "exactRefund": True},
        },
    }


def _signed_status(evidence: dict) -> dict:
    signature = hmac.new(
        EVIDENCE_SECRET.encode(),
        canonical_json(evidence).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "jobId": "rehearsal_job_0001",
        "state": "SUCCEEDED",
        "configHash": CONFIG_HASH,
        "step": "Complete",
        "message": "Delivery and refund passed.",
        "walletTransaction": None,
        "evidence": evidence,
        "evidenceHmac": "0x" + signature,
    }


def test_completed_rehearsal_requires_signed_delivery_and_exact_refund(tmp_path) -> None:
    settings = _settings(tmp_path)
    evidence = _evidence()
    validated = validate_status(_signed_status(evidence), settings=settings)
    assert validated["state"] == "SUCCEEDED"
    assert validated["phase"] == "COMPLETE"
    assert validated["completedSteps"] == 4
    assert validated["evidence"]["lanes"]["refund"]["exactRefund"] is True

    tampered = _evidence()
    tampered["lanes"]["refund"]["exactRefund"] = False
    with pytest.raises(LaunchRehearsalError):
        validate_status(_signed_status(tampered), settings=settings)


def test_rehearsal_rejects_non_base_or_value_bearing_wallet_transaction(tmp_path) -> None:
    settings = _settings(tmp_path)
    value = {
        "jobId": "rehearsal_job_0001",
        "state": "AWAITING_WALLET",
        "configHash": CONFIG_HASH,
        "step": "Review",
        "message": "",
        "walletTransaction": {
            "chainId": 84532,
            "to": "0x" + "12" * 20,
            "value": "0x1",
            "data": "0x1234",
        },
    }
    with pytest.raises(LaunchRehearsalError, match="not Base Sepolia safe"):
        validate_status(value, settings=settings)


def test_rehearsal_rejects_impossible_guided_progress(tmp_path) -> None:
    settings = _settings(tmp_path)
    value = {
        "jobId": "rehearsal_job_0001",
        "state": "AWAITING_WALLET",
        "configHash": CONFIG_HASH,
        "phase": "PAY_DELIVERY",
        "completedSteps": 9,
        "step": "Send test payment",
        "message": "",
        "walletTransaction": None,
    }
    with pytest.raises(LaunchRehearsalError, match="progress changed"):
        validate_status(value, settings=settings)


def test_rehearsal_evidence_is_non_overwritable(tmp_path) -> None:
    settings = _settings(tmp_path)
    evidence = _evidence()
    digest = persist_evidence(settings, evidence)
    expected = hashlib.sha256(
        (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii"
        )
    ).hexdigest()
    assert digest == "0x" + expected
    assert persist_evidence(settings, evidence) == digest

    changed = _evidence()
    changed["lanes"]["delivery"]["success"] = False
    with pytest.raises(LaunchRehearsalError, match="different bytes"):
        persist_evidence(settings, changed)


def test_completed_rehearsal_is_bound_to_store_and_canonical_file(tmp_path) -> None:
    settings = _settings(tmp_path)
    store = GenesisStore(tmp_path / "genesis.db")
    ceremony_id = "0x" + "12" * 32
    store.create_draft(ceremony_id, {}, now=100)
    evidence = _evidence()
    digest = persist_evidence(settings, evidence)
    store.set_settlement_rehearsal(
        ceremony_id,
        job_id="rehearsal_job_0001",
        config_hash=CONFIG_HASH,
        state="SUCCEEDED",
        payload={"evidenceDigest": digest},
        now=101,
    )

    loaded, loaded_digest = require_completed_rehearsal(
        settings,
        store,
        ceremony_id,
    )
    assert loaded == evidence
    assert loaded_digest == digest

    settings.launch_settlement_rehearsal_path = str(tmp_path / "changed.json")
    (tmp_path / "changed.json").write_text(
        json.dumps(evidence, indent=2) + "\n",
        encoding="ascii",
    )
    with pytest.raises(GenesisConflict, match="not canonical"):
        require_completed_rehearsal(settings, store, ceremony_id)


def test_completed_rehearsal_rejects_changed_coordinator_configuration(
    tmp_path,
) -> None:
    settings = _settings(tmp_path)
    store = GenesisStore(tmp_path / "genesis.db")
    ceremony_id = "0x" + "34" * 32
    store.create_draft(ceremony_id, {}, now=100)
    digest = persist_evidence(settings, _evidence())
    store.set_settlement_rehearsal(
        ceremony_id,
        job_id="rehearsal_job_0002",
        config_hash=CONFIG_HASH,
        state="SUCCEEDED",
        payload={"evidenceDigest": digest},
        now=101,
    )
    settings.launch_rehearsal_config_hash = "0x" + "cd" * 32

    with pytest.raises(GenesisConflict, match="configuration changed"):
        require_completed_rehearsal(settings, store, ceremony_id)
