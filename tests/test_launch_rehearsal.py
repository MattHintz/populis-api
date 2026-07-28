from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from solslot_api.config import Settings
from solslot_api.launch_rehearsal import (
    LaunchRehearsalError,
    canonical_json,
    persist_evidence,
    validate_status,
)


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


def _evidence() -> dict:
    return {
        "schemaVersion": 2,
        "kind": "solslot-rc22-settlement-rehearsal",
        "releaseTag": "solslot-v2-alpha-rc22-20260727",
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
