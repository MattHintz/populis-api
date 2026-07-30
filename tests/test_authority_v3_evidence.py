from __future__ import annotations

import hashlib
import json

import pytest

from solslot_api.authority_v3_evidence import load_governance_evidence
from solslot_api.config import Settings


def _canonical_hash(payload: dict) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _evidence() -> dict:
    payload = {
        "schemaVersion": 3,
        "kind": "solslot-alpha-authority-v3-governance-deployment",
        "authorityRule": "slot0_and_one_of_slot1_slot2",
        "network": "baseSepolia",
        "chainId": 84532,
        "safes": {
            "identities": [{"slot": slot} for slot in range(3)],
        },
        "chiaAuthority": {
            "network": "testnet11",
        },
        "runtimeCodeHashes": {},
        "recovery": {
            "routineDelaySeconds": "86400",
            "lostKeyDelaySeconds": "604800",
            "replacementAcceptanceRequired": True,
            "globalFreezeRequired": True,
            "crossChainConvergenceRequired": True,
            "recoveryKitRotationSupported": True,
            "rollbackRequiresChiaCancellationReceipt": True,
        },
    }
    payload["artifactHash"] = _canonical_hash(payload)
    return payload


def _settings(tmp_path, payload: dict) -> Settings:
    path = tmp_path / "authority-v3-governance.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return Settings(
        runtime_environment="test",
        authority_v3_governance_evidence_path=str(path),
    )


def test_accepts_recovery_kit_and_receipt_bound_rollback_evidence(
    tmp_path,
) -> None:
    payload = _evidence()
    loaded = load_governance_evidence(_settings(tmp_path, payload))
    assert loaded["artifactHash"] == payload["artifactHash"]


@pytest.mark.parametrize(
    "field",
    (
        "recoveryKitRotationSupported",
        "rollbackRequiresChiaCancellationReceipt",
    ),
)
def test_rejects_evidence_missing_recovery_safety_capability(
    tmp_path,
    field: str,
) -> None:
    payload = _evidence()
    payload["recovery"].pop(field)
    payload["artifactHash"] = _canonical_hash(
        {
            key: value
            for key, value in payload.items()
            if key != "artifactHash"
        }
    )
    with pytest.raises(ValueError, match="recovery policy differs"):
        load_governance_evidence(_settings(tmp_path, payload))
