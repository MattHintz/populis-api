from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from solslot_api.config import Settings
from solslot_api.genesis_store import GenesisStore
from solslot_api.launch_gates import require_operation_gate
from solslot_api.launch_rehearsal import persist_evidence


CEREMONY_ID = "0x" + "71" * 32
CONFIG_HASH = "0x" + "72" * 32


def _settings(tmp_path) -> Settings:
    return Settings(
        runtime_environment="test",
        network="testnet11",
        launch_control_enabled=True,
        genesis_db_path=str(tmp_path / "genesis.db"),
        launch_settlement_rehearsal_path=str(tmp_path / "settlement.json"),
        launch_rehearsal_config_hash=CONFIG_HASH,
    )


def _evidence(settings: Settings) -> dict:
    return {
        "schemaVersion": 2,
        "kind": "solslot-rc26-settlement-rehearsal",
        "releaseTag": settings.launch_release_tag,
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


def _open_gate(store: GenesisStore, gate_name: str) -> None:
    now = int(time.time())
    store.upsert_gate(
        CEREMONY_ID,
        gate_name=gate_name,
        opens_at=now - 1,
        closes_at=now + 600,
        payload_hash="0x" + "73" * 32,
        state="open",
        now=now,
    )


def _lock(store: GenesisStore) -> None:
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET state='locked' WHERE ceremony_id=?",
            (CEREMONY_ID,),
        )


def test_operational_windows_require_completed_genesis(tmp_path) -> None:
    settings = _settings(tmp_path)
    store = GenesisStore(settings.genesis_db_path)
    store.create_draft(CEREMONY_ID, {}, now=100)
    _open_gate(store, "minting")

    with pytest.raises(HTTPException, match="signed alpha launch is not complete"):
        require_operation_gate(settings, "minting")

    _lock(store)
    require_operation_gate(settings, "minting")


def test_purchase_windows_require_write_once_settlement_proof(tmp_path) -> None:
    settings = _settings(tmp_path)
    store = GenesisStore(settings.genesis_db_path)
    store.create_draft(CEREMONY_ID, {}, now=100)
    _lock(store)
    _open_gate(store, "purchases")

    with pytest.raises(HTTPException, match="settlement rehearsal is not started"):
        require_operation_gate(settings, "purchases")

    evidence = _evidence(settings)
    digest = persist_evidence(settings, evidence)
    store.set_settlement_rehearsal(
        CEREMONY_ID,
        job_id="rehearsal_job_0001",
        config_hash=CONFIG_HASH,
        state="SUCCEEDED",
        payload={"evidenceDigest": digest},
        now=101,
    )
    require_operation_gate(settings, "purchases")
