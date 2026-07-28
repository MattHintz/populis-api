from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from solslot_api.sols_capability_evidence import (
    SolsCapabilityEvidenceError,
    load_sols_capability_evidence,
)


ROOT = "0x" + "11" * 32
ROUTE = {
    "routeId": "0x" + "12" * 32,
    "sourceChainId": "0x" + "13" * 32,
    "destinationChainId": "0x" + "14" * 32,
    "assetId": "0x" + "15" * 32,
    "remoteAssetId": "0x" + "16" * 32,
    "decimals": 3,
    "active": True,
}


def _write_evidence(path: Path, *, governed_root: str = ROOT) -> str:
    payload = {
        "schemaVersion": 1,
        "kind": "solslot-sols-capability-release",
        "capability": "warp-cat-bridge",
        "network": "mainnet",
        "releaseTag": "solslot-v2-beta-rc1",
        "sourceSha": "ab" * 20,
        "governedRoot": governed_root,
        "auditStatus": "reviewed",
        "testOnly": False,
        "adapterIds": ["warp-cat-bridge-v1"],
        "records": [ROUTE],
        "runtimeEvidence": {
            "verified": True,
            "evidenceRoot": "0x" + "17" * 32,
        },
        "implementation": {
            "complete": True,
            "fixturesPassed": True,
        },
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_capability_evidence_binds_checksum_root_and_exact_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bridge-evidence.json"
    digest = _write_evidence(path)

    evidence = load_sols_capability_evidence(
        path_value=str(path),
        expected_sha256=digest,
        capability="warp-cat-bridge",
        governed_root=ROOT,
        governed_records=[ROUTE],
    )

    assert evidence.adapter_ids == ("warp-cat-bridge-v1",)
    assert evidence.governed_root == ROOT
    assert evidence.sha256 == digest


def test_capability_evidence_rejects_altered_statutes_or_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bridge-evidence.json"
    digest = _write_evidence(path)

    with pytest.raises(SolsCapabilityEvidenceError, match="different governed root"):
        load_sols_capability_evidence(
            path_value=str(path),
            expected_sha256=digest,
            capability="warp-cat-bridge",
            governed_root="0x" + "ff" * 32,
            governed_records=[ROUTE],
        )

    path.write_text(path.read_text() + "\n", encoding="utf-8")
    with pytest.raises(SolsCapabilityEvidenceError, match="checksum changed"):
        load_sols_capability_evidence(
            path_value=str(path),
            expected_sha256=digest,
            capability="warp-cat-bridge",
        )


def test_capability_evidence_rejects_record_substitution(tmp_path: Path) -> None:
    path = tmp_path / "bridge-evidence.json"
    digest = _write_evidence(path)
    altered = {**ROUTE, "remoteAssetId": "0x" + "ee" * 32}

    with pytest.raises(SolsCapabilityEvidenceError, match="records do not match"):
        load_sols_capability_evidence(
            path_value=str(path),
            expected_sha256=digest,
            capability="warp-cat-bridge",
            governed_root=ROOT,
            governed_records=[altered],
        )
