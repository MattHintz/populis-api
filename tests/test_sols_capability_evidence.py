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
EVM_CHAIN_ID = 8453
CHIA_CHAIN_ID = "0x" + "13" * 32
SOLS_ASSET_ID = "0x" + "15" * 32
WRAPPED_CAT = "0x1616161616161616161616161616161616161616"
ROUTE = {
    "routeId": "0x" + "12" * 32,
    "sourceChainId": CHIA_CHAIN_ID,
    "destinationChainId": "0x" + EVM_CHAIN_ID.to_bytes(32, "big").hex(),
    "assetId": SOLS_ASSET_ID,
    "remoteAssetId": "0x" + "00" * 12 + WRAPPED_CAT[2:],
    "decimals": 3,
    "active": True,
}


def _write_evidence(path: Path, *, governed_root: str = ROOT) -> str:
    payload = {
        "schemaVersion": 2,
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
            "adapters": [
                {
                    "adapterId": "warp-cat-bridge-v1",
                    "kind": "WARP_CAT",
                    "recordId": ROUTE["routeId"],
                    "networkLabel": "Base",
                    "assetSymbol": "SOLS",
                    "assetDecimals": 3,
                    "chiaChainId": CHIA_CHAIN_ID,
                    "evmChainId": EVM_CHAIN_ID,
                    "solsAssetId": SOLS_ASSET_ID,
                    "wrappedCat": WRAPPED_CAT,
                    "warpPortal": (
                        "0x1717171717171717171717171717171717171717"
                    ),
                    "assetRegistry": (
                        "0x1818181818181818181818181818181818181818"
                    ),
                    "runtimeCodeHashes": {
                        "wrappedCat": "0x" + "19" * 32,
                        "warpPortal": "0x" + "1a" * 32,
                        "assetRegistry": "0x" + "1b" * 32,
                    },
                    "messageTollWei": "1",
                    "chiaMessageTollMojos": "1",
                    "officialHandoffUrlTemplate": (
                        "https://warp.green/bridge?destination={destination}"
                        "&amount={amountMojos}&asset={assetId}"
                    ),
                    "explorerUrlTemplate": (
                        "https://warp.green/explorer/{operationId}"
                    ),
                }
            ],
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
    assert evidence.adapter_descriptors[0]["recordId"] == ROUTE["routeId"]
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


def test_capability_evidence_rejects_incomplete_or_unbound_adapter(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bridge-evidence.json"
    _write_evidence(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["runtimeEvidence"]["adapters"][0]["wrappedCat"] = (
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    )
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    with pytest.raises(
        SolsCapabilityEvidenceError,
        match="remoteAssetId does not match governance",
    ):
        load_sols_capability_evidence(
            path_value=str(path),
            expected_sha256=digest,
            capability="warp-cat-bridge",
            governed_root=ROOT,
            governed_records=[ROUTE],
        )


def test_capability_evidence_rejects_missing_runtime_code_hash(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bridge-evidence.json"
    _write_evidence(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    del payload["runtimeEvidence"]["adapters"][0]["runtimeCodeHashes"][
        "assetRegistry"
    ]
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    with pytest.raises(
        SolsCapabilityEvidenceError,
        match="runtimeCodeHashes.assetRegistry",
    ):
        load_sols_capability_evidence(
            path_value=str(path),
            expected_sha256=digest,
            capability="warp-cat-bridge",
            governed_root=ROOT,
            governed_records=[ROUTE],
        )
