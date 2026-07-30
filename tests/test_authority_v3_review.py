from __future__ import annotations

import hashlib
import json

import pytest

from solslot_api.authority_v3_review import (
    AuthorityV3ReviewError,
    PINNED_CNI_WALLET_SDK_COMMIT,
    PINNED_CNI_WALLET_SDK_REPOSITORY,
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
    load_authority_v3_review,
    read_authority_v3_review_receipt,
)
from solslot_api.config import Settings


SOURCE_NAMES = (
    "protocol",
    "evm",
    "omnichain",
    "api",
    "legacyBackend",
    "keyOfSolomon",
    "samuel",
    "customerWeb",
    "adminPortal",
)


def _canonical_hash(payload: dict) -> str:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key != "artifactHash"
    }
    return "0x" + hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def _payload() -> dict:
    payload = {
        "schemaVersion": 1,
        "kind": "solslot-authority-v3-independent-review",
        "network": "testnet11",
        "protocolVersion": "solslot-v2-rc23",
        "outcome": "approved",
        "reviewRequestHash": "0x" + "40" * 32,
        "sourceShas": {
            name: f"{index:x}" * 40
            for index, name in enumerate(SOURCE_NAMES, start=1)
        },
        "chiaAuthority": {
            "innerModHash": "0x" + "41" * 32,
        },
        "evmAuthority": {
            "governanceEvidenceHash": "0x" + "42" * 32,
        },
        "upstream": {
            "repository": PINNED_CNI_WALLET_SDK_REPOSITORY,
            "commit": PINNED_CNI_WALLET_SDK_COMMIT,
            "license": "Apache-2.0",
            "manifestHash": "0x"
            + RECOVERY_DEPENDENCY_MANIFEST_HASH,
        },
        "reviews": [
            {
                "scope": scope,
                "approved": True,
                "reviewer": f"Independent reviewer {index}",
                "evidenceFile": f"{scope}.md",
                "evidenceHash": "0x"
                + bytes([0x50 + index] * 32).hex(),
                "completedAt": "2026-07-29T12:00:00+00:00",
            }
            for index, scope in enumerate(
                (
                    "chialisp-wrapper",
                    "mips-composition",
                    "safe-recovery-module",
                    "safe-authority-guards",
                ),
                start=1,
            )
        ],
    }
    payload["artifactHash"] = _canonical_hash(payload)
    return payload


def _write(tmp_path, payload: dict) -> Settings:
    path = tmp_path / "authority-v3-review.json"
    raw = (
        json.dumps(payload, sort_keys=True, indent=2)
        + "\n"
    ).encode("ascii")
    path.write_bytes(raw)
    return Settings(
        runtime_environment="test",
        authority_v3_independent_review_path=str(path),
        authority_v3_independent_review_sha256=hashlib.sha256(
            raw
        ).hexdigest(),
    )


def test_loads_checksum_pinned_complete_review(tmp_path) -> None:
    payload = _payload()
    result = load_authority_v3_review(
        _write(tmp_path, payload),
        source_shas=payload["sourceShas"],
        authority_inner_mod_hash=payload["chiaAuthority"][
            "innerModHash"
        ],
        governance_evidence_hash=payload["evmAuthority"][
            "governanceEvidenceHash"
        ],
    )
    assert result["artifactHash"] == payload["artifactHash"]
    assert result["reviewerCount"] == 4
    assert result["reviewRequestHash"] == payload["reviewRequestHash"]
    assert len(result["evidenceFiles"]) == 4
    assert len(result["scopes"]) == 4
    assert read_authority_v3_review_receipt(
        _write(tmp_path, payload),
        expected_file_sha256=result["fileSha256"],
    ) == (tmp_path / "authority-v3-review.json").read_bytes()


def test_rejects_missing_scope_or_stale_source(tmp_path) -> None:
    payload = _payload()
    payload["reviews"].pop()
    payload["artifactHash"] = _canonical_hash(payload)
    with pytest.raises(
        AuthorityV3ReviewError,
        match="four trust boundaries",
    ):
        load_authority_v3_review(
            _write(tmp_path, payload),
            source_shas=payload["sourceShas"],
            authority_inner_mod_hash="0x" + "41" * 32,
            governance_evidence_hash="0x" + "42" * 32,
        )

    payload = _payload()
    expected = dict(payload["sourceShas"])
    expected["api"] = "f" * 40
    with pytest.raises(AuthorityV3ReviewError, match="sourceShas.api"):
        load_authority_v3_review(
            _write(tmp_path, payload),
            source_shas=expected,
            authority_inner_mod_hash="0x" + "41" * 32,
            governance_evidence_hash="0x" + "42" * 32,
        )


def test_rejects_mutable_or_wrong_deployment_receipt(tmp_path) -> None:
    payload = _payload()
    settings = _write(tmp_path, payload)
    settings.authority_v3_independent_review_sha256 = "f" * 64
    with pytest.raises(AuthorityV3ReviewError, match="checksum"):
        load_authority_v3_review(
            settings,
            source_shas=payload["sourceShas"],
            authority_inner_mod_hash="0x" + "41" * 32,
            governance_evidence_hash="0x" + "42" * 32,
        )

    settings = _write(tmp_path, payload)
    with pytest.raises(
        AuthorityV3ReviewError,
        match="different code or deployment",
    ):
        load_authority_v3_review(
            settings,
            source_shas=payload["sourceShas"],
            authority_inner_mod_hash="0x" + "41" * 32,
            governance_evidence_hash="0x" + "99" * 32,
        )


def test_rejects_review_changed_before_archival(tmp_path) -> None:
    payload = _payload()
    settings = _write(tmp_path, payload)
    expected = "0x" + hashlib.sha256(
        (tmp_path / "authority-v3-review.json").read_bytes()
    ).hexdigest()
    (tmp_path / "authority-v3-review.json").write_text(
        "{}\n",
        encoding="ascii",
    )

    with pytest.raises(
        AuthorityV3ReviewError,
        match="changed before archival",
    ):
        read_authority_v3_review_receipt(
            settings,
            expected_file_sha256=expected,
        )


def test_rejects_review_of_different_recovery_dependencies(
    tmp_path,
) -> None:
    payload = _payload()
    payload["upstream"]["manifestHash"] = "0x" + "aa" * 32
    payload["artifactHash"] = _canonical_hash(payload)
    with pytest.raises(
        AuthorityV3ReviewError,
        match="pinned Chia SDK",
    ):
        load_authority_v3_review(
            _write(tmp_path, payload),
            source_shas=payload["sourceShas"],
            authority_inner_mod_hash="0x" + "41" * 32,
            governance_evidence_hash="0x" + "42" * 32,
        )


def test_rejects_unbound_request_or_reused_evidence_file(tmp_path) -> None:
    payload = _payload()
    payload.pop("reviewRequestHash")
    payload["artifactHash"] = _canonical_hash(payload)
    with pytest.raises(
        AuthorityV3ReviewError,
        match="review request hash",
    ):
        load_authority_v3_review(
            _write(tmp_path, payload),
            source_shas=payload["sourceShas"],
            authority_inner_mod_hash="0x" + "41" * 32,
            governance_evidence_hash="0x" + "42" * 32,
        )

    payload = _payload()
    payload["reviews"][1]["evidenceFile"] = payload["reviews"][0][
        "evidenceFile"
    ]
    payload["artifactHash"] = _canonical_hash(payload)
    with pytest.raises(
        AuthorityV3ReviewError,
        match="approval is incomplete",
    ):
        load_authority_v3_review(
            _write(tmp_path, payload),
            source_shas=payload["sourceShas"],
            authority_inner_mod_hash="0x" + "41" * 32,
            governance_evidence_hash="0x" + "42" * 32,
        )
