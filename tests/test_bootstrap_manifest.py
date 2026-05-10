from __future__ import annotations

import json
from pathlib import Path

import pytest

from populis_api import bootstrap_manifest as bm
from populis_api.bootstrap_manifest import (
    BootstrapArtifactPaths,
    BootstrapManifestError,
    build_bootstrap_artifacts,
    canonical_json_bytes,
    content_hash,
    persist_bootstrap_artifacts,
)


H = lambda byte: "0x" + byte * 32


def deployment_manifest() -> dict:
    return {
        "network": "testnet11",
        "params": {"quorum_bps": 5000},
        "pool_launcher_id": H("11"),
        "did_launcher_id": H("22"),
        "tracker_launcher_id": H("33"),
        "pgt_tail_hash": H("44"),
        "pool_token_tail_hash": H("55"),
        "pool_full_puzhash": H("66"),
        "tracker_full_puzhash": H("77"),
    }


def admin_records() -> dict:
    return {
        "version": 1,
        "launcher_id": H("88"),
        "admin_records": [
            {
                "admin_idx": 0,
                "m_within": 1,
                "leaves": [
                    {
                        "kind": "eip712_member",
                        "leaf_hash": H("99"),
                        "evm_address": "0x" + "aa" * 20,
                        "secp256k1_pubkey": "0x02" + "bb" * 32,
                        "type_hash": H("cc"),
                        "prefix_and_domain_separator": "0x1901" + "dd" * 32,
                    }
                ],
            }
        ],
    }


def artifact_paths(root: Path) -> BootstrapArtifactPaths:
    return BootstrapArtifactPaths(
        admin_records_json=root / "admin_records.json",
        portal_runtime_config_json=root / "portal_runtime_config.json",
        bootstrap_manifest_json=root / "bootstrap_manifest.json",
    )


def artifacts_and_records() -> tuple:
    records = admin_records()
    artifacts = build_bootstrap_artifacts(
        deployment_manifest=deployment_manifest(),
        admin_records=records,
        admin_authority_launcher_id=records["launcher_id"],
        admins_hash=H("ab"),
        mips_root=H("cd"),
    )
    return artifacts, records


def test_content_hash_uses_canonical_json_ordering() -> None:
    left = {"b": [2, 1], "a": {"z": True, "m": None}}
    right = {"a": {"m": None, "z": True}, "b": [2, 1]}

    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert content_hash(left) == content_hash(right)
    assert content_hash(left).startswith("sha256:")


def test_builds_public_bootstrap_manifest_and_runtime_config() -> None:
    deployment = deployment_manifest()
    records = admin_records()

    artifacts = build_bootstrap_artifacts(
        deployment_manifest=deployment,
        admin_records=records,
        admin_authority_launcher_id=records["launcher_id"],
        admins_hash=H("ab"),
        mips_root=H("cd"),
        read_only_api_url="https://api.populis.example",
        read_only_coinset_url="https://coinset.example",
    )

    bootstrap = artifacts.bootstrap_manifest
    runtime = artifacts.portal_runtime_config
    assert bootstrap["version"] == 1
    assert bootstrap["network"] == "testnet11"
    assert bootstrap["protocol"]["pool_launcher_id"] == H("11")
    assert bootstrap["admin_authority_v2"] == {
        "launcher_id": H("88"),
        "admins_hash": H("ab"),
        "mips_root": H("cd"),
        "authority_version": 1,
    }
    assert bootstrap["artifact_hashes"]["deployment_manifest_json"] == content_hash(deployment)
    assert bootstrap["artifact_hashes"]["admin_records_json"] == content_hash(records)
    assert bootstrap["artifact_hashes"]["portal_runtime_config_json"] == content_hash(runtime)
    assert runtime["admin_authority_v2"]["authority_version"] == 1
    assert runtime["admin_authority_v2"]["admin_records_hash"] == content_hash(records)
    assert runtime["read_only_api_url"] == "https://api.populis.example"
    assert runtime["read_only_coinset_url"] == "https://coinset.example"


def test_builds_explicit_authority_version_for_future_snapshots() -> None:
    artifacts = build_bootstrap_artifacts(
        deployment_manifest=deployment_manifest(),
        admin_records=admin_records(),
        admin_authority_launcher_id=H("88"),
        admins_hash=H("ab"),
        mips_root=H("cd"),
        authority_version=7,
    )

    assert artifacts.bootstrap_manifest["admin_authority_v2"]["authority_version"] == 7
    assert artifacts.portal_runtime_config["admin_authority_v2"]["authority_version"] == 7


@pytest.mark.parametrize("authority_version", [0, -1, True, "1"])
def test_rejects_invalid_authority_version(authority_version) -> None:
    with pytest.raises(BootstrapManifestError, match="authority_version"):
        build_bootstrap_artifacts(
            deployment_manifest=deployment_manifest(),
            admin_records=admin_records(),
            admin_authority_launcher_id=H("88"),
            admins_hash=H("ab"),
            mips_root=H("cd"),
            authority_version=authority_version,
        )


@pytest.mark.parametrize(
    "forbidden",
    [
        "POPULIS_ADMIN_TOKEN",
        "populis_bootstrap_session",
        "Bearer abc",
        "raw_wallet_signature",
        "auth_nonce",
        "jwt_secret",
        "faucet_private_key",
    ],
)
def test_rejects_secret_bearing_input_artifacts(forbidden: str) -> None:
    records = admin_records()
    records["forbidden"] = forbidden

    with pytest.raises(BootstrapManifestError, match="forbidden credential marker"):
        build_bootstrap_artifacts(
            deployment_manifest=deployment_manifest(),
            admin_records=records,
            admin_authority_launcher_id=H("88"),
            admins_hash=H("ab"),
            mips_root=H("cd"),
        )


def test_rejects_admin_records_bound_to_different_launcher() -> None:
    with pytest.raises(BootstrapManifestError, match="launcher_id does not match"):
        build_bootstrap_artifacts(
            deployment_manifest=deployment_manifest(),
            admin_records=admin_records(),
            admin_authority_launcher_id=H("ef"),
            admins_hash=H("ab"),
            mips_root=H("cd"),
        )


def test_outputs_do_not_contain_secret_or_signature_material() -> None:
    artifacts = build_bootstrap_artifacts(
        deployment_manifest=deployment_manifest(),
        admin_records=admin_records(),
        admin_authority_launcher_id=H("88"),
        admins_hash=H("ab"),
        mips_root=H("cd"),
    )

    emitted = json.dumps(
        {
            "bootstrap_manifest": artifacts.bootstrap_manifest,
            "portal_runtime_config": artifacts.portal_runtime_config,
        },
        sort_keys=True,
    ).lower()
    for forbidden in (
        "populis_admin_token",
        "populis_bootstrap_session",
        "bootstrap_session",
        "bearer",
        "jwt",
        "secret",
        "signature",
        "nonce",
        "private_key",
    ):
        assert forbidden not in emitted


def test_persists_public_artifacts_with_bootstrap_manifest_last(tmp_path, monkeypatch) -> None:
    artifacts, records = artifacts_and_records()
    paths = artifact_paths(tmp_path)
    writes: list[str] = []
    original = bm._atomic_write_json

    def spy(path, value):
        writes.append(Path(path).name)
        original(path, value)

    monkeypatch.setattr(bm, "_atomic_write_json", spy)

    persist_bootstrap_artifacts(
        artifacts=artifacts,
        admin_records=records,
        paths=paths,
    )

    assert writes == [
        "admin_records.json",
        "portal_runtime_config.json",
        "bootstrap_manifest.json",
    ]
    assert json.loads(paths.admin_records_json.read_text()) == records
    assert json.loads(paths.portal_runtime_config_json.read_text()) == artifacts.portal_runtime_config
    assert json.loads(paths.bootstrap_manifest_json.read_text()) == artifacts.bootstrap_manifest


def test_persistence_refuses_existing_bootstrap_manifest(tmp_path) -> None:
    artifacts, records = artifacts_and_records()
    paths = artifact_paths(tmp_path)
    paths.bootstrap_manifest_json.write_text('{"locked": true}', encoding="utf-8")

    with pytest.raises(BootstrapManifestError, match="already exists"):
        persist_bootstrap_artifacts(
            artifacts=artifacts,
            admin_records=records,
            paths=paths,
        )

    assert not paths.admin_records_json.exists()
    assert not paths.portal_runtime_config_json.exists()


def test_partial_failure_does_not_write_lock_manifest(tmp_path, monkeypatch) -> None:
    artifacts, records = artifacts_and_records()
    paths = artifact_paths(tmp_path)
    original = bm._atomic_write_json

    def fail_runtime(path, value):
        if Path(path).name == "portal_runtime_config.json":
            raise OSError("disk full")
        original(path, value)

    monkeypatch.setattr(bm, "_atomic_write_json", fail_runtime)

    with pytest.raises(OSError, match="disk full"):
        persist_bootstrap_artifacts(
            artifacts=artifacts,
            admin_records=records,
            paths=paths,
        )

    assert paths.admin_records_json.exists()
    assert not paths.portal_runtime_config_json.exists()
    assert not paths.bootstrap_manifest_json.exists()


def test_persistence_rechecks_lock_before_final_manifest_write(tmp_path, monkeypatch) -> None:
    artifacts, records = artifacts_and_records()
    paths = artifact_paths(tmp_path)
    original = bm._atomic_write_json

    def race_lock(path, value):
        original(path, value)
        if Path(path).name == "portal_runtime_config.json":
            paths.bootstrap_manifest_json.write_text('{"locked": true}', encoding="utf-8")

    monkeypatch.setattr(bm, "_atomic_write_json", race_lock)

    with pytest.raises(BootstrapManifestError, match="already exists"):
        persist_bootstrap_artifacts(
            artifacts=artifacts,
            admin_records=records,
            paths=paths,
        )

    assert json.loads(paths.bootstrap_manifest_json.read_text()) == {"locked": True}
