from __future__ import annotations

import json
from pathlib import Path

import pytest

from populis_api import bootstrap_manifest as bm
from populis_api.bootstrap_manifest import (
    BootstrapArtifactPaths,
    BootstrapManifestError,
    build_bootstrap_artifacts,
    build_bootstrap_recovery_anchor,
    build_bootstrap_recovery_anchor_create_coin_preview,
    build_bootstrap_recovery_anchor_memos,
    build_bootstrap_recovery_anchor_publish_intent,
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
        bootstrap_recovery_anchor_json=root / "bootstrap_recovery_anchor.json",
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


def clone_json(value: dict) -> dict:
    return json.loads(json.dumps(value))


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
    assert artifacts.bootstrap_recovery_anchor["tag"] == bm.BOOTSTRAP_RECOVERY_ANCHOR_TAG
    assert artifacts.bootstrap_recovery_anchor["bootstrap_manifest_hash"] == content_hash(bootstrap)
    assert artifacts.bootstrap_recovery_anchor["portal_runtime_config_hash"] == content_hash(runtime)
    assert artifacts.bootstrap_recovery_anchor["admin_records_hash"] == content_hash(records)


def test_builds_bootstrap_recovery_anchor_from_finalized_artifacts() -> None:
    artifacts, records = artifacts_and_records()

    anchor = build_bootstrap_recovery_anchor(
        bootstrap_manifest=artifacts.bootstrap_manifest,
        portal_runtime_config=artifacts.portal_runtime_config,
    )

    expected_payload = {
        "version": 1,
        "tag": bm.BOOTSTRAP_RECOVERY_ANCHOR_TAG,
        "network": "testnet11",
        "admin_authority_v2_launcher_id": H("88"),
        "authority_version": 1,
        "bootstrap_manifest_hash": content_hash(artifacts.bootstrap_manifest),
        "portal_runtime_config_hash": content_hash(artifacts.portal_runtime_config),
        "admin_records_hash": content_hash(records),
    }
    assert anchor.payload == expected_payload
    assert anchor.payload_bytes == canonical_json_bytes(expected_payload)
    assert anchor.payload_hash == content_hash(expected_payload)
    assert json.loads(anchor.payload_bytes) == expected_payload


def test_bootstrap_recovery_anchor_accepts_explicit_payload_version() -> None:
    artifacts, _ = artifacts_and_records()

    anchor = build_bootstrap_recovery_anchor(
        bootstrap_manifest=artifacts.bootstrap_manifest,
        portal_runtime_config=artifacts.portal_runtime_config,
        version=2,
    )

    assert anchor.payload["version"] == 2


@pytest.mark.parametrize("version", [0, -1, True, "1"])
def test_bootstrap_recovery_anchor_rejects_invalid_payload_version(version) -> None:
    artifacts, _ = artifacts_and_records()

    with pytest.raises(BootstrapManifestError, match="recovery anchor version"):
        build_bootstrap_recovery_anchor(
            bootstrap_manifest=artifacts.bootstrap_manifest,
            portal_runtime_config=artifacts.portal_runtime_config,
            version=version,
        )


def test_bootstrap_recovery_anchor_rejects_runtime_config_hash_drift() -> None:
    artifacts, _ = artifacts_and_records()
    runtime = clone_json(artifacts.portal_runtime_config)
    runtime["read_only_api_url"] = "https://mirror.populis.example"

    with pytest.raises(BootstrapManifestError, match="portal_runtime_config_json hash"):
        build_bootstrap_recovery_anchor(
            bootstrap_manifest=artifacts.bootstrap_manifest,
            portal_runtime_config=runtime,
        )


def test_bootstrap_recovery_anchor_rejects_admin_records_hash_drift() -> None:
    artifacts, _ = artifacts_and_records()
    runtime = clone_json(artifacts.portal_runtime_config)
    runtime["admin_authority_v2"]["admin_records_hash"] = f"sha256:{'ff' * 32}"

    with pytest.raises(BootstrapManifestError, match="admin_records_json hash"):
        build_bootstrap_recovery_anchor(
            bootstrap_manifest=artifacts.bootstrap_manifest,
            portal_runtime_config=runtime,
        )


def test_bootstrap_recovery_anchor_rejects_authority_coordinate_mismatch() -> None:
    artifacts, _ = artifacts_and_records()
    runtime = clone_json(artifacts.portal_runtime_config)
    runtime["admin_authority_v2"]["authority_version"] = 2

    with pytest.raises(BootstrapManifestError, match="authority_version"):
        build_bootstrap_recovery_anchor(
            bootstrap_manifest=artifacts.bootstrap_manifest,
            portal_runtime_config=runtime,
        )


def test_bootstrap_recovery_anchor_rejects_secret_bearing_artifacts() -> None:
    artifacts, _ = artifacts_and_records()
    manifest = clone_json(artifacts.bootstrap_manifest)
    manifest["forbidden"] = "POPULIS_ADMIN_TOKEN"

    with pytest.raises(BootstrapManifestError, match="forbidden credential marker"):
        build_bootstrap_recovery_anchor(
            bootstrap_manifest=manifest,
            portal_runtime_config=artifacts.portal_runtime_config,
        )


def test_builds_bootstrap_recovery_anchor_marker_memos() -> None:
    artifacts, _ = artifacts_and_records()

    carrier = build_bootstrap_recovery_anchor_memos(
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
    )

    assert carrier.tag_memo == b"POPULIS_BOOTSTRAP_V1"
    assert carrier.payload_memo == canonical_json_bytes(artifacts.bootstrap_recovery_anchor)
    assert carrier.memos == (carrier.tag_memo, carrier.payload_memo)
    assert carrier.payload_hash == content_hash(artifacts.bootstrap_recovery_anchor)
    assert json.loads(carrier.payload_memo) == artifacts.bootstrap_recovery_anchor


def test_bootstrap_recovery_anchor_marker_memos_canonicalize_input_order() -> None:
    artifacts, _ = artifacts_and_records()
    payload = artifacts.bootstrap_recovery_anchor
    reordered = {
        "tag": payload["tag"],
        "version": payload["version"],
        "portal_runtime_config_hash": payload["portal_runtime_config_hash"],
        "network": payload["network"],
        "admin_records_hash": payload["admin_records_hash"],
        "authority_version": payload["authority_version"],
        "bootstrap_manifest_hash": payload["bootstrap_manifest_hash"],
        "admin_authority_v2_launcher_id": payload["admin_authority_v2_launcher_id"],
    }

    carrier = build_bootstrap_recovery_anchor_memos(
        bootstrap_recovery_anchor=reordered,
    )

    assert carrier.payload_memo == canonical_json_bytes(payload)
    assert carrier.payload_hash == content_hash(payload)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("tag", "WRONG", "tag"),
        ("version", 0, "recovery anchor version"),
        ("admin_authority_v2_launcher_id", "88" * 32, "canonical 0x-prefixed"),
        ("authority_version", "1", "authority_version"),
        ("bootstrap_manifest_hash", "sha256:" + "AA" * 32, "canonical sha256"),
        ("portal_runtime_config_hash", "sha256:" + "zz" * 32, "sha256 content hash"),
        ("admin_records_hash", "0x" + "12" * 32, "sha256 content hash"),
    ],
)
def test_bootstrap_recovery_anchor_marker_memos_reject_invalid_payload(
    field: str,
    value: object,
    match: str,
) -> None:
    artifacts, _ = artifacts_and_records()
    payload = clone_json(artifacts.bootstrap_recovery_anchor)
    payload[field] = value

    with pytest.raises(BootstrapManifestError, match=match):
        build_bootstrap_recovery_anchor_memos(
            bootstrap_recovery_anchor=payload,
        )


def test_bootstrap_recovery_anchor_marker_memos_reject_secret_material() -> None:
    artifacts, _ = artifacts_and_records()
    payload = clone_json(artifacts.bootstrap_recovery_anchor)
    payload["private_url"] = "https://secret.example/bootstrap"

    with pytest.raises(BootstrapManifestError, match="forbidden credential marker"):
        build_bootstrap_recovery_anchor_memos(
            bootstrap_recovery_anchor=payload,
        )


def test_builds_bootstrap_recovery_anchor_publish_intent() -> None:
    artifacts, _ = artifacts_and_records()
    carrier = build_bootstrap_recovery_anchor_memos(
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
    )

    intent = build_bootstrap_recovery_anchor_publish_intent(
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
    )

    assert intent.network == "testnet11"
    assert intent.marker_coin_amount_mojos == 1
    assert intent.admin_authority_v2_launcher_id == H("88")
    assert intent.authority_version == 1
    assert intent.bootstrap_manifest_hash == artifacts.bootstrap_recovery_anchor[
        "bootstrap_manifest_hash"
    ]
    assert intent.portal_runtime_config_hash == artifacts.bootstrap_recovery_anchor[
        "portal_runtime_config_hash"
    ]
    assert intent.admin_records_hash == artifacts.bootstrap_recovery_anchor["admin_records_hash"]
    assert intent.tag_memo == carrier.tag_memo
    assert intent.payload_memo == carrier.payload_memo
    assert intent.memos == carrier.memos
    assert intent.payload_hash == carrier.payload_hash
    for non_authority_field in (
        "marker_puzzle_hash",
        "marker_coin_id",
        "parent_coin_id",
        "future_spend",
        "spend_bundle",
    ):
        assert not hasattr(intent, non_authority_field)


def test_bootstrap_recovery_anchor_publish_intent_accepts_custom_marker_amount() -> None:
    artifacts, _ = artifacts_and_records()

    intent = build_bootstrap_recovery_anchor_publish_intent(
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
        marker_coin_amount_mojos=42,
    )

    assert intent.marker_coin_amount_mojos == 42
    assert intent.memos == build_bootstrap_recovery_anchor_memos(
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
    ).memos


@pytest.mark.parametrize(
    ("amount", "match"),
    [
        (0, "at least 1 mojo"),
        (-1, "at least 1 mojo"),
        (True, "integer number of mojos"),
        ("1", "integer number of mojos"),
    ],
)
def test_bootstrap_recovery_anchor_publish_intent_rejects_invalid_marker_amount(
    amount: object,
    match: str,
) -> None:
    artifacts, _ = artifacts_and_records()

    with pytest.raises(BootstrapManifestError, match=match):
        build_bootstrap_recovery_anchor_publish_intent(
            bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
            marker_coin_amount_mojos=amount,
        )


def test_bootstrap_recovery_anchor_publish_intent_rejects_secret_material() -> None:
    artifacts, _ = artifacts_and_records()
    payload = clone_json(artifacts.bootstrap_recovery_anchor)
    payload["mutable_service_credentials"] = {"token": "not-public"}

    with pytest.raises(BootstrapManifestError, match="forbidden credential marker"):
        build_bootstrap_recovery_anchor_publish_intent(
            bootstrap_recovery_anchor=payload,
        )


def test_builds_bootstrap_recovery_anchor_create_coin_preview() -> None:
    artifacts, _ = artifacts_and_records()
    intent = build_bootstrap_recovery_anchor_publish_intent(
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
        marker_coin_amount_mojos=42,
    )

    preview = build_bootstrap_recovery_anchor_create_coin_preview(
        publish_intent=intent,
        marker_puzzle_hash=H("ef"),
    )

    assert preview.condition_opcode == bm.CREATE_COIN_CONDITION_OPCODE == 51
    assert preview.marker_puzzle_hash == H("ef")
    assert preview.marker_coin_amount_mojos == 42
    assert preview.tag_memo == intent.tag_memo
    assert preview.payload_memo == intent.payload_memo
    assert preview.memos == intent.memos
    assert preview.condition == (
        51,
        bytes.fromhex("ef" * 32),
        42,
        intent.memos,
    )
    assert preview.condition_hex == (
        51,
        H("ef"),
        42,
        tuple("0x" + memo.hex() for memo in intent.memos),
    )
    assert preview.payload_hash == intent.payload_hash
    for non_authority_field in (
        "marker_coin_id",
        "parent_coin_id",
        "future_spend",
        "spend_bundle",
        "wallet_signature",
    ):
        assert not hasattr(preview, non_authority_field)


@pytest.mark.parametrize("marker_puzzle_hash", ["ef" * 32, "0x" + "EF" * 32])
def test_bootstrap_recovery_anchor_create_coin_preview_normalizes_marker_puzzle_hash(
    marker_puzzle_hash: str,
) -> None:
    artifacts, _ = artifacts_and_records()
    intent = build_bootstrap_recovery_anchor_publish_intent(
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
    )

    preview = build_bootstrap_recovery_anchor_create_coin_preview(
        publish_intent=intent,
        marker_puzzle_hash=marker_puzzle_hash,
    )

    assert preview.marker_puzzle_hash == H("ef")
    assert preview.condition[1] == bytes.fromhex("ef" * 32)


@pytest.mark.parametrize("marker_puzzle_hash", ["0x1234", "0x" + "zz" * 32, 123])
def test_bootstrap_recovery_anchor_create_coin_preview_rejects_invalid_marker_puzzle_hash(
    marker_puzzle_hash: object,
) -> None:
    artifacts, _ = artifacts_and_records()
    intent = build_bootstrap_recovery_anchor_publish_intent(
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
    )

    with pytest.raises(BootstrapManifestError, match="marker_puzzle_hash"):
        build_bootstrap_recovery_anchor_create_coin_preview(
            publish_intent=intent,
            marker_puzzle_hash=marker_puzzle_hash,
        )


def test_bootstrap_recovery_anchor_create_coin_preview_rejects_tampered_intent() -> None:
    artifacts, _ = artifacts_and_records()
    intent = build_bootstrap_recovery_anchor_publish_intent(
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
    )
    tampered = bm.BootstrapRecoveryAnchorPublishIntent(
        network=intent.network,
        marker_coin_amount_mojos=intent.marker_coin_amount_mojos,
        admin_authority_v2_launcher_id=intent.admin_authority_v2_launcher_id,
        authority_version=intent.authority_version,
        bootstrap_manifest_hash=intent.bootstrap_manifest_hash,
        portal_runtime_config_hash=intent.portal_runtime_config_hash,
        admin_records_hash=intent.admin_records_hash,
        tag_memo=intent.tag_memo,
        payload_memo=intent.payload_memo,
        memos=(intent.payload_memo, intent.tag_memo),
        payload_hash=intent.payload_hash,
    )

    with pytest.raises(BootstrapManifestError, match="memos must be tag memo then payload memo"):
        build_bootstrap_recovery_anchor_create_coin_preview(
            publish_intent=tampered,
            marker_puzzle_hash=H("ef"),
        )


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
            "bootstrap_recovery_anchor": artifacts.bootstrap_recovery_anchor,
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
        "bootstrap_recovery_anchor.json",
        "bootstrap_manifest.json",
    ]
    assert json.loads(paths.admin_records_json.read_text()) == records
    assert json.loads(paths.portal_runtime_config_json.read_text()) == artifacts.portal_runtime_config
    assert json.loads(paths.bootstrap_recovery_anchor_json.read_text()) == (
        artifacts.bootstrap_recovery_anchor
    )
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
    assert not paths.bootstrap_recovery_anchor_json.exists()


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
    assert not paths.bootstrap_recovery_anchor_json.exists()
    assert not paths.bootstrap_manifest_json.exists()


def test_persistence_rechecks_lock_before_final_manifest_write(tmp_path, monkeypatch) -> None:
    artifacts, records = artifacts_and_records()
    paths = artifact_paths(tmp_path)
    original = bm._atomic_write_json

    def race_lock(path, value):
        original(path, value)
        if Path(path).name == "bootstrap_recovery_anchor.json":
            paths.bootstrap_manifest_json.write_text('{"locked": true}', encoding="utf-8")

    monkeypatch.setattr(bm, "_atomic_write_json", race_lock)

    with pytest.raises(BootstrapManifestError, match="already exists"):
        persist_bootstrap_artifacts(
            artifacts=artifacts,
            admin_records=records,
            paths=paths,
        )

    assert paths.bootstrap_recovery_anchor_json.exists()
    assert json.loads(paths.bootstrap_manifest_json.read_text()) == {"locked": True}
