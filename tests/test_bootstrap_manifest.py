from __future__ import annotations

import json

import pytest

from populis_api.bootstrap_manifest import (
    BootstrapManifestError,
    build_bootstrap_artifacts,
    canonical_json_bytes,
    content_hash,
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
    }
    assert bootstrap["artifact_hashes"]["deployment_manifest_json"] == content_hash(deployment)
    assert bootstrap["artifact_hashes"]["admin_records_json"] == content_hash(records)
    assert bootstrap["artifact_hashes"]["portal_runtime_config_json"] == content_hash(runtime)
    assert runtime["admin_authority_v2"]["admin_records_hash"] == content_hash(records)
    assert runtime["read_only_api_url"] == "https://api.populis.example"
    assert runtime["read_only_coinset_url"] == "https://coinset.example"


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
