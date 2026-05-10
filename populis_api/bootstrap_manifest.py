from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


FORBIDDEN_ARTIFACT_MARKERS = (
    "populis_admin_token",
    "populis_bootstrap_session",
    "bootstrap_session",
    "authorization",
    "bearer",
    "jwt",
    "secret",
    "signature",
    "nonce",
    "private_key",
    "faucet_mnemonic",
    "faucet_seed",
    "faucet_master_sk",
)


class BootstrapManifestError(ValueError):
    pass


@dataclass(frozen=True)
class BootstrapArtifacts:
    bootstrap_manifest: dict[str, Any]
    portal_runtime_config: dict[str, Any]


@dataclass(frozen=True)
class BootstrapArtifactPaths:
    admin_records_json: Path
    portal_runtime_config_json: Path
    bootstrap_manifest_json: Path


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def content_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def build_bootstrap_artifacts(
    *,
    deployment_manifest: Mapping[str, Any],
    admin_records: Mapping[str, Any],
    admin_authority_launcher_id: str,
    admins_hash: str,
    mips_root: str,
    read_only_api_url: str | None = None,
    read_only_coinset_url: str | None = None,
) -> BootstrapArtifacts:
    deployment = dict(deployment_manifest)
    records = dict(admin_records)
    _assert_public_artifact(deployment, "deployment_manifest.json")
    _assert_public_artifact(records, "admin_records.json")

    network = _require_str(deployment, "network")
    admin_launcher = _normalize_hex32(admin_authority_launcher_id, "admin_authority_launcher_id")
    normalized_admins_hash = _normalize_hex32(admins_hash, "admins_hash")
    normalized_mips_root = _normalize_hex32(mips_root, "mips_root")
    records_launcher = _normalize_hex32(records.get("launcher_id"), "admin_records.launcher_id")
    if records_launcher != admin_launcher:
        raise BootstrapManifestError(
            "admin_records.json launcher_id does not match admin-authority launcher id"
        )

    protocol = {
        "pool_launcher_id": _hex_from_manifest(deployment, "pool_launcher_id"),
        "did_launcher_id": _hex_from_manifest(deployment, "did_launcher_id"),
        "tracker_launcher_id": _hex_from_manifest(deployment, "tracker_launcher_id"),
        "pgt_tail_hash": _hex_from_manifest(deployment, "pgt_tail_hash"),
        "pool_token_tail_hash": _hex_from_manifest(deployment, "pool_token_tail_hash"),
        "pool_full_puzhash": _hex_from_manifest(deployment, "pool_full_puzhash"),
        "tracker_full_puzhash": _hex_from_manifest(deployment, "tracker_full_puzhash"),
    }
    deployment_hash = content_hash(deployment)
    records_hash = content_hash(records)

    portal_runtime_config: dict[str, Any] = {
        "version": 1,
        "network": network,
        "protocol": protocol,
        "admin_authority_v2": {
            "launcher_id": admin_launcher,
            "admins_hash": normalized_admins_hash,
            "mips_root": normalized_mips_root,
            "admin_records_hash": records_hash,
        },
    }
    if read_only_api_url is not None:
        portal_runtime_config["read_only_api_url"] = read_only_api_url
    if read_only_coinset_url is not None:
        portal_runtime_config["read_only_coinset_url"] = read_only_coinset_url

    runtime_hash = content_hash(portal_runtime_config)
    bootstrap_manifest = {
        "version": 1,
        "network": network,
        "protocol": protocol,
        "admin_authority_v2": {
            "launcher_id": admin_launcher,
            "admins_hash": normalized_admins_hash,
            "mips_root": normalized_mips_root,
        },
        "artifact_hashes": {
            "deployment_manifest_json": deployment_hash,
            "admin_records_json": records_hash,
            "portal_runtime_config_json": runtime_hash,
        },
    }
    _assert_public_artifact(portal_runtime_config, "portal_runtime_config.json")
    _assert_public_artifact(bootstrap_manifest, "bootstrap_manifest.json")
    return BootstrapArtifacts(
        bootstrap_manifest=bootstrap_manifest,
        portal_runtime_config=portal_runtime_config,
    )


def persist_bootstrap_artifacts(
    *,
    artifacts: BootstrapArtifacts,
    admin_records: Mapping[str, Any],
    paths: BootstrapArtifactPaths,
) -> None:
    admin_records_path = Path(paths.admin_records_json)
    runtime_config_path = Path(paths.portal_runtime_config_json)
    bootstrap_manifest_path = Path(paths.bootstrap_manifest_json)
    if bootstrap_manifest_path.exists():
        raise BootstrapManifestError(
            f"bootstrap manifest already exists at {bootstrap_manifest_path}"
        )

    records = dict(admin_records)
    _assert_public_artifact(records, "admin_records.json")
    _assert_public_artifact(artifacts.portal_runtime_config, "portal_runtime_config.json")
    _assert_public_artifact(artifacts.bootstrap_manifest, "bootstrap_manifest.json")

    _atomic_write_json(admin_records_path, records)
    _atomic_write_json(runtime_config_path, artifacts.portal_runtime_config)
    if bootstrap_manifest_path.exists():
        raise BootstrapManifestError(
            f"bootstrap manifest already exists at {bootstrap_manifest_path}"
        )
    _atomic_write_json(bootstrap_manifest_path, artifacts.bootstrap_manifest)


def _assert_public_artifact(value: Mapping[str, Any], label: str) -> None:
    text = canonical_json_bytes(value).decode("utf-8").lower()
    for marker in FORBIDDEN_ARTIFACT_MARKERS:
        if marker in text:
            raise BootstrapManifestError(
                f"{label} contains forbidden credential marker {marker!r}"
            )


def _require_str(manifest: Mapping[str, Any], key: str) -> str:
    value = manifest.get(key)
    if not isinstance(value, str) or not value:
        raise BootstrapManifestError(f"{key} must be a non-empty string")
    return value


def _hex_from_manifest(manifest: Mapping[str, Any], key: str) -> str:
    return _normalize_hex32(manifest.get(key), key)


def _normalize_hex32(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise BootstrapManifestError(f"{field} must be a 0x-prefixed 32-byte hex string")
    body = value[2:] if value.startswith(("0x", "0X")) else value
    if len(body) != 64:
        raise BootstrapManifestError(f"{field} must be 32 bytes, got {len(body) // 2}")
    try:
        bytes.fromhex(body)
    except ValueError as e:
        raise BootstrapManifestError(f"{field} is not valid hex") from e
    return "0x" + body.lower()


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as fh:
            tmp_path = Path(fh.name)
            fh.write(canonical_json_bytes(value))
            fh.write(b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except Exception:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
        raise


__all__ = [
    "BootstrapArtifacts",
    "BootstrapArtifactPaths",
    "BootstrapManifestError",
    "FORBIDDEN_ARTIFACT_MARKERS",
    "build_bootstrap_artifacts",
    "canonical_json_bytes",
    "content_hash",
    "persist_bootstrap_artifacts",
]
