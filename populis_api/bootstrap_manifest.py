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
    "private_url",
    "service_credential",
    "service_credentials",
    "mutable_service_credentials",
    "faucet_mnemonic",
    "faucet_seed",
    "faucet_master_sk",
)
BOOTSTRAP_RECOVERY_ANCHOR_TAG = "POPULIS_BOOTSTRAP_V1"
BOOTSTRAP_RECOVERY_ANCHOR_MARKER_MIN_MOJOS = 1


class BootstrapManifestError(ValueError):
    pass


@dataclass(frozen=True)
class BootstrapArtifacts:
    bootstrap_manifest: dict[str, Any]
    portal_runtime_config: dict[str, Any]
    bootstrap_recovery_anchor: dict[str, Any]


@dataclass(frozen=True)
class BootstrapArtifactPaths:
    admin_records_json: Path
    portal_runtime_config_json: Path
    bootstrap_recovery_anchor_json: Path
    bootstrap_manifest_json: Path


@dataclass(frozen=True)
class BootstrapRecoveryAnchor:
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_hash: str


@dataclass(frozen=True)
class BootstrapRecoveryAnchorCarrierMemos:
    tag_memo: bytes
    payload_memo: bytes
    memos: tuple[bytes, bytes]
    payload_hash: str


@dataclass(frozen=True)
class BootstrapRecoveryAnchorPublishIntent:
    network: str
    marker_coin_amount_mojos: int
    admin_authority_v2_launcher_id: str
    authority_version: int
    bootstrap_manifest_hash: str
    portal_runtime_config_hash: str
    admin_records_hash: str
    tag_memo: bytes
    payload_memo: bytes
    memos: tuple[bytes, bytes]
    payload_hash: str


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
    authority_version: int = 1,
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
    normalized_authority_version = _validate_authority_version(authority_version)
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
            "authority_version": normalized_authority_version,
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
            "authority_version": normalized_authority_version,
        },
        "artifact_hashes": {
            "deployment_manifest_json": deployment_hash,
            "admin_records_json": records_hash,
            "portal_runtime_config_json": runtime_hash,
        },
    }
    recovery_anchor = build_bootstrap_recovery_anchor(
        bootstrap_manifest=bootstrap_manifest,
        portal_runtime_config=portal_runtime_config,
    )
    _assert_public_artifact(portal_runtime_config, "portal_runtime_config.json")
    _assert_public_artifact(bootstrap_manifest, "bootstrap_manifest.json")
    _assert_public_artifact(recovery_anchor.payload, "bootstrap_recovery_anchor.json")
    return BootstrapArtifacts(
        bootstrap_manifest=bootstrap_manifest,
        portal_runtime_config=portal_runtime_config,
        bootstrap_recovery_anchor=recovery_anchor.payload,
    )


def build_bootstrap_recovery_anchor(
    *,
    bootstrap_manifest: Mapping[str, Any],
    portal_runtime_config: Mapping[str, Any],
    version: int = 1,
) -> BootstrapRecoveryAnchor:
    normalized_version = _validate_recovery_anchor_version(version)
    manifest = dict(bootstrap_manifest)
    runtime = dict(portal_runtime_config)
    _assert_public_artifact(manifest, "bootstrap_manifest.json")
    _assert_public_artifact(runtime, "portal_runtime_config.json")

    network = _require_str(manifest, "network")
    runtime_network = _require_str(runtime, "network")
    if runtime_network != network:
        raise BootstrapManifestError(
            "portal_runtime_config network does not match bootstrap manifest"
        )

    manifest_authority = _require_mapping(
        manifest.get("admin_authority_v2"),
        "bootstrap_manifest.admin_authority_v2",
    )
    runtime_authority = _require_mapping(
        runtime.get("admin_authority_v2"),
        "portal_runtime_config.admin_authority_v2",
    )
    artifact_hashes = _require_mapping(
        manifest.get("artifact_hashes"),
        "bootstrap_manifest.artifact_hashes",
    )

    admin_launcher = _normalize_hex32(
        manifest_authority.get("launcher_id"),
        "bootstrap_manifest.admin_authority_v2.launcher_id",
    )
    runtime_admin_launcher = _normalize_hex32(
        runtime_authority.get("launcher_id"),
        "portal_runtime_config.admin_authority_v2.launcher_id",
    )
    if runtime_admin_launcher != admin_launcher:
        raise BootstrapManifestError(
            "portal_runtime_config admin authority launcher does not match bootstrap manifest"
        )

    for field in ("admins_hash", "mips_root"):
        manifest_value = _normalize_hex32(
            manifest_authority.get(field),
            f"bootstrap_manifest.admin_authority_v2.{field}",
        )
        runtime_value = _normalize_hex32(
            runtime_authority.get(field),
            f"portal_runtime_config.admin_authority_v2.{field}",
        )
        if runtime_value != manifest_value:
            raise BootstrapManifestError(
                f"portal_runtime_config admin authority {field} does not match bootstrap manifest"
            )

    authority_version = _validate_authority_version(
        manifest_authority.get("authority_version")
    )
    runtime_authority_version = _validate_authority_version(
        runtime_authority.get("authority_version")
    )
    if runtime_authority_version != authority_version:
        raise BootstrapManifestError(
            "portal_runtime_config authority_version does not match bootstrap manifest"
        )

    admin_records_hash = _require_content_hash(
        runtime_authority.get("admin_records_hash"),
        "portal_runtime_config.admin_authority_v2.admin_records_hash",
    )
    manifest_admin_records_hash = _require_content_hash(
        artifact_hashes.get("admin_records_json"),
        "bootstrap_manifest.artifact_hashes.admin_records_json",
    )
    if manifest_admin_records_hash != admin_records_hash:
        raise BootstrapManifestError(
            "bootstrap manifest admin_records_json hash does not match portal_runtime_config"
        )

    runtime_hash = content_hash(runtime)
    manifest_runtime_hash = _require_content_hash(
        artifact_hashes.get("portal_runtime_config_json"),
        "bootstrap_manifest.artifact_hashes.portal_runtime_config_json",
    )
    if manifest_runtime_hash != runtime_hash:
        raise BootstrapManifestError(
            "bootstrap manifest portal_runtime_config_json hash does not match portal_runtime_config"
        )

    payload = {
        "version": normalized_version,
        "tag": BOOTSTRAP_RECOVERY_ANCHOR_TAG,
        "network": network,
        "admin_authority_v2_launcher_id": admin_launcher,
        "authority_version": authority_version,
        "bootstrap_manifest_hash": content_hash(manifest),
        "portal_runtime_config_hash": runtime_hash,
        "admin_records_hash": admin_records_hash,
    }
    _assert_public_artifact(payload, "bootstrap_recovery_anchor")
    payload_bytes = canonical_json_bytes(payload)
    return BootstrapRecoveryAnchor(
        payload=payload,
        payload_bytes=payload_bytes,
        payload_hash=content_hash(payload),
    )


def build_bootstrap_recovery_anchor_memos(
    *,
    bootstrap_recovery_anchor: Mapping[str, Any],
) -> BootstrapRecoveryAnchorCarrierMemos:
    payload = _validate_bootstrap_recovery_anchor_payload(bootstrap_recovery_anchor)
    tag_memo = BOOTSTRAP_RECOVERY_ANCHOR_TAG.encode("utf-8")
    payload_memo = canonical_json_bytes(payload)
    return BootstrapRecoveryAnchorCarrierMemos(
        tag_memo=tag_memo,
        payload_memo=payload_memo,
        memos=(tag_memo, payload_memo),
        payload_hash=content_hash(payload),
    )


def build_bootstrap_recovery_anchor_publish_intent(
    *,
    bootstrap_recovery_anchor: Mapping[str, Any],
    marker_coin_amount_mojos: int = BOOTSTRAP_RECOVERY_ANCHOR_MARKER_MIN_MOJOS,
) -> BootstrapRecoveryAnchorPublishIntent:
    amount = _validate_marker_coin_amount_mojos(marker_coin_amount_mojos)
    payload = _validate_bootstrap_recovery_anchor_payload(bootstrap_recovery_anchor)
    carrier = build_bootstrap_recovery_anchor_memos(bootstrap_recovery_anchor=payload)
    return BootstrapRecoveryAnchorPublishIntent(
        network=_require_str(payload, "network"),
        marker_coin_amount_mojos=amount,
        admin_authority_v2_launcher_id=payload["admin_authority_v2_launcher_id"],
        authority_version=payload["authority_version"],
        bootstrap_manifest_hash=payload["bootstrap_manifest_hash"],
        portal_runtime_config_hash=payload["portal_runtime_config_hash"],
        admin_records_hash=payload["admin_records_hash"],
        tag_memo=carrier.tag_memo,
        payload_memo=carrier.payload_memo,
        memos=carrier.memos,
        payload_hash=carrier.payload_hash,
    )


def persist_bootstrap_artifacts(
    *,
    artifacts: BootstrapArtifacts,
    admin_records: Mapping[str, Any],
    paths: BootstrapArtifactPaths,
) -> None:
    admin_records_path = Path(paths.admin_records_json)
    runtime_config_path = Path(paths.portal_runtime_config_json)
    recovery_anchor_path = Path(paths.bootstrap_recovery_anchor_json)
    bootstrap_manifest_path = Path(paths.bootstrap_manifest_json)
    if bootstrap_manifest_path.exists():
        raise BootstrapManifestError(
            f"bootstrap manifest already exists at {bootstrap_manifest_path}"
        )

    records = dict(admin_records)
    _assert_public_artifact(records, "admin_records.json")
    _assert_public_artifact(artifacts.portal_runtime_config, "portal_runtime_config.json")
    _assert_public_artifact(artifacts.bootstrap_recovery_anchor, "bootstrap_recovery_anchor.json")
    _assert_public_artifact(artifacts.bootstrap_manifest, "bootstrap_manifest.json")

    _atomic_write_json(admin_records_path, records)
    _atomic_write_json(runtime_config_path, artifacts.portal_runtime_config)
    if bootstrap_manifest_path.exists():
        raise BootstrapManifestError(
            f"bootstrap manifest already exists at {bootstrap_manifest_path}"
        )
    _atomic_write_json(recovery_anchor_path, artifacts.bootstrap_recovery_anchor)
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


def _require_mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BootstrapManifestError(f"{field} must be an object")
    return value


def _validate_bootstrap_recovery_anchor_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    _assert_public_artifact(payload, "bootstrap_recovery_anchor.json")
    _validate_recovery_anchor_version(payload.get("version"))
    tag = _require_str(payload, "tag")
    if tag != BOOTSTRAP_RECOVERY_ANCHOR_TAG:
        raise BootstrapManifestError(
            f"bootstrap_recovery_anchor tag must be {BOOTSTRAP_RECOVERY_ANCHOR_TAG}"
        )
    _require_str(payload, "network")
    normalized_launcher = _normalize_hex32(
        payload.get("admin_authority_v2_launcher_id"),
        "admin_authority_v2_launcher_id",
    )
    if payload.get("admin_authority_v2_launcher_id") != normalized_launcher:
        raise BootstrapManifestError(
            "admin_authority_v2_launcher_id must be a canonical 0x-prefixed 32-byte hex string"
        )
    _validate_authority_version(payload.get("authority_version"))
    for field in (
        "bootstrap_manifest_hash",
        "portal_runtime_config_hash",
        "admin_records_hash",
    ):
        normalized_hash = _require_content_hash(payload.get(field), field)
        if payload.get(field) != normalized_hash:
            raise BootstrapManifestError(f"{field} must be a canonical sha256 content hash")
    return payload


def _validate_marker_coin_amount_mojos(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BootstrapManifestError("marker coin amount must be an integer number of mojos")
    if value < BOOTSTRAP_RECOVERY_ANCHOR_MARKER_MIN_MOJOS:
        raise BootstrapManifestError(
            f"marker coin amount must be at least {BOOTSTRAP_RECOVERY_ANCHOR_MARKER_MIN_MOJOS} mojo"
        )
    return value


def _require_content_hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BootstrapManifestError(f"{field} must be a sha256 content hash")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64:
        raise BootstrapManifestError(f"{field} must be a sha256 content hash")
    try:
        bytes.fromhex(digest)
    except ValueError as e:
        raise BootstrapManifestError(f"{field} must be a sha256 content hash") from e
    return "sha256:" + digest.lower()


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


def _validate_authority_version(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BootstrapManifestError("authority_version must be a positive integer")
    if value < 1:
        raise BootstrapManifestError("authority_version must be >= 1")
    return value


def _validate_recovery_anchor_version(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BootstrapManifestError("recovery anchor version must be a positive integer")
    if value < 1:
        raise BootstrapManifestError("recovery anchor version must be >= 1")
    return value


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
    "BOOTSTRAP_RECOVERY_ANCHOR_MARKER_MIN_MOJOS",
    "BOOTSTRAP_RECOVERY_ANCHOR_TAG",
    "BootstrapArtifacts",
    "BootstrapArtifactPaths",
    "BootstrapManifestError",
    "BootstrapRecoveryAnchor",
    "BootstrapRecoveryAnchorCarrierMemos",
    "BootstrapRecoveryAnchorPublishIntent",
    "FORBIDDEN_ARTIFACT_MARKERS",
    "build_bootstrap_artifacts",
    "build_bootstrap_recovery_anchor",
    "build_bootstrap_recovery_anchor_memos",
    "build_bootstrap_recovery_anchor_publish_intent",
    "canonical_json_bytes",
    "content_hash",
    "persist_bootstrap_artifacts",
]
