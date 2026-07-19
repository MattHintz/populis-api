"""Load and verify the canonical signed Solslot V2 public artifact."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from eth_keys import keys as eth_keys

from solslot_puzzles.artifact_schema_v2 import (
    artifact_signing_typed_data,
    verify_public_artifact,
)

from .config import Settings
from .evm_auth import recover_evm_signer
from .release_metadata import load_release_metadata


class PublicArtifactError(ValueError):
    """The configured public artifact cannot be trusted."""


class PublicArtifactMissing(PublicArtifactError):
    """No finalized V2 ceremony artifact exists yet."""


def _verify_admin_signature(
    payload: Mapping[str, Any],
    _index: int,
    pubkey: bytes,
    signature: bytes,
) -> bool:
    try:
        recovered = recover_evm_signer(
            artifact_signing_typed_data(payload),
            "0x" + signature.hex(),
        )
    except (TypeError, ValueError):
        return False
    return recovered.compressed_pubkey == pubkey


def _same_hex(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and left.lower() == right.lower()


def _require_configured_evm_binding(
    configured: str | None,
    signed: object,
    label: str,
) -> None:
    if configured is None:
        raise PublicArtifactError(
            f"configured {label} is required to verify signed artifact"
        )
    if not _same_hex(configured, signed):
        raise PublicArtifactError(f"configured {label} does not match signed artifact")


def _verify_runtime_bindings(settings: Settings, payload: Mapping[str, Any]) -> None:
    if payload.get("network") != settings.network:
        raise PublicArtifactError("public artifact network does not match this API")
    if payload.get("evmChainId") != settings.zkpassport_evm_chain_id:
        raise PublicArtifactError("public artifact EVM chain does not match this API")

    launchers = payload.get("launcherIds")
    bridge = payload.get("bridgePolicy")
    addresses = payload.get("evmAddresses")
    validators = payload.get("validatorSet")
    if not all(isinstance(value, Mapping) for value in (launchers, bridge, addresses, validators)):
        raise PublicArtifactError("public artifact runtime bindings are incomplete")

    configured_bindings = (
        (settings.pool_launcher_id, launchers.get("pool"), "pool launcher"),
        (
            settings.governance_launcher_id,
            launchers.get("governance"),
            "governance launcher",
        ),
        (
            settings.protocol_config_launcher_id,
            launchers.get("protocolConfig"),
            "protocol-config launcher",
        ),
        (
            settings.vault_version_registry_launcher_id,
            launchers.get("vaultVersionRegistry"),
            "vault-version registry launcher",
        ),
        (
            settings.zkpassport_bridge_policy_hash,
            bridge.get("policyHash"),
            "bridge policy",
        ),
    )
    for configured, signed, label in configured_bindings:
        if configured is not None and not _same_hex(configured, signed):
            raise PublicArtifactError(f"configured {label} does not match signed artifact")
    evm_bindings = (
        (
            settings.zkpassport_forwarder_address,
            addresses.get("forwarder"),
            "forwarder address",
        ),
        (
            settings.zkpassport_verifier_adapter_address,
            addresses.get("verifierAdapter"),
            "verifier adapter address",
        ),
        (
            settings.zkpassport_emitter_address,
            addresses.get("attestationEmitter"),
            "attestation emitter address",
        ),
    )
    for configured, signed, label in evm_bindings:
        _require_configured_evm_binding(configured, signed, label)

    if validators.get("threshold") != settings.zkpassport_validator_threshold:
        raise PublicArtifactError("validator threshold does not match signed artifact")
    configured_keys = [value.lower() for value in settings.zkpassport_validator_pubkeys]
    signed_keys = [str(value).lower() for value in validators.get("pubkeys", [])]
    if configured_keys and configured_keys != signed_keys:
        raise PublicArtifactError("validator roster does not match signed artifact")
    if bridge.get("policyVersion") != settings.zkpassport_policy_version:
        raise PublicArtifactError("credential policy version does not match signed artifact")

    release = load_release_metadata(settings.release_metadata_path)
    if release is None:
        if settings.runtime_environment in {"staging", "production"}:
            raise PublicArtifactError("release metadata is required beside a signed artifact")
        return
    source_shas = payload.get("sourceShas")
    if not isinstance(source_shas, Mapping):
        raise PublicArtifactError("public artifact source commits are missing")
    if source_shas.get("api") != release.apiCommit:
        raise PublicArtifactError("API release commit does not match signed artifact")
    if source_shas.get("protocol") != release.protocolCommit:
        raise PublicArtifactError("protocol release commit does not match signed artifact")


def verify_signed_public_artifact_file(path_value: str | Path) -> dict[str, Any]:
    """Read and cryptographically verify a V2 public artifact.

    Runtime services which do not share the coordinator's mutable settings
    (notably the isolated validator signers) use this narrower entry point.
    It verifies the complete artifact schema and administrator signature
    quorum, but deliberately leaves host-specific runtime binding to the
    caller.
    """
    path = Path(path_value)
    if not path.is_file():
        raise PublicArtifactMissing("signed V2 public artifact is unavailable")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicArtifactError("signed V2 public artifact is unreadable") from exc
    if not isinstance(payload, dict):
        raise PublicArtifactError("signed V2 public artifact must be an object")
    try:
        verify_public_artifact(payload, signature_verifier=_verify_admin_signature)
    except (TypeError, ValueError) as exc:
        raise PublicArtifactError(f"signed V2 public artifact is invalid: {exc}") from exc
    return payload


def load_signed_public_artifact(settings: Settings) -> dict[str, Any]:
    """Read, cryptographically verify, and runtime-bind the V2 artifact."""
    payload = verify_signed_public_artifact_file(settings.public_artifact_path)
    _verify_runtime_bindings(settings, payload)
    return payload


def signed_admin_allowlist(settings: Settings) -> set[str]:
    """Return the EVM identities committed by the signed 2-of-3 artifact.

    Both compressed keys and derived addresses are returned so signature
    recovery and JWT revocation checks can compare canonical values without a
    second, operator-maintained roster file.  ``load_signed_public_artifact``
    performs the signature quorum and runtime binding checks first.
    """
    artifact = load_signed_public_artifact(settings)
    admin = artifact["adminAuthority"]
    identities: set[str] = set()
    for value in admin["compressedPubkeys"]:
        normalized = str(value).lower()
        raw = bytes.fromhex(normalized.removeprefix("0x"))
        try:
            public_key = eth_keys.PublicKey.from_compressed_bytes(raw)
        except (TypeError, ValueError) as exc:
            raise PublicArtifactError(
                "signed V2 artifact contains an invalid administrator key"
            ) from exc
        identities.add(normalized)
        identities.add(public_key.to_checksum_address().lower())
    return identities


__all__ = [
    "PublicArtifactError",
    "PublicArtifactMissing",
    "load_signed_public_artifact",
    "signed_admin_allowlist",
    "verify_signed_public_artifact_file",
]
