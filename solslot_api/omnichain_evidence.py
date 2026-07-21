"""Fail-closed binding for the separately deployed CCIP/Warp escrow rail."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .config import Settings


MAX_EVIDENCE_BYTES = 128 * 1024
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class OmnichainEvidenceError(RuntimeError):
    """The external escrow rail is not safely configured for use."""


@dataclass(frozen=True)
class OmnichainEvidence:
    source_sha: str
    chain_id: int
    gateway_profile: str
    gateway_address: str
    spoke_address: str


def _canonical_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _require_address(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    return value.lower()


def _require_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    return value.lower()


def _load_evidence(path_value: str | None, label: str) -> dict[str, Any]:
    if not path_value:
        raise OmnichainEvidenceError(f"Omnichain {label} evidence is not configured")
    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        raise OmnichainEvidenceError(f"Omnichain {label} evidence is unavailable")
    try:
        if path.stat().st_size <= 0 or path.stat().st_size > MAX_EVIDENCE_BYTES:
            raise OmnichainEvidenceError(f"Omnichain {label} evidence size is invalid")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OmnichainEvidenceError(f"Omnichain {label} evidence is invalid") from exc
    if not isinstance(raw, Mapping):
        raise OmnichainEvidenceError(f"Omnichain {label} evidence must be an object")
    evidence = dict(raw)
    declared_hash = _require_hash(evidence.pop("artifactHash", None), f"{label}.artifactHash")
    if declared_hash != _canonical_hash(evidence):
        raise OmnichainEvidenceError(f"Omnichain {label} evidence hash mismatches")
    evidence["artifactHash"] = declared_hash
    return evidence


def load_omnichain_evidence(
    settings: Settings,
    *,
    chain_id: int,
    token_address: str,
    gateway_profile: str,
) -> OmnichainEvidence:
    """Load the reviewed deployment record required for one EVM rail request."""

    if not settings.payment_omnichain_enabled:
        raise OmnichainEvidenceError("Omnichain payments are disabled")
    source_sha = (settings.payment_omnichain_source_sha or "").lower()
    expected_profile = settings.payment_omnichain_gateway_profile
    if not _GIT_SHA_RE.fullmatch(source_sha) or not expected_profile:
        raise OmnichainEvidenceError("Omnichain deployment evidence is not configured")
    evidence = _load_evidence(settings.payment_omnichain_evidence_path, "deployment")
    declared_hash = str(evidence["artifactHash"])
    if evidence.get("schemaVersion") != 1 or evidence.get("rail") != "ccip-warp-escrow":
        raise OmnichainEvidenceError("Omnichain deployment evidence schema is unsupported")
    if evidence.get("protocolVersion") != "solslot-v2":
        raise OmnichainEvidenceError("Omnichain deployment evidence protocol is invalid")
    if evidence.get("sourceSha") != source_sha:
        raise OmnichainEvidenceError("Omnichain deployment evidence source SHA mismatches")
    if evidence.get("chainId") != chain_id:
        raise OmnichainEvidenceError("Omnichain deployment evidence chain mismatches")

    contracts = evidence.get("contracts")
    configuration = evidence.get("configuration")
    code_hashes = evidence.get("runtimeCodeHashes")
    if not isinstance(contracts, Mapping) or not isinstance(configuration, Mapping):
        raise OmnichainEvidenceError("Omnichain deployment evidence contracts are invalid")
    if not isinstance(code_hashes, Mapping):
        raise OmnichainEvidenceError("Omnichain deployment evidence code hashes are invalid")
    expected_token = _require_address(token_address, "configured token")
    if expected_token not in {
        _require_address(contracts.get("usdc"), "USDC"),
        _require_address(contracts.get("usdt"), "USDT"),
    }:
        raise OmnichainEvidenceError("Omnichain deployment evidence token mismatches")
    for name in ("ccipRouter", "gateway", "spoke", "usdc", "usdt"):
        _require_address(contracts.get(name), name)
        _require_hash(code_hashes.get(name), f"runtimeCodeHashes.{name}")
    activation = _load_evidence(
        settings.payment_omnichain_activation_evidence_path, "activation"
    )
    if (
        activation.get("schemaVersion") != 1
        or activation.get("kind") != "ccip-warp-escrow-activation"
        or activation.get("deploymentArtifactHash") != declared_hash
        or activation.get("sourceSha") != source_sha
        or activation.get("network") != evidence.get("network")
        or activation.get("chainId") != chain_id
        or activation.get("gatewayProfile") != expected_profile
        or activation.get("ownershipAccepted") is not True
    ):
        raise OmnichainEvidenceError("Omnichain activation evidence mismatches")
    if gateway_profile != expected_profile:
        raise OmnichainEvidenceError("Omnichain gateway profile is not enabled")
    activation_contracts = activation.get("contracts")
    activation_hashes = activation.get("runtimeCodeHashes")
    if not isinstance(activation_contracts, Mapping) or not isinstance(activation_hashes, Mapping):
        raise OmnichainEvidenceError("Omnichain activation evidence contracts are invalid")
    for name in ("gateway", "spoke"):
        if _require_address(activation_contracts.get(name), f"activation.{name}") != _require_address(
            contracts.get(name), name
        ) or _require_hash(activation_hashes.get(name), f"activation.runtimeCodeHashes.{name}") != _require_hash(
            code_hashes.get(name), f"runtimeCodeHashes.{name}"
        ):
            raise OmnichainEvidenceError("Omnichain activation evidence contract mismatches")
    if _require_address(activation.get("governance"), "activation.governance") != _require_address(
        configuration.get("governance"), "configuration.governance"
    ):
        raise OmnichainEvidenceError("Omnichain activation evidence governance mismatches")
    owners = activation.get("observedOwners")
    if not isinstance(owners, Mapping) or any(
        _require_address(owners.get(name), f"activation.observedOwners.{name}")
        != _require_address(configuration.get("governance"), "configuration.governance")
        for name in ("gateway", "spoke")
    ):
        raise OmnichainEvidenceError("Omnichain governance ownership is not accepted")

    return OmnichainEvidence(
        source_sha=source_sha,
        chain_id=chain_id,
        gateway_profile=gateway_profile,
        gateway_address=_require_address(contracts.get("gateway"), "gateway"),
        spoke_address=_require_address(contracts.get("spoke"), "spoke"),
    )


__all__ = ["OmnichainEvidence", "OmnichainEvidenceError", "load_omnichain_evidence"]
