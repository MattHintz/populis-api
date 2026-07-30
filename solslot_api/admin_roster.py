"""Current Authority V3 administrator identities.

The signed public artifact fixes the three authority slots. Completed,
cross-chain key-change receipts may replace a slot's daily identity without
changing that roster. This module is the only API-side projection from those
two authoritative sources into an authentication allowlist.
"""

from __future__ import annotations

from typing import Any, Mapping

from eth_keys import keys as eth_keys

from .config import Settings
from .evm_auth import normalize_evm_address
from .genesis_store import GenesisNotFound, GenesisStore
from .public_artifact import PublicArtifactError, load_signed_public_artifact


HEX32_LENGTH = 64
COMPRESSED_SECP256K1_LENGTH = 66


def _hex_value(value: str, length: int, label: str) -> str:
    normalized = str(value or "").lower()
    if not normalized.startswith("0x") or len(normalized) != length + 2:
        raise PublicArtifactError(f"{label} must be 0x-prefixed hex")
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise PublicArtifactError(f"{label} must be valid hex") from exc
    if not any(raw):
        raise PublicArtifactError(f"{label} cannot be zero")
    return normalized


def address_from_compressed_pubkey(value: str) -> str:
    normalized = _hex_value(
        value,
        COMPRESSED_SECP256K1_LENGTH,
        "administrator compressed public key",
    )
    try:
        return eth_keys.PublicKey.from_compressed_bytes(
            bytes.fromhex(normalized[2:])
        ).to_checksum_address()
    except (TypeError, ValueError) as exc:
        raise PublicArtifactError(
            "administrator compressed public key is invalid"
        ) from exc


def artifact_ceremony_id(artifact: Mapping[str, Any]) -> str:
    ceremony = artifact.get("ceremony")
    if not isinstance(ceremony, Mapping):
        raise PublicArtifactError("signed artifact ceremony binding is missing")
    return _hex_value(
        str(ceremony.get("ceremonyId") or ""),
        HEX32_LENGTH,
        "ceremonyId",
    )


def artifact_admins(
    artifact: Mapping[str, Any],
) -> list[tuple[str, str]]:
    """Return the canonical ``(EVM address, compressed key)`` for each slot."""

    authority = artifact.get("adminAuthority")
    if not isinstance(authority, Mapping) or authority.get("version") != 3:
        raise PublicArtifactError(
            "signed artifact does not contain Admin Authority V3"
        )
    identities = authority.get("identityVaults")
    if not isinstance(identities, list) or len(identities) != 3:
        raise PublicArtifactError(
            "signed artifact must contain three identity vaults"
        )

    result: list[tuple[str, str]] = []
    for slot, identity in enumerate(identities):
        if not isinstance(identity, Mapping) or identity.get("slot") != slot:
            raise PublicArtifactError(
                "signed identity-vault slots are not canonical"
            )
        compressed = str(identity.get("dailyCompressedPubkey") or "").lower()
        result.append(
            (
                address_from_compressed_pubkey(compressed).lower(),
                compressed,
            )
        )
    return result


def current_artifact_admins(
    artifact: Mapping[str, Any],
    store: GenesisStore,
) -> list[tuple[str, str]]:
    """Apply completed key-change receipts to the immutable three-slot roster."""

    administrators = artifact_admins(artifact)
    ceremony_id = artifact_ceremony_id(artifact)
    try:
        cases = reversed(store.recovery_cases(ceremony_id))
    except GenesisNotFound:
        return administrators

    for case in cases:
        if case["state"] != "COMPLETED" or case["kind"] == "RECOVERY_KIT":
            continue
        intent = case.get("intent")
        if not isinstance(intent, Mapping):
            raise PublicArtifactError(
                "completed administrator rotation is missing its signed intent"
            )
        slot = int(intent.get("slot", -1))
        if slot not in range(3):
            raise PublicArtifactError(
                "completed administrator rotation has an invalid slot"
            )
        new_evm = normalize_evm_address(
            intent.get("newDailyEvmKey"),
            "current administrator wallet",
        )
        new_chia = _hex_value(
            str(intent.get("newDailyChiaKey") or ""),
            COMPRESSED_SECP256K1_LENGTH,
            "current administrator Chia key",
        )
        if address_from_compressed_pubkey(new_chia).lower() != new_evm.lower():
            raise PublicArtifactError(
                "completed administrator rotation does not bind one daily identity"
            )
        administrators[slot] = (new_evm.lower(), new_chia)
    return administrators


def current_signed_admins(
    settings: Settings,
    store: GenesisStore | None = None,
) -> list[tuple[str, str]]:
    artifact = load_signed_public_artifact(settings)
    active_store = store or GenesisStore(settings.genesis_db_path)
    return current_artifact_admins(artifact, active_store)


def current_signed_admin_allowlist(
    settings: Settings,
    store: GenesisStore | None = None,
) -> set[str]:
    return {
        identity
        for administrator in current_signed_admins(settings, store)
        for identity in administrator
    }


__all__ = [
    "address_from_compressed_pubkey",
    "artifact_admins",
    "artifact_ceremony_id",
    "current_artifact_admins",
    "current_signed_admin_allowlist",
    "current_signed_admins",
]
