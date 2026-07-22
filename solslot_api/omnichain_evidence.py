"""Fail-closed binding for the separately deployed CCIP/Warp escrow rail."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from eth_utils import keccak

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
    governance_root_safe: str
    governance_timelock: str


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


def _require_selector(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.isdigit() or int(value) <= 0:
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    return value


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    return value


def _require_transaction(value: object, label: str) -> None:
    transaction = _require_mapping(value, label)
    _require_hash(transaction.get("hash"), f"{label}.hash")
    block_number = transaction.get("blockNumber")
    if not isinstance(block_number, int) or isinstance(block_number, bool) or block_number <= 0:
        raise OmnichainEvidenceError(f"Omnichain evidence {label}.blockNumber is invalid")


def _preflight_runtime_hash(
    hashes: Mapping[str, Any], address: str, label: str
) -> str:
    normalized = _require_address(address, label)
    for candidate, code_hash in hashes.items():
        if _require_address(candidate, f"preflight.runtimeCodeHashes.{label}") == normalized:
            return _require_hash(code_hash, f"preflight.runtimeCodeHashes.{label}")
    raise OmnichainEvidenceError(
        f"Omnichain preflight evidence is missing {label} runtime code"
    )


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
    if evidence.get("schemaVersion") != 3 or evidence.get("rail") != "ccip-warp-escrow":
        raise OmnichainEvidenceError("Omnichain deployment evidence schema is unsupported")
    if evidence.get("protocolVersion") != "solslot-v2":
        raise OmnichainEvidenceError("Omnichain deployment evidence protocol is invalid")
    if evidence.get("sourceSha") != source_sha:
        raise OmnichainEvidenceError("Omnichain deployment evidence source SHA mismatches")
    if evidence.get("chainId") != chain_id:
        raise OmnichainEvidenceError("Omnichain deployment evidence chain mismatches")
    governance_artifact_hash = _require_hash(
        evidence.get("governanceArtifactHash"), "governanceArtifactHash"
    )
    samuel_artifact_hash = _require_hash(
        evidence.get("samuelCoordinateArtifactHash"),
        "samuelCoordinateArtifactHash",
    )

    contracts = evidence.get("contracts")
    configuration = evidence.get("configuration")
    code_hashes = evidence.get("runtimeCodeHashes")
    if not isinstance(contracts, Mapping) or not isinstance(configuration, Mapping):
        raise OmnichainEvidenceError("Omnichain deployment evidence contracts are invalid")
    if not isinstance(code_hashes, Mapping):
        raise OmnichainEvidenceError("Omnichain deployment evidence code hashes are invalid")
    expected_token = _require_address(token_address, "configured token")
    if expected_token != _require_address(contracts.get("usdc"), "USDC"):
        raise OmnichainEvidenceError("Omnichain deployment evidence token mismatches")
    for name in ("ccipRouter", "gateway", "spoke", "usdc"):
        _require_address(contracts.get(name), name)
        _require_hash(code_hashes.get(name), f"runtimeCodeHashes.{name}")
    governance_root_safe = _require_address(
        configuration.get("governanceRootSafe"), "configuration.governanceRootSafe"
    )
    governance_timelock = _require_address(
        configuration.get("governanceTimelock"),
        "configuration.governanceTimelock",
    )
    payout = _require_address(
        configuration.get("payoutAddress"), "configuration.payoutAddress"
    )
    if payout != governance_root_safe or governance_root_safe == governance_timelock:
        raise OmnichainEvidenceError("Omnichain governance configuration is invalid")
    for name in ("governanceRootSafe", "governanceTimelock"):
        _require_hash(code_hashes.get(name), f"runtimeCodeHashes.{name}")
    deployment_transactions = _require_mapping(
        evidence.get("deploymentTransactions"), "deploymentTransactions"
    )
    for name in (
        "gateway",
        "spoke",
        "gatewayOwnershipTransfer",
        "spokeOwnershipTransfer",
        "trustedSpokeUpdate",
    ):
        _require_transaction(
            deployment_transactions.get(name), f"deploymentTransactions.{name}"
        )

    governance = _load_evidence(
        settings.payment_omnichain_governance_evidence_path, "governance"
    )
    governance_safes = _require_mapping(governance.get("safes"), "governance.safes")
    owner_safe_record = _require_mapping(
        governance_safes.get("ownerIdentity"), "governance.safes.ownerIdentity"
    )
    coadmin_safe_record = _require_mapping(
        governance_safes.get("coadmin"), "governance.safes.coadmin"
    )
    root_safe_record = _require_mapping(
        governance_safes.get("root"), "governance.safes.root"
    )
    governance_timelock_record = _require_mapping(
        governance.get("timelock"), "governance.timelock"
    )
    governance_hashes = _require_mapping(
        governance.get("runtimeCodeHashes"), "governance.runtimeCodeHashes"
    )
    owner_safe_owners = owner_safe_record.get("owners")
    coadmin_safe_owners = coadmin_safe_record.get("owners")
    root_safe_owners = root_safe_record.get("owners")
    if not all(
        isinstance(owners, list)
        for owners in (owner_safe_owners, coadmin_safe_owners, root_safe_owners)
    ):
        raise OmnichainEvidenceError("Omnichain governance Safe owners are invalid")
    owner_safe = _require_address(
        owner_safe_record.get("address"), "governance.safes.ownerIdentity.address"
    )
    coadmin_safe = _require_address(
        coadmin_safe_record.get("address"), "governance.safes.coadmin.address"
    )
    root_safe = _require_address(
        root_safe_record.get("address"), "governance.safes.root.address"
    )
    owner_guard = _require_address(
        owner_safe_record.get("guard"), "governance.safes.ownerIdentity.guard"
    )
    coadmin_guard = _require_address(
        coadmin_safe_record.get("guard"), "governance.safes.coadmin.guard"
    )
    root_guard = _require_address(
        root_safe_record.get("guard"), "governance.safes.root.guard"
    )
    owner_address = _require_address(
        owner_safe_owners[0] if len(owner_safe_owners) == 1 else None,
        "governance.safes.ownerIdentity.owner",
    )
    coadmin_addresses = [
        _require_address(owner, "governance.safes.coadmin.owner")
        for owner in coadmin_safe_owners
    ]
    root_addresses = [
        _require_address(owner, "governance.safes.root.owner")
        for owner in root_safe_owners
    ]
    recovery = _require_mapping(governance.get("recovery"), "governance.recovery")
    infrastructure = _require_mapping(
        governance.get("safeInfrastructure"), "governance.safeInfrastructure"
    )
    secp_guardian = _require_address(
        recovery.get("secp256k1Guardian"), "governance.recovery.secp256k1Guardian"
    )
    bls_pubkey = recovery.get("blsGuardianPubkey")
    if (
        not isinstance(bls_pubkey, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]{96}", bls_pubkey)
        or int(bls_pubkey, 16) == 0
    ):
        raise OmnichainEvidenceError("Omnichain governance BLS recovery key is invalid")
    bls_commitment = _require_hash(
        recovery.get("blsGuardianCommitment"),
        "governance.recovery.blsGuardianCommitment",
    )
    observed_bls_commitment = "0x" + keccak(bytes.fromhex(bls_pubkey[2:])).hex()
    administrator_records = governance.get("administrators")
    if not isinstance(administrator_records, list) or len(administrator_records) != 3:
        raise OmnichainEvidenceError("Omnichain governance administrators are invalid")
    administrator_slots = [record.get("slot") for record in administrator_records if isinstance(record, Mapping)]
    administrator_addresses = [
        _require_address(record.get("address"), "governance.administrator.address")
        for record in administrator_records
        if isinstance(record, Mapping)
    ]
    recovery_coadmins = recovery.get("coadmins")
    if not isinstance(recovery_coadmins, list):
        raise OmnichainEvidenceError("Omnichain governance recovery coadmins are invalid")
    normalized_recovery_coadmins = [
        _require_address(owner, "governance.recovery.coadmin")
        for owner in recovery_coadmins
    ]
    governance_contract_addresses = {
        "ownerIdentitySafe": owner_safe,
        "coadminSafe": coadmin_safe,
        "rootSafe": root_safe,
        "timelock": governance_timelock,
        "recovery": _require_address(
            recovery.get("address"), "governance.recovery.address"
        ),
        "ownerGuard": owner_guard,
        "coadminGuard": coadmin_guard,
        "rootGuard": root_guard,
        "ownerSetup": _require_address(
            infrastructure.get("ownerSetup"),
            "governance.safeInfrastructure.ownerSetup",
        ),
        "compatibilityFallbackHandler": _require_address(
            infrastructure.get("compatibilityFallbackHandler"),
            "governance.safeInfrastructure.compatibilityFallbackHandler",
        ),
        "signMessageLibrary": _require_address(
            infrastructure.get("signMessageLibrary"),
            "governance.safeInfrastructure.signMessageLibrary",
        ),
    }
    if secp_guardian in governance_contract_addresses.values():
        raise OmnichainEvidenceError(
            "Omnichain governance recovery guardian is not separate"
        )
    for name in governance_contract_addresses:
        _require_hash(
            governance_hashes.get(name),
            f"governance.runtimeCodeHashes.{name}",
        )
    if (
        governance.get("schemaVersion") != 2
        or governance.get("kind") != "solslot-alpha-owner-required-governance-deployment"
        or governance.get("authorityRule") != "slot0_and_one_of_slot1_slot2"
        or governance.get("sourceSha") != source_sha
        or governance.get("network") != "baseSepolia"
        or governance.get("chainId") != 84532
        or governance.get("artifactHash") != governance_artifact_hash
        or owner_safe_record.get("threshold") != 1
        or coadmin_safe_record.get("threshold") != 1
        or root_safe_record.get("threshold") != 2
        or len(coadmin_addresses) != 2
        or len(set((owner_address, *coadmin_addresses, secp_guardian))) != 4
        or administrator_slots != [1, 2, 3]
        or administrator_addresses != [owner_address, *coadmin_addresses]
        or len(root_addresses) != 2
        or set(root_addresses) != {owner_safe, coadmin_safe}
        or root_safe != governance_root_safe
        or len({owner_guard, coadmin_guard, root_guard}) != 3
        or _require_address(recovery.get("ownerGuard"), "governance.recovery.ownerGuard")
        != owner_guard
        or normalized_recovery_coadmins != coadmin_addresses
        or recovery.get("delaySeconds") != "604800"
        or recovery.get("replacementAcceptanceRequired") is not True
        or observed_bls_commitment != bls_commitment
        or infrastructure.get("safeVersion") != "1.4.1"
        or _require_address(governance.get("payoutAddress"), "governance.payoutAddress")
        != governance_root_safe
        or _require_address(governance_timelock_record.get("address"), "governance.timelock.address")
        != governance_timelock
        or governance_timelock_record.get("minimumDelaySeconds") != "86400"
        or _require_address(governance_timelock_record.get("proposer"), "governance.timelock.proposer")
        != governance_root_safe
        or _require_address(governance_timelock_record.get("executor"), "governance.timelock.executor")
        != governance_root_safe
        or _require_address(governance_timelock_record.get("canceller"), "governance.timelock.canceller")
        != governance_root_safe
        or governance_timelock_record.get("externalAdmin")
        != "0x0000000000000000000000000000000000000000"
        or _require_hash(governance_hashes.get("rootSafe"), "governance.runtimeCodeHashes.rootSafe")
        != _require_hash(code_hashes.get("governanceRootSafe"), "runtimeCodeHashes.governanceRootSafe")
        or _require_hash(governance_hashes.get("timelock"), "governance.runtimeCodeHashes.timelock")
        != _require_hash(code_hashes.get("governanceTimelock"), "runtimeCodeHashes.governanceTimelock")
    ):
        raise OmnichainEvidenceError("Omnichain governance evidence mismatches")

    samuel = _load_evidence(
        settings.payment_omnichain_samuel_evidence_path, "samuel"
    )
    samuel_testnet = _require_mapping(samuel.get("testnet11"), "samuel.testnet11")
    samuel_base = _require_mapping(samuel.get("baseSepolia"), "samuel.baseSepolia")
    validator_keys = samuel.get("validatorPublicKeys")
    if (
        samuel.get("schemaVersion") != 1
        or samuel.get("kind") != "solslot-samuel-testnet-coordinates"
        or samuel.get("artifactHash") != samuel_artifact_hash
        or not _GIT_SHA_RE.fullmatch(str(samuel.get("sourceSha", "")))
        or samuel.get("threshold") != 2
        or not isinstance(validator_keys, list)
        or len(validator_keys) != 3
        or len({str(key).lower() for key in validator_keys}) != 3
        or any(not re.fullmatch(r"0x[0-9a-fA-F]{96}", str(key)) for key in validator_keys)
        or samuel_base.get("chainId") != 84532
    ):
        raise OmnichainEvidenceError("Omnichain Samuel evidence mismatches")
    for name in ("portalLauncherId", "bridgingPuzzleHash", "returnPuzzleHash"):
        _require_hash(samuel_testnet.get(name), f"samuel.testnet11.{name}")
    samuel_portal = _require_address(
        samuel_base.get("warpPortalAddress"), "samuel.baseSepolia.warpPortalAddress"
    )
    preflight = _load_evidence(
        settings.payment_omnichain_preflight_evidence_path, "preflight"
    )
    if (
        preflight.get("schemaVersion") != 3
        or preflight.get("kind")
        != "solslot-omnichain-testnet-deployment-preflight"
        or preflight.get("sourceSha") != source_sha
        or preflight.get("network") != evidence.get("network")
        or preflight.get("chainId") != chain_id
        or _require_selector(preflight.get("chainSelector"), "preflight.chainSelector")
        != _require_selector(evidence.get("chainSelector"), "chainSelector")
        or evidence.get("preflightArtifactHash") != preflight.get("artifactHash")
        or preflight.get("governanceArtifactHash") != governance_artifact_hash
        or preflight.get("samuelCoordinateArtifactHash") != samuel_artifact_hash
    ):
        raise OmnichainEvidenceError("Omnichain preflight evidence mismatches")
    preflight_settings = _require_mapping(
        preflight.get("settings"), "preflight.settings"
    )
    preflight_inspection = _require_mapping(
        preflight.get("inspection"), "preflight.inspection"
    )
    preflight_decimals = _require_mapping(
        preflight_inspection.get("tokenDecimals"), "preflight.tokenDecimals"
    )
    preflight_hashes = _require_mapping(
        preflight_inspection.get("runtimeCodeHashes"),
        "preflight.runtimeCodeHashes",
    )
    expected_preflight_addresses = {
        "ccipRouter": contracts.get("ccipRouter"),
        "payout": payout,
        "governance": governance_timelock,
        "rootSafe": governance_root_safe,
        "usdc": contracts.get("usdc"),
    }
    for name, address in expected_preflight_addresses.items():
        if _require_address(preflight_settings.get(name), f"preflight.{name}") != _require_address(
            address, name
        ):
            raise OmnichainEvidenceError(
                "Omnichain preflight evidence contracts mismatch"
            )
    if (
        preflight_settings.get("callbackGas") != configuration.get("callbackGas")
        or preflight_settings.get("emergencyDelay")
        != configuration.get("emergencyDelay")
        or preflight_settings.get("confirmations") != evidence.get("confirmations")
        or preflight_decimals.get("usdc") != 6
        or _require_address(preflight_settings.get("warpPortal"), "preflight.warpPortal")
        != samuel_portal
    ):
        raise OmnichainEvidenceError("Omnichain preflight evidence settings mismatch")
    for name in ("ccipRouter", "usdc"):
        if _preflight_runtime_hash(
            preflight_hashes, str(contracts.get(name)), name
        ) != _require_hash(code_hashes.get(name), f"runtimeCodeHashes.{name}"):
            raise OmnichainEvidenceError(
                "Omnichain preflight evidence runtime code mismatches"
            )
    for name, address in (
        ("governanceRootSafe", governance_root_safe),
        ("governanceTimelock", governance_timelock),
    ):
        if _preflight_runtime_hash(preflight_hashes, address, name) != _require_hash(
            code_hashes.get(name), f"runtimeCodeHashes.{name}"
        ):
            raise OmnichainEvidenceError(
                "Omnichain preflight evidence runtime code mismatches"
            )
    activation = _load_evidence(
        settings.payment_omnichain_activation_evidence_path, "activation"
    )
    if (
        activation.get("schemaVersion") != 3
        or activation.get("kind") != "ccip-warp-escrow-activation"
        or activation.get("deploymentArtifactHash") != declared_hash
        or activation.get("sourceSha") != source_sha
        or activation.get("network") != evidence.get("network")
        or activation.get("chainId") != chain_id
        or activation.get("gatewayProfile") != expected_profile
        or not _HASH_RE.fullmatch(
            str(activation.get("ownershipOperationArtifactHash", ""))
        )
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
    if _require_address(
        activation.get("governance"), "activation.governance"
    ) != governance_timelock or _require_address(
        activation.get("governanceRootSafe"), "activation.governanceRootSafe"
    ) != governance_root_safe:
        raise OmnichainEvidenceError("Omnichain activation evidence governance mismatches")
    owners = activation.get("observedOwners")
    if not isinstance(owners, Mapping) or any(
        _require_address(owners.get(name), f"activation.observedOwners.{name}")
        != governance_timelock
        for name in ("gateway", "spoke")
    ):
        raise OmnichainEvidenceError("Omnichain governance ownership is not accepted")

    ownership_intent = _load_evidence(
        settings.payment_omnichain_ownership_intent_evidence_path,
        "ownership_intent",
    )
    if (
        ownership_intent.get("schemaVersion") != 2
        or ownership_intent.get("kind")
        != "solslot-omnichain-ownership-activation-intent"
        or ownership_intent.get("artifactHash")
        != activation.get("ownershipOperationArtifactHash")
        or ownership_intent.get("deploymentArtifactHash") != declared_hash
        or ownership_intent.get("network") != evidence.get("network")
        or ownership_intent.get("chainId") != chain_id
        or ownership_intent.get("minimumDelaySeconds") != "86400"
        or _require_address(ownership_intent.get("rootSafe"), "ownershipIntent.rootSafe")
        != governance_root_safe
        or _require_address(
            ownership_intent.get("timelock"), "ownershipIntent.timelock"
        )
        != governance_timelock
    ):
        raise OmnichainEvidenceError("Omnichain ownership intent evidence mismatches")
    _require_hash(ownership_intent.get("operationId"), "ownershipIntent.operationId")

    return OmnichainEvidence(
        source_sha=source_sha,
        chain_id=chain_id,
        gateway_profile=gateway_profile,
        gateway_address=_require_address(contracts.get("gateway"), "gateway"),
        spoke_address=_require_address(contracts.get("spoke"), "spoke"),
        governance_root_safe=governance_root_safe,
        governance_timelock=governance_timelock,
    )


__all__ = ["OmnichainEvidence", "OmnichainEvidenceError", "load_omnichain_evidence"]
