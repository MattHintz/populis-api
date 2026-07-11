"""zkPassport vault enrollment receipt index.

This router tracks public, non-PII credential receipt material for the
testnet alpha vault stamp flow.  The Chia vault state is still the source of
truth; this index reserves bridge coins and gives the frontend a recoverable
receipt surface instead of trusting browser-local flags.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional

import httpx
from eth_abi import decode as abi_decode
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia_rs import AugSchemeMPL, Coin, G1Element, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from web3 import Web3

from .config import Settings
from .coinset_client import CoinsetClient
from .evm_auth import recover_evm_signer
from .faucet import AGG_SIG_ME_DATA
from .state import VaultRecord, get_registry

router = APIRouter(prefix="/zkpassport/enrollments", tags=["zkpassport"])

_HEX32_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
_EMPTY_ATTEST_ROOT = "0x4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
_STORE_LOCK = threading.Lock()
_ATTESTATION_EVENT_SIGNATURE = (
    "VaultAttestationVerified(address,bytes32,bytes32,uint16,bytes32,bytes32,"
    "uint64,bytes32,bytes32,bytes32,uint64,bytes32,bytes32,bytes32,uint16)"
)
_ATTESTATION_EVENT_TOPIC = bytes(Web3.keccak(text=_ATTESTATION_EVENT_SIGNATURE))


@dataclass(frozen=True)
class IndexedEvmAttestation:
    sender: str
    vault_launcher_id: str
    scoped_nullifier: str
    nullifier_type: int
    service_scope_hash: str
    service_subscope_hash: str
    proof_timestamp: int
    attestation_leaf_hash: str
    identity_attest_root: str
    bridge_parent_id: str
    bridge_amount: int
    bridge_coin_id: str
    bridge_message: str
    bridge_policy_hash: str
    policy_version: int
    validator_message: str
    transaction_hash: str
    block_number: int


@dataclass(frozen=True)
class BridgeCoinCandidate:
    parent_id: str
    amount: int
    coin_id: str


class AttestationProof(BaseModel):
    bitpath: int = Field(0, ge=0)
    siblings: list[str] = Field(default_factory=list)

    @field_validator("siblings")
    @classmethod
    def _siblings_are_hashes(cls, value: list[str]) -> list[str]:
        return [_normalize_hex32(v, "attestationProof.siblings[]") for v in value]


class VaultCredentialReceipt(BaseModel):
    vaultLauncherId: str
    network: str
    policyVersion: int = Field(..., ge=1)
    identityAttestRoot: str
    attestationLeafHash: str
    attestationProof: AttestationProof
    scopedNullifier: Optional[str] = None
    nullifierType: Optional[int] = None
    serviceScopeHash: Optional[str] = None
    serviceSubscopeHash: Optional[str] = None
    proofTimestamp: Optional[int] = None
    bridgePolicyHash: str
    bridgeParentId: str
    bridgeAmount: int = Field(..., gt=0)
    bridgeCoinId: str
    bridgeMessage: Optional[str] = None
    validatorMessage: Optional[str] = None
    evmTxHash: str
    evmConfirmedBlockIndex: Optional[int] = None
    chiaVaultCoinId: Optional[str] = None
    confirmedBlockIndex: Optional[int] = None
    chiaSpendBundleId: Optional[str] = None
    enrolledAt: int


class EnrollmentRecord(BaseModel):
    vaultLauncherId: str
    network: str
    policyVersion: int
    status: Literal[
        "reserved",
        "evm_confirmed",
        "stamp_pending",
        "chia_confirmed",
        "receipt_syncing",
    ]
    bridgePolicyHash: str
    bridgeParentId: str
    bridgeAmount: int
    bridgeCoinId: str
    createdAt: int
    updatedAt: int
    receipt: Optional[VaultCredentialReceipt] = None


class CreateEnrollmentRequest(BaseModel):
    vaultLauncherId: str


class RecordProofRequest(BaseModel):
    vaultLauncherId: str
    policyVersion: int = Field(..., ge=1)
    identityAttestRoot: str
    attestationLeafHash: str
    attestationProof: AttestationProof = Field(default_factory=AttestationProof)
    bridgePolicyHash: str
    bridgeParentId: str
    bridgeAmount: int = Field(..., gt=0)
    bridgeCoinId: str
    bridgeMessage: Optional[str] = None
    validatorMessage: Optional[str] = None
    evmTxHash: str


class RecordChiaConfirmationRequest(BaseModel):
    chiaVaultCoinId: str
    confirmedBlockIndex: int = Field(..., ge=0)


class PrepareChiaStampResponse(BaseModel):
    vaultLauncherId: str
    authType: Literal["evm", "chia_bls"]
    currentVaultCoinId: str
    identityAttestRoot: str
    typedData: Optional[dict[str, Any]] = None
    currentTimestamp: Optional[int] = None
    vaultCoinSpend: Optional[dict[str, Any]] = None


class SubmitChiaStampRequest(BaseModel):
    signature: str
    currentTimestamp: Optional[int] = Field(None, ge=0)


class SubmitChiaStampResponse(BaseModel):
    enrollment: EnrollmentRecord
    spendBundleId: str
    expectedVaultCoinId: str


class SyncChiaStampResponse(BaseModel):
    enrollment: EnrollmentRecord
    confirmed: bool


def _settings() -> Settings:
    return Settings()


def _normalize_hex32(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not _HEX32_RE.match(text):
        raise ValueError(f"{field} must be a 32-byte hex string")
    return "0x" + text.removeprefix("0x").lower()


def _normalize_tx(value: object, field: str) -> str:
    return _normalize_hex32(value, field)


def _coin_id(parent_id: str, puzzle_hash: str, amount: int) -> str:
    coin = Coin(
        parent_coin_info=bytes32.fromhex(parent_id.removeprefix("0x")),
        puzzle_hash=bytes32.fromhex(puzzle_hash.removeprefix("0x")),
        amount=uint64(amount),
    )
    return "0x" + coin.name().hex()


def _hex32(value: bytes) -> str:
    return "0x" + bytes(value).hex()


def _fetch_verified_evm_attestation(
    settings: Settings,
    *,
    transaction_hash: str,
    expected_vault_launcher_id: str,
) -> IndexedEvmAttestation:
    """Read and fully validate the canonical emitter event from Sepolia."""
    tx_hash = _normalize_tx(transaction_hash, "evmTxHash")
    emitter_address = Web3.to_checksum_address(settings.zkpassport_emitter_address)
    w3 = Web3(
        Web3.HTTPProvider(
            settings.zkpassport_evm_rpc_url,
            request_kwargs={"timeout": 20.0},
        )
    )
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except Exception as exc:  # noqa: BLE001 - provider-specific not-found errors vary
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The zkPassport EVM transaction is not confirmed: {exc}",
        ) from exc
    if int(receipt.get("status", 0)) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The zkPassport EVM transaction reverted.",
        )

    matching: list[IndexedEvmAttestation] = []
    for log in receipt.get("logs", []):
        topics = list(log.get("topics") or [])
        if (
            str(log.get("address", "")).lower() != emitter_address.lower()
            or len(topics) != 4
            or bytes(topics[0]) != _ATTESTATION_EVENT_TOPIC
        ):
            continue
        sender = Web3.to_checksum_address("0x" + bytes(topics[1])[-20:].hex())
        vault_launcher_id = _hex32(bytes(topics[2]))
        scoped_nullifier = _hex32(bytes(topics[3]))
        try:
            (
                nullifier_type,
                service_scope_hash,
                service_subscope_hash,
                proof_timestamp,
                attestation_leaf_hash,
                attestation_root,
                bridge_parent_id,
                bridge_amount,
                bridge_coin_id,
                bridge_message,
                bridge_policy_hash,
                policy_version,
            ) = abi_decode(
                [
                    "uint16",
                    "bytes32",
                    "bytes32",
                    "uint64",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "uint64",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "uint16",
                ],
                bytes(log.get("data") or b""),
            )
        except Exception as exc:  # noqa: BLE001 - malformed event is a hard failure
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"The zkPassport emitter event is malformed: {exc}",
            ) from exc

        matching.append(
            IndexedEvmAttestation(
                sender=sender,
                vault_launcher_id=vault_launcher_id,
                scoped_nullifier=scoped_nullifier,
                nullifier_type=int(nullifier_type),
                service_scope_hash=_hex32(service_scope_hash),
                service_subscope_hash=_hex32(service_subscope_hash),
                proof_timestamp=int(proof_timestamp),
                attestation_leaf_hash=_hex32(attestation_leaf_hash),
                identity_attest_root=_hex32(attestation_root),
                bridge_parent_id=_hex32(bridge_parent_id),
                bridge_amount=int(bridge_amount),
                bridge_coin_id=_hex32(bridge_coin_id),
                bridge_message=_hex32(bridge_message),
                bridge_policy_hash=_hex32(bridge_policy_hash),
                policy_version=int(policy_version),
                validator_message="",
                transaction_hash=tx_hash,
                block_number=int(receipt.get("blockNumber", 0)),
            )
        )

    expected_vault = _normalize_hex32(expected_vault_launcher_id, "vaultLauncherId")
    matching = [event for event in matching if event.vault_launcher_id == expected_vault]
    if len(matching) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The transaction must contain exactly one canonical vault attestation event.",
        )
    event = matching[0]

    try:
        from populis_puzzles.zkpassport_attestation import (
            ZkPassportAttestation,
            compute_attestation_bridge_message,
            compute_attestation_root,
            compute_validator_bridge_message,
        )

        attestation = ZkPassportAttestation(
            vault_launcher_id=bytes32.fromhex(event.vault_launcher_id.removeprefix("0x")),
            scoped_nullifier=bytes32.fromhex(event.scoped_nullifier.removeprefix("0x")),
            nullifier_type=event.nullifier_type,
            service_scope_hash=bytes32.fromhex(event.service_scope_hash.removeprefix("0x")),
            service_subscope_hash=bytes32.fromhex(event.service_subscope_hash.removeprefix("0x")),
            proof_timestamp=event.proof_timestamp,
            policy_version=event.policy_version,
        )
        leaf = attestation.leaf_hash
        root = compute_attestation_root([leaf])
        bridge_policy_hash = bytes32.fromhex(event.bridge_policy_hash.removeprefix("0x"))
        bridge_message = compute_attestation_bridge_message(
            vault_launcher_id=attestation.vault_launcher_id,
            attestation_root=root,
            bridge_policy_hash=bridge_policy_hash,
            policy_version=event.policy_version,
        )
        bridge_coin_id = Coin(
            bytes32.fromhex(event.bridge_parent_id.removeprefix("0x")),
            bridge_policy_hash,
            uint64(event.bridge_amount),
        ).name()
        validator_message = compute_validator_bridge_message(
            vault_launcher_id=attestation.vault_launcher_id,
            attestation_root=root,
            bridge_policy_hash=bridge_policy_hash,
            bridge_coin_id=bridge_coin_id,
            bridge_message=bridge_message,
            attestation_leaf_hash=leaf,
            scoped_nullifier=attestation.scoped_nullifier,
            nullifier_type=attestation.nullifier_type,
            service_scope_hash=attestation.service_scope_hash,
            service_subscope_hash=attestation.service_subscope_hash,
            proof_timestamp=attestation.proof_timestamp,
            policy_version=event.policy_version,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The zkPassport event commitments are invalid: {exc}",
        ) from exc

    expected = {
        "policyVersion": 1,
        "attestationLeafHash": _hex32(leaf),
        "identityAttestRoot": _hex32(root),
        "bridgePolicyHash": _normalize_hex32(
            settings.zkpassport_bridge_policy_hash,
            "zkpassport_bridge_policy_hash",
        ),
        "bridgeCoinId": _hex32(bridge_coin_id),
        "bridgeMessage": _hex32(bridge_message),
    }
    observed = {
        "policyVersion": event.policy_version,
        "attestationLeafHash": event.attestation_leaf_hash,
        "identityAttestRoot": event.identity_attest_root,
        "bridgePolicyHash": event.bridge_policy_hash,
        "bridgeCoinId": event.bridge_coin_id,
        "bridgeMessage": event.bridge_message,
    }
    if observed != expected:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The zkPassport EVM event commitments do not match the Chia policy.",
        )
    return IndexedEvmAttestation(
        **{
            **event.__dict__,
            "validator_message": _hex32(validator_message),
        }
    )


def _fetch_coin_record_by_name(settings: Settings, coin_id: str) -> Optional[dict[str, Any]]:
    base_url = settings.coinset_base_url.rstrip("/")
    try:
        with httpx.Client(
            base_url=base_url,
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post("/get_coin_record_by_name", json={"name": coin_id})
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Coinset could not verify the Chia vault stamp: {exc}",
        ) from exc
    if not isinstance(payload, dict):
        return None
    record = payload.get("coin_record")
    return record if isinstance(record, dict) else None


def _fetch_coin_records_by_parent_ids(
    settings: Settings,
    parent_ids: list[str],
    *,
    include_spent: bool = False,
) -> list[dict[str, Any]]:
    base_url = settings.coinset_base_url.rstrip("/")
    try:
        with httpx.Client(
            base_url=base_url,
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post(
                "/get_coin_records_by_parent_ids",
                json={
                    "parent_ids": parent_ids,
                    "include_spent_coins": include_spent,
                },
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Coinset could not resolve the current vault coin: {exc}",
        ) from exc
    records = payload.get("coin_records") if isinstance(payload, dict) else None
    return records if isinstance(records, list) else []


def _coin_from_record(record: dict[str, Any], field: str) -> Coin:
    coin = record.get("coin")
    if not isinstance(coin, dict):
        raise ValueError(f"{field} is missing coin fields")
    parent_id = _normalize_hex32(coin.get("parent_coin_info"), f"{field}.parent_coin_info")
    puzzle_hash = _normalize_hex32(coin.get("puzzle_hash"), f"{field}.puzzle_hash")
    amount = int(coin.get("amount"))
    return Coin(
        bytes32.fromhex(parent_id.removeprefix("0x")),
        bytes32.fromhex(puzzle_hash.removeprefix("0x")),
        uint64(amount),
    )


def _find_initial_vault_coin(settings: Settings, vault_launcher_id: str) -> Coin:
    launcher = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    candidates: list[Coin] = []
    for record in _fetch_coin_records_by_parent_ids(settings, [launcher]):
        if record.get("spent_block_index") not in (0, None) or record.get("spent") is True:
            continue
        try:
            coin = _coin_from_record(record, "vaultCoin")
        except (TypeError, ValueError):
            continue
        if coin.parent_coin_info == bytes32.fromhex(launcher.removeprefix("0x")) and int(coin.amount) == 1:
            candidates.append(coin)
    if len(candidates) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The unspent initial Chia vault coin could not be resolved uniquely. "
                "The vault may already be stamped or its launcher is not confirmed."
            ),
        )
    return candidates[0]


def _verify_reserved_bridge_coin(settings: Settings, record: EnrollmentRecord) -> Coin:
    coin_record = _fetch_coin_record_by_name(settings, record.bridgeCoinId)
    if coin_record is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The reserved zkPassport bridge coin is not confirmed on Chia.",
        )
    try:
        coin = _coin_from_record(coin_record, "bridgeCoin")
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Coinset returned an invalid bridge coin: {exc}",
        ) from exc
    expected = Coin(
        bytes32.fromhex(record.bridgeParentId.removeprefix("0x")),
        bytes32.fromhex(record.bridgePolicyHash.removeprefix("0x")),
        uint64(record.bridgeAmount),
    )
    if coin != expected or _hex32(coin.name()) != record.bridgeCoinId:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The reserved bridge coin does not match its indexed enrollment.",
        )
    if coin_record.get("spent_block_index") not in (0, None) or coin_record.get("spent") is True:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The reserved zkPassport bridge coin is already spent.",
        )
    return coin


def _validator_key(settings: Settings):
    seed_hex = str(settings.zkpassport_validator_seed_hex or "").removeprefix("0x")
    try:
        seed = bytes.fromhex(seed_hex)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The zkPassport validator seed is not valid hex.",
        ) from exc
    if len(seed) != 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The zkPassport validator is not configured with a 32-byte seed.",
        )
    return AugSchemeMPL.key_gen(seed)


def _verify_current_chia_vault_coin(
    settings: Settings,
    *,
    coin_id: str,
    confirmed_block_index: int,
    expected_puzzle_hash: str,
) -> dict[str, Any]:
    record = _fetch_coin_record_by_name(settings, coin_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Coinset has no confirmed record for the claimed vault coin.",
        )
    coin = record.get("coin")
    if not isinstance(coin, dict):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Coinset returned a malformed vault coin record.",
        )
    try:
        parent_id = _normalize_hex32(coin.get("parent_coin_info"), "coin.parent_coin_info")
        puzzle_hash = _normalize_hex32(coin.get("puzzle_hash"), "coin.puzzle_hash")
        amount = int(coin.get("amount"))
        observed_confirmed_height = int(record.get("confirmed_block_index"))
        spent_height = int(record.get("spent_block_index") or 0)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Coinset returned an invalid vault coin record.",
        ) from exc
    if amount != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The confirmed coin is not a one-mojo vault singleton coin.",
        )
    if puzzle_hash != expected_puzzle_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The current vault coin puzzle hash does not match the stamped identity root.",
        )
    if _coin_id(parent_id, puzzle_hash, amount) != coin_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The claimed vault coin id does not match Coinset's coin fields.",
        )
    if observed_confirmed_height != confirmed_block_index:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The claimed confirmation height does not match Coinset.",
        )
    if spent_height != 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The claimed vault coin is already spent, so it is not current.",
        )
    return record


def _expected_stamped_vault_puzzle_hash(
    settings: Settings,
    *,
    vault_launcher_id: str,
    identity_attest_root: str,
) -> str:
    if not settings.pool_launcher_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pool launcher id is not configured; cannot verify stamped vault puzzle.",
        )
    registry = get_registry()
    record = registry.get(bytes32.fromhex(vault_launcher_id.removeprefix("0x")))
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vault is not registered on this server; cannot verify stamped vault puzzle.",
        )
    try:
        from populis_puzzles.vault_driver import (
            one_leaf_merkle_root,
            puzzle_for_vault_full,
        )

        expected = puzzle_for_vault_full(
            bytes32.fromhex(vault_launcher_id.removeprefix("0x")),
            bytes(record.owner_pubkey),
            int(record.auth_type),
            one_leaf_merkle_root(bytes(record.owner_pubkey)),
            bytes32.fromhex(settings.pool_launcher_id.removeprefix("0x")),
            identity_attest_root=bytes32.fromhex(identity_attest_root.removeprefix("0x")),
            zkpassport_bridge_policy_hash=bytes32.fromhex(
                settings.zkpassport_bridge_policy_hash.removeprefix("0x")
            ),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Vault registry cannot reconstruct the stamped vault puzzle: {exc}",
        ) from exc
    return "0x" + expected.get_tree_hash().hex()


def _sync_chia_stamp(settings: Settings, key: str) -> EnrollmentRecord:
    with _STORE_LOCK:
        existing = _load_store(settings).get("records", {}).get(key)
    if not existing:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    record = EnrollmentRecord.model_validate(existing)
    if record.receipt is None or not record.receipt.chiaVaultCoinId:
        return record
    if record.status not in {"stamp_pending", "receipt_syncing", "chia_confirmed"}:
        return record

    coin_id = _normalize_hex32(record.receipt.chiaVaultCoinId, "receipt.chiaVaultCoinId")
    coin_record = _fetch_coin_record_by_name(settings, coin_id)
    if coin_record is None:
        return record
    try:
        confirmed_block_index = int(coin_record.get("confirmed_block_index"))
    except (TypeError, ValueError):
        return record
    expected_puzzle_hash = _expected_stamped_vault_puzzle_hash(
        settings,
        vault_launcher_id=key,
        identity_attest_root=record.receipt.identityAttestRoot,
    )
    try:
        _verify_current_chia_vault_coin(
            settings,
            coin_id=coin_id,
            confirmed_block_index=confirmed_block_index,
            expected_puzzle_hash=expected_puzzle_hash,
        )
    except HTTPException:
        if record.status != "chia_confirmed":
            raise
        with _STORE_LOCK:
            data = _load_store(settings)
            records: dict[str, Any] = data.setdefault("records", {})
            latest = EnrollmentRecord.model_validate(records.get(key, existing))
            downgraded = latest.model_copy(
                update={"status": "receipt_syncing", "updatedAt": int(time.time())}
            )
            records[key] = downgraded.model_dump()
            _save_store(settings, data)
        return downgraded

    registry = get_registry()
    vault_record = registry.get(bytes32.fromhex(key.removeprefix("0x")))
    if vault_record is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vault ownership metadata is missing; the Chia stamp cannot be indexed safely.",
        )
    registry.record(
        VaultRecord(
            launcher_id=vault_record.launcher_id,
            full_puzhash=bytes32.fromhex(expected_puzzle_hash.removeprefix("0x")),
            p2_vault_puzhash=vault_record.p2_vault_puzhash,
            auth_type=vault_record.auth_type,
            owner_pubkey=vault_record.owner_pubkey,
            owner_evm_address=vault_record.owner_evm_address,
            spend_bundle_id=record.receipt.chiaSpendBundleId or vault_record.spend_bundle_id,
            pushed_at=vault_record.pushed_at,
        )
    )

    with _STORE_LOCK:
        data = _load_store(settings)
        records = data.setdefault("records", {})
        latest_raw = records.get(key)
        if not latest_raw:
            raise HTTPException(status_code=404, detail="Enrollment not found.")
        latest = EnrollmentRecord.model_validate(latest_raw)
        if latest.receipt is None:
            raise HTTPException(status_code=409, detail="No EVM proof receipt to confirm.")
        receipt = latest.receipt.model_copy(
            update={
                "chiaVaultCoinId": coin_id,
                "confirmedBlockIndex": confirmed_block_index,
            }
        )
        confirmed = latest.model_copy(
            update={
                "status": "chia_confirmed",
                "receipt": receipt,
                "updatedAt": int(time.time()),
            }
        )
        records[key] = confirmed.model_dump()
        _save_store(settings, data)
    return confirmed


def _store_path(settings: Settings) -> Path:
    return Path(settings.zkpassport_enrollment_store_path)


def _load_store(settings: Settings) -> dict[str, Any]:
    path = _store_path(settings)
    if not path.exists():
        return {"records": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"zkPassport enrollment store is malformed: {exc}",
        ) from exc
    if not isinstance(data, dict):
        return {"records": {}}
    records = data.get("records")
    if not isinstance(records, dict):
        data["records"] = {}
    return data


def _save_store(settings: Settings, data: dict[str, Any]) -> None:
    path = _store_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _bridge_parent_pool(settings: Settings) -> list[str]:
    raw = settings.zkpassport_bridge_parent_ids or ""
    parents = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            parents.append(_normalize_hex32(item, "zkpassport_bridge_parent_ids"))
    return parents


def _fetch_bridge_coin_records(settings: Settings, bridge_policy_hash: str) -> list[dict[str, Any]]:
    base_url = settings.coinset_base_url.rstrip("/")
    try:
        with httpx.Client(
            base_url=base_url,
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post(
                "/get_coin_records_by_puzzle_hash",
                json={
                    "puzzle_hash": bridge_policy_hash,
                    "include_spent_coins": False,
                },
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Coinset could not discover zkPassport bridge coins: {exc}",
        ) from exc
    if not isinstance(payload, dict):
        return []
    records = payload.get("coin_records") or []
    return records if isinstance(records, list) else []


def _bridge_coin_candidates(
    settings: Settings,
    *,
    bridge_policy_hash: str,
    default_amount: int,
    extra_candidates: Optional[list[BridgeCoinCandidate]] = None,
) -> list[BridgeCoinCandidate]:
    candidates_by_id: dict[str, BridgeCoinCandidate] = {}

    for parent in _bridge_parent_pool(settings):
        coin_id = _coin_id(parent, bridge_policy_hash, default_amount)
        candidates_by_id[coin_id] = BridgeCoinCandidate(
            parent_id=parent,
            amount=default_amount,
            coin_id=coin_id,
        )

    for record in _fetch_bridge_coin_records(settings, bridge_policy_hash):
        if not isinstance(record, dict):
            continue
        if record.get("spent_block_index") not in (0, None) or record.get("spent") is True:
            continue
        coin = record.get("coin")
        if not isinstance(coin, dict):
            continue
        try:
            parent = _normalize_hex32(coin.get("parent_coin_info"), "bridge.parent_coin_info")
            puzzle_hash = _normalize_hex32(coin.get("puzzle_hash"), "bridge.puzzle_hash")
            amount = int(coin.get("amount"))
        except (TypeError, ValueError):
            continue
        if puzzle_hash != bridge_policy_hash or amount <= 0:
            continue
        coin_id = _coin_id(parent, puzzle_hash, amount)
        candidates_by_id[coin_id] = BridgeCoinCandidate(
            parent_id=parent,
            amount=amount,
            coin_id=coin_id,
        )

    for candidate in extra_candidates or []:
        if candidate.amount > 0:
            candidates_by_id[candidate.coin_id] = candidate

    return sorted(
        candidates_by_id.values(),
        key=lambda item: (item.amount, item.parent_id),
    )


async def _auto_top_up_bridge_pool(settings: Settings) -> list[BridgeCoinCandidate]:
    if not settings.zkpassport_bridge_auto_topup_enabled:
        return []
    if settings.network != "testnet11":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Automatic zkPassport bridge top-up is available only on testnet11.",
        )

    from .admin import BridgePoolTopUpRequest, top_up_zkpassport_bridge_pool

    try:
        response = await top_up_zkpassport_bridge_pool(
            BridgePoolTopUpRequest(
                count=int(settings.zkpassport_bridge_auto_topup_count),
                start_amount=int(settings.zkpassport_bridge_auto_topup_start_amount),
                fee=int(settings.zkpassport_bridge_auto_topup_fee),
                dry_run=False,
            ),
            settings,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Automatic zkPassport bridge top-up failed: {exc}",
        ) from exc

    return [
        BridgeCoinCandidate(
            parent_id=coin.parentId,
            amount=coin.bridgeAmount,
            coin_id=coin.bridgeCoinId,
        )
        for coin in response.coins
    ]


def _public_record(record: dict[str, Any]) -> EnrollmentRecord:
    return EnrollmentRecord.model_validate(record)


def indexed_validator_message(vault_launcher_id: str) -> Optional[str]:
    """Return the indexed validator message for a vault, if a proof exists."""
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    with _STORE_LOCK:
        record = _load_store(settings).get("records", {}).get(key)
    if not record:
        return None
    parsed = EnrollmentRecord.model_validate(record)
    return parsed.receipt.validatorMessage if parsed.receipt else None


def indexed_validator_signing_context(
    vault_launcher_id: str,
) -> Optional[tuple[str, str, str]]:
    """Return the AGG_SIG_ME inputs for one indexed vault proof."""
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    with _STORE_LOCK:
        record = _load_store(settings).get("records", {}).get(key)
    if not record:
        return None
    parsed = EnrollmentRecord.model_validate(record)
    if parsed.receipt is None or not parsed.receipt.validatorMessage:
        return None
    return (
        parsed.receipt.validatorMessage,
        parsed.bridgeCoinId,
        parsed.network,
    )


@router.post("", response_model=EnrollmentRecord)
async def create_enrollment(req: CreateEnrollmentRequest) -> EnrollmentRecord:
    settings = _settings()
    vault_launcher_id = _normalize_hex32(req.vaultLauncherId, "vaultLauncherId")
    bridge_policy_hash = _normalize_hex32(
        settings.zkpassport_bridge_policy_hash,
        "zkpassport_bridge_policy_hash",
    )
    bridge_amount = int(settings.zkpassport_bridge_amount)
    if bridge_amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="zkPassport bridge amount is not configured.",
        )
    extra_candidates: list[BridgeCoinCandidate] = []
    top_up_attempted = False
    last_empty_pool = False

    while True:
        bridge_candidates = _bridge_coin_candidates(
            settings,
            bridge_policy_hash=bridge_policy_hash,
            default_amount=bridge_amount,
            extra_candidates=extra_candidates,
        )
        last_empty_pool = not bridge_candidates

        with _STORE_LOCK:
            data = _load_store(settings)
            records: dict[str, Any] = data.setdefault("records", {})
            existing = records.get(vault_launcher_id)
            if existing:
                return _public_record(existing)

            used_coin_ids = {
                str(record.get("bridgeCoinId", "")).lower()
                for record in records.values()
                if isinstance(record, dict)
            }
            bridge_candidate = next(
                (
                    candidate
                    for candidate in bridge_candidates
                    if candidate.coin_id not in used_coin_ids
                ),
                None,
            )
            if bridge_candidate is not None:
                now = int(time.time())
                record = EnrollmentRecord(
                    vaultLauncherId=vault_launcher_id,
                    network=settings.network,
                    policyVersion=1,
                    status="reserved",
                    bridgePolicyHash=bridge_policy_hash,
                    bridgeParentId=bridge_candidate.parent_id,
                    bridgeAmount=bridge_candidate.amount,
                    bridgeCoinId=bridge_candidate.coin_id,
                    createdAt=now,
                    updatedAt=now,
                )
                records[vault_launcher_id] = record.model_dump()
                _save_store(settings, data)
                return record

        if settings.zkpassport_bridge_auto_topup_enabled and not top_up_attempted:
            top_up_attempted = True
            extra_candidates = await _auto_top_up_bridge_pool(settings)
            continue

        detail = (
            "No unspent zkPassport bridge coins are available; top up the bridge pool."
            if last_empty_pool
            else "No unreserved zkPassport bridge coins remain; top up the bridge pool."
        )
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
                if last_empty_pool
                else status.HTTP_409_CONFLICT
            ),
            detail=detail,
        )


@router.get("/{vault_launcher_id}", response_model=EnrollmentRecord)
def get_enrollment(vault_launcher_id: str) -> EnrollmentRecord:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    with _STORE_LOCK:
        record = _load_store(settings).get("records", {}).get(key)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No zkPassport enrollment receipt is indexed for this vault.",
        )
    parsed = _public_record(record)
    if parsed.status in {"stamp_pending", "receipt_syncing", "chia_confirmed"}:
        return _sync_chia_stamp(settings, key)
    return parsed


@router.post("/{vault_launcher_id}/proof", response_model=EnrollmentRecord)
def record_evm_proof(vault_launcher_id: str, req: RecordProofRequest) -> EnrollmentRecord:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    vault_from_body = _normalize_hex32(req.vaultLauncherId, "vaultLauncherId")
    if vault_from_body != key:
        raise HTTPException(status_code=422, detail="vaultLauncherId does not match URL.")

    event = _fetch_verified_evm_attestation(
        settings,
        transaction_hash=req.evmTxHash,
        expected_vault_launcher_id=key,
    )
    if event.identity_attest_root == _EMPTY_ATTEST_ROOT:
        raise HTTPException(status_code=422, detail="identityAttestRoot must be non-empty.")
    if req.attestationProof.bitpath != 0 or req.attestationProof.siblings:
        raise HTTPException(
            status_code=422,
            detail="Alpha policy requires the one-leaf attestation proof.",
        )

    client_commitments = {
        "policyVersion": int(req.policyVersion),
        "identityAttestRoot": _normalize_hex32(
            req.identityAttestRoot,
            "identityAttestRoot",
        ),
        "attestationLeafHash": _normalize_hex32(
            req.attestationLeafHash,
            "attestationLeafHash",
        ),
        "bridgePolicyHash": _normalize_hex32(req.bridgePolicyHash, "bridgePolicyHash"),
        "bridgeParentId": _normalize_hex32(req.bridgeParentId, "bridgeParentId"),
        "bridgeAmount": int(req.bridgeAmount),
        "bridgeCoinId": _normalize_hex32(req.bridgeCoinId, "bridgeCoinId"),
        "bridgeMessage": _normalize_hex32(req.bridgeMessage, "bridgeMessage")
        if req.bridgeMessage
        else None,
        "validatorMessage": _normalize_hex32(req.validatorMessage, "validatorMessage")
        if req.validatorMessage
        else None,
    }
    event_commitments = {
        "policyVersion": event.policy_version,
        "identityAttestRoot": event.identity_attest_root,
        "attestationLeafHash": event.attestation_leaf_hash,
        "bridgePolicyHash": event.bridge_policy_hash,
        "bridgeParentId": event.bridge_parent_id,
        "bridgeAmount": event.bridge_amount,
        "bridgeCoinId": event.bridge_coin_id,
        "bridgeMessage": event.bridge_message,
        "validatorMessage": event.validator_message,
    }
    if client_commitments != event_commitments:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Browser proof fields do not match the indexed EVM attestation event.",
        )

    vault_record = get_registry().get(bytes32.fromhex(key.removeprefix("0x")))
    if (
        vault_record is not None
        and vault_record.owner_evm_address
        and vault_record.owner_evm_address.lower() != event.sender.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The zkPassport event signer is not the registered EVM vault owner.",
        )

    with _STORE_LOCK:
        data = _load_store(settings)
        records: dict[str, Any] = data.setdefault("records", {})
        existing = records.get(key)
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Create an enrollment before recording proof.",
            )
        record = EnrollmentRecord.model_validate(existing)
        if record.status == "chia_confirmed":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This vault credential enrollment is already confirmed on Chia.",
            )
        if record.status == "stamp_pending":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The Chia vault identity stamp is already pending.",
            )
        expected = {
            "bridgePolicyHash": record.bridgePolicyHash,
            "bridgeParentId": record.bridgeParentId,
            "bridgeAmount": record.bridgeAmount,
            "bridgeCoinId": record.bridgeCoinId,
        }
        observed = {
            "bridgePolicyHash": event.bridge_policy_hash,
            "bridgeParentId": event.bridge_parent_id,
            "bridgeAmount": event.bridge_amount,
            "bridgeCoinId": event.bridge_coin_id,
        }
        if observed != expected:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="EVM event bridge fields do not match the reserved enrollment.",
            )
        for other_key, other in records.items():
            if other_key == key or not isinstance(other, dict):
                continue
            other_receipt = other.get("receipt")
            if (
                isinstance(other_receipt, dict)
                and str(other_receipt.get("evmTxHash", "")).lower()
                == event.transaction_hash.lower()
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This EVM attestation transaction is already bound to another vault.",
                )

        now = int(time.time())
        receipt = VaultCredentialReceipt(
            vaultLauncherId=key,
            network=record.network,
            policyVersion=event.policy_version,
            identityAttestRoot=event.identity_attest_root,
            attestationLeafHash=event.attestation_leaf_hash,
            attestationProof=AttestationProof(bitpath=0, siblings=[]),
            scopedNullifier=event.scoped_nullifier,
            nullifierType=event.nullifier_type,
            serviceScopeHash=event.service_scope_hash,
            serviceSubscopeHash=event.service_subscope_hash,
            proofTimestamp=event.proof_timestamp,
            bridgePolicyHash=record.bridgePolicyHash,
            bridgeParentId=record.bridgeParentId,
            bridgeAmount=record.bridgeAmount,
            bridgeCoinId=record.bridgeCoinId,
            bridgeMessage=event.bridge_message,
            validatorMessage=event.validator_message,
            evmTxHash=event.transaction_hash,
            evmConfirmedBlockIndex=event.block_number,
            confirmedBlockIndex=record.receipt.confirmedBlockIndex
            if record.receipt
            else None,
            chiaVaultCoinId=record.receipt.chiaVaultCoinId if record.receipt else None,
            chiaSpendBundleId=record.receipt.chiaSpendBundleId if record.receipt else None,
            enrolledAt=record.receipt.enrolledAt if record.receipt else now,
        )
        updated = record.model_copy(
            update={
                "status": "chia_confirmed"
                if receipt.confirmedBlockIndex is not None
                else "evm_confirmed",
                "receipt": receipt,
                "updatedAt": now,
            }
        )
        records[key] = updated.model_dump()
        _save_store(settings, data)
        return updated


def _wallet_coin_spend(coin_spend: Any) -> dict[str, Any]:
    """Return the CHIP-0002 shape consumed by Goby and Sage."""
    return {
        "coin": {
            "parentCoinInfo": _hex32(coin_spend.coin.parent_coin_info),
            "puzzleHash": _hex32(coin_spend.coin.puzzle_hash),
            "amount": int(coin_spend.coin.amount),
        },
        "puzzleReveal": "0x" + bytes(coin_spend.puzzle_reveal).hex(),
        "solution": "0x" + bytes(coin_spend.solution).hex(),
    }


def _build_bls_chia_stamp(
    settings: Settings,
    *,
    key: str,
    record: EnrollmentRecord,
    event: IndexedEvmAttestation,
    vault_coin: Coin,
    current_timestamp: int,
) -> tuple[Any, Coin, bytes, G2Element]:
    """Build the exact BLS vault spend and both AGG_SIG_ME messages.

    The browser receives only the vault coin spend. The API rebuilds it from
    canonical state during submission and verifies the returned owner
    signature before aggregating the independently produced validator
    signature.
    """
    if record.receipt is None:
        raise HTTPException(status_code=409, detail="No EVM proof receipt to stamp.")
    if not settings.pool_launcher_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pool launcher id is not configured; the vault stamp cannot be built.",
        )

    from populis_puzzles.vault_driver import (
        AUTH_TYPE_BLS,
        DEFAULT_IDENTITY_ATTEST_ROOT,
        one_leaf_merkle_root,
        puzzle_for_vault_full,
    )
    from populis_puzzles.zkpassport_bridge_driver import (
        build_bridge_and_vault_update_identity_bundle,
        make_bridge_policy_hash,
    )

    launcher = bytes32.fromhex(key.removeprefix("0x"))
    vault_record = get_registry().get(launcher)
    if vault_record is None or vault_record.auth_type != AUTH_TYPE_BLS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The registered vault is not a Chia BLS vault.",
        )
    owner_pubkey = bytes(vault_record.owner_pubkey)
    try:
        G1Element.from_bytes(owner_pubkey)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The registered BLS vault owner key is invalid.",
        ) from exc

    pool_launcher_id = bytes32.fromhex(settings.pool_launcher_id.removeprefix("0x"))
    bridge_policy_hash = bytes32.fromhex(record.bridgePolicyHash.removeprefix("0x"))
    members_root = one_leaf_merkle_root(owner_pubkey)
    current_puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        AUTH_TYPE_BLS,
        members_root,
        pool_launcher_id,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    if bytes32(current_puzzle.get_tree_hash()) != vault_coin.puzzle_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The current Chia coin does not match the registered BLS vault.",
        )

    validator_sk = _validator_key(settings)
    validator_pubkey = bytes(validator_sk.get_g1())
    if make_bridge_policy_hash([validator_pubkey], 1) != bridge_policy_hash:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The configured validator key does not match the vault bridge policy.",
        )

    try:
        built = build_bridge_and_vault_update_identity_bundle(
            bridge_parent_id=bytes32.fromhex(record.bridgeParentId.removeprefix("0x")),
            bridge_amount=record.bridgeAmount,
            validator_pubkeys=[validator_pubkey],
            threshold=1,
            signer_indices=[0],
            vault_coin=vault_coin,
            vault_launcher_id=launcher,
            owner_pubkey_bytes=owner_pubkey,
            auth_type=AUTH_TYPE_BLS,
            members_merkle_root=members_root,
            pool_launcher_id=pool_launcher_id,
            new_identity_attest_root=bytes32.fromhex(
                record.receipt.identityAttestRoot.removeprefix("0x")
            ),
            attestation_leaf_hash=bytes32.fromhex(
                record.receipt.attestationLeafHash.removeprefix("0x")
            ),
            scoped_nullifier=bytes32.fromhex(event.scoped_nullifier.removeprefix("0x")),
            nullifier_type=event.nullifier_type,
            service_scope_hash=bytes32.fromhex(event.service_scope_hash.removeprefix("0x")),
            service_subscope_hash=bytes32.fromhex(
                event.service_subscope_hash.removeprefix("0x")
            ),
            proof_timestamp=event.proof_timestamp,
            current_timestamp=current_timestamp,
            lineage_proof=LineageProof(parent_name=launcher, amount=uint64(1)),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The Chia BLS identity stamp could not be built: {exc}",
        ) from exc
    if _hex32(built.bridge.validator_message) != event.validator_message:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The Chia bridge validator message does not match the EVM event.",
        )

    identity_root = bytes32.fromhex(record.receipt.identityAttestRoot.removeprefix("0x"))
    expected_puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        AUTH_TYPE_BLS,
        members_root,
        pool_launcher_id,
        identity_attest_root=identity_root,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    expected_vault_coin = Coin(
        vault_coin.name(),
        bytes32(expected_puzzle.get_tree_hash()),
        uint64(1),
    )
    owner_inner_message = bytes(
        Program.to([b"z", identity_root, vault_coin.name()]).get_tree_hash()
    )
    owner_message = (
        owner_inner_message
        + bytes(vault_coin.name())
        + AGG_SIG_ME_DATA[settings.network]
    )
    validator_signature = AugSchemeMPL.sign(
        validator_sk,
        bytes(built.bridge.validator_message)
        + bytes(built.bridge.bridge_coin_id)
        + AGG_SIG_ME_DATA[settings.network],
    )
    return built, expected_vault_coin, owner_message, validator_signature


async def _push_chia_stamp_and_mark_pending(
    settings: Settings,
    *,
    key: str,
    spend_bundle: SpendBundle,
    expected_vault_coin: Coin,
) -> SubmitChiaStampResponse:
    spend_bundle_id = _hex32(spend_bundle.name())
    expected_vault_coin_id = _hex32(expected_vault_coin.name())
    coinset = CoinsetClient(settings.coinset_base_url)
    try:
        push_result = await coinset.push_tx(spend_bundle.to_json_dict())
    except Exception as exc:  # noqa: BLE001 - normalize provider failures for the portal
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Coinset could not submit the Chia vault stamp: {exc}",
        ) from exc
    finally:
        await coinset.close()
    push_status = str(push_result.get("status") or "").upper()
    if not push_result.get("success") and push_status not in {"SUCCESS", "PENDING"}:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Coinset rejected the Chia vault stamp: {push_result.get('error') or push_result}",
        )

    with _STORE_LOCK:
        data = _load_store(settings)
        records: dict[str, Any] = data.setdefault("records", {})
        latest_raw = records.get(key)
        if not latest_raw:
            raise HTTPException(status_code=404, detail="Enrollment not found.")
        latest = EnrollmentRecord.model_validate(latest_raw)
        if latest.receipt is None:
            raise HTTPException(status_code=409, detail="No EVM proof receipt to stamp.")
        receipt = latest.receipt.model_copy(
            update={
                "chiaVaultCoinId": expected_vault_coin_id,
                "chiaSpendBundleId": spend_bundle_id,
                "confirmedBlockIndex": None,
            }
        )
        pending = latest.model_copy(
            update={
                "status": "stamp_pending",
                "receipt": receipt,
                "updatedAt": int(time.time()),
            }
        )
        records[key] = pending.model_dump()
        _save_store(settings, data)
    return SubmitChiaStampResponse(
        enrollment=pending,
        spendBundleId=spend_bundle_id,
        expectedVaultCoinId=expected_vault_coin_id,
    )


@router.post("/{vault_launcher_id}/stamp/prepare", response_model=PrepareChiaStampResponse)
def prepare_chia_stamp(vault_launcher_id: str) -> PrepareChiaStampResponse:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    with _STORE_LOCK:
        existing = _load_store(settings).get("records", {}).get(key)
    if not existing:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    record = EnrollmentRecord.model_validate(existing)
    if record.status == "chia_confirmed":
        raise HTTPException(status_code=409, detail="This vault is already stamped on Chia.")
    if record.status == "stamp_pending":
        raise HTTPException(status_code=409, detail="The Chia vault stamp is already pending.")
    if record.status != "evm_confirmed" or record.receipt is None:
        raise HTTPException(
            status_code=409,
            detail="A confirmed EVM zkPassport event is required before stamping the vault.",
        )

    vault_coin = _find_initial_vault_coin(settings, key)
    vault_record = get_registry().get(bytes32.fromhex(key.removeprefix("0x")))
    auth_type = "chia_bls" if vault_record and vault_record.auth_type == 1 else "evm"
    typed_data: Optional[dict[str, Any]] = None
    current_timestamp: Optional[int] = None
    vault_coin_spend: Optional[dict[str, Any]] = None
    if auth_type == "evm":
        from populis_puzzles.vault_driver import eip712_typed_data_for_vault_spend

        typed_data = eip712_typed_data_for_vault_spend(
            b"z",
            bytes32.fromhex(record.receipt.identityAttestRoot.removeprefix("0x")),
            vault_coin.name(),
        )
    else:
        event = _fetch_verified_evm_attestation(
            settings,
            transaction_hash=record.receipt.evmTxHash,
            expected_vault_launcher_id=key,
        )
        _verify_reserved_bridge_coin(settings, record)
        current_timestamp = int(time.time())
        built, _, _, _ = _build_bls_chia_stamp(
            settings,
            key=key,
            record=record,
            event=event,
            vault_coin=vault_coin,
            current_timestamp=current_timestamp,
        )
        vault_coin_spend = _wallet_coin_spend(built.vault_spend)
    return PrepareChiaStampResponse(
        vaultLauncherId=key,
        authType=auth_type,
        currentVaultCoinId=_hex32(vault_coin.name()),
        identityAttestRoot=record.receipt.identityAttestRoot,
        typedData=typed_data,
        currentTimestamp=current_timestamp,
        vaultCoinSpend=vault_coin_spend,
    )


@router.post("/{vault_launcher_id}/stamp/submit", response_model=SubmitChiaStampResponse)
async def submit_evm_chia_stamp(
    vault_launcher_id: str,
    req: SubmitChiaStampRequest,
) -> SubmitChiaStampResponse:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    with _STORE_LOCK:
        existing = _load_store(settings).get("records", {}).get(key)
    if not existing:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    record = EnrollmentRecord.model_validate(existing)
    if record.status == "stamp_pending" and record.receipt:
        if record.receipt.chiaSpendBundleId and record.receipt.chiaVaultCoinId:
            return SubmitChiaStampResponse(
                enrollment=record,
                spendBundleId=record.receipt.chiaSpendBundleId,
                expectedVaultCoinId=record.receipt.chiaVaultCoinId,
            )
    if record.status != "evm_confirmed" or record.receipt is None:
        raise HTTPException(
            status_code=409,
            detail="A confirmed EVM zkPassport event is required before stamping the vault.",
        )
    if not settings.pool_launcher_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pool launcher id is not configured; the vault stamp cannot be built.",
        )

    event = _fetch_verified_evm_attestation(
        settings,
        transaction_hash=record.receipt.evmTxHash,
        expected_vault_launcher_id=key,
    )
    if (
        event.identity_attest_root != record.receipt.identityAttestRoot
        or event.validator_message != record.receipt.validatorMessage
        or event.bridge_coin_id != record.bridgeCoinId
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The indexed receipt no longer matches the canonical EVM event.",
        )

    vault_coin = _find_initial_vault_coin(settings, key)
    _verify_reserved_bridge_coin(settings, record)

    launcher = bytes32.fromhex(key.removeprefix("0x"))
    vault_record = get_registry().get(launcher)
    if vault_record is not None and vault_record.auth_type == 1:
        if req.currentTimestamp is None:
            raise HTTPException(
                status_code=422,
                detail="currentTimestamp is required for a Chia BLS vault stamp.",
            )
        if abs(int(time.time()) - req.currentTimestamp) > 90:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The BLS vault stamp authorization expired. Prepare and sign it again.",
            )
        built, expected_vault_coin, owner_message, validator_signature = (
            _build_bls_chia_stamp(
                settings,
                key=key,
                record=record,
                event=event,
                vault_coin=vault_coin,
                current_timestamp=req.currentTimestamp,
            )
        )
        try:
            owner_signature_bytes = bytes.fromhex(req.signature.removeprefix("0x"))
            if len(owner_signature_bytes) != 96:
                raise ValueError("BLS vault stamp signature must be 96 bytes.")
            owner_signature = G2Element.from_bytes(owner_signature_bytes)
            owner_public_key = G1Element.from_bytes(bytes(vault_record.owner_pubkey))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not AugSchemeMPL.verify(owner_public_key, owner_message, owner_signature):
            raise HTTPException(
                status_code=400,
                detail="The BLS owner signature does not authorize this exact vault stamp.",
            )
        spend_bundle = SpendBundle(
            list(built.spend_bundle.coin_spends),
            AugSchemeMPL.aggregate([owner_signature, validator_signature]),
        )
        return await _push_chia_stamp_and_mark_pending(
            settings,
            key=key,
            spend_bundle=spend_bundle,
            expected_vault_coin=expected_vault_coin,
        )

    from populis_puzzles.vault_driver import (
        AUTH_TYPE_SECP256K1,
        DEFAULT_IDENTITY_ATTEST_ROOT,
        compact_signature_from_evm,
        eip712_typed_data_for_vault_spend,
        one_leaf_merkle_root,
        puzzle_for_p2_vault,
        puzzle_for_vault_full,
    )
    from populis_puzzles.zkpassport_bridge_driver import (
        build_bridge_and_vault_update_identity_bundle,
        make_bridge_policy_hash,
    )

    identity_root = bytes32.fromhex(record.receipt.identityAttestRoot.removeprefix("0x"))
    typed_data = eip712_typed_data_for_vault_spend(
        b"z",
        identity_root,
        vault_coin.name(),
    )
    try:
        recovery = recover_evm_signer(typed_data, req.signature)
        compact_signature = compact_signature_from_evm(req.signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if recovery.address.lower() != event.sender.lower():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The vault stamp signature is not from the zkPassport event signer.",
        )

    pool_launcher_id = bytes32.fromhex(settings.pool_launcher_id.removeprefix("0x"))
    bridge_policy_hash = bytes32.fromhex(record.bridgePolicyHash.removeprefix("0x"))
    members_root = one_leaf_merkle_root(recovery.compressed_pubkey)
    current_puzzle = puzzle_for_vault_full(
        launcher,
        recovery.compressed_pubkey,
        AUTH_TYPE_SECP256K1,
        members_root,
        pool_launcher_id,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    if bytes32(current_puzzle.get_tree_hash()) != vault_coin.puzzle_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The owner signature does not reconstruct the current unstamped Chia vault coin. "
                "Reconnect the wallet that created this vault."
            ),
        )

    registry = get_registry()
    vault_record = registry.get(launcher)
    if vault_record is not None:
        if (
            vault_record.auth_type != AUTH_TYPE_SECP256K1
            or bytes(vault_record.owner_pubkey) != recovery.compressed_pubkey
            or (
                vault_record.owner_evm_address
                and vault_record.owner_evm_address.lower() != recovery.address.lower()
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The vault stamp signature conflicts with registered vault ownership.",
            )
    else:
        registry.record(
            VaultRecord(
                launcher_id=launcher,
                full_puzhash=bytes32(current_puzzle.get_tree_hash()),
                p2_vault_puzhash=bytes32(puzzle_for_p2_vault(launcher).get_tree_hash()),
                auth_type=AUTH_TYPE_SECP256K1,
                owner_pubkey=recovery.compressed_pubkey,
                owner_evm_address=recovery.address,
                spend_bundle_id=f"recovered:{_hex32(vault_coin.name())}",
                pushed_at=time.time(),
            )
        )

    validator_sk = _validator_key(settings)
    validator_pubkey = bytes(validator_sk.get_g1())
    if make_bridge_policy_hash([validator_pubkey], 1) != bridge_policy_hash:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The configured validator key does not match the vault bridge policy.",
        )

    try:
        built = build_bridge_and_vault_update_identity_bundle(
            bridge_parent_id=bytes32.fromhex(record.bridgeParentId.removeprefix("0x")),
            bridge_amount=record.bridgeAmount,
            validator_pubkeys=[validator_pubkey],
            threshold=1,
            signer_indices=[0],
            vault_coin=vault_coin,
            vault_launcher_id=launcher,
            owner_pubkey_bytes=recovery.compressed_pubkey,
            auth_type=AUTH_TYPE_SECP256K1,
            members_merkle_root=members_root,
            pool_launcher_id=pool_launcher_id,
            new_identity_attest_root=identity_root,
            attestation_leaf_hash=bytes32.fromhex(
                record.receipt.attestationLeafHash.removeprefix("0x")
            ),
            scoped_nullifier=bytes32.fromhex(event.scoped_nullifier.removeprefix("0x")),
            nullifier_type=event.nullifier_type,
            service_scope_hash=bytes32.fromhex(event.service_scope_hash.removeprefix("0x")),
            service_subscope_hash=bytes32.fromhex(
                event.service_subscope_hash.removeprefix("0x")
            ),
            proof_timestamp=event.proof_timestamp,
            current_timestamp=int(time.time()),
            lineage_proof=LineageProof(parent_name=launcher, amount=uint64(1)),
            signature_data=compact_signature,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The Chia identity stamp could not be built: {exc}",
        ) from exc
    if _hex32(built.bridge.validator_message) != event.validator_message:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The Chia bridge validator message does not match the EVM event.",
        )

    validator_signature = AugSchemeMPL.sign(
        validator_sk,
        bytes(built.bridge.validator_message)
        + bytes(built.bridge.bridge_coin_id)
        + AGG_SIG_ME_DATA[settings.network],
    )
    spend_bundle = SpendBundle(list(built.spend_bundle.coin_spends), validator_signature)
    expected_puzzle = puzzle_for_vault_full(
        launcher,
        recovery.compressed_pubkey,
        AUTH_TYPE_SECP256K1,
        members_root,
        pool_launcher_id,
        identity_attest_root=identity_root,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    expected_vault_coin = Coin(
        vault_coin.name(),
        bytes32(expected_puzzle.get_tree_hash()),
        uint64(1),
    )
    return await _push_chia_stamp_and_mark_pending(
        settings,
        key=key,
        spend_bundle=spend_bundle,
        expected_vault_coin=expected_vault_coin,
    )


@router.post("/{vault_launcher_id}/stamp/sync", response_model=SyncChiaStampResponse)
def sync_chia_stamp(vault_launcher_id: str) -> SyncChiaStampResponse:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    enrollment = _sync_chia_stamp(settings, key)
    return SyncChiaStampResponse(
        enrollment=enrollment,
        confirmed=enrollment.status == "chia_confirmed",
    )


@router.post("/{vault_launcher_id}/chia-confirmation", response_model=EnrollmentRecord)
def record_chia_confirmation(
    vault_launcher_id: str,
    req: RecordChiaConfirmationRequest,
) -> EnrollmentRecord:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    chia_vault_coin_id = _normalize_hex32(req.chiaVaultCoinId, "chiaVaultCoinId")
    confirmed_block_index = int(req.confirmedBlockIndex)
    with _STORE_LOCK:
        existing = _load_store(settings).get("records", {}).get(key)
    if not existing:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    existing_record = EnrollmentRecord.model_validate(existing)
    if existing_record.receipt is None:
        raise HTTPException(status_code=409, detail="No EVM proof receipt to confirm.")
    existing_coin_id = (
        _normalize_hex32(existing_record.receipt.chiaVaultCoinId, "receipt.chiaVaultCoinId")
        if existing_record.receipt.chiaVaultCoinId
        else None
    )
    if existing_coin_id and existing_coin_id != chia_vault_coin_id:
        raise HTTPException(
            status_code=409,
            detail="This enrollment is already confirmed for a different vault coin.",
        )

    _verify_current_chia_vault_coin(
        settings,
        coin_id=chia_vault_coin_id,
        confirmed_block_index=confirmed_block_index,
        expected_puzzle_hash=_expected_stamped_vault_puzzle_hash(
            settings,
            vault_launcher_id=key,
            identity_attest_root=existing_record.receipt.identityAttestRoot,
        ),
    )

    with _STORE_LOCK:
        data = _load_store(settings)
        records: dict[str, Any] = data.setdefault("records", {})
        existing = records.get(key)
        if not existing:
            raise HTTPException(status_code=404, detail="Enrollment not found.")
        record = EnrollmentRecord.model_validate(existing)
        if record.receipt is None:
            raise HTTPException(status_code=409, detail="No EVM proof receipt to confirm.")
        existing_coin_id = (
            _normalize_hex32(record.receipt.chiaVaultCoinId, "receipt.chiaVaultCoinId")
            if record.receipt.chiaVaultCoinId
            else None
        )
        if existing_coin_id and existing_coin_id != chia_vault_coin_id:
            raise HTTPException(
                status_code=409,
                detail="This enrollment is already confirmed for a different vault coin.",
            )
        receipt = record.receipt.model_copy(
            update={
                "chiaVaultCoinId": chia_vault_coin_id,
                "confirmedBlockIndex": confirmed_block_index,
            }
        )
        updated = record.model_copy(
            update={
                "status": "chia_confirmed",
                "receipt": receipt,
                "updatedAt": int(time.time()),
            }
        )
        records[key] = updated.model_dump()
        _save_store(settings, data)
        return updated
