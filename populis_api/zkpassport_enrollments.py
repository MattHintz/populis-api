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
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from .config import Settings
from .state import get_registry
router = APIRouter(prefix="/zkpassport/enrollments", tags=["zkpassport"])

_HEX32_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
_EMPTY_ATTEST_ROOT = "0x4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
_STORE_LOCK = threading.Lock()


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
    bridgePolicyHash: str
    bridgeParentId: str
    bridgeAmount: int = Field(..., gt=0)
    bridgeCoinId: str
    bridgeMessage: Optional[str] = None
    validatorMessage: Optional[str] = None
    evmTxHash: str
    chiaVaultCoinId: Optional[str] = None
    confirmedBlockIndex: Optional[int] = None
    enrolledAt: int


class EnrollmentRecord(BaseModel):
    vaultLauncherId: str
    network: str
    policyVersion: int
    status: Literal[
        "reserved",
        "evm_confirmed",
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
    return _public_record(record)


@router.post("/{vault_launcher_id}/proof", response_model=EnrollmentRecord)
def record_evm_proof(vault_launcher_id: str, req: RecordProofRequest) -> EnrollmentRecord:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    vault_from_body = _normalize_hex32(req.vaultLauncherId, "vaultLauncherId")
    if vault_from_body != key:
        raise HTTPException(status_code=422, detail="vaultLauncherId does not match URL.")

    identity_root = _normalize_hex32(req.identityAttestRoot, "identityAttestRoot")
    if identity_root == _EMPTY_ATTEST_ROOT:
        raise HTTPException(status_code=422, detail="identityAttestRoot must be non-empty.")

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
        expected = {
            "bridgePolicyHash": record.bridgePolicyHash,
            "bridgeParentId": record.bridgeParentId,
            "bridgeAmount": record.bridgeAmount,
            "bridgeCoinId": record.bridgeCoinId,
        }
        observed = {
            "bridgePolicyHash": _normalize_hex32(req.bridgePolicyHash, "bridgePolicyHash"),
            "bridgeParentId": _normalize_hex32(req.bridgeParentId, "bridgeParentId"),
            "bridgeAmount": int(req.bridgeAmount),
            "bridgeCoinId": _normalize_hex32(req.bridgeCoinId, "bridgeCoinId"),
        }
        if observed != expected:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Proof bridge fields do not match the reserved enrollment.",
            )

        now = int(time.time())
        receipt = VaultCredentialReceipt(
            vaultLauncherId=key,
            network=record.network,
            policyVersion=req.policyVersion,
            identityAttestRoot=identity_root,
            attestationLeafHash=_normalize_hex32(
                req.attestationLeafHash,
                "attestationLeafHash",
            ),
            attestationProof=req.attestationProof,
            bridgePolicyHash=record.bridgePolicyHash,
            bridgeParentId=record.bridgeParentId,
            bridgeAmount=record.bridgeAmount,
            bridgeCoinId=record.bridgeCoinId,
            bridgeMessage=_normalize_hex32(req.bridgeMessage, "bridgeMessage")
            if req.bridgeMessage
            else None,
            validatorMessage=_normalize_hex32(req.validatorMessage, "validatorMessage")
            if req.validatorMessage
            else None,
            evmTxHash=_normalize_tx(req.evmTxHash, "evmTxHash"),
            confirmedBlockIndex=record.receipt.confirmedBlockIndex
            if record.receipt
            else None,
            chiaVaultCoinId=record.receipt.chiaVaultCoinId if record.receipt else None,
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
