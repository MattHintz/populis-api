"""Exact cross-chain key-change intents for Admin Authority V3."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping, Optional

import httpx
from chia_rs import AugSchemeMPL, G1Element, G2Element
from eth_abi import encode as abi_encode
from eth_utils import keccak
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .admin_security import (
    AUTHORITY_EVM_CHAIN_ID,
    SecurityActor,
    _artifact_admins,
    _artifact_ceremony_id,
    _canonical_hash,
    _hex_value,
    require_security_actor,
)
from .config import Settings, get_settings
from .evm_auth import normalize_evm_address
from .genesis import get_genesis_store
from .genesis_store import GenesisConflict, GenesisStore, GenesisStoreError
from .public_artifact import load_signed_public_artifact


router = APIRouter(
    prefix="/admin/security/key-changes",
    tags=["admin-key-changes"],
)

MAX_EVIDENCE_BYTES = 128 * 1024
ROUTINE_DELAY_SECONDS = 86_400
LOST_DELAY_SECONDS = 604_800
EXECUTION_WINDOW_SECONDS = 604_800
INTENT_TYPE_HASH = keccak(text="SolslotAdminKeyChangeIntentV1")
INTENT_TUPLE_ABI = (
    "(uint8,uint8,address,address,bytes,bytes,bytes32[3],address[3],"
    "bytes32,address,address,string,uint256,bytes32,uint256,uint64,uint64)"
)
TERMINAL_CASE_STATES = {"COMPLETED", "CANCELLED", "FAILED"}


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class AdminKeyChangeIntentV1(ApiModel):
    schema_version: Literal[1] = Field(1, alias="schemaVersion")
    slot: int = Field(ge=0, le=2)
    kind: Literal["ROUTINE", "LOST"]
    old_daily_evm_key: str = Field(alias="oldDailyEvmKey")
    new_daily_evm_key: str = Field(alias="newDailyEvmKey")
    old_daily_chia_key: str = Field(alias="oldDailyChiaKey")
    new_daily_chia_key: str = Field(alias="newDailyChiaKey")
    identity_launcher_ids: list[str] = Field(
        alias="identityLauncherIds",
        min_length=3,
        max_length=3,
    )
    identity_safes: list[str] = Field(
        alias="identitySafes",
        min_length=3,
        max_length=3,
    )
    authority_launcher_id: str = Field(alias="authorityLauncherId")
    coadmin_safe: str = Field(alias="coadminSafe")
    root_safe: str = Field(alias="rootSafe")
    chia_network: Literal["testnet11"] = Field(
        "testnet11",
        alias="chiaNetwork",
    )
    evm_chain_id: Literal[84532] = Field(
        AUTHORITY_EVM_CHAIN_ID,
        alias="evmChainId",
    )
    source_manifest_hash: str = Field(alias="sourceManifestHash")
    nonce: int = Field(ge=1)
    expires_at: int = Field(alias="expiresAt", ge=1)
    recovery_key_revision: int = Field(
        alias="recoveryKeyRevision",
        ge=1,
    )

    @field_validator(
        "old_daily_chia_key",
        "new_daily_chia_key",
    )
    @classmethod
    def validate_chia_daily_key(cls, value: str) -> str:
        return _hex_value(value, 66, "daily Chia key")

    @field_validator(
        "authority_launcher_id",
        "source_manifest_hash",
    )
    @classmethod
    def validate_bytes32(cls, value: str) -> str:
        return _hex_value(value, 64, "intent bytes32")

    @field_validator("identity_launcher_ids")
    @classmethod
    def validate_launcher_ids(cls, values: list[str]) -> list[str]:
        normalized = [
            _hex_value(value, 64, "identity launcher ID")
            for value in values
        ]
        if len(set(normalized)) != 3:
            raise ValueError("identity launcher IDs must be unique")
        return normalized

    @field_validator(
        "old_daily_evm_key",
        "new_daily_evm_key",
        "coadmin_safe",
        "root_safe",
    )
    @classmethod
    def validate_address(cls, value: str) -> str:
        return normalize_evm_address(value, "authority address")

    @field_validator("identity_safes")
    @classmethod
    def validate_identity_safes(cls, values: list[str]) -> list[str]:
        normalized = [
            normalize_evm_address(value, "identity Safe") for value in values
        ]
        if len({value.lower() for value in normalized}) != 3:
            raise ValueError("identity Safes must be unique")
        return normalized


class RoutinePrepareRequest(ApiModel):
    new_daily_compressed_pubkey: str = Field(
        alias="newDailyCompressedPubkey"
    )

    @field_validator("new_daily_compressed_pubkey")
    @classmethod
    def validate_new_key(cls, value: str) -> str:
        return _hex_value(value, 66, "newDailyCompressedPubkey")


class LostPrepareRequest(RoutinePrepareRequest):
    ceremony_id: str = Field(alias="ceremonyId")
    slot: int = Field(ge=0, le=2)
    evm_guardian: str = Field(alias="evmGuardian")
    recovery_bls_pubkey: str = Field(alias="recoveryBlsPubkey")

    @field_validator("ceremony_id")
    @classmethod
    def validate_ceremony_id(cls, value: str) -> str:
        return _hex_value(value, 64, "ceremonyId")

    @field_validator("evm_guardian")
    @classmethod
    def validate_guardian(cls, value: str) -> str:
        return normalize_evm_address(value, "evmGuardian")

    @field_validator("recovery_bls_pubkey")
    @classmethod
    def validate_recovery_key(cls, value: str) -> str:
        return _hex_value(value, 96, "recoveryBlsPubkey")


class PreparedKeyChange(ApiModel):
    intent: AdminKeyChangeIntentV1
    intent_hash: str = Field(alias="intentHash")
    coordinator: str
    prepare_transaction: dict[str, Any] = Field(alias="prepareTransaction")
    clear_signing: dict[str, Any] = Field(alias="clearSigning")
    recovery_bls_digest: Optional[str] = Field(
        None,
        alias="recoveryBlsDigest",
    )


class PreparedTransactionSubmission(ApiModel):
    intent: AdminKeyChangeIntentV1
    transaction_hash: str = Field(alias="transactionHash")
    recovery_bls_signature: Optional[str] = Field(
        None,
        alias="recoveryBlsSignature",
    )

    @field_validator("transaction_hash")
    @classmethod
    def validate_transaction_hash(cls, value: str) -> str:
        return _hex_value(value, 64, "transactionHash")

    @field_validator("recovery_bls_signature")
    @classmethod
    def validate_recovery_signature(
        cls,
        value: str | None,
    ) -> str | None:
        return (
            _hex_value(value, 192, "recoveryBlsSignature")
            if value is not None
            else None
        )


def _stable_hash(record: Mapping[str, Any]) -> str:
    payload = {
        key: value for key, value in record.items() if key != "artifactHash"
    }
    return _canonical_hash(payload)


def _load_governance_evidence(settings: Settings) -> dict[str, Any]:
    path_value = settings.authority_v3_governance_evidence_path
    if not path_value:
        raise ValueError("Authority V3 EVM deployment evidence is unavailable")
    path = Path(path_value)
    try:
        stat = path.lstat()
        if (
            not path.is_file()
            or path.is_symlink()
            or stat.st_size <= 0
            or stat.st_size > MAX_EVIDENCE_BYTES
        ):
            raise ValueError("Authority V3 EVM deployment evidence is invalid")
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Authority V3 EVM deployment evidence is unreadable"
        ) from exc
    if (
        not isinstance(evidence, dict)
        or evidence.get("schemaVersion") != 3
        or evidence.get("kind")
        != "solslot-alpha-authority-v3-governance-deployment"
        or evidence.get("authorityRule") != "slot0_and_one_of_slot1_slot2"
        or evidence.get("network") != "baseSepolia"
        or evidence.get("chainId") != AUTHORITY_EVM_CHAIN_ID
        or evidence.get("artifactHash") != _stable_hash(evidence)
    ):
        raise ValueError("Authority V3 EVM deployment evidence is unsupported")
    recovery = evidence.get("recovery")
    safes = evidence.get("safes")
    chia = evidence.get("chiaAuthority")
    hashes = evidence.get("runtimeCodeHashes")
    if not all(
        isinstance(value, Mapping)
        for value in (recovery, safes, chia, hashes)
    ):
        raise ValueError("Authority V3 EVM evidence is incomplete")
    identities = safes.get("identities")
    if (
        not isinstance(identities, list)
        or len(identities) != 3
        or [item.get("slot") for item in identities] != [0, 1, 2]
        or recovery.get("routineDelaySeconds") != "86400"
        or recovery.get("lostKeyDelaySeconds") != "604800"
        or recovery.get("globalFreezeRequired") is not True
        or recovery.get("crossChainConvergenceRequired") is not True
        or recovery.get("replacementAcceptanceRequired") is not True
    ):
        raise ValueError("Authority V3 EVM recovery policy differs")
    return evidence


def hash_admin_key_change_intent(intent: AdminKeyChangeIntentV1) -> str:
    kind_value = 1 if intent.kind == "ROUTINE" else 2
    encoded = abi_encode(
        [
            "bytes32",
            "uint8",
            "uint8",
            "address",
            "address",
            "bytes32",
            "bytes32",
            "bytes32[3]",
            "address[3]",
            "bytes32",
            "address",
            "address",
            "bytes32",
            "uint256",
            "bytes32",
            "uint256",
            "uint64",
            "uint64",
        ],
        [
            INTENT_TYPE_HASH,
            intent.slot,
            kind_value,
            intent.old_daily_evm_key,
            intent.new_daily_evm_key,
            keccak(bytes.fromhex(intent.old_daily_chia_key[2:])),
            keccak(bytes.fromhex(intent.new_daily_chia_key[2:])),
            [bytes.fromhex(value[2:]) for value in intent.identity_launcher_ids],
            intent.identity_safes,
            bytes.fromhex(intent.authority_launcher_id[2:]),
            intent.coadmin_safe,
            intent.root_safe,
            keccak(text=intent.chia_network),
            intent.evm_chain_id,
            bytes.fromhex(intent.source_manifest_hash[2:]),
            intent.nonce,
            intent.expires_at,
            intent.recovery_key_revision,
        ],
    )
    return "0x" + keccak(encoded).hex()


def _intent_tuple(intent: AdminKeyChangeIntentV1) -> tuple[Any, ...]:
    return (
        intent.slot,
        1 if intent.kind == "ROUTINE" else 2,
        intent.old_daily_evm_key,
        intent.new_daily_evm_key,
        bytes.fromhex(intent.old_daily_chia_key[2:]),
        bytes.fromhex(intent.new_daily_chia_key[2:]),
        [bytes.fromhex(value[2:]) for value in intent.identity_launcher_ids],
        intent.identity_safes,
        bytes.fromhex(intent.authority_launcher_id[2:]),
        intent.coadmin_safe,
        intent.root_safe,
        intent.chia_network,
        intent.evm_chain_id,
        bytes.fromhex(intent.source_manifest_hash[2:]),
        intent.nonce,
        intent.expires_at,
        intent.recovery_key_revision,
    )


def _function_data(signature: str, abi_types: list[str], values: list[Any]) -> str:
    selector = keccak(text=signature)[:4]
    return "0x" + (selector + abi_encode(abi_types, values)).hex()


def prepare_key_change_calldata(intent: AdminKeyChangeIntentV1) -> str:
    function_name = (
        "prepareRoutine" if intent.kind == "ROUTINE" else "prepareLostKey"
    )
    signature = f"{function_name}({INTENT_TUPLE_ABI})"
    return _function_data(
        signature,
        [INTENT_TUPLE_ABI],
        [_intent_tuple(intent)],
    )


def recovery_intent_bls_digest(intent_hash: str) -> bytes:
    intent = bytes.fromhex(_hex_value(intent_hash, 64, "intentHash")[2:])

    def atom_hash(value: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + value).digest()

    def pair_hash(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x02" + left + right).digest()

    message = pair_hash(
        atom_hash(b"SolslotAdminKeyChangeIntentV1"),
        atom_hash(intent),
    )
    return pair_hash(atom_hash(b"Chia Signed Message"), atom_hash(message))


async def _rpc(settings: Settings, method: str, params: list[Any]) -> Any:
    if not settings.authority_v3_evm_rpc_url:
        raise ValueError("Authority V3 Base Sepolia RPC is unavailable")
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            settings.authority_v3_evm_rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            },
        )
    response.raise_for_status()
    payload = response.json()
    if payload.get("error") or "result" not in payload:
        raise ValueError(f"Authority V3 RPC {method} failed")
    return payload["result"]


async def _call_uint(
    settings: Settings,
    contract: str,
    function_signature: str,
) -> int:
    result = await _rpc(
        settings,
        "eth_call",
        [
            {
                "to": contract,
                "data": "0x" + keccak(text=function_signature)[:4].hex(),
            },
            "latest",
        ],
    )
    return int(str(result), 16)


async def _verified_context(
    settings: Settings,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    artifact = load_signed_public_artifact(settings)
    evidence = _load_governance_evidence(settings)
    authority = artifact["adminAuthority"]
    chia = evidence["chiaAuthority"]
    if (
        authority.get("version") != 3
        or str(chia.get("authorityLauncherId")).lower()
        != str(artifact["launcherIds"]["adminAuthority"]).lower()
        or str(chia.get("sourceManifestHash")).lower()
        != str(authority.get("sourceManifestHash")).lower()
        or [str(value).lower() for value in chia.get("identityLauncherIds", [])]
        != [
            str(item["launcherId"]).lower()
            for item in authority.get("identityVaults", [])
        ]
    ):
        raise ValueError("Authority V3 Chia and EVM evidence do not match")
    coordinator = normalize_evm_address(
        evidence["recovery"]["address"],
        "recovery coordinator",
    )
    expected_code_hash = str(evidence["runtimeCodeHashes"]["recovery"]).lower()
    code = await _rpc(settings, "eth_getCode", [coordinator, "latest"])
    if "0x" + keccak(bytes.fromhex(str(code)[2:])).hex() != expected_code_hash:
        raise ValueError("Authority V3 recovery runtime code hash changed")
    if await _call_uint(settings, coordinator, "isChangeActive()") != 0:
        raise GenesisConflict("another administrator key change is active")
    nonce = await _call_uint(settings, coordinator, "changeNonce()")
    return artifact, evidence, nonce


def _new_daily_identity(compressed: str) -> tuple[str, str]:
    from eth_keys import keys as eth_keys

    normalized = _hex_value(compressed, 66, "new daily key")
    try:
        address = eth_keys.PublicKey.from_compressed_bytes(
            bytes.fromhex(normalized[2:])
        ).to_checksum_address()
    except (TypeError, ValueError) as exc:
        raise ValueError("new daily key is invalid") from exc
    return normalized, address


def _build_intent(
    *,
    artifact: Mapping[str, Any],
    evidence: Mapping[str, Any],
    slot: int,
    kind: Literal["ROUTINE", "LOST"],
    new_daily_compressed_pubkey: str,
    nonce: int,
    now: int,
) -> AdminKeyChangeIntentV1:
    administrators = _artifact_admins(artifact)
    new_chia, new_evm = _new_daily_identity(new_daily_compressed_pubkey)
    old_evm, old_chia = administrators[slot]
    if new_evm.lower() in {
        address.lower() for address, _compressed in administrators
    }:
        raise ValueError("replacement daily wallet is already an administrator")
    safes = evidence["safes"]
    recovery_records = evidence["recovery"]["identities"]
    if (
        not isinstance(recovery_records, list)
        or len(recovery_records) != 3
        or [item.get("slot") for item in recovery_records] != [0, 1, 2]
    ):
        raise ValueError("Authority V3 recovery roster is malformed")
    delay = ROUTINE_DELAY_SECONDS if kind == "ROUTINE" else LOST_DELAY_SECONDS
    return AdminKeyChangeIntentV1(
        slot=slot,
        kind=kind,
        oldDailyEvmKey=old_evm,
        newDailyEvmKey=new_evm,
        oldDailyChiaKey=old_chia,
        newDailyChiaKey=new_chia,
        identityLauncherIds=evidence["chiaAuthority"]["identityLauncherIds"],
        identitySafes=[
            item["address"] for item in safes["identities"]
        ],
        authorityLauncherId=evidence["chiaAuthority"]["authorityLauncherId"],
        coadminSafe=safes["coadmin"]["address"],
        rootSafe=safes["root"]["address"],
        sourceManifestHash=evidence["chiaAuthority"]["sourceManifestHash"],
        nonce=nonce + 1,
        expiresAt=now + delay + EXECUTION_WINDOW_SECONDS,
        recoveryKeyRevision=int(recovery_records[slot]["revision"]),
    )


def _prepared_response(
    intent: AdminKeyChangeIntentV1,
    evidence: Mapping[str, Any],
) -> PreparedKeyChange:
    intent_hash = hash_admin_key_change_intent(intent)
    coordinator = normalize_evm_address(
        evidence["recovery"]["address"],
        "recovery coordinator",
    )
    return PreparedKeyChange(
        intent=intent,
        intentHash=intent_hash,
        coordinator=coordinator,
        prepareTransaction={
            "chainId": AUTHORITY_EVM_CHAIN_ID,
            "to": coordinator,
            "value": "0",
            "data": prepare_key_change_calldata(intent),
        },
        clearSigning={
            "title": (
                "Rotate administrator wallet"
                if intent.kind == "ROUTINE"
                else "Recover lost administrator wallet"
            ),
            "slot": intent.slot,
            "oldWallet": intent.old_daily_evm_key,
            "newWallet": intent.new_daily_evm_key,
            "financialEffect": "No funds move.",
            "authorityEffect": (
                "The replacement controls this administrator identity only "
                "after both chains match."
            ),
            "delaySeconds": (
                ROUTINE_DELAY_SECONDS
                if intent.kind == "ROUTINE"
                else LOST_DELAY_SECONDS
            ),
            "expiresAt": intent.expires_at,
            "operationsFreeze": True,
            "oldKeyCanVeto": True,
        },
        recoveryBlsDigest=(
            "0x" + recovery_intent_bls_digest(intent_hash).hex()
            if intent.kind == "LOST"
            else None
        ),
    )


@router.post("/routine/prepare", response_model=PreparedKeyChange)
async def prepare_routine_key_change(
    body: RoutinePrepareRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> PreparedKeyChange:
    try:
        artifact, evidence, nonce = await _verified_context(settings)
        intent = _build_intent(
            artifact=artifact,
            evidence=evidence,
            slot=actor.authority_slot,
            kind="ROUTINE",
            new_daily_compressed_pubkey=body.new_daily_compressed_pubkey,
            nonce=nonce,
            now=int(time.time()),
        )
        if intent.old_daily_evm_key.lower() != actor.wallet.lower():
            raise ValueError("connected wallet is not the current slot wallet")
        return _prepared_response(intent, evidence)
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/lost/prepare", response_model=PreparedKeyChange)
async def prepare_lost_key_change(
    body: LostPrepareRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> PreparedKeyChange:
    try:
        artifact, evidence, nonce = await _verified_context(settings)
        if _artifact_ceremony_id(artifact) != body.ceremony_id:
            raise ValueError("recovery ceremony does not match the live authority")
        kit = store.recovery_kit(body.ceremony_id, body.slot + 1)
        if (
            str(kit["evmGuardian"]).lower() != body.evm_guardian.lower()
            or str(kit["recoveryBlsPubkey"]).lower()
            != body.recovery_bls_pubkey.lower()
        ):
            raise ValueError("recovery kit does not match the enrolled slot")
        intent = _build_intent(
            artifact=artifact,
            evidence=evidence,
            slot=body.slot,
            kind="LOST",
            new_daily_compressed_pubkey=body.new_daily_compressed_pubkey,
            nonce=nonce,
            now=int(time.time()),
        )
        return _prepared_response(intent, evidence)
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def verify_lost_recovery_bls_signature(
    *,
    intent: AdminKeyChangeIntentV1,
    recovery_bls_pubkey: str,
    signature: str,
) -> None:
    if intent.kind != "LOST":
        raise ValueError("recovery BLS proof is only valid for lost-key recovery")
    try:
        public_key = G1Element.from_bytes(
            bytes.fromhex(_hex_value(recovery_bls_pubkey, 96, "recovery key")[2:])
        )
        parsed_signature = G2Element.from_bytes(
            bytes.fromhex(_hex_value(signature, 192, "recovery signature")[2:])
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("recovery BLS proof is malformed") from exc
    if not AugSchemeMPL.verify(
        public_key,
        recovery_intent_bls_digest(hash_admin_key_change_intent(intent)),
        parsed_signature,
    ):
        raise ValueError("recovery BLS proof is invalid")


__all__ = [
    "AdminKeyChangeIntentV1",
    "PreparedKeyChange",
    "hash_admin_key_change_intent",
    "prepare_key_change_calldata",
    "recovery_intent_bls_digest",
    "router",
    "verify_lost_recovery_bls_signature",
]
