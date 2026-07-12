"""Vault-owner authorization for Solslot V2 credential mutations."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Literal

from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator

from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1

from .config import Settings
from .credential_ledger import LedgerConflict, OwnerChallenge, get_credential_ledger
from .evm_auth import recover_evm_signer
from .state import VaultRecord, get_registry


CredentialAction = Literal[
    "create",
    "record_proof",
    "relay",
    "stamp_prepare",
    "stamp_submit",
    "stamp_sync",
    "chia_confirmation",
]

CREDENTIAL_ACTION_PRIMARY_TYPE = "SolslotVaultCredentialAction"
CREDENTIAL_ACTION_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
    ],
    CREDENTIAL_ACTION_PRIMARY_TYPE: [
        {"name": "vaultLauncherId", "type": "bytes32"},
        {"name": "action", "type": "bytes32"},
        {"name": "payloadHash", "type": "bytes32"},
        {"name": "nonce", "type": "bytes32"},
        {"name": "expiresAt", "type": "uint64"},
    ],
}


class OwnerAuth(BaseModel):
    challengeId: str = Field(..., min_length=32, max_length=128)
    signature: str = Field(..., min_length=2)


class OwnerChallengeRequest(BaseModel):
    action: CredentialAction
    payload: dict[str, Any] = Field(default_factory=dict)


class OwnerChallengeResponse(BaseModel):
    challengeId: str
    vaultLauncherId: str
    action: CredentialAction
    payloadHash: str
    authType: Literal["evm", "chia_bls"]
    expiresAt: int
    typedData: dict[str, Any] | None = None
    messageHex: str | None = None


@dataclass(frozen=True)
class VerifiedOwner:
    owner_key: str
    auth_type: Literal["evm", "chia_bls"]
    vault_record: VaultRecord


def normalize_hex32(value: object, field: str) -> str:
    text = str(value or "").strip().lower().removeprefix("0x")
    if len(text) != 64:
        raise ValueError(f"{field} must be a 32-byte hex string")
    try:
        bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be a 32-byte hex string") from exc
    return "0x" + text


def credential_payload_hash(
    action: CredentialAction,
    vault_launcher_id: str,
    payload: dict[str, Any],
) -> str:
    envelope = {
        "action": action,
        "payload": payload,
        "vaultLauncherId": normalize_hex32(vault_launcher_id, "vaultLauncherId"),
    }
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def credential_action_hash(action: CredentialAction) -> str:
    return "0x" + hashlib.sha256(action.encode("ascii")).hexdigest()


def credential_typed_data(
    settings: Settings,
    challenge: OwnerChallenge,
) -> dict[str, Any]:
    return {
        "types": CREDENTIAL_ACTION_TYPES,
        "primaryType": CREDENTIAL_ACTION_PRIMARY_TYPE,
        "domain": {
            "name": settings.eip712_name,
            "version": settings.eip712_version,
            "chainId": settings.eip712_chain_id,
        },
        "message": {
            "vaultLauncherId": challenge.vault_launcher_id,
            "action": credential_action_hash(challenge.action),
            "payloadHash": challenge.payload_hash,
            "nonce": challenge.nonce,
            "expiresAt": challenge.expires_at,
        },
    }


def credential_bls_message(settings: Settings, challenge: OwnerChallenge) -> bytes:
    material = b"\x53SOLSLOT_V2_CREDENTIAL_ACTION\x00" + b"".join(
        (
            bytes.fromhex(challenge.vault_launcher_id.removeprefix("0x")),
            bytes.fromhex(credential_action_hash(challenge.action).removeprefix("0x")),
            bytes.fromhex(challenge.payload_hash.removeprefix("0x")),
            bytes.fromhex(challenge.nonce.removeprefix("0x")),
            int(challenge.expires_at).to_bytes(8, "big"),
            settings.network.encode("ascii"),
        )
    )
    return hashlib.sha256(material).digest()


def require_alpha_writes(settings: Settings) -> None:
    if not settings.alpha_writes_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Solslot V2 protocol writes are locked until the security audit "
                "and fresh genesis ceremony are complete."
            ),
        )


def require_minting_writes(settings: Settings) -> None:
    require_alpha_writes(settings)
    if not settings.minting_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Solslot V2 minting and offer creation remain locked until the "
                "independent audit and live ceremony smoke gate pass."
            ),
        )
    if settings.network != "testnet11":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Solslot protocol writes are disabled outside Testnet Alpha.",
        )


def require_vault_record(vault_launcher_id: str) -> VaultRecord:
    vault = normalize_hex32(vault_launcher_id, "vaultLauncherId")
    record = get_registry().get(bytes32.fromhex(vault.removeprefix("0x")))
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The vault is not registered in the canonical V2 vault registry.",
        )
    return record


def issue_owner_challenge(
    settings: Settings,
    *,
    vault_launcher_id: str,
    request: OwnerChallengeRequest,
) -> OwnerChallengeResponse:
    require_alpha_writes(settings)
    vault = normalize_hex32(vault_launcher_id, "vaultLauncherId")
    record = require_vault_record(vault)
    if record.auth_type == AUTH_TYPE_SECP256K1 and record.owner_evm_address:
        auth_type: Literal["evm", "chia_bls"] = "evm"
    elif record.auth_type == AUTH_TYPE_BLS:
        auth_type = "chia_bls"
    else:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This vault authorization type cannot stamp V2 credentials.",
        )
    payload_hash = credential_payload_hash(request.action, vault, request.payload)
    challenge = get_credential_ledger(settings).issue_owner_challenge(
        vault_launcher_id=vault,
        action=request.action,
        payload_hash=payload_hash,
        auth_type=auth_type,
        ttl_seconds=settings.zkpassport_owner_challenge_ttl_seconds,
    )
    return OwnerChallengeResponse(
        challengeId=challenge.challenge_id,
        vaultLauncherId=vault,
        action=request.action,
        payloadHash=payload_hash,
        authType=auth_type,
        expiresAt=challenge.expires_at,
        typedData=credential_typed_data(settings, challenge) if auth_type == "evm" else None,
        messageHex=(
            "0x" + credential_bls_message(settings, challenge).hex()
            if auth_type == "chia_bls"
            else None
        ),
    )


def verify_owner_auth(
    settings: Settings,
    *,
    vault_launcher_id: str,
    action: CredentialAction,
    payload: dict[str, Any],
    owner_auth: OwnerAuth,
) -> VerifiedOwner:
    require_alpha_writes(settings)
    vault = normalize_hex32(vault_launcher_id, "vaultLauncherId")
    record = require_vault_record(vault)
    payload_hash = credential_payload_hash(action, vault, payload)
    ledger = get_credential_ledger(settings)
    challenge = ledger.get_owner_challenge(owner_auth.challengeId)
    if challenge is None:
        raise HTTPException(status_code=409, detail="Owner challenge is unknown or consumed.")
    if challenge.expires_at < int(time.time()):
        raise HTTPException(status_code=409, detail="Owner challenge expired.")
    if (
        challenge.vault_launcher_id != vault
        or challenge.action != action
        or challenge.payload_hash != payload_hash
    ):
        raise HTTPException(status_code=409, detail="Owner challenge does not match this mutation.")

    if challenge.auth_type == "evm":
        if record.auth_type != AUTH_TYPE_SECP256K1 or not record.owner_evm_address:
            raise HTTPException(status_code=409, detail="Vault owner metadata is not EVM-authenticated.")
        try:
            recovered = recover_evm_signer(
                credential_typed_data(settings, challenge),
                owner_auth.signature,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=401, detail=f"Invalid owner signature: {exc}") from exc
        if recovered.address.lower() != record.owner_evm_address.lower():
            raise HTTPException(status_code=403, detail="Signature does not belong to this vault owner.")
        owner_key = recovered.address.lower()
        auth_type: Literal["evm", "chia_bls"] = "evm"
    elif challenge.auth_type == "chia_bls":
        if record.auth_type != AUTH_TYPE_BLS:
            raise HTTPException(status_code=409, detail="Vault owner metadata is not BLS-authenticated.")
        try:
            signature = G2Element.from_bytes(bytes.fromhex(owner_auth.signature.removeprefix("0x")))
            pubkey = G1Element.from_bytes(bytes(record.owner_pubkey))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=401, detail=f"Invalid BLS owner signature: {exc}") from exc
        if not AugSchemeMPL.verify(pubkey, credential_bls_message(settings, challenge), signature):
            raise HTTPException(status_code=403, detail="BLS signature does not belong to this vault owner.")
        owner_key = "0x" + bytes(pubkey).hex()
        auth_type = "chia_bls"
    else:
        raise HTTPException(status_code=409, detail="Unsupported owner challenge type.")

    try:
        ledger.consume_owner_challenge(
            challenge_id=owner_auth.challengeId,
            vault_launcher_id=vault,
            action=action,
            payload_hash=payload_hash,
        )
    except LedgerConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return VerifiedOwner(owner_key=owner_key, auth_type=auth_type, vault_record=record)


__all__ = [
    "CREDENTIAL_ACTION_PRIMARY_TYPE",
    "CREDENTIAL_ACTION_TYPES",
    "CredentialAction",
    "OwnerAuth",
    "OwnerChallengeRequest",
    "OwnerChallengeResponse",
    "VerifiedOwner",
    "credential_payload_hash",
    "credential_typed_data",
    "issue_owner_challenge",
    "require_alpha_writes",
    "require_minting_writes",
    "verify_owner_auth",
]
