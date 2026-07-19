"""Cryptographic verification for owner-signed property amendments."""
from __future__ import annotations

import hashlib
from typing import Any

from chia_rs import AugSchemeMPL, G1Element, G2Element

from solslot_puzzles.property_metadata import canonicalize_json

from .admin_auth import AdminClaims
from .config import Settings
from .evm_auth import normalize_evm_address, recover_evm_signer
from .property_metadata import PropertyAmendmentV1


AMENDMENT_PRIMARY_TYPE = "SolslotPropertyAmendment"
AMENDMENT_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
    ],
    AMENDMENT_PRIMARY_TYPE: [
        {"name": "collectionId", "type": "string"},
        {"name": "previousRoot", "type": "bytes32"},
        {"name": "newRoot", "type": "bytes32"},
        {"name": "reasonHash", "type": "bytes32"},
        {"name": "effectiveDate", "type": "string"},
        {"name": "changedFieldsHash", "type": "bytes32"},
    ],
}


def amendment_message_payload(amendment: PropertyAmendmentV1) -> dict[str, Any]:
    return {
        "schemaVersion": amendment.schema_version,
        "collectionId": amendment.collection_id,
        "previousRoot": amendment.previous_root.lower(),
        "newRoot": amendment.new_root.lower(),
        "reason": amendment.reason,
        "effectiveDate": amendment.effective_date,
        "changedFields": amendment.changed_fields,
    }


def amendment_message_hash(amendment: PropertyAmendmentV1) -> bytes:
    return hashlib.sha256(canonicalize_json(amendment_message_payload(amendment))).digest()


def amendment_typed_data(
    amendment: PropertyAmendmentV1,
    settings: Settings,
) -> dict[str, Any]:
    changed_fields_hash = hashlib.sha256(
        canonicalize_json(amendment.changed_fields)
    ).digest()
    return {
        "types": AMENDMENT_TYPES,
        "primaryType": AMENDMENT_PRIMARY_TYPE,
        "domain": {
            "name": "Solslot Property Metadata",
            "version": "1",
            "chainId": settings.eip712_chain_id,
        },
        "message": {
            "collectionId": amendment.collection_id,
            "previousRoot": amendment.previous_root,
            "newRoot": amendment.new_root,
            "reasonHash": "0x" + hashlib.sha256(amendment.reason.encode("utf-8")).hexdigest(),
            "effectiveDate": amendment.effective_date,
            "changedFieldsHash": "0x" + changed_fields_hash.hex(),
        },
    }


def verify_amendment_signature(
    amendment: PropertyAmendmentV1,
    *,
    claims: AdminClaims,
    settings: Settings,
) -> None:
    signature = amendment.signature
    if signature.scheme == "eip712":
        if claims.auth_type != "evm":
            raise ValueError("EIP-712 amendment requires an EVM owner session")
        if int(signature.chain_id) != settings.eip712_chain_id:
            raise ValueError("amendment chainId does not match the configured network")
        recovery = recover_evm_signer(
            amendment_typed_data(amendment, settings), signature.signature
        )
        expected = normalize_evm_address(claims.sub)
        if normalize_evm_address(signature.signer) != expected:
            raise ValueError("amendment signer does not match the collection owner")
        if normalize_evm_address(recovery.address) != expected:
            raise ValueError("amendment signature was produced by a different wallet")
        if signature.typed_data_hash.lower() != "0x" + recovery.digest.hex():
            raise ValueError("typedDataHash does not match the signed EIP-712 envelope")
        return

    if claims.auth_type != "chia_bls":
        raise ValueError("BLS amendment requires a Chia owner session")
    owner_hex = claims.sub.removeprefix("0x")
    signer_hex = signature.signer.removeprefix("0x")
    if signer_hex.lower() != owner_hex.lower():
        raise ValueError("amendment signer does not match the collection owner")
    digest = amendment_message_hash(amendment)
    if signature.message_hash.lower() != "0x" + digest.hex():
        raise ValueError("messageHash does not match the canonical amendment envelope")
    try:
        public_key = G1Element.from_bytes(bytes.fromhex(owner_hex))
        bls_signature = G2Element.from_bytes(bytes.fromhex(signature.signature.removeprefix("0x")))
    except (ValueError, AssertionError) as exc:
        raise ValueError("invalid BLS public key or amendment signature") from exc
    if not AugSchemeMPL.verify(public_key, digest, bls_signature):
        raise ValueError("invalid BLS amendment signature")


__all__ = [
    "amendment_message_hash",
    "amendment_typed_data",
    "verify_amendment_signature",
]
