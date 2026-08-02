"""Canonical provider evidence for Base USDC protocol-asset delivery."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Mapping

from chia_rs.sized_bytes import bytes32

from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError, PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    ExternalSettlementReceiptV1,
    PurchaseArtifactV3,
    PurchaseBatchSettlementReceiptV1,
    PurchaseBatchV1,
    build_external_settlement_receipt_v1,
    build_purchase_batch_settlement_receipt_v1,
)
from solslot_puzzles.voucher_presale_v2_driver import (
    curry_direct_base_result_authorization,
)


_BASE_PROVIDER_TAG = b"SOLSLOT_BASE_ESCROW_PROVIDER_V1"


def canonical_base_evidence_json(evidence: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(evidence),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def base_evidence_hash(evidence: Mapping[str, Any]) -> bytes32:
    return bytes32(sha256(canonical_base_evidence_json(evidence).encode("ascii")).digest())


def base_provider_id(
    *,
    chain_id: int,
    spoke: str,
    settlement_token: str,
) -> bytes32:
    if chain_id <= 0 or chain_id >= 1 << 64:
        raise PaymentArtifactError("Base chain ID is invalid")
    spoke_bytes = _address_bytes(spoke, "Base escrow spoke")
    token_bytes = _address_bytes(settlement_token, "Base settlement token")
    return bytes32(
        sha256(
            _BASE_PROVIDER_TAG
            + b"\x00"
            + chain_id.to_bytes(8, "big")
            + spoke_bytes
            + token_bytes
        ).digest()
    )


def build_base_settlement_receipt(
    *,
    artifact: PurchaseArtifactV3,
    evidence: Mapping[str, Any],
    result_authorization_puzzle_hash: bytes32,
) -> ExternalSettlementReceiptV1:
    if artifact.rail != PaymentRail.EVM_TEST_USD:
        raise PaymentArtifactError("Base receipt requires an EVM USDC artifact")
    source = evidence.get("source")
    if not isinstance(source, Mapping):
        raise PaymentArtifactError("Base evidence source is missing")
    global_payment_id = _hex32(evidence.get("globalPaymentId"), "globalPaymentId")
    chain_id = source.get("chainId")
    observed_at = source.get("blockTimestamp")
    if isinstance(chain_id, bool) or not isinstance(chain_id, int):
        raise PaymentArtifactError("Base evidence chain ID is invalid")
    if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at <= 0:
        raise PaymentArtifactError("Base evidence timestamp is invalid")
    provider = base_provider_id(
        chain_id=chain_id,
        spoke=str(source.get("spoke") or ""),
        settlement_token=str(evidence.get("settlementToken") or ""),
    )
    return build_external_settlement_receipt_v1(
        artifact=artifact,
        provider_id=provider,
        external_reference_hash=global_payment_id,
        evidence_hash=base_evidence_hash(evidence),
        observed_at=observed_at,
        result_authorization_puzzle_hash=(
            result_authorization_puzzle_hash
        ),
    )


def base_result_authorization_puzzle_hash(
    *,
    artifact: PurchaseArtifactV3 | PurchaseBatchV1,
    evidence: Mapping[str, Any],
    return_puzzle_hash: bytes32,
) -> bytes32:
    """Derive the exact Chia result coin authorized by a Base deposit."""

    if artifact.rail != PaymentRail.EVM_TEST_USD:
        raise PaymentArtifactError(
            "Base result authorization requires an EVM USDC artifact"
        )
    global_payment_id = _hex32(
        evidence.get("globalPaymentId"),
        "globalPaymentId",
    )
    if return_puzzle_hash == bytes32.zeros:
        raise PaymentArtifactError("Base return puzzle hash cannot be zero")
    return bytes32(
        curry_direct_base_result_authorization(
            purchase_artifact_hash=(
                artifact.batch_hash
                if isinstance(artifact, PurchaseBatchV1)
                else artifact.artifact_hash
            ),
            global_payment_id=global_payment_id,
            payment_principal=(
                artifact.total_rail_amount
                if isinstance(artifact, PurchaseBatchV1)
                else artifact.rail_amount
            ),
            return_puzzle_hash=return_puzzle_hash,
        ).get_tree_hash()
    )


def build_base_batch_settlement_receipt(
    *,
    batch: PurchaseBatchV1,
    evidence: Mapping[str, Any],
    validator_pubkeys: tuple[bytes, bytes, bytes],
    result_authorization_puzzle_hash: bytes32,
) -> PurchaseBatchSettlementReceiptV1:
    """Bind one confirmed Base deposit to an exact SmartDeed batch."""

    if batch.rail != PaymentRail.EVM_TEST_USD:
        raise PaymentArtifactError("Base batch receipt requires EVM USDC")
    source = evidence.get("source")
    if not isinstance(source, Mapping):
        raise PaymentArtifactError("Base batch evidence source is missing")
    chain_id = source.get("chainId")
    observed_at = source.get("blockTimestamp")
    if isinstance(chain_id, bool) or not isinstance(chain_id, int):
        raise PaymentArtifactError("Base batch evidence chain ID is invalid")
    if isinstance(observed_at, bool) or not isinstance(observed_at, int):
        raise PaymentArtifactError("Base batch evidence timestamp is invalid")
    return build_purchase_batch_settlement_receipt_v1(
        batch=batch,
        provider_id=base_provider_id(
            chain_id=chain_id,
            spoke=str(source.get("spoke") or ""),
            settlement_token=str(evidence.get("settlementToken") or ""),
        ),
        external_reference_hash=_hex32(
            evidence.get("globalPaymentId"),
            "globalPaymentId",
        ),
        evidence_hash=base_evidence_hash(evidence),
        observed_at=observed_at,
        validator_pubkeys=validator_pubkeys,
        collected_amount_minor=batch.total_rail_amount,
        result_authorization_puzzle_hash=result_authorization_puzzle_hash,
    )


def _address_bytes(value: str, label: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        raise PaymentArtifactError(f"{label} must be a 20-byte address")
    try:
        result = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise PaymentArtifactError(f"{label} must be a 20-byte address") from exc
    if result == bytes(20):
        raise PaymentArtifactError(f"{label} cannot be zero")
    return result


def _hex32(value: Any, label: str) -> bytes32:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 66:
        raise PaymentArtifactError(f"{label} must be 32-byte hex")
    try:
        result = bytes32.from_hexstr(value)
    except ValueError as exc:
        raise PaymentArtifactError(f"{label} must be 32-byte hex") from exc
    if result == bytes32.zeros:
        raise PaymentArtifactError(f"{label} cannot be zero")
    return result


__all__ = [
    "base_evidence_hash",
    "base_provider_id",
    "base_result_authorization_puzzle_hash",
    "build_base_batch_settlement_receipt",
    "build_base_settlement_receipt",
    "canonical_base_evidence_json",
]
