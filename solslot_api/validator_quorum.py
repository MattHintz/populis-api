"""Private 2-of-3 validator coordinator for Chia credential stamps."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from chia_rs import AugSchemeMPL, G1Element, G2Element
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentResolution,
    PaymentTransition,
)
from solslot_puzzles.payment_artifacts_v3 import (
    StripeDisputeState,
    StripePaymentStatus,
    StripeRefundState,
    payment_attestation_from_json,
    purchase_artifact_from_json as purchase_artifact_v3_from_json,
    stripe_evidence_from_json,
    stripe_receipt_from_json,
)
from solslot_puzzles.zkpassport_bridge_driver import require_genesis_validator_set

from .config import Settings
from .faucet import AGG_SIG_ME_DATA


logger = logging.getLogger(__name__)


class ValidatorQuorumError(RuntimeError):
    """Raised when independent validator signatures cannot reach quorum."""


def _hex(value: str, size: int, field: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hex") from exc
    if len(raw) != size:
        raise ValueError(f"{field} must be {size} bytes")
    return normalized


def base_settlement_evidence_hash(evidence: dict[str, Any]) -> str:
    """Hash the authenticated Base deposit evidence used for terminal settlement."""
    encoded = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


class ValidatorClaim(BaseModel):
    """All public evidence a signer must independently revalidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    artifact_hash: str
    vault_launcher_id: str
    current_vault_coin_id: str
    owner_key: str
    owner_auth_type: int = Field(..., ge=1, le=3)
    owner_authorization: str
    owner_authorization_hash: str
    current_timestamp: int = Field(..., ge=1)
    evm_transaction_hash: str
    evm_block_number: int = Field(..., ge=0)
    emitter_address: str
    policy_version: int = Field(..., ge=2)
    identity_attest_root: str
    attestation_leaf_hash: str
    scoped_nullifier: str
    nullifier_type: int = Field(..., ge=0)
    service_scope_hash: str
    service_subscope_hash: str
    proof_timestamp: int = Field(..., ge=1)
    bridge_policy_hash: str
    bridge_parent_id: str
    bridge_amount: int = Field(..., gt=0)
    bridge_coin_id: str
    validator_message: str

    @field_validator(
        "artifact_hash",
        "vault_launcher_id",
        "current_vault_coin_id",
        "owner_authorization_hash",
        "identity_attest_root",
        "attestation_leaf_hash",
        "scoped_nullifier",
        "service_scope_hash",
        "service_subscope_hash",
        "bridge_policy_hash",
        "bridge_parent_id",
        "bridge_coin_id",
        "validator_message",
    )
    @classmethod
    def _hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @field_validator("evm_transaction_hash")
    @classmethod
    def _tx_hash(cls, value: str) -> str:
        return _hex(value, 32, "evm_transaction_hash")

    @field_validator("emitter_address")
    @classmethod
    def _address(cls, value: str) -> str:
        return _hex(value, 20, "emitter_address")

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(f"unsupported Chia network: {self.network}")
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.bridge_coin_id[2:])
            + additional_data
        )


class PrimaryPurchaseClaim(BaseModel):
    """Public evidence for one governed native SmartDeed delivery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    purchase_artifact: dict[str, Any]
    buyer_offer: str = Field(..., min_length=16, max_length=2_000_000)
    deed_coin_id: str
    deed_puzzle_hash: str
    smart_deed_inner_hash: str
    protocol_puzzle_hash: str
    credential_vault_coin_id: str
    credential_identity_root: str
    credential_policy_version: int = Field(..., ge=2)
    credential_bridge_policy_hash: str
    credential_owner_auth_type: int
    credential_owner_key: str

    @field_validator(
        "genesis_artifact_hash",
        "deed_coin_id",
        "deed_puzzle_hash",
        "smart_deed_inner_hash",
        "protocol_puzzle_hash",
        "credential_vault_coin_id",
        "credential_identity_root",
        "credential_bridge_policy_hash",
    )
    @classmethod
    def _purchase_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @model_validator(mode="after")
    def _validate_credential_owner(self) -> "PrimaryPurchaseClaim":
        expected_size = {1: 48, 3: 33}.get(self.credential_owner_auth_type)
        if expected_size is None:
            raise ValueError("credential owner auth type must be BLS or secp256k1")
        normalized = _hex(
            self.credential_owner_key,
            expected_size,
            "credential_owner_key",
        )
        object.__setattr__(self, "credential_owner_key", normalized)
        if self.credential_owner_auth_type == 1:
            G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def purchase_id(self) -> str:
        value = self.purchase_artifact.get("purchaseId")
        if not isinstance(value, str):
            raise ValidatorQuorumError("purchase artifact has no purchase ID")
        return _hex(value, 32, "purchaseId")

    def purchase_artifact_hash(self) -> str:
        value = self.purchase_artifact.get("artifactHash")
        if not isinstance(value, str):
            raise ValidatorQuorumError("purchase artifact has no artifact hash")
        return _hex(value, 32, "artifactHash")

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        return (
            bytes.fromhex(self.purchase_artifact_hash()[2:])
            + bytes.fromhex(self.deed_coin_id[2:])
            + additional_data
        )


class InventoryReservationClaim(BaseModel):
    """Public evidence for one governed SmartDeed inventory reservation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    purchase_artifact: dict[str, Any]
    reservation_expires_at: int = Field(..., ge=1)
    available_coin_id: str
    available_puzzle_hash: str
    reserved_coin_id: str
    reserved_puzzle_hash: str
    smart_deed_inner_hash: str
    protocol_puzzle_hash: str
    credential_vault_coin_id: str
    credential_identity_root: str
    credential_policy_version: int = Field(..., ge=2)
    credential_bridge_policy_hash: str
    credential_owner_auth_type: int
    credential_owner_key: str
    validator_message: str

    @field_validator(
        "genesis_artifact_hash",
        "available_coin_id",
        "available_puzzle_hash",
        "reserved_coin_id",
        "reserved_puzzle_hash",
        "smart_deed_inner_hash",
        "protocol_puzzle_hash",
        "credential_vault_coin_id",
        "credential_identity_root",
        "credential_bridge_policy_hash",
        "validator_message",
    )
    @classmethod
    def _reservation_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @model_validator(mode="after")
    def _validate_reservation(self) -> "InventoryReservationClaim":
        expected_size = {1: 48, 3: 33}.get(
            self.credential_owner_auth_type
        )
        if expected_size is None:
            raise ValueError(
                "credential owner auth type must be BLS or secp256k1"
            )
        normalized = _hex(
            self.credential_owner_key,
            expected_size,
            "credential_owner_key",
        )
        object.__setattr__(self, "credential_owner_key", normalized)
        if self.credential_owner_auth_type == 1:
            G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        try:
            purchase_artifact_v3_from_json(self.purchase_artifact)
        except (PaymentArtifactError, TypeError, ValueError) as exc:
            raise ValueError("inventory purchase artifact is invalid") from exc
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def purchase_id(self) -> str:
        purchase = purchase_artifact_v3_from_json(self.purchase_artifact)
        return "0x" + bytes(purchase.purchase_id).hex()

    def purchase_artifact_hash(self) -> str:
        purchase = purchase_artifact_v3_from_json(self.purchase_artifact)
        return "0x" + bytes(purchase.artifact_hash).hex()

    def deed_launcher_id(self) -> str:
        purchase = purchase_artifact_v3_from_json(self.purchase_artifact)
        return "0x" + bytes(purchase.deed_launcher_id).hex()

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.available_coin_id[2:])
            + additional_data
        )


class InventoryExtensionClaim(BaseModel):
    """Evidence for one payment-backed reservation extension."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: str = Field(pattern=r"^(PROCESSING|SETTLEMENT)$")
    network: str
    genesis_artifact_hash: str
    purchase_artifact: dict[str, Any]
    stripe_evidence: dict[str, Any]
    current_expires_at: int = Field(..., ge=1)
    next_expires_at: int = Field(..., ge=1)
    current_coin_id: str
    current_puzzle_hash: str
    next_coin_id: str
    next_puzzle_hash: str
    smart_deed_inner_hash: str
    protocol_puzzle_hash: str
    credential_vault_coin_id: str
    credential_identity_root: str
    credential_policy_version: int = Field(..., ge=2)
    credential_bridge_policy_hash: str
    credential_owner_auth_type: int
    credential_owner_key: str
    validator_message: str

    @field_validator(
        "genesis_artifact_hash",
        "current_coin_id",
        "current_puzzle_hash",
        "next_coin_id",
        "next_puzzle_hash",
        "smart_deed_inner_hash",
        "protocol_puzzle_hash",
        "credential_vault_coin_id",
        "credential_identity_root",
        "credential_bridge_policy_hash",
        "validator_message",
    )
    @classmethod
    def _extension_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @model_validator(mode="after")
    def _validate_extension(self) -> "InventoryExtensionClaim":
        if (
            self.next_expires_at <= self.current_expires_at
            or self.next_expires_at
            > self.current_expires_at + 11 * 24 * 60 * 60
        ):
            raise ValueError(
                "reservation extension must advance by at most eleven days"
            )
        expected_size = {1: 48, 3: 33}.get(
            self.credential_owner_auth_type
        )
        if expected_size is None:
            raise ValueError(
                "credential owner auth type must be BLS or secp256k1"
            )
        normalized = _hex(
            self.credential_owner_key,
            expected_size,
            "credential_owner_key",
        )
        object.__setattr__(self, "credential_owner_key", normalized)
        if self.credential_owner_auth_type == 1:
            G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        try:
            purchase_artifact_v3_from_json(self.purchase_artifact)
            evidence = stripe_evidence_from_json(self.stripe_evidence)
        except (PaymentArtifactError, TypeError, ValueError) as exc:
            raise ValueError(
                "inventory extension evidence is invalid"
            ) from exc
        expected_status = 2 if self.phase == "PROCESSING" else 3
        if int(evidence.status) != expected_status:
            raise ValueError(
                "inventory extension phase does not match Stripe status"
            )
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def purchase_id(self) -> str:
        purchase = purchase_artifact_v3_from_json(self.purchase_artifact)
        return "0x" + bytes(purchase.purchase_id).hex()

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.current_coin_id[2:])
            + additional_data
        )


class InventoryReleaseClaim(BaseModel):
    """Evidence for returning one Stripe reservation to inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: str = Field(
        pattern=r"^(PAYMENT_FAILED|DELIVERY_TIMEOUT|PRESALE_REFUND)$"
    )
    event_type: str = Field(min_length=1, max_length=128)
    network: str
    genesis_artifact_hash: str
    purchase_artifact: dict[str, Any]
    stripe_evidence: dict[str, Any]
    current_expires_at: int = Field(..., ge=1)
    current_coin_id: str
    current_puzzle_hash: str
    next_coin_id: str
    next_puzzle_hash: str
    expected_delivery_coin_id: str
    smart_deed_inner_hash: str
    protocol_puzzle_hash: str
    request_hash: str | None = None
    requested_at: int | None = Field(default=None, ge=1)
    validator_message: str

    @field_validator(
        "genesis_artifact_hash",
        "current_coin_id",
        "current_puzzle_hash",
        "next_coin_id",
        "next_puzzle_hash",
        "expected_delivery_coin_id",
        "smart_deed_inner_hash",
        "protocol_puzzle_hash",
        "validator_message",
    )
    @classmethod
    def _release_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @field_validator("request_hash")
    @classmethod
    def _release_request_hash(cls, value: str | None) -> str | None:
        return None if value is None else _hex(value, 32, "request_hash")

    @model_validator(mode="after")
    def _validate_release(self) -> "InventoryReleaseClaim":
        try:
            purchase = purchase_artifact_v3_from_json(
                self.purchase_artifact
            )
            evidence = stripe_evidence_from_json(self.stripe_evidence)
        except (PaymentArtifactError, TypeError, ValueError) as exc:
            raise ValueError("inventory release evidence is invalid") from exc
        if (
            evidence.amount_minor
            != purchase.subtotal_minor + evidence.processing_charge_minor
            or evidence.refund_state != StripeRefundState.NONE
            or evidence.refunded_minor != 0
            or evidence.dispute_state != StripeDisputeState.NONE
        ):
            raise ValueError(
                "inventory release requires exact undisputed Stripe evidence"
            )
        if self.reason == "PAYMENT_FAILED":
            if (
                self.event_type
                not in {
                    "payment_intent.payment_failed",
                    "payment_intent.canceled",
                }
                or evidence.status
                not in {
                    StripePaymentStatus.REQUIRES_PAYMENT_METHOD,
                    StripePaymentStatus.CANCELED,
                }
                or self.request_hash is not None
                or self.requested_at is not None
            ):
                raise ValueError(
                    "failed-payment release does not match Stripe state"
                )
        else:
            if (
                self.event_type != "payment_intent.succeeded"
                or evidence.status != StripePaymentStatus.SUCCEEDED
            ):
                raise ValueError(
                    "paid inventory release requires succeeded Stripe evidence"
                )
            if self.reason == "PRESALE_REFUND":
                if self.request_hash is None or self.requested_at is None:
                    raise ValueError(
                        "presale refund release requires a bound request"
                    )
            elif self.request_hash is not None or self.requested_at is not None:
                raise ValueError(
                    "delivery-timeout release cannot carry a refund request"
                )
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def purchase_id(self) -> str:
        purchase = purchase_artifact_v3_from_json(self.purchase_artifact)
        return "0x" + bytes(purchase.purchase_id).hex()

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.current_coin_id[2:])
            + additional_data
        )


class StripeSettlementClaim(BaseModel):
    """Public evidence for one exact Stripe-funded SmartDeed delivery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    pending_attestation: dict[str, Any]
    stripe_receipt: dict[str, Any]
    reservation_expires_at: int = Field(..., ge=1)
    receipt_coin_id: str
    receipt_puzzle_hash: str
    deed_coin_id: str
    deed_puzzle_hash: str
    expected_deed_output_coin_id: str
    expected_deed_output_puzzle_hash: str
    smart_deed_inner_hash: str
    protocol_puzzle_hash: str
    credential_vault_coin_id: str
    credential_identity_root: str
    credential_policy_version: int = Field(..., ge=2)
    credential_bridge_policy_hash: str
    credential_owner_auth_type: int
    credential_owner_key: str

    @field_validator(
        "genesis_artifact_hash",
        "receipt_coin_id",
        "receipt_puzzle_hash",
        "deed_coin_id",
        "deed_puzzle_hash",
        "expected_deed_output_coin_id",
        "expected_deed_output_puzzle_hash",
        "smart_deed_inner_hash",
        "protocol_puzzle_hash",
        "credential_vault_coin_id",
        "credential_identity_root",
        "credential_bridge_policy_hash",
    )
    @classmethod
    def _stripe_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @model_validator(mode="after")
    def _validate_credential_owner(self) -> "StripeSettlementClaim":
        expected_size = {1: 48, 3: 33}.get(self.credential_owner_auth_type)
        if expected_size is None:
            raise ValueError(
                "credential owner auth type must be BLS or secp256k1"
            )
        normalized = _hex(
            self.credential_owner_key,
            expected_size,
            "credential_owner_key",
        )
        object.__setattr__(self, "credential_owner_key", normalized)
        if self.credential_owner_auth_type == 1:
            G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        try:
            pending = payment_attestation_from_json(
                self.pending_attestation
            )
            stripe_receipt_from_json(self.stripe_receipt)
        except (PaymentArtifactError, TypeError, ValueError) as exc:
            raise ValueError("Stripe settlement receipt is invalid") from exc
        receipt = stripe_receipt_from_json(self.stripe_receipt)
        if (
            pending.transition != PaymentTransition.PENDING
            or pending.resolution != PaymentResolution.NONE
            or pending.purchase_id != receipt.artifact.purchase_id
            or pending.artifact_hash != receipt.artifact.artifact_hash
            or receipt.attestation.previous_attestation_hash
            != pending.attestation_hash
        ):
            raise ValueError(
                "Stripe settlement does not reference its pending attestation"
            )
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def purchase_id(self) -> str:
        receipt = stripe_receipt_from_json(self.stripe_receipt)
        return "0x" + bytes(receipt.artifact.purchase_id).hex()

    def payment_intent_id(self) -> str:
        return stripe_receipt_from_json(
            self.stripe_receipt
        ).evidence.payment_intent_id

    def event_id(self) -> str:
        return stripe_receipt_from_json(
            self.stripe_receipt
        ).evidence.event_id

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        receipt = stripe_receipt_from_json(self.stripe_receipt)
        return (
            bytes(receipt.receipt_hash)
            + bytes.fromhex(self.receipt_coin_id[2:])
            + additional_data
        )


class VoucherIssuanceClaim(BaseModel):
    """Public evidence for one paid, chain-bound RC20 voucher issuance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    series_terms: dict[str, Any]
    voucher_commitment: dict[str, Any]
    purchase_artifact: dict[str, Any]
    series_coin_id: str
    series_sold_count: int = Field(..., ge=0)
    series_redeemed_count: int = Field(..., ge=0)
    series_refunded_count: int = Field(..., ge=0)
    series_phase: int = Field(..., ge=1, le=3)
    series_launched_at: int = Field(..., ge=0)
    purchase_launcher_coin_id: str
    payment_evidence: dict[str, Any]
    buyer_offer: str | None = Field(default=None, min_length=16, max_length=2_000_000)
    validator_message: str

    @field_validator(
        "genesis_artifact_hash",
        "series_coin_id",
        "purchase_launcher_coin_id",
        "validator_message",
    )
    @classmethod
    def _issuance_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def global_payment_id(self) -> str:
        value = self.voucher_commitment.get("globalPaymentId")
        if not isinstance(value, str):
            raise ValidatorQuorumError("voucher has no global payment ID")
        return _hex(value, 32, "globalPaymentId")

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.series_coin_id[2:])
            + additional_data
        )


class VoucherSeriesPhaseClaim(BaseModel):
    """Chain evidence for one validator-governed series phase advance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    series_terms: dict[str, Any]
    series_coin_id: str
    series_sold_count: int = Field(..., ge=0)
    series_redeemed_count: int = Field(..., ge=0)
    series_refunded_count: int = Field(..., ge=0)
    series_phase: int = Field(..., ge=1, le=3)
    series_launched_at: int = Field(..., ge=0)
    transition: int = Field(..., ge=2, le=3)
    launch_anchor: int = Field(..., ge=0)
    deed_launcher_ids: list[str] = Field(default_factory=list, max_length=100_000)
    governance_execution_ids: list[str] = Field(
        default_factory=list,
        max_length=100_000,
    )
    validator_message: str

    @field_validator(
        "genesis_artifact_hash",
        "series_coin_id",
        "validator_message",
    )
    @classmethod
    def _phase_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @field_validator("deed_launcher_ids", "governance_execution_ids")
    @classmethod
    def _phase_hex32_list(cls, value: list[str], info) -> list[str]:
        return [_hex(item, 32, info.field_name) for item in value]

    @model_validator(mode="after")
    def _validate_phase_transition(self) -> "VoucherSeriesPhaseClaim":
        if self.transition not in {2, 3}:
            raise ValueError("series phase transition must launch or cancel")
        if self.transition == 2:
            if self.launch_anchor <= 0:
                raise ValueError("series launch requires a positive launch anchor")
            if not self.deed_launcher_ids:
                raise ValueError("series launch requires governed deed evidence")
            if len(self.deed_launcher_ids) != len(self.governance_execution_ids):
                raise ValueError("series launch governance evidence is incomplete")
        elif (
            self.launch_anchor != 0
            or self.deed_launcher_ids
            or self.governance_execution_ids
        ):
            raise ValueError("series cancellation cannot carry launch evidence")
        if len(set(self.deed_launcher_ids)) != len(self.deed_launcher_ids):
            raise ValueError("series launch deed evidence contains duplicates")
        if len(set(self.governance_execution_ids)) != len(
            self.governance_execution_ids
        ):
            raise ValueError("series launch execution evidence contains duplicates")
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.series_coin_id[2:])
            + additional_data
        )


class VoucherTransitionClaim(BaseModel):
    """Evidence for one terminal RC20 voucher refund or redemption."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    series_terms: dict[str, Any]
    voucher_commitment: dict[str, Any]
    purchase_artifact: dict[str, Any]
    series_coin_id: str
    series_sold_count: int = Field(..., ge=0)
    series_redeemed_count: int = Field(..., ge=0)
    series_refunded_count: int = Field(..., ge=0)
    series_phase: int = Field(..., ge=1, le=3)
    series_launched_at: int = Field(..., ge=0)
    voucher_launcher_id: str
    voucher_coin_id: str
    payment_coin_id: str
    vault_launcher_id: str
    vault_coin_id: str | None = None
    vault_identity_attest_root: str | None = None
    vault_owner_auth_type: int | None = None
    vault_owner_key: str | None = None
    owner_authorization: str = ""
    current_timestamp: int = Field(..., ge=1)
    action: int = Field(..., ge=1, le=4)
    deed_coin_id: str | None = None
    deed_puzzle_hash: str | None = None
    smart_deed_inner_hash: str | None = None
    protocol_puzzle_hash: str | None = None
    buyer_offer: str | None = Field(default=None, min_length=16, max_length=2_000_000)
    payment_evidence: dict[str, Any] | None = None
    external_settlement_evidence_hash: str | None = None
    external_validator_message: str | None = None
    reservation_expires_at: int | None = Field(default=None, ge=1)
    validator_message: str

    @field_validator(
        "genesis_artifact_hash",
        "series_coin_id",
        "voucher_launcher_id",
        "voucher_coin_id",
        "payment_coin_id",
        "vault_launcher_id",
        "validator_message",
    )
    @classmethod
    def _transition_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @field_validator(
        "deed_coin_id",
        "deed_puzzle_hash",
        "smart_deed_inner_hash",
        "protocol_puzzle_hash",
        "vault_coin_id",
        "vault_identity_attest_root",
        "external_settlement_evidence_hash",
        "external_validator_message",
    )
    @classmethod
    def _optional_transition_hex32(cls, value: str | None, info) -> str | None:
        return None if value is None else _hex(value, 32, info.field_name)

    @model_validator(mode="after")
    def _validate_owner_and_action(self) -> "VoucherTransitionClaim":
        if self.action not in {1, 2, 3, 4}:
            raise ValueError("voucher transition action is invalid")
        owner_fields = (
            self.vault_coin_id,
            self.vault_identity_attest_root,
            self.vault_owner_auth_type,
            self.vault_owner_key,
        )
        if self.action == 2:
            if any(value is not None for value in owner_fields):
                raise ValueError(
                    "expired refund cannot carry current vault ownership evidence"
                )
            if self.owner_authorization:
                raise ValueError("expired refund cannot request an owner signature")
        else:
            if any(value is None for value in owner_fields):
                raise ValueError("voucher transition requires current vault evidence")
            expected_size = {1: 48, 3: 33}.get(self.vault_owner_auth_type)
            if expected_size is None:
                raise ValueError("voucher vault owner must use BLS or secp256k1")
            normalized = _hex(
                self.vault_owner_key,  # type: ignore[arg-type]
                expected_size,
                "vault_owner_key",
            )
            object.__setattr__(self, "vault_owner_key", normalized)
            if self.vault_owner_auth_type == 1:
                G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        redemption_fields = (
            self.deed_coin_id,
            self.deed_puzzle_hash,
            self.smart_deed_inner_hash,
            self.protocol_puzzle_hash,
            self.buyer_offer,
        )
        if self.action == 3:
            if any(value is None for value in redemption_fields):
                raise ValueError("voucher redemption requires exact deed evidence")
            if self.owner_authorization:
                raise ValueError("voucher redemption cannot request a second owner signature")
        elif self.action in {1, 4}:
            if any(value is not None for value in redemption_fields):
                raise ValueError("voucher refund cannot carry deed evidence")
            assert self.vault_owner_auth_type is not None
            auth_size = 96 if self.vault_owner_auth_type == 1 else 65
            object.__setattr__(
                self,
                "owner_authorization",
                _hex(self.owner_authorization, auth_size, "owner_authorization"),
            )
        else:
            if any(value is not None for value in redemption_fields):
                raise ValueError("voucher refund cannot carry deed evidence")
        voucher_schema = self.voucher_commitment.get("schema")
        payment_rail = self.voucher_commitment.get("paymentRail")
        is_base = payment_rail == 1
        is_stripe_v3 = (
            voucher_schema == "solslot.voucher-commitment.v3"
            and payment_rail == 3
        )
        external_fields = (
            self.payment_evidence,
            self.external_settlement_evidence_hash,
            self.external_validator_message,
        )
        if is_base or is_stripe_v3:
            if any(value is None for value in external_fields):
                raise ValueError(
                    "external voucher transition requires authenticated settlement evidence"
                )
        elif any(value is not None for value in external_fields):
            raise ValueError(
                "native voucher transition cannot carry external settlement evidence"
            )
        if is_stripe_v3:
            if self.action == 3 and self.reservation_expires_at is None:
                raise ValueError(
                    "Stripe voucher redemption requires the exact reservation expiry"
                )
        elif self.reservation_expires_at is not None:
            raise ValueError(
                "legacy voucher transition cannot carry a Stripe reservation expiry"
            )
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def global_payment_id(self) -> str:
        value = self.voucher_commitment.get("globalPaymentId")
        if not isinstance(value, str):
            raise ValidatorQuorumError("voucher has no global payment ID")
        return _hex(value, 32, "globalPaymentId")

    def signature_messages(self) -> tuple[bytes, ...]:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        inner = bytes.fromhex(self.validator_message[2:])
        messages = tuple(
            inner + bytes.fromhex(coin_id[2:]) + additional_data
            for coin_id in (self.series_coin_id, self.voucher_coin_id)
        )
        payment_message = (
            bytes.fromhex(self.external_validator_message[2:])
            if self.external_validator_message is not None
            else inner
        )
        messages += (
            payment_message
            + bytes.fromhex(self.payment_coin_id[2:])
            + additional_data,
        )
        if self.action == 3:
            artifact_hash = self.purchase_artifact.get("artifactHash")
            if not isinstance(artifact_hash, str) or self.deed_coin_id is None:
                raise ValidatorQuorumError("voucher redemption has no deed binding")
            messages += (
                bytes.fromhex(_hex(artifact_hash, 32, "artifactHash")[2:])
                + bytes.fromhex(self.deed_coin_id[2:])
                + additional_data,
            )
        return messages


class ValidatorSignatureResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claimHash: str
    signerIndex: int = Field(..., ge=0)
    validatorPubkey: str
    signature: str


class ValidatorHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    signerIndex: int = Field(..., ge=0, le=2)
    validatorPubkey: str
    apiCommit: str
    protocolCommit: str
    network: str
    bridgePolicyHash: str
    evmAddresses: dict[str, str]
    artifactHash: str | None = None
    artifactReady: bool
    ledgerReady: bool
    stripeSettlementReady: bool


@dataclass(frozen=True)
class ValidatorQuorumResult:
    signer_indices: tuple[int, ...]
    aggregated_signature: G2Element
    claim_hash: str


def configured_validator_pubkeys(settings: Settings) -> tuple[bytes, ...]:
    try:
        pubkeys = tuple(
            bytes.fromhex(value.removeprefix("0x"))
            for value in settings.zkpassport_validator_pubkeys
        )
    except ValueError as exc:
        raise ValidatorQuorumError("validator public key configuration is invalid") from exc
    try:
        validator_set = require_genesis_validator_set(
            pubkeys,
            settings.zkpassport_validator_threshold,
        )
    except ValueError as exc:
        raise ValidatorQuorumError(str(exc)) from exc
    if len(settings.zkpassport_validator_urls) != len(validator_set.pubkeys):
        raise ValidatorQuorumError("validator URL and public key counts do not match")
    return validator_set.pubkeys


def configured_bridge_policy_hash(settings: Settings) -> str:
    pubkeys = configured_validator_pubkeys(settings)
    validator_set = require_genesis_validator_set(
        pubkeys,
        settings.zkpassport_validator_threshold,
    )
    return "0x" + bytes(validator_set.policy_hash).hex()


def _private_validator_client(settings: Settings) -> httpx.AsyncClient:
    ca_path = Path(str(settings.zkpassport_validator_mtls_ca_path or ""))
    cert_path = Path(str(settings.zkpassport_validator_mtls_cert_path or ""))
    key_path = Path(str(settings.zkpassport_validator_mtls_key_path or ""))
    for path, label in (
        (ca_path, "validator CA"),
        (cert_path, "validator client certificate"),
        (key_path, "validator client key"),
    ):
        if not path.is_file():
            raise ValidatorQuorumError(f"{label} file is unavailable")

    try:
        ssl_context = ssl.create_default_context(cafile=str(ca_path))
        ssl_context.load_cert_chain(
            certfile=str(cert_path),
            keyfile=str(key_path),
        )
    except (OSError, ssl.SSLError) as exc:
        raise ValidatorQuorumError(
            "validator mTLS client credentials are invalid"
        ) from exc

    return httpx.AsyncClient(
        verify=ssl_context,
        timeout=settings.zkpassport_validator_timeout_seconds,
        trust_env=False,
    )


async def probe_validator_health(
    settings: Settings,
    *,
    expected_api_commit: str,
    expected_protocol_commit: str,
    expected_network: str,
    expected_bridge_policy_hash: str,
    expected_evm_addresses: dict[str, str],
    expected_artifact_ready: bool | None = None,
    expected_artifact_hash: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[ValidatorHealthResponse, ...]:
    """Contact every private signer and bind health to the ceremony plan."""
    pubkeys = configured_validator_pubkeys(settings)
    if configured_bridge_policy_hash(settings) != expected_bridge_policy_hash.lower():
        raise ValidatorQuorumError(
            "ceremony bridge policy does not match configured validator roster"
        )
    normalized_addresses = {
        key: value.lower() for key, value in expected_evm_addresses.items()
    }
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_health(index: int, url: str) -> ValidatorHealthResponse:
        response = await client.get(url.rstrip("/") + "/health")
        response.raise_for_status()
        parsed = ValidatorHealthResponse.model_validate(response.json())
        expected_pubkey = "0x" + pubkeys[index].hex()
        checks = (
            (parsed.status, "healthy", "status"),
            (parsed.signerIndex, index, "signer index"),
            (parsed.validatorPubkey.lower(), expected_pubkey, "validator public key"),
            (parsed.apiCommit, expected_api_commit, "API commit"),
            (parsed.protocolCommit, expected_protocol_commit, "protocol commit"),
            (parsed.network, expected_network, "network"),
            (
                parsed.bridgePolicyHash.lower(),
                expected_bridge_policy_hash.lower(),
                "bridge policy",
            ),
            (
                {key: value.lower() for key, value in parsed.evmAddresses.items()},
                normalized_addresses,
                "EVM addresses",
            ),
            (parsed.ledgerReady, True, "signature ledger"),
        )
        for observed, expected, label in checks:
            if observed != expected:
                raise ValidatorQuorumError(
                    f"validator signer {index} {label} does not match ceremony"
                )
        if (
            expected_artifact_ready is not None
            and parsed.artifactReady is not expected_artifact_ready
        ):
            raise ValidatorQuorumError(
                f"validator signer {index} artifact readiness does not match ceremony phase"
            )
        if expected_artifact_hash is not None and (
            not parsed.artifactReady
            or str(parsed.artifactHash or "").lower()
            != expected_artifact_hash.lower()
        ):
            raise ValidatorQuorumError(
                f"validator signer {index} artifact hash does not match finalized genesis"
            )
        return parsed

    try:
        results = await asyncio.gather(
            *(
                request_health(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            ),
            return_exceptions=True,
        )
    finally:
        if owns_client:
            await client.aclose()
    failures = [
        f"signer {index}: {result}"
        for index, result in enumerate(results)
        if isinstance(result, BaseException)
    ]
    if failures:
        raise ValidatorQuorumError(
            "live validator preflight failed: " + "; ".join(failures)
        )
    return tuple(result for result in results if isinstance(result, ValidatorHealthResponse))


async def collect_validator_quorum(
    settings: Settings,
    claim: ValidatorClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect and verify an exact 2-of-3 signature set over ``claim``."""

    pubkeys = configured_validator_pubkeys(settings)
    expected_policy_hash = configured_bridge_policy_hash(settings)
    if claim.bridge_policy_hash != expected_policy_hash:
        raise ValidatorQuorumError("claim bridge policy does not match configured validators")
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()

    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(index: int, url: str) -> tuple[int, G2Element] | None:
        endpoint = url.rstrip("/") + "/v1/zkpassport/sign"
        try:
            response = await client.post(
                endpoint,
                json={"claim": claim.model_dump(mode="json"), "claimHash": claim_hash},
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash:
                raise ValueError("claim hash mismatch")
            if parsed.signerIndex != index:
                raise ValueError("signer index mismatch")
            configured_pubkey = pubkeys[index]
            response_pubkey = bytes.fromhex(parsed.validatorPubkey.removeprefix("0x"))
            if response_pubkey != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            public_key = G1Element.from_bytes(configured_pubkey)
            if not AugSchemeMPL.verify(public_key, message, signature):
                raise ValueError("invalid validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001 - one signer may be unavailable
            logger.warning("validator signer %s rejected or unavailable: %s", index, exc)
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()

    valid = sorted((item for item in responses if item is not None), key=lambda item: item[0])
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            f"validator quorum unavailable: received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_primary_purchase_quorum(
    settings: Settings,
    claim: PrimaryPurchaseClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect the configured quorum for one already wallet-signed offer."""

    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int,
        url: str,
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/primary-purchase/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(
                response.json()
            )
            if parsed.claimHash.lower() != claim_hash:
                raise ValueError("claim hash mismatch")
            if parsed.signerIndex != index:
                raise ValueError("signer index mismatch")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(
                parsed.validatorPubkey.removeprefix("0x")
            ) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey),
                message,
                signature,
            ):
                raise ValueError("invalid validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "primary purchase signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(
                    settings.zkpassport_validator_urls
                )
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "primary purchase validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_inventory_reservation_quorum(
    settings: Settings,
    claim: InventoryReservationClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect the configured quorum for one exact deed reservation."""

    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int,
        url: str,
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/inventory-reservation/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(
                response.json()
            )
            if (
                parsed.claimHash.lower() != claim_hash
                or parsed.signerIndex != index
            ):
                raise ValueError(
                    "inventory signer response does not match the claim"
                )
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(
                parsed.validatorPubkey.removeprefix("0x")
            ) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey),
                message,
                signature,
            ):
                raise ValueError("invalid inventory reservation signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "inventory reservation signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(
                    settings.zkpassport_validator_urls
                )
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "inventory reservation validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_inventory_extension_quorum(
    settings: Settings,
    claim: InventoryExtensionClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect the configured quorum for one exact reservation extension."""

    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int,
        url: str,
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/inventory-extension/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(
                response.json()
            )
            if (
                parsed.claimHash.lower() != claim_hash
                or parsed.signerIndex != index
            ):
                raise ValueError(
                    "inventory extension signer response does not match"
                )
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(
                parsed.validatorPubkey.removeprefix("0x")
            ) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey),
                message,
                signature,
            ):
                raise ValueError("invalid inventory extension signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "inventory extension signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(
                    settings.zkpassport_validator_urls
                )
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "inventory extension validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_inventory_release_quorum(
    settings: Settings,
    claim: InventoryReleaseClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect quorum for one exact return to canonical inventory."""

    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int,
        url: str,
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/inventory-release/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(
                response.json()
            )
            if (
                parsed.claimHash.lower() != claim_hash
                or parsed.signerIndex != index
            ):
                raise ValueError(
                    "inventory release signer response does not match"
                )
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(
                parsed.validatorPubkey.removeprefix("0x")
            ) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey),
                message,
                signature,
            ):
                raise ValueError("invalid inventory release signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "inventory release signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(
                    settings.zkpassport_validator_urls
                )
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "inventory release validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_stripe_settlement_quorum(
    settings: Settings,
    claim: StripeSettlementClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect two independent signatures for one retrieved Stripe receipt."""

    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int,
        url: str,
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/stripe-settlement/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(
                response.json()
            )
            if (
                parsed.claimHash.lower() != claim_hash
                or parsed.signerIndex != index
            ):
                raise ValueError(
                    "Stripe signer response does not match the claim"
                )
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(
                parsed.validatorPubkey.removeprefix("0x")
            ) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey),
                message,
                signature,
            ):
                raise ValueError("invalid Stripe settlement signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Stripe settlement signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(
                    settings.zkpassport_validator_urls
                )
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "Stripe settlement validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_voucher_issuance_quorum(
    settings: Settings,
    claim: VoucherIssuanceClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect two independent signatures for an exact voucher issuance."""
    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int, url: str
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/voucher-issuance/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash or parsed.signerIndex != index:
                raise ValueError("voucher signer response does not match claim")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(parsed.validatorPubkey.removeprefix("0x")) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey), message, signature
            ):
                raise ValueError("invalid validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "voucher issuance signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "voucher issuance validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_voucher_transition_quorum(
    settings: Settings,
    claim: VoucherTransitionClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect quorum signatures for all three terminal protocol spends."""
    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    messages = claim.signature_messages()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int, url: str
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/voucher-transition/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash or parsed.signerIndex != index:
                raise ValueError("voucher transition signer response does not match claim")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(parsed.validatorPubkey.removeprefix("0x")) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            public_key = G1Element.from_bytes(configured_pubkey)
            if not AugSchemeMPL.aggregate_verify(
                [public_key] * len(messages),
                list(messages),
                signature,
            ):
                raise ValueError("invalid voucher transition validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "voucher transition signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "voucher transition validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_voucher_series_phase_quorum(
    settings: Settings,
    claim: VoucherSeriesPhaseClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect two independent signatures for an exact series phase spend."""
    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int, url: str
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/voucher-series-phase/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash or parsed.signerIndex != index:
                raise ValueError("series phase signer response does not match claim")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(parsed.validatorPubkey.removeprefix("0x")) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey), message, signature
            ):
                raise ValueError("invalid series phase validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "series phase signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "series phase validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


__all__ = [
    "ValidatorClaim",
    "PrimaryPurchaseClaim",
    "InventoryReservationClaim",
    "InventoryExtensionClaim",
    "InventoryReleaseClaim",
    "StripeSettlementClaim",
    "VoucherIssuanceClaim",
    "VoucherSeriesPhaseClaim",
    "VoucherTransitionClaim",
    "ValidatorHealthResponse",
    "ValidatorQuorumError",
    "ValidatorQuorumResult",
    "base_settlement_evidence_hash",
    "collect_validator_quorum",
    "collect_primary_purchase_quorum",
    "collect_inventory_reservation_quorum",
    "collect_inventory_extension_quorum",
    "collect_inventory_release_quorum",
    "collect_stripe_settlement_quorum",
    "collect_voucher_issuance_quorum",
    "collect_voucher_series_phase_quorum",
    "collect_voucher_transition_quorum",
    "configured_bridge_policy_hash",
    "configured_validator_pubkeys",
    "probe_validator_health",
]
