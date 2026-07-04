"""Protocol purchase artifact endpoints for Sols Lot integrations.

The Sols marketplace backend owns purchase-intent state and payment rails.
Populis API owns the public, deterministic protocol artifact boundary:
build the artifact, verify its hash, and verify that a rail-specific payment
completion is bound to the artifact the buyer saw.
"""
from __future__ import annotations

import time
from typing import Annotated, Any, Literal, Mapping, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field, model_validator

from .bootstrap_manifest import _assert_public_artifact, content_hash
from .config import Settings, get_settings


router = APIRouter(prefix="/protocol", tags=["protocol-artifacts"])

ProtocolRail = Literal["chia", "base_usdc", "stripe"]
PurchaseIntentState = Literal[
    "created",
    "zk_verified",
    "artifact_ready",
    "payment_pending",
    "paid",
    "protocol_verified",
    "finalized",
    "failed",
    "expired",
    "refund_pending",
    "manual_review",
]


class ProtocolPaymentTerms(BaseModel):
    currency: str = Field(..., min_length=1, max_length=32)
    amount: int = Field(..., gt=0)
    quantity: int = Field(1, ge=1)
    payment_puzzle_hash: Optional[str] = Field(None, max_length=132)
    protocol_treasury_puzhash: Optional[str] = Field(None, max_length=132)


class BuildProtocolOfferArtifactRequest(BaseModel):
    instance_id: str = Field(..., min_length=1, max_length=128)
    purchase_intent_id: str = Field(..., min_length=1, max_length=128)
    rail: ProtocolRail
    deed_launcher_id: str = Field(..., min_length=1, max_length=132)
    property_id: str = Field(..., min_length=1, max_length=256)
    collection_id: str = Field(..., min_length=1, max_length=256)
    share_ppm: int = Field(..., ge=1, le=1_000_000)
    vault_launcher_id: str = Field(..., min_length=1, max_length=132)
    expires_at: int = Field(..., gt=0, description="Unix seconds")
    payment_terms: ProtocolPaymentTerms
    raw_offer: Optional[str] = Field(None, max_length=2_000_000)
    zk_passport_required: bool = True
    current_state: PurchaseIntentState = "created"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_zkpassport(self):
        if self.zk_passport_required is not True:
            raise ValueError("zk_passport_required must be true for Sols Lot protocol purchases")
        return self


class ProtocolOfferArtifactResponse(BaseModel):
    artifact: dict[str, Any]
    artifact_hash: str
    protocol: dict[str, Any]


class VerifyProtocolOfferArtifactRequest(BaseModel):
    artifact: dict[str, Any]
    artifact_hash: str
    now: Optional[int] = Field(None, gt=0)


class VerifyProtocolOfferArtifactResponse(BaseModel):
    valid: bool
    artifact_hash: str
    expected_artifact_hash: str
    expired: bool
    reasons: list[str] = Field(default_factory=list)


class VerifyPurchaseFinalizationRequest(BaseModel):
    artifact: dict[str, Any]
    artifact_hash: str
    rail: ProtocolRail
    purchase_intent_id: str = Field(..., min_length=1, max_length=128)
    payment_evidence: dict[str, Any] = Field(default_factory=dict)
    now: Optional[int] = Field(None, gt=0)


class VerifyPurchaseFinalizationResponse(BaseModel):
    verified: bool
    artifact_hash: str
    finalized_state: PurchaseIntentState
    reasons: list[str] = Field(default_factory=list)


@router.post("/offer-artifacts", response_model=ProtocolOfferArtifactResponse)
async def build_protocol_offer_artifact(
    body: BuildProtocolOfferArtifactRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> ProtocolOfferArtifactResponse:
    _require_server_to_server_token(settings, authorization)
    artifact = _build_artifact(body, settings)
    try:
        _assert_public_artifact(artifact, "protocol_offer_artifact")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    artifact_hash = content_hash(artifact)
    return ProtocolOfferArtifactResponse(
        artifact=artifact,
        artifact_hash=artifact_hash,
        protocol=_protocol_object_from_artifact(artifact, artifact_hash),
    )


@router.post("/offer-artifacts/verify", response_model=VerifyProtocolOfferArtifactResponse)
async def verify_protocol_offer_artifact(
    body: VerifyProtocolOfferArtifactRequest,
) -> VerifyProtocolOfferArtifactResponse:
    reasons = _artifact_rejection_reasons(
        body.artifact,
        body.artifact_hash,
        now=body.now,
    )
    expected_hash = content_hash(body.artifact)
    return VerifyProtocolOfferArtifactResponse(
        valid=not reasons,
        artifact_hash=body.artifact_hash,
        expected_artifact_hash=expected_hash,
        expired="expired" in reasons,
        reasons=reasons,
    )


@router.post(
    "/purchase-finalizations/verify",
    response_model=VerifyPurchaseFinalizationResponse,
)
async def verify_purchase_finalization(
    body: VerifyPurchaseFinalizationRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> VerifyPurchaseFinalizationResponse:
    _require_server_to_server_token(settings, authorization)
    reasons = _artifact_rejection_reasons(
        body.artifact,
        body.artifact_hash,
        now=body.now,
    )
    protocol = _mapping(body.artifact.get("protocol"))
    if protocol.get("purchaseIntentId") != body.purchase_intent_id:
        reasons.append("purchase_intent_mismatch")
    if protocol.get("rail") != body.rail:
        reasons.append("rail_mismatch")
    evidence_reasons = _payment_evidence_rejection_reasons(
        body.rail,
        body.payment_evidence,
    )
    reasons.extend(evidence_reasons)
    return VerifyPurchaseFinalizationResponse(
        verified=not reasons,
        artifact_hash=content_hash(body.artifact),
        finalized_state="protocol_verified" if not reasons else "manual_review",
        reasons=reasons,
    )


def _build_artifact(
    body: BuildProtocolOfferArtifactRequest,
    settings: Settings,
) -> dict[str, Any]:
    protocol = {
        "instanceId": body.instance_id,
        "purchaseIntentId": body.purchase_intent_id,
        "rail": body.rail,
        "deedLauncherId": body.deed_launcher_id,
        "propertyId": body.property_id,
        "collectionId": body.collection_id,
        "sharePpm": body.share_ppm,
        "vaultLauncherId": body.vault_launcher_id,
        "zkPassportRequired": True,
        "currentState": body.current_state,
        "expiresAt": body.expires_at,
    }
    if body.raw_offer:
        protocol["rawOffer"] = body.raw_offer
    artifact: dict[str, Any] = {
        "version": 1,
        "kind": "solslot_protocol_offer",
        "network": settings.network,
        "protocol": protocol,
        "paymentTerms": body.payment_terms.model_dump(exclude_none=True),
        "metadata": body.metadata,
        "issuedAt": int(time.time()),
    }
    if settings.pool_launcher_id:
        artifact["poolLauncherId"] = settings.pool_launcher_id
    if settings.protocol_config_launcher_id:
        artifact["protocolConfigLauncherId"] = settings.protocol_config_launcher_id
    if settings.vault_version_registry_launcher_id:
        artifact["vaultVersionRegistryLauncherId"] = (
            settings.vault_version_registry_launcher_id
        )
    return artifact


def _protocol_object_from_artifact(
    artifact: Mapping[str, Any],
    artifact_hash: str,
) -> dict[str, Any]:
    protocol = dict(_mapping(artifact.get("protocol")))
    protocol["artifactHash"] = artifact_hash
    protocol["paymentStatus"] = "unpaid"
    protocol["protocolStatus"] = protocol.get("currentState", "artifact_ready")
    return protocol


def _artifact_rejection_reasons(
    artifact: dict[str, Any],
    artifact_hash: str,
    *,
    now: Optional[int],
) -> list[str]:
    reasons: list[str] = []
    try:
        _assert_public_artifact(artifact, "protocol_offer_artifact")
    except ValueError as e:
        reasons.append(str(e))
    expected_hash = content_hash(artifact)
    if artifact_hash != expected_hash:
        reasons.append("artifact_hash_mismatch")
    protocol = _mapping(artifact.get("protocol"))
    if artifact.get("kind") != "solslot_protocol_offer":
        reasons.append("kind_mismatch")
    if protocol.get("zkPassportRequired") is not True:
        reasons.append("zkpassport_required_missing")
    expires_at = protocol.get("expiresAt")
    if not isinstance(expires_at, int) or expires_at <= 0:
        reasons.append("expires_at_invalid")
    elif (now or int(time.time())) > expires_at:
        reasons.append("expired")
    return reasons


def _payment_evidence_rejection_reasons(
    rail: ProtocolRail,
    evidence: dict[str, Any],
) -> list[str]:
    try:
        _assert_public_artifact(evidence, "purchase_finalization_evidence")
    except ValueError as e:
        return [str(e)]
    if rail == "chia":
        if not any(evidence.get(k) for k in ("spend_bundle_id", "accepted_offer_id", "coin_spend_id")):
            return ["chia_evidence_missing"]
    elif rail == "base_usdc":
        if not evidence.get("tx_hash"):
            return ["base_usdc_tx_hash_missing"]
    elif rail == "stripe":
        if not any(evidence.get(k) for k in ("checkout_session_id", "payment_intent_id")):
            return ["stripe_evidence_missing"]
    return []


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _require_server_to_server_token(
    settings: Settings,
    authorization: str | None,
) -> None:
    expected = settings.protocol_artifact_api_token
    if not expected:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing protocol artifact bearer token.",
        )
    supplied = authorization.removeprefix("Bearer ").strip()
    if supplied != expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid protocol artifact bearer token.",
        )
