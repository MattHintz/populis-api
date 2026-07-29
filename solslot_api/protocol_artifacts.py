"""Protocol purchase artifact endpoints for Sols Lot integrations.

The Sols marketplace backend owns purchase-intent state and payment rails.
Solslot API owns the public, deterministic protocol artifact boundary:
build the artifact, verify its hash, and verify that a rail-specific payment
completion is bound to the artifact the buyer saw.
"""
from __future__ import annotations

import secrets
import time
from typing import Annotated, Any, Literal, Mapping, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.payment_artifacts_v2 import (
    DeedPriceV1,
    PaymentArtifactError,
    PaymentRail,
    PurchaseArtifactV2,
    build_cat_purchase_artifact,
    build_evm_test_usd_purchase_artifact,
    build_stripe_purchase_artifact,
    build_xch_purchase_artifact,
    purchase_artifact_from_json,
    purchase_artifact_to_json,
    validate_deed_price_plan,
)
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault

from .bootstrap_manifest import _assert_public_artifact, content_hash
from .config import Settings, get_settings
from .credential_auth import require_minting_writes
from .collection_store import (
    CollectionNotFound,
    get_collection_store,
)
from .payment_quotes import (
    PaymentQuoteError,
    load_authorized_oracle_round,
    parse_authorized_oracle_round,
)
from .payment_purchase_store import (
    PaymentPurchaseConflict,
    PaymentPurchaseNotFound,
    get_payment_purchase_store,
)
from .omnichain_evidence import OmnichainEvidenceError, load_omnichain_evidence
from .public_artifact import (
    PublicArtifactError,
    PublicArtifactMissing,
    load_signed_public_artifact,
)


router = APIRouter(prefix="/protocol", tags=["protocol-artifacts"])

ProtocolRail = Literal[
    "chia_xch",
    "chia_cat",
    "base_usdc",
    "evm_usdc",
    "stripe",
]
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


@router.get("/artifact", response_model=dict[str, Any])
async def get_signed_public_artifact(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return only the administrator-signed RC22 ceremony artifact."""
    try:
        return load_signed_public_artifact(settings)
    except PublicArtifactMissing as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except PublicArtifactError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed RC22 public artifact failed verification.",
        ) from exc


class ProtocolPaymentTerms(BaseModel):
    currency: str = Field(..., min_length=1, max_length=32)
    amount: Optional[int] = Field(None, gt=0)
    quantity: int = Field(1, ge=1)
    usd_amount_minor: Optional[int] = Field(None, gt=0)
    payment_puzzle_hash: Optional[str] = Field(None, max_length=132)
    protocol_treasury_puzhash: Optional[str] = Field(None, max_length=132)
    chain_id: Optional[int] = Field(None, gt=0)


class BuildProtocolOfferArtifactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["solslot-v2"]
    network: Literal["testnet11"]
    genesis_artifact_hash: str = Field(..., min_length=66, max_length=66)
    instance_id: str = Field(..., min_length=1, max_length=128)
    purchase_intent_id: str = Field(..., min_length=1, max_length=128)
    rail: ProtocolRail
    deed_launcher_id: Optional[str] = Field(None, min_length=1, max_length=132)
    property_id: str = Field(..., min_length=1, max_length=256)
    collection_id: str = Field(..., min_length=1, max_length=256)
    share_ppm: Optional[int] = Field(None, ge=1, le=1_000_000)
    vault_launcher_id: str = Field(..., min_length=1, max_length=132)
    current_vault_coin_id: str = Field(..., min_length=66, max_length=66)
    identity_attest_root: str = Field(..., min_length=66, max_length=66)
    expires_at: int = Field(..., gt=0, description="Unix seconds")
    payment_terms: ProtocolPaymentTerms
    zk_passport_required: bool = True
    current_state: PurchaseIntentState = "created"
    metadata: dict[str, Any] = Field(default_factory=dict)
    metadata_root: Optional[str] = Field(None, min_length=66, max_length=66)
    metadata_anchor_id: Optional[str] = Field(
        None, min_length=66, max_length=66
    )
    authorization_nonce: Optional[str] = Field(
        None, min_length=66, max_length=66
    )
    authorization_expires_at: Optional[int] = Field(None, gt=0)
    native_asset_id: Optional[str] = Field(
        None, min_length=66, max_length=66
    )
    native_asset_decimals: Optional[int] = Field(None, ge=0, le=18)

    @model_validator(mode="after")
    def require_zkpassport(self):
        if self.zk_passport_required is not True:
            raise ValueError("zk_passport_required must be true for Sols Lot protocol purchases")
        return self


class ProtocolOfferArtifactResponse(BaseModel):
    artifact: dict[str, Any]
    artifact_hash: str
    protocol: dict[str, Any]
    purchase_artifact: Optional[dict[str, Any]] = None
    purchase_artifact_hash: Optional[str] = None
    purchase_id: Optional[str] = None
    oracle_authorization: Optional[dict[str, Any]] = None


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


class VerifyExternalEscrowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    gateway_profile: str = Field(
        ...,
        alias="gatewayProfile",
        min_length=1,
        max_length=32,
    )
    global_payment_id: str = Field(
        ...,
        alias="globalPaymentId",
        min_length=66,
        max_length=66,
    )
    purchase_id: str = Field(
        ...,
        alias="purchaseId",
        min_length=66,
        max_length=66,
    )
    artifact_hash: str = Field(
        ...,
        alias="artifactHash",
        min_length=66,
        max_length=66,
    )
    amount: int = Field(..., gt=0)
    quantity: int = Field(..., ge=1)
    collection_id: str = Field(
        ...,
        alias="collectionId",
        min_length=66,
        max_length=66,
    )
    deed_launcher_id: str = Field(
        ...,
        alias="deedLauncherId",
        min_length=66,
        max_length=66,
    )
    vault_launcher_id: str = Field(
        ...,
        alias="vaultLauncherId",
        min_length=66,
        max_length=66,
    )
    destination_puzzle: str = Field(
        ...,
        alias="destinationPuzzle",
        min_length=66,
        max_length=66,
    )
    quote_expires_at: int = Field(..., alias="quoteExpiresAt", gt=0)
    depositor: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$")
    settlement_token: str = Field(
        ...,
        alias="settlementToken",
        pattern=r"^0x[0-9a-fA-F]{40}$",
    )
    local_payment_id: str = Field(
        ...,
        alias="localPaymentId",
        pattern=r"^0x[0-9a-fA-F]{64}$",
    )


class ExternalEscrowSource(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    chain_id: int = Field(..., alias="chainId", gt=0)
    spoke: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$")
    transaction_hash: str = Field(
        ...,
        alias="transactionHash",
        pattern=r"^0x[0-9a-fA-F]{64}$",
    )
    block_number: int = Field(..., alias="blockNumber", gt=0)
    block_hash: str = Field(
        ...,
        alias="blockHash",
        pattern=r"^0x[0-9a-fA-F]{64}$",
    )
    block_timestamp: int = Field(..., alias="blockTimestamp", gt=0)
    log_index: int = Field(..., alias="logIndex", ge=0)
    confirmations: int = Field(..., ge=12)


class VerifyExternalEscrowWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    escrow_message: VerifyExternalEscrowRequest = Field(..., alias="escrowMessage")
    source: ExternalEscrowSource


class VerifyExternalEscrowResponse(BaseModel):
    verified: bool
    purchase_intent_id: str
    purchase_artifact: dict[str, Any]
    fulfillment: dict[str, Any]


@router.post("/offer-artifacts", response_model=ProtocolOfferArtifactResponse)
async def build_protocol_offer_artifact(
    body: BuildProtocolOfferArtifactRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> ProtocolOfferArtifactResponse:
    require_minting_writes(settings)
    _require_server_to_server_token(settings, authorization)
    from .zkpassport_enrollments import _normalize_hex32, _sync_chia_stamp
    from .vault_eligibility import require_current_approved_vault

    vault_launcher_id = _normalize_hex32(body.vault_launcher_id, "vault_launcher_id")
    approved_vault = require_current_approved_vault(
        settings,
        vault_launcher_id,
        expected_current_coin_id=body.current_vault_coin_id,
        expected_identity_attest_root=body.identity_attest_root,
        sync_enrollment=_sync_chia_stamp,
    )
    receipt = approved_vault.enrollment.receipt
    try:
        genesis_artifact = load_signed_public_artifact(settings)
    except PublicArtifactError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed RC22 genesis artifact is unavailable or invalid.",
        ) from exc
    expected_genesis_hash = _normalize_hex32(
        body.genesis_artifact_hash,
        "genesis_artifact_hash",
    )
    if genesis_artifact.get("artifactHash") != expected_genesis_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The requested genesis artifact is not the active signed artifact.",
        )
    try:
        if body.rail in {"base_usdc", "evm_usdc"}:
            chain_id = body.payment_terms.chain_id
            if chain_id is None and body.rail == "base_usdc":
                chain_id = 84532
            token_address = (
                settings.payment_evm_usdc_tokens.get(str(chain_id))
                if chain_id is not None
                else None
            )
            if token_address is None:
                raise OmnichainEvidenceError("EVM chain is not enabled for protocol purchases")
            load_omnichain_evidence(
                settings,
                chain_id=chain_id,
                token_address=token_address,
                gateway_profile=str(settings.payment_omnichain_gateway_profile or ""),
            )
        canonical_payment = _build_canonical_payment_artifact(
            body,
            settings,
            vault_launcher_id=vault_launcher_id,
        )
    except OmnichainEvidenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except (PaymentArtifactError, PaymentQuoteError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    artifact = _build_artifact(
        body,
        settings,
        receipt=receipt.model_dump(),
        genesis_artifact=genesis_artifact,
        canonical_payment=canonical_payment,
    )
    try:
        _assert_protocol_offer_public_artifact(artifact)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    artifact_hash = content_hash(artifact)
    purchase_artifact, oracle_authorization = canonical_payment
    try:
        stored = get_payment_purchase_store(
            settings.payment_purchase_db_path
        ).save(
            purchase_intent_id=body.purchase_intent_id,
            rail=body.rail,
            offer_artifact_hash=artifact_hash,
            offer_artifact=artifact,
            purchase_artifact=purchase_artifact,
            created_at=int(time.time()),
        )
    except PaymentPurchaseConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    artifact = stored.offer_artifact
    artifact_hash = stored.offer_artifact_hash
    purchase_artifact = stored.purchase_artifact
    oracle_authorization = artifact.get("oracleAuthorization")
    return ProtocolOfferArtifactResponse(
        artifact=artifact,
        artifact_hash=artifact_hash,
        protocol=_protocol_object_from_artifact(artifact, artifact_hash),
        purchase_artifact=purchase_artifact,
        purchase_artifact_hash=purchase_artifact["artifactHash"],
        purchase_id=purchase_artifact["purchaseId"],
        oracle_authorization=oracle_authorization,
    )


@router.post("/offer-artifacts/verify", response_model=VerifyProtocolOfferArtifactResponse)
async def verify_protocol_offer_artifact(
    body: VerifyProtocolOfferArtifactRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> VerifyProtocolOfferArtifactResponse:
    reasons = _artifact_rejection_reasons(
        body.artifact,
        body.artifact_hash,
        now=body.now,
        settings=settings,
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
        settings=settings,
    )
    protocol = _mapping(body.artifact.get("protocol"))
    if protocol.get("purchaseIntentId") != body.purchase_intent_id:
        reasons.append("purchase_intent_mismatch")
    if protocol.get("rail") != body.rail:
        reasons.append("rail_mismatch")
    canonical: PurchaseArtifactV2 | None = None
    canonical_json = body.artifact.get("purchaseArtifactV2")
    if isinstance(canonical_json, Mapping):
        try:
            canonical = purchase_artifact_from_json(canonical_json)
        except (PaymentArtifactError, TypeError, ValueError):
            reasons.append("purchase_artifact_v2_invalid")
    evidence_reasons = _payment_evidence_rejection_reasons(
        body.rail,
        body.payment_evidence,
    )
    reasons.extend(evidence_reasons)
    if canonical is not None and body.rail == "stripe":
        amount = body.payment_evidence.get(
            "amount_total",
            body.payment_evidence.get("amount_received"),
        )
        currency = str(body.payment_evidence.get("currency") or "").lower()
        if amount != canonical.rail_amount:
            reasons.append("stripe_amount_mismatch")
        if currency != "usd":
            reasons.append("stripe_currency_mismatch")
    if canonical is not None and body.rail in {"base_usdc", "evm_usdc"}:
        try:
            stored = get_payment_purchase_store(
                settings.payment_purchase_db_path
            ).get(_hex32(canonical.purchase_id))
        except PaymentPurchaseNotFound:
            reasons.append("external_purchase_not_found")
        else:
            message = stored.external_message
            if message is None:
                reasons.append("external_message_not_verified")
            else:
                token_address = settings.payment_evm_usdc_tokens.get(
                    str(canonical.rail_chain_id)
                )
                gateway_profile = message.get("gatewayProfile")
                if token_address is None or not isinstance(gateway_profile, str):
                    reasons.append("external_escrow_evidence_unavailable")
                else:
                    try:
                        load_omnichain_evidence(
                            settings,
                            chain_id=canonical.rail_chain_id,
                            token_address=token_address,
                            gateway_profile=gateway_profile,
                        )
                    except OmnichainEvidenceError:
                        reasons.append("external_escrow_evidence_unavailable")
                if (
                    body.payment_evidence.get("global_payment_id")
                    != message.get("globalPaymentId")
                ):
                    reasons.append("external_global_payment_mismatch")
    return VerifyPurchaseFinalizationResponse(
        verified=not reasons,
        artifact_hash=content_hash(body.artifact),
        finalized_state="protocol_verified" if not reasons else "manual_review",
        reasons=reasons,
    )


@router.post(
    "/external-payments/verify",
    response_model=VerifyExternalEscrowResponse,
)
async def verify_external_escrow(
    payload: VerifyExternalEscrowWebhookRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> VerifyExternalEscrowResponse:
    """Verify and bind one confirmed escrow event and its protocol message."""

    _require_omnichain_ingest_token(settings, authorization)
    body = payload.escrow_message
    source = payload.source
    normalized = {
        "gatewayProfile": body.gateway_profile,
        "globalPaymentId": _normalized_hex32(
            body.global_payment_id,
            "globalPaymentId",
        ),
        "purchaseId": _normalized_hex32(
            body.purchase_id,
            "purchaseId",
        ),
        "artifactHash": _normalized_hex32(
            body.artifact_hash,
            "artifactHash",
        ),
        "amount": body.amount,
        "quantity": body.quantity,
        "collectionId": _normalized_hex32(
            body.collection_id,
            "collectionId",
        ),
        "deedLauncherId": _normalized_hex32(
            body.deed_launcher_id,
            "deedLauncherId",
        ),
        "vaultLauncherId": _normalized_hex32(
            body.vault_launcher_id,
            "vaultLauncherId",
        ),
        "destinationPuzzle": _normalized_hex32(
            body.destination_puzzle,
            "destinationPuzzle",
        ),
        "quoteExpiresAt": body.quote_expires_at,
        "depositor": _normalized_evm_address(body.depositor, "depositor"),
        "settlementToken": _normalized_evm_address(
            body.settlement_token,
            "settlementToken",
        ),
        "localPaymentId": _normalized_hex32(
            body.local_payment_id,
            "localPaymentId",
        ),
        "source": {
            "chainId": source.chain_id,
            "spoke": _normalized_evm_address(source.spoke, "source.spoke"),
            "transactionHash": _normalized_hex32(
                source.transaction_hash,
                "source.transactionHash",
            ),
            "blockNumber": source.block_number,
            "blockHash": _normalized_hex32(source.block_hash, "source.blockHash"),
            "blockTimestamp": source.block_timestamp,
            "logIndex": source.log_index,
            "confirmations": source.confirmations,
        },
    }
    if normalized["globalPaymentId"] == _hex32(bytes32.zeros):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="globalPaymentId cannot be zero",
        )
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        record = store.get(normalized["purchaseId"])
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    if record.rail not in {"base_usdc", "evm_usdc"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="purchase artifact is not an EVM escrow purchase",
        )
    try:
        canonical = purchase_artifact_from_json(record.purchase_artifact)
        canonical.assert_live(int(time.time()))
    except PaymentArtifactError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    token_address = settings.payment_evm_usdc_tokens.get(str(canonical.rail_chain_id))
    if token_address is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="EVM chain is not enabled for protocol purchases",
        )
    try:
        deployment = load_omnichain_evidence(
            settings,
            chain_id=canonical.rail_chain_id,
            token_address=token_address,
            gateway_profile=normalized["gatewayProfile"],
        )
    except OmnichainEvidenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    source_evidence = normalized["source"]
    if (
        source_evidence["chainId"] != canonical.rail_chain_id
        or source_evidence["spoke"] != deployment.spoke_address
        or source_evidence["confirmations"] < deployment.confirmations
        or normalized["settlementToken"] != token_address.lower()
        or canonical.rail_asset_id != _evm_token_asset_id(token_address)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="external payment provenance does not match the reviewed escrow rail",
        )
    expected = {
        "purchaseId": _hex32(canonical.purchase_id),
        "artifactHash": _hex32(canonical.artifact_hash),
        "amount": canonical.rail_amount,
        "quantity": 1,
        "collectionId": _hex32(canonical.collection_id),
        "deedLauncherId": _hex32(canonical.deed_launcher_id),
        "vaultLauncherId": _hex32(canonical.vault_launcher_id),
        "destinationPuzzle": _hex32(canonical.vault_p2_puzzle_hash),
        "quoteExpiresAt": canonical.quote_expires_at,
    }
    mismatches = [
        field
        for field, expected_value in expected.items()
        if normalized[field] != expected_value
    ]
    if mismatches:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "external payment does not match the purchase artifact: "
                + ", ".join(mismatches)
            ),
        )
    try:
        record = store.bind_external_message(
            normalized["purchaseId"],
            normalized,
        )
    except (PaymentPurchaseConflict, PaymentPurchaseNotFound) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return VerifyExternalEscrowResponse(
        verified=True,
        purchase_intent_id=record.purchase_intent_id,
        purchase_artifact=record.purchase_artifact,
        fulfillment={
            **expected,
            "globalPaymentId": normalized["globalPaymentId"],
            "gatewayProfile": normalized["gatewayProfile"],
            "usdAmountMinor": canonical.usd_amount_minor,
            "railChainId": canonical.rail_chain_id,
            "railAssetId": _hex32(canonical.rail_asset_id),
            "railAssetDecimals": canonical.rail_asset_decimals,
            "depositor": normalized["depositor"],
            "source": normalized["source"],
        },
    )


@router.post("/purchase-intents/escrow-webhook")
async def receive_external_escrow_webhook(
    payload: VerifyExternalEscrowWebhookRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Canonical callback consumed by the read-only confirmed-event relayer."""

    verified = await verify_external_escrow(payload, settings, authorization)
    presale = _ingest_verified_presale_payment(payload, verified, settings)
    return {
        "escrow": verified.model_dump(mode="json"),
        "verification": verified.model_dump(mode="json"),
        "presale": presale,
    }


def _ingest_verified_presale_payment(
    payload: VerifyExternalEscrowWebhookRequest,
    verified: VerifyExternalEscrowResponse,
    settings: Settings,
) -> dict[str, Any] | None:
    """Route one confirmed Base payment into its active voucher campaign."""
    from .presale_endpoints import (
        VoucherIssuanceEvidenceRequest,
        _external_escrow_contract,
        get_presale_store,
    )
    from .vault_eligibility import require_current_approved_vault

    store = get_presale_store(settings)
    try:
        series = store.get(payload.escrow_message.collection_id)
    except KeyError:
        return None
    if series["state"] != "PRESALE":
        return None
    # A closed customer sales window prevents new purchase artifacts. It must
    # not strand a payment that was already confirmed by the configured escrow
    # while its artifact was valid. The callback remains authenticated and all
    # artifact, vault, price, deed, and chain evidence checks still apply.
    body = payload.escrow_message
    source = payload.source
    record = get_payment_purchase_store(settings.payment_purchase_db_path).get(
        body.purchase_id
    )
    artifact = purchase_artifact_from_json(record.purchase_artifact)
    payer = bytes32(
        b"\x00" * 12 + bytes.fromhex(body.depositor.removeprefix("0x"))
    )
    evidence = VoucherIssuanceEvidenceRequest(
        purchaseArtifact=verified.purchase_artifact,
        globalPaymentId=body.global_payment_id,
        originalPayer=_hex32(payer),
        evidenceId=(
            f"base:{source.transaction_hash.lower()}:{source.log_index}"
        ),
        confirmedHeight=source.block_number,
        transactionIndex=0,
        outputIndex=source.log_index,
        confirmedAt=source.block_timestamp,
    )
    approved = require_current_approved_vault(
        settings,
        _hex32(artifact.vault_launcher_id),
    )
    return store.ingest_payment(
        series["termsHash"],
        evidence,
        approved_vault=approved,
        issued_purchase=record,
        external_escrow_contract=_external_escrow_contract(
            settings,
            artifact,
            record,
        ),
    )


def _build_canonical_payment_artifact(
    body: BuildProtocolOfferArtifactRequest,
    settings: Settings,
    *,
    vault_launcher_id: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    now = int(time.time())
    canonical_rails = {
        "chia_xch",
        "chia_cat",
        "base_usdc",
        "evm_usdc",
        "stripe",
    }
    if body.rail not in canonical_rails:
        raise PaymentArtifactError("unsupported protocol payment rail")
    if not settings.collection_metadata_enabled:
        raise PaymentArtifactError(
            "protocol purchases require the collection metadata workspace"
        )
    if body.payment_terms.quantity != 1:
        raise PaymentArtifactError(
            "primary purchases deliver exactly one governed SmartDeed"
        )
    if (
        body.rail in {"base_usdc", "evm_usdc"}
        and body.expires_at > now + 30 * 60
    ):
        raise PaymentArtifactError(
            "EVM escrow quote validity cannot exceed 30 minutes"
        )
    try:
        collection = get_collection_store(settings).get(body.collection_id)
    except CollectionNotFound as exc:
        raise PaymentArtifactError(str(exc)) from exc
    if (
        collection["state"] != "PUBLISHED"
        or not collection["allocationLocked"]
        or not collection["metadataRoot"]
        or not collection["metadataAnchorId"]
    ):
        raise PaymentArtifactError(
            "protocol purchases require a published, allocation-locked collection"
        )
    deed = next(
        (
            item
            for item in collection["deeds"]
            if item["deedId"].casefold() == body.property_id.casefold()
            or str(item.get("deedLauncherId") or "").casefold()
            == body.property_id.casefold()
        ),
        None,
    )
    if deed is None:
        raise PaymentArtifactError(
            "purchase deed is not in the sealed collection allocation"
        )
    if (
        not deed["deedLauncherId"]
        or not deed["executeBundleId"]
        or deed["confirmationHeight"] is None
    ):
        raise PaymentArtifactError(
            "purchase deed is not confirmed and available for delivery"
        )
    expected_deed_launcher = _bytes32_field(
        deed["deedLauncherId"], "deed_launcher_id"
    )
    if (
        body.deed_launcher_id is not None
        and _bytes32_field(body.deed_launcher_id, "deed_launcher_id")
        != expected_deed_launcher
    ):
        raise PaymentArtifactError(
            "deed_launcher_id does not match the collection workspace"
        )
    if (
        body.share_ppm is not None
        and body.share_ppm != int(deed["sharePpm"])
    ):
        raise PaymentArtifactError(
            "share_ppm does not match the sealed deed allocation"
        )
    share_ppm, usd_amount_minor = _sealed_deed_price(collection, deed)
    if (
        body.payment_terms.usd_amount_minor is not None
        and body.payment_terms.usd_amount_minor != usd_amount_minor
    ):
        raise PaymentArtifactError(
            "USD amount does not match the sealed deed allocation"
        )
    expected_metadata_root = _bytes32_field(
        collection["metadataRoot"], "metadata_root"
    )
    expected_metadata_anchor = _bytes32_field(
        collection["metadataAnchorId"], "metadata_anchor_id"
    )
    for supplied, expected, label in (
        (body.metadata_root, expected_metadata_root, "metadata_root"),
        (
            body.metadata_anchor_id,
            expected_metadata_anchor,
            "metadata_anchor_id",
        ),
    ):
        if supplied is not None and _bytes32_field(supplied, label) != expected:
            raise PaymentArtifactError(
                f"{label} does not match the published collection"
            )

    required = {
        "authorization_nonce": body.authorization_nonce,
        "authorization_expires_at": body.authorization_expires_at,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise PaymentArtifactError(
            "protocol purchases require " + ", ".join(missing)
        )

    collection_id = bytes32(canonicalise_property_id(collection["id"]))
    deed_launcher_id = expected_deed_launcher
    expected_collection_canon = body.metadata.get("collectionIdCanon")
    if (
        expected_collection_canon is not None
        and _bytes32_field(
            expected_collection_canon, "metadata.collectionIdCanon"
        )
        != collection_id
    ):
        raise PaymentArtifactError(
            "collectionIdCanon does not match the collection workspace"
        )
    vault_id = _bytes32_field(vault_launcher_id, "vault_launcher_id")
    vault_p2 = puzzle_hash_for_p2_vault(vault_id)
    common = {
        "network": settings.network,
        "collection_id": collection_id,
        "deed_launcher_id": deed_launcher_id,
        "metadata_root": expected_metadata_root,
        "metadata_anchor_id": expected_metadata_anchor,
        "share_ppm": share_ppm,
        "usd_amount_minor": usd_amount_minor,
        "vault_launcher_id": vault_id,
        "vault_p2_puzzle_hash": vault_p2,
        "authorization_nonce": _bytes32_field(
            str(body.authorization_nonce), "authorization_nonce"
        ),
        "authorization_expires_at": int(
            body.authorization_expires_at or 0
        ),
        "quote_expires_at": body.expires_at,
    }

    if body.rail == "stripe":
        if body.payment_terms.chain_id is not None:
            raise PaymentArtifactError(
                "Stripe purchases cannot declare an EVM chain"
            )
        if body.payment_terms.currency.upper() != "USD":
            raise PaymentArtifactError(
                "Stripe purchases must use USD minor units"
            )
        purchase = build_stripe_purchase_artifact(**common)
        purchase.assert_live(now)
        return purchase_artifact_to_json(purchase), None

    if body.rail in {"base_usdc", "evm_usdc"}:
        if body.native_asset_id is not None or body.native_asset_decimals is not None:
            raise PaymentArtifactError(
                "EVM purchases cannot declare Chia CAT fields"
            )
        if body.payment_terms.currency.upper() not in {"USDC", "WUSDC"}:
            raise PaymentArtifactError(
                "EVM escrow purchases must use the configured USD stablecoin"
            )
        chain_id = body.payment_terms.chain_id
        if chain_id is None and body.rail == "base_usdc":
            chain_id = 84532
        if chain_id is None:
            raise PaymentArtifactError(
                "EVM escrow purchases require payment_terms.chain_id"
            )
        token_address = settings.payment_evm_usdc_tokens.get(str(chain_id))
        if token_address is None:
            raise PaymentArtifactError(
                "EVM chain is not enabled for protocol purchases"
            )
        purchase = build_evm_test_usd_purchase_artifact(
            **common,
            chain_id=chain_id,
            token_asset_id=_evm_token_asset_id(token_address),
        )
        purchase.assert_live(now)
        return purchase_artifact_to_json(purchase), None

    asset_id = bytes32.zeros
    if body.rail == "chia_cat":
        if body.native_asset_id is None:
            raise PaymentArtifactError(
                "Chia CAT offers require native_asset_id"
            )
        if body.native_asset_decimals is None:
            raise PaymentArtifactError(
                "Chia CAT offers require native_asset_decimals"
            )
        asset_id = _bytes32_field(
            body.native_asset_id, "native_asset_id"
        )
        if asset_id == bytes32.zeros:
            raise PaymentArtifactError("native_asset_id cannot be zero")
        allowed_cat_ids = {
            _bytes32_field(value, "payment_oracle_allowed_cat_asset_ids")
            for value in settings.payment_oracle_allowed_cat_asset_ids
        }
        if asset_id not in allowed_cat_ids:
            raise PaymentArtifactError(
                "native_asset_id is not enabled for protocol purchases"
            )
    elif body.native_asset_id is not None or body.native_asset_decimals is not None:
        raise PaymentArtifactError(
            "native XCH offers cannot declare CAT asset fields"
        )

    authorized_round = load_authorized_oracle_round(
        settings,
        asset_id=asset_id,
        now=now,
    )
    if authorized_round.round.network != settings.network:
        raise PaymentArtifactError(
            "oracle round network does not match the active protocol"
        )
    native_common = {
        **common,
        "oracle_round": authorized_round.round,
    }
    if body.rail == "chia_xch":
        purchase = build_xch_purchase_artifact(**native_common)
    else:
        purchase = build_cat_purchase_artifact(
            **native_common,
            cat_asset_id=asset_id,
            cat_decimals=int(body.native_asset_decimals or 0),
        )
    purchase.assert_live(now)
    return (
        purchase_artifact_to_json(purchase),
        authorized_round.public_evidence(),
    )


def _build_artifact(
    body: BuildProtocolOfferArtifactRequest,
    settings: Settings,
    *,
    receipt: dict[str, Any],
    genesis_artifact: Mapping[str, Any],
    canonical_payment: tuple[dict[str, Any], dict[str, Any] | None],
) -> dict[str, Any]:
    launchers = _mapping(genesis_artifact.get("launcherIds"))
    protocol = {
        "instanceId": body.instance_id,
        "purchaseIntentId": body.purchase_intent_id,
        "rail": body.rail,
        "deedLauncherId": body.deed_launcher_id,
        "propertyId": body.property_id,
        "collectionId": body.collection_id,
        "sharePpm": body.share_ppm,
        "vaultLauncherId": receipt["vaultLauncherId"],
        "zkPassportRequired": True,
        "currentState": body.current_state,
        "expiresAt": body.expires_at,
    }
    purchase_artifact, _oracle_authorization = canonical_payment
    protocol["deedLauncherId"] = purchase_artifact["deedLauncherId"]
    protocol["collectionWorkspaceId"] = body.collection_id
    protocol["collectionId"] = purchase_artifact["collectionId"]
    protocol["sharePpm"] = purchase_artifact["sharePpm"]
    protocol["purchaseArtifactHash"] = purchase_artifact["artifactHash"]
    protocol["purchaseId"] = purchase_artifact["purchaseId"]
    payment_terms = {
        "currency": (
            "XCH" if body.rail == "chia_xch" else body.payment_terms.currency
        ),
        "amount": purchase_artifact["railAmount"],
        "quantity": 1,
        "usd_amount_minor": purchase_artifact["usdAmountMinor"],
        "asset_id": purchase_artifact["railAssetId"],
        "asset_decimals": purchase_artifact["railAssetDecimals"],
    }
    artifact: dict[str, Any] = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "version": 2,
        "kind": "solslot_protocol_offer",
        "network": settings.network,
        "genesisArtifactHash": genesis_artifact["artifactHash"],
        "protocol": protocol,
        "vaultCredentialReceipt": receipt,
        "paymentTerms": payment_terms,
        "metadata": body.metadata,
        "issuedAt": int(time.time()),
    }
    purchase_artifact, oracle_authorization = canonical_payment
    artifact["purchaseArtifactV2"] = purchase_artifact
    if oracle_authorization is not None:
        artifact["oracleAuthorization"] = oracle_authorization
    artifact["poolLauncherId"] = launchers["pool"]
    artifact["protocolConfigLauncherId"] = launchers["protocolConfig"]
    artifact["vaultVersionRegistryLauncherId"] = launchers["vaultVersionRegistry"]
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
    settings: Optional[Settings] = None,
) -> list[str]:
    reasons: list[str] = []
    try:
        _assert_protocol_offer_public_artifact(artifact)
    except ValueError as e:
        reasons.append(str(e))
    expected_hash = content_hash(artifact)
    if artifact_hash != expected_hash:
        reasons.append("artifact_hash_mismatch")
    protocol = _mapping(artifact.get("protocol"))
    if artifact.get("kind") != "solslot_protocol_offer":
        reasons.append("kind_mismatch")
    if artifact.get("schemaVersion") != 2:
        reasons.append("schema_version_mismatch")
    if artifact.get("protocolVersion") != "solslot-v2":
        reasons.append("protocol_version_mismatch")
    if artifact.get("network") != "testnet11":
        reasons.append("network_mismatch")
    if protocol.get("zkPassportRequired") is not True:
        reasons.append("zkpassport_required_missing")
    canonical_json = artifact.get("purchaseArtifactV2")
    if protocol.get("rail") in {
        "chia_xch",
        "chia_cat",
        "base_usdc",
        "evm_usdc",
        "stripe",
    }:
        if not isinstance(canonical_json, Mapping):
            reasons.append("purchase_artifact_v2_missing")
    if isinstance(canonical_json, Mapping):
        try:
            canonical = purchase_artifact_from_json(canonical_json)
            canonical.assert_live(now or int(time.time()))
            expected_pairs = (
                (canonical.network, artifact.get("network"), "purchase_network"),
                (
                    _hex32(canonical.collection_id),
                    protocol.get("collectionId"),
                    "purchase_collection",
                ),
                (
                    _hex32(canonical.deed_launcher_id),
                    protocol.get("deedLauncherId"),
                    "purchase_deed",
                ),
                (
                    canonical.share_ppm,
                    protocol.get("sharePpm"),
                    "purchase_share",
                ),
                (
                    _hex32(canonical.vault_launcher_id),
                    protocol.get("vaultLauncherId"),
                    "purchase_vault",
                ),
                (
                    canonical.quote_expires_at,
                    protocol.get("expiresAt"),
                    "purchase_expiry",
                ),
                (
                    _hex32(canonical.artifact_hash),
                    protocol.get("purchaseArtifactHash"),
                    "purchase_artifact_hash",
                ),
                (
                    _hex32(canonical.purchase_id),
                    protocol.get("purchaseId"),
                    "purchase_id",
                ),
            )
            for observed, expected, label in expected_pairs:
                if observed != expected:
                    reasons.append(f"{label}_mismatch")
            expected_rail = {
                PaymentRail.CHIA_XCH: "chia_xch",
                PaymentRail.CHIA_CAT: "chia_cat",
                PaymentRail.STRIPE: "stripe",
            }.get(canonical.rail)
            protocol_rail = protocol.get("rail")
            if canonical.rail == PaymentRail.EVM_TEST_USD:
                rail_matches = protocol_rail in {"base_usdc", "evm_usdc"}
            else:
                rail_matches = expected_rail == protocol_rail
            if not rail_matches:
                reasons.append("purchase_rail_mismatch")
            canonical_p2 = puzzle_hash_for_p2_vault(
                canonical.vault_launcher_id
            )
            if canonical.vault_p2_puzzle_hash != canonical_p2:
                reasons.append("purchase_vault_p2_mismatch")

            if (
                settings is not None
                and canonical.rail
                in {PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT}
            ):
                authorization = parse_authorized_oracle_round(
                    settings,
                    artifact.get("oracleAuthorization"),
                )
                if (
                    authorization.round.round_hash
                    != canonical.oracle_round_hash
                    or authorization.round.asset_id
                    != canonical.rail_asset_id
                    or authorization.round.asset_decimals
                    != canonical.rail_asset_decimals
                    or authorization.round.price_usd_minor_per_asset
                    != canonical.oracle_price_usd_minor_per_asset
                    or authorization.round.source_evidence_root
                    != canonical.source_evidence_root
                ):
                    reasons.append("purchase_oracle_mismatch")
        except (PaymentArtifactError, PaymentQuoteError, TypeError, ValueError):
            reasons.append("purchase_artifact_v2_invalid")
    expires_at = protocol.get("expiresAt")
    if not isinstance(expires_at, int) or expires_at <= 0:
        reasons.append("expires_at_invalid")
    elif (now or int(time.time())) > expires_at:
        reasons.append("expired")
    receipt = _mapping(artifact.get("vaultCredentialReceipt"))
    if receipt.get("vaultLauncherId") != protocol.get("vaultLauncherId"):
        reasons.append("credential_vault_mismatch")
    if receipt.get("network") != artifact.get("network"):
        reasons.append("credential_network_mismatch")
    if receipt.get("policyVersion") != 2:
        reasons.append("credential_policy_mismatch")
    identity_root = receipt.get("identityAttestRoot")
    if not isinstance(identity_root, str) or identity_root in {
        "",
        "0x" + "00" * 32,
        "0x4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
    }:
        reasons.append("credential_root_missing")
    proof = _mapping(receipt.get("attestationProof"))
    if proof.get("bitpath") != 0 or proof.get("siblings") != []:
        reasons.append("credential_proof_path_mismatch")
    if receipt.get("attestationLeafHash") != identity_root:
        reasons.append("credential_proof_root_mismatch")
    if not receipt.get("chiaVaultCoinId") or not isinstance(
        receipt.get("confirmedBlockIndex"),
        int,
    ):
        reasons.append("credential_chia_confirmation_missing")
    if settings is not None:
        try:
            genesis_artifact = load_signed_public_artifact(settings)
        except PublicArtifactError:
            reasons.append("active_genesis_artifact_unavailable")
            return reasons
        launchers = _mapping(genesis_artifact.get("launcherIds"))
        if artifact.get("genesisArtifactHash") != genesis_artifact.get("artifactHash"):
            reasons.append("genesis_artifact_hash_mismatch")
        if artifact.get("network") != settings.network:
            reasons.append("active_network_mismatch")
        coordinate_pairs = (
            ("poolLauncherId", launchers.get("pool")),
            ("protocolConfigLauncherId", launchers.get("protocolConfig")),
            ("vaultVersionRegistryLauncherId", launchers.get("vaultVersionRegistry")),
        )
        for field, expected in coordinate_pairs:
            if not expected or artifact.get(field) != expected:
                reasons.append(f"{field}_mismatch")
        bridge_policy = _mapping(genesis_artifact.get("bridgePolicy"))
        if receipt.get("bridgePolicyHash") != bridge_policy.get("policyHash"):
            reasons.append("credential_bridge_policy_mismatch")
        try:
            from .zkpassport_enrollments import _normalize_hex32, _sync_chia_stamp

            vault_launcher_id = _normalize_hex32(
                str(protocol.get("vaultLauncherId") or ""),
                "vaultLauncherId",
            )
            current_enrollment = _sync_chia_stamp(settings, vault_launcher_id)
            current_receipt = current_enrollment.receipt
            if (
                current_enrollment.status != "chia_confirmed"
                or current_receipt is None
                or current_receipt.vaultLauncherId != receipt.get("vaultLauncherId")
                or current_receipt.identityAttestRoot != receipt.get("identityAttestRoot")
                or current_receipt.chiaVaultCoinId != receipt.get("chiaVaultCoinId")
                or current_receipt.confirmedBlockIndex
                != receipt.get("confirmedBlockIndex")
            ):
                reasons.append("credential_not_current_on_chia")
        except (HTTPException, ValueError, TypeError):
            reasons.append("credential_not_current_on_chia")
        retired = {
            str(value).lower()
            for value in genesis_artifact.get("retiredCoordinates", [])
            if isinstance(value, str)
        }
        coordinate_values = [artifact.get(field) for field, _expected in coordinate_pairs]
        coordinate_values.extend(
            (protocol.get("deedLauncherId"), protocol.get("vaultLauncherId"))
        )
        if any(
            isinstance(value, str) and value.lower() in retired
            for value in coordinate_values
        ):
            reasons.append("retired_coordinate")
    return reasons


def _payment_evidence_rejection_reasons(
    rail: ProtocolRail,
    evidence: dict[str, Any],
) -> list[str]:
    try:
        _assert_public_artifact(evidence, "purchase_finalization_evidence")
    except ValueError as e:
        return [str(e)]
    if rail in {"chia_xch", "chia_cat"}:
        if not any(evidence.get(k) for k in ("spend_bundle_id", "accepted_offer_id", "coin_spend_id")):
            return ["chia_evidence_missing"]
    elif rail in {"base_usdc", "evm_usdc"}:
        if not evidence.get("tx_hash"):
            return ["base_usdc_tx_hash_missing"]
    elif rail == "stripe":
        if not any(evidence.get(k) for k in ("checkout_session_id", "payment_intent_id")):
            return ["stripe_evidence_missing"]
    return []


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sealed_deed_price(
    collection: Mapping[str, Any],
    selected_deed: Mapping[str, Any],
) -> tuple[int, int]:
    dossier = _mapping(collection.get("dossier"))
    offering = _mapping(dossier.get("offering"))
    currency = offering.get("currency")
    if not isinstance(currency, str) or currency.strip().upper() != "USD":
        raise PaymentArtifactError(
            "protocol purchases require a USD-denominated sealed target raise"
        )
    target_raise = _positive_decimal_integer(
        offering.get("targetRaiseMinor"),
        "dossier.offering.targetRaiseMinor",
    )
    allocation = dossier.get("deedAllocation")
    if not isinstance(allocation, list) or not allocation:
        raise PaymentArtifactError(
            "published collection is missing its sealed deed allocation"
        )

    prices: list[DeedPriceV1] = []
    selected_price: DeedPriceV1 | None = None
    selected_id = selected_deed.get("deedId")
    if not isinstance(selected_id, str) or not selected_id.strip():
        raise PaymentArtifactError("selected collection deed has no deedId")

    for index, value in enumerate(allocation):
        item = _mapping(value)
        deed_id = item.get("deedId")
        share_ppm = item.get("sharePpm")
        if not isinstance(deed_id, str) or not deed_id.strip():
            raise PaymentArtifactError(
                f"dossier.deedAllocation[{index}].deedId is invalid"
            )
        if (
            isinstance(share_ppm, bool)
            or not isinstance(share_ppm, int)
            or share_ppm < 1
            or share_ppm > 1_000_000
        ):
            raise PaymentArtifactError(
                f"dossier.deedAllocation[{index}].sharePpm is invalid"
            )
        numerator = target_raise * share_ppm
        usd_amount_minor, remainder = divmod(numerator, 1_000_000)
        if remainder:
            raise PaymentArtifactError(
                "sealed deed allocation produces fractional USD minor units"
            )
        price = DeedPriceV1(
            deed_id=bytes32(canonicalise_property_id(deed_id)),
            share_ppm=share_ppm,
            usd_amount_minor=usd_amount_minor,
        )
        prices.append(price)
        if deed_id.casefold() == selected_id.casefold():
            if selected_price is not None:
                raise PaymentArtifactError(
                    "sealed deed allocation contains duplicate deed IDs"
                )
            selected_price = price
            dossier_par_value = _positive_decimal_integer(
                item.get("parValueMojos"),
                f"dossier.deedAllocation[{index}].parValueMojos",
            )
            collection_par_value = _positive_decimal_integer(
                selected_deed.get("parValueMojos"),
                "collection deed parValueMojos",
            )
            if dossier_par_value != collection_par_value:
                raise PaymentArtifactError(
                    "collection deed par value does not match the sealed allocation"
                )

    validate_deed_price_plan(
        prices,
        target_raise_usd_minor=target_raise,
    )
    if selected_price is None:
        raise PaymentArtifactError(
            "purchase deed is not in the sealed dossier allocation"
        )
    if selected_price.share_ppm != int(selected_deed["sharePpm"]):
        raise PaymentArtifactError(
            "collection deed share does not match the sealed allocation"
        )
    return selected_price.share_ppm, selected_price.usd_amount_minor


def _positive_decimal_integer(value: Any, label: str) -> int:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise PaymentArtifactError(
            f"{label} must be a canonical positive decimal string"
        )
    parsed = int(value)
    if parsed < 1:
        raise PaymentArtifactError(f"{label} must be positive")
    return parsed


def _assert_protocol_offer_public_artifact(
    artifact: Mapping[str, Any],
) -> None:
    scan_target = dict(artifact)
    # These two envelopes have strict parsers and contain intentionally public
    # fields named authorizationNonce and signature. They carry no credential.
    scan_target.pop("purchaseArtifactV2", None)
    scan_target.pop("oracleAuthorization", None)
    _assert_public_artifact(scan_target, "protocol_offer_artifact")


def _bytes32_field(value: str, label: str) -> bytes32:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 66:
        raise PaymentArtifactError(f"{label} must be 0x-prefixed bytes32")
    try:
        return bytes32.from_hexstr(value)
    except ValueError as exc:
        raise PaymentArtifactError(f"{label} must be valid bytes32") from exc


def _normalized_hex32(value: str, label: str) -> str:
    return _hex32(_bytes32_field(value, label))


def _normalized_evm_address(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        raise PaymentArtifactError(f"{label} must be 0x-prefixed bytes20")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise PaymentArtifactError(f"{label} must be valid bytes20") from exc
    if raw == b"\x00" * 20:
        raise PaymentArtifactError(f"{label} cannot be zero")
    return "0x" + raw.hex()


def _evm_token_asset_id(value: str) -> bytes32:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        raise PaymentArtifactError(
            "configured EVM stablecoin address must be 0x-prefixed bytes20"
        )
    try:
        token = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise PaymentArtifactError(
            "configured EVM stablecoin address must be valid hex"
        ) from exc
    return bytes32(b"\x00" * 12 + token)


def _hex32(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


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


def _require_omnichain_ingest_token(
    settings: Settings,
    authorization: str | None,
) -> None:
    expected = settings.payment_omnichain_ingest_token
    if not expected or len(expected) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Omnichain escrow callback authentication is not configured.",
        )
    supplied = ""
    if authorization and authorization.startswith("Bearer "):
        supplied = authorization.removeprefix("Bearer ").strip()
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid omnichain escrow callback credential.",
        )
