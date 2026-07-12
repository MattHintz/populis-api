from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

import jwt as pyjwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict

from .admin import require_admin_token
from .admin_auth import require_admin_jwt
from .admin_records import (
    AdminRecordsDriftError,
    AdminRecordsLoadError,
    load_admin_records_from_mapping,
    verify_against_admins_hash_hex,
)
from .bootstrap_manifest import (
    BootstrapArtifactPaths,
    BootstrapManifestError,
    build_bootstrap_artifacts,
    build_bootstrap_recovery_anchor_create_coin_preview,
    build_bootstrap_recovery_anchor_publish_intent,
    persist_bootstrap_artifacts,
    verify_bootstrap_recovery_artifacts,
)
from .config import Settings, get_settings
from .credential_auth import require_alpha_writes


router = APIRouter(prefix="/admin/bootstrap", tags=["admin-bootstrap"])

BOOTSTRAP_COOKIE_NAME = "solslot_bootstrap_session"
BOOTSTRAP_COOKIE_PATH = "/admin/bootstrap"
BOOTSTRAP_SCOPE = "bootstrap"

_resolved_bootstrap_secret: Optional[str] = None


@dataclass(frozen=True)
class BootstrapSessionClaims:
    iat: int
    exp: int


class BootstrapChallengeResponse(BaseModel):
    unlocked: bool
    expires_at: int


class BootstrapStatusResponse(BaseModel):
    locked: bool
    authenticated: bool
    expires_at: Optional[int] = None


class BootstrapFinalizeRequest(BaseModel):
    admin_records: dict[str, Any]
    admin_authority_launcher_id: str
    admins_hash: str
    mips_root: str
    read_only_api_url: Optional[str] = None
    read_only_coinset_url: Optional[str] = None


class AdminAuthorityV2ManifestArtifact(BaseModel):
    model_config = ConfigDict(extra="allow")

    launcher_id: str
    admins_hash: str
    mips_root: str
    authority_version: int


class AdminAuthorityV2RuntimeArtifact(AdminAuthorityV2ManifestArtifact):
    admin_records_hash: str


class BootstrapManifestArtifact(BaseModel):
    model_config = ConfigDict(extra="allow")

    schemaVersion: Literal[2]
    protocolVersion: Literal["solslot-v2"]
    network: str
    protocol: dict[str, Any]
    admin_authority_v2: AdminAuthorityV2ManifestArtifact
    artifact_hashes: dict[str, str]


class PortalRuntimeConfigArtifact(BaseModel):
    model_config = ConfigDict(extra="allow")

    schemaVersion: Literal[2]
    protocolVersion: Literal["solslot-v2"]
    network: str
    protocol: dict[str, Any]
    admin_authority_v2: AdminAuthorityV2RuntimeArtifact


class BootstrapRecoveryAnchorArtifact(BaseModel):
    model_config = ConfigDict(extra="allow")

    version: Literal[2]
    tag: str
    network: str
    admin_authority_v2_launcher_id: str
    authority_version: int
    bootstrap_manifest_hash: str
    portal_runtime_config_hash: str
    admin_records_hash: str


class BootstrapFinalizeResponse(BaseModel):
    locked: bool
    bootstrap_manifest: BootstrapManifestArtifact
    portal_runtime_config: PortalRuntimeConfigArtifact
    bootstrap_recovery_anchor: BootstrapRecoveryAnchorArtifact


class BootstrapRecoveryAnchorPublishIntentResponse(BaseModel):
    network: str
    marker_coin_amount_mojos: int
    admin_authority_v2_launcher_id: str
    authority_version: int
    bootstrap_manifest_hash: str
    portal_runtime_config_hash: str
    admin_records_hash: str
    tag_memo_utf8: str
    tag_memo_hex: str
    payload_memo_json: BootstrapRecoveryAnchorArtifact
    payload_memo_utf8: str
    payload_memo_hex: str
    memos_hex: list[str]
    payload_hash: str


class BootstrapRecoveryAnchorCreateCoinPreviewRequest(BaseModel):
    marker_puzzle_hash: str


class BootstrapRecoveryAnchorCreateCoinPreviewResponse(BaseModel):
    condition_opcode: int
    marker_puzzle_hash: str
    marker_coin_amount_mojos: int
    tag_memo_hex: str
    payload_memo_hex: str
    memos_hex: list[str]
    condition_hex: tuple[int, str, int, tuple[str, str]]
    payload_hash: str


class BootstrapRecoveryAnchorVerifyRequest(BaseModel):
    bootstrap_recovery_anchor: BootstrapRecoveryAnchorArtifact
    bootstrap_manifest: BootstrapManifestArtifact
    portal_runtime_config: PortalRuntimeConfigArtifact
    admin_records: dict[str, Any]
    deployment_manifest: Optional[dict[str, Any]] = None
    live_admin_authority_v2: Optional[AdminAuthorityV2ManifestArtifact] = None


class BootstrapRecoveryAnchorVerifyResponse(BaseModel):
    verified: bool
    deployment_manifest_verified: bool
    live_authority_verified: bool
    network: Optional[str] = None
    admin_authority_v2_launcher_id: Optional[str] = None
    admins_hash: Optional[str] = None
    mips_root: Optional[str] = None
    authority_version: Optional[int] = None
    bootstrap_manifest_hash: Optional[str] = None
    portal_runtime_config_hash: Optional[str] = None
    admin_records_hash: Optional[str] = None
    deployment_manifest_hash: Optional[str] = None
    error: Optional[str] = None


def reset_bootstrap_state_for_tests() -> None:
    global _resolved_bootstrap_secret
    _resolved_bootstrap_secret = None


def bootstrap_manifest_path(settings: Settings) -> Path:
    return Path(settings.bootstrap_manifest_path)


def bootstrap_locked(settings: Settings) -> bool:
    return bootstrap_manifest_path(settings).exists()


def bootstrap_admin_records_path(settings: Settings) -> Path:
    if settings.admin_records_path:
        return Path(settings.admin_records_path)
    return bootstrap_manifest_path(settings).with_name("admin_records_v2.json")


def portal_runtime_config_path(settings: Settings) -> Path:
    return bootstrap_manifest_path(settings).with_name("portal_runtime_config_v2.json")


def bootstrap_recovery_anchor_path(settings: Settings) -> Path:
    return bootstrap_manifest_path(settings).with_name("bootstrap_recovery_anchor_v2.json")


def load_persisted_bootstrap_recovery_anchor(settings: Settings) -> dict[str, Any]:
    if not bootstrap_locked(settings):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Bootstrap recovery anchor publish intent is available only after bootstrap_manifest_v2.json exists.",
        )
    recovery_anchor_path = bootstrap_recovery_anchor_path(settings)
    if not recovery_anchor_path.exists():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="bootstrap_recovery_anchor_v2.json is required before publishing the recovery anchor.",
        )
    try:
        recovery_anchor = json.loads(recovery_anchor_path.read_text(encoding="utf-8"))
    except OSError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to read bootstrap_recovery_anchor_v2.json.",
        ) from e
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Persisted bootstrap_recovery_anchor_v2.json is invalid: {e}",
        ) from e
    if not isinstance(recovery_anchor, dict):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Persisted bootstrap_recovery_anchor_v2.json is invalid: bootstrap_recovery_anchor_v2.json top-level must be an object",
        )
    return recovery_anchor


def get_bootstrap_secret(settings: Settings) -> str:
    global _resolved_bootstrap_secret
    if _resolved_bootstrap_secret is not None:
        return _resolved_bootstrap_secret
    if settings.bootstrap_session_secret:
        _resolved_bootstrap_secret = settings.bootstrap_session_secret
    else:
        _resolved_bootstrap_secret = secrets.token_hex(32)
    return _resolved_bootstrap_secret


def issue_bootstrap_session(settings: Settings) -> tuple[str, int]:
    now = int(time.time())
    exp = now + settings.bootstrap_session_ttl_seconds
    payload = {
        "scope": BOOTSTRAP_SCOPE,
        "iat": now,
        "exp": exp,
    }
    token = pyjwt.encode(payload, get_bootstrap_secret(settings), algorithm="HS256")
    return token, exp


def verify_bootstrap_session(token: str, settings: Settings) -> BootstrapSessionClaims:
    try:
        payload = pyjwt.decode(
            token,
            get_bootstrap_secret(settings),
            algorithms=["HS256"],
            options={"require": ["scope", "exp", "iat"]},
        )
    except pyjwt.ExpiredSignatureError as e:
        raise ValueError("bootstrap session expired") from e
    except pyjwt.InvalidTokenError as e:
        raise ValueError(f"invalid bootstrap session: {e}") from e
    if payload.get("scope") != BOOTSTRAP_SCOPE:
        raise ValueError("bootstrap session scope is not 'bootstrap'")
    return BootstrapSessionClaims(iat=int(payload["iat"]), exp=int(payload["exp"]))


def require_bootstrap_session(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> BootstrapSessionClaims:
    if bootstrap_locked(settings):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Bootstrapper is locked because bootstrap_manifest_v2.json already exists.",
        )
    token = request.cookies.get(BOOTSTRAP_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bootstrap session cookie.",
        )
    try:
        return verify_bootstrap_session(token, settings)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


def require_recovery_anchor_handoff_auth(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> Any:
    if authorization:
        return require_admin_jwt(settings, authorization)
    token = request.cookies.get(BOOTSTRAP_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing admin bearer token or bootstrap session cookie.",
        )
    try:
        return verify_bootstrap_session(token, settings)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


@router.post("/challenge", response_model=BootstrapChallengeResponse)
async def bootstrap_challenge(
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> BootstrapChallengeResponse:
    if bootstrap_locked(settings):
        response.delete_cookie(BOOTSTRAP_COOKIE_NAME, path=BOOTSTRAP_COOKIE_PATH)
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Bootstrapper is locked because bootstrap_manifest_v2.json already exists.",
        )
    require_admin_token(settings, authorization)
    token, exp = issue_bootstrap_session(settings)
    response.set_cookie(
        BOOTSTRAP_COOKIE_NAME,
        token,
        max_age=settings.bootstrap_session_ttl_seconds,
        httponly=True,
        secure=settings.bootstrap_cookie_secure,
        samesite="strict",
        path=BOOTSTRAP_COOKIE_PATH,
    )
    return BootstrapChallengeResponse(unlocked=True, expires_at=exp)


@router.get("/status", response_model=BootstrapStatusResponse)
async def bootstrap_status(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> BootstrapStatusResponse:
    locked = bootstrap_locked(settings)
    if locked:
        return BootstrapStatusResponse(
            locked=True,
            authenticated=False,
        )
    token = request.cookies.get(BOOTSTRAP_COOKIE_NAME)
    if not token:
        return BootstrapStatusResponse(
            locked=False,
            authenticated=False,
        )
    try:
        claims = verify_bootstrap_session(token, settings)
    except ValueError:
        return BootstrapStatusResponse(
            locked=False,
            authenticated=False,
        )
    return BootstrapStatusResponse(
        locked=False,
        authenticated=True,
        expires_at=claims.exp,
    )


@router.post("/finalize", response_model=BootstrapFinalizeResponse)
async def bootstrap_finalize(
    body: BootstrapFinalizeRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    _claims: Annotated[BootstrapSessionClaims, Depends(require_bootstrap_session)],
) -> BootstrapFinalizeResponse:
    require_alpha_writes(settings)
    deployment_manifest_path = Path(settings.deployment_manifest_path)
    if not deployment_manifest_path.exists():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Protocol deployment manifest is required before bootstrap finalize.",
        )

    try:
        deployment_manifest = json.loads(deployment_manifest_path.read_text())
        if not isinstance(deployment_manifest, dict):
            raise ValueError("deployment manifest top-level must be an object")
        admin_records_config = load_admin_records_from_mapping(
            body.admin_records,
            "admin_records",
        )
        verify_against_admins_hash_hex(admin_records_config, body.admins_hash)
        artifacts = build_bootstrap_artifacts(
            deployment_manifest=deployment_manifest,
            admin_records=body.admin_records,
            admin_authority_launcher_id=body.admin_authority_launcher_id,
            admins_hash=body.admins_hash,
            mips_root=body.mips_root,
            read_only_api_url=body.read_only_api_url,
            read_only_coinset_url=body.read_only_coinset_url,
        )
        persist_bootstrap_artifacts(
            artifacts=artifacts,
            admin_records=body.admin_records,
            paths=BootstrapArtifactPaths(
                admin_records_json=bootstrap_admin_records_path(settings),
                portal_runtime_config_json=portal_runtime_config_path(settings),
                bootstrap_recovery_anchor_json=bootstrap_recovery_anchor_path(settings),
                bootstrap_manifest_json=bootstrap_manifest_path(settings),
            ),
        )
    except (AdminRecordsLoadError, AdminRecordsDriftError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Bootstrap finalize admin records validation failed: {e}",
        ) from e
    except BootstrapManifestError as e:
        detail = str(e)
        if "already exists" in detail:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Bootstrapper is locked because bootstrap_manifest_v2.json already exists.",
            ) from e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Bootstrap finalize artifact validation failed: {detail}",
        ) from e
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Protocol deployment manifest is corrupt or unreadable.",
        ) from e
    except OSError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist bootstrap artifacts.",
        ) from e

    return BootstrapFinalizeResponse(
        locked=True,
        bootstrap_manifest=artifacts.bootstrap_manifest,
        portal_runtime_config=artifacts.portal_runtime_config,
        bootstrap_recovery_anchor=artifacts.bootstrap_recovery_anchor,
    )


@router.get(
    "/recovery-anchor/publish-intent",
    response_model=BootstrapRecoveryAnchorPublishIntentResponse,
)
async def bootstrap_recovery_anchor_publish_intent(
    settings: Annotated[Settings, Depends(get_settings)],
    _auth: Annotated[Any, Depends(require_recovery_anchor_handoff_auth)],
) -> BootstrapRecoveryAnchorPublishIntentResponse:
    try:
        recovery_anchor = load_persisted_bootstrap_recovery_anchor(settings)
        intent = build_bootstrap_recovery_anchor_publish_intent(
            bootstrap_recovery_anchor=recovery_anchor,
        )
        tag_memo_utf8 = intent.tag_memo.decode("utf-8")
        payload_memo_utf8 = intent.payload_memo.decode("utf-8")
        payload_memo_json = json.loads(payload_memo_utf8)
    except (BootstrapManifestError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Persisted bootstrap_recovery_anchor_v2.json is invalid: {e}",
        ) from e
    return BootstrapRecoveryAnchorPublishIntentResponse(
        network=intent.network,
        marker_coin_amount_mojos=intent.marker_coin_amount_mojos,
        admin_authority_v2_launcher_id=intent.admin_authority_v2_launcher_id,
        authority_version=intent.authority_version,
        bootstrap_manifest_hash=intent.bootstrap_manifest_hash,
        portal_runtime_config_hash=intent.portal_runtime_config_hash,
        admin_records_hash=intent.admin_records_hash,
        tag_memo_utf8=tag_memo_utf8,
        tag_memo_hex="0x" + intent.tag_memo.hex(),
        payload_memo_json=payload_memo_json,
        payload_memo_utf8=payload_memo_utf8,
        payload_memo_hex="0x" + intent.payload_memo.hex(),
        memos_hex=["0x" + memo.hex() for memo in intent.memos],
        payload_hash=intent.payload_hash,
    )


@router.post(
    "/recovery-anchor/create-coin-preview",
    response_model=BootstrapRecoveryAnchorCreateCoinPreviewResponse,
)
async def bootstrap_recovery_anchor_create_coin_preview(
    body: BootstrapRecoveryAnchorCreateCoinPreviewRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    _auth: Annotated[Any, Depends(require_recovery_anchor_handoff_auth)],
) -> BootstrapRecoveryAnchorCreateCoinPreviewResponse:
    try:
        recovery_anchor = load_persisted_bootstrap_recovery_anchor(settings)
        intent = build_bootstrap_recovery_anchor_publish_intent(
            bootstrap_recovery_anchor=recovery_anchor,
        )
    except BootstrapManifestError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Persisted bootstrap_recovery_anchor_v2.json is invalid: {e}",
        ) from e
    try:
        preview = build_bootstrap_recovery_anchor_create_coin_preview(
            publish_intent=intent,
            marker_puzzle_hash=body.marker_puzzle_hash,
        )
    except BootstrapManifestError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Bootstrap recovery anchor CREATE_COIN preview failed: {e}",
        ) from e
    tag_memo_hex = "0x" + preview.tag_memo.hex()
    payload_memo_hex = "0x" + preview.payload_memo.hex()
    return BootstrapRecoveryAnchorCreateCoinPreviewResponse(
        condition_opcode=preview.condition_opcode,
        marker_puzzle_hash=preview.marker_puzzle_hash,
        marker_coin_amount_mojos=preview.marker_coin_amount_mojos,
        tag_memo_hex=tag_memo_hex,
        payload_memo_hex=payload_memo_hex,
        memos_hex=[tag_memo_hex, payload_memo_hex],
        condition_hex=preview.condition_hex,
        payload_hash=preview.payload_hash,
    )


@router.post(
    "/recovery-anchor/verify",
    response_model=BootstrapRecoveryAnchorVerifyResponse,
)
async def bootstrap_recovery_anchor_verify(
    body: BootstrapRecoveryAnchorVerifyRequest,
) -> BootstrapRecoveryAnchorVerifyResponse:
    try:
        verification = verify_bootstrap_recovery_artifacts(
            bootstrap_recovery_anchor=body.bootstrap_recovery_anchor.model_dump(),
            bootstrap_manifest=body.bootstrap_manifest.model_dump(),
            portal_runtime_config=body.portal_runtime_config.model_dump(),
            admin_records=body.admin_records,
            deployment_manifest=body.deployment_manifest,
            live_admin_authority_v2=(
                body.live_admin_authority_v2.model_dump()
                if body.live_admin_authority_v2 is not None
                else None
            ),
        )
    except BootstrapManifestError as e:
        return BootstrapRecoveryAnchorVerifyResponse(
            verified=False,
            deployment_manifest_verified=False,
            live_authority_verified=False,
            error=str(e),
        )
    return BootstrapRecoveryAnchorVerifyResponse(
        verified=True,
        deployment_manifest_verified=body.deployment_manifest is not None,
        live_authority_verified=body.live_admin_authority_v2 is not None,
        network=verification.network,
        admin_authority_v2_launcher_id=verification.admin_authority_v2_launcher_id,
        admins_hash=verification.admins_hash,
        mips_root=verification.mips_root,
        authority_version=verification.authority_version,
        bootstrap_manifest_hash=verification.bootstrap_manifest_hash,
        portal_runtime_config_hash=verification.portal_runtime_config_hash,
        admin_records_hash=verification.admin_records_hash,
        deployment_manifest_hash=verification.deployment_manifest_hash,
    )


__all__ = [
    "BOOTSTRAP_COOKIE_NAME",
    "BOOTSTRAP_COOKIE_PATH",
    "BOOTSTRAP_SCOPE",
    "BootstrapChallengeResponse",
    "BootstrapRecoveryAnchorCreateCoinPreviewRequest",
    "BootstrapRecoveryAnchorCreateCoinPreviewResponse",
    "BootstrapRecoveryAnchorVerifyRequest",
    "BootstrapRecoveryAnchorVerifyResponse",
    "BootstrapFinalizeRequest",
    "BootstrapFinalizeResponse",
    "BootstrapRecoveryAnchorArtifact",
    "BootstrapRecoveryAnchorPublishIntentResponse",
    "BootstrapStatusResponse",
    "BootstrapSessionClaims",
    "bootstrap_admin_records_path",
    "bootstrap_locked",
    "bootstrap_manifest_path",
    "bootstrap_recovery_anchor_create_coin_preview",
    "bootstrap_recovery_anchor_path",
    "bootstrap_recovery_anchor_publish_intent",
    "bootstrap_recovery_anchor_verify",
    "issue_bootstrap_session",
    "load_persisted_bootstrap_recovery_anchor",
    "portal_runtime_config_path",
    "require_recovery_anchor_handoff_auth",
    "require_bootstrap_session",
    "reset_bootstrap_state_for_tests",
    "router",
    "verify_bootstrap_session",
]
