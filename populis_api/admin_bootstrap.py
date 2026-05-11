from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Optional

import jwt as pyjwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict

from .admin import require_admin_token
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
    persist_bootstrap_artifacts,
)
from .config import Settings, get_settings


router = APIRouter(prefix="/admin/bootstrap", tags=["admin-bootstrap"])

BOOTSTRAP_COOKIE_NAME = "populis_bootstrap_session"
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

    version: int
    network: str
    protocol: dict[str, Any]
    admin_authority_v2: AdminAuthorityV2ManifestArtifact
    artifact_hashes: dict[str, str]


class PortalRuntimeConfigArtifact(BaseModel):
    model_config = ConfigDict(extra="allow")

    version: int
    network: str
    protocol: dict[str, Any]
    admin_authority_v2: AdminAuthorityV2RuntimeArtifact


class BootstrapFinalizeResponse(BaseModel):
    locked: bool
    bootstrap_manifest: BootstrapManifestArtifact
    portal_runtime_config: PortalRuntimeConfigArtifact


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
    return bootstrap_manifest_path(settings).with_name("admin_records.json")


def portal_runtime_config_path(settings: Settings) -> Path:
    return bootstrap_manifest_path(settings).with_name("portal_runtime_config.json")


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
            detail="Bootstrapper is locked because bootstrap_manifest.json already exists.",
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
            detail="Bootstrapper is locked because bootstrap_manifest.json already exists.",
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
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    _claims: Annotated[BootstrapSessionClaims, Depends(require_bootstrap_session)],
) -> BootstrapFinalizeResponse:
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
                detail="Bootstrapper is locked because bootstrap_manifest.json already exists.",
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

    response.delete_cookie(BOOTSTRAP_COOKIE_NAME, path=BOOTSTRAP_COOKIE_PATH)
    return BootstrapFinalizeResponse(
        locked=True,
        bootstrap_manifest=artifacts.bootstrap_manifest,
        portal_runtime_config=artifacts.portal_runtime_config,
    )


__all__ = [
    "BOOTSTRAP_COOKIE_NAME",
    "BOOTSTRAP_COOKIE_PATH",
    "BOOTSTRAP_SCOPE",
    "BootstrapChallengeResponse",
    "BootstrapFinalizeRequest",
    "BootstrapFinalizeResponse",
    "BootstrapStatusResponse",
    "BootstrapSessionClaims",
    "bootstrap_admin_records_path",
    "bootstrap_locked",
    "bootstrap_manifest_path",
    "issue_bootstrap_session",
    "portal_runtime_config_path",
    "require_bootstrap_session",
    "reset_bootstrap_state_for_tests",
    "router",
    "verify_bootstrap_session",
]
