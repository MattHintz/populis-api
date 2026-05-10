from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Optional

import jwt as pyjwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel

from .admin import require_admin_token
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


def reset_bootstrap_state_for_tests() -> None:
    global _resolved_bootstrap_secret
    _resolved_bootstrap_secret = None


def bootstrap_manifest_path(settings: Settings) -> Path:
    return Path(settings.bootstrap_manifest_path)


def bootstrap_locked(settings: Settings) -> bool:
    return bootstrap_manifest_path(settings).exists()


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


__all__ = [
    "BOOTSTRAP_COOKIE_NAME",
    "BOOTSTRAP_COOKIE_PATH",
    "BOOTSTRAP_SCOPE",
    "BootstrapChallengeResponse",
    "BootstrapStatusResponse",
    "BootstrapSessionClaims",
    "bootstrap_locked",
    "bootstrap_manifest_path",
    "issue_bootstrap_session",
    "require_bootstrap_session",
    "reset_bootstrap_state_for_tests",
    "router",
    "verify_bootstrap_session",
]
