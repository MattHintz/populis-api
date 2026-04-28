"""Admin Desk authentication: wallet-signed challenge + short-lived JWT.

Replaces the static `POPULIS_ADMIN_TOKEN` flow for interactive operator
sessions.  See ``docs/ADMIN_DESK_DESIGN.md`` §3 for the full rationale.

Flow:
    1. Client POST /admin/auth/challenge { owner, auth_type } →
       server issues a 32-byte nonce + EIP-712 envelope.  Nonce is
       held in a dedicated ChallengeStore (separate from the vault
       registration store so DoS / rate-limit budgets don't share).
    2. Client signs the envelope with their wallet (signTypedData_v4
       for EVM; AugSchemeMPL for BLS — same patterns as the vault
       registration flow already supports).
    3. Client POST /admin/auth/login { owner, nonce, signature }.
       Server:
         a. Pops the challenge atomically (write-once-read-once).
         b. Recovers the pubkey from the signature.
         c. Verifies the recovered address matches ``owner``.
         d. Verifies the recovered pubkey is in the allowlist.
         e. Issues a short-lived JWT (HS256, default 15-min TTL).
    4. Client uses ``Authorization: Bearer <jwt>`` for /admin/mint/*
       and /admin/auth/refresh.

The JWT secret is configured via ``POPULIS_ADMIN_JWT_SECRET``.  If
unset, a per-process random secret is generated — fine for local
development (every restart invalidates outstanding tokens) but
production deployments MUST set this explicitly.
"""
from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Optional

import jwt as pyjwt
from eth_utils import to_checksum_address
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from .challenges import ChallengeStore, ChallengeStoreFullError, RateLimitedError
from .config import Settings, get_settings
from .evm_auth import recover_evm_signer

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/auth", tags=["admin-auth"])


# ── EIP-712 envelope for admin login ─────────────────────────────────────────
ADMIN_LOGIN_PRIMARY_TYPE = "PopulisAdminLogin"

ADMIN_LOGIN_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
    ],
    ADMIN_LOGIN_PRIMARY_TYPE: [
        {"name": "owner",    "type": "address"},
        {"name": "nonce",    "type": "bytes32"},
        # ``issuedAt`` lets the user's wallet display when the challenge
        # was minted — a small UX nicety + a defense-in-depth check
        # against grossly stale signatures (the server still enforces
        # TTL via the ChallengeStore expires_at).
        {"name": "issuedAt", "type": "uint256"},
    ],
}


def admin_login_typed_data(
    owner_address: str,
    nonce_hex: str,
    issued_at: int,
    settings: Settings,
) -> dict[str, Any]:
    """Build the EIP-712 envelope the admin signs to log in.

    Mirrors ``evm_auth.registration_typed_data`` — same domain so the
    user's wallet trust model carries over — but with a distinct
    primary type so a registration signature cannot replay as a login
    signature.  EVM wallets display the primary type prominently in
    the signing prompt.
    """
    return {
        "types": ADMIN_LOGIN_TYPES,
        "primaryType": ADMIN_LOGIN_PRIMARY_TYPE,
        "domain": {
            "name": settings.eip712_name,
            "version": settings.eip712_version,
            "chainId": settings.eip712_chain_id,
        },
        "message": {
            "owner": to_checksum_address(owner_address),
            "nonce": nonce_hex,
            "issuedAt": issued_at,
        },
    }


# ── Module-level state ───────────────────────────────────────────────────────
# Dedicated challenge store so admin login flow has its own rate-limit
# + max-pending budget, distinct from the vault-registration challenges.
_admin_challenges: Optional[ChallengeStore] = None
_resolved_jwt_secret: Optional[str] = None


def get_admin_challenges() -> ChallengeStore:
    global _admin_challenges
    if _admin_challenges is None:
        s = get_settings()
        _admin_challenges = ChallengeStore(
            ttl_seconds=s.challenge_ttl_seconds,
            max_pending=2_000,                          # admin desk: tiny vs public vault flow
            per_ip_per_minute=s.admin_login_per_ip_per_minute,
        )
    return _admin_challenges


def get_jwt_secret(settings: Optional[Settings] = None) -> str:
    """Return the configured JWT secret, caching a random fallback once.

    If ``POPULIS_ADMIN_JWT_SECRET`` is set, it's used verbatim.  Otherwise
    a per-process random secret is generated on first use.  Subsequent
    calls return the same secret so tokens issued in the same process
    are mutually verifiable.
    """
    global _resolved_jwt_secret
    if _resolved_jwt_secret is not None:
        return _resolved_jwt_secret
    s = settings or get_settings()
    if s.admin_jwt_secret:
        _resolved_jwt_secret = s.admin_jwt_secret
    else:
        _resolved_jwt_secret = secrets.token_hex(32)
        logger.warning(
            "POPULIS_ADMIN_JWT_SECRET unset; generated a random per-process "
            "secret. Outstanding admin tokens will not survive restart."
        )
    return _resolved_jwt_secret


def reset_admin_state_for_tests() -> None:
    """Test-only helper: clear the cached challenge store + JWT secret."""
    global _admin_challenges, _resolved_jwt_secret
    _admin_challenges = None
    _resolved_jwt_secret = None


# ── JWT helpers ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class AdminClaims:
    """Decoded JWT claims for an authenticated admin desk user."""
    sub: str             # owner pubkey (lowercase 0x-hex)
    auth_type: str       # "evm" | "chia_bls"
    iat: int
    exp: int


def issue_jwt(
    *,
    sub: str,
    auth_type: str,
    settings: Settings,
) -> tuple[str, int]:
    """Mint a fresh admin JWT.  Returns ``(token, expires_at_unix)``."""
    now = int(time.time())
    exp = now + settings.admin_jwt_ttl_seconds
    payload = {
        "sub": sub.lower(),
        "auth_type": auth_type,
        "iat": now,
        "exp": exp,
        "scope": "admin",
    }
    token = pyjwt.encode(
        payload, get_jwt_secret(settings), algorithm="HS256",
    )
    return token, exp


class JWTVerifyError(Exception):
    """Raised when JWT verification fails (expired, malformed, wrong sig)."""


def verify_jwt(token: str, settings: Optional[Settings] = None) -> AdminClaims:
    """Decode + verify an admin JWT.  Raises JWTVerifyError on failure."""
    s = settings or get_settings()
    try:
        payload = pyjwt.decode(
            token,
            get_jwt_secret(s),
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "iat", "scope"]},
        )
    except pyjwt.ExpiredSignatureError as e:
        raise JWTVerifyError("token expired") from e
    except pyjwt.InvalidTokenError as e:
        raise JWTVerifyError(f"invalid token: {e}") from e

    if payload.get("scope") != "admin":
        raise JWTVerifyError("token scope is not 'admin'")
    auth_type = payload.get("auth_type", "")
    if auth_type not in ("evm", "chia_bls"):
        raise JWTVerifyError(f"unknown auth_type: {auth_type!r}")
    return AdminClaims(
        sub=str(payload["sub"]),
        auth_type=auth_type,
        iat=int(payload["iat"]),
        exp=int(payload["exp"]),
    )


# ── FastAPI dependency ───────────────────────────────────────────────────────
def require_admin_jwt(
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> AdminClaims:
    """Guard for /admin/mint/* (and /admin/auth/refresh).

    Returns the decoded admin claims; the wrapped handler can read
    ``claims.sub`` to attribute actions back to the operator.

    503 if the admin desk is not configured (empty allowlist).
    401 if the Authorization header is missing or malformed.
    403 if the JWT is invalid/expired/forged.
    """
    if not settings.admin_pubkey_allowlist_set():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Admin desk is disabled (POPULIS_ADMIN_PUBKEY_ALLOWLIST unset)."
            ),
        )
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header (expected 'Bearer <token>').",
        )
    token = authorization.split(None, 1)[1].strip()
    try:
        return verify_jwt(token, settings)
    except JWTVerifyError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(e),
        ) from e


# ── Wire schemas ─────────────────────────────────────────────────────────────
AuthType = Literal["evm", "chia_bls"]


class AdminChallengeRequest(BaseModel):
    owner: str = Field(..., description="0x-prefixed Ethereum address (EVM) "
                                        "or 0x-prefixed BLS G1 pubkey hex.")
    auth_type: AuthType = Field("evm")


class AdminChallengeResponse(BaseModel):
    nonce: str
    expires_at: int
    typed_data: dict[str, Any]


class AdminLoginRequest(BaseModel):
    owner: str
    nonce: str
    signature: str
    auth_type: AuthType = Field("evm")


class AdminLoginResponse(BaseModel):
    jwt: str
    expires_at: int
    owner: str


class AdminRefreshResponse(BaseModel):
    jwt: str
    expires_at: int


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post("/challenge", response_model=AdminChallengeResponse)
async def admin_challenge(
    body: AdminChallengeRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AdminChallengeResponse:
    """Issue a fresh login challenge for an admin candidate.

    Rate-limited (POPULIS_ADMIN_LOGIN_PER_IP_PER_MINUTE) and capped on
    total pending size to bound DoS surface.  Does NOT verify
    allowlist membership at this stage — that check happens on
    /login.  Issuing a challenge is harmless even for an unrecognised
    pubkey because the challenge is single-use and TTL'd.
    """
    if not settings.admin_pubkey_allowlist_set():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin desk is disabled (POPULIS_ADMIN_PUBKEY_ALLOWLIST unset).",
        )

    source_ip = request.client.host if request.client else None
    store = get_admin_challenges()
    try:
        ch = store.issue(
            address=body.owner,
            auth_type=body.auth_type,
            source_ip=source_ip,
        )
    except RateLimitedError as e:
        raise HTTPException(status_code=429, detail=str(e)) from e
    except ChallengeStoreFullError as e:
        raise HTTPException(status_code=429, detail=str(e)) from e

    issued_at = int(ch.issued_at)
    if body.auth_type == "evm":
        typed_data = admin_login_typed_data(
            owner_address=body.owner,
            nonce_hex=ch.nonce,
            issued_at=issued_at,
            settings=settings,
        )
    else:
        # BLS path: surface the same fields as a flat dict; the chia
        # wallet service in the portal will hash + sign these directly.
        # Step A.2 leaves the BLS verification path as 501 in /login;
        # the challenge envelope is provided so future work can
        # implement it without breaking the wire schema.
        typed_data = {
            "primaryType": ADMIN_LOGIN_PRIMARY_TYPE,
            "message": {
                "owner": body.owner,
                "nonce": ch.nonce,
                "issuedAt": issued_at,
            },
        }

    return AdminChallengeResponse(
        nonce=ch.nonce,
        expires_at=int(ch.expires_at),
        typed_data=typed_data,
    )


@router.post("/login", response_model=AdminLoginResponse)
async def admin_login(
    body: AdminLoginRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AdminLoginResponse:
    """Verify a signed challenge and mint a short-lived admin JWT.

    Errors:
      404  nonce not found / already consumed / expired
      401  signature invalid / address mismatch
      403  recovered pubkey not in allowlist
      501  auth_type=='chia_bls' (BLS verification deferred to a
           later checkpoint; see the module-level comment)
    """
    if not settings.admin_pubkey_allowlist_set():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin desk is disabled (POPULIS_ADMIN_PUBKEY_ALLOWLIST unset).",
        )

    if body.auth_type == "chia_bls":
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "BLS admin login is reserved for a later checkpoint. "
                "Use auth_type='evm' for now."
            ),
        )

    store = get_admin_challenges()
    ch = store.pop(nonce=body.nonce, address=body.owner, auth_type=body.auth_type)
    if ch is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Challenge not found / already consumed / expired.",
        )

    typed_data = admin_login_typed_data(
        owner_address=body.owner,
        nonce_hex=ch.nonce,
        issued_at=int(ch.issued_at),
        settings=settings,
    )
    try:
        recovery = recover_evm_signer(typed_data, body.signature)
    except Exception as e:
        # eth_keys raises BadSignature (which is *not* a ValueError) when
        # v/r/s components are out of range; eth_account raises a few
        # other errors when the structure is malformed.  All of these
        # collapse to a 401 from the caller's perspective — the
        # signature is unusable.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Signature verification failed: {e}",
        ) from e

    if recovery.address.lower() != body.owner.lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Recovered address {recovery.address} does not match "
                f"declared owner {body.owner}."
            ),
        )

    # Allowlist check.  We accept either the address (typical operator
    # convention — short hex) OR the recovered compressed pubkey
    # (33-byte hex), so an operator can configure whichever they
    # prefer.  Compare lowercased.
    allowlist = settings.admin_pubkey_allowlist_set()
    candidates = {
        recovery.address.lower(),
        recovery.compressed_pubkey_hex.lower(),
    }
    if not (candidates & allowlist):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Recovered pubkey is not in POPULIS_ADMIN_PUBKEY_ALLOWLIST. "
                f"address={recovery.address}"
            ),
        )

    # Use the address (lowercase) as the JWT subject for evm auth;
    # that's what the portal will display in its UI and what the
    # mint-proposal store will tag rows with via owner_pubkey.
    sub = recovery.address.lower()
    token, exp = issue_jwt(
        sub=sub,
        auth_type=body.auth_type,
        settings=settings,
    )
    logger.info("Admin login: %s authenticated (auth_type=%s)", sub, body.auth_type)
    return AdminLoginResponse(jwt=token, expires_at=exp, owner=sub)


@router.post("/refresh", response_model=AdminRefreshResponse)
async def admin_refresh(
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AdminRefreshResponse:
    """Mint a new JWT with a fresh expiry, given a still-valid current one.

    This lets a long-running admin session avoid forcing the user to
    re-sign with their wallet every TTL period; the JWT itself is the
    proof of authorisation.  If the current JWT has expired the
    dependency returns 403 and the client must restart the login flow.

    A subsequent allowlist change does NOT invalidate already-issued
    JWTs — by design.  Operators rotating the allowlist must restart
    the API to invalidate all in-flight admin sessions; the 15-minute
    default TTL bounds the worst-case delay.
    """
    token, exp = issue_jwt(
        sub=claims.sub,
        auth_type=claims.auth_type,
        settings=settings,
    )
    return AdminRefreshResponse(jwt=token, expires_at=exp)


__all__ = [
    "router",
    "AdminClaims",
    "AdminChallengeRequest",
    "AdminChallengeResponse",
    "AdminLoginRequest",
    "AdminLoginResponse",
    "AdminRefreshResponse",
    "ADMIN_LOGIN_PRIMARY_TYPE",
    "ADMIN_LOGIN_TYPES",
    "admin_login_typed_data",
    "issue_jwt",
    "verify_jwt",
    "require_admin_jwt",
    "get_admin_challenges",
    "get_jwt_secret",
    "reset_admin_state_for_tests",
    "JWTVerifyError",
]
