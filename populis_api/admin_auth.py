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
from pydantic import BaseModel, Field, model_validator

from .challenges import ChallengeStore, ChallengeStoreFullError, RateLimitedError
from .config import Settings, get_settings
from .evm_auth import normalize_evm_address, recover_evm_signer

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/auth", tags=["admin-auth"])


# ── EIP-712 envelope for admin login ─────────────────────────────────────────
ADMIN_LOGIN_PRIMARY_TYPE = "PopulisAdminLogin"

# The only scope minted by the JWT issuer today.  Surfaced as a
# constant so the EIP-712 envelope binds it explicitly: when a
# future refactor introduces additional scopes (e.g. ``admin-readonly``
# or per-action scopes), an existing user signature cannot be replayed
# to mint a JWT for the new scope without the operator re-signing
# (POP-CANON-015).
ADMIN_LOGIN_SCOPE = "admin"

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
        # POP-CANON-015: bind authType + scope so a signature for one
        # auth path / scope cannot be replayed for another.  Today
        # ``authType`` is constrained by the challenge store invariant
        # and ``scope`` is hard-coded to ``"admin"``, but the
        # cryptographic binding is what future-proofs the envelope
        # against scope-confusion attacks.
        {"name": "authType", "type": "string"},
        {"name": "scope",    "type": "string"},
    ],
}


def admin_login_typed_data(
    owner_address: str,
    nonce_hex: str,
    issued_at: int,
    settings: Settings,
    *,
    auth_type: str = "evm",
    scope: str = ADMIN_LOGIN_SCOPE,
) -> dict[str, Any]:
    """Build the EIP-712 envelope the admin signs to log in.

    Mirrors ``evm_auth.registration_typed_data`` — same domain so the
    user's wallet trust model carries over — but with a distinct
    primary type so a registration signature cannot replay as a login
    signature.  EVM wallets display the primary type prominently in
    the signing prompt.

    ``auth_type`` and ``scope`` are bound into the signed message so
    a signature for ``auth_type='evm', scope='admin'`` cannot later
    be replayed to authenticate as ``auth_type='chia_bls'`` or for a
    different scope (POP-CANON-015 future-proofing).
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
            "authType": auth_type,
            "scope": scope,
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

    Resolution rules (POP-CANON-016):
      1. If ``POPULIS_ADMIN_JWT_SECRET`` is set: use it verbatim.
      2. If unset AND the allowlist is empty (admin desk disabled):
         generate a per-process random fallback so tests and dev
         environments can issue JWTs without forcing the operator
         to set a secret they're not using.
      3. If unset AND the allowlist is non-empty: refuse — this is
         the multi-worker divergence trap.  Each gunicorn/uvicorn
         worker would otherwise generate its own random secret;
         JWTs issued by worker A would fail verification on worker B,
         producing intermittent 403s indistinguishable from real
         token-tampering signals.

    Subsequent calls return the cached value so tokens issued in the
    same process are mutually verifiable.
    """
    global _resolved_jwt_secret
    if _resolved_jwt_secret is not None:
        return _resolved_jwt_secret
    s = settings or get_settings()
    if s.admin_jwt_secret:
        _resolved_jwt_secret = s.admin_jwt_secret
        return _resolved_jwt_secret

    # POP-CANON-016: fail fast when the admin desk is enabled but
    # the JWT secret is not.  Allow the random-fallback path only
    # when the admin desk itself is disabled (empty allowlist).
    if s.effective_admin_allowlist_set():
        raise RuntimeError(
            "Admin desk is enabled (POPULIS_ADMIN_PUBKEY_ALLOWLIST or "
            "admin_records_path is set) but POPULIS_ADMIN_JWT_SECRET is "
            "empty.  Multi-worker deployments would generate divergent "
            "per-process secrets, causing intermittent 403s when load-"
            "balanced refresh requests land on a different worker than "
            "the original /login.  Set POPULIS_ADMIN_JWT_SECRET to a "
            "stable high-entropy value (≥32 bytes hex) before enabling "
            "the admin desk."
        )

    _resolved_jwt_secret = secrets.token_hex(32)
    logger.warning(
        "POPULIS_ADMIN_JWT_SECRET unset; generated a random per-process "
        "secret. Outstanding admin tokens will not survive restart. "
        "(Allowed because POPULIS_ADMIN_PUBKEY_ALLOWLIST is empty — "
        "the admin desk is disabled.)"
    )
    return _resolved_jwt_secret


def reset_admin_state_for_tests() -> None:
    """Test-only helper: clear the cached challenge store + JWT secret."""
    global _admin_challenges, _resolved_jwt_secret
    _admin_challenges = None
    _resolved_jwt_secret = None


def validate_admin_config_at_startup(settings: Settings) -> None:
    """Fail-fast check, run once from the FastAPI lifespan.

    Surfaces admin-desk misconfiguration at boot rather than at the
    first admin request.  This is the startup-time complement to the
    runtime guard inside ``get_jwt_secret`` (POP-CANON-016): operators
    deploying with monitoring that watches process health get
    immediate feedback, instead of discovering the misconfiguration
    only when an admin tries to sign in hours later.

    Raises:
        RuntimeError: ``POPULIS_ADMIN_PUBKEY_ALLOWLIST`` is non-empty
            but ``POPULIS_ADMIN_JWT_SECRET`` is empty.  In that
            configuration each gunicorn/uvicorn worker would generate
            its own random secret on first JWT issuance, causing
            cross-worker token-verification failures (the
            "intermittent 403s" trap described in
            ``research/CANON_POPULIS_ADMIN_DESK_AUDIT_2026_04_28.md``).
    """
    # ── Phase 2.5b-1: chain-verified admin records (preferred path) ───
    #
    # When admin_records_path is set, load the JSON, verify it binds to
    # the configured launcher_id, and verify its admins_hash matches
    # the operator-supplied (and Phase 2.5b-2: directly-from-chain)
    # ``admins_hash``.  Drift means the JSON is stale or tampered —
    # refuse to boot rather than silently gate with mismatched records.
    #
    # We do this BEFORE the "is admin desk enabled?" check because that
    # check itself loads the records (via ``effective_admin_allowlist_set``);
    # surfacing the load error here gives the operator a single clean
    # boot-time message instead of a half-loaded fallback path.
    if settings.admin_records_path:
        from .admin_records import (
            AdminRecordsDriftError,
            AdminRecordsLoadError,
            get_admin_records_for_settings,
            verify_against_admins_hash,
            verify_against_launcher_id,
        )
        from chia_rs.sized_bytes import bytes32

        try:
            records = get_admin_records_for_settings(settings)
        except AdminRecordsLoadError as e:
            raise RuntimeError(
                f"Failed to load admin records from "
                f"POPULIS_ADMIN_RECORDS_PATH={settings.admin_records_path!r}: {e}"
            ) from e
        except AdminRecordsDriftError as e:
            raise RuntimeError(str(e)) from e
        if records is None:
            # Should not happen — admin_records_path is set so loader
            # returns a config or raises.  Defensive belt-and-braces.
            raise RuntimeError(
                f"admin_records_path set but loader returned None: "
                f"{settings.admin_records_path!r}"
            )

        # Cross-check launcher id against env (catches deployment mix-ups).
        try:
            verify_against_launcher_id(
                records,
                settings.protocol_admin_authority_v2_launcher_id,
            )
        except AdminRecordsDriftError as e:
            raise RuntimeError(str(e)) from e

        # Cross-check admins_hash.  Operator supplies this via
        # POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH today; Phase
        # 2.5b-2 will replace with a direct coinset.org fetch.
        if settings.protocol_admin_authority_v2_admins_hash:
            expected_hex = settings.protocol_admin_authority_v2_admins_hash
            if expected_hex.startswith(("0x", "0X")):
                expected_hex = expected_hex[2:]
            try:
                expected = bytes32(bytes.fromhex(expected_hex))
            except (ValueError, AssertionError) as e:
                raise RuntimeError(
                    f"POPULIS_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH "
                    f"is not valid 32-byte hex: {e}"
                ) from e
            try:
                verify_against_admins_hash(records, expected)
            except AdminRecordsDriftError as e:
                raise RuntimeError(str(e)) from e

        logger.info(
            "Admin desk gated by admin_records_path: "
            "%d admin slot(s), %d EVM address(es) in allowlist.",
            len(records.admin_records),
            len(records.eip712_evm_address_set()),
        )

    if not settings.effective_admin_allowlist_set():
        # Admin desk disabled — random per-process secret is acceptable
        # (it's only used for the dev/test environment paths and never
        # shared across workers because admin endpoints all 503).
        logger.info(
            "Admin desk disabled (no admin_records_path and "
            "POPULIS_ADMIN_PUBKEY_ALLOWLIST unset)."
        )
        return

    if not settings.admin_jwt_secret:
        raise RuntimeError(
            "Admin desk is enabled (POPULIS_ADMIN_PUBKEY_ALLOWLIST is set) "
            "but POPULIS_ADMIN_JWT_SECRET is empty. "
            "Multi-worker deployments would generate divergent per-process "
            "secrets, causing intermittent 403s on load-balanced refresh "
            "requests.  Set POPULIS_ADMIN_JWT_SECRET to a stable "
            "high-entropy value (≥32 bytes hex) before starting the API."
        )

    # ── POP-CANON-021: A.2 transparency drift guard ─────────────────────
    #
    # Three independent settings are involved in admin authority:
    #
    #   1. POPULIS_ADMIN_PUBKEY_ALLOWLIST            (EVM addresses) →
    #      gates require_admin_jwt at request time.
    #   2. POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS  (BLS G1)        →
    #      published via /admin/auth/authority as a transparency
    #      surface; intended to mirror (1) one-to-one.
    #   3. The on-chain singleton at
    #      POPULIS_PROTOCOL_ADMIN_AUTHORITY_LAUNCHER_ID — auditable
    #      truth.  Phase 2.5 deferred.
    #
    # Without a startup check, an operator can ship the API with
    # (1) populated and (2) empty, and the unauthenticated
    # /admin/auth/authority endpoint will publish "no on-chain
    # authority exists" while the admin desk is fully operational.
    # That's transparency theatre: third-party auditors are misled.
    #
    # We refuse to boot in two demonstrable drift cases:
    #
    #   Drift A — EVM allowlist set, BLS pubkey list empty.
    #   Drift B — Both non-empty, cardinality mismatch.
    #
    # The check is intentionally cheap: it runs at startup once, never
    # at request time, and only fires when admin desk is enabled.
    #
    # Phase 2.5b-1: SKIP this check when the admin desk is gated by
    # ``admin_records_path`` rather than the env-var allowlist.  The
    # records JSON encodes the EVM↔BLS mapping per-leaf, so the
    # transparency-drift trap (env says X EVMs, on-chain says 0 BLS
    # keys) doesn't apply — both sides come from the same JSON file
    # whose hash is verified against chain.
    if settings.admin_records_path:
        return

    bls_pubkeys = settings.admin_authority_pubkeys_list()
    allowlist_size = len(settings.admin_pubkey_allowlist_set())

    if not bls_pubkeys:
        raise RuntimeError(
            "Admin authority drift: POPULIS_ADMIN_PUBKEY_ALLOWLIST is set "
            f"({allowlist_size} EVM admin"
            f"{'' if allowlist_size == 1 else 's'}) but "
            "POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS is empty.  "
            "GET /admin/auth/authority would publish "
            "'enabled: false' (no on-chain authority) while the API "
            "fully accepts EVM-signed admin logins — third-party "
            "auditors reading the endpoint would be silently misled.  "
            "Either populate POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS "
            "with one BLS G1 pubkey per EVM admin (each operator must "
            "maintain a 1-to-1 mapping off-chain), or explicitly disable "
            "the admin desk by emptying POPULIS_ADMIN_PUBKEY_ALLOWLIST.  "
            "See SECURITY.md §A.2 for operator key-mapping discipline."
        )

    if len(bls_pubkeys) != allowlist_size:
        raise RuntimeError(
            f"Admin authority cardinality mismatch: "
            f"POPULIS_ADMIN_PUBKEY_ALLOWLIST has {allowlist_size} EVM "
            f"admin{'' if allowlist_size == 1 else 's'}; "
            f"POPULIS_PROTOCOL_ADMIN_AUTHORITY_PUBKEYS has "
            f"{len(bls_pubkeys)} BLS pubkey"
            f"{'' if len(bls_pubkeys) == 1 else 's'}.  "
            "These must be 1-to-1: each EVM admin must have a "
            "corresponding BLS pubkey in the on-chain authority "
            "singleton, and vice versa.  See SECURITY.md §A.2."
        )

    logger.info(
        "Admin desk enabled (%d pubkey%s allowlisted, %d BLS pubkey%s "
        "configured for /admin/auth/authority transparency, JWT TTL %ds).",
        allowlist_size,
        "" if allowlist_size == 1 else "s",
        len(bls_pubkeys),
        "" if len(bls_pubkeys) == 1 else "s",
        settings.admin_jwt_ttl_seconds,
    )


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
    403 if the JWT is invalid/expired/forged, OR if ``claims.sub`` is
        no longer present in the live allowlist (POP-CANON-012:
        revocation must terminate sessions without requiring a process
        restart, even if the JWT itself is still cryptographically
        valid under the unchanged secret).
    """
    if not settings.effective_admin_allowlist_set():
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
        claims = verify_jwt(token, settings)
    except JWTVerifyError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(e),
        ) from e

    # POP-CANON-012: re-check live allowlist on every authenticated
    # request.  An admin removed from POPULIS_ADMIN_PUBKEY_ALLOWLIST
    # must lose all admin authority within at most one settings cache
    # cycle, regardless of whether their JWT is still within its TTL.
    # Without this check, refresh-after-revocation chains keep a
    # compromised admin authoritative until the API process restarts.
    if claims.sub.lower() not in settings.effective_admin_allowlist_set():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Subject {claims.sub} is no longer in the admin allowlist. "
                f"Re-authenticate via /admin/auth/login if your pubkey was re-added."
            ),
        )
    return claims


# ── Wire schemas ─────────────────────────────────────────────────────────────
AuthType = Literal["evm", "chia_bls"]


class AdminChallengeRequest(BaseModel):
    owner: str = Field(..., description="0x-prefixed Ethereum address (EVM) "
                                        "or 0x-prefixed BLS G1 pubkey hex.")
    auth_type: AuthType = Field("evm")

    @model_validator(mode="after")
    def validate_owner_for_auth_type(self):
        if self.auth_type == "evm":
            self.owner = normalize_evm_address(self.owner, "owner")
        return self


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
    if not settings.effective_admin_allowlist_set():
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
            auth_type=body.auth_type,
            scope=ADMIN_LOGIN_SCOPE,
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
                "authType": body.auth_type,
                "scope": ADMIN_LOGIN_SCOPE,
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
    if not settings.effective_admin_allowlist_set():
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
        auth_type=body.auth_type,
        scope=ADMIN_LOGIN_SCOPE,
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
    allowlist = settings.effective_admin_allowlist_set()
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


@router.get("/authority", tags=["admin-auth"])
async def admin_authority(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Public read of the on-chain admin-authority singleton state (A.2).

    Returns the deterministic ``state_hash`` along with the launcher
    coin id, allowlist pubkey hashes (not full pubkeys, for bandwidth
    + privacy), quorum threshold, and authority version.  The endpoint
    is intentionally unauthenticated: any third party can fetch it,
    walk the singleton lineage on coinset.org, and verify the operator
    is publishing the same state on-chain.

    When the operator has not configured A.2 (no launcher id, no
    pubkeys), the response has ``enabled: false`` and most fields are
    ``null`` — the endpoint never 404s, so monitoring tools can
    consistently scrape it.

    Phase 2 (this commit): the singleton is informational; admin desk
    gating still uses ``admin_pubkey_allowlist`` (POP-CANON-012).
    Phase 2.5 wires the singleton into ``require_admin_jwt`` so live
    revocation becomes a chain event, not an env push.

    POP-CANON-021 disclaimer: the response includes a ``phase`` field
    so consumers (auditors, monitors, downstream wallets) can tell
    in-band that the published state is NOT the gating source today.
    Without this field a third party could read the response and
    incorrectly conclude the on-chain BLS quorum is what authorises
    admin requests.  In Phase 2 the BLS quorum authorises *rotations*
    of the on-chain authority singleton; the API admin desk itself is
    still gated by ``POPULIS_ADMIN_PUBKEY_ALLOWLIST``.
    """
    from .admin_authority import build_admin_authority_snapshot
    snap = build_admin_authority_snapshot(settings)
    return {
        "enabled": snap.enabled,
        "launcher_id": snap.launcher_id_hex,
        "allowlist_pubkey_hashes": snap.allowlist_pubkey_hashes_hex,
        "quorum_m": snap.quorum_m,
        "authority_version": snap.authority_version,
        "state_hash": snap.state_hash_hex,
        # ── Transparency-drift disclaimer (POP-CANON-021) ────────
        # The published state above is informational.  The admin desk
        # is gated by `POPULIS_ADMIN_PUBKEY_ALLOWLIST` (EVM addresses,
        # validated against the JWT subject by `require_admin_jwt`),
        # not by the BLS allowlist published here.
        #
        # Phase progression:
        #   "2-informational-only" — current.  This snapshot is
        #     published as a transparency surface, NOT as the
        #     gating source.  Operators must maintain a 1-to-1
        #     EVM↔BLS mapping out-of-band; the startup validator
        #     (POP-CANON-021) refuses to boot when it detects drift.
        #   "2.5-on-chain-gated" — future.  `require_admin_jwt`
        #     reads the on-chain singleton at every request and
        #     rejects subjects whose pubkey hash is not in the
        #     latest unspent state.  At that point gating_source
        #     will become the singleton itself.
        "phase": "2-informational-only",
        "gating_source": "POPULIS_ADMIN_PUBKEY_ALLOWLIST",
        "informational_only": True,
    }


@router.get("/authority_v2", tags=["admin-auth"])
async def admin_authority_v2(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Public read of the on-chain admin-authority v2 singleton state.

    The v2 singleton (``admin_authority_v2_inner.clsp``, Phase 9-Hermes-C)
    replaces v1's flat BLS allowlist with CHIP-0043 MIPS composition:
    each admin slot holds a OneOfN of personal auth methods (BLS,
    EIP-712 / MetaMask, passkey, ...) under a protocol-level MofN quorum.
    Lets admins mix signing methods and add backup keys over time
    without going through PGT governance.

    Returns the deterministic ``state_hash`` along with the launcher
    coin id, MIPS root hash, admins hash, pending-ops hash, and
    authority version. The endpoint is intentionally unauthenticated:
    any third party can fetch it, walk the singleton lineage on
    coinset.org, and verify the operator is publishing the same state
    on-chain.

    When the operator has not configured v2 (no launcher id, no state
    hashes), the response has ``enabled: false`` and most fields are
    ``null`` — the endpoint never 404s, so monitoring tools can
    consistently scrape it.

    The ``phase`` field tells consumers whether v2 is the gating
    source for admin auth or just an informational transparency
    surface (mirrors v1's POP-CANON-021 disclaimer pattern). In Phase
    2-informational-only the admin desk is still gated by v1's BLS
    allowlist; v2's MIPS quorum authorises rotations of the v2
    singleton state but doesn't yet authenticate API requests.

    Migration story: see
    ``research/POPULIS_ADMIN_AUTHORITY_V2_DESIGN.md`` section 7.
    """
    from .admin_authority_v2 import build_admin_authority_v2_snapshot
    snap = build_admin_authority_v2_snapshot(settings)
    return {
        "enabled": snap.enabled,
        "launcher_id": snap.launcher_id_hex,
        "mips_root_hash": snap.mips_root_hash_hex,
        "admins_hash": snap.admins_hash_hex,
        "pending_ops_hash": snap.pending_ops_hash_hex,
        "authority_version": snap.authority_version,
        "state_hash": snap.state_hash_hex,
        "deployment_status": snap.deployment_status,
        "chain_verifiable": snap.chain_verifiable,
        # Migration phase indicator. Mirrors v1's `phase` field shape
        # so consumers can pick the same handling code path.
        "phase": snap.phase,
        # Phase 2.5b: Surface the actual current gating source so
        # consumers don't have to guess which mode is active.
        # POPULIS_ADMIN_RECORDS_PATH (chain-verified records JSON) is
        # PREFERRED when set; the env var is the legacy/fallback path.
        "gating_source": (
            "POPULIS_ADMIN_RECORDS_PATH"
            if settings.admin_records_path
            else "POPULIS_ADMIN_PUBKEY_ALLOWLIST"
        ),
        # ``informational_only`` flips to False when v2 is the actual
        # gating source AND its records JSON is hash-verified against
        # chain.  Phase 2.5b achieves the latter; Phase 4 (v2 quorum
        # actively authorises spends) finishes the former.
        "informational_only": not bool(settings.admin_records_path),
    }


class Eip712LeafHashRequest(BaseModel):
    """Request body for ``POST /admin/auth/eip712/compute_leaf_hash``."""

    secp256k1_pubkey: str = Field(
        ...,
        description=(
            "0x-prefixed 33-byte compressed secp256k1 public key.  Recover "
            "from a wallet signature client-side (the portal does this via "
            "ethers.SigningKey.recoverPublicKey + compressSecp256k1Pubkey)."
        ),
    )
    network: Optional[Literal["testnet11", "mainnet"]] = Field(
        None,
        description=(
            "Chia network selector.  When omitted, falls back to the API's "
            "configured ``POPULIS_NETWORK``.  Bound into the EIP-712 domain "
            "salt so signatures cannot be replayed across networks."
        ),
    )


class Eip712LeafHashResponse(BaseModel):
    """Response shape for ``POST /admin/auth/eip712/compute_leaf_hash``."""

    leaf_hash: str
    """0x-prefixed 32-byte sha256tree of the curried Eip712Member puzzle.

    This is the value the launch wizard pastes into the admin records
    JSON's ``leaves[i].leaf_hash`` field — and what the on-chain
    ``ADMINS_HASH`` ultimately commits to via the singleton state.
    """

    secp256k1_pubkey: str
    """Echoed back from the request, lowercased + 0x-prefixed.  Lets
    the caller copy the entire response into the records JSON without
    re-formatting."""

    type_hash: str
    """0x-prefixed 32-byte CHIP-0037 type hash.  Constant across
    networks; surfaced so the wizard can include it in the records
    JSON without re-deriving."""

    prefix_and_domain_separator: str
    """0x-prefixed 34-byte EIP-712 prefix (0x1901) + domain separator,
    bound to the network's genesis challenge."""

    network: str
    """Echoes which network's domain separator was used."""


@router.post(
    "/eip712/compute_leaf_hash",
    response_model=Eip712LeafHashResponse,
    tags=["admin-auth"],
)
async def admin_eip712_compute_leaf_hash(
    body: Eip712LeafHashRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Eip712LeafHashResponse:
    """Compute the canonical Eip712Member leaf hash for an operator's
    public key.

    **Why this endpoint exists.** The launch wizard needs to write
    ``leaf_hash`` into the admin records JSON before submitting the
    on-chain launch (so it can compute ``admins_hash``, then the eve
    coin's puzzle hash, then the launcher's spend solution).  The
    canonical leaf hash requires currying the ``Eip712Member`` puzzle
    bytecode with the operator's pubkey and tree-hashing the result.
    The portal's WASM SDK (chia-wallet-sdk-wasm 0.33) doesn't yet
    expose the ``eip712_member.clsp`` bytecode (PR #396 adds it but
    isn't released), so we surface a server-side computation here.

    **Trust model.** Pure deterministic computation — no secrets, no
    state, no auth required.  Anyone can call it; anyone can verify
    the response by re-running the same Python helper or (eventually)
    the same WASM helper.  The leaf hash is a public commitment.

    **Errors:**
      400  pubkey is malformed (not 33 bytes, not hex, etc.)
      400  network is configured but neither testnet11 nor mainnet
    """
    from .admin_records import _parse_hex
    from populis_puzzles.eip712_helpers import (
        compute_eip712_member_leaf_hash,
        eip712_prefix_and_domain_separator,
        eip712_type_hash,
        genesis_challenge_for_network,
    )

    network = body.network or settings.network
    try:
        genesis = genesis_challenge_for_network(network)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    try:
        pubkey = _parse_hex(body.secp256k1_pubkey, "secp256k1_pubkey")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if len(pubkey) != 33:
        raise HTTPException(
            status_code=400,
            detail=(
                f"secp256k1_pubkey must be 33 bytes (compressed), "
                f"got {len(pubkey)}"
            ),
        )

    prefix = eip712_prefix_and_domain_separator(genesis)
    type_h = eip712_type_hash()
    try:
        leaf_hash = compute_eip712_member_leaf_hash(
            secp256k1_pubkey=pubkey,
            prefix_and_domain_separator=prefix,
            type_hash=type_h,
        )
    except ValueError as e:
        # Defensive: the parse above already enforces the constraints
        # compute_eip712_member_leaf_hash checks, but surface any
        # mismatch as 400 anyway.
        raise HTTPException(status_code=400, detail=str(e)) from e

    return Eip712LeafHashResponse(
        leaf_hash="0x" + leaf_hash.hex(),
        secp256k1_pubkey="0x" + pubkey.hex(),
        type_hash="0x" + type_h.hex(),
        prefix_and_domain_separator="0x" + prefix.hex(),
        network=network,
    )


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

    Allowlist revocation is enforced by ``require_admin_jwt`` (see
    POP-CANON-012): a subject removed from the allowlist while their
    JWT is still cryptographically valid will fail this dependency
    with 403 — they cannot refresh.  Operators rotating the allowlist
    therefore terminate revoked sessions within at most one
    ``get_settings`` cache cycle, no process restart required.
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
    "ADMIN_LOGIN_SCOPE",
    "ADMIN_LOGIN_TYPES",
    "admin_login_typed_data",
    "validate_admin_config_at_startup",
    "issue_jwt",
    "verify_jwt",
    "require_admin_jwt",
    "get_admin_challenges",
    "get_jwt_secret",
    "reset_admin_state_for_tests",
    "JWTVerifyError",
]
