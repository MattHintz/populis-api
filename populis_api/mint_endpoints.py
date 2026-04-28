"""Admin Desk mint-proposal endpoints.

Backed by ``MintProposalStore`` for the lifecycle CRUD; gated by
``require_admin_jwt`` from ``admin_auth``.

Step A.2 scope:
  * /admin/mint/propose          DRAFT — full implementation
  * /admin/mint                  list  — full implementation
  * /admin/mint/{id}             read  — full implementation
  * /admin/mint/{id}/cancel      DRAFT → CANCELED — full implementation
  * /admin/mint/{id}/publish     501 — chain integration is Step B work
  * /admin/mint/{id}/execute     501 — chain integration is Step B work
  * /admin/committee/proposals   list filtered for committee — full impl
  * /admin/committee/vote        501 — chain integration is Step B work

The 501 endpoints surface a deliberate boundary: the API tracks
proposal state in SQLite for the desk UI's sake, but the actual
on-chain spend builders (PGT lock, EXECUTE_MINT, vote forwarding)
are non-trivial driver code that lands in Step B.  Returning 501
with a clear "see Step B" message keeps the API contract honest
without blocking frontend development on /propose, /list, /cancel.
"""
from __future__ import annotations

import logging
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from .admin_auth import AdminClaims, require_admin_jwt
from .config import Settings, get_settings
from .mint_proposals import (
    DuplicateProperty,
    InvalidTransition,
    MintProposalStore,
    ProposalNotFound,
    StoredMintProposal,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin-mint"])


# ── Module-level store singleton ────────────────────────────────────────────
_store: Optional[MintProposalStore] = None


def get_mint_proposal_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> MintProposalStore:
    """Lazy singleton for the SQLite-backed proposal store."""
    global _store
    if _store is None:
        _store = MintProposalStore(settings.admin_db_path)
        logger.info(
            "Opened mint-proposal store at %s (schema v%d)",
            settings.admin_db_path,
            _store.schema_version(),
        )
    return _store


def reset_mint_store_for_tests() -> None:
    """Test-only helper: close + clear the cached store."""
    global _store
    if _store is not None:
        try:
            _store.close()
        except Exception:
            pass
    _store = None


# ── Wire schemas ────────────────────────────────────────────────────────────
def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def _parse_bytes32(value: str, label: str) -> bytes:
    """Decode a 0x-prefixed 32-byte hex string into bytes."""
    raw = _strip0x(value)
    if len(raw) != 64:
        raise HTTPException(
            status_code=400,
            detail=f"{label} must be a 32-byte hex string (got {len(raw)} hex chars)",
        )
    try:
        return bytes.fromhex(raw)
    except ValueError as e:
        raise HTTPException(
            status_code=400, detail=f"{label}: invalid hex ({e})",
        ) from e


class ProposeMintRequest(BaseModel):
    """Inputs the operator gives at DRAFT time.

    ``quorum_required`` is a snapshot of the protocol-level quorum
    expressed in *PGT mojos*; the desk reads it from the deployed
    governance manifest's ``quorum_bps × pgt_total_supply / 10_000``
    and the operator can override per-proposal if the manifest is
    looser than the desired threshold.
    """
    par_value: int = Field(..., gt=0, description="Par value in mojos (1 mojo = 1¢)")
    asset_class: str = Field(..., min_length=1, max_length=64,
                             description='e.g. "RWA-RE-RES" for residential real estate')
    property_id: str = Field(..., min_length=1, max_length=128,
                             description="Operator-assigned canonical id, e.g. \"US-TX-Travis-12345\"")
    jurisdiction: str = Field(..., min_length=1, max_length=64,
                              description="ISO-style jurisdiction code, e.g. \"US-TX-Travis\"")
    royalty_puzhash: str = Field(..., description="0x-prefixed 32-byte royalty payee puzzle hash")
    royalty_bps: int = Field(..., ge=0, le=10_000,
                             description="Basis points (0–10000) of par_value paid as royalty")
    quorum_required: int = Field(..., gt=0,
                                 description="Minimum PGT-mojos of YES votes for the proposal to pass")
    off_chain_metadata: Optional[dict[str, Any]] = Field(
        None, description="Free-form blob — title, address, photos, attestations etc.",
    )


class CancelMintRequest(BaseModel):
    """Empty body — kept as a class so future cancel-reasons can attach."""
    pass


class MintProposalListResponse(BaseModel):
    proposals: list[dict[str, Any]]
    count: int


# ── /admin/mint/* endpoints ─────────────────────────────────────────────────
def _to_response(rec: StoredMintProposal) -> dict[str, Any]:
    return rec.to_public_dict()


@router.post(
    "/admin/mint/propose",
    response_model=dict[str, Any],
    dependencies=[Depends(require_admin_jwt)],
)
async def propose_mint(
    body: ProposeMintRequest,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
) -> dict[str, Any]:
    """Create a DRAFT mint proposal.

    All four computed puzzle hashes (smart_deed_inner / eve_inner /
    deed_full / proposal_hash) depend on the launcher coin id and so
    are NOT computed here — they're populated atomically by /publish
    in Step B.  DRAFT carries only operator metadata.
    """
    royalty_puzhash = _parse_bytes32(body.royalty_puzhash, "royalty_puzhash")
    try:
        rec = store.create(
            owner_pubkey=claims.sub,
            par_value=body.par_value,
            asset_class=body.asset_class,
            property_id=body.property_id,
            jurisdiction=body.jurisdiction,
            royalty_puzhash=royalty_puzhash,
            royalty_bps=body.royalty_bps,
            quorum_required=body.quorum_required,
            off_chain_metadata=body.off_chain_metadata,
        )
    except DuplicateProperty as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    logger.info(
        "Created DRAFT mint proposal %s by %s (property_id=%s par_value=%d)",
        rec.id, claims.sub, rec.property_id, rec.par_value,
    )
    return _to_response(rec)


@router.get(
    "/admin/mint",
    response_model=MintProposalListResponse,
    dependencies=[Depends(require_admin_jwt)],
)
async def list_mint_proposals(
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
    state: Optional[str] = None,
    owner: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> MintProposalListResponse:
    """List proposals, filtered by state and/or owner.

    Returns the public dict shape (same as /admin/mint/{id}).
    """
    if limit < 1 or limit > 1_000:
        raise HTTPException(status_code=400, detail="limit must be 1..1000")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")
    states = [state] if state else None
    try:
        rows = store.list(
            states=states,
            owner_pubkey=owner.lower() if owner else None,
            limit=limit,
            offset=offset,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    total = store.count(state=state)
    return MintProposalListResponse(
        proposals=[_to_response(r) for r in rows],
        count=total,
    )


@router.get(
    "/admin/mint/{proposal_id}",
    response_model=dict[str, Any],
    dependencies=[Depends(require_admin_jwt)],
)
async def get_mint_proposal(
    proposal_id: str,
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
) -> dict[str, Any]:
    rec = store.get(proposal_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Unknown proposal id {proposal_id!r}")
    return _to_response(rec)


@router.post(
    "/admin/mint/{proposal_id}/cancel",
    response_model=dict[str, Any],
    dependencies=[Depends(require_admin_jwt)],
)
async def cancel_mint_proposal(
    proposal_id: str,
    body: CancelMintRequest,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
) -> dict[str, Any]:
    """DRAFT → CANCELED.  Only the original proposer can cancel.

    Cancellation is the operator's escape hatch from a misconfigured
    DRAFT — it removes the active-property reservation so the same
    property_id can be re-proposed cleanly.  Once a proposal is
    PROPOSED on-chain it must run its on-chain lifecycle to
    completion (passes or fails by quorum); /cancel cannot pre-empt
    chain state.
    """
    rec = store.get(proposal_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Unknown proposal id {proposal_id!r}")
    if rec.owner_pubkey.lower() != claims.sub.lower():
        raise HTTPException(
            status_code=403,
            detail=(
                f"Only the original proposer ({rec.owner_pubkey}) may cancel "
                f"this proposal; you are {claims.sub}."
            ),
        )
    try:
        cancelled = store.cancel(proposal_id)
    except InvalidTransition as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except ProposalNotFound as e:
        # Race: the proposal was deleted between get() and cancel().
        raise HTTPException(status_code=404, detail=str(e)) from e
    logger.info("Cancelled mint proposal %s by %s", proposal_id, claims.sub)
    return _to_response(cancelled)


# ── 501 stubs (Step B will replace these with real chain integration) ──────
_STEP_B_NOTE = (
    "This endpoint is reserved for Step B of the Admin Desk rollout, where "
    "the API gains actual chain-spend integration (PGT lock, launcher coin "
    "selection, EXECUTE_MINT bundle building, push_tx).  Step A.2 ships "
    "only the DRAFT lifecycle + auth scaffolding."
)


@router.post(
    "/admin/mint/{proposal_id}/publish",
    response_model=dict[str, Any],
    dependencies=[Depends(require_admin_jwt)],
)
async def publish_mint_proposal(proposal_id: str) -> dict[str, Any]:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=f"/admin/mint/{{id}}/publish is not implemented yet. {_STEP_B_NOTE}",
    )


@router.post(
    "/admin/mint/{proposal_id}/execute",
    response_model=dict[str, Any],
    dependencies=[Depends(require_admin_jwt)],
)
async def execute_mint_proposal(proposal_id: str) -> dict[str, Any]:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=f"/admin/mint/{{id}}/execute is not implemented yet. {_STEP_B_NOTE}",
    )


# ── /admin/committee/* endpoints ────────────────────────────────────────────
#
# POP-CANON-013: committee endpoints are deliberately NOT gated by
# require_admin_jwt.  The design (see ADMIN_DESK_DESIGN.md §6.3) is that
# committee voting is open to any PGT holder, not just allowlisted
# admins — locking it behind the admin allowlist would conflate
# "operator desk authority" (an internal-team capability) with
# "PGT-weighted governance" (a token-holder capability), breaking
# decentralised governance.
#
# /committee/proposals is a public read.  /committee/vote (Step B) will
# carry its authority in the embedded PGT-VOTE signature inside the
# spend bundle — the API is publish-only and validates bundle
# structure, not signer identity.
@router.get(
    "/admin/committee/proposals",
    response_model=MintProposalListResponse,
)
async def list_committee_proposals(
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
    limit: int = 100,
    offset: int = 0,
) -> MintProposalListResponse:
    """List proposals open for committee voting.

    Filters to PROPOSED + VOTING — terminal and DRAFT proposals are
    excluded.  Used by the committee voting UI to populate the
    "open proposals" sidebar.

    Public: no authentication required.  Any PGT holder (or any
    interested observer) may read this list.  Rate-limiting can be
    layered at the reverse-proxy edge if needed.
    """
    if limit < 1 or limit > 1_000:
        raise HTTPException(status_code=400, detail="limit must be 1..1000")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")
    rows = store.list(
        states=["PROPOSED", "VOTING"],
        limit=limit,
        offset=offset,
    )
    # store.count doesn't accept multi-state, so sum manually for the
    # response total.
    total = store.count(state="PROPOSED") + store.count(state="VOTING")
    return MintProposalListResponse(
        proposals=[_to_response(r) for r in rows],
        count=total,
    )


@router.post(
    "/admin/committee/vote",
    response_model=dict[str, Any],
)
async def cast_committee_vote(proposal_id: str = "") -> dict[str, Any]:
    """Forward a committee vote bundle to chain.  Step B implementation.

    The PGT-VOTE signature inside the spend bundle is the authority —
    the API does not require admin JWT authentication for this
    endpoint.  Voters who hold PGT but are not allowlisted admins must
    be able to participate in governance.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=f"/admin/committee/vote is not implemented yet. {_STEP_B_NOTE}",
    )


__all__ = [
    "router",
    "ProposeMintRequest",
    "CancelMintRequest",
    "MintProposalListResponse",
    "get_mint_proposal_store",
    "reset_mint_store_for_tests",
]
