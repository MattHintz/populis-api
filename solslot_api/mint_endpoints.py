"""Admin Desk mint-proposal endpoints.

Backed by ``MintProposalStore`` for the lifecycle CRUD; gated by
``require_admin_jwt`` from ``admin_auth``.

Step A.2 / B scope:
  * /admin/mint/propose          DRAFT — full implementation
  * /admin/mint                  list  — full implementation
  * /admin/mint/{id}             read  — full implementation
  * /admin/mint/{id}/cancel      DRAFT → CANCELED — full implementation
  * /admin/mint/{id}/publish     501 — mint-side Step B work (SGT lock + EXECUTE_MINT builder)
  * /admin/mint/{id}/execute     501 — mint-side Step B work
  * /admin/committee/proposals   list filtered for committee — full impl
  * /admin/committee/vote        publish-only forwarder (Brick 3.5c-3)

Per POP-CANON-013 the committee-vote endpoint is **publish-only** and **not
gated by admin JWT** — the SGT signature embedded in the spend bundle is the
authority, and any SGT holder (not just allowlisted admins) must be able to
participate.  The voter's wallet builds the bundle client-side using the
governance/registry drivers in solslot-protocol (e.g.
``sgt_driver.build_tracker_execute_coin_spend`` + the registry routine
co-spend, sim-proven in ``test_governance_vault_version_execute_sim.py``);
this endpoint validates structure and forwards to coinset.org's mempool.
"""
from __future__ import annotations

import logging
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .admin_auth import AdminClaims, require_admin_jwt
from .config import Settings, get_settings
from .coinset_client import CoinsetClient
from .credential_auth import require_minting_writes
from .mint_proposals import (
    DuplicateProperty,
    InvalidTransition,
    MintProposalStore,
    ProposalNotFound,
    StoredMintProposal,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin-mint"])


def require_mint_writes(
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    require_minting_writes(settings)


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
    expressed in *SGT mojos*; the desk reads it from the deployed
    governance manifest's ``quorum_bps × sgt_total_supply / 10_000``
    and the operator can override per-proposal if the manifest is
    looser than the desired threshold.
    """
    par_value: int = Field(..., gt=0, description="Par value in mojos (1 mojo = 1¢)")
    asset_class: str = Field(..., min_length=1, max_length=64,
                             description='e.g. "RWA-RE-RES" for residential real estate')
    property_id: str = Field(..., min_length=1, max_length=128,
                             description="Operator-assigned canonical id, e.g. \"US-TX-Travis-12345\"")
    collection_id: str = Field(..., min_length=1, max_length=128,
                               description="Canonical collection id used for NAV-registry pricing")
    share_ppm: int = Field(..., ge=1, le=1_000_000,
                           description="Share of collection NAV in ppm; 1000000 = 100%")
    jurisdiction: str = Field(..., min_length=1, max_length=64,
                              description="ISO-style jurisdiction code, e.g. \"US-TX-Travis\"")
    royalty_puzhash: str = Field(..., description="0x-prefixed 32-byte royalty payee puzzle hash")
    royalty_bps: int = Field(..., ge=0, le=10_000,
                             description="Basis points (0–10000) of par_value paid as royalty")
    quorum_required: int = Field(..., gt=0,
                                 description="Minimum SGT-mojos of YES votes for the proposal to pass")
    off_chain_metadata: Optional[dict[str, Any]] = Field(
        None, description="Free-form blob — title, address, photos, attestations etc.",
    )


class PublishProposalMetadataRequest(BaseModel):
    property_id_canon: str = Field(..., description="0x-prefixed bytes32")
    collection_id_canon: str = Field(..., description="0x-prefixed bytes32")
    share_ppm: int = Field(..., ge=1, le=1_000_000)
    property_registry_puzzle_hash: str = Field(..., description="0x-prefixed bytes32")
    par_value_mojos: int = Field(..., gt=0)
    asset_class: int = Field(..., ge=0)
    jurisdiction: str = Field(..., description="0x-prefixed UTF-8 bytes")
    royalty_puzhash: str = Field(..., description="0x-prefixed bytes32")
    royalty_bps: int = Field(..., ge=0, le=10_000)
    quorum_threshold: int = Field(..., gt=0)
    owner_member_hash: str = Field(..., description="0x-prefixed bytes32")
    gov_member_hash: str = Field(..., description="0x-prefixed bytes32")


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
    dependencies=[Depends(require_admin_jwt), Depends(require_mint_writes)],
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
            collection_id=body.collection_id,
            share_ppm=body.share_ppm,
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
    dependencies=[Depends(require_admin_jwt), Depends(require_mint_writes)],
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
    "the API gains actual chain-spend integration (SGT lock, launcher coin "
    "selection, EXECUTE_MINT bundle building, push_tx).  Step A.2 ships "
    "only the DRAFT lifecycle + auth scaffolding."
)


@router.post(
    "/admin/mint/{proposal_id}/publish",
    response_model=dict[str, Any],
    dependencies=[Depends(require_admin_jwt), Depends(require_mint_writes)],
)
async def publish_mint_proposal(proposal_id: str) -> dict[str, Any]:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=f"/admin/mint/{{id}}/publish is not implemented yet. {_STEP_B_NOTE}",
    )


@router.post(
    "/admin/mint/{proposal_id}/execute",
    response_model=dict[str, Any],
    dependencies=[Depends(require_admin_jwt), Depends(require_mint_writes)],
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
# committee voting is open to any SGT holder, not just allowlisted
# admins — locking it behind the admin allowlist would conflate
# "operator desk authority" (an internal-team capability) with
# "SGT-weighted governance" (a token-holder capability), breaking
# decentralised governance.
#
# /committee/proposals is a public read.  /committee/vote (Step B) will
# carry its authority in the embedded SGT-VOTE signature inside the
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

    Public: no authentication required.  Any SGT holder (or any
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


class CommitteeVoteRequest(BaseModel):
    """Publish-only committee-vote payload.

    ``spend_bundle`` is a JSON object matching ``chia_rs.SpendBundle``'s
    ``to_json_dict()`` shape — i.e. ``{coin_spends: [...], aggregated_signature:
    "0x..."}`` — built and signed by the voter's wallet client-side using the
    SGT lock + governance tracker drivers (mirrors of
    ``sgt_driver.build_tracker_execute_coin_spend`` etc.).  The API neither
    constructs nor signs governance spends; it only forwards.

    ``proposal_id`` is purely informational (logged for correlation); the
    proposal binding is enforced on-chain by the bundle's own coin spends
    against the governance tracker singleton's proposal_hash.
    """

    spend_bundle: dict[str, Any] = Field(
        ...,
        description=(
            "SpendBundle JSON dict (chia_rs.SpendBundle.to_json_dict shape)."
        ),
    )
    proposal_id: Optional[str] = Field(
        None,
        max_length=256,
        description="Optional informational proposal id for logging/correlation.",
    )


class CommitteeVoteResponse(BaseModel):
    pushed: bool
    status: str
    spend_bundle_id: str = Field(..., description="0x-prefixed sha256 id of the bundle.")
    proposal_id: Optional[str] = None


async def _get_coinset_dep(request: Request) -> Optional[CoinsetClient]:
    """Lazy ``app.state.coinset`` lookup.

    Defined locally (rather than imported from ``app.py``) to avoid a circular
    import — ``app.py`` includes this router.  Returns ``None`` rather than
    raising so request-body validation errors (422) fire BEFORE the missing-
    coinset 502; the endpoint itself raises 502 when ``coinset is None``.

    Async so the dep runs on the event loop thread (FastAPI dispatches sync
    deps to a worker pool, which would touch chia_rs LazyNodes bound to the
    lifespan thread → pyo3 panic — same constraint as
    :func:`solslot_api.app.get_coinset`).

    Tests override this via ``app.dependency_overrides[_get_coinset_dep] =
    lambda: mock``.
    """
    return getattr(request.app.state, "coinset", None)


@router.post(
    "/admin/committee/vote",
    response_model=CommitteeVoteResponse,
    dependencies=[Depends(require_mint_writes)],
)
async def cast_committee_vote(
    body: CommitteeVoteRequest,
    coinset: Annotated[Optional[CoinsetClient], Depends(_get_coinset_dep)],
) -> CommitteeVoteResponse:
    """Forward a committee-action spend bundle (PROPOSE / VOTE / EXECUTE) to chain.

    Publish-only forwarder.  The SGT signature embedded in the bundle's coin
    spends is the authority (POP-CANON-013): governance voting is open to any
    SGT holder, NOT gated by the admin allowlist — locking it behind admin JWT
    would conflate operator desk authority with token-holder governance.

    The API performs only **structural** validation (the bundle parses as a
    well-formed ``chia_rs.SpendBundle`` with at least one coin spend) before
    handing off to ``coinset.org``'s mempool, which enforces all semantic rules
    (signatures, announcements, quorum, deadlines, lineage).  Mempool rejection
    is surfaced as ``pushed=false`` with the chain's status string so the
    portal can render a precise error; coinset transport failures are 502.
    """
    # Lazy import — chia_rs is heavy and only this endpoint deserializes a
    # SpendBundle on the API side.
    from chia_rs import SpendBundle

    if coinset is None:
        raise HTTPException(
            status_code=502, detail="Coinset client not initialised.",
        )

    try:
        bundle = SpendBundle.from_json_dict(body.spend_bundle)
    except (KeyError, TypeError, ValueError) as e:
        raise HTTPException(
            status_code=400,
            detail=f"spend_bundle is not a valid SpendBundle JSON: {e}",
        ) from e
    if len(bundle.coin_spends) == 0:
        raise HTTPException(
            status_code=400,
            detail="spend_bundle must contain at least one coin_spend.",
        )
    bundle_id = "0x" + bytes(bundle.name()).hex()

    try:
        push_result = await coinset.push_tx(bundle.to_json_dict())
    except Exception as e:
        logger.exception(
            "coinset push_tx failed for committee vote %s (proposal_id=%r): %s",
            bundle_id, body.proposal_id, e,
        )
        raise HTTPException(
            status_code=502, detail=f"coinset.org error forwarding committee vote: {e}",
        ) from e

    accepted = bool(push_result.get("success"))
    if accepted:
        status_str = str(push_result.get("status") or "SUCCESS")
        logger.info(
            "committee vote %s accepted (proposal_id=%r, status=%s)",
            bundle_id, body.proposal_id, status_str,
        )
    else:
        status_str = str(
            push_result.get("status") or push_result.get("error") or push_result
        )
        logger.warning(
            "committee vote %s rejected (proposal_id=%r, status=%s)",
            bundle_id, body.proposal_id, status_str,
        )

    return CommitteeVoteResponse(
        pushed=accepted,
        status=status_str,
        spend_bundle_id=bundle_id,
        proposal_id=body.proposal_id,
    )


__all__ = [
    "router",
    "ProposeMintRequest",
    "CancelMintRequest",
    "MintProposalListResponse",
    "CommitteeVoteRequest",
    "CommitteeVoteResponse",
    "get_mint_proposal_store",
    "reset_mint_store_for_tests",
]
