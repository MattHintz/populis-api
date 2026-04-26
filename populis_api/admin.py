"""Admin endpoints for Populis API.

Protected by a static bearer token (POPULIS_ADMIN_TOKEN env var).  When
the token is unset, all admin endpoints return 503 — the safe default
for a public deployment that hasn't opted in.

Endpoints:
  POST /admin/deploy/protocol      — atomic 4-coin deployment of the full stack
  GET  /admin/deployment           — current persisted manifest
  POST /admin/governance/propose   — open a new proposal (PGT lock + bill)
  POST /admin/governance/vote      — cast additional PGT lock votes
  POST /admin/governance/execute   — fire a passed proposal (after deadline)
  POST /admin/governance/expire    — clear a below-quorum proposal

The governance endpoints are deliberately lower-level: they take the raw
PGT spend bundle from the operator's own wallet driver and only handle the
tracker-side spend.  This avoids embedding wallet management in the API
while still letting the operator drive a full governance flow.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from .config import Settings, get_settings


# Heavy chia/CLVM imports are deferred to inside the request handlers
# to avoid binding chia_rs LazyNode instances to the import thread.  The
# admin endpoints are async and may be dispatched on different threads;
# touching these modules at import time triggered `LazyNode is unsendable`
# panics under starlette's TestClient + lifespan + dependency_overrides.
#
# DO NOT move these imports back to the top level.


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])


# ── Auth dependency ──────────────────────────────────────────────────────────
def require_admin_token(
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> None:
    """Guard for every admin endpoint.

    Returns 503 when no token is configured (admin disabled by default).
    Returns 401 when the Authorization header is missing or malformed.
    Returns 403 when the token doesn't match.
    """
    if not settings.admin_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin endpoints are disabled (POPULIS_ADMIN_TOKEN unset).",
        )
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header (expected 'Bearer <token>').",
        )
    presented = authorization.split(None, 1)[1].strip()
    # Constant-time compare
    import hmac
    if not hmac.compare_digest(presented, settings.admin_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin token.",
        )


# ── Helpers for app-state plumbing ───────────────────────────────────────────
def _get_app_state(name: str):
    """Lazy lookup of FastAPI app state attributes (faucet, coinset, etc.).

    We can't use Depends() here because admin needs the same app.state-bound
    objects that the rest of the app does (faucet, coinset).  Importing the
    app module at top-level would create a circular import; resolve it
    lazily via the request's app reference instead.
    """
    from .app import app  # local import: app.py imports admin.py
    return getattr(app.state, name, None)


def _faucet_or_503():
    f = _get_app_state("faucet")
    if f is None:
        raise HTTPException(
            status_code=503,
            detail="Faucet not configured — set POPULIS_FAUCET_* to enable deployment.",
        )
    return f


def _coinset_or_502():
    c = _get_app_state("coinset")
    if c is None:
        raise HTTPException(status_code=502, detail="Coinset client not initialised.")
    return c


def _spend_bundle_to_json(bundle) -> dict[str, Any]:
    if hasattr(bundle, "to_json_dict"):
        return bundle.to_json_dict()
    return {
        "coin_spends": [
            {
                "coin": {
                    "parent_coin_info": "0x" + bytes(cs.coin.parent_coin_info).hex(),
                    "puzzle_hash": "0x" + bytes(cs.coin.puzzle_hash).hex(),
                    "amount": cs.coin.amount,
                },
                "puzzle_reveal": "0x" + bytes(cs.puzzle_reveal).hex(),
                "solution": "0x" + bytes(cs.solution).hex(),
            }
            for cs in bundle.coin_spends
        ],
        "aggregated_signature": "0x" + bytes(bundle.aggregated_signature).hex(),
    }


def _coin_from_record(rec: dict):
    """Convert a coinset.org coin record into a chia ``Coin``.

    Imports lazily — see top-of-file note about LazyNode threading.
    """
    from chia.types.blockchain_format.coin import Coin
    from chia_rs.sized_bytes import bytes32
    from chia_rs.sized_ints import uint64

    payload = rec.get("coin") or rec
    return Coin(
        parent_coin_info=bytes32.fromhex(payload["parent_coin_info"].removeprefix("0x")),
        puzzle_hash=bytes32.fromhex(payload["puzzle_hash"].removeprefix("0x")),
        amount=uint64(int(payload["amount"])),
    )


# ── Schemas ──────────────────────────────────────────────────────────────────
class DeployRequest(BaseModel):
    """Request body for ``POST /admin/deploy/protocol``."""

    quorum_bps: int = Field(5000, ge=1, le=10000)
    voting_window_seconds: int = Field(300, ge=1)
    pgt_total_supply: int = Field(1_000_000, ge=1)
    min_proposal_stake: int = Field(10_000, ge=1)
    fp_scale: int = Field(1000, ge=1)
    initial_pool_status: int = Field(1, ge=0, le=1)
    fee_per_spend: int = Field(0, ge=0)
    # Optional: restrict to specific faucet coins by name.  When omitted, the
    # 4 smallest unspent faucet coins are used (smallest-first to minimize
    # change output count).  PGT genesis needs ≥ pgt_total_supply mojos in
    # one of them.
    pgt_coin_id: Optional[str] = None
    pool_coin_id: Optional[str] = None
    did_coin_id: Optional[str] = None
    gov_coin_id: Optional[str] = None
    dry_run: bool = Field(
        False,
        description=(
            "When true, compute and return the deployment plan without "
            "pushing the bundle to chain or persisting the manifest."
        ),
    )


class DeployResponse(BaseModel):
    spend_bundle_id: Optional[str]
    pushed: bool
    manifest: dict[str, Any]


class ManifestResponse(BaseModel):
    deployed: bool
    manifest: Optional[dict[str, Any]] = None


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.get("/deployment", response_model=ManifestResponse,
            dependencies=[Depends(require_admin_token)])
async def get_deployment(
    settings: Annotated[Settings, Depends(get_settings)],
) -> ManifestResponse:
    """Return the persisted deployment manifest if present."""
    from populis_puzzles.protocol_deployment import load_manifest_dict

    path = Path(settings.deployment_manifest_path)
    if not path.exists():
        return ManifestResponse(deployed=False, manifest=None)
    try:
        manifest = load_manifest_dict(path)
    except (ValueError, json.JSONDecodeError) as e:
        logger.exception("Failed to load deployment manifest %s: %s", path, e)
        raise HTTPException(
            status_code=500,
            detail=f"Manifest at {path} is corrupt: {e}",
        ) from e
    return ManifestResponse(deployed=True, manifest=manifest)


@router.post("/deploy/protocol", response_model=DeployResponse,
             dependencies=[Depends(require_admin_token)])
async def deploy_protocol(
    body: DeployRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> DeployResponse:
    """Atomically deploy the protocol stack to chain.

    Selects 4 unspent faucet coins (or uses the explicitly-named ones from
    the request), computes the deployment plan, builds the signed
    SpendBundle, optionally pushes it to coinset.org, and persists the
    manifest to disk.

    A re-deploy is rejected if a manifest already exists — the operator
    must remove the file (or change ``deployment_manifest_path``) to
    deliberately re-deploy.
    """
    # Lazy CLVM imports — see module note about LazyNode thread binding
    from chia_rs.sized_bytes import bytes32
    from populis_puzzles.protocol_deployment import (
        ProtocolDeploymentParams,
        ProtocolDeploymentPlan,
        build_deployment_bundle,
        plan_to_manifest_dict,
        save_manifest,
    )

    manifest_path = Path(settings.deployment_manifest_path)
    if manifest_path.exists() and not body.dry_run:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Deployment manifest already exists at {manifest_path}; "
                "remove it (or change POPULIS_DEPLOYMENT_MANIFEST_PATH) to "
                "deliberately re-deploy."
            ),
        )

    faucet = _faucet_or_503()
    coinset = _coinset_or_502()

    # Fetch unspent faucet coins (excluding any explicitly-named coins from
    # the request, those are looked up directly).
    coin_records = await coinset.get_coin_records_by_puzzle_hash(
        "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
    )
    unspent: list = []
    for rec in coin_records:
        if rec.get("spent_block_index") in (0, None):
            unspent.append(_coin_from_record(rec))

    pgt_amount_required = body.pgt_total_supply + body.fee_per_spend
    launcher_amount_required = 1 + body.fee_per_spend

    pgt_coin = _select_coin_by_id(unspent, body.pgt_coin_id, pgt_amount_required, "pgt_coin")
    pool_coin = _select_coin_by_id(unspent, body.pool_coin_id, launcher_amount_required, "pool_coin")
    did_coin = _select_coin_by_id(unspent, body.did_coin_id, launcher_amount_required, "did_coin")
    gov_coin = _select_coin_by_id(unspent, body.gov_coin_id, launcher_amount_required, "gov_coin")

    # Distinct coins
    selected_names = {pgt_coin.name(), pool_coin.name(), did_coin.name(), gov_coin.name()}
    if len(selected_names) != 4:
        raise HTTPException(
            status_code=409,
            detail="Selected coins must be 4 distinct unspent faucet coins.",
        )

    plan = ProtocolDeploymentPlan(
        network=settings.network,
        params=ProtocolDeploymentParams(
            quorum_bps=body.quorum_bps,
            voting_window_seconds=body.voting_window_seconds,
            pgt_total_supply=body.pgt_total_supply,
            min_proposal_stake=body.min_proposal_stake,
            fp_scale=body.fp_scale,
            initial_pool_status=body.initial_pool_status,
        ),
        faucet_inner_puzhash=faucet.address_puzzle_hash,
        pgt_genesis_coin_id=bytes32(pgt_coin.name()),
        pool_genesis_coin_id=bytes32(pool_coin.name()),
        did_genesis_coin_id=bytes32(did_coin.name()),
        gov_genesis_coin_id=bytes32(gov_coin.name()),
    )

    if body.dry_run:
        return DeployResponse(
            spend_bundle_id=None,
            pushed=False,
            manifest=plan_to_manifest_dict(plan),
        )

    deployment = build_deployment_bundle(
        plan=plan,
        faucet=faucet,
        pgt_coin=pgt_coin,
        pool_coin=pool_coin,
        did_coin=did_coin,
        gov_coin=gov_coin,
        fee_per_spend=body.fee_per_spend,
    )

    try:
        push_result = await coinset.push_tx(_spend_bundle_to_json(deployment.spend_bundle))
    except Exception as e:
        logger.exception("coinset push_tx failed: %s", e)
        raise HTTPException(status_code=502, detail=f"coinset.org rejected the spend: {e}") from e

    if not push_result.get("success"):
        status_msg = push_result.get("status") or push_result.get("error") or push_result
        logger.warning("Deployment push_tx returned non-success: %s", status_msg)
        # Don't persist the manifest if the push failed — caller can re-run.
        raise HTTPException(
            status_code=502,
            detail=f"Deployment bundle was rejected: {status_msg}",
        )

    # Persist the manifest only after a successful push.
    save_manifest(plan, manifest_path)
    logger.info(
        "Protocol deployed: tracker_launcher_id=%s pool_launcher_id=%s "
        "did_launcher_id=%s pgt_genesis=%s",
        plan.tracker_launcher_id.hex(),
        plan.pool_launcher_id.hex(),
        plan.did_launcher_id.hex(),
        plan.pgt_genesis_coin_id.hex(),
    )
    return DeployResponse(
        spend_bundle_id=deployment.spend_bundle_id,
        pushed=True,
        manifest=plan_to_manifest_dict(plan),
    )


def _select_coin_by_id(
    candidates: list, coin_id: Optional[str], min_amount: int, label: str
):
    """Pick a coin from ``candidates`` by name (if ``coin_id`` is given) or
    smallest-amount-that-meets-min_amount otherwise.

    Removes the selected coin from ``candidates`` (in-place) so the caller
    doesn't pick the same coin twice across multiple invocations.
    """
    from chia_rs.sized_bytes import bytes32

    if coin_id is not None:
        target = bytes32.fromhex(coin_id.removeprefix("0x"))
        for i, c in enumerate(candidates):
            if c.name() == target:
                if c.amount < min_amount:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"{label}: coin {coin_id} has amount {c.amount} < "
                            f"required {min_amount}"
                        ),
                    )
                candidates.pop(i)
                return c
        raise HTTPException(
            status_code=404,
            detail=f"{label}: coin {coin_id} is not an unspent faucet coin.",
        )

    # Smallest-coin-that-fits selection
    fitting = sorted(
        (c for c in candidates if c.amount >= min_amount),
        key=lambda c: c.amount,
    )
    if not fitting:
        raise HTTPException(
            status_code=503,
            detail=(
                f"{label}: no unspent faucet coin with amount ≥ {min_amount}. "
                "Top up the faucet from a testnet11 faucet or specify "
                f"{label}_id explicitly."
            ),
        )
    chosen = fitting[0]
    candidates.remove(chosen)
    return chosen


__all__ = ["router", "require_admin_token"]
