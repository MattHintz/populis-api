"""Customer-facing RC22 portfolio and action snapshot."""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from solslot_puzzles.vault_driver import AUTH_TYPE_BLS

from .chia_provider import ChiaProvider, ChiaProviderError
from .collection_store import CollectionStore, get_collection_store
from .config import Settings, get_settings
from .credential_auth import require_vault_record, verify_vault_session
from .presale_endpoints import get_presale_store
from .public_artifact import (
    PublicArtifactError,
    PublicArtifactMissing,
)
from .sols_market import SolsMarketReader
from .sols_swap_store import SolsSwapStore
from .vault_eligibility import require_current_approved_vault


router = APIRouter(prefix="/sols", tags=["customer-journey"])


class CustomerJourneySnapshotV1(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: int = Field(alias="schemaVersion")
    network: str
    vault: dict[str, Any]
    balances: dict[str, Any]
    holdings: list[dict[str, Any]]
    vouchers: list[dict[str, Any]]
    pending_operations: list[dict[str, Any]] = Field(
        alias="pendingOperations"
    )
    recent_activity: list[dict[str, Any]] = Field(alias="recentActivity")
    opportunities: list[dict[str, Any]]
    capabilities: dict[str, Any]
    recommended_action: dict[str, Any] = Field(alias="recommendedAction")
    verification: dict[str, Any]


def _reader(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> SolsMarketReader:
    provider = getattr(request.app.state, "coinset", None)
    if not isinstance(provider, ChiaProvider):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Chia provider is unavailable.",
        )
    return SolsMarketReader(provider, store, settings)


def _swap_store(request: Request, settings: Settings) -> SolsSwapStore:
    store = getattr(request.app.state, "sols_swap_store", None)
    if isinstance(store, SolsSwapStore):
        return store
    store = SolsSwapStore(settings.admin_db_path)
    request.app.state.sols_swap_store = store
    return store


def _operation_payload(operation: Any) -> dict[str, Any]:
    return {
        "operationHash": operation.operation_hash,
        "direction": operation.direction,
        "vaultLauncherId": operation.vault_launcher_id,
        "deedLauncherId": operation.deed_launcher_id,
        "status": operation.status,
        "quoteExpiresAt": operation.quote_expires_at,
        "transactionId": operation.transaction_id,
        "feeMojos": operation.fee_mojos,
        "feeTargetSeconds": operation.fee_target_seconds,
        "submissionProvider": operation.submission_provider,
        "mempoolObservedAt": operation.mempool_observed_at,
        "updatedAt": operation.updated_at,
    }


def _capability(
    *,
    available: bool,
    state: str,
    reason: str | None,
    path: str,
) -> dict[str, Any]:
    return {
        "available": available,
        "state": state,
        "reason": reason,
        "path": path,
    }


def _recommended_action(
    *,
    eligible: bool,
    operations: list[dict[str, Any]],
    vouchers: list[dict[str, Any]],
    holdings: list[dict[str, Any]],
    opportunities: list[dict[str, Any]],
    bls_vault: bool,
) -> dict[str, Any]:
    pending = next(
        (
            item
            for item in operations
            if item["status"] in {"PREPARED", "SUBMITTED"}
        ),
        None,
    )
    if pending is not None:
        return {
            "kind": "RESUME_SWAP",
            "label": "Track your swap",
            "path": f"/swap/{pending['operationHash']}",
        }
    active_voucher = next(
        (
            item
            for item in vouchers
            if item.get("state")
            not in {"REFUNDED", "REDEEMED"}
        ),
        None,
    )
    if active_voucher is not None:
        return {
            "kind": "REVIEW_VOUCHER",
            "label": "Review your reservation",
            "path": "/my-solslot?view=vouchers",
        }
    if not eligible:
        return {
            "kind": "VERIFY",
            "label": "Verify your vault",
            "path": "/my-solslot?view=verify",
        }
    if bls_vault and opportunities:
        return {
            "kind": "CHOOSE_DEED",
            "label": "Choose a SmartDeed",
            "path": "/swap/sols-to-deed",
        }
    if holdings:
        return {
            "kind": "REVIEW_HOLDINGS",
            "label": "Review your SmartDeeds",
            "path": "/my-solslot?view=holdings",
        }
    return {
        "kind": "BROWSE",
        "label": "Browse properties",
        "path": "/",
    }


@router.get(
    "/vaults/{vault_launcher_id}/journey",
    response_model=CustomerJourneySnapshotV1,
)
async def customer_journey_snapshot(
    vault_launcher_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> CustomerJourneySnapshotV1:
    session = verify_vault_session(settings, request, vault_launcher_id)
    record = require_vault_record(session.vault_launcher_id)
    eligible = False
    eligibility_reason: str | None = None
    try:
        require_current_approved_vault(
            settings,
            session.vault_launcher_id,
        )
        eligible = True
    except HTTPException as exc:
        eligibility_reason = str(exc.detail)

    try:
        market = await reader.snapshot()
        holdings_view = await reader.vault_holdings(
            session.vault_launcher_id
        )
    except PublicArtifactMissing:
        market = {
            "network": settings.network,
            "asset": {"tailHash": None},
            "opportunities": [],
            "outcome": "LOCKED",
        }
        holdings_view = {
            "holdings": [],
            "verifiedHoldingCount": 0,
            "rejectedHoldingCandidateCount": 0,
            "source": "awaiting-signed-genesis",
        }
    except (
        ChiaProviderError,
        PublicArtifactError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Customer portfolio verification failed closed: {exc}",
        ) from exc

    balance: str | None = None
    balance_coverage = "UNAVAILABLE_FOR_EVM_VAULT"
    tail_hash = market.get("asset", {}).get("tailHash")
    if record.auth_type == AUTH_TYPE_BLS and isinstance(tail_hash, str):
        try:
            balance = str(
                await reader.registered_bls_balance(
                    bytes(record.owner_pubkey),
                    tail_hash,
                )
            )
            balance_coverage = "REGISTERED_OWNER_KEY"
        except (ChiaProviderError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Sols balance verification failed closed: {exc}",
            ) from exc

    vouchers = get_presale_store(settings).vouchers_for_vault(
        session.vault_launcher_id
    )
    operations = [
        _operation_payload(item)
        for item in _swap_store(request, settings).list_for_vault(
            session.vault_launcher_id
        )
    ]
    pending_operations = [
        item
        for item in operations
        if item["status"] in {"PREPARED", "SUBMITTED"}
    ]
    holdings = list(holdings_view["holdings"])
    opportunities = list(market.get("opportunities") or [])
    bls_vault = record.auth_type == AUTH_TYPE_BLS
    swap_ready = eligible and bls_vault and bool(opportunities)
    reverse_swap_ready = eligible and bls_vault and bool(holdings)
    capabilities = {
        "primaryPurchase": _capability(
            available=eligible,
            state="AVAILABLE" if eligible else "VERIFY_FIRST",
            reason=eligibility_reason,
            path="/",
        ),
        "solsToDeed": _capability(
            available=swap_ready,
            state="AVAILABLE" if swap_ready else "WAITING",
            reason=(
                None
                if swap_ready
                else (
                    "A verified Chia or Google vault and live Pool V4 "
                    "inventory are required."
                )
            ),
            path="/swap/sols-to-deed",
        ),
        "deedToSols": _capability(
            available=reverse_swap_ready,
            state=(
                "AVAILABLE"
                if reverse_swap_ready
                else "WAITING" if bls_vault else "NOT_YET_AVAILABLE"
            ),
            reason=(
                None
                if reverse_swap_ready
                else (
                    "A verified SmartDeed holding is required."
                    if bls_vault
                    else (
                        "EVM vault payouts require the governed Warp wSOLS "
                        "route. Native Testnet11 swaps use a Chia or Google "
                        "vault."
                    )
                )
            ),
            path="/swap/deed-to-sols",
        ),
        "bridge": _capability(
            available=False,
            state="PREVIEW",
            reason="Warp bridge actions are disabled during Testnet Alpha.",
            path="/bridge",
        ),
        "liquidity": _capability(
            available=False,
            state="PREVIEW",
            reason="Liquidity actions are disabled during Testnet Alpha.",
            path="/liquidity",
        ),
    }
    recent_activity = sorted(
        [
            *(
                {
                    "kind": "SWAP",
                    "status": item["status"],
                    "occurredAt": item["updatedAt"],
                    "operationHash": item["operationHash"],
                }
                for item in operations
            ),
            *(
                {
                    "kind": "VOUCHER",
                    "status": item["state"],
                    "occurredAt": item.get("updatedAt")
                    or item.get("createdAt")
                    or 0,
                    "serial": item["serial"],
                }
                for item in vouchers
            ),
        ],
        key=lambda item: float(item["occurredAt"] or 0),
        reverse=True,
    )[:20]
    return CustomerJourneySnapshotV1(
        schemaVersion=1,
        network=settings.network,
        vault={
            "launcherId": session.vault_launcher_id,
            "authType": "chia_bls" if bls_vault else "evm",
            "identityConfirmed": eligible,
            "eligibilityReason": eligibility_reason,
        },
        balances={
            "solsMojos": balance,
            "solsCoverage": balance_coverage,
        },
        holdings=holdings,
        vouchers=vouchers,
        pendingOperations=pending_operations,
        recentActivity=recent_activity,
        opportunities=opportunities,
        capabilities=capabilities,
        recommendedAction=_recommended_action(
            eligible=eligible,
            operations=operations,
            vouchers=vouchers,
            holdings=holdings,
            opportunities=opportunities,
            bls_vault=bls_vault,
        ),
        verification={
            "holdingsSource": holdings_view["source"],
            "verifiedHoldingCount": holdings_view[
                "verifiedHoldingCount"
            ],
            "rejectedHoldingCandidateCount": holdings_view[
                "rejectedHoldingCandidateCount"
            ],
            "marketOutcome": market.get("outcome"),
        },
    )


__all__ = [
    "CustomerJourneySnapshotV1",
    "customer_journey_snapshot",
    "router",
]
